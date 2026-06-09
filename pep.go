// Decision Mode PEP (Policy Enforcement Point) contract for the AxonFlow Go SDK.
//
// A PEP follows one path: decide -> fulfill -> forward (ADR-056, epic #2563).
//
//   - decide:  ask the PDP (POST /api/v1/decide) for a verdict on a request.
//   - fulfill: for every obligation the verdict carries, call the ENGINE
//     endpoint named in the obligation's Fulfillment block to obtain
//     engine-redacted content.
//   - forward: forward the (possibly redacted) content, or block, per verdict.
//
// The structural guarantee #2563 demands: this SDK contains NO redaction logic
// of its own. There is no regex, no pattern table, no masking branch. The ONLY
// way it can discharge a redact_pii obligation is by POSTing the source content
// to the engine endpoint the obligation names (via the existing MCPCheckInput)
// and forwarding what the engine returns. If an obligation arrives without a
// fulfillable engine endpoint — or the engine reports the redactor did not run —
// FulfillRequest fails CLOSED (returns ErrObligationNotFulfillable) rather than
// forwarding unredacted content.
//
// This mirrors platform/shared/pep (the Go reference PEP) so the SDK PEP cannot
// reimplement redaction the way a hand-rolled regex would.
package axonflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Obligation contract constants (mirror platform/agent/decision_handler.go).
const (
	// ObligationRedactPII is the obligation a PEP discharges by replacing
	// request content with engine-redacted content before forwarding.
	ObligationRedactPII = "redact_pii"

	// PhaseRequest / PhaseResponse are the fulfillment phases. /decide runs
	// pre-call so it only emits request-phase obligations; the response-phase
	// value is part of the contract for PEP helpers that fan out to the
	// response-redaction endpoint after the backend call.
	PhaseRequest  = "request"
	PhaseResponse = "response"

	// ContentTypeText is the only redaction content-type wired today. The
	// contract is content-type agnostic — a PEP holding content of a type not
	// advertised by an obligation's ContentTypes must fail closed rather than
	// forward it unredacted.
	ContentTypeText = "text/plain"
)

// Verdict values returned by the PDP.
const (
	VerdictAllow         = "allow"
	VerdictDeny          = "deny"
	VerdictNeedsApproval = "needs_approval"
)

// Engine endpoints + the decide path. An obligation whose fulfillment endpoint
// is not one of these is rejected — a PEP must not be steered into calling an
// arbitrary URL by a malformed verdict.
const (
	decidePath            = "/api/v1/decide"
	requestRedactionPath  = "/api/v1/mcp/check-input"
	responseRedactionPath = "/api/v1/mcp/check-output"
)

// ErrObligationNotFulfillable means a Decision Mode obligation could not be
// discharged through the engine — it named no request-phase fulfillment, named
// an endpoint this client will not call, advertised a content-type the PEP is
// not holding, the engine endpoint failed, or the engine reported the redactor
// did not run (redaction_evaluated=false).
//
// This is a FAIL-CLOSED signal (ADR-056 / #2563): the caller MUST block the
// request, never forward unredacted content. The SDK contains no local
// redaction path, so it cannot silently substitute its own masking. Match it
// with errors.Is.
var ErrObligationNotFulfillable = errors.New("axonflow: obligation not engine-fulfillable")

// --- Decision API wire DTOs (mirror platform/agent/decision_handler.go) ---

// DecideRequest is the POST /api/v1/decide body. Required: Stage (one of "llm" |
// "tool" | "agent") and Query.
type DecideRequest struct {
	Stage          string                 `json:"stage"`
	Query          string                 `json:"query"`
	CallerIdentity DecisionCallerIdentity `json:"caller_identity"`
	Target         DecisionTarget         `json:"target"`
	UserToken      string                 `json:"user_token,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

// DecisionCallerIdentity is the gateway-asserted identity for a /decide request.
// OrgID / TenantID are optional in the body — the auth-derived identity is
// authoritative; body-supplied values are accepted only when they match.
type DecisionCallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// DecisionTarget describes what the gateway is about to call.
type DecisionTarget struct {
	Type     string `json:"type,omitempty"`     // "llm" | "tool" | "agent"
	Model    string `json:"model,omitempty"`    // when type=llm
	Provider string `json:"provider,omitempty"` // when type=llm
	Tool     string `json:"tool,omitempty"`     // when type=tool
}

// DecideResponse is the PDP verdict returned by POST /api/v1/decide. Obligations
// is always a slice so PEP code can iterate without a nil-check. TraceID is
// W3C-format (32 lowercase hex chars). Error is set on the deny path when the
// request was malformed.
type DecideResponse struct {
	Verdict           string       `json:"verdict"`
	DecisionID        string       `json:"decision_id,omitempty"`
	TraceID           string       `json:"trace_id,omitempty"`
	Reasons           []string     `json:"reasons,omitempty"`
	Obligations       []Obligation `json:"obligations"`
	EvaluatedPolicies []string     `json:"evaluated_policies"`
	Stage             string       `json:"stage,omitempty"`
	ExpiresAt         time.Time    `json:"expires_at,omitempty"`
	Error             string       `json:"error,omitempty"`
}

// Obligation is a self-describing, engine-fulfillable PEP requirement on an
// allow verdict. /decide is a pure PDP and never mutates content, so a
// redact_pii obligation is "call the AxonFlow engine endpoint named in
// Fulfillment to obtain engine-redacted content" — not "redact this yourself".
// Client-side redaction is forbidden.
type Obligation struct {
	Type        string                 `json:"type"`
	Detail      string                 `json:"detail,omitempty"`
	Fulfillment *ObligationFulfillment `json:"fulfillment,omitempty"`
}

// ObligationFulfillment names the engine call a PEP makes to discharge an
// obligation. ContentTypes advertises the mime-types the endpoint's detectors
// can handle today; a PEP holding content of a type NOT in this list must fail
// closed rather than forward it unredacted (ADR-056 / #2563 addendum).
type ObligationFulfillment struct {
	Endpoint     string   `json:"endpoint"`
	Method       string   `json:"method,omitempty"`
	Phase        string   `json:"phase"`
	ContentTypes []string `json:"content_types,omitempty"`
}

// Decide asks the PDP for a verdict on a request (POST /api/v1/decide).
//
// This is the PDP step of a PEP. /decide is a pure decision point: it NEVER
// mutates content. When an allow verdict carries a redact_pii obligation,
// discharge it with FulfillRequest (or use the one-call DecideAndFulfill) —
// never by redacting locally.
//
// Decision Mode auth is HTTP Basic (org:license), which this client already
// sends via addAuthHeaders; demo / wrong credentials are refused with HTTP 401,
// surfaced as the SDK's *httpError (StatusCode 401). A deny verdict is returned
// in the body with HTTP 200, not as an error.
func (c *AxonFlowClient) Decide(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	// Stamp the configured identity when the caller didn't set one explicitly.
	if req.CallerIdentity.OrgID == "" {
		req.CallerIdentity.OrgID = c.config.ClientID
	}

	fullURL := c.config.Endpoint + decidePath
	var result DecideResponse
	if err := c.makeJSONRequest(ctx, "POST", fullURL, req, &result); err != nil {
		return nil, err
	}
	if result.Obligations == nil {
		result.Obligations = []Obligation{}
	}
	return &result, nil
}

// FulfillRequest discharges every request-phase redact_pii obligation on
// decision by calling the engine endpoint the obligation names, and returns the
// engine-redacted statement to forward.
//
// Contract:
//   - No obligations (or none that mutate the request): returns (statement,
//     false, nil) — forward the original.
//   - A redact_pii obligation with a valid request-phase Fulfillment: POSTs
//     statement to that endpoint and returns (engineRedacted, true, nil).
//   - A redact_pii obligation that names no request-phase fulfillment, advertises
//     a content-type the PEP is not holding, names an endpoint this client will
//     not call, whose engine call fails, or whose engine reported the redactor
//     did not run: returns ErrObligationNotFulfillable. The caller MUST treat
//     this as fail-closed (block) — never forward unredacted content.
//
// didRedact reflects whether the ENGINE actually changed the content, not merely
// that an obligation was present. There is no code path in which this method
// redacts locally — fulfillment is always the engine round-trip.
func (c *AxonFlowClient) FulfillRequest(ctx context.Context, decision *DecideResponse, statement string) (string, bool, error) {
	if decision == nil {
		return statement, false, nil
	}
	redacted := statement
	didRedact := false
	for _, ob := range decision.Obligations {
		if ob.Type != ObligationRedactPII {
			// redact_pii is the only content-mutating obligation today; other
			// types are pass-through by contract.
			continue
		}
		if ob.Fulfillment == nil || ob.Fulfillment.Phase != PhaseRequest {
			// A redact_pii obligation with no request-phase fulfillment cannot
			// be discharged here — fail closed rather than forward unredacted.
			return statement, false, fmt.Errorf("%w: redact_pii missing request-phase fulfillment", ErrObligationNotFulfillable)
		}
		// Content-type-agnostic check: this client submits text. If the endpoint
		// advertises content types and text is not one of them, fail closed
		// rather than forward — never assume the endpoint can handle our content.
		if len(ob.Fulfillment.ContentTypes) > 0 && !containsPEPString(ob.Fulfillment.ContentTypes, ContentTypeText) {
			return statement, false, fmt.Errorf("%w: endpoint does not advertise a %s detector", ErrObligationNotFulfillable, ContentTypeText)
		}
		if !isAllowedFulfillmentEndpoint(ob.Fulfillment.Endpoint, requestRedactionPath) {
			return statement, false, fmt.Errorf("%w: endpoint %q is not the request-redaction endpoint", ErrObligationNotFulfillable, ob.Fulfillment.Endpoint)
		}
		out, err := c.fulfillViaCheckInput(ctx, redacted)
		if err != nil {
			return statement, false, err
		}
		// didRedact reflects whether the ENGINE actually changed the content,
		// not merely that an obligation was present — the engine may report
		// nothing to mask (fulfillViaCheckInput returns the statement unchanged).
		if out != redacted {
			didRedact = true
		}
		redacted = out
	}
	return redacted, didRedact, nil
}

// fulfillViaCheckInput POSTs statement to the request-redaction engine endpoint
// (the existing MCPCheckInput) and returns the engine-masked statement. It fails
// closed (returns ErrObligationNotFulfillable) when the engine call errors, the
// engine returns non-200, or redaction_evaluated is false — never returns
// unredacted content under an unfulfillable condition.
func (c *AxonFlowClient) fulfillViaCheckInput(ctx context.Context, statement string) (string, error) {
	result, err := c.MCPCheckInput(ctx, MCPCheckInputRequest{
		ConnectorType: "gateway",
		Statement:     statement,
		ContentType:   ContentTypeText,
		Operation:     "execute",
	})
	if err != nil {
		return "", fmt.Errorf("%w: request-redaction engine call failed: %v", ErrObligationNotFulfillable, err)
	}
	// FAIL CLOSED if the redactor did not actually run (#2563 B1). Without this
	// the PEP cannot distinguish "engine looked, found nothing" (safe to forward
	// the original) from "engine wasn't looking" (would leak PII) — both arrive
	// as redacted:false. The endpoint sets redaction_evaluated=true on every
	// evaluated allow path; its absence means the redactor was disabled and we
	// must NOT forward.
	if !result.RedactionEvaluated {
		return "", fmt.Errorf("%w: engine reported the redactor did not run (redaction disabled)", ErrObligationNotFulfillable)
	}
	if result.Redacted {
		// FAIL CLOSED on a self-contradictory engine response: redacted=true with
		// no redacted_statement means the engine claims it masked something but
		// gave us nothing to forward — never fall back to the unredacted original.
		if result.RedactedStatement == "" {
			return "", fmt.Errorf("%w: engine reported redacted=true but returned no redacted_statement", ErrObligationNotFulfillable)
		}
		return result.RedactedStatement, nil
	}
	// Redactor ran and found nothing to mask — forward the statement unchanged.
	return statement, nil
}

// DecideAndFulfill is the blessed one-call PEP path: decide, then fulfill any
// request-phase obligation. It returns the verdict, the content to forward
// (engine-redacted when an obligation applied), and the raw decision.
//
// Callers branch on verdict: forward content on allow; block on deny /
// needs_approval. On the not-fulfillable path it returns ErrObligationNotFulfillable
// with empty content (computed after fulfillment failed) so a caller that
// ignores the error cannot accidentally forward the unredacted query — fail-closed
// by construction (#2563 L2).
func (c *AxonFlowClient) DecideAndFulfill(ctx context.Context, req DecideRequest) (verdict, content string, decision *DecideResponse, err error) {
	decision, err = c.Decide(ctx, req)
	if err != nil {
		return "", req.Query, nil, err
	}
	if decision.Verdict != VerdictAllow {
		return decision.Verdict, req.Query, decision, nil
	}
	redacted, _, ferr := c.FulfillRequest(ctx, decision, req.Query)
	if ferr != nil {
		return decision.Verdict, "", decision, ferr
	}
	return decision.Verdict, redacted, decision, nil
}

// HasRequestRedaction reports whether any obligation requires request-phase PII
// redaction. Exposed so a PEP can branch ("does this verdict carry work for
// me?") before calling FulfillRequest.
func HasRequestRedaction(obligations []Obligation) bool {
	for _, o := range obligations {
		if o.Type == ObligationRedactPII && o.Fulfillment != nil && o.Fulfillment.Phase == PhaseRequest {
			return true
		}
	}
	return false
}

// containsPEPString reports whether v is in s.
func containsPEPString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// isAllowedFulfillmentEndpoint reports whether endpoint is the expected engine
// path. It tolerates an absolute URL whose path component matches (some PDPs
// return a fully-qualified obligation endpoint); a blank endpoint never matches.
func isAllowedFulfillmentEndpoint(endpoint, expected string) bool {
	e := strings.TrimSpace(endpoint)
	if e == expected {
		return true
	}
	// Accept an absolute URL whose path is the expected engine path.
	if i := strings.Index(e, "://"); i >= 0 {
		rest := e[i+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			path := rest[slash:]
			if q := strings.IndexByte(path, '?'); q >= 0 {
				path = path[:q]
			}
			return path == expected
		}
	}
	return false
}
