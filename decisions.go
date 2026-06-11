// Decision explainability methods for AxonFlow SDK.
// Implements the contract locked in ADR-043 (Explainability Data Contract).
package axonflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ============================================================================
// Types (ADR-043 — frozen shape)
// ============================================================================

// DecisionExplanation is the canonical payload returned by Decisions.Explain.
// Shape is frozen per ADR-043; additive fields may be added with omitempty,
// renames/removals require a major version bump.
type DecisionExplanation struct {
	DecisionID                string          `json:"decision_id"`
	Timestamp                 time.Time       `json:"timestamp"`
	PolicyMatches             []ExplainPolicy `json:"policy_matches"`
	MatchedRules              []ExplainRule   `json:"matched_rules,omitempty"`
	Decision                  string          `json:"decision"` // canonical audit verdict: allowed|blocked|redacted|needs_approval|error (9.0.0+)
	Reason                    string          `json:"reason"`
	RiskLevel                 string          `json:"risk_level,omitempty"`
	OverrideAvailable         bool            `json:"override_available"`
	OverrideExistingID        string          `json:"override_existing_id,omitempty"`
	HistoricalHitCountSession int             `json:"historical_hit_count_session"`
	PolicySourceLink          string          `json:"policy_source_link,omitempty"`
	ToolSignature             string          `json:"tool_signature,omitempty"`

	// Context is the FULL sanitized request context the PEP attached to the
	// decision (canonical lower_snake_case keys, string values), read from
	// the audit row's policy_details->'context'. Unlike ListDecisions (which
	// truncates to the 5 most-correlated keys), Explain returns every
	// persisted key up to the platform's 10-key cap, so an auditor gets the
	// complete correlation set (x_ai_agent / x_session_id / x_leader_identity,
	// x-bukuwarung-*). ContextTruncated reports whether the agent dropped
	// surplus keys at write time. Both omitempty so pre-v8.4.0 audit rows keep
	// their original byte-shape. (platform #2509 / epic #2508)
	Context          map[string]string `json:"context,omitempty"`
	ContextTruncated bool              `json:"context_truncated,omitempty"`
}

// ExplainPolicy is a policy reference inside an explanation.
type ExplainPolicy struct {
	PolicyID          string `json:"policy_id"`
	PolicyName        string `json:"policy_name,omitempty"`
	Action            string `json:"action,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`
	AllowOverride     bool   `json:"allow_override,omitempty"`
	PolicyDescription string `json:"policy_description,omitempty"`
}

// ExplainRule is rule-level detail inside an explanation.
type ExplainRule struct {
	PolicyID  string `json:"policy_id"`
	RuleID    string `json:"rule_id,omitempty"`
	RuleText  string `json:"rule_text,omitempty"`
	MatchedOn string `json:"matched_on,omitempty"`
}

// ============================================================================
// Methods
// ============================================================================

// ExplainDecision fetches the full explanation for a previously-made
// policy decision. The caller must either own the decision (user_email
// match) or belong to the same tenant. Returns a 404-equivalent error
// when the decision is past retention.
//
// Context cancellation is honored; the underlying HTTP request is bound
// to the given ctx.
//
// Example:
//
//	exp, err := client.ExplainDecision(ctx, "dec_wf123_step4")
//	if err != nil { return err }
//	if exp.OverrideAvailable {
//	    // offer the user a "override this for 10 minutes" action
//	}
func (c *AxonFlowClient) ExplainDecision(ctx context.Context, decisionID string) (*DecisionExplanation, error) {
	if decisionID == "" {
		return nil, fmt.Errorf("decisionID is required")
	}

	// Path-escape the decision ID — platform-generated IDs are usually
	// filesystem-safe, but nothing in ADR-043 guarantees it, and IDs that
	// contain "/" or "?" would break the URL otherwise.
	fullURL := c.config.Endpoint + "/api/v1/decisions/" + url.PathEscape(decisionID) + "/explain"

	httpReq, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build explain request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/json")
	c.addAuthHeaders(httpReq)

	resp, err := c.doHttpRequest(c.httpClient, httpReq)
	if err != nil {
		return nil, fmt.Errorf("explain request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read explain response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var out DecisionExplanation
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to decode explain response: %w", err)
	}
	return &out, nil
}

// ============================================================================
// list_decisions — Session γ (#1982)
// ============================================================================

// DecisionSummary is the slim 5-field row returned by ListDecisions.
// PolicyID and ToolSignature are omitempty because pre-α1 audit rows
// + dynamic-only blocks may not populate them. Additive new fields
// land via omitempty per ADR-043 §"Versioning" (non-breaking).
//
// Cross-SDK parity:
//
//	Python: axonflow-sdk-python/axonflow/decisions.py (DecisionSummary)
//	TS:     axonflow-sdk-typescript/src/types/decisions.ts (DecisionSummary)
//	Java:   .../sdk/types/DecisionSummary.java
//	Rust:   axonflow-sdk-rust/src/types/decisions.rs (DecisionSummary)
type DecisionSummary struct {
	DecisionID    string    `json:"decision_id"`
	Timestamp     time.Time `json:"timestamp"`
	Decision      string    `json:"decision"` // canonical audit verdict: allowed|blocked|redacted|needs_approval|error (9.0.0+)
	PolicyID      string    `json:"policy_id,omitempty"`
	ToolSignature string    `json:"tool_signature,omitempty"`

	// Context is the sanitized request context the PEP attached to the
	// decision (canonical lower_snake_case keys, string values), surfaced
	// from the audit row's policy_details->'context'. The list summary is
	// truncated by the platform to the 5 most-correlated keys; the full map
	// (up to the 10-key cap) is available via ExplainDecision. omitempty so
	// pre-v8.4.0 audit rows + decisions with no context keep the original
	// byte-shape. (platform #2509 / epic #2508)
	Context map[string]string `json:"context,omitempty"`
}

// ListDecisionsOptions carries the 5 optional filters for ListDecisions.
// Zero / empty values are omitted from the URL so the platform applies
// its tier-default page. Limit=0 means "use the tier default"; pass
// the value you want explicitly.
//
// Decision, when set, must be a canonical audit verdict
// (allowed|blocked|redacted|needs_approval|error) on platform 9.0.0+; the
// pre-9.0.0 values allow|deny|require_approval are rejected with HTTP 400.
// See https://docs.getaxonflow.com/docs/deployment/v8-to-v9-migration/
type ListDecisionsOptions struct {
	Since         time.Time
	Decision      string // allowed|blocked|redacted|needs_approval|error (9.0.0+)
	PolicyID      string
	ToolSignature string
	Limit         int
}

// UpgradeInfo is the V1 upgrade context inside a 429 envelope.
// Mirrors the platform-side
// feedback_429_no_upgrade_hint_is_conversion_gap.md contract.
type UpgradeInfo struct {
	Tier       string `json:"tier"`
	Wording    string `json:"wording"`
	CompareURL string `json:"compare_url"`
	BuyURL     string `json:"buy_url"`
}

// RateLimitEnvelope is the parsed 429 body when ListDecisions hits a
// tier cap. Surface via *RateLimitError so callers can branch on the
// upgrade fields without re-parsing the body.
type RateLimitEnvelope struct {
	Error     string      `json:"error"`
	LimitType string      `json:"limit_type"`
	Tier      string      `json:"tier"`
	Limit     int         `json:"limit"`
	Remaining int         `json:"remaining"`
	Upgrade   UpgradeInfo `json:"upgrade"`
}

// RateLimitError is the typed 429 surfaced when ListDecisions hits a
// tier cap. Implements error and exposes the parsed RateLimitEnvelope
// so callers can branch on Upgrade.{Tier,CompareURL,BuyURL} cleanly.
//
// Use errors.As(err, &rle) to extract from a wrapped error chain.
type RateLimitError struct {
	Envelope RateLimitEnvelope
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("HTTP 429 (tier=%s, limit_type=%s): %s",
		e.Envelope.Tier, e.Envelope.LimitType, e.Envelope.Error)
}

// ListDecisions returns recent policy decisions for the caller's tenant
// (slim 5-field DecisionSummary rows). The platform applies a tier-gated
// cap; passing a Limit above the cap yields *RateLimitError carrying the
// V1 upgrade envelope. Filters compose; zero-valued fields are omitted
// from the URL.
//
// Example:
//
//	decisions, err := client.ListDecisions(ctx, ListDecisionsOptions{
//	    Decision: "blocked",
//	    Limit:    10,
//	})
//	var rle *RateLimitError
//	if errors.As(err, &rle) {
//	    fmt.Println("upgrade to:", rle.Envelope.Upgrade.BuyURL)
//	}
func (c *AxonFlowClient) ListDecisions(ctx context.Context, opts ListDecisionsOptions) ([]DecisionSummary, error) {
	fullURL := c.config.Endpoint + "/api/v1/decisions"
	if qs := buildListDecisionsQuery(opts); qs != "" {
		fullURL += "?" + qs
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build list_decisions request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	c.addAuthHeaders(httpReq)

	resp, err := c.doHttpRequest(c.httpClient, httpReq)
	if err != nil {
		return nil, fmt.Errorf("list_decisions request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read list_decisions response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Try to parse the V1 upgrade envelope. If the body changed
		// shape we still surface the 429 — never silently succeed.
		var env RateLimitEnvelope
		if jerr := json.Unmarshal(body, &env); jerr == nil && env.LimitType != "" {
			return nil, &RateLimitError{Envelope: env}
		}
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var envelope struct {
		Decisions []DecisionSummary `json:"decisions"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("failed to decode list_decisions response: %w", err)
	}
	return envelope.Decisions, nil
}

// buildListDecisionsQuery serializes ListDecisionsOptions into a URL
// query string. Zero-valued fields are omitted; field order is stable
// so test mocks can match the URL exactly.
func buildListDecisionsQuery(opts ListDecisionsOptions) string {
	q := url.Values{}
	if !opts.Since.IsZero() {
		// Use UTC + RFC3339 — same wire format the explain endpoint
		// emits on the server side.
		q.Set("since", opts.Since.UTC().Format(time.RFC3339))
	}
	if opts.Decision != "" {
		q.Set("decision", opts.Decision)
	}
	if opts.PolicyID != "" {
		q.Set("policy_id", opts.PolicyID)
	}
	if opts.ToolSignature != "" {
		q.Set("tool_signature", opts.ToolSignature)
	}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	return q.Encode()
}

// AsRateLimitError unwraps err and returns the typed RateLimitError if
// present. Convenience for callers that don't want to import errors and
// declare the local pointer.
func AsRateLimitError(err error) (*RateLimitError, bool) {
	var rle *RateLimitError
	if errors.As(err, &rle) {
		return rle, true
	}
	return nil, false
}
