// AuthZEN-native authorization for the AxonFlow SDK.
//
// This is the surface the ADR-065 compatibility plan commits to in all five
// SDKs. It talks to POST /api/v1/access/evaluation, whose wire shape is
// generated from the platform's canonical contract (see authzen_types_gen.go);
// nothing in this file re-states a field name or an enum value.
//
// # What this replaces, and when
//
// Nothing yet. The existing decision surface stays wire-stable through all of
// v11 and is not deprecated here. This is the surface to write NEW integrations
// against, because at v11 the engine behind it changes to the ADR-065 Policy
// Decision Point with no wire change - an integration written against it
// migrates once rather than twice.
//
// # The one thing worth knowing before you call it
//
// The server refuses anything it cannot evaluate rather than evaluating around
// it. Send a subject property, an unrecognised context member, or an argument
// beside the query, and you get an *AuthZENError naming the exact member -- not
// a decision computed without it. That is deliberate: a decision that silently
// ignored an attribute would tell you the attribute was weighed when it was
// not, and every audit of that decision would inherit the claim.
//
// So treat an *AuthZENError as "fix the request", and treat only
// AuthZENErrorCodeEvaluationUnavailable as worth retrying.
package axonflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// authzenPath is the AuthZEN evaluation endpoint.
const authzenPath = "/api/v1/access/evaluation"

// authzenProfileHeader negotiates the AxonFlow profile.
//
// The SDK always sends it. AuthZEN 1.0's response is a bare boolean, and the
// four-valued state, obligations and approval challenge ride in the response
// context, which the server returns only to a caller that asked for it by
// version. This SDK understands the profile, so there is no reason to ask for
// less than it can read.
const authzenProfileHeader = "X-Axonflow-AuthZEN-Profile"

// Retryable reports whether the caller could get a different answer by sending
// the same request again.
//
// Only a dependency failure is. Every other code names something about the
// request itself, which will not change on a retry -- so a client that retries
// on any error burns its budget on requests that cannot succeed.
func (c AuthZENErrorCode) Retryable() bool {
	return c == AuthZENErrorCodeEvaluationUnavailable
}

// Error implements error so a refusal can be returned as one and recovered with
// errors.As.
func (e *AuthZENError) Error() string {
	if e == nil {
		return "<nil authzen error>"
	}
	if e.Pointer != "" {
		return fmt.Sprintf("axonflow: %s at %s: %s", e.Code, e.Pointer, e.Message)
	}
	return fmt.Sprintf("axonflow: %s: %s", e.Code, e.Message)
}

// AsAuthZENError unwraps err and returns the typed refusal when there is one.
//
// Convenience for callers that would rather not declare the local pointer:
//
//	dec, err := client.Evaluate(ctx, req)
//	if azErr, ok := axonflow.AsAuthZENError(err); ok {
//	    log.Printf("fix %s: %s", azErr.Pointer, azErr.Message)
//	}
func AsAuthZENError(err error) (*AuthZENError, bool) {
	var e *AuthZENError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Allowed reports whether the enforcement point may proceed.
//
// Read this rather than comparing the state yourself. Exactly one state permits
// execution, and a caller that branches on anything else -- "not DENY", say --
// treats a CHALLENGE or an ERROR as permission.
//
// It requires the boolean and the state to AGREE. Per the contract `decision`
// is the collapse of the state: ALLOW is true and every other state is false.
// A response where the two disagree was not evaluated to either of them, so it
// cannot be acted on, and reading only the boolean turned {decision:true,
// state:CHALLENGE} into permission. The state lives in the profile context, so
// a decision carrying no context is not an allow either -- which is the same
// reading State gives it.
func (r *AuthZENResponse) Allowed() bool {
	return r != nil && r.Decision && r.Context != nil && r.Context.State == AuthZENOperationalStateAllow
}

// State returns the four-valued operational state, or ERROR when the server did
// not send a profile context.
//
// The fallback is ERROR rather than a zero value because an absent context means
// this client could not read the outcome in detail, and the safe reading of an
// outcome you could not read is not ALLOW.
func (r *AuthZENResponse) State() AuthZENOperationalState {
	if r == nil || r.Context == nil {
		return AuthZENOperationalStateError
	}
	return r.Context.State
}

// Obligations returns the instructions the enforcement point must discharge
// before proceeding.
//
// A mandatory obligation that cannot be discharged means the operation must NOT
// proceed, even though Allowed reported true: an allow with an undischarged
// mandatory obligation is not an allow.
func (r *AuthZENResponse) Obligations() []AuthZENObligation {
	if r == nil || r.Context == nil {
		return nil
	}
	return r.Context.Obligations
}

// Evaluate asks whether one subject may perform one action on one resource.
//
// Example:
//
//	dec, err := client.Evaluate(ctx, axonflow.AuthZENRequest{
//	    Subject:  &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
//	    Action:   &axonflow.AuthZENAction{Name: "llm.completion"},
//	    Resource: &axonflow.AuthZENResource{Type: "llm", ID: "llm"},
//	    Context: map[string]any{
//	        "args": map[string]any{"query": userPrompt},
//	    },
//	})
//	if err != nil {
//	    return err // fail closed
//	}
//	if !dec.Allowed() {
//	    return fmt.Errorf("blocked: %s", dec.State())
//	}
func (c *AxonFlowClient) Evaluate(ctx context.Context, req AuthZENRequest) (*AuthZENResponse, error) {
	env := AuthZENEnvelope{Evaluation: &req}
	return c.evaluateEnvelope(ctx, env)
}

// EvaluateAll asks whether one operation is permitted against SEVERAL
// preconditions at once.
//
// It returns ONE decision, not one per entry. The entries of a bulk request are
// preconditions of a single operation -- moving a ticket must be authorized
// against the destination project as well as against the ticket -- so they
// combine to the least permissive outcome: one denied entry denies the
// operation. An API returning a list would invite a caller to act on the entry
// it liked.
//
// Any member an entry omits is inherited from the envelope's shared base, so
// the common case is a shared subject and action with one resource per entry:
//
//	dec, err := client.EvaluateAll(ctx, axonflow.AuthZENBulk{
//	    Subject: &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
//	    Action:  &axonflow.AuthZENAction{Name: "tool.call"},
//	    Context: map[string]any{"args": map[string]any{"query": userPrompt}},
//	    Evaluations: []AuthZENRequest{
//	        {Resource: &axonflow.AuthZENResource{Type: "tool", ID: "jira/move_issue"}},
//	        {Resource: &axonflow.AuthZENResource{Type: "tool", ID: "jira/update_project"}},
//	    },
//	})
func (c *AxonFlowClient) EvaluateAll(ctx context.Context, bulk AuthZENBulk) (*AuthZENResponse, error) {
	env := AuthZENEnvelope{Evaluations: &bulk}
	return c.evaluateEnvelope(ctx, env)
}

// evaluateEnvelope is the one transport path both entry points share.
func (c *AxonFlowClient) evaluateEnvelope(ctx context.Context, env AuthZENEnvelope) (*AuthZENResponse, error) {
	// Tri-state attributes are resolved FIRST, before validation and before
	// any bytes exist to send: a known attribute becomes its value, an absent
	// one is omitted, and an UNKNOWN one refuses the whole envelope with a
	// typed *AuthZENUnresolvedError naming its JSON Pointer. Unlike the
	// validation below, this IS a safety boundary rather than a convenience:
	// the server cannot perform it, because an unknown attribute has no wire
	// representation -- sent without it, the request is indistinguishable from
	// one whose attribute is absent, and the decision would record an
	// attribute as weighed that nobody ever read. See authzen_attribute.go.
	env, err := resolveAuthZENEnvelope(env)
	if err != nil {
		return nil, err
	}

	// Validated before the round trip. The server enforces the same rules and
	// answers with a typed refusal, so this is a convenience rather than a
	// safety boundary -- but a caller that mis-built an envelope learns it from
	// a local error naming the member instead of from a 422.
	if err := env.Validate(); err != nil {
		return nil, err
	}

	body, err := json.Marshal(env)
	if err != nil {
		// The encoder is the backstop under the resolver: an attribute that
		// reached it inside a container the resolver does not walk (a
		// caller's own struct) refuses the request here instead of being
		// sent. Surface that as the same typed refusal the resolver gives.
		if unresolved, ok := AsAuthZENUnresolvedError(err); ok {
			return nil, unresolved
		}
		return nil, fmt.Errorf("failed to encode the AuthZEN request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Endpoint+authzenPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build the AuthZEN request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set(authzenProfileHeader, AuthZENProfileV1)
	c.addAuthHeaders(httpReq)

	resp, err := c.doHttpRequest(c.httpClient, httpReq)
	if err != nil {
		return nil, fmt.Errorf("AuthZEN request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the AuthZEN response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// A refusal is a typed document, so the caller can branch on the code
		// and be pointed at the member to fix. A body that is not one still
		// surfaces as an error -- never as a decision.
		var refusal AuthZENError
		if jerr := json.Unmarshal(raw, &refusal); jerr == nil && refusal.Code != "" && refusal.Message != "" {
			return nil, &refusal
		}
		return nil, &httpError{statusCode: resp.StatusCode, message: string(raw)}
	}

	// Strict decoding on the success path. An unknown member in a decision is a
	// server speaking a profile this build does not understand, and quietly
	// dropping it would mean acting on a partial reading of an authorization
	// decision.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var out AuthZENResponse
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode the AuthZEN response: %w; body=%s", err, string(raw))
	}

	// A 200 carrying NO profile context is refused, for the same reason and by
	// the same argument as the mismatched profile below.
	//
	// An absent context IS the blanked context. The SDK always negotiates -- the
	// header goes out above, unconditionally -- and the contract returns the
	// context to every enforcement point that negotiated, so an answer without
	// one means the negotiation was not honoured. That is exactly the case where
	// obligations may exist and be unreadable. Returning the decision produced an
	// object that contradicted itself: Allowed() reported true while State()
	// reported ERROR and Obligations() reported nil, indistinguishable from "no
	// obligations".
	if out.Context == nil {
		return nil, &AuthZENError{
			Code: AuthZENErrorCodeEvaluationUnavailable,
			Message: fmt.Sprintf(
				"the server answered without a profile context, though this build negotiated %q. "+
					"The state, the obligations and the approval challenge that constrain an allow are "+
					"carried in that payload, so the decision cannot be acted on safely.",
				AuthZENProfileV1),
		}
	}

	// A profile context from a version this build does not know is REFUSED, not
	// silently dropped.
	//
	// Dropping it was a fail-open. The SDK always negotiates, so a mismatched
	// profile means the server answered in a dialect this build cannot read --
	// and the parts it cannot read are exactly the parts that constrain an
	// allow: the obligations and the approval challenge. Blanking the context
	// left Allowed() returning true, Obligations() returning nil
	// (indistinguishable from "no obligations"), and the caller proceeding on an
	// allow whose mandatory redaction it never saw.
	//
	// Refusing is the only answer that does not misreport. It is also the one
	// that matters at the v11 cutover, which is precisely when a server starts
	// speaking a profile an older SDK does not know.
	if out.Context.Profile != AuthZENProfileV1 {
		return nil, &AuthZENError{
			Code: AuthZENErrorCodeEvaluationUnavailable,
			Message: fmt.Sprintf(
				"the server answered with AuthZEN profile %q; this build can only interpret %q. "+
					"The obligations and approval challenge that constrain an allow are carried in that "+
					"payload, so the decision cannot be acted on safely. Upgrade the SDK.",
				out.Context.Profile, AuthZENProfileV1),
		}
	}

	// The decoded response is held to the contract it was generated from, not
	// merely to what the decoder accepts.
	//
	// The request path validates before the round trip; the response path did
	// not validate at all, so a context stripped to the profile alone decoded
	// cleanly and yielded an allow whose state was the empty string -- a value
	// the SDK's own generated Valid rejects. Validate recurses, so this also
	// covers an obligation the caller is expected to discharge but that names no
	// source policy.
	if err := out.Validate(); err != nil {
		return nil, &AuthZENError{
			Code: AuthZENErrorCodeEvaluationUnavailable,
			Message: fmt.Sprintf(
				"the server's answer does not satisfy the AuthZEN contract this build was generated "+
					"from (%s): %v. A decision missing a member the contract requires cannot be acted "+
					"on, because the missing member may be the one that constrains it.",
				AuthZENContractSchemaVersion, err),
		}
	}
	return &out, nil
}
