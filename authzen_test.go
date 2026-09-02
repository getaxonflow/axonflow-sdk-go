package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authzenServer stands up a server that answers the AuthZEN route with whatever
// the case wants, and hands back a client pointed at it.
func authzenServer(t *testing.T, handler http.HandlerFunc) *AxonFlowClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: srv.URL},
		httpClient: srv.Client(),
	}
}

func okRequest() AuthZENRequest {
	return AuthZENRequest{
		Subject:  &AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
		Action:   &AuthZENAction{Name: "llm.completion"},
		Resource: &AuthZENResource{Type: "llm", ID: "llm"},
		Context:  map[string]any{"args": map[string]any{"query": "what is the weather"}},
	}
}

// TestEvaluateSendsTheEnvelopeAndNegotiatesTheProfile pins what goes out.
//
// The profile header is the difference between receiving a boolean and
// receiving the state, obligations and challenge. An SDK that stopped sending it
// would keep working -- every test asserting `Allowed()` would still pass --
// while silently losing everything a caller needs to enforce an obligation.
func TestEvaluateSendsTheEnvelopeAndNegotiatesTheProfile(t *testing.T) {
	var gotPath, gotProfile, gotMethod string
	var gotBody map[string]any

	c := authzenServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotProfile, gotMethod = r.URL.Path, r.Header.Get(authzenProfileHeader), r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthZENResponse{
			Decision: true,
			Context: &AuthZENResponseContext{
				Profile: AuthZENProfileV1, State: AuthZENOperationalStateAllow,
				Category: AuthZENCategoryAllowed, DecisionID: "d-1",
				SchemaVersion: AuthZENContractSchemaVersion,
			},
		})
	})

	dec, err := c.Evaluate(context.Background(), okRequest())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method %q, want POST", gotMethod)
	}
	if gotPath != authzenPath {
		t.Errorf("path %q, want %q", gotPath, authzenPath)
	}
	if gotProfile != AuthZENProfileV1 {
		t.Errorf("profile header %q, want %q", gotProfile, AuthZENProfileV1)
	}
	// The singular member, and only it.
	if _, ok := gotBody["evaluation"]; !ok {
		t.Errorf("the body carries no `evaluation` member: %v", gotBody)
	}
	if _, ok := gotBody["evaluations"]; ok {
		t.Errorf("the body carries both envelope members: %v", gotBody)
	}
	if !dec.Allowed() {
		t.Error("Allowed() was false on decision=true")
	}
	if dec.State() != AuthZENOperationalStateAllow {
		t.Errorf("State() = %q", dec.State())
	}
}

func TestEvaluateAllSendsThePluralEnvelope(t *testing.T) {
	var gotBody map[string]any
	c := authzenServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		// A complete profile context, because the client refuses a 200 that
		// carries none: the negotiation went out, so an answer without one is
		// an answer whose obligations this build could not have read.
		_ = json.NewEncoder(w).Encode(AuthZENResponse{
			Decision: false,
			Context: &AuthZENResponseContext{
				Profile: AuthZENProfileV1, State: AuthZENOperationalStateDeny,
				Category: AuthZENCategoryNotPermitted, DecisionID: "d-2",
				SchemaVersion: AuthZENContractSchemaVersion,
			},
		})
	})

	_, err := c.EvaluateAll(context.Background(), AuthZENBulk{
		Subject: &AuthZENSubject{Type: "gateway", ID: "g"},
		Action:  &AuthZENAction{Name: "tool.call"},
		Context: map[string]any{"args": map[string]any{"query": "q"}},
		Evaluations: []AuthZENRequest{
			{Resource: &AuthZENResource{Type: "tool", ID: "jira/move_issue"}},
			{Resource: &AuthZENResource{Type: "tool", ID: "jira/update_project"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if _, ok := gotBody["evaluations"]; !ok {
		t.Fatalf("the body carries no `evaluations` member: %v", gotBody)
	}
	if _, ok := gotBody["evaluation"]; ok {
		t.Errorf("the body carries both envelope members: %v", gotBody)
	}
}

// TestEvaluateSurfacesARefusalAsATypedError is the unhappy path this surface
// exists to make usable.
//
// The server refuses what it cannot evaluate rather than evaluating around it,
// so the refusal has to reach the caller as something it can BRANCH on -- with
// the offending member named. A refusal flattened into a generic HTTP error
// would leave a caller with a 422 and forty context keys to bisect.
func TestEvaluateSurfacesARefusalAsATypedError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      AuthZENError
		retryable bool
	}{
		{
			name:   "an attribute the server cannot evaluate",
			status: http.StatusUnprocessableEntity,
			body: AuthZENError{
				Code:    AuthZENErrorCodeUnevaluableAttribute,
				Pointer: "/evaluation/subject/properties",
				Message: "this surface cannot evaluate caller-supplied properties",
			},
		},
		{
			name:   "an action outside the evaluable set",
			status: http.StatusUnprocessableEntity,
			body: AuthZENError{
				Code:      AuthZENErrorCodeUnsupportedAction,
				Pointer:   "/evaluation/action/name",
				Message:   `action "jira.transition_issue" is not an evaluable action`,
				Supported: []string{"agent.invoke", "llm.completion", "tool.call"},
			},
		},
		{
			name:   "a malformed envelope",
			status: http.StatusBadRequest,
			body: AuthZENError{
				Code:    AuthZENErrorCodeMalformedEnvelope,
				Message: "envelope must carry exactly one member",
			},
		},
		{
			name:   "the evaluator could not answer",
			status: http.StatusBadGateway,
			body: AuthZENError{
				Code:    AuthZENErrorCodeEvaluationUnavailable,
				Message: "the evaluator did not return a verdict",
			},
			retryable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(tc.body)
			})

			dec, err := c.Evaluate(context.Background(), okRequest())
			if err == nil {
				t.Fatalf("a refusal was returned as a decision: %+v", dec)
			}
			// A refusal must NEVER arrive as a decision, however the caller
			// reads it. This is the fail-open that matters: a caller writing
			// `if dec.Allowed()` on a nil decision would panic, but one writing
			// `if !dec.Allowed() { deny }` on a zero-valued decision would
			// deny, and one writing `dec, _ := ...; if dec.Allowed()` must not
			// see true.
			if dec.Allowed() {
				t.Error("a refusal produced an allowed decision")
			}

			azErr, ok := AsAuthZENError(err)
			if !ok {
				t.Fatalf("the refusal did not surface as *AuthZENError: %T %v", err, err)
			}
			if azErr.Code != tc.body.Code {
				t.Errorf("code %q, want %q", azErr.Code, tc.body.Code)
			}
			if azErr.Pointer != tc.body.Pointer {
				t.Errorf("pointer %q, want %q", azErr.Pointer, tc.body.Pointer)
			}
			if azErr.Code.Retryable() != tc.retryable {
				t.Errorf("Retryable() = %v, want %v", azErr.Code.Retryable(), tc.retryable)
			}
			// The message names the member, so a log line is actionable.
			if tc.body.Pointer != "" && !strings.Contains(azErr.Error(), tc.body.Pointer) {
				t.Errorf("Error() does not name the pointer: %s", azErr.Error())
			}
		})
	}
}

// TestOnlyTheDependencyFailureIsRetryable pins the retry rule over the whole
// enumeration rather than the four codes the cases above happen to use.
func TestOnlyTheDependencyFailureIsRetryable(t *testing.T) {
	retryable := 0
	for _, code := range AllAuthZENErrorCodes() {
		if code.Retryable() {
			retryable++
			if code != AuthZENErrorCodeEvaluationUnavailable {
				t.Errorf("%q is retryable; only a dependency failure should be", code)
			}
		}
	}
	if retryable != 1 {
		t.Errorf("%d codes are retryable, want exactly 1", retryable)
	}
}

// TestEvaluateRefusesAnUnauthenticatedCall pins that an auth failure is
// observable rather than silently becoming a deny.
func TestEvaluateRefusesAnUnauthenticatedCall(t *testing.T) {
	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing or invalid credentials"}`))
	})

	dec, err := c.Evaluate(context.Background(), okRequest())
	if err == nil {
		t.Fatalf("an unauthenticated call returned a decision: %+v", dec)
	}
	if dec.Allowed() {
		t.Error("an unauthenticated call produced an allowed decision")
	}
	// The body is not an AuthZENError, so it must surface as an HTTP error
	// carrying the status -- never be flattened into something a caller could
	// mistake for a policy outcome.
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("the error does not carry the status: %v", err)
	}
	if _, ok := AsAuthZENError(err); ok {
		t.Error("a non-AuthZEN body was reported as a typed refusal")
	}
}

// TestEvaluateRefusesAProfileItCannotRead pins the fail-open that mattered
// most.
//
// This SDK always negotiates, so a mismatched profile means the server answered
// in a dialect this build cannot read -- and the unreadable parts are exactly
// the ones that CONSTRAIN an allow: the obligations and the approval challenge.
//
// The first version blanked the context and returned the decision. That left
// Allowed() true, Obligations() nil (indistinguishable from "no obligations"),
// and the documented path -- "read Allowed() rather than comparing the state
// yourself" -- proceeding on an allow whose mandatory redaction it never saw.
// It is the v11 cutover scenario exactly: that is when a server starts speaking
// a profile an older SDK does not know.
func TestEvaluateRefusesAProfileItCannotRead(t *testing.T) {
	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true,"context":{` +
			`"profile":"axonflow-authzen-profile-2099-01-01","state":"ALLOW",` +
			`"category":"allowed","decision_id":"d-1","schema_version":"2099-01-01"}}`))
	})

	dec, err := c.Evaluate(context.Background(), okRequest())
	if err == nil {
		t.Fatalf("an unreadable profile was accepted: %+v", dec)
	}
	// It must NOT come back as an allow by any route the caller might take.
	if dec.Allowed() {
		t.Error("an unreadable profile produced an allowed decision")
	}
	if len(dec.Obligations()) != 0 {
		t.Error("obligations were reported from a payload this build cannot read")
	}
	azErr, ok := AsAuthZENError(err)
	if !ok {
		t.Fatalf("expected a typed error, got %T: %v", err, err)
	}
	// Retryable: a newer server will keep answering the same way until the SDK
	// is upgraded, so the code must not invite a retry loop... but it IS the
	// dependency-shaped code, so assert the message carries the remedy instead.
	if !strings.Contains(azErr.Message, AuthZENProfileV1) {
		t.Errorf("the error does not name the profile this build understands: %s", azErr.Message)
	}
	if !strings.Contains(azErr.Message, "2099-01-01") {
		t.Errorf("the error does not name the profile the server sent: %s", azErr.Message)
	}
}

// TestEvaluateRefusesA200WithNoProfileContext is the SAME fail-open as the
// unreadable profile above, on the branch that was left open.
//
// An absent context IS the blanked context. The SDK always negotiates and the
// contract returns the context to any enforcement point that negotiated, so a
// 200 without one means the negotiation was not honoured -- which is exactly
// the case where obligations may exist and be unreadable. Before this was
// refused it produced an object that contradicted itself: Allowed() true while
// State() reported ERROR and Obligations() reported nil, indistinguishable from
// "no obligations".
func TestEvaluateRefusesA200WithNoProfileContext(t *testing.T) {
	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	})

	dec, err := c.Evaluate(context.Background(), okRequest())
	if err == nil {
		t.Fatalf("a 200 with no profile context was accepted: %+v", dec)
	}
	if dec.Allowed() {
		t.Error("a response with no profile context produced an allowed decision")
	}
	if len(dec.Obligations()) != 0 {
		t.Error("obligations were reported from a response that carried no context")
	}
	azErr, ok := AsAuthZENError(err)
	if !ok {
		t.Fatalf("expected a typed error, got %T: %v", err, err)
	}
	if azErr.Code != AuthZENErrorCodeEvaluationUnavailable {
		t.Errorf("code %q, want %q", azErr.Code, AuthZENErrorCodeEvaluationUnavailable)
	}
	if !strings.Contains(azErr.Message, AuthZENProfileV1) {
		t.Errorf("the error does not name the profile this build negotiated: %s", azErr.Message)
	}
}

// TestEvaluateValidatesTheDecodedResponse pins that the response is held to the
// contract it was generated from, not merely to what json.Decode accepts.
//
// The REQUEST path validates before the round trip; the response path did not
// validate at all. A context carrying only the profile decodes cleanly, and the
// decision it produced failed the SDK's own generated Validate while still
// reporting Allowed() true with an empty State().
func TestEvaluateValidatesTheDecodedResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"a context with only the profile", `{"decision":true,"context":{"profile":"` + AuthZENProfileV1 + `"}}`},
		{"a context with no state", `{"decision":true,"context":{"profile":"` + AuthZENProfileV1 + `",` +
			`"category":"allowed","decision_id":"d-1","schema_version":"` + AuthZENContractSchemaVersion + `"}}`},
		{"a context with no decision id", `{"decision":true,"context":{"profile":"` + AuthZENProfileV1 + `",` +
			`"state":"ALLOW","category":"allowed","schema_version":"` + AuthZENContractSchemaVersion + `"}}`},
		{"an obligation with no source policy", `{"decision":true,"context":{"profile":"` + AuthZENProfileV1 + `",` +
			`"state":"ALLOW","category":"allowed","decision_id":"d-1","schema_version":"` + AuthZENContractSchemaVersion + `",` +
			`"obligations":[{"type":"field_redact","mandatory":true,"schema_version":1}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})

			dec, err := c.Evaluate(context.Background(), okRequest())
			if err == nil {
				t.Fatalf("a response that fails the SDK's own Validate was accepted: %+v (state=%q)", dec, dec.State())
			}
			if dec.Allowed() {
				t.Error("an unvalidatable response produced an allowed decision")
			}
			if _, ok := AsAuthZENError(err); !ok {
				t.Errorf("expected a typed error, got %T: %v", err, err)
			}
		})
	}
}

// TestAllowedRequiresTheStateToAgreeWithTheBoolean pins the cross-check.
//
// Per the contract `decision` is the COLLAPSE of the state: ALLOW is true and
// every other state is false. A response where the two disagree was not
// evaluated to either of them, so it must not yield an allow -- and Allowed()
// is the documented way to read the outcome, so the check belongs there rather
// than in every caller.
func TestAllowedRequiresTheStateToAgreeWithTheBoolean(t *testing.T) {
	ctxJSON := func(decision bool, state, category string) string {
		return fmt.Sprintf(`{"decision":%t,"context":{"profile":%q,"state":%q,"category":%q,`+
			`"decision_id":"d-1","schema_version":%q}}`,
			decision, AuthZENProfileV1, state, category, AuthZENContractSchemaVersion)
	}
	for _, tc := range []struct {
		name        string
		body        string
		wantAllowed bool
		wantState   AuthZENOperationalState
	}{
		{"the boolean says allow and the state says challenge",
			ctxJSON(true, "CHALLENGE", "approval_required"), false, AuthZENOperationalStateChallenge},
		{"the boolean says allow and the state says deny",
			ctxJSON(true, "DENY", "not_permitted"), false, AuthZENOperationalStateDeny},
		{"the boolean says deny and the state says allow",
			ctxJSON(false, "ALLOW", "allowed"), false, AuthZENOperationalStateAllow},
		// The control. Without it every assertion above passes over an
		// Allowed() that returns false unconditionally.
		{"the boolean and the state both say allow",
			ctxJSON(true, "ALLOW", "allowed"), true, AuthZENOperationalStateAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})

			dec, err := c.Evaluate(context.Background(), okRequest())
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if dec.Allowed() != tc.wantAllowed {
				t.Errorf("Allowed() = %v, want %v (state=%q)", dec.Allowed(), tc.wantAllowed, dec.State())
			}
			if dec.State() != tc.wantState {
				t.Errorf("State() = %q, want %q", dec.State(), tc.wantState)
			}
		})
	}
}

// TestEnvelopeValidationRecursesIntoItsMembers pins the local checks over the
// members themselves, not only over their presence.
//
// The envelope nil-checked the singular's subject, action and resource and the
// bulk validated its shared base, so a subject with an empty type -- the Go
// zero value, which is what an omitted field leaves behind -- was serialised as
// `"type": ""` and sent. The SDK's stated purpose is to fail before the round
// trip on exactly the fields the server refuses.
func TestEnvelopeValidationRecursesIntoItsMembers(t *testing.T) {
	called := false
	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthZENResponse{Decision: true})
	})

	t.Run("a singular subject with no type", func(t *testing.T) {
		req := okRequest()
		req.Subject = &AuthZENSubject{ID: "llm-gateway-01"}
		if _, err := c.Evaluate(context.Background(), req); err == nil {
			t.Error("a subject with no type was sent")
		}
	})
	t.Run("a singular resource with no id", func(t *testing.T) {
		req := okRequest()
		req.Resource = &AuthZENResource{Type: "llm"}
		if _, err := c.Evaluate(context.Background(), req); err == nil {
			t.Error("a resource with no id was sent")
		}
	})
	t.Run("a bulk entry resource with no id", func(t *testing.T) {
		_, err := c.EvaluateAll(context.Background(), AuthZENBulk{
			Subject:     &AuthZENSubject{Type: "gateway", ID: "g"},
			Action:      &AuthZENAction{Name: "tool.call"},
			Evaluations: []AuthZENRequest{{Resource: &AuthZENResource{Type: "tool"}}},
		})
		if err == nil {
			t.Error("a bulk entry carrying a resource with no id was sent")
		}
	})

	if called {
		t.Error("an envelope with an invalid member reached the network")
	}
}

func TestEvaluateRefusesAnUnknownResponseMember(t *testing.T) {
	// The response carries a COMPLETE profile context on purpose. Without one
	// the handler refuses on the missing-context branch instead, and this test
	// reports green while asserting nothing about strictness — which is
	// exactly what happened once the generated types grew an UnmarshalJSON
	// (encoding/json applies none of an enclosing Decoder's settings inside a
	// json.Unmarshaler, so the outer DisallowUnknownFields stopped reaching
	// this subtree, silently). The fixture must reach the decode.
	const body = `{"decision":true,"advice":"proceed","context":{` +
		`"profile":"axonflow-authzen-profile-2026-08-29","state":"allow",` +
		`"category":"data_access","decision_id":"d1","schema_version":"2026-08-29"}}`

	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	dec, err := c.Evaluate(context.Background(), okRequest())
	if err == nil {
		t.Fatalf("an unknown response member was accepted: %+v", dec)
	}
	if !strings.Contains(err.Error(), "advice") {
		t.Errorf("the refusal does not name the unknown member; it may be refusing for an "+
			"unrelated reason and asserting nothing about strictness: %v", err)
	}
	if dec.Allowed() {
		t.Error("an undecodable response produced an allowed decision")
	}
}

// TestGeneratedTypesDecodeStrictly pins that strictness survives the generated
// UnmarshalJSON methods, on the types that have one AND on a nested type that
// does not.
//
// It asserts on plain json.Unmarshal rather than through Evaluate, because the
// property is about the TYPES: once a type carries an UnmarshalJSON, no caller
// — this SDK's response path, a user's own decode, a nested decode one level
// up — can impose strictness on it from outside.
func TestGeneratedTypesDecodeStrictly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		target  func() any
		unknown string
	}{
		{
			name:    "on a type that carries a presence check",
			payload: `{"decision":true,"advice":"proceed"}`,
			target:  func() any { return new(AuthZENResponse) },
			unknown: "advice",
		},
		{
			name: "on a nested type that does not",
			payload: `{"decision":true,"context":{"profile":"p","state":"allow","category":"c",` +
				`"decision_id":"d","schema_version":"2026-08-29","deny_after":"2026-01-01T00:00:00Z"}}`,
			target:  func() any { return new(AuthZENResponse) },
			unknown: "deny_after",
		},
		{
			name: "on an obligation reached through its parent",
			payload: `{"profile":"p","state":"allow","category":"c","decision_id":"d",` +
				`"schema_version":"2026-08-29","obligations":[{"type":"redact","mandatory":true,` +
				`"source_policy":"p1","schema_version":1,"severity":"high"}]}`,
			target:  func() any { return new(AuthZENResponseContext) },
			unknown: "severity",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := json.Unmarshal([]byte(tc.payload), tc.target())
			if err == nil {
				t.Fatalf("the unknown member %q was silently dropped; acting on a partial reading "+
					"of an authorization decision is the failure this strictness exists to prevent", tc.unknown)
			}
			if !strings.Contains(err.Error(), tc.unknown) {
				t.Errorf("the refusal does not name %q: %v", tc.unknown, err)
			}
		})
	}
}

// TestEnvelopeValidationFailsBeforeTheRoundTrip pins the local checks.
func TestEnvelopeValidationFailsBeforeTheRoundTrip(t *testing.T) {
	called := false
	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthZENResponse{Decision: true})
	})

	for _, tc := range []struct {
		name string
		req  AuthZENRequest
	}{
		{"no subject", AuthZENRequest{
			Action:   &AuthZENAction{Name: "llm.completion"},
			Resource: &AuthZENResource{Type: "llm", ID: "llm"},
		}},
		{"no action", AuthZENRequest{
			Subject:  &AuthZENSubject{Type: "gateway", ID: "g"},
			Resource: &AuthZENResource{Type: "llm", ID: "llm"},
		}},
		{"no resource", AuthZENRequest{
			Subject: &AuthZENSubject{Type: "gateway", ID: "g"},
			Action:  &AuthZENAction{Name: "tool.call"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Evaluate(context.Background(), tc.req); err == nil {
				t.Error("an incomplete evaluation was sent")
			}
		})
	}
	if called {
		t.Error("an invalid envelope reached the network")
	}

	// The bulk envelope's own minimum, for the same reason: zero entries is not
	// a request for zero decisions.
	if _, err := c.EvaluateAll(context.Background(), AuthZENBulk{}); err == nil {
		t.Error("an empty bulk envelope was sent")
	}
}

// TestGeneratedEnumValidRecognisesOnlyKnownValues pins the generated helper.
func TestGeneratedEnumValidRecognisesOnlyKnownValues(t *testing.T) {
	for _, s := range AllAuthZENOperationalStates() {
		if !s.Valid() {
			t.Errorf("%q is declared but not Valid", s)
		}
	}
	for _, unknown := range []AuthZENOperationalState{"", "allow", "MAYBE"} {
		if unknown.Valid() {
			t.Errorf("%q is not declared but reported Valid", unknown)
		}
	}
	// Exactly one state permits execution, and it is not "not DENY".
	if !AuthZENOperationalStateAllow.Valid() || AuthZENOperationalStateChallenge == AuthZENOperationalStateAllow {
		t.Error("the state enumeration is not what the contract declares")
	}
}
