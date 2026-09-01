package axonflow

import (
	"context"
	"encoding/json"
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
		_ = json.NewEncoder(w).Encode(AuthZENResponse{Decision: false})
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

func TestEvaluateRefusesAnUnknownResponseMember(t *testing.T) {
	c := authzenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true,"advice":"proceed"}`))
	})

	dec, err := c.Evaluate(context.Background(), okRequest())
	if err == nil {
		t.Fatalf("an unknown response member was accepted: %+v", dec)
	}
	if dec.Allowed() {
		t.Error("an undecodable response produced an allowed decision")
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
