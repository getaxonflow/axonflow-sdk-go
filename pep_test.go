package axonflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The exact obligation the real agent emits on /decide for a request carrying
// PII under a redact policy (verified live against an enterprise agent).
func redactObligation() Obligation {
	return Obligation{
		Type: ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{
			Endpoint:     requestRedactionPath,
			Method:       "POST",
			Phase:        PhaseRequest,
			ContentTypes: []string{ContentTypeText},
		},
	}
}

func decideAllow(obs []Obligation) DecideResponse {
	return DecideResponse{
		Verdict:           VerdictAllow,
		DecisionID:        "dec-1",
		TraceID:           "04110a0b50577bbbdda23a00dcbaf6da",
		Obligations:       obs,
		EvaluatedPolicies: []string{"sys_pii_email"},
		Stage:             "tool",
	}
}

// newPEPClient builds a client pointed at srv with Basic-auth creds.
func newPEPClient(endpoint string) *AxonFlowClient {
	return &AxonFlowClient{
		config: AxonFlowConfig{
			Endpoint:     endpoint,
			ClientID:     "org-test",
			ClientSecret: "license-test",
		},
		httpClient: &http.Client{},
	}
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

func TestHasRequestRedaction(t *testing.T) {
	if !HasRequestRedaction([]Obligation{redactObligation()}) {
		t.Error("HasRequestRedaction = false, want true for request-phase redact_pii")
	}
	respPhase := []Obligation{{
		Type:        ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{Endpoint: responseRedactionPath, Phase: PhaseResponse},
	}}
	if HasRequestRedaction(respPhase) {
		t.Error("HasRequestRedaction = true, want false for response-phase obligation")
	}
	if HasRequestRedaction(nil) {
		t.Error("HasRequestRedaction = true, want false for empty obligations")
	}
	noFul := []Obligation{{Type: ObligationRedactPII}}
	if HasRequestRedaction(noFul) {
		t.Error("HasRequestRedaction = true, want false for obligation with no fulfillment")
	}
}

func TestIsAllowedFulfillmentEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		expected string
		want     bool
	}{
		{"/api/v1/mcp/check-input", requestRedactionPath, true},
		{"https://pdp:8443/api/v1/mcp/check-input", requestRedactionPath, true},
		{"https://pdp/api/v1/mcp/check-input?x=1", requestRedactionPath, true},
		{"", requestRedactionPath, false},
		{"/api/v1/other", requestRedactionPath, false},
		{"https://evil.example.com/steal", requestRedactionPath, false},
		{"  /api/v1/mcp/check-input  ", requestRedactionPath, true}, // trimmed
	}
	for _, tc := range cases {
		if got := isAllowedFulfillmentEndpoint(tc.endpoint, tc.expected); got != tc.want {
			t.Errorf("isAllowedFulfillmentEndpoint(%q, %q) = %v, want %v", tc.endpoint, tc.expected, got, tc.want)
		}
	}
}

func TestContainsPEPString(t *testing.T) {
	if !containsPEPString([]string{"a", ContentTypeText}, ContentTypeText) {
		t.Error("containsPEPString = false, want true")
	}
	if containsPEPString([]string{"a", "b"}, ContentTypeText) {
		t.Error("containsPEPString = true, want false")
	}
}

// ---------------------------------------------------------------------------
// Decide
// ---------------------------------------------------------------------------

func TestDecide_ParsesObligations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != decidePath {
			t.Errorf("got %s %s, want POST %s", r.Method, r.URL.Path, decidePath)
		}
		// The SDK must send HTTP Basic org:license on /decide.
		user, pass, ok := r.BasicAuth()
		if !ok || user != "org-test" || pass != "license-test" {
			t.Errorf("BasicAuth = (%q,%q,%v), want (org-test,license-test,true)", user, pass, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decideAllow([]Obligation{redactObligation()}))
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	resp, err := c.Decide(context.Background(), DecideRequest{
		Stage:  "tool",
		Query:  "Email a@b.com",
		Target: DecisionTarget{Type: "tool"},
	})
	if err != nil {
		t.Fatalf("Decide error: %v", err)
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q, want allow", resp.Verdict)
	}
	if resp.TraceID != "04110a0b50577bbbdda23a00dcbaf6da" {
		t.Errorf("TraceID = %q", resp.TraceID)
	}
	if len(resp.Obligations) != 1 {
		t.Fatalf("len(Obligations) = %d, want 1", len(resp.Obligations))
	}
	ob := resp.Obligations[0]
	if ob.Type != ObligationRedactPII || ob.Fulfillment == nil {
		t.Fatalf("obligation = %+v", ob)
	}
	if ob.Fulfillment.Endpoint != requestRedactionPath || ob.Fulfillment.Phase != PhaseRequest {
		t.Errorf("fulfillment = %+v", ob.Fulfillment)
	}
	if len(ob.Fulfillment.ContentTypes) != 1 || ob.Fulfillment.ContentTypes[0] != ContentTypeText {
		t.Errorf("content_types = %v", ob.Fulfillment.ContentTypes)
	}
}

func TestDecide_StampsOrgID(t *testing.T) {
	var captured DecideRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decideAllow(nil))
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	if _, err := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "hi"}); err != nil {
		t.Fatalf("Decide error: %v", err)
	}
	if captured.CallerIdentity.OrgID != "org-test" {
		t.Errorf("caller_identity.org_id = %q, want org-test (stamped from ClientID)", captured.CallerIdentity.OrgID)
	}
}

func TestDecide_EmptyObligationsIsNonNilSlice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// platform always sends [], but be defensive: omit it entirely.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"verdict":"allow","decision_id":"d1","evaluated_policies":[]}`)
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	resp, err := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "hi"})
	if err != nil {
		t.Fatalf("Decide error: %v", err)
	}
	if resp.Obligations == nil {
		t.Error("Obligations is nil, want non-nil empty slice")
	}
	if len(resp.Obligations) != 0 {
		t.Errorf("len(Obligations) = %d, want 0", len(resp.Obligations))
	}
}

func TestDecide_401SurfacesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	_, err := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "hi"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	var he *httpError
	if !errors.As(err, &he) {
		t.Fatalf("error type = %T, want *httpError", err)
	}
	if he.statusCode != http.StatusUnauthorized {
		t.Errorf("statusCode = %d, want 401", he.statusCode)
	}
}

func TestDecide_OmitsEmptyFieldsOnWire(t *testing.T) {
	var raw map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &raw)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decideAllow(nil))
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	if _, err := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "hi"}); err != nil {
		t.Fatalf("Decide error: %v", err)
	}
	if raw["stage"] != "tool" {
		t.Errorf("stage = %v, want tool", raw["stage"])
	}
	if _, ok := raw["user_token"]; ok {
		t.Error("user_token present on wire, want omitted when empty")
	}
	if _, ok := raw["context"]; ok {
		t.Error("context present on wire, want omitted when empty")
	}
}

// ---------------------------------------------------------------------------
// FulfillRequest — the fail-closed core
// ---------------------------------------------------------------------------

// checkInputServer returns a server that answers /api/v1/mcp/check-input with
// the given JSON body and records the captured request body.
func checkInputServer(t *testing.T, respBody string, captured *map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != requestRedactionPath {
			t.Errorf("path = %q, want %q", r.URL.Path, requestRedactionPath)
		}
		if captured != nil {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, captured)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
}

func TestFulfillRequest_EngineRedactsAndForwards(t *testing.T) {
	var captured map[string]interface{}
	srv := checkInputServer(t, `{"allowed":true,"policies_evaluated":1,"redacted":true,"redacted_statement":"Email jo****om","redaction_evaluated":true}`, &captured)
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow([]Obligation{redactObligation()})
	content, did, err := c.FulfillRequest(context.Background(), &decision, "Email john@x.com")
	if err != nil {
		t.Fatalf("FulfillRequest error: %v", err)
	}
	if content != "Email jo****om" {
		t.Errorf("content = %q, want engine-redacted", content)
	}
	if !did {
		t.Error("didRedact = false, want true")
	}
	// The PEP submitted the source content to the engine with text/plain.
	if captured["statement"] != "Email john@x.com" {
		t.Errorf("statement = %v, want original", captured["statement"])
	}
	if captured["content_type"] != ContentTypeText {
		t.Errorf("content_type = %v, want %q", captured["content_type"], ContentTypeText)
	}
	if captured["connector_type"] != "gateway" {
		t.Errorf("connector_type = %v, want gateway", captured["connector_type"])
	}
}

func TestFulfillRequest_NoObligationsPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("engine was called, but no obligation should trigger a call")
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow(nil)
	content, did, err := c.FulfillRequest(context.Background(), &decision, "nothing to mask")
	if err != nil {
		t.Fatalf("FulfillRequest error: %v", err)
	}
	if content != "nothing to mask" || did {
		t.Errorf("content=%q did=%v, want passthrough", content, did)
	}
}

func TestFulfillRequest_NilDecisionPassthrough(t *testing.T) {
	c := newPEPClient("http://unused")
	content, did, err := c.FulfillRequest(context.Background(), nil, "x")
	if err != nil || content != "x" || did {
		t.Errorf("got (%q,%v,%v), want passthrough", content, did, err)
	}
}

func TestFulfillRequest_EngineFoundNothingForwardsOriginal(t *testing.T) {
	// Redactor ran (redaction_evaluated:true) but masked nothing → forward original.
	srv := checkInputServer(t, `{"allowed":true,"redacted":false,"redaction_evaluated":true}`, nil)
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow([]Obligation{redactObligation()})
	content, did, err := c.FulfillRequest(context.Background(), &decision, "clean text")
	if err != nil {
		t.Fatalf("FulfillRequest error: %v", err)
	}
	if content != "clean text" {
		t.Errorf("content = %q, want original forwarded", content)
	}
	if did {
		t.Error("didRedact = true, want false (engine masked nothing)")
	}
}

func TestFulfillRequest_NonRedactObligationIsPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("engine was called for a non-redact obligation")
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow([]Obligation{{Type: "log_only"}})
	content, did, err := c.FulfillRequest(context.Background(), &decision, "x")
	if err != nil {
		t.Fatalf("FulfillRequest error: %v", err)
	}
	if content != "x" || did {
		t.Errorf("got (%q,%v), want passthrough", content, did)
	}
}

// --- fail-closed branches ---

func TestFulfillRequest_FailClosed_NoRequestPhaseFulfillment(t *testing.T) {
	cases := map[string]Obligation{
		"nil fulfillment": {Type: ObligationRedactPII, Fulfillment: nil},
		"response phase":  {Type: ObligationRedactPII, Fulfillment: &ObligationFulfillment{Endpoint: requestRedactionPath, Phase: PhaseResponse}},
	}
	for name, ob := range cases {
		t.Run(name, func(t *testing.T) {
			c := newPEPClient("http://unused")
			decision := decideAllow([]Obligation{ob})
			_, did, err := c.FulfillRequest(context.Background(), &decision, "secret email a@b.com")
			// The error IS the fail-closed signal — a correct caller never
			// forwards on a non-nil err. didRedact must be false.
			if !errors.Is(err, ErrObligationNotFulfillable) {
				t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
			}
			if did {
				t.Error("didRedact = true on fail-closed path")
			}
		})
	}
}

func TestFulfillRequest_FailClosed_UnadvertisedContentType(t *testing.T) {
	c := newPEPClient("http://unused")
	ob := Obligation{Type: ObligationRedactPII, Fulfillment: &ObligationFulfillment{
		Endpoint:     requestRedactionPath,
		Phase:        PhaseRequest,
		ContentTypes: []string{"image/png"}, // text/plain not advertised
	}}
	decision := decideAllow([]Obligation{ob})
	_, did, err := c.FulfillRequest(context.Background(), &decision, "secret a@b.com")
	// The error IS the fail-closed signal; a correct caller never forwards on a
	// non-nil err. didRedact must be false on every fail-closed path.
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
	}
	if did {
		t.Error("didRedact = true on fail-closed path")
	}
}

func TestFulfillRequest_FailClosed_ForeignEndpoint(t *testing.T) {
	c := newPEPClient("http://unused")
	ob := Obligation{Type: ObligationRedactPII, Fulfillment: &ObligationFulfillment{
		Endpoint: "https://evil.example.com/steal",
		Phase:    PhaseRequest,
	}}
	decision := decideAllow([]Obligation{ob})
	_, did, err := c.FulfillRequest(context.Background(), &decision, "secret a@b.com")
	// The error IS the fail-closed signal; a correct caller never forwards on a
	// non-nil err. didRedact must be false on every fail-closed path.
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
	}
	if did {
		t.Error("didRedact = true on fail-closed path")
	}
}

func TestFulfillRequest_FailClosed_EngineError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `boom`)
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow([]Obligation{redactObligation()})
	_, did, err := c.FulfillRequest(context.Background(), &decision, "secret a@b.com")
	// The error IS the fail-closed signal; a correct caller never forwards on a
	// non-nil err. didRedact must be false on every fail-closed path.
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
	}
	if did {
		t.Error("didRedact = true on fail-closed path")
	}
}

func TestFulfillRequest_FailClosed_RedactionEvaluatedFalse(t *testing.T) {
	// Engine returned 200 with redaction_evaluated:false → redactor did not run.
	srv := checkInputServer(t, `{"allowed":true,"redacted":false,"redaction_evaluated":false}`, nil)
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow([]Obligation{redactObligation()})
	_, did, err := c.FulfillRequest(context.Background(), &decision, "secret a@b.com")
	// The error IS the fail-closed signal; a correct caller never forwards on a
	// non-nil err. didRedact must be false on every fail-closed path.
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
	}
	if did {
		t.Error("didRedact = true on fail-closed path")
	}
}

func TestFulfillRequest_FailClosed_RedactionEvaluatedAbsent(t *testing.T) {
	// Engine response predates the field → defaults false → fail closed.
	srv := checkInputServer(t, `{"allowed":true}`, nil)
	defer srv.Close()

	c := newPEPClient(srv.URL)
	decision := decideAllow([]Obligation{redactObligation()})
	_, did, err := c.FulfillRequest(context.Background(), &decision, "secret a@b.com")
	// The error IS the fail-closed signal; a correct caller never forwards on a
	// non-nil err. didRedact must be false on every fail-closed path.
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
	}
	if did {
		t.Error("didRedact = true on fail-closed path")
	}
}

// ---------------------------------------------------------------------------
// DecideAndFulfill
// ---------------------------------------------------------------------------

func TestDecideAndFulfill_AllowRedacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case decidePath:
			_ = json.NewEncoder(w).Encode(decideAllow([]Obligation{redactObligation()}))
		case requestRedactionPath:
			_, _ = io.WriteString(w, `{"allowed":true,"redacted":true,"redacted_statement":"Email jo****om","redaction_evaluated":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	verdict, content, decision, err := c.DecideAndFulfill(context.Background(), DecideRequest{Stage: "tool", Query: "Email john@x.com"})
	if err != nil {
		t.Fatalf("DecideAndFulfill error: %v", err)
	}
	if verdict != VerdictAllow {
		t.Errorf("verdict = %q, want allow", verdict)
	}
	if content != "Email jo****om" {
		t.Errorf("content = %q, want engine-redacted", content)
	}
	if decision == nil || decision.DecisionID != "dec-1" {
		t.Errorf("decision = %+v", decision)
	}
}

func TestDecideAndFulfill_DenyReturnsOriginalQueryNoFulfill(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == requestRedactionPath {
			t.Error("engine called on a deny verdict")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictDeny, DecisionID: "dec-d", Error: "blocked"})
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	verdict, content, decision, err := c.DecideAndFulfill(context.Background(), DecideRequest{Stage: "tool", Query: "the original query"})
	if err != nil {
		t.Fatalf("DecideAndFulfill error: %v", err)
	}
	if verdict != VerdictDeny {
		t.Errorf("verdict = %q, want deny", verdict)
	}
	if content != "the original query" {
		t.Errorf("content = %q, want original query on deny", content)
	}
	if decision == nil || decision.Verdict != VerdictDeny {
		t.Errorf("decision = %+v", decision)
	}
}

func TestDecideAndFulfill_UnfulfillableReturnsEmptyContent(t *testing.T) {
	// Allow verdict carries a redact_pii obligation, but the engine reports the
	// redactor did not run → unfulfillable → empty content (fail-closed by
	// construction so a caller ignoring err cannot forward the raw query).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case decidePath:
			_ = json.NewEncoder(w).Encode(decideAllow([]Obligation{redactObligation()}))
		case requestRedactionPath:
			_, _ = io.WriteString(w, `{"allowed":true,"redaction_evaluated":false}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	verdict, content, _, err := c.DecideAndFulfill(context.Background(), DecideRequest{Stage: "tool", Query: "secret a@b.com"})
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err = %v, want ErrObligationNotFulfillable", err)
	}
	if content != "" {
		t.Errorf("content = %q, want empty on unfulfillable (no PII leak path)", content)
	}
	if strings.Contains(content, "a@b.com") {
		t.Error("FAIL-CLOSED VIOLATION: PII leaked into DecideAndFulfill content")
	}
	if verdict != VerdictAllow {
		t.Errorf("verdict = %q, want allow (verdict still returned)", verdict)
	}
}

func TestDecideAndFulfill_DecideErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newPEPClient(srv.URL)
	verdict, content, decision, err := c.DecideAndFulfill(context.Background(), DecideRequest{Stage: "tool", Query: "q"})
	if err == nil {
		t.Fatal("expected error when Decide fails")
	}
	if verdict != "" || decision != nil {
		t.Errorf("got verdict=%q decision=%+v, want zero values on decide error", verdict, decision)
	}
	// content is the original query per the reference contract, but the error is
	// non-nil so the caller must not forward.
	if content != "q" {
		t.Errorf("content = %q", content)
	}
}
