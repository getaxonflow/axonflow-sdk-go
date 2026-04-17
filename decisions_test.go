package axonflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExplainDecision_RequiresDecisionID(t *testing.T) {
	c := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: "http://test"},
		httpClient: &http.Client{},
	}
	_, err := c.ExplainDecision(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty decision ID")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error message = %q, want substring 'required'", err.Error())
	}
}

func TestExplainDecision_HappyPath(t *testing.T) {
	want := DecisionExplanation{
		DecisionID: "dec_wf1_step2",
		Timestamp:  time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		Decision:   "deny",
		Reason:     "SQL injection detected",
		RiskLevel:  "high",
		PolicyMatches: []ExplainPolicy{
			{
				PolicyID:      "pol-sqli",
				PolicyName:    "SQL Injection Detector",
				Action:        "deny",
				RiskLevel:     "high",
				AllowOverride: true,
			},
		},
		OverrideAvailable:         true,
		HistoricalHitCountSession: 3,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/decisions/dec_wf1_step2/explain" {
			t.Errorf("Path = %q, want '/api/v1/decisions/dec_wf1_step2/explain'", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: srv.URL},
		httpClient: srv.Client(),
	}
	got, err := c.ExplainDecision(context.Background(), "dec_wf1_step2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.DecisionID != want.DecisionID {
		t.Errorf("DecisionID = %q, want %q", got.DecisionID, want.DecisionID)
	}
	if got.Decision != "deny" {
		t.Errorf("Decision = %q, want 'deny'", got.Decision)
	}
	if len(got.PolicyMatches) != 1 {
		t.Fatalf("PolicyMatches length = %d, want 1", len(got.PolicyMatches))
	}
	if got.PolicyMatches[0].PolicyID != "pol-sqli" {
		t.Errorf("PolicyMatches[0].PolicyID = %q", got.PolicyMatches[0].PolicyID)
	}
	if !got.OverrideAvailable {
		t.Error("OverrideAvailable = false, want true")
	}
	if got.HistoricalHitCountSession != 3 {
		t.Errorf("HistoricalHitCountSession = %d, want 3", got.HistoricalHitCountSession)
	}
}

func TestExplainDecision_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Decision not found"}`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: srv.URL},
		httpClient: srv.Client(),
	}
	_, err := c.ExplainDecision(context.Background(), "dec-missing")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestExplainDecision_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: srv.URL},
		httpClient: srv.Client(),
	}
	_, err := c.ExplainDecision(context.Background(), "dec-x")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestExplainDecision_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	c := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: srv.URL},
		httpClient: srv.Client(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.ExplainDecision(ctx, "dec-x")
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestAuditSearchRequest_NewFiltersSerialize(t *testing.T) {
	// Confirm the three new filters serialize correctly in JSON.
	req := AuditSearchRequest{
		DecisionID: "dec-abc",
		PolicyName: "SQL Injection Detector",
		OverrideID: "ov-xyz",
		Limit:      50,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"decision_id":"dec-abc"`, `"policy_name":"SQL Injection Detector"`, `"override_id":"ov-xyz"`} {
		if !strings.Contains(s, want) {
			t.Errorf("serialized JSON missing %q: %s", want, s)
		}
	}
}
