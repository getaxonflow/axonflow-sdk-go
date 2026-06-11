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
		Decision:   "blocked",
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
	if got.Decision != "blocked" {
		t.Errorf("Decision = %q, want 'blocked'", got.Decision)
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

func TestExplainDecision_URLEncodesDecisionID(t *testing.T) {
	// Use RequestURI (raw request line) rather than r.URL.Path (decoded) so
	// we can verify the wire form actually carries escaped bytes.
	var capturedURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecisionExplanation{DecisionID: "a/b", Decision: "allowed"})
	}))
	defer srv.Close()

	c := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: srv.URL},
		httpClient: srv.Client(),
	}
	// Plain slash is enough — PathEscape escapes '/' in a single path segment.
	_, err := c.ExplainDecision(context.Background(), "a/b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedURI, "a%2Fb") {
		t.Errorf("RequestURI = %q, expected URL-encoded decision ID 'a%%2Fb'", capturedURI)
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

// ============================================================================
// list_decisions — Session γ contract tests (#1982)
// ============================================================================

func TestListDecisions_HappyPath(t *testing.T) {
	want := []DecisionSummary{
		{
			DecisionID:    "dec-1",
			Timestamp:     time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
			Decision:      "blocked",
			PolicyID:      "pol-sqli",
			ToolSignature: "postgres.query",
		},
		{
			DecisionID:    "dec-2",
			Timestamp:     time.Date(2026, 5, 7, 11, 0, 0, 0, time.UTC),
			Decision:      "allowed",
			PolicyID:      "pol-default",
			ToolSignature: "github.status",
		},
		{
			DecisionID:    "dec-3",
			Timestamp:     time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC),
			Decision:      "needs_approval",
			PolicyID:      "pol-amount",
			ToolSignature: "stripe.charge",
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/decisions" {
			t.Errorf("Path = %q, want /api/v1/decisions", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"decisions": want})
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	got, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	if got[0].DecisionID != "dec-1" || got[0].Decision != "blocked" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[2].Decision != "needs_approval" {
		t.Errorf("got[2].Decision = %q", got[2].Decision)
	}
}

// TestListDecisions_FilterSerialization asserts every option field
// lands in the URL with stable field order. Easiest miss the brief
// flagged: forgetting to register a new field in the URL builder.
func TestListDecisions_FilterSerialization(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"decisions": []}`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{
		Since:         time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC),
		Decision:      "blocked",
		PolicyID:      "pol-sqli",
		ToolSignature: "postgres.query",
		Limit:         25,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"since=2026-05-07T00%3A00%3A00Z",
		"decision=blocked",
		"policy_id=pol-sqli",
		"tool_signature=postgres.query",
		"limit=25",
	} {
		if !strings.Contains(capturedQuery, want) {
			t.Errorf("query %q missing %q", capturedQuery, want)
		}
	}
}

func TestListDecisions_OmitsUnsetFilters(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"decisions": []}`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{Decision: "blocked"})
	if err != nil {
		t.Fatal(err)
	}
	if capturedQuery != "decision=blocked" {
		t.Errorf("zero-valued fields must be omitted; got %q", capturedQuery)
	}
}

// TestListDecisions_429UpgradeEnvelope asserts the typed RateLimitError
// surfaces with the V1 upgrade fields populated.
func TestListDecisions_429UpgradeEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Axonflow-Tier-Limit", "decision_list_size")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"Free tier shows the last 5 decisions in 24h. Pro raises this to 100 decisions in the last 30 days.","limit_type":"decision_list_size","tier":"Community","limit":5,"remaining":0,"upgrade":{"tier":"Pro","wording":"Free tier shows the last 5 decisions in 24h. Pro raises this to 100 decisions in the last 30 days.","compare_url":"https://getaxonflow.com/pricing/","buy_url":"https://buy.stripe.com/bJe28qbztcdVchjdkw8k800"}}`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{Limit: 10})
	if err == nil {
		t.Fatal("expected error")
	}
	rle, ok := AsRateLimitError(err)
	if !ok {
		t.Fatalf("err = %T, want *RateLimitError; chain = %v", err, err)
	}
	if rle.Envelope.Tier != "Community" {
		t.Errorf("Tier = %q, want Community", rle.Envelope.Tier)
	}
	if rle.Envelope.LimitType != "decision_list_size" {
		t.Errorf("LimitType = %q", rle.Envelope.LimitType)
	}
	if rle.Envelope.Limit != 5 {
		t.Errorf("Limit = %d, want 5", rle.Envelope.Limit)
	}
	if rle.Envelope.Upgrade.Tier != "Pro" || rle.Envelope.Upgrade.CompareURL == "" || rle.Envelope.Upgrade.BuyURL == "" {
		t.Errorf("Upgrade = %+v", rle.Envelope.Upgrade)
	}
}

// TestListDecisions_429MalformedBody — when the platform changes the
// 429 shape and we can't parse the envelope, fall back to *httpError
// rather than silently succeed.
func TestListDecisions_429MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("not a json envelope"))
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := AsRateLimitError(err); ok {
		t.Errorf("malformed body must not parse as RateLimitError")
	}
	httpErr, ok := err.(*httpError)
	if !ok {
		t.Fatalf("err = %T, want *httpError", err)
	}
	if httpErr.statusCode != 429 {
		t.Errorf("statusCode = %d, want 429", httpErr.statusCode)
	}
}

func TestListDecisions_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"X-Tenant-ID header is required"}`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	httpErr, ok := err.(*httpError)
	if !ok {
		t.Fatalf("err = %T, want *httpError", err)
	}
	if httpErr.statusCode != 401 {
		t.Errorf("statusCode = %d, want 401", httpErr.statusCode)
	}
}

// TestListDecisions_ForwardCompat — additive unknown fields in both
// the outer envelope AND inner DecisionSummary parse cleanly.
func TestListDecisions_ForwardCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"decisions": [{
				"decision_id": "dec-fwd",
				"timestamp": "2026-05-07T12:00:00Z",
				"decision": "blocked",
				"policy_id": "pol-x",
				"tool_signature": "tool-x",
				"policy_version": 7,
				"latest_policy_version": 9,
				"arbitrary_unknown": "ignored"
			}],
			"next_cursor": "future_cursor_pagination"
		}`))
	}))
	defer srv.Close()

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: srv.URL}, httpClient: srv.Client()}
	got, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DecisionID != "dec-fwd" {
		t.Errorf("forward-compat parse failed: %+v", got)
	}
}

// TestDecisionSummary_OptionalFieldsRoundTrip — pre-α1 audit rows /
// dynamic-only blocks may not populate policy_id + tool_signature;
// the DecisionSummary type must accept them as zero strings on parse
// AND drop them on re-serialize via omitempty.
func TestDecisionSummary_OptionalFieldsRoundTrip(t *testing.T) {
	raw := []byte(`{"decision_id":"dec-min","timestamp":"2026-05-07T12:00:00Z","decision":"blocked"}`)
	var d DecisionSummary
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.PolicyID != "" || d.ToolSignature != "" {
		t.Errorf("expected zero values; got %+v", d)
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "policy_id") || strings.Contains(s, "tool_signature") {
		t.Errorf("omitempty must drop unset optionals: %s", s)
	}
}

// TestDecisionSummary_ContextRoundTrip — v8.4.0 (platform #2509): the LIST
// row carries the sanitized request context the PEP attached to the decision.
// The map must parse and re-serialize without information loss.
func TestDecisionSummary_ContextRoundTrip(t *testing.T) {
	raw := []byte(`{"decision_id":"dec-ctx","timestamp":"2026-05-30T12:00:00Z","decision":"blocked",` +
		`"context":{"x_ai_agent":"refund-bot","x_session_id":"sess-42","x_leader_identity":"ops-lead"}}`)
	var d DecisionSummary
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Context) != 3 {
		t.Fatalf("expected 3 context keys, got %d (%+v)", len(d.Context), d.Context)
	}
	if d.Context["x_ai_agent"] != "refund-bot" || d.Context["x_session_id"] != "sess-42" {
		t.Errorf("context values not preserved: %+v", d.Context)
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back DecisionSummary
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.Context["x_leader_identity"] != "ops-lead" {
		t.Errorf("round-trip lost context: %s", out)
	}
}

// TestDecisionSummary_ContextOmittedWhenEmpty — a decision with no request
// context (or a pre-v8.4.0 audit row) must keep its original byte-shape:
// omitempty drops the absent map so the wire payload is unchanged.
func TestDecisionSummary_ContextOmittedWhenEmpty(t *testing.T) {
	raw := []byte(`{"decision_id":"dec-noctx","timestamp":"2026-05-30T12:00:00Z","decision":"allowed"}`)
	var d DecisionSummary
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.Context != nil {
		t.Errorf("expected nil context, got %+v", d.Context)
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "context") {
		t.Errorf("omitempty must drop unset context: %s", out)
	}
}

// TestDecisionExplanation_ContextAndTruncated — v8.4.0 (platform #2509): the
// explain payload returns the FULL context map plus the context_truncated flag.
func TestDecisionExplanation_ContextAndTruncated(t *testing.T) {
	raw := []byte(`{"decision_id":"dec-x","timestamp":"2026-05-30T12:00:00Z","decision":"blocked",` +
		`"reason":"pii","override_available":false,"historical_hit_count_session":0,` +
		`"policy_matches":[],"context":{"x_ai_agent":"a","x_session_id":"s"},"context_truncated":true}`)
	var e DecisionExplanation
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Context) != 2 || e.Context["x_ai_agent"] != "a" {
		t.Errorf("explain context not parsed: %+v", e.Context)
	}
	if !e.ContextTruncated {
		t.Errorf("expected context_truncated=true")
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"context_truncated":true`) {
		t.Errorf("context_truncated must serialize when true: %s", out)
	}
}

// TestDecisionExplanation_ContextTruncatedOmittedWhenFalse — the common case
// (nothing dropped) must not emit context_truncated, preserving byte-shape.
func TestDecisionExplanation_ContextTruncatedOmittedWhenFalse(t *testing.T) {
	e := DecisionExplanation{DecisionID: "d", Decision: "allowed"}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "context_truncated") {
		t.Errorf("omitempty must drop context_truncated when false: %s", out)
	}
}
