package axonflow

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test a: First-call response shape.
// gate_count == 1, prior_completion_status == "none", first_attempt_at == last_attempt_at,
// last_decision == decision.
func TestStepGate_RetryContext_FirstCall(t *testing.T) {
	now := "2026-04-21T15:30:45.123Z"
	resp := map[string]interface{}{
		"decision":        "allow",
		"step_id":         "step_1",
		"cached":          false,
		"decision_source": "fresh",
		"retry_context": map[string]interface{}{
			"gate_count":              1,
			"completion_count":        0,
			"prior_completion_status": "none",
			"prior_output_available":  false,
			"prior_output":            nil,
			"prior_completion_at":     nil,
			"first_attempt_at":        now,
			"last_attempt_at":         now,
			"last_decision":           "allow",
			"idempotency_key":         "",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "" {
			t.Errorf("Expected no query params on default gate, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})

	gate, err := client.StepGate("wf_1", "step_1", StepGateRequest{StepType: StepTypeLLMCall})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rc := gate.RetryContext
	if rc.GateCount != 1 {
		t.Errorf("GateCount = %d, want 1", rc.GateCount)
	}
	if rc.CompletionCount != 0 {
		t.Errorf("CompletionCount = %d, want 0", rc.CompletionCount)
	}
	if rc.PriorCompletionStatus != PriorCompletionStatusNone {
		t.Errorf("PriorCompletionStatus = %q, want %q", rc.PriorCompletionStatus, PriorCompletionStatusNone)
	}
	if rc.PriorOutputAvailable {
		t.Errorf("PriorOutputAvailable = true, want false")
	}
	if rc.PriorOutput != nil {
		t.Errorf("PriorOutput = %v, want nil", rc.PriorOutput)
	}
	if rc.PriorCompletionAt != nil {
		t.Errorf("PriorCompletionAt = %v, want nil", rc.PriorCompletionAt)
	}
	if !rc.FirstAttemptAt.Equal(rc.LastAttemptAt) {
		t.Errorf("FirstAttemptAt (%s) != LastAttemptAt (%s) on first call", rc.FirstAttemptAt, rc.LastAttemptAt)
	}
	if rc.LastDecision != GateDecisionAllow {
		t.Errorf("LastDecision = %q, want %q on first call", rc.LastDecision, GateDecisionAllow)
	}
	if rc.IdempotencyKey != "" {
		t.Errorf("IdempotencyKey = %q, want empty", rc.IdempotencyKey)
	}
}

// Test b: Second-call after completion.
// gate_count == 2, completion_count == 1, prior_completion_status == "completed",
// prior_output_available == true.
func TestStepGate_RetryContext_SecondCallAfterCompletion(t *testing.T) {
	first := "2026-04-21T15:30:00.000Z"
	now := "2026-04-21T15:31:00.000Z"
	completedAt := "2026-04-21T15:30:30.000Z"
	resp := map[string]interface{}{
		"decision": "allow",
		"step_id":  "step_1",
		"retry_context": map[string]interface{}{
			"gate_count":              2,
			"completion_count":        1,
			"prior_completion_status": "completed",
			"prior_output_available":  true,
			"prior_output":            nil,
			"prior_completion_at":     completedAt,
			"first_attempt_at":        first,
			"last_attempt_at":         now,
			"last_decision":           "allow",
			"idempotency_key":         "",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})
	gate, err := client.StepGate("wf_1", "step_1", StepGateRequest{StepType: StepTypeLLMCall})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rc := gate.RetryContext
	if rc.GateCount != 2 {
		t.Errorf("GateCount = %d, want 2", rc.GateCount)
	}
	if rc.CompletionCount != 1 {
		t.Errorf("CompletionCount = %d, want 1", rc.CompletionCount)
	}
	if rc.PriorCompletionStatus != PriorCompletionStatusCompleted {
		t.Errorf("PriorCompletionStatus = %q, want %q", rc.PriorCompletionStatus, PriorCompletionStatusCompleted)
	}
	if !rc.PriorOutputAvailable {
		t.Errorf("PriorOutputAvailable = false, want true")
	}
	if rc.PriorCompletionAt == nil {
		t.Fatal("PriorCompletionAt = nil, want non-nil")
	}
	if rc.FirstAttemptAt.Equal(rc.LastAttemptAt) {
		t.Errorf("FirstAttemptAt should differ from LastAttemptAt on second call")
	}
}

// Test c: Second-call without completion.
// gate_count == 2, completion_count == 0, prior_completion_status == "gated_not_completed",
// prior_output_available == false.
func TestStepGate_RetryContext_SecondCallWithoutCompletion(t *testing.T) {
	resp := map[string]interface{}{
		"decision": "allow",
		"step_id":  "step_1",
		"retry_context": map[string]interface{}{
			"gate_count":              2,
			"completion_count":        0,
			"prior_completion_status": "gated_not_completed",
			"prior_output_available":  false,
			"prior_output":            nil,
			"prior_completion_at":     nil,
			"first_attempt_at":        "2026-04-21T15:30:00.000Z",
			"last_attempt_at":         "2026-04-21T15:31:00.000Z",
			"last_decision":           "allow",
			"idempotency_key":         "",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})
	gate, err := client.StepGate("wf_1", "step_1", StepGateRequest{StepType: StepTypeLLMCall})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	rc := gate.RetryContext
	if rc.GateCount != 2 {
		t.Errorf("GateCount = %d, want 2", rc.GateCount)
	}
	if rc.CompletionCount != 0 {
		t.Errorf("CompletionCount = %d, want 0", rc.CompletionCount)
	}
	if rc.PriorCompletionStatus != PriorCompletionStatusGatedNotCompleted {
		t.Errorf("PriorCompletionStatus = %q, want %q", rc.PriorCompletionStatus, PriorCompletionStatusGatedNotCompleted)
	}
	if rc.PriorOutputAvailable {
		t.Errorf("PriorOutputAvailable = true, want false")
	}
	if rc.PriorCompletionAt != nil {
		t.Errorf("PriorCompletionAt = %v, want nil", rc.PriorCompletionAt)
	}
}

// Test d: include_prior_output=true populates prior_output when available.
func TestStepGate_IncludePriorOutput_QueryParamAndPayload(t *testing.T) {
	priorOutput := map[string]interface{}{"result": "ok", "score": 0.92}
	var gotIncludeFlag bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIncludeFlag = r.URL.Query().Get("include_prior_output") == "true"
		payload := map[string]interface{}{
			"decision": "allow",
			"step_id":  "step_1",
			"retry_context": map[string]interface{}{
				"gate_count":              2,
				"completion_count":        1,
				"prior_completion_status": "completed",
				"prior_output_available":  true,
				"prior_output":            priorOutput,
				"prior_completion_at":     "2026-04-21T15:30:30.000Z",
				"first_attempt_at":        "2026-04-21T15:30:00.000Z",
				"last_attempt_at":         "2026-04-21T15:31:00.000Z",
				"last_decision":           "allow",
				"idempotency_key":         "",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})

	gate, err := client.StepGateWithOptions(
		"wf_1", "step_1",
		StepGateRequest{StepType: StepTypeLLMCall},
		StepGateOptions{IncludePriorOutput: true},
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !gotIncludeFlag {
		t.Error("Expected include_prior_output=true to be sent on query string")
	}
	if gate.RetryContext.PriorOutput == nil {
		t.Fatal("Expected prior_output to be populated, got nil")
	}
	if got, ok := gate.RetryContext.PriorOutput["result"].(string); !ok || got != "ok" {
		t.Errorf("Expected prior_output.result = \"ok\", got %v", gate.RetryContext.PriorOutput["result"])
	}
}

// Test e: Idempotency key round-trip — pass on gate, echoed on retry_context.idempotency_key,
// same key required on /complete.
func TestStepGate_IdempotencyKey_RoundTrip(t *testing.T) {
	const key = "payment:wire:acct4471:invoice-7721"
	var gotGateKey, gotCompleteKey string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/workflows/wf_1/steps/step_1/gate", func(w http.ResponseWriter, r *http.Request) {
		var req StepGateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode gate request: %v", err)
		}
		gotGateKey = req.IdempotencyKey
		payload := map[string]interface{}{
			"decision": "allow",
			"step_id":  "step_1",
			"retry_context": map[string]interface{}{
				"gate_count":              1,
				"completion_count":        0,
				"prior_completion_status": "none",
				"prior_output_available":  false,
				"prior_output":            nil,
				"prior_completion_at":     nil,
				"first_attempt_at":        "2026-04-21T15:30:00.000Z",
				"last_attempt_at":         "2026-04-21T15:30:00.000Z",
				"last_decision":           "allow",
				"idempotency_key":         key,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	})
	mux.HandleFunc("/api/v1/workflows/wf_1/steps/step_1/complete", func(w http.ResponseWriter, r *http.Request) {
		var req MarkStepCompletedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode complete request: %v", err)
		}
		gotCompleteKey = req.IdempotencyKey
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})

	gate, err := client.StepGate("wf_1", "step_1", StepGateRequest{
		StepType:       StepTypeLLMCall,
		IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("Unexpected gate error: %v", err)
	}
	if gotGateKey != key {
		t.Errorf("Gate request idempotency_key = %q, want %q", gotGateKey, key)
	}
	if gate.RetryContext.IdempotencyKey != key {
		t.Errorf("Response retry_context.idempotency_key = %q, want %q", gate.RetryContext.IdempotencyKey, key)
	}

	if err := client.MarkStepCompleted("wf_1", "step_1", &MarkStepCompletedRequest{
		Output:         map[string]interface{}{"ok": true},
		IdempotencyKey: key,
	}); err != nil {
		t.Fatalf("Unexpected complete error: %v", err)
	}
	if gotCompleteKey != key {
		t.Errorf("Complete request idempotency_key = %q, want %q", gotCompleteKey, key)
	}
}

// Test f: 409 IDEMPOTENCY_KEY_MISMATCH maps to typed *IdempotencyKeyMismatchError.
func TestMarkStepCompleted_IdempotencyMismatch_TypedError(t *testing.T) {
	body := `{
      "error": {
        "code": "IDEMPOTENCY_KEY_MISMATCH",
        "message": "idempotency_key on complete does not match the key recorded on gate",
        "details": {
          "workflow_id": "wf_41231a72",
          "step_id": "step-2",
          "expected_idempotency_key": "payment:wire:acct4471:invoice-7721",
          "received_idempotency_key": "payment:wire:acct4471:invoice-9999"
        }
      }
    }`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})

	err := client.MarkStepCompleted("wf_41231a72", "step-2", &MarkStepCompletedRequest{
		IdempotencyKey: "payment:wire:acct4471:invoice-9999",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	var idemErr *IdempotencyKeyMismatchError
	if !errors.As(err, &idemErr) {
		t.Fatalf("Expected *IdempotencyKeyMismatchError, got %T: %v", err, err)
	}
	if idemErr.WorkflowID != "wf_41231a72" {
		t.Errorf("WorkflowID = %q, want wf_41231a72", idemErr.WorkflowID)
	}
	if idemErr.StepID != "step-2" {
		t.Errorf("StepID = %q, want step-2", idemErr.StepID)
	}
	if idemErr.ExpectedIdempotencyKey != "payment:wire:acct4471:invoice-7721" {
		t.Errorf("ExpectedIdempotencyKey = %q", idemErr.ExpectedIdempotencyKey)
	}
	if idemErr.ReceivedIdempotencyKey != "payment:wire:acct4471:invoice-9999" {
		t.Errorf("ReceivedIdempotencyKey = %q", idemErr.ReceivedIdempotencyKey)
	}
}

// Also surface 409 on the gate call path.
func TestStepGate_IdempotencyMismatch_TypedError(t *testing.T) {
	body := `{"error":{"code":"IDEMPOTENCY_KEY_MISMATCH","message":"mismatch","details":{"workflow_id":"wf_1","step_id":"s1","expected_idempotency_key":"a","received_idempotency_key":"b"}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "t"})
	_, err := client.StepGate("wf_1", "s1", StepGateRequest{
		StepType:       StepTypeLLMCall,
		IdempotencyKey: "b",
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	var idemErr *IdempotencyKeyMismatchError
	if !errors.As(err, &idemErr) {
		t.Fatalf("Expected *IdempotencyKeyMismatchError, got %T: %v", err, err)
	}
	if idemErr.ExpectedIdempotencyKey != "a" || idemErr.ReceivedIdempotencyKey != "b" {
		t.Errorf("unexpected keys: expected=%q received=%q", idemErr.ExpectedIdempotencyKey, idemErr.ReceivedIdempotencyKey)
	}
}

// Sanity: ensure timestamps round-trip to time.Time as expected.
func TestRetryContext_TimestampsDecodeToTime(t *testing.T) {
	raw := `{
      "gate_count": 1,
      "completion_count": 0,
      "prior_completion_status": "none",
      "prior_output_available": false,
      "prior_output": null,
      "prior_completion_at": null,
      "first_attempt_at": "2026-04-21T15:30:45.123Z",
      "last_attempt_at": "2026-04-21T15:30:45.123Z",
      "last_decision": "allow",
      "idempotency_key": ""
    }`
	var rc RetryContext
	if err := json.Unmarshal([]byte(raw), &rc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2026-04-21T15:30:45.123Z")
	if !rc.FirstAttemptAt.Equal(want) {
		t.Errorf("FirstAttemptAt = %v, want %v", rc.FirstAttemptAt, want)
	}
}
