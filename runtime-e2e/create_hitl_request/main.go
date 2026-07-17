//go:build ignore

// runtime-e2e/create_hitl_request/main.go
//
// Real-wire test of the SDK's CreateHITLRequest method
// (getaxonflow/axonflow-enterprise#2421). Spins up a tiny in-process
// HTTP server that mimics the platform handler at
// platform/agent/hitl/handler.go:177, drives client.CreateHITLRequest
// against it through the real net/http transport, then asserts the
// captured request body carries every required field plus the new
// notify_url surface added in
// getaxonflow/axonflow-enterprise#2419.
//
// No httptest, no test doubles — real net.Listen + http.Serve on both
// sides. Satisfies the runtime-e2e/ DoD gate that the unit suite under
// hitl_test.go (httptest-based) does not.
//
// Run via:
//
//	go run runtime-e2e/create_hitl_request/main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

const notifyURL = "https://workflows.example.com/hooks/runtime-e2e"

func main() {
	var capturedBody atomic.Value
	capturedBody.Store([]byte{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/hitl/queue" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		capturedBody.Store(body)
		var in axonflow.HITLCreateInput
		if err := json.Unmarshal(body, &in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": axonflow.HITLApprovalRequest{
				RequestID:           "hitl-req-runtime-e2e-001",
				OrgID:               "org-runtime-e2e",
				TenantID:            "tenant-runtime-e2e",
				ClientID:            in.ClientID,
				UserID:              in.UserID,
				OriginalQuery:       in.OriginalQuery,
				RequestType:         in.RequestType,
				RequestContext:      in.RequestContext,
				TriggeredPolicyID:   in.TriggeredPolicyID,
				TriggeredPolicyName: in.TriggeredPolicyName,
				TriggerReason:       in.TriggerReason,
				Severity:            in.Severity,
				NotifyURL:           in.NotifyURL,
				Status:              "pending",
				ExpiresAt:           "2026-05-23T11:00:00Z",
				CreatedAt:           "2026-05-23T10:00:00Z",
				UpdatedAt:           "2026-05-23T10:00:00Z",
			},
		})
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Shutdown(context.Background())

	endpoint := "http://" + listener.Addr().String()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     "runtime-e2e",
		ClientSecret: "runtime-e2e-secret",
		Mode:         "production",
	})

	req, err := client.CreateHITLRequest(axonflow.HITLCreateInput{
		ClientID:            "runtime-e2e-client",
		UserID:              "runtime-e2e-user",
		OriginalQuery:       "disburse $50000 to cust-runtime-e2e",
		RequestType:         "adk-tool",
		RequestContext:      map[string]interface{}{"tool_name": "disburse_payment"},
		TriggeredPolicyID:   "loan-amount-cap",
		TriggeredPolicyName: "Loan amount cap",
		TriggerReason:       "Disbursement above $10k requires manager approval",
		Severity:            "high",
		NotifyURL:           notifyURL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: CreateHITLRequest returned error: %v\n", err)
		os.Exit(1)
	}

	body := capturedBody.Load().([]byte)
	if len(body) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: server captured no body")
		os.Exit(1)
	}

	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: wire body not valid JSON: %v\n%s\n", err, body)
		os.Exit(1)
	}

	expected := map[string]string{
		"client_id":             "runtime-e2e-client",
		"user_id":               "runtime-e2e-user",
		"original_query":        "disburse $50000 to cust-runtime-e2e",
		"request_type":          "adk-tool",
		"triggered_policy_id":   "loan-amount-cap",
		"triggered_policy_name": "Loan amount cap",
		"trigger_reason":        "Disbursement above $10k requires manager approval",
		"severity":              "high",
		"notify_url":            notifyURL,
	}
	for field, want := range expected {
		got, _ := wire[field].(string)
		if got != want {
			fmt.Fprintf(os.Stderr, "FAIL: wire body field %q = %q, want %q\nFull body: %s\n", field, got, want, body)
			os.Exit(1)
		}
	}
	if req.RequestID != "hitl-req-runtime-e2e-001" {
		fmt.Fprintf(os.Stderr, "FAIL: parsed RequestID = %q\n", req.RequestID)
		os.Exit(1)
	}
	if req.NotifyURL != notifyURL {
		fmt.Fprintf(os.Stderr, "FAIL: parsed NotifyURL = %q, want %q\n", req.NotifyURL, notifyURL)
		os.Exit(1)
	}

	fmt.Println("PASS: CreateHITLRequest wire payload + response parsing round-trip OK")
	fmt.Printf("Wire body: %s\n", body)
	fmt.Printf("Parsed RequestID=%s NotifyURL=%s\n", req.RequestID, req.NotifyURL)
}
