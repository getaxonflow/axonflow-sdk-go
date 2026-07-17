//go:build ignore

// runtime-e2e/caller_name_audit/main.go
//
// Real-wire test of AuditToolCallRequest.CallerName (#2912, sub-issue of
// epic #2905) against a real running agent+orchestrator stack.
//
// getaxonflow/axonflow-enterprise PR #2953 added a `caller_name` field to
// the orchestrator's tool-call audit path alongside the legacy `tool_type`
// field (kept as a deprecated input fallback). The server resolves caller
// identity as: caller_name if supplied -> legacy tool_type if supplied ->
// a default. This test proves the SDK's new CallerName field on
// AuditToolCallRequest actually reaches policy_details.caller_name on a
// real audit_logs row — not just that it marshals correctly (that's
// covered by the httptest-based unit tests in audit_test.go).
//
// Steps:
//  1. Call the real SDK's client.AuditToolCall with CallerName set to a
//     distinctive, non-default value ("e2e-caller-name-probe") and a
//     unique WorkflowID so we can find the resulting row.
//  2. The orchestrator's AuditLogger batches writes (flush every 10s), so
//     poll GET /api/v1/audit/tenant/{tenantID} (the same route
//     GetAuditLogsByTenant hits) until the row lands.
//  3. The SDK's typed AuditLogEntry does not surface policy_details (it's
//     an internal JSONB blob), so this step reads the raw JSON body
//     directly — the only way to observe policy_details.caller_name from
//     outside the platform — and asserts it equals what we sent.
//
// Run via:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	export AXONFLOW_TENANT_ID=<registered tenant/client id>
//	export AXONFLOW_TENANT_SECRET=<its secret>
//	go run runtime-e2e/caller_name_audit/main.go
//
// See ../README.md for how to register a tenant against a local stack.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	endpoint := getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getenv("AXONFLOW_TENANT_ID", "buku-e-go-e2e")
	secret := getenv("AXONFLOW_TENANT_SECRET", "buku-e-secret")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: secret,
	})

	workflowID := fmt.Sprintf("e2e-caller-name-%d", time.Now().UnixNano())
	const wantCallerName = "e2e-caller-name-probe"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.AuditToolCall(ctx, axonflow.AuditToolCallRequest{
		ToolName:   "e2eCallerNameTool",
		CallerName: wantCallerName,
		WorkflowID: workflowID,
	})
	if err != nil {
		fail("SDK AuditToolCall: %v", err)
	}
	fmt.Printf("SDK AuditToolCall recorded → audit_id=%s status=%s\n", resp.AuditID, resp.Status)

	// The orchestrator's AuditLogger batch-writes every 10s; poll the
	// tenant-audit route (the same one GetAuditLogsByTenant hits) using a
	// raw HTTP call so we can inspect policy_details, which the SDK's
	// typed AuditLogEntry does not expose.
	var policyDetails map[string]interface{}
	deadline := time.Now().Add(25 * time.Second)
	for {
		found, pd, findErr := findAuditRowRaw(endpoint, clientID, secret, workflowID)
		if findErr != nil {
			fail("raw audit/tenant lookup: %v", findErr)
		}
		if found {
			policyDetails = pd
			break
		}
		if time.Now().After(deadline) {
			fail("audit row for workflow_id=%s did not appear within %s (batch flush may not have fired)", workflowID, 25*time.Second)
		}
		time.Sleep(2 * time.Second)
	}

	gotCallerName, ok := policyDetails["caller_name"]
	if !ok {
		fail("policy_details missing caller_name key entirely: %v", policyDetails)
	}
	if gotCallerName != wantCallerName {
		fail("policy_details.caller_name = %q, want %q (full policy_details: %v)", gotCallerName, wantCallerName, policyDetails)
	}
	if _, hasToolType := policyDetails["tool_type"]; hasToolType {
		fail("policy_details.tool_type should no longer be written for new rows once caller_name resolves, but found: %v", policyDetails["tool_type"])
	}

	fmt.Printf("PASS: policy_details.caller_name = %q reached the audit_logs row via the real agent+orchestrator stack\n", gotCallerName)
	fmt.Printf("Wire policy_details: %v\n", policyDetails)
}

// findAuditRowRaw hits GET /api/v1/audit/tenant/{tenantID} directly (the
// exact route GetAuditLogsByTenant uses) and decodes the raw JSON body so
// we can read policy_details, a field the SDK's AuditLogEntry does not
// declare. Returns found=false (no error) if the row hasn't landed yet.
func findAuditRowRaw(endpoint, clientID, secret, workflowID string) (found bool, policyDetails map[string]interface{}, err error) {
	url := fmt.Sprintf("%s/api/v1/audit/tenant/%s?limit=50", endpoint, clientID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	creds := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + secret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("X-Client-ID", clientID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var parsed struct {
		Entries []struct {
			RequestID     string                 `json:"request_id"`
			PolicyDetails map[string]interface{} `json:"policy_details"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, nil, fmt.Errorf("unmarshal audit/tenant response: %w (body: %s)", err, body)
	}

	for _, e := range parsed.Entries {
		if e.RequestID == workflowID {
			return true, e.PolicyDetails, nil
		}
	}
	return false, nil, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
