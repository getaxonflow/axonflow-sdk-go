//go:build ignore

// runtime-e2e/caller_name_audit/main.go
//
// Real-wire test of AuditToolCallRequest.CallerName (#2912, sub-issue of
// epic #2905) against a real running agent+orchestrator stack.
//
// getaxonflow/axonflow-enterprise PR #2953 (merged, shipped in platform
// v9.11.0) added a `caller_name` field to the orchestrator's tool-call
// audit path alongside the legacy `tool_type` field (kept as a deprecated
// input fallback). The server resolves caller identity as: caller_name if
// supplied -> legacy tool_type if supplied -> a default. #2903 (folded
// into the same #2953 merge) changed that default from the earlier
// "claude_code" to "unknown" — an unidentified caller must not be
// silently attributed to a specific client. This test proves both:
//
//   - the SDK's CallerName field on AuditToolCallRequest actually reaches
//     policy_details.caller_name on a real audit_logs row (not just that
//     it marshals correctly — that's covered by the httptest-based unit
//     tests in audit_test.go);
//   - when a caller supplies NEITHER CallerName nor the legacy ToolType,
//     the persisted row resolves policy_details.caller_name to "unknown"
//     (#2903), not the old "claude_code" default.
//
// Steps:
//  1. Call the real SDK's client.AuditToolCall with CallerName set to a
//     distinctive, non-default value ("e2e-caller-name-probe") and a
//     unique WorkflowID so we can find the resulting row.
//  2. Call it again with neither CallerName nor ToolType set, using a
//     second unique WorkflowID.
//  3. The orchestrator's AuditLogger batches writes (flush every 10s), so
//     poll GET /api/v1/audit/tenant/{tenantID} (the same route
//     GetAuditLogsByTenant hits) until each row lands.
//  4. The SDK's typed AuditLogEntry does not surface policy_details (it's
//     an internal JSONB blob), so this step reads the raw JSON body
//     directly — the only way to observe policy_details.caller_name from
//     outside the platform — and asserts it equals what's expected for
//     each case.
//
// Run via:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	export AXONFLOW_TENANT_ID=<registered tenant/client id>
//	export AXONFLOW_TENANT_SECRET=<its secret>
//	go run runtime-e2e/caller_name_audit/main.go
//
// See ../README.md for how to register a tenant against a local stack.
//
// Deployment-mode caveat: step 3's poll reads GET /api/v1/audit/tenant/{id}.
// In non-community deployment modes that route is scoped by the caller's
// role/identity (resolveCallerReadScope in platform/orchestrator/run.go),
// so a bare Basic-Auth machine caller with no per-user identity sees an
// empty page and this test will time out waiting for its own row — even
// though the row was written correctly. Run this against a stack with
// DEPLOYMENT_MODE=community (isCommunityMode() short-circuits the
// role-scoping), or against an enterprise stack with a per-user identity
// header wired in, to see the assertions actually pass end to end.

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

	// ---- Case 1: CallerName supplied -> policy_details.caller_name echoes it.
	const wantCallerName = "e2e-caller-name-probe"
	workflowIDWithCaller := fmt.Sprintf("e2e-caller-name-%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	resp, err := client.AuditToolCall(ctx, axonflow.AuditToolCallRequest{
		ToolName:   "e2eCallerNameTool",
		CallerName: wantCallerName,
		WorkflowID: workflowIDWithCaller,
	})
	cancel()
	if err != nil {
		fail("SDK AuditToolCall (with CallerName): %v", err)
	}
	fmt.Printf("SDK AuditToolCall recorded → audit_id=%s status=%s\n", resp.AuditID, resp.Status)

	policyDetails := pollForPolicyDetails(endpoint, clientID, secret, workflowIDWithCaller)

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

	// ---- Case 2 (#2903): neither CallerName nor ToolType supplied ->
	// policy_details.caller_name resolves to "unknown", NOT the old
	// "claude_code" default. #2903 was folded into the same #2953 merge
	// that shipped CallerName (platform v9.11.0).
	workflowIDNeither := fmt.Sprintf("e2e-caller-name-neither-%d", time.Now().UnixNano())

	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	resp2, err := client.AuditToolCall(ctx2, axonflow.AuditToolCallRequest{
		ToolName:   "e2eCallerNameDefaultTool",
		WorkflowID: workflowIDNeither,
	})
	cancel2()
	if err != nil {
		fail("SDK AuditToolCall (neither CallerName nor ToolType): %v", err)
	}
	fmt.Printf("SDK AuditToolCall recorded → audit_id=%s status=%s\n", resp2.AuditID, resp2.Status)

	defaultPolicyDetails := pollForPolicyDetails(endpoint, clientID, secret, workflowIDNeither)

	const wantDefaultCallerName = "unknown"
	gotDefaultCallerName, ok := defaultPolicyDetails["caller_name"]
	if !ok {
		fail("policy_details missing caller_name key entirely on the no-identity row: %v", defaultPolicyDetails)
	}
	if gotDefaultCallerName != wantDefaultCallerName {
		fail("policy_details.caller_name (neither CallerName nor ToolType supplied) = %q, want %q (#2903) — full policy_details: %v",
			gotDefaultCallerName, wantDefaultCallerName, defaultPolicyDetails)
	}
	fmt.Printf("PASS: policy_details.caller_name defaults to %q (#2903) when neither CallerName nor ToolType is supplied\n", gotDefaultCallerName)
	fmt.Printf("Wire policy_details: %v\n", defaultPolicyDetails)

	fmt.Println("ALL PASS: CallerName round-trips to policy_details.caller_name, and the no-identity default is \"unknown\" (#2903), not \"claude_code\"")
}

// pollForPolicyDetails polls GET /api/v1/audit/tenant/{tenantID} (the exact
// route GetAuditLogsByTenant uses) until a row with the given workflowID
// (request_id) appears, then returns its policy_details. The orchestrator's
// AuditLogger batch-writes every 10s, so this can take up to that long plus
// write latency. Fails the process on timeout or transport error.
func pollForPolicyDetails(endpoint, clientID, secret, workflowID string) map[string]interface{} {
	deadline := time.Now().Add(25 * time.Second)
	for {
		found, pd, findErr := findAuditRowRaw(endpoint, clientID, secret, workflowID)
		if findErr != nil {
			fail("raw audit/tenant lookup for workflow_id=%s: %v", workflowID, findErr)
		}
		if found {
			return pd
		}
		if time.Now().After(deadline) {
			fail("audit row for workflow_id=%s did not appear within %s (batch flush may not have fired)", workflowID, 25*time.Second)
		}
		time.Sleep(2 * time.Second)
	}
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
