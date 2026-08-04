//go:build ignore

// runtime-e2e/audit_real_wire_fields/main.go
//
// Real-wire test of the #3254 additive interim on the audit read model
// (getaxonflow/axonflow-enterprise#3254) against a real running
// agent+orchestrator stack.
//
// The 9.x orchestrator serves policy_decision, policy_details and
// response_time_ms on every audit entry (platform/orchestrator/
// audit_logger.go AuditEntry, identical from v9.6.1 through v9.13.0) and
// has NEVER served the seven fields the SDK modeled before this interim
// (query_summary, success, blocked, risk_score, latency_ms,
// policy_violations, metadata). This test proves, through the actual
// user-facing surface (real import, real NewClient, real agent):
//
//   - a row written via the SDK's AuditToolCall comes back through the
//     SDK's SearchAuditLogs with PolicyDecision populated ("allowed")
//     and PolicyDetails carrying the tool_name/caller_name context;
//   - the seven deprecated fiction fields are zero-valued on every real
//     entry returned by the live server - the #3254 claim, observed on
//     the wire rather than asserted from fixtures;
//   - the new `action` search filter round-trips: filtering by the
//     verdict the row landed with returns the row, and filtering by a
//     verdict it did not land with excludes it (proves the server reads
//     `action`; the deprecated search-request `request_type` is known to
//     be ignored server-side, which is why it is deprecated).
//
// Run via:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	export AXONFLOW_TENANT_ID=<registered tenant/client id>
//	export AXONFLOW_TENANT_SECRET=<its secret>
//	go run runtime-e2e/audit_real_wire_fields/main.go
//
// See ../README.md for how to register a tenant against a local stack.
//
// Deployment-mode caveat: audit search reads are tenant-scoped off the
// caller's auth-derived identity. Write and read with the SAME
// credentials or the row will not be visible to the search (same class
// as the caller_name_audit suite's scoping caveat). The orchestrator's
// AuditLogger batches writes (flush every ~10s), so the search polls.
package main

import (
	"context"
	"fmt"
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
	ctx := context.Background()

	toolName := fmt.Sprintf("e2e_3254_wire_fields_%d", time.Now().UnixNano())
	ok := true
	wr, err := client.AuditToolCall(ctx, axonflow.AuditToolCallRequest{
		ToolName:   toolName,
		CallerName: "e2e-3254-probe",
		DurationMs: 137,
		Success:    &ok,
	})
	if err != nil {
		fail("AuditToolCall write failed: %v", err)
	}
	fmt.Printf("wrote audit row: audit_id=%s status=%s tool=%s\n", wr.AuditID, wr.Status, toolName)

	// 1) Poll the SDK's own SearchAuditLogs until the row lands.
	entry := pollForEntry(ctx, client, toolName, nil)
	fmt.Printf("row visible via SearchAuditLogs: id=%s\n", entry.ID)

	// 2) The new real-wire fields must populate on the live row.
	if entry.PolicyDecision != "allowed" {
		fail("PolicyDecision = %q, want \"allowed\" on a successful tool call", entry.PolicyDecision)
	}
	if entry.PolicyDetails == nil {
		fail("PolicyDetails is nil, want the verdict-context object")
	}
	if got := entry.PolicyDetails["tool_name"]; got != toolName {
		fail("PolicyDetails[tool_name] = %v, want %s", got, toolName)
	}
	if got := entry.PolicyDetails["caller_name"]; got != "e2e-3254-probe" {
		fail("PolicyDetails[caller_name] = %v, want e2e-3254-probe", got)
	}
	fmt.Printf("real fields populated: policy_decision=%q policy_details keys ok response_time_ms=%d\n",
		entry.PolicyDecision, entry.ResponseTimeMs)

	// 3) The seven deprecated fiction fields must be zero-valued on
	// EVERY live entry - the server has never sent them on the 9.x line.
	res, err := client.SearchAuditLogs(ctx, &axonflow.AuditSearchRequest{Limit: 50})
	if err != nil {
		fail("SearchAuditLogs failed: %v", err)
	}
	for _, e := range res.Entries {
		if e.QuerySummary != "" || e.Success || e.Blocked || e.RiskScore != 0 ||
			e.LatencyMs != 0 || e.PolicyViolations != nil || e.Metadata != nil {
			fail("entry %s: a deprecated fiction field is non-zero on a real server response: %+v", e.ID, e)
		}
	}
	fmt.Printf("fiction fields zero-valued across %d live entries\n", len(res.Entries))

	// 4) The `action` filter is read by the server: filtering by the
	// verdict this row landed with must return it; filtering by a
	// verdict it did not land with must exclude it.
	allowed := pollForEntry(ctx, client, toolName, &axonflow.AuditSearchRequest{Action: "allowed", Limit: 50})
	fmt.Printf("action=allowed returns the row: id=%s\n", allowed.ID)

	blockedRes, err := client.SearchAuditLogs(ctx, &axonflow.AuditSearchRequest{Action: "blocked", Limit: 50})
	if err != nil {
		fail("SearchAuditLogs action=blocked failed: %v", err)
	}
	for _, e := range blockedRes.Entries {
		if e.PolicyDetails != nil && e.PolicyDetails["tool_name"] == toolName {
			fail("action=blocked returned the allowed-verdict row %s - the server did not filter by action", e.ID)
		}
	}
	fmt.Println("action=blocked excludes the allowed-verdict row")

	fmt.Println("PASS: audit_real_wire_fields")
}

// pollForEntry searches (with optional extra filters) until an entry
// whose policy_details.tool_name matches toolName appears, or times out.
func pollForEntry(ctx context.Context, client *axonflow.AxonFlowClient, toolName string, req *axonflow.AuditSearchRequest) axonflow.AuditLogEntry {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		search := &axonflow.AuditSearchRequest{Limit: 50}
		if req != nil {
			search = req
		}
		res, err := client.SearchAuditLogs(ctx, search)
		if err != nil {
			fail("SearchAuditLogs failed while polling: %v", err)
		}
		for _, e := range res.Entries {
			if e.PolicyDetails != nil && e.PolicyDetails["tool_name"] == toolName {
				return e
			}
		}
		time.Sleep(3 * time.Second)
	}
	fail("timed out waiting for audit row with tool_name=%s (filters=%+v)", toolName, req)
	return axonflow.AuditLogEntry{}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
