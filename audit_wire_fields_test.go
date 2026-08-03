// Tests for the #3254 additive interim on the audit read model:
// real 9.x wire fields (policy_decision, policy_details, response_time_ms,
// search-side action) parse, and the seven deprecated fiction fields stay
// tolerated without collision.
//
// Fixture provenance:
//   - testdata/audit_search_live_v9130.json is a REAL capture: raw
//     POST /api/v1/audit/search response captured 2026-08-03 from an
//     isolated community v9.13.0 stack (session 3254, compose project
//     s3254, agent proxy with demo credentials). Copied verbatim.
//   - testdata/audit_search_old_server.json is a HAND-MODIFIED variant of
//     that capture with policy_decision/policy_details/response_time_ms
//     removed, simulating an old server that does not send them.
//   - testdata/audit_search_both_present.json is a HAND-MODIFIED variant
//     of that capture with the seven fiction fields injected alongside
//     the real fields (and response_time_ms made non-zero), proving both
//     generations parse side by side with no collision.
package axonflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func loadAuditFixture(t *testing.T, path string) AuditSearchResponse {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var resp AuditSearchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return resp
}

// TestAuditLogEntryParsesRealCapture deserializes the real v9.13.0
// capture: the three new fields must be populated where the server sent
// them, and the seven fiction fields must be zero-valued because the
// server never sends them.
func TestAuditLogEntryParsesRealCapture(t *testing.T) {
	resp := loadAuditFixture(t, "testdata/audit_search_live_v9130.json")
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries in the live capture, got %d", len(resp.Entries))
	}

	errEntry := resp.Entries[0]
	if errEntry.PolicyDecision != "error" {
		t.Errorf("entry 0: PolicyDecision = %q, want %q (open string set, not an enum)", errEntry.PolicyDecision, "error")
	}
	if errEntry.PolicyDetails == nil {
		t.Fatal("entry 0: PolicyDetails is nil, want populated map")
	}
	if got := errEntry.PolicyDetails["error_message"]; got != "blocked by policy sys_sqli_or_true" {
		t.Errorf("entry 0: PolicyDetails[error_message] = %v, want the captured policy error", got)
	}
	if got := errEntry.PolicyDetails["tool_name"]; got != "s3254_blocked_probe" {
		t.Errorf("entry 0: PolicyDetails[tool_name] = %v, want s3254_blocked_probe", got)
	}

	okEntry := resp.Entries[1]
	if okEntry.PolicyDecision != "allowed" {
		t.Errorf("entry 1: PolicyDecision = %q, want %q", okEntry.PolicyDecision, "allowed")
	}
	if okEntry.PolicyDetails == nil {
		t.Fatal("entry 1: PolicyDetails is nil, want populated map")
	}
	if got := okEntry.PolicyDetails["success"]; got != true {
		t.Errorf("entry 1: PolicyDetails[success] = %v, want true", got)
	}

	// The real read-model fields around them keep parsing.
	for i, e := range resp.Entries {
		if e.RequestType != "tool_call_audit" {
			t.Errorf("entry %d: RequestType = %q, want tool_call_audit", i, e.RequestType)
		}
		if e.ID == "" || e.Timestamp.IsZero() || e.TenantID != "community" {
			t.Errorf("entry %d: real fields did not parse: id=%q ts=%v tenant=%q", i, e.ID, e.Timestamp, e.TenantID)
		}
		// response_time_ms is 0 on these tool-call rows in the capture;
		// it must parse without error (non-zero parsing is proven by the
		// both-present fixture and the live-stack probe).
		if e.ResponseTimeMs != 0 {
			t.Errorf("entry %d: ResponseTimeMs = %d, capture carries 0", i, e.ResponseTimeMs)
		}
		// The seven fiction fields are ABSENT from the real wire and
		// must come back zero-valued.
		if e.QuerySummary != "" || e.Success || e.Blocked || e.RiskScore != 0 ||
			e.LatencyMs != 0 || e.PolicyViolations != nil || e.Metadata != nil {
			t.Errorf("entry %d: a deprecated fiction field is non-zero against the real capture: %+v", i, e)
		}
	}
}

// TestAuditLogEntryOldServerTolerance parses the hand-modified variant
// with the three new fields removed: absence must be tolerated and the
// new fields must default to zero values.
func TestAuditLogEntryOldServerTolerance(t *testing.T) {
	resp := loadAuditFixture(t, "testdata/audit_search_old_server.json")
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}
	for i, e := range resp.Entries {
		if e.PolicyDecision != "" {
			t.Errorf("entry %d: PolicyDecision = %q, want empty default", i, e.PolicyDecision)
		}
		if e.PolicyDetails != nil {
			t.Errorf("entry %d: PolicyDetails = %v, want nil default", i, e.PolicyDetails)
		}
		if e.ResponseTimeMs != 0 {
			t.Errorf("entry %d: ResponseTimeMs = %d, want 0 default", i, e.ResponseTimeMs)
		}
		if e.ID == "" || e.RequestType != "tool_call_audit" {
			t.Errorf("entry %d: existing fields must keep parsing: id=%q type=%q", i, e.ID, e.RequestType)
		}
	}
}

// TestAuditLogEntryFictionAndRealCoexist parses the hand-modified variant
// carrying BOTH the deprecated fiction fields and the real wire fields:
// both generations must parse with no collision.
func TestAuditLogEntryFictionAndRealCoexist(t *testing.T) {
	resp := loadAuditFixture(t, "testdata/audit_search_both_present.json")
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}
	wantDecisions := []string{"error", "allowed"}
	for i, e := range resp.Entries {
		if e.PolicyDecision != wantDecisions[i] {
			t.Errorf("entry %d: PolicyDecision = %q, want %q", i, e.PolicyDecision, wantDecisions[i])
		}
		if e.PolicyDetails == nil {
			t.Errorf("entry %d: PolicyDetails is nil, want populated", i)
		}
		if want := int64(1234 + i); e.ResponseTimeMs != want {
			t.Errorf("entry %d: ResponseTimeMs = %d, want %d", i, e.ResponseTimeMs, want)
		}
		if e.QuerySummary != "fictional summary" || !e.Success || !e.Blocked ||
			e.RiskScore != 0.85 || e.LatencyMs != 999 ||
			len(e.PolicyViolations) != 1 || e.Metadata == nil {
			t.Errorf("entry %d: deprecated fields must still parse when present: %+v", i, e)
		}
	}
}

// TestSearchAuditLogsSendsActionAndDeprecatedRequestType asserts the
// search body carries the new server-read `action` filter and, for the
// interim, still carries the deprecated `request_type` (harmless, the
// 9.x server ignores it; dropped at the next major, #3254).
func TestSearchAuditLogsSendsActionAndDeprecatedRequestType(t *testing.T) {
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]AuditLogEntry{})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	_, err := client.SearchAuditLogs(context.Background(), &AuditSearchRequest{
		Action:      "blocked",
		RequestType: "tool_call_audit",
	})
	if err != nil {
		t.Fatalf("SearchAuditLogs failed: %v", err)
	}
	if gotBody["action"] != "blocked" {
		t.Errorf("request body action = %v, want %q", gotBody["action"], "blocked")
	}
	if gotBody["request_type"] != "tool_call_audit" {
		t.Errorf("request body request_type = %v, want it still sent in the interim", gotBody["request_type"])
	}
}
