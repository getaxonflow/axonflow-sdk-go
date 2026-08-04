// Tests for the #3254 pin-advance batch on the masfeat/OJK models:
// real 9.x wire fields (RegistrySummary counts, KillSwitch
// trigger_reason/restore_reason, OJK export summary, OJK breach real
// spellings) parse, the deprecated fiction fields stay zero-valued
// against server-shaped payloads, and old servers omitting the new
// fields are tolerated.
//
// Fixture provenance: every testdata/*_source_derived.json fixture is
// SOURCE-DERIVED from the server structs at community v9.13.0
// (df027c788) - platform/orchestrator/masfeat/types.go and
// platform/orchestrator/ojk/types.go. They are NOT live captures: the
// s3254 community stack gates the masfeat/OJK routes (enterprise
// modules), so no capture is obtainable there; see the PR body for the
// live-leg attempt and its result.
package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// serveFixture returns a client wired to an httptest server that
// answers every request with the named fixture, so deserialization is
// exercised through the REAL method path (auth headers, status
// handling, unmarshal), not a bare json.Unmarshal.
func serveFixture(t *testing.T, path string) (*AxonFlowClient, func()) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	return client, server.Close
}

// stripKeys returns a copy of the fixture with the listed keys removed,
// simulating an old server that predates those fields.
func stripKeys(t *testing.T, path string, keys ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	for _, k := range keys {
		delete(m, k)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal fixture: %v", err)
	}
	return out
}

func TestRegistrySummaryParsesRealWireShape(t *testing.T) {
	client, done := serveFixture(t, "testdata/masfeat_registry_summary_source_derived.json")
	defer done()

	got, err := client.MASFEATGetRegistrySummary()
	if err != nil {
		t.Fatalf("MASFEATGetRegistrySummary: %v", err)
	}
	// The real 9.x fields populate.
	if got.OrgID != "org-s3254" || got.TotalSystems != 12 || got.ActiveSystems != 9 {
		t.Errorf("real scalar fields did not parse: %+v", got)
	}
	if got.HighMateriality != 3 || got.MediumMateriality != 4 || got.LowMateriality != 5 {
		t.Errorf("materiality counts did not parse: high=%d med=%d low=%d",
			got.HighMateriality, got.MediumMateriality, got.LowMateriality)
	}
	if got.AssessmentsDue != 2 || got.KillSwitchesTriggered != 1 {
		t.Errorf("assessments_due=%d kill_switches_triggered=%d, want 2 and 1",
			got.AssessmentsDue, got.KillSwitchesTriggered)
	}
	// The fiction fields stay zero against a server-shaped payload.
	if got.HighMaterialityCount != 0 || got.MediumMaterialityCount != 0 || got.LowMaterialityCount != 0 ||
		got.ByUseCase != nil || got.ByStatus != nil {
		t.Errorf("a deprecated fiction field is non-zero against the real wire shape: %+v", got)
	}
}

func TestKillSwitchParsesRealWireShape(t *testing.T) {
	client, done := serveFixture(t, "testdata/masfeat_killswitch_source_derived.json")
	defer done()

	got, err := client.MASFEATGetKillSwitch("sys-1")
	if err != nil {
		t.Fatalf("MASFEATGetKillSwitch: %v", err)
	}
	if got.TriggerReason != "accuracy fell below threshold" {
		t.Errorf("TriggerReason = %q, want the served trigger_reason", got.TriggerReason)
	}
	if got.RestoreReason != "model retrained and revalidated" {
		t.Errorf("RestoreReason = %q, want the served restore_reason", got.RestoreReason)
	}
	if got.TriggeredReason != "" {
		t.Errorf("deprecated TriggeredReason = %q, must stay empty against the real wire", got.TriggeredReason)
	}
	// Existing real fields keep parsing around the additions.
	if got.ID != "ks-1" || got.Status != KillSwitchTriggered || got.TriggeredBy != "monitoring-system" ||
		got.RestoredBy != "ops@example.com" || !got.AutoTriggerEnabled {
		t.Errorf("existing fields did not parse: %+v", got)
	}
}

func TestAISystemRegistryFictionStaysZero(t *testing.T) {
	// Direct deserialization of the source-derived shape: the server has
	// no technical_owner field anywhere, so the deprecated field must
	// stay empty while owner_team/owner_email (both real) populate.
	raw, err := os.ReadFile("testdata/masfeat_ai_system_registry_source_derived.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var got AISystemRegistry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TechnicalOwner != "" {
		t.Errorf("deprecated TechnicalOwner = %q, must stay empty against the real wire", got.TechnicalOwner)
	}
	if got.OwnerTeam != "risk-engineering" || got.BusinessOwner != "risk-lead@example.com" {
		t.Errorf("real owner fields did not parse: owner_team=%q owner_email=%q", got.OwnerTeam, got.BusinessOwner)
	}
	if got.CustomerImpact != 4 || got.ModelComplexity != 3 || got.HumanReliance != 5 {
		t.Errorf("risk ratings did not parse: %+v", got)
	}
}

// TestOJKAuditExportParsesSummary deserializes the source-derived
// export response directly - the Go SDK has no OJK client method (the
// types are consumed by users unmarshalling responses themselves), so
// direct deserialization IS the real consumer path here.
func TestOJKAuditExportParsesSummary(t *testing.T) {
	raw, err := os.ReadFile("testdata/ojk_audit_export_source_derived.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var got OJKAuditExportResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Summary == nil {
		t.Fatal("Summary is nil, want the nested export summary")
	}
	if got.Summary.TotalRecords != 421 {
		t.Errorf("Summary.TotalRecords = %d, want 421 (the real home of the record count)", got.Summary.TotalRecords)
	}
	if got.Summary.RecordsByType["llm_calls"] != 401 {
		t.Errorf("Summary.RecordsByType = %v, want llm_calls=401", got.Summary.RecordsByType)
	}
	if got.Summary.DateRange.Start.IsZero() || got.Summary.DateRange.End.IsZero() {
		t.Error("Summary.DateRange did not parse")
	}
	if got.Summary.ComplianceScore != 0.97 {
		t.Errorf("Summary.ComplianceScore = %v, want 0.97", got.Summary.ComplianceScore)
	}
	if got.Framework != "uu_pdp" || got.Format != "json" || got.ExpiresAt == nil {
		t.Errorf("framework/format/expires_at did not parse: %+v", got)
	}
	if got.RecordCount != 0 {
		t.Errorf("deprecated RecordCount = %d, must stay zero against the real wire", got.RecordCount)
	}
	if got.ExportID != "exp-1" || got.Status != "completed" || got.DownloadURL == "" {
		t.Errorf("existing real fields did not parse: %+v", got)
	}
}

func TestOJKBreachNotificationParsesRealWireShape(t *testing.T) {
	raw, err := os.ReadFile("testdata/ojk_breach_notification_source_derived.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var got OJKBreachNotification
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DataSubjectsAffected != 1500 {
		t.Errorf("DataSubjectsAffected = %d, want 1500", got.DataSubjectsAffected)
	}
	if len(got.DataTypesInvolved) != 2 || got.IncidentTimestamp.IsZero() || got.DiscoveryTime.IsZero() ||
		got.NotificationDeadline.IsZero() || got.NotifiedAuthority != "MOCDA" ||
		got.SubmittedAt == nil || len(got.RemediationSteps) != 2 {
		t.Errorf("real wire fields did not parse: %+v", got)
	}
	// All six fiction fields stay zero against the real wire shape.
	if !got.IncidentDate.IsZero() || !got.NotificationDate.IsZero() || got.AffectedSubjects != 0 ||
		got.DataCategories != nil || got.Severity != "" || got.RegulatoryRef != "" {
		t.Errorf("a deprecated fiction field is non-zero against the real wire shape: %+v", got)
	}
}

// TestMasfeatOJKOldServerTolerance strips the newly added fields from
// every fixture and asserts the models still parse with zero-value
// defaults - absence tolerance for old servers.
func TestMasfeatOJKOldServerTolerance(t *testing.T) {
	t.Run("RegistrySummary", func(t *testing.T) {
		payload := stripKeys(t, "testdata/masfeat_registry_summary_source_derived.json",
			"org_id", "high_materiality", "medium_materiality", "low_materiality",
			"assessments_due", "kill_switches_triggered")
		var got RegistrySummary
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.OrgID != "" || got.HighMateriality != 0 || got.AssessmentsDue != 0 || got.KillSwitchesTriggered != 0 {
			t.Errorf("new fields must default when absent: %+v", got)
		}
		if got.TotalSystems != 12 {
			t.Errorf("pre-existing fields must keep parsing: %+v", got)
		}
	})
	t.Run("KillSwitch", func(t *testing.T) {
		payload := stripKeys(t, "testdata/masfeat_killswitch_source_derived.json",
			"trigger_reason", "restore_reason")
		var got KillSwitch
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.TriggerReason != "" || got.RestoreReason != "" {
			t.Errorf("new fields must default when absent: %+v", got)
		}
		if got.ID != "ks-1" {
			t.Errorf("pre-existing fields must keep parsing: %+v", got)
		}
	})
	t.Run("OJKAuditExportResponse", func(t *testing.T) {
		payload := stripKeys(t, "testdata/ojk_audit_export_source_derived.json",
			"summary", "framework", "format", "expires_at")
		var got OJKAuditExportResponse
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Summary != nil || got.Framework != "" || got.Format != "" || got.ExpiresAt != nil {
			t.Errorf("new fields must default when absent: %+v", got)
		}
		if got.ExportID != "exp-1" {
			t.Errorf("pre-existing fields must keep parsing: %+v", got)
		}
	})
	t.Run("OJKBreachNotification", func(t *testing.T) {
		payload := stripKeys(t, "testdata/ojk_breach_notification_source_derived.json",
			"incident_timestamp", "discovery_time", "notification_deadline",
			"data_subjects_affected", "data_types_involved", "remediation_steps",
			"notified_authority", "submitted_at", "created_at")
		var got OJKBreachNotification
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !got.IncidentTimestamp.IsZero() || got.DataSubjectsAffected != 0 || got.DataTypesInvolved != nil {
			t.Errorf("new fields must default when absent: %+v", got)
		}
		if got.ID != "breach-1" || got.Description == "" {
			t.Errorf("pre-existing fields must keep parsing: %+v", got)
		}
	})
}
