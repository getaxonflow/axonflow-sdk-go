package axonflow

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOJKPillarConstants(t *testing.T) {
	tests := []struct {
		pillar OJKPillar
		want   string
	}{
		{OJKPillarReliability, "reliability"},
		{OJKPillarAccountability, "accountability"},
		{OJKPillarHumanOversight, "human_oversight"},
	}
	for _, tt := range tests {
		if string(tt.pillar) != tt.want {
			t.Errorf("OJKPillar %q != %q", tt.pillar, tt.want)
		}
	}
}

func TestOJKFrameworkConstants(t *testing.T) {
	tests := []struct {
		fw   OJKComplianceFramework
		want string
	}{
		{OJKFrameworkAIGovernance, "ojk_ai_governance"},
		{OJKFrameworkDataProtection, "ojk_data_protection"},
		{OJKFrameworkOperationalRisk, "ojk_operational_risk"},
		{OJKFrameworkConsumerProtection, "ojk_consumer_protection"},
	}
	for _, tt := range tests {
		if string(tt.fw) != tt.want {
			t.Errorf("OJKComplianceFramework %q != %q", tt.fw, tt.want)
		}
	}
}

func TestOJKReadinessScoreJSON(t *testing.T) {
	score := OJKReadinessScore{
		Pillar:      OJKPillarReliability,
		Score:       7,
		MaxScore:    10,
		Findings:    []string{"Model drift detected"},
		Remediation: []string{"Implement retraining pipeline"},
	}

	data, err := json.Marshal(score)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded OJKReadinessScore
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Pillar != OJKPillarReliability {
		t.Errorf("pillar = %q, want %q", decoded.Pillar, OJKPillarReliability)
	}
	if decoded.Score != 7 {
		t.Errorf("score = %d, want 7", decoded.Score)
	}
	if decoded.MaxScore != 10 {
		t.Errorf("max_score = %d, want 10", decoded.MaxScore)
	}
	if len(decoded.Findings) != 1 {
		t.Errorf("findings len = %d, want 1", len(decoded.Findings))
	}
}

func TestOJKReadinessScoreOmitsEmpty(t *testing.T) {
	score := OJKReadinessScore{
		Pillar:   OJKPillarAccountability,
		Score:    5,
		MaxScore: 10,
	}

	data, err := json.Marshal(score)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	if _, ok := raw["findings"]; ok {
		t.Error("findings should be omitted when nil")
	}
	if _, ok := raw["remediation"]; ok {
		t.Error("remediation should be omitted when nil")
	}
}

func TestOJKBreachNotificationJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	breach := OJKBreachNotification{
		ID:               "breach-001",
		IncidentDate:     now.Add(-24 * time.Hour),
		NotificationDate: now,
		Description:      "Unauthorized access to customer data",
		AffectedSubjects: 1500,
		DataCategories:   []string{"NIK", "phone_number"},
		Severity:         "high",
		Status:           "reported",
		RegulatoryRef:    "UU PDP Art. 46",
	}

	data, err := json.Marshal(breach)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded OJKBreachNotification
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != "breach-001" {
		t.Errorf("id = %q, want breach-001", decoded.ID)
	}
	if decoded.AffectedSubjects != 1500 {
		t.Errorf("affected_subjects = %d, want 1500", decoded.AffectedSubjects)
	}
	if len(decoded.DataCategories) != 2 {
		t.Errorf("data_categories len = %d, want 2", len(decoded.DataCategories))
	}
}

func TestCrossBorderTransferRecordJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	record := CrossBorderTransferRecord{
		ID:              "xfer-001",
		SourceCountry:   "ID",
		DestCountry:     "SG",
		TransferBasis:   "adequacy",
		DataCategories:  []string{"financial_data"},
		TransferDate:    now,
		RecipientEntity: "Partner Bank SG",
		Purpose:         "Cross-border payment processing",
		Status:          "approved",
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded CrossBorderTransferRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.SourceCountry != "ID" {
		t.Errorf("source_country = %q, want ID", decoded.SourceCountry)
	}
	if decoded.DestCountry != "SG" {
		t.Errorf("dest_country = %q, want SG", decoded.DestCountry)
	}
	if decoded.TransferBasis != "adequacy" {
		t.Errorf("transfer_basis = %q, want adequacy", decoded.TransferBasis)
	}
}

func TestCrossBorderTransferRecordOmitsEmpty(t *testing.T) {
	record := CrossBorderTransferRecord{
		ID:            "xfer-002",
		SourceCountry: "ID",
		DestCountry:   "US",
		TransferBasis: "consent",
		TransferDate:  time.Now(),
		Status:        "pending",
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	if _, ok := raw["data_categories"]; ok {
		t.Error("data_categories should be omitted when nil")
	}
	if _, ok := raw["recipient_entity"]; ok {
		t.Error("recipient_entity should be omitted when empty")
	}
	if _, ok := raw["purpose"]; ok {
		t.Error("purpose should be omitted when empty")
	}
}

// TestTransferBasisConstants pins the wire values of the UU PDP Pasal 56
// transfer-basis constants added in v8.4.0 (platform #2513).
func TestTransferBasisConstants(t *testing.T) {
	cases := map[string]string{
		TransferBasisAdequacy:    "adequacy",
		TransferBasisSafeguards:  "safeguards",
		TransferBasisPasal56bDPA: "pasal_56b_dpa",
		TransferBasisConsent:     "consent",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("transfer-basis constant = %q, want %q", got, want)
		}
	}
}

// TestCrossBorderTransferRecord_Pasal56bDPA — the new Pasal 56(b) explicit DPA
// tag must round-trip on CrossBorderTransferRecord without information loss.
func TestCrossBorderTransferRecord_Pasal56bDPA(t *testing.T) {
	record := CrossBorderTransferRecord{
		ID:            "xfer-56b",
		SourceCountry: "ID",
		DestCountry:   "SG",
		TransferBasis: TransferBasisPasal56bDPA,
		TransferDate:  time.Now().Truncate(time.Second),
		Status:        "approved",
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"transfer_basis":"pasal_56b_dpa"`) {
		t.Errorf("expected pasal_56b_dpa on the wire: %s", data)
	}
	var decoded CrossBorderTransferRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.TransferBasis != "pasal_56b_dpa" {
		t.Errorf("transfer_basis = %q, want pasal_56b_dpa", decoded.TransferBasis)
	}
}

// TestTransferBasis_BackwardCompatSafeguards — existing v8.3.0-shaped records
// using "safeguards" must continue to parse unchanged after the widening.
func TestTransferBasis_BackwardCompatSafeguards(t *testing.T) {
	raw := []byte(`{"id":"xfer-old","source_country":"ID","dest_country":"NL",` +
		`"transfer_basis":"safeguards","transfer_date":"2026-05-26T00:00:00Z","status":"approved"}`)
	var decoded CrossBorderTransferRecord
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.TransferBasis != TransferBasisSafeguards {
		t.Errorf("transfer_basis = %q, want safeguards", decoded.TransferBasis)
	}
}

func TestOJKAuditExportRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	req := OJKAuditExportRequest{
		StartDate: now.Add(-7 * 24 * time.Hour),
		EndDate:   now,
		Framework: OJKFrameworkAIGovernance,
		Format:    "csv",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var decoded OJKAuditExportRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	if decoded.Framework != OJKFrameworkAIGovernance {
		t.Errorf("framework = %q, want %q", decoded.Framework, OJKFrameworkAIGovernance)
	}

	resp := OJKAuditExportResponse{
		ExportID:    "exp-001",
		Status:      "completed",
		RecordCount: 42,
		CreatedAt:   now,
		DownloadURL: "https://exports.example.com/exp-001.csv",
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var decodedResp OJKAuditExportResponse
	if err := json.Unmarshal(respData, &decodedResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if decodedResp.RecordCount != 42 {
		t.Errorf("record_count = %d, want 42", decodedResp.RecordCount)
	}
	if decodedResp.DownloadURL == "" {
		t.Error("download_url should not be empty")
	}
}
