package axonflow

import "time"

// ===========================================================================
// OJK Compliance Types
// ===========================================================================

// OJKComplianceFramework represents the OJK AI governance framework reference
type OJKComplianceFramework string

const (
	OJKFrameworkAIGovernance       OJKComplianceFramework = "ojk_ai_governance"
	OJKFrameworkDataProtection     OJKComplianceFramework = "ojk_data_protection"
	OJKFrameworkOperationalRisk    OJKComplianceFramework = "ojk_operational_risk"
	OJKFrameworkConsumerProtection OJKComplianceFramework = "ojk_consumer_protection"
)

// OJKPillar represents the pillars of OJK AI governance
type OJKPillar string

const (
	OJKPillarReliability    OJKPillar = "reliability"
	OJKPillarAccountability OJKPillar = "accountability"
	OJKPillarHumanOversight OJKPillar = "human_oversight"
)

// OJKReadinessScore represents a pillar-level readiness assessment
type OJKReadinessScore struct {
	Pillar      OJKPillar `json:"pillar"`
	Score       int       `json:"score"`
	MaxScore    int       `json:"max_score"`
	Findings    []string  `json:"findings,omitempty"`
	Remediation []string  `json:"remediation,omitempty"`
}

// OJKBreachNotification represents a data breach notification record
type OJKBreachNotification struct {
	ID               string    `json:"id"`
	IncidentDate     time.Time `json:"incident_date"`
	NotificationDate time.Time `json:"notification_date"`
	Description      string    `json:"description"`
	AffectedSubjects int       `json:"affected_subjects"`
	DataCategories   []string  `json:"data_categories,omitempty"`
	Severity         string    `json:"severity"`
	Status           string    `json:"status"`
	RegulatoryRef    string    `json:"regulatory_ref,omitempty"`
}

// OJKAuditExportRequest represents a request to export OJK audit data
type OJKAuditExportRequest struct {
	StartDate  time.Time              `json:"start_date"`
	EndDate    time.Time              `json:"end_date"`
	Framework  OJKComplianceFramework `json:"framework,omitempty"`
	IncludePII bool                   `json:"include_pii,omitempty"`
	Format     string                 `json:"format,omitempty"`
}

// OJKAuditExportResponse represents the response from an OJK audit export
type OJKAuditExportResponse struct {
	ExportID    string    `json:"export_id"`
	Status      string    `json:"status"`
	RecordCount int       `json:"record_count"`
	CreatedAt   time.Time `json:"created_at"`
	DownloadURL string    `json:"download_url,omitempty"`
}

// CrossBorderTransferRecord represents a cross-border data transfer record
type CrossBorderTransferRecord struct {
	ID              string    `json:"id"`
	SourceCountry   string    `json:"source_country"`
	DestCountry     string    `json:"dest_country"`
	TransferBasis   string    `json:"transfer_basis"`
	DataCategories  []string  `json:"data_categories,omitempty"`
	TransferDate    time.Time `json:"transfer_date"`
	RecipientEntity string    `json:"recipient_entity,omitempty"`
	Purpose         string    `json:"purpose,omitempty"`
	Status          string    `json:"status"`
}
