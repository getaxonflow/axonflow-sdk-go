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

// OJKBreachNotification represents a UU PDP Art. 46 data breach
// notification record as served by the 9.x server
// (platform/orchestrator/ojk/types.go OJKBreachNotification).
type OJKBreachNotification struct {
	ID string `json:"id"`
	// IncidentTimestamp is when the breach occurred. Served by the 9.x
	// server. Zero when an old server omits it.
	IncidentTimestamp time.Time `json:"incident_timestamp"`
	// DiscoveryTime is when the breach was discovered. Served by the
	// 9.x server. Zero when an old server omits it.
	DiscoveryTime time.Time `json:"discovery_time"`
	// NotificationDeadline is the UU PDP 72h notification deadline.
	// Served by the 9.x server. Zero when an old server omits it.
	NotificationDeadline time.Time `json:"notification_deadline,omitempty"`
	// DataSubjectsAffected is the number of affected data subjects.
	// Served by the 9.x server. Zero when an old server omits it.
	DataSubjectsAffected int `json:"data_subjects_affected"`
	// DataTypesInvolved lists the categories of data involved. Served
	// by the 9.x server. Nil when an old server omits it.
	DataTypesInvolved []string `json:"data_types_involved,omitempty"`
	Description       string   `json:"description"`
	// RemediationSteps lists the remediation actions taken. Served by
	// the 9.x server. Nil when an old server omits it.
	RemediationSteps []string `json:"remediation_steps,omitempty"`
	// NotifiedAuthority names the notified authority (MOCDA until the
	// DPA is constituted). Served by the 9.x server. Empty when an old
	// server omits it.
	NotifiedAuthority string `json:"notified_authority,omitempty"`
	Status            string `json:"status"`
	// SubmittedAt is set when the notification is transmitted to the
	// authority. Served by the 9.x server. Nil when omitted.
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
	// AcknowledgedAt is set when the authority confirms receipt. Served
	// by the 9.x server. Nil when omitted.
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	// CreatedAt is when the record was created. Served by the 9.x
	// server. Zero when an old server omits it.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// IncidentDate is when the breach occurred.
	//
	// Deprecated: never populated on the 9.x line - the server serves
	// `incident_timestamp` instead (getaxonflow/axonflow-enterprise#3254).
	// Read `incident_timestamp`. Scheduled for removal in the next major.
	IncidentDate time.Time `json:"incident_date"`
	// NotificationDate is when the authority was notified.
	//
	// Deprecated: never populated on the 9.x line - the server serves
	// `notification_deadline` and `submitted_at` instead
	// (getaxonflow/axonflow-enterprise#3254). Read `submitted_at` for
	// when the notification went out and `notification_deadline` for
	// the 72h deadline. Scheduled for removal in the next major.
	NotificationDate time.Time `json:"notification_date"`
	// AffectedSubjects is the number of affected data subjects.
	//
	// Deprecated: never populated on the 9.x line - the server serves
	// `data_subjects_affected` instead
	// (getaxonflow/axonflow-enterprise#3254). Read
	// `data_subjects_affected`. Scheduled for removal in the next major.
	AffectedSubjects int `json:"affected_subjects"`
	// DataCategories lists the categories of data involved.
	//
	// Deprecated: never populated on the 9.x line - the server serves
	// `data_types_involved` instead
	// (getaxonflow/axonflow-enterprise#3254). Read
	// `data_types_involved`. Scheduled for removal in the next major.
	DataCategories []string `json:"data_categories,omitempty"`
	// Severity is the breach severity.
	//
	// Deprecated: never populated on the 9.x line - no wire equivalent
	// (getaxonflow/axonflow-enterprise#3254). Scheduled for removal in
	// the next major.
	Severity string `json:"severity"`
	// RegulatoryRef is a regulatory reference for the notification.
	//
	// Deprecated: never populated on the 9.x line - no wire equivalent
	// (getaxonflow/axonflow-enterprise#3254). Scheduled for removal in
	// the next major.
	RegulatoryRef string `json:"regulatory_ref,omitempty"`
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
// as served by the 9.x server (platform/orchestrator/ojk/types.go
// OJKAuditExportResponse). The exported payload itself (`data`) and the
// export metadata object (`metadata`) are not modeled in this interim -
// unmarshal the raw response if you need them.
type OJKAuditExportResponse struct {
	ExportID string `json:"export_id"`
	Status   string `json:"status"`
	// Framework is the compliance framework the export was produced
	// for. Served by the 9.x server. Empty when an old server omits it.
	Framework OJKComplianceFramework `json:"framework,omitempty"`
	// Format is the export format. Served by the 9.x server. Empty when
	// an old server omits it.
	Format string `json:"format,omitempty"`
	// Summary carries the export statistics, including the record
	// counts (`summary.total_records`, `summary.records_by_type`).
	// Served by the 9.x server. Nil when an old server omits it.
	Summary *OJKAuditExportSummary `json:"summary,omitempty"`
	// RecordCount is the number of exported records.
	//
	// Deprecated: never populated on the 9.x line - the wire carries
	// the counts inside `summary` (`summary.total_records`;
	// getaxonflow/axonflow-enterprise#3254). Read `Summary`. Scheduled
	// for removal in the next major.
	RecordCount int       `json:"record_count"`
	CreatedAt   time.Time `json:"created_at"`
	// ExpiresAt is when the export (and its download URL) expires.
	// Served by the 9.x server. Nil when an old server omits it.
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	DownloadURL string     `json:"download_url,omitempty"`
}

// OJKAuditExportSummary contains statistics about an exported audit data
// set, as served by the 9.x server (platform/orchestrator/ojk/types.go
// OJKAuditExportSummary).
type OJKAuditExportSummary struct {
	// TotalRecords is the total number of exported records - the real
	// home of the count the deprecated top-level `record_count` never
	// carried.
	TotalRecords int `json:"total_records"`
	// RecordsByType breaks the record count down by audit data type.
	RecordsByType map[string]int `json:"records_by_type"`
	// DateRange is the time range the export covers.
	DateRange DateRange `json:"date_range"`
	// ComplianceScore is the aggregate compliance score for the range.
	ComplianceScore float64 `json:"compliance_score"`
}

// DateRange represents a time range with an inclusive start and end.
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
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

// Cross-border transfer-basis values recognized under Indonesia UU PDP Pasal 56.
// These are the legal bases the platform accepts for the TransferBasis field on
// CrossBorderTransferRecord and AuditLogEntry. The field remains a plain string
// so the SDK never rejects a value a newer platform may add; these constants give
// callers type-safe access to the known set.
//
//   - TransferBasisAdequacy    → Pasal 56(a): destination with adequate protection
//   - TransferBasisSafeguards  → Pasal 56(b): binding legal instrument (generic label)
//   - TransferBasisPasal56bDPA → Pasal 56(b): binding legal instrument, explicit DPA tag
//   - TransferBasisConsent     → Pasal 56(c): explicit data-subject consent
//
// "safeguards" and "pasal_56b_dpa" are semantic equivalents; both are surfaced
// verbatim and never auto-translated, so an auditor sees the value recorded at
// decision time. (platform #2513 / epic #2508)
const (
	TransferBasisAdequacy    = "adequacy"
	TransferBasisSafeguards  = "safeguards"
	TransferBasisPasal56bDPA = "pasal_56b_dpa"
	TransferBasisConsent     = "consent"
)
