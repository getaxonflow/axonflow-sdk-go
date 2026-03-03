# Changelog

All notable changes to the AxonFlow Go SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.8.0] - 2026-03-03

### Added

- **Version Discovery**: `HealthCheckDetailed()` method returning `HealthResponse` with platform version, capabilities list, and SDK compatibility info
- **Capability Check**: `HasCapability(name)` method on `HealthResponse` to check if the platform supports a specific feature
- **SDK Version Constant**: `Version` constant in `version.go` for programmatic SDK version access
- **User-Agent Header**: `axonflow-sdk-go/{version}` sent on all HTTP requests via `userAgentRoundTripper`
- **Version Compatibility Warning**: Logged when SDK version is below the platform's `min_sdk_version`
- `trace_id` field on `CreateWorkflowRequest`, `CreateWorkflowResponse`, `WorkflowStatusResponse`, and `ListWorkflowsOptions` for distributed tracing correlation
- `ToolContext` type for per-tool governance within workflow steps
- `tool_context` field on `StepGateRequest` for tool-level policy enforcement
- New types: `PlatformCapability`, `SDKCompatibility`
- Anonymous runtime telemetry for version adoption tracking and feature usage signals
- `TelemetryEnabled` / `telemetry` configuration option to explicitly control telemetry
- `AXONFLOW_TELEMETRY=off` and `DO_NOT_TRACK=1` environment variable opt-out support

---

## [3.7.0] - 2026-02-28

### Added

- **MCP Policy-Check Endpoints** (Platform v4.6.0+): Standalone policy validation for external orchestrators (LangGraph, CrewAI) to enforce AxonFlow policies without executing connector queries
  - `MCPCheckInput(ctx, req)`: Validate SQL/commands against input policies (SQLi detection, dangerous query blocking, PII in queries, dynamic policies). Returns `Allowed: true` or `BlockReason` with details
  - `MCPCheckOutput(ctx, req)`: Validate MCP response data against output policies (PII redaction, exfiltration limits, dynamic policies). Returns original or redacted data with `PolicyInfo`
  - New types: `MCPCheckInputRequest`, `MCPCheckInputResponse`, `MCPCheckOutputRequest`, `MCPCheckOutputResponse`
  - Supports both query-style (`ResponseData`) and execute-style (`Message` + `Metadata`) output validation

---

## [3.6.0] - 2026-02-22

### Added

- Media governance configuration methods: `GetMediaGovernanceConfig()`, `UpdateMediaGovernanceConfig()`, `GetMediaGovernanceStatus()`
- Media governance types: `MediaGovernanceConfig`, `MediaGovernanceStatus`
- Media policy category constants: `CategoryMediaSafety`, `CategoryMediaBiometric`, `CategoryMediaPII`, `CategoryMediaDocument`
- `MarkStepCompletedRequest` now accepts post-execution metrics (`tokens_in`, `tokens_out`, `cost_usd`)

---

## [3.5.0] - 2026-02-18

### Added

- **Media Governance Types**: `MediaContent`, `MediaAnalysisResult`, `MediaAnalysisResponse` for multimodal image governance
- **`ProxyLLMCallWithMedia()`**: Send images (base64 or URL) alongside queries for governance analysis before LLM routing

### Changed

- **Response cache skipped for media requests**: Requests containing media bypass the response cache (binary content makes cache keys unreliable)

### Breaking

- `MediaAnalysisResult.ExtractedText` replaced by `HasExtractedText` (bool) and `ExtractedTextLength` (int). Raw extracted text is no longer exposed in API responses.

---

## [3.4.0] - 2026-02-13

### Added

- **FailWorkflow** (#1187): Fail a workflow with optional reason
  - `FailWorkflow(workflowID, reason string) error`: sends `POST /api/v1/workflows/{id}/fail`
  - Follows same pattern as `AbortWorkflow()`
- **HITL Queue API** (Enterprise): Human-in-the-loop approval queue management
  - `ListHITLQueue(opts HITLQueueListOptions) (*HITLQueueListResponse, error)`: list pending approvals
  - `GetHITLRequest(requestID string) (*HITLApprovalRequest, error)`: get approval details
  - `ApproveHITLRequest(requestID string, review HITLReviewInput) error`: approve a request
  - `RejectHITLRequest(requestID string, review HITLReviewInput) error`: reject a request
  - `GetHITLStats() (*HITLStats, error)`: dashboard statistics
  - New types: `HITLApprovalRequest`, `HITLQueueListOptions`, `HITLQueueListResponse`, `HITLReviewInput`, `HITLStats`

## [3.3.1] - 2026-02-12

### Fixed

- `StreamExecutionStatus()` used incorrect endpoint path (`/api/v1/executions/{id}/stream` → `/api/v1/unified/executions/{id}/stream`), causing 404 errors when streaming execution status updates

## [3.3.0] - 2026-02-10

### Added

- **WCP Approval Gates** (Issue #1169): HITL approval and rejection for workflow steps
  - `ApproveStep(workflowID, stepID)` - Approve a pending workflow step
  - `RejectStep(workflowID, stepID, reason)` - Reject a step with reason
  - `GetPendingApprovals(opts)` - List steps awaiting human approval

- **MAP Plan Cancellation** (Issue #1072): Cancel running multi-agent plans
  - `CancelPlan(planID, reason)` - Cancel a plan with optional reason (omits reason from body when empty)

- **MAP Plan Update** (Issue #1072): Modify plan configuration before or during execution
  - `UpdatePlan(planID, request)` - Update execution mode, domain, or version

- **MAP Plan Versioning and Rollback** (Issue #1072): Version history and rollback support
  - `GetPlanVersions(planID)` - List plan version history
  - `RollbackPlan(planID, version)` - Rollback to a previous version (returns `ErrVersionConflict` on 409)
  - New types: `RollbackPlanResponse`, `PlanVersion`

- **Webhook Subscriptions** (Issue #1169): Event notification management
  - `CreateWebhook(request)` - Create a webhook subscription
  - `ListWebhooks()` - List active webhook subscriptions
  - `GetWebhook(webhookID)` - Get webhook details
  - `UpdateWebhook(webhookID, request)` - Update webhook configuration
  - `DeleteWebhook(webhookID)` - Delete a webhook subscription
  - New type: `WebhookSubscription`

- **Unified Execution Cancellation** (EPIC #1074): Cancel running executions across both MAP and WCP subsystems
  - `CancelExecution(executionID, reason)` - Cancel a unified execution via `POST /api/v1/unified/executions/{id}/cancel`
  - Propagates to MAP `CancelPlan()` or WCP `AbortWorkflow()` based on execution type
  - Reason is optional: pass empty string to cancel without a reason

### Fixed

- **`ExecutePlan` status hardcoded**: `ExecutePlan()` always returned `Status: "completed"` regardless of actual server response. Now reads status from response (`data.status` > `metadata.status` > default), correctly surfacing `"awaiting_approval"` for WCP confirm mode.
- **Unified execution API URLs** (EPIC #1074): `GetExecutionStatus()` and `ListUnifiedExecutions()` now use correct `/api/v1/unified/executions` path (was incorrectly pointing to `/api/v1/executions` which is the Execution Replay API)
- **`RollbackPlan` request body**: Removed redundant version from request body (version is already in URL path)
- **`CancelPlan` empty reason**: No longer sends `"reason": ""` when reason is empty

---

## [3.2.0] - 2026-02-05

### Added

- **Dynamic policy tier support**: `Tier` (`PolicyTier`) and `OrganizationID` fields on `CreateDynamicPolicyRequest`, `UpdateDynamicPolicyRequest`, and `DynamicPolicy` response. Defaults to `TierTenant` when not specified, matching `CreateStaticPolicy()` behavior.
- **`ListDynamicPoliciesOptions` filters**: Filter dynamic policies by `Tier` and `OrganizationID`, matching static policy list options.

---

## [3.1.0] - 2026-02-04

### Changed

- Version bump to keep Go aligned with the 3.1.0 cross-SDK release train.
- No functional Go SDK code, API, or runtime behavior changes in this release.

## [3.0.0] - 2026-02-03

### Breaking Changes

- **Removed `ExecuteQuery()`**: Use `ProxyLLMCall()` instead (deprecated since v2.7.0)
- **Module path changed**: `github.com/getaxonflow/axonflow-sdk-go/v2` → `github.com/getaxonflow/axonflow-sdk-go/v3`

### Added

- **`WasRedacted()` helper**: Convenience method on `MCPExecuteResponse` to check if any fields were redacted by PII policies

### Changed

- Updated all internal references and examples from `ExecuteQuery` to `ProxyLLMCall`

---

## [2.7.1] - 2026-01-25

### Changed

- **Gateway Mode smart defaults**: `GetPolicyApprovedContext()` and `AuditLLMCall()` now use `"community"` as default clientId when not configured, enabling zero-config usage for community/self-hosted deployments

### Fixed

- **PolicyCategory**: Added `CategoryPIISingapore` constant for Singapore PII detection policies (NRIC, FIN, UEN patterns)

---

## [2.7.0] - 2026-01-25

### Added

- **Unified Execution Tracking** (Issue #1075 - EPIC #1074): Consistent status tracking for MAP plans and WCP workflows
  - `GetExecutionStatus(executionID)` - Get unified execution status by ID
  - `ListUnifiedExecutions(opts)` - List executions with type/status filters
  - `ExecutionStatus` struct with unified fields for both MAP and WCP executions
  - `ExecutionType` constants: `ExecutionTypeMAP`, `ExecutionTypeWCP`
  - `ExecutionStatusValue` constants: `ExecutionStatusPending`, `ExecutionStatusRunning`, `ExecutionStatusCompleted`, `ExecutionStatusFailed`, `ExecutionStatusCancelled`, `ExecutionStatusAborted`, `ExecutionStatusExpired`
  - `StepStatusValue` constants: `StepStatusPending`, `StepStatusRunning`, `StepStatusCompleted`, `StepStatusFailed`, `StepStatusSkipped`, `StepStatusBlocked`, `StepStatusApproval`
  - `UnifiedStepType` constants: `StepTypeLLMCall`, `StepTypeToolCall`, `StepTypeConnectorCall`, `StepTypeHumanTask`, `StepTypeSynthesis`, `StepTypeAction`, `StepTypeGate`
  - `UnifiedStepStatus` struct with step-level details (duration, cost, policy decisions)
  - Helper methods: `IsTerminal()`, `IsStepTerminal()`, `IsStepBlocking()`, `CalculateProgress()`, `GetCurrentStep()`, `CalculateTotalCost()`
  - Consistent response format across MAP Multi-Agent Planning and WCP Workflow Control Plane

- **MAS FEAT Compliance Module** (Enterprise): Singapore financial services AI governance
  - AI System Registry: `MASFEATRegisterSystem()`, `MASFEATGetSystem()`, `MASFEATUpdateSystem()`, `MASFEATListSystems()`, `MASFEATActivateSystem()`, `MASFEATRetireSystem()`, `MASFEATGetRegistrySummary()`
  - 3-Dimensional Risk Rating: Customer Impact × Model Complexity × Human Reliance
  - Materiality Classification: High (sum≥12), Medium (sum≥8), Low (sum<8)
  - FEAT Assessments: `MASFEATCreateAssessment()`, `MASFEATGetAssessment()`, `MASFEATUpdateAssessment()`, `MASFEATListAssessments()`, `MASFEATSubmitAssessment()`, `MASFEATApproveAssessment()`, `MASFEATRejectAssessment()`
  - Assessment Lifecycle: pending → in_progress → completed → approved/rejected
  - Kill Switch: `MASFEATGetKillSwitch()`, `MASFEATConfigureKillSwitch()`, `MASFEATCheckKillSwitch()`, `MASFEATTriggerKillSwitch()`, `MASFEATRestoreKillSwitch()`, `MASFEATEnableKillSwitch()`, `MASFEATDisableKillSwitch()`, `MASFEATGetKillSwitchHistory()`
  - Automatic model shutdown based on accuracy, bias, and error rate thresholds
  - New types: `AISystemRegistry`, `AISystemUseCase`, `MaterialityClassification`, `SystemStatus`, `FEATAssessment`, `FEATAssessmentStatus`, `FEATPillar`, `KillSwitch`, `KillSwitchStatus`, `KillSwitchEvent`, `KillSwitchEventType`, `RegistrySummary`

- **ProxyLLMCall()**: New primary method for Proxy Mode with improved documentation
  - Clearly describes Proxy Mode behavior (AxonFlow makes the LLM call on your behalf)
  - Documents when to use Proxy Mode vs Gateway Mode
  - Same functionality as ExecuteQuery, but with clearer naming

- **BudgetInfo**: `QueryResponse.BudgetInfo` for budget enforcement (HTTP 402)

### Deprecated

- **ExecuteQuery()**: Deprecated in favor of ProxyLLMCall()
  - Will be removed in v3.0.0
  - Emits deprecation warning in debug mode
  - Remains functional as a wrapper around ProxyLLMCall()

---

## [2.6.0] - 2026-01-18

### Added

- **Workflow Policy Enforcement** (Issues #1019, #1020, #1021): Policy transparency for workflow operations
  - `StepGateResponse` now includes `PoliciesEvaluated` and `PoliciesMatched` fields with `PolicyMatch` type
  - `PolicyMatch` type with `PolicyID`, `PolicyName`, `Action`, `Reason` for policy transparency
  - `PolicyEvaluationResult` type for MAP execution with `Allowed`, `AppliedPolicies`, `RiskScore`
  - Workflow operations (`workflow_created`, `workflow_step_gate`, `workflow_completed`) logged to audit trail

---

## [2.5.0] - 2026-01-17

### Added

- **Workflow Control Plane** (Issue #834): Governance gates for external orchestrators
  - "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
  - `CreateWorkflow()` - Register workflows from LangChain/LangGraph/CrewAI/external
  - `StepGate()` - Check if step is allowed to proceed (allow/block/require_approval)
  - `MarkStepCompleted()` - Mark a step as completed with optional output data
  - `GetWorkflow()` - Get workflow status and step history
  - `ListWorkflows()` - List workflows with filters (status, source, pagination)
  - `CompleteWorkflow()` - Mark workflow as completed
  - `AbortWorkflow()` - Abort workflow with reason
  - `ResumeWorkflow()` - Resume after approval
  - New types: `WorkflowStatus`, `WorkflowSource`, `GateDecision`, `StepType`, `ApprovalStatus`, `MarkStepCompletedRequest`
  - Helper methods on `StepGateResponse`: `IsAllowed()`, `IsBlocked()`, `RequiresApproval()`
  - Helper methods on `WorkflowStatus` and `WorkflowStatusResponse`: `IsTerminal()`

---

## [2.4.0] - 2026-01-14

### Added

- **MCP Exfiltration Detection** (Issue #966): `PolicyInfo` now includes `ExfiltrationCheck` with row/volume limit information
  - `ExfiltrationCheckInfo` type with `RowsReturned`, `RowLimit`, `BytesReturned`, `ByteLimit`, `WithinLimits` fields
  - Prevents large-scale data extraction via MCP queries
  - Configurable via `MCP_MAX_ROWS_PER_QUERY` and `MCP_MAX_BYTES_PER_QUERY` environment variables

- **MCP Dynamic Policies** (Issue #968): `PolicyInfo` now includes `DynamicPolicyInfo` for Orchestrator-evaluated policies
  - `DynamicPolicyInfo` type with `PoliciesEvaluated`, `MatchedPolicies`, `OrchestratorReachable`, `ProcessingTimeMs`
  - `DynamicPolicyMatch` type with `PolicyID`, `PolicyName`, `PolicyType`, `Action`, `Reason`
  - Supports rate limiting, budget controls, time-based access, and role-based access policies
  - Optional feature - enable via `MCP_DYNAMIC_POLICIES_ENABLED=true`

---

## [2.3.0] - 2026-01-09

### Added

- **MCP Policy Enforcement Response Fields**: `MCPQuery()` and `MCPExecute()` now return policy enforcement metadata
  - `Redacted bool` - Whether any fields were redacted by PII policies
  - `RedactedFields []string` - JSON paths of redacted fields (e.g., `rows[0].ssn`)
  - `PolicyInfo *PolicyInfo` - Full policy evaluation metadata

- **PolicyInfo types**: New types for policy enforcement metadata
  - `PolicyInfo` - Contains `PoliciesEvaluated`, `Blocked`, `BlockReason`, `RedactionsApplied`, `ProcessingTimeMs`, `MatchedPolicies`
  - `PolicyMatchInfo` - Details of matched policies including `PolicyID`, `PolicyName`, `Category`, `Severity`, `Action`

---

## [2.2.0] - 2026-01-08

### Added

- **OAuth2-style client credentials**: New `ClientID` and `ClientSecret` configuration fields following OAuth2 client credentials pattern.
  - `ClientID` is used for request identification (required for most API calls)
  - `ClientSecret` is optional - community/self-hosted deployments work without it

- **Enterprise: Close PR** (`ClosePR`): Close a PR without merging and optionally delete the branch
  - Useful for cleaning up test/demo PRs created by code governance examples
  - Supports all Git providers: GitHub, GitLab, Bitbucket
  - Requires enterprise portal authentication

### Changed

- **Simplified authentication**: For community mode, simply provide `ClientID` for request identification. No `ClientSecret` needed.

```go
// Community mode - no secret needed
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",
    ClientID: "my-app",  // Used for request identification
})
```

### Fixed

- **GetPlanStatus endpoint**: Fixed endpoint path from `/api/plans/{id}` to `/api/v1/plan/{id}` to match orchestrator API

### Enterprise

- OAuth2 Basic auth: `Authorization: Basic base64(clientId:clientSecret)` replaces `X-License-Key` header
- Removed `LicenseKey` configuration option (use `ClientID`/`ClientSecret`)

## [2.1.0] - 2026-01-05

### Added

- **Sensitive Data Category**: Added `CategorySensitiveData` to `PolicyCategory` enum for policies that return `sensitive-data` category
- **Provider Restrictions for Compliance**: Support for `allowed_providers` in dynamic policy action config
  - Specify allowed providers via `DynamicPolicyAction.Config["allowed_providers"]`
  - Enables GDPR, HIPAA, and RBI compliance by restricting LLM routing to specific providers
  - Example: `Actions: []DynamicPolicyAction{{Type: "route", Config: map[string]interface{}{"allowed_providers": []string{"ollama", "azure-eu"}}}}`
- **Category field**: Added `Category` field to `CreateDynamicPolicyRequest` and `UpdateDynamicPolicyRequest`
- **DynamicPolicy fields**: Added `Category`, `Tier`, `Version`, `TenantID` fields to `DynamicPolicy` struct

### Fixed

- **ToggleDynamicPolicy HTTP Method**: Changed from PATCH to PUT to match API specification
- **Dynamic Policy Response Parsing**: Fixed `ListDynamicPolicies`, `GetDynamicPolicy`, `CreateDynamicPolicy`, `UpdateDynamicPolicy`, `ToggleDynamicPolicy`, and `GetEffectiveDynamicPolicies` to correctly parse wrapped API responses
  - API returns `{"policies": [...]}` and `{"policy": {...}}` wrappers
  - Added `dynamicPoliciesResponse` and `dynamicPolicyResponse` wrapper structs

## [2.0.0] - 2026-01-05

### Breaking Changes

- **BREAKING**: Renamed `AgentURL` to `Endpoint` in `AxonFlowConfig`
- **BREAKING**: Removed `OrchestratorURL` and `PortalURL` config options (Agent now proxies all routes per ADR-026)
- **BREAKING**: Dynamic policy API path changed from `/api/v1/policies/dynamic` to `/api/v1/dynamic-policies`

### Added

- **Audit Log Reading**: Added `SearchAuditLogs()` for searching audit logs with filters (user email, client ID, time range, request type)
- **Tenant Audit Logs**: Added `GetAuditLogsByTenant()` for retrieving audit logs scoped to a specific tenant
- **Audit Types**: Added `AuditLogEntry`, `AuditSearchRequest`, `AuditQueryOptions`, and `AuditSearchResponse` types
- **PII Redaction Support**: Added `RequiresRedaction` field to `PolicyApprovalResult` (Issue #891)
  - When `true`, PII was detected with redact action and response should be processed for redaction
  - Supports new detection defaults: PII defaults to redact instead of block

### Changed

- All SDK methods now route through single Agent endpoint
- Simplified configuration - only `Endpoint` field needed
- Removed `getOrchestratorURL()` and `getPortalURL()` helper methods

### Migration Guide

**Before (v1.x):**
```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    AgentURL:        "http://localhost:8080",
    OrchestratorURL: "http://localhost:8081",
    PortalURL:       "http://localhost:8082",
    ClientID:        "my-client",
    ClientSecret:    "my-secret",
})
```

**After (v2.x):**
```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     "my-client",
    ClientSecret: "my-secret",
})
```

---

## [1.17.0] - 2026-01-04

### Added

- **Portal Authentication**: Added `LoginToPortal()` and `LogoutFromPortal()` for session-based authentication
- **Portal URL Configuration**: New `PortalURL` config option for Code Governance portal endpoints
- **CSV Export**: Added `ExportCodeGovernanceDataCSV()` for CSV format exports

### Fixed

- **Code Governance Authentication**: Changed Code Governance methods to use portal session-based auth instead of API key auth

---

## [1.16.0] - 2026-01-04

### Added

- **Get Connector**: `GetConnector(id)` to retrieve details for a specific connector
- **Connector Health Check**: `GetConnectorHealth(id)` to check health status of an installed connector
- **ConnectorHealthStatus type**: New type for connector health responses
- **Orchestrator Health Check**: `OrchestratorHealthCheck()` to verify Orchestrator service health
- **Uninstall Connector**: `UninstallConnector()` to remove installed MCP connectors

### Fixed

- **Connector API Endpoints**: Fixed endpoints to use Orchestrator (port 8081) instead of Agent
  - `ListConnectors()` - Changed from Agent `/api/connectors` to Orchestrator `/api/v1/connectors`
  - `InstallConnector()` - Fixed path to `/api/v1/connectors/{id}/install`
- **Dynamic Policies Endpoint**: Changed from Agent `/api/v1/policies` to Orchestrator `/api/v1/policies/dynamic`

---

## [1.15.0] - 2026-01-04

### Added

- **Execution Replay API**: Debug governed workflows with step-by-step state capture
  - `ListExecutions()` - List executions with filtering (status, time range)
  - `GetExecution()` - Get execution with all step snapshots
  - `GetExecutionSteps()` - Get individual step snapshots
  - `GetExecutionTimeline()` - Timeline view for visualization
  - `ExportExecution()` - Export for compliance/archival
  - `DeleteExecution()` - Delete execution records

- **Cost Controls**: Budget management and LLM usage tracking
  - `CreateBudget()` / `GetBudget()` / `ListBudgets()` - Budget CRUD
  - `UpdateBudget()` / `DeleteBudget()` - Budget management
  - `GetBudgetStatus()` - Check current budget usage
  - `CheckBudget()` - Pre-request budget validation
  - `RecordUsage()` - Record LLM token usage
  - `GetUsageSummary()` - Usage analytics and reporting

---

## [1.14.0] - 2025-12-30

### Fixed

- **403 Forbidden Handling**: Properly handle HTTP 403 responses for blocked requests
  - Agent returns 403 when requests are blocked by policy
  - Previously this triggered retry logic and fail-open, causing blocked requests to appear allowed
  - Now correctly parses 403 response body and returns `Blocked=true` with proper `BlockReason`

---

## [1.13.0] - 2025-12-30

### Changed

- **Community Mode**: Credentials are now optional for self-hosted/community deployments
  - SDK can be initialized without `ClientSecret` or `LicenseKey` for community features
  - `ExecuteQuery()` and `HealthCheck()` work without credentials
  - Auth headers are only sent when credentials are configured

### Added

- `requireCredentials()` helper for enterprise feature validation
- Enterprise features (`GetPolicyApprovedContext`, `AuditLLMCall`) now validate credentials at call time

### Fixed

- Gateway Mode methods now return clear error message when called without credentials

---

## [1.12.0] - 2025-12-30

### Fixed

- Fixed JSON field names for `PolicyOverride` types to match API schema (`action_override`, `override_reason`)
- Fixed `ListPolicyOverrides()` to correctly parse wrapped response format
- Fixed `GetStaticPolicyVersions()` to correctly parse wrapped response format

> **Note:** These changes affect Enterprise users only. Community users can skip this release.

---

## [1.11.0] - 2025-12-29

### Added

- **Enterprise Policy Features**:
  - `OrganizationID` field in `CreateStaticPolicyRequest` for organization-tier policies
  - `OrganizationID` field in `ListStaticPoliciesOptions` for filtering by organization
  - `ListPolicyOverrides()` method to list all active policy overrides

- **Type Aliases** (for backward compatibility with existing code):
  - `ListStaticPoliciesRequest` = `ListStaticPoliciesOptions`
  - `CreateOverrideRequest` = `CreatePolicyOverrideRequest`
  - `GetEffectiveRequest` = `EffectivePoliciesOptions`

- **TestPatternResult Improvements**:
  - `Results` field as alias for `Matches`
  - `GetResults()` method for convenience

---

## [1.10.0] - 2025-12-29

### Added

- **Code Governance Metrics & Export APIs** (Enterprise): Compliance reporting for AI-generated code
  - `GetCodeGovernanceMetrics()` - Returns aggregated statistics (PR counts, file totals, security findings)
  - `ExportCodeGovernanceData()` - Exports PR records as JSON for auditors
  - `ExportCodeGovernanceDataCSV()` - Exports PR records as CSV

- **New Types**: `CodeGovernanceMetrics`, `ExportOptions`, `ExportResponse`

---

## [1.9.0] - 2025-12-29

### Added

- **Code Governance Git Provider APIs** (Enterprise): Create PRs from LLM-generated code
  - `ValidateGitProvider()` - Validate credentials before saving
  - `ConfigureGitProvider()` - Configure GitHub, GitLab, or Bitbucket
  - `ListGitProviders()` - List configured providers
  - `DeleteGitProvider()` - Remove a provider
  - `CreatePR()` - Create PR from generated code with audit trail
  - `ListPRs()` - List PRs with filtering
  - `GetPR()` - Get PR details
  - `SyncPRStatus()` - Sync status from Git provider

- **New Types**: `GitProviderType`, `FileAction`, `CodeFile`, `CreatePRRequest`, `CreatePRResponse`, `PRRecord`, `ListPRsOptions`, `ListPRsResponse`

- **Supported Git Providers**:
  - GitHub (Cloud and Enterprise Server)
  - GitLab (Cloud and Self-Managed)
  - Bitbucket (Cloud and Server/Data Center)

---

## [1.8.0] - 2025-12-28

### Added

- **HITL Support**: `ActionRequireApproval` for human oversight policies
  - Use with `CreateStaticPolicy()` to trigger approval workflows
  - Enterprise: Full HITL queue integration
  - Community: Auto-approves immediately

---

## [1.7.0] - 2025-12-28

### Added

- **Code Governance Support** - `CodeArtifact` type for detecting and auditing LLM-generated code (#16)
  - `CodeArtifact` struct in `PolicyEvaluationInfo` with fields:
    - `IsCodeOutput` - Whether response contains code
    - `Language` - Detected programming language (14 supported)
    - `CodeType` - Code category (function, class, script, config, snippet, module)
    - `SizeBytes` - Size of detected code in bytes
    - `LineCount` - Number of lines of code
    - `SecretsDetected` - Count of potential secrets found
    - `UnsafePatterns` - Count of unsafe code patterns
  - Automatic code detection in LLM responses
  - Supports Python, Go, TypeScript, JavaScript, Java, SQL, Ruby, Rust, C/C++, Bash, YAML, JSON, Dockerfile, Terraform

## [1.6.0] - 2025-12-25

### Added

- **Policy CRUD Methods**: Full policy management support for Unified Policy Architecture v2.0.0
  - `ListStaticPolicies()` - List policies with filtering
  - `GetStaticPolicy()` - Get single policy by ID
  - `CreateStaticPolicy()` - Create custom policy
  - `UpdateStaticPolicy()` - Update existing policy
  - `DeleteStaticPolicy()` - Delete policy
  - `ToggleStaticPolicy()` - Enable/disable policy
  - `GetEffectiveStaticPolicies()` - Get merged hierarchy
  - `TestPattern()` - Test regex pattern

- **Policy Override Methods** (Enterprise)
- **Dynamic Policy Methods**
- **New Types**: `StaticPolicy`, `DynamicPolicy`, `PolicyOverride`

## [1.5.1] - 2025-12-23

### Added

- **MAP Timeout Configuration** - New `MapTimeout` config option (default: 120s) for Multi-Agent Planning operations
  - MAP operations involve multiple LLM calls and can take 30-60+ seconds
  - Separate `mapHttpClient` with longer timeout
  - `GeneratePlan()` and `ExecutePlan()` now use the longer MAP timeout

## [1.5.0] - 2025-12-19

### Added

- **LLM Interceptors** - Transparent governance for LLM API calls (#8)
  - `WrapOpenAIClient()` for OpenAI API interception
  - `WrapAnthropicClient()` for Anthropic API interception
  - `WrapGeminiModel()` for Google Generative AI interception
  - Policy enforcement and audit logging for all providers
- Full feature parity with other SDKs for LLM interceptors

## [1.4.1] - 2025-12-15

### Added

- **Contract Testing Suite** - Validates SDK models against real API responses (#7)
  - JSON fixtures for all response types
  - Integration test workflow with GitHub Actions
- Unit tests for `parseTimeWithFallback` helper (#5)

### Fixed

- Datetime parsing with nanosecond precision (#4)
- `GeneratePlan()` and `ExecutePlan()` authentication with explicit user token (#4)

## [1.4.0] - 2025-12-10

### Changed

- Prepare for repository rename to `axonflow-sdk-go`
- Updated module path and documentation

## [1.3.0] - 2025-12-08

### Added

- **Gateway Mode API** - Support for direct LLM calls with policy enforcement (#1)
  - `GetPolicyApprovedContext()` for pre-checks
  - `AuditLLMCall()` for compliance logging
- Self-hosted mode for localhost deployments
  - Skip auth headers for localhost endpoints
  - License key optional for self-hosted
- User token parameter to `QueryConnector()` method

### Fixed

- Formatting in connectors example
- Printf format mismatch in basic example
- Nested error handling in SDK
- `PolicyEvaluationInfo.ProcessingTime` type mismatch

## [1.2.0] - 2025-12-04

### Added

- License-based authentication as primary method
- License key authentication support

## [1.1.0] - 2025-11-27

### Added

- License key authentication support
- Comprehensive examples with license key authentication

## [1.0.0] - 2025-10-27

### Added

- Initial release of AxonFlow Go SDK
- Core client with `ExecuteQuery()` for governed AI calls
- Policy enforcement with `PolicyViolationError`
- Multi-agent planning with `GeneratePlan()` and `ExecutePlan()`
- MCP connector operations (`ListConnectors`, `InstallConnector`, `QueryConnector`)
- Comprehensive type definitions
- Retry logic with exponential backoff
- Response caching with TTL
