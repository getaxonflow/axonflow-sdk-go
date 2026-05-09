# Changelog

All notable changes to the AxonFlow Go SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [8.0.0] - 2026-05-09 — Decision History API + policy_version recorded on every decision + telemetry simplification

**Major release.** The headline feature is the new decision-history client API:
`ListDecisions` for paging through recorded decisions, plus a runnable example
showing the full record → list → explain audit flow. Bundled into a major
because the v8 line also tightens the telemetry contract — see `Removed` at
the bottom of this entry for that.

### Added

- **`ListDecisions(opts ListDecisionsOptions)` client method.** Pages over
 recorded decision history from the orchestrator, mirroring `GET
 /api/v1/decisions`. Companion to the v7.4.0 `GetDecisionExplain` method —
 callers can now both list and drill in. See `examples/list_decisions/`.
- **`examples/explain-decision/`** end-to-end runnable example covering
 the full decision audit flow: record → list → explain.

### Migration guide (v7 → v8)

- **Module import path: `/v7` → `/v8`.** Required by Go's semantic-import
 versioning rule. To upgrade:
 ```bash
 go get github.com/getaxonflow/axonflow-sdk-go/v8@latest
 ```
 Then update every `import "github.com/getaxonflow/axonflow-sdk-go/v7"`
 in your code to `/v8`. No symbol-level changes from the path migration
 itself.
- **`AxonFlowConfig.TelemetryEnabled` field removed.** Code referencing
 this field will fail to compile. Migration: remove the field from your
 `AxonFlowConfig{}` literal. If you were using it to disable telemetry,
 set `AXONFLOW_TELEMETRY=off` in the environment instead — that's the
 sole opt-out lever as of v8. If you were using it to force-enable, the
 default is now ON for every mode so the field is no longer needed.

### Telemetry

- **`AXONFLOW_TELEMETRY=off` is the sole opt-out.** `AxonFlowConfig.TelemetryEnabled` field removed; sandbox-mode clients now fire on the same 7-day heartbeat schedule as production (was suppressed pre-v8), tagged `stream="sandbox"` so dev pings stay distinguishable.
- **Heartbeat payload v1 schema additions** on the wire: new `telemetry_type` and `deployment_mode` fields. Existing receivers continue working unchanged — strictly additive.

## [7.1.0] - 2026-05-06 — X-Axonflow-Client header + scope-aware license validation

**Companion release to platform v7.7.0.** The Go SDK now sends an
`X-Axonflow-Client` identification header on every governed request, which
the agent uses to derive the SDK request scope and validate it against any
license token's audience claim per the license matrix.

### Added

- **`X-Axonflow-Client: sdk-go/<version>` header** on every governed
 outbound request. Set automatically by the SDK transport; not
 configurable. Agents at v7.7.0+ derive request scope from this header
 and reject cross-quadrant token misuse (e.g. a SaaS Plugin Pro token
 paired with an SDK request) at the validator boundary. Older agents
 (pre-v7.7.0) ignore the header and continue to work unchanged.

### Compatibility

- **Go module path stays `github.com/getaxonflow/axonflow-sdk-go/v7`** —
 no major bump, no import-path migration. Existing v7.0.x callers
 rebuild against v7.1.0 with no source changes.
- **Backward-compatible against pre-v7.7.0 agents.** The header is
 silently dropped by older agents; the SDK behaves identically against
 v7.0.x / v7.1.x / v7.6.x agents as before.
- **Forward-compatible.** Future agent releases that require the header
 on specific governed surfaces will work with this SDK without further
 client changes.

### Companion releases (same day)

- **Platform v7.7.0** — V1 SaaS Plugin Pro launch, license matrix,
 per-tenant tier resolution, GDPR right-to-erasure
 ([CHANGELOG](https://github.com/getaxonflow/axonflow/blob/main/CHANGELOG.md))
- **Python SDK v7.1.0** / **TypeScript SDK v7.1.0** /
 **Java SDK v7.1.0** — same `X-Axonflow-Client` injection
- **Plugins** — Claude Code / Cursor / Codex v1.2.0; OpenClaw v2.2.0
 with Pro license token paste activating Pro features

axonflow-sdk-rust remains at v0.1.0 (preview); SDK-Rust will gain the
header in a future preview release.

## [7.0.0] - 2026-04-29 — Production, quality, and security hardening — upgrade encouraged

**Upgrade strongly recommended.** Over the past month we've shipped substantial production, quality, and security hardening across the AxonFlow SDKs and platform — upgrade to the latest major for a more secure, reliable, and bug-free experience.

**Security highlights from this release cycle:**
- **Webhook signing-key now exposed by SDK response type** (this release). The `Secret` (HMAC-SHA256) field on `WebhookSubscription` — returned by `CreateWebhook` — was missing from the SDK type, so callers had no way to retrieve the signing key and webhook signature verification was effectively un-implementable. The field is now wired through end-to-end. Documented in [`GHSA-mhc4-qq83-fmrr`](https://github.com/getaxonflow/axonflow-sdk-go/security/advisories/GHSA-mhc4-qq83-fmrr).
- **`DO_NOT_TRACK` opt-out removed in favor of `AXONFLOW_TELEMETRY=off`** (this release). `DO_NOT_TRACK` was unreliable because host CLIs and runtimes commonly inject `DO_NOT_TRACK=1` regardless of user intent; an explicit AxonFlow-scoped opt-out is the only signal we honor now.
- **Telemetry transport opt-out reliability** (last cycle, v6.x). Tests that mutate `DO_NOT_TRACK` no longer silently leak real pings from CI; the telemetry transport is mocked at the test boundary and a CI canary asserts it stays mocked.

Major release across the AxonFlow SDK family. Companion releases ship the same day: TypeScript v7.0.0 / Python v7.0.0 / Go v7.0.0 (with `/v7` module path migration) / Java v7.0.0. The full set of platform-side security fixes shipped alongside this release is documented in the consolidated platform advisory [`GHSA-9h64-2846-7x7f`](https://github.com/getaxonflow/axonflow/security/advisories/GHSA-9h64-2846-7x7f).

**Reliability and bug-fix highlights:**
- **`retry_context` + `idempotency_key` for cross-step de-duplication** (last cycle, v6.x). Workflow steps that retry across pod restarts no longer record duplicate audit entries; idempotency_key flows end-to-end through MAP HITL approve/reject responses.
- **Plane-scoped pending-approvals parity** (last cycle, v6.x). MAP plane now exposes `/api/v1/plans/approvals/pending` mirroring the WCP plane queue; the SDK gained a typed accessor with full pagination.
- **Synchronous telemetry send for short-lived processes** (last cycle, v6.x). Short-lived CLI invocations no longer drop the ping at process exit; the synchronous send path delivers reliably and a version-alignment CI gate keeps `Version` and `go.mod` in lockstep.

### BREAKING

- **Module import path is now `github.com/getaxonflow/axonflow-sdk-go/v7`** (was `/v6`). Required by Go's semantic-import versioning rule for any module at v2+. To upgrade: `go get github.com/getaxonflow/axonflow-sdk-go/v7@latest` and update every import statement from `/v6` → `/v7`. No symbol-level changes from the path migration itself.
- **`DO_NOT_TRACK` is no longer honored as an AxonFlow telemetry opt-out.** Use `AXONFLOW_TELEMETRY=off` instead. Host tools and CLIs commonly inject `DO_NOT_TRACK=1` regardless of user intent, which makes it unreliable as a signal.

### Changed

- **Telemetry switched to a 7-day delivered-heartbeat.** At most one anonymous ping per environment every 7 days, with the stamp advanced only after the POST returns 2xx — a transient network failure doesn't silence telemetry until the next window. Concurrent goroutines are de-duplicated by an in-flight gate. Restricted runtimes where `os.UserCacheDir()` is unavailable (e.g. AWS Lambda) fall back transparently to the previous "one ping per process" behavior.

### Fixed

- The `DO_NOT_TRACK=1 is deprecated.` `log.Printf` warning is no longer emitted on every `NewClient` call when `DO_NOT_TRACK=1` is set.

## [6.0.0] - 2026-04-28 — ListProviders() + SDKCompatibility wire-shape fix

Major release. The breaking change is `SDKCompatibility.MinSDKVersion` and `RecommendedSDKVersion` moving from `string` to `map[string]string` to match the real on-the-wire shape the platform has been returning since v4.8.0. Coordinated cycle: TypeScript v6.2.0 / Python v6.9.0 / Java v6.2.0 ship same day as minors.

### BREAKING

- **Module import path is now `github.com/getaxonflow/axonflow-sdk-go/v6`** (was `/v5`). Required by Go's semantic-import versioning rule for any module at v2+. To upgrade: `go get github.com/getaxonflow/axonflow-sdk-go/v6@latest` and update every import statement from `/v5` → `/v6`. No symbol-level changes from the path migration itself.
- **`SDKCompatibility.MinSDKVersion`** and **`SDKCompatibility.RecommendedSDKVersion`** are now `map[string]string` (per-language) instead of `string`, matching the actual on-the-wire shape returned by the platform `/health` endpoint since v4.8.0. The previous `string` type silently unmarshalled the JSON object to an empty string, making the SDK version-mismatch warning a no-op. New helpers `(*SDKCompatibility).MinSDKVersionFor("go")` / `RecommendedSDKVersionFor("go")` return the per-language entry. Aligns Go with Java + TypeScript SDKs.

### Added

- **`(*AxonFlowClient).ListProviders(opts *ListProvidersOptions)`** — list configured LLM providers and their per-provider health snapshot. Calls `GET /api/v1/llm-providers`. New `LLMProvider` and `LLMProviderHealth` types; `ListProvidersOptions{Type, Enabled}` for filtering. Closes the parity gap with the Java SDK's `listLLMProviders()` and the Python SDK's `list_providers()`.

### Fixed

- **`Sandbox()`** now targets `http://localhost:8080` (was the decommissioned `https://staging-eu.getaxonflow.com`, torn down 2026-04-09). Override via `NewClient` with an explicit `Endpoint` for hosted environments.
- **All examples + READMEs** — replaced the decommissioned `staging-eu.getaxonflow.com` references with `http://localhost:8080` in `examples/basic/`, `examples/connectors/`, `examples/planning/`, `examples/README.md`, `README.md`, `SECURITY.md`, and `CONTRIBUTING.md`.
- **Stale `axonflow-go` module path corrected to `axonflow-sdk-go/v5`** in `examples/README.md`, `SECURITY.md`, and `CONTRIBUTING.md`. The bare `axonflow-go` resolved to a v1.17.0 relic the main README already warns about; the docs were sending readers straight into the trap.
- **`examples/basic/`, `examples/connectors/`** — replaced the hardcoded `"demo-user-token"` literal with an empty string. The SDK auto-populates `user_token` (defaulting to `"anonymous"`); the literal was rejected outright by stacks with JWT middleware enabled.
- **`README.md` VPC example + `SECURITY.md` HTTPS example** — replaced fictional `vpc-private-endpoint.getaxonflow.com` and `api.getaxonflow.com` hostnames with clearly-placeholder `*.example.com` URLs.

## [5.8.0] - 2026-04-25 — Plugin Batch 1 explainability fields on MCP responses

Minor release. Surfaces fields the AxonFlow agent has emitted since v7.1.0 (Plugin Batch 1) but the SDK didn't declare. Pure field-additions on existing methods — `,omitempty`-tagged so existing user code keeps compiling. Documented in OpenAPI via platform v7.4.3.

Coordinated cycle: TypeScript v6.1.0 / Python v6.8.0 / Java v6.1.0 ship same day with the same field set.

### Added

- **`MCPCheckInputResponse`** gains 5 optional Plugin Batch 1 fields:
 - `DecisionID string` — audit correlator
 - `RiskLevel string` — `low` | `medium` | `high` | `critical`
 - `PolicyMatches []ExplainPolicy` — per-policy explainability records
 - `OverrideAvailable *bool` — whether session override is permitted for the matched policies
 - `OverrideExistingID string` — already-active override consumed by this decision (if any)
- **`MCPCheckOutputResponse`** gains 3 optional fields:
 - `DecisionID`
 - `PolicyMatches []ExplainPolicy`
 - `RedactedMessage string` — text-redaction counterpart to `RedactedData` (used when the connector returned a string message rather than tabular rows; e.g. execute-style responses)

`ExplainPolicy` already shipped (in `decisions.go`) — same struct now reused on MCP responses. Pre-v7.1.0 platforms return zero values; callers should treat absence as "context not available" rather than an error.

### Deferred

`Client.ExplainDecision(ctx, decisionID)` and the full `ExplainRule` / `DecisionExplanation` type surface are tracked separately as feature work. This release ships only field-surfacing on existing methods.

## [5.7.0] - 2026-04-25 — Wire-shape canonicalization

Minor release. Purely additive — new fields are pointer or `,omitempty`-tagged so existing user code keeps compiling; deprecated aliases preserved for source-compat. Coordinated with TypeScript v6.0.0 / Java v6.0.0 / Python v6.7.0 SDK releases. The wire-shape contract gate's pinned OpenAPI spec SHA bumps with the platform v7.4.2 spec corrections; one baseline drift entry (`DynamicPolicyInfo`) auto-resolves.

### Added

- **`WebhookSubscription.Secret`** — HMAC-SHA256 signing key now exposed on the response from `CreateWebhook`. Required to verify the `X-AxonFlow-Signature` header on inbound webhook deliveries; without it, callers couldn't validate payload authenticity. Also adds `OrgID` and `TenantID` (ownership scoping).
- **`StepGateRequest`** carries `TokensIn`, `TokensOut`, `CostUSD` so budget-based policies can evaluate gate-time cost estimates.
- **`StepGateResponse.DecisionID`** — unique audit correlator that links a gate response to its audit row (previously absent on the SDK, present on the wire).
- **`ListWorkflowsResponse.Limit` / `Offset`** — pagination echo, surfaced on the response.
- **`StaticPolicy.PolicyID` / `Priority`** — wire-canonical fields surfaced.
- **`CreateStaticPolicyRequest.Priority` / `Tags`** and **`UpdateStaticPolicyRequest.Priority` / `Tags`** — match the spec.
- **`UpdatePlanRequest.Metadata`** — accept arbitrary plan metadata, opaque to the platform.
- **`UsageBreakdownItem.GroupBy`** — dimension name (provider/model/agent/etc.) is now exposed on each item.
- **`BudgetAlert.Acknowledged`** — alert dismissal flag.
- **`Budget.OrgID` / `TenantID`** — ownership scoping.
- **`UsageRecord`** gains `CreatedAt`, `Success`, `ErrorMessage`, `LatencyMS`, `TeamID`, `TenantID`, `UserID`, `WorkflowID` to match the wire. The legacy `Timestamp` field is `Deprecated`; the wire emits `created_at`, so `Timestamp` has always read empty.
- **`WorkflowStatusResponse.Metadata`** — arbitrary workflow metadata.
- **`CreateWorkflowResponse.StartedAt`** — wire-canonical timestamp. Legacy `CreatedAt` and `Source` are `Deprecated`; they have always read zero/empty (wire emits neither).
- **`ExecutionSnapshot.RetryCount`** — number of retry attempts on a step.
- **`Finding.Article`** — regulatory article reference (e.g. MAS FEAT principle number).
- **`PolicyOverride.ID` / `EnabledOverride`** — wire-canonical fields. `Active` is `Deprecated`; the wire emits `enabled_override`, so `Active` has always read false.
- **`PolicyVersion.ID` / `PolicyID` / `ChangeSummary` / `Snapshot`** — match the wire shape (versions are immutable snapshots, not before/after diffs). `ChangeDescription`, `PreviousValues`, `NewValues` are `Deprecated` orphan-reads.
- **`DynamicPolicyMatch.Message`** — wire-canonical name. `Reason` is `Deprecated` (read empty today).
- **`ExfiltrationCheckInfo.Exceeded` / `LimitType`** — match the wire. `WithinLimits` is `Deprecated`.
- **`CancelPlanResponse.Success`** — wire-canonical boolean. `Message` is `Deprecated` (orphan read).
- **`PlanResponse`** gains the wire top-level fields `Success`, `Version`, `Result`, `Error`, `WorkflowExecutionID`, `PolicyInfo`. The decoder is JSON.Decode passthrough, so consumers can now read these directly.
- **`ResumePlanResponse.Result`** — final aggregated result (canonical wire field). The 6 fields `WorkflowID`, `Message`, `StepResult`, `NextStep`, `NextStepName`, `TotalSteps` are now `Deprecated`; none of them were populated by the resume decoder against the actual server response.
- **`HealthResponse.Components` / `Features`** — match the wire health shape.

### Notes

The above is an audit-driven sweep against the wire-shape contract gate. All changes are additive (new fields are pointer or `,omitempty`-tagged so existing user code keeps compiling) or `Deprecated`-marked alias fields kept for source-compat. Removal scheduled for v6.

Two platform-side spec corrections filed alongside this work, for issues the audit surfaced where the spec was wrong (server emits the SDK's name): `AISystemRegistry.materiality_classification` and `DynamicPolicyInfo` schema. No SDK change for those — the SDK is correct.

## [5.6.1] - 2026-04-25

### Changed

- README makes the `/v5` import path requirement explicit. `go get github.com/getaxonflow/axonflow-sdk-go@latest` (without `/v5`) resolves to the pre-v2 `v1.17.0` relic; the correct module path is `github.com/getaxonflow/axonflow-sdk-go/v5`. Added a top-of-README banner, corrected the install command and import examples (all formerly `/v4`), and expanded the Migration Guide with v1→v5 and v4→v5 paths.

### Notes

- `go.mod` now declares `gopkg.in/yaml.v3` as a test-only dependency, used by the internal wire-shape contract CI (`contract_wire_shape_test.go` and the `internal/wireshape` helper package). It is not imported by any non-test source file, so consumers' compiled binaries do not link it — the dep appears only in `go.sum` / `go mod graph`.

### Fixed

- Telemetry pings now deliver reliably from short-lived processes (CLI, serverless, cold-starts). `NewClient` blocks briefly (~350ms warm, ~1.3s cold; bounded at `telemetryTimeout`) while the ping is sent synchronously.
- Telemetry path is bounded at `telemetryTimeout` (3s) total; the `/health` probe and checkpoint POST share a single context deadline instead of stacking.

## [5.6.0] - 2026-04-22

### Added

- **Rich `ApproveStepResponse` / `RejectStepResponse`** — both types now carry the
 same shape as the step-gate response. `Decision` resolves to `"allow"` on a
 successful approval or `"block"` on rejection; `RetryContext` mirrors the gate
 response retry state; `ApprovedBy` / `ApprovedAt` / `RejectedBy` / `RejectedAt`
 carry the reviewer identity; `ApprovalID` is the deterministic HITL queue
 entry UUID; `PoliciesMatched` reconstructs the governance trail. Legacy fields
 (`WorkflowID`, `StepID`, `Status`) remain for back-compat.
- **`ApproveStepResponse.PlanID` / `RejectStepResponse.PlanID`** — populated when
 the response comes from the MAP plan-scoped endpoint; empty on WCP responses.
 The server projects both planes through a single helper, so the same SDK types
 work across both endpoints.
- **`GetPendingPlanApprovals`** — new client method that lists MAP-plane pending
 approvals (`GET /api/v1/plans/approvals/pending`), the counterpart of the
 existing `GetPendingApprovals` for the WCP plane. Accepts an optional
 `PlanID` filter via `PendingApprovalsOptions{PlanID: "plan-abc"}` so reviewer
 tools can scope the listing to one plan. Available on Evaluation+ licenses
 (same tier gate as the MAP step approve/reject endpoints).
- **`PendingApproval.PlanID`** — populated on MAP-plane entries, empty on WCP
 entries. Mirrors the approve/reject asymmetry. `PendingApproval` also gains
 `StepIndex`, `Decision`, `DecisionReason`, `PoliciesMatched`, `StepInput`,
 and `ApprovalStatus` so reviewer tools can render the full approval context
 without a second request.

### Fixed

- **`ApproveStep` / `RejectStep` / `GetPendingApprovals` endpoint URLs** — all
 three previously targeted non-existent paths under `/api/v1/workflow-control/`
 and would fail against a real AxonFlow server. Corrected to the canonical
 `/api/v1/workflows/{id}/steps/{step_id}/(approve|reject)` and
 `/api/v1/workflows/approvals/pending` routes. Customers using these methods
 against a live deployment were receiving 404s; this release makes them work.
- **`PendingApprovalsResponse` JSON tags** — the struct previously decoded
 `approvals` / `total`, which never matched the server wire format
 (`pending_approvals` / `count`). Fields are now `PendingApprovals` and
 `Count` with the correct JSON tags. Callers that ranged over `Approvals` or
 read `Total` need to update to the new names.

### Deprecated

- `DO_NOT_TRACK=1` as an AxonFlow telemetry opt-out — scheduled for removal after 2026-05-05 in the next major release. Use `AXONFLOW_TELEMETRY=off` instead. The SDK emits a one-line migration warning when `DO_NOT_TRACK=1` is the active control and `AXONFLOW_TELEMETRY=off` is not also set.

### Unchanged

- The `ApproveStep(workflowID, stepID)` and `RejectStep(workflowID, stepID)`
 method signatures are unchanged — only the response fields grew. Callers that
 only read `WorkflowID` / `StepID` / `Status` keep working.

## [5.5.0] - 2026-04-21

### Added

- **`retry_context` and `idempotency_key` support on the step gate** — `StepGateResponse`
 now carries a non-nullable `RetryContext` object on every gate call with the true
 `(workflow_id, step_id)` lifecycle: `GateCount`, `CompletionCount`,
 `PriorCompletionStatus` (`"none"` / `"completed"` / `"gated_not_completed"`),
 `PriorOutputAvailable`, `PriorOutput`, `PriorCompletionAt`, `FirstAttemptAt`,
 `LastAttemptAt`, `LastDecision`, and `IdempotencyKey`. Prefer these to the legacy
 `Cached` / `DecisionSource` fields.
- **`StepGateWithOptions`** — new method taking `StepGateOptions{IncludePriorOutput: bool}`
 (default `false`). When `true`, the SDK sends `?include_prior_output=true` and
 `RetryContext.PriorOutput` is populated when a prior `/complete` has landed. Existing
 `StepGate(workflowID, stepID, req)` is unchanged and calls `StepGateWithOptions` with
 zero options, so existing callers keep working.
- **`StepGateRequest.IdempotencyKey`** — caller-supplied opaque business-level key
 (max 255 chars). Immutable once recorded on the first gate call for a
 `(workflow_id, step_id)`; subsequent gate/complete calls must pass the same key.
- **`MarkStepCompletedRequest.IdempotencyKey`** — must match the key set on the
 corresponding gate call, if any. Mismatch (including missing-vs-set on either side)
 surfaces as a typed `*IdempotencyKeyMismatchError`.
- **`IdempotencyKeyMismatchError`** — typed error returned by `StepGate`,
 `StepGateWithOptions`, and `MarkStepCompleted` when the platform returns HTTP 409
 with `error.code == "IDEMPOTENCY_KEY_MISMATCH"`. Surfaces `WorkflowID`, `StepID`,
 `ExpectedIdempotencyKey`, `ReceivedIdempotencyKey`, and `Message`. Use
 `errors.As(err, &idemErr)` to unwrap.

### Deprecated

- **`StepGateResponse.Cached`** and **`StepGateResponse.DecisionSource`** — still populated
 but deprecated in favor of `RetryContext.GateCount > 1` and
 `RetryContext.PriorCompletionStatus`. Planned for removal in a future major version.

### Compatibility

Companion to the platform change that introduces `retry_context` on
`POST /api/v1/workflows/{workflow_id}/steps/{step_id}/gate`. Additive only — existing
callers that never set `IdempotencyKey` or `IncludePriorOutput` see no behavior change.

## [5.4.0] - 2026-04-18

### Added

- **Execution boundary semantics** — `RetryPolicy` type with `RetryPolicyIdempotent`
 (default) and `RetryPolicyReevaluate` constants. Step gate requests now accept
 `retry_policy` to control whether repeated calls for the same step return the
 cached decision or force a fresh policy evaluation.
- **Step gate response metadata** — `Cached` (bool) and `DecisionSource` (string)
 fields on `StepGateResponse` indicate whether the response came from a cached
 decision ("cached") or a fresh policy evaluation ("fresh").
- **Workflow checkpoints** — `GetCheckpoints(workflowID)` lists step-gate
 checkpoints for a workflow. `ResumeFromCheckpoint(workflowID, checkpointID)`
 resumes from a specific checkpoint with fresh policy evaluation (Enterprise).
- **Checkpoint types** — `Checkpoint`, `CheckpointListResponse`, and
 `ResumeFromCheckpointResponse` types for checkpoint operations.
- **`ExplainDecision(ctx, decisionID)`** — fetches the full explanation for a
 previously-made policy decision via `GET /api/v1/decisions/:id/explain`.
 Returns a `DecisionExplanation` containing matched policies, risk level,
 reason, override availability, existing override ID (if any), and a
 rolling-24h session hit count for the matched rule. Shape is frozen;
 additive-only fields ensure forward compatibility.
- **`AuditSearchRequest.DecisionID`, `PolicyName`, `OverrideID`** — three new
 optional filter fields on `SearchAuditLogs`. Use `DecisionID` to gather every
 record tied to one decision; `PolicyName` to find everything matched by a
 specific policy; `OverrideID` to reconstruct an override's full lifecycle
 (`override_created` → `override_used` → `override_expired | override_revoked`).

### Compatibility

Companion to platform v7.1.0. Works against plugin releases (OpenClaw v1.3.0+,
Claude Code v0.5.0+, Cursor v0.5.0+, Codex v0.4.0+) that surface the
`DecisionExplanation` shape. The new audit filter fields pass through when
unset; server-side filtering only activates on v7.1.0+ platforms.

## [5.3.1] - 2026-04-11

### Fixed

- `ListConnectors`, `GetConnector`, `GetConnectorHealth` now send Basic auth
 credentials. Previously bypassed the centralized auth mechanism by using
 `httpClient.Get()` directly, causing 401 errors on authenticated servers.
- `GetPlanStatus` now sends Basic auth credentials (same fix).
- All execution replay methods (`ListExecutions`, `GetExecution`,
 `GetExecutionSteps`, `GetExecutionTimeline`, `ExportExecution`,
 `DeleteExecution`) now send Basic auth credentials.

---

## [5.3.0] - 2026-04-09

### Added

- `AXONFLOW_TRY=1` environment variable to connect to `try.getaxonflow.com` shared evaluation server
- `RegisterTry()` and `RegisterTryWithEndpoint()` helpers for self-registering a tenant
- Checkpoint telemetry reports `endpoint_type: "community-saas"` when try mode is active

---

## [5.2.0] - 2026-04-08

### Added

- **Telemetry `endpoint_type` field.** The anonymous telemetry ping now includes an SDK-derived classification of the configured AxonFlow endpoint as one of `localhost`, `private_network`, `remote`, or `unknown`. The raw URL is never sent and is not hashed. This helps distinguish self-hosted evaluation from real production deployments on the checkpoint dashboard. Opt out as before via `DO_NOT_TRACK=1` or `AXONFLOW_TELEMETRY=off`.
- **`ClassifyEndpoint(url)` function and `EndpointType*` constants** exported from `telemetry.go` for applications that want to inspect the classification.

### Changed

- Examples and documentation updated to reflect the new AxonFlow platform v6.2.0 defaults for `PII_ACTION` (now `warn` — was `redact`) and the new `AXONFLOW_PROFILE` env var. No SDK API changes.

### Known issue (fixed in v5.3.0)

- `version.go` `Version` constant was not bumped in this release and still declares `"5.1.0"`. Published tag is `v5.2.0` but `axonflow.Version` returns `"5.1.0"`. Use v5.3.0 or later if you need an accurate SDK version string at runtime.

---

## [5.1.0] - 2026-04-06

### Added

- **`GovernedTool` adapter** — framework-agnostic tool governance wrapper. Wraps any `Tool` interface with input/output policy enforcement (`MCPCheckInput` before execution, `MCPCheckOutput` after). Helpers: `GovernTool(tool, client, opts)`, `GovernTools(tools, client, opts)`.
- **`CheckToolInput()` / `CheckToolOutput()`** — generic aliases for tool governance. Existing `MCPCheckInput()` / `MCPCheckOutput()` remain supported.
- **`PolicyViolationError`** in the main `axonflow` package, with `IsPolicyViolationError()` helper.

### Changed

- Anonymous telemetry is now enabled by default for all endpoints, including localhost/self-hosted evaluation. Opt out with `DO_NOT_TRACK=1` or `AXONFLOW_TELEMETRY=off`.

---

## [5.0.0] - 2026-04-05

### BREAKING CHANGES

- **`X-Tenant-ID` header removed.** The SDK no longer sends `X-Tenant-ID`. The server derives tenant from OAuth2 Client Credentials (Basic auth). Requires platform v6.0.0+.
- **`MaterialityClassification` field renamed.** MAS FEAT `AISystemRegistry.Materiality` renamed to `AISystemRegistry.MaterialityClassification` to match server JSON field `materiality_classification`.

### Added

- **`Status` field on `PlanResponse`.** The server returns plan status (pending, executing, completed, failed, cancelled) which was previously not parsed by the SDK.

### Fixed

- **MCP examples missing `client_id` and `user_token`** in request body for enterprise MCP handler authentication.

---

## [4.3.0] - 2026-03-25

### Added

- `SimulatePolicies()` — dry-run all active policies against an input query. Returns allowed/blocked status, applied policies, risk score, and daily usage. Requires Evaluation tier or above.
- `GetPolicyImpactReport()` — test a single policy against multiple inputs and get aggregate match/block statistics.
- `DetectPolicyConflicts()` — analyze active policies for contradictions, shadows, and redundancies. Optionally filter to conflicts involving a specific policy.
- Types: `SimulatePoliciesRequest`, `SimulatePoliciesResponse`, `SimulationDailyUsage`, `ImpactReportInput`, `ImpactReportRequest`, `ImpactReportResult`, `ImpactReportResponse`, `PolicyConflictRef`, `PolicyConflict`, `PolicyConflictResponse`

### Security

- `InsecureSkipTLSVerify` config field added as explicit opt-in for disabling TLS certificate verification. Previously only controllable via `NODE_TLS_REJECT_UNAUTHORIZED=0` environment variable. Warning log emitted when TLS verification is disabled. Resolves CodeQL `go/disabled-certificate-check` alert.

---

## [4.2.0] - 2026-03-17

### Added

- `LangGraphAdapter` — wraps LangGraph workflows with AxonFlow governance gates and per-tool policy enforcement. Includes:
 - `CheckGate()` / `StepCompleted()` — step-level governance at LangGraph node boundaries
 - `CheckToolGate()` / `ToolCompleted()` — per-tool governance within tool_call nodes (each tool gets its own gate check)
 - `NewMCPToolInterceptor()` — creates an interceptor enforcing `MCPCheckInput → handler → MCPCheckOutput` around every MCP tool call
 - `WaitForApproval()` — poll until a step is approved or rejected, with context cancellation support
 - `StartWorkflow()` / `CompleteWorkflow()` / `AbortWorkflow()` / `FailWorkflow()` — workflow lifecycle management
- `WorkflowBlockedError` and `WorkflowApprovalRequiredError` error types
- `NewLangGraphAdapter()` constructor with functional options (`WithSource()`, `WithAutoBlock()`)
- Option structs: `CheckGateOptions`, `StepCompletedOptions`, `CheckToolGateOptions`, `ToolCompletedOptions`
- MCP interceptor types: `MCPInterceptorOptions`, `MCPToolRequest`, `MCPToolHandler`, `MCPToolInterceptor`
- `GetCircuitBreakerStatus()` — query active circuit breaker circuits and emergency stop state
- `GetCircuitBreakerHistory(limit)` — retrieve circuit breaker trip/reset audit trail
- `GetCircuitBreakerConfig(tenantID)` — get effective circuit breaker config (global or tenant-specific)
- `UpdateCircuitBreakerConfig(config)` — update per-tenant circuit breaker thresholds

---

## [4.1.0] - 2026-03-14

### Added

- `AuditToolCall()` — record non-LLM tool calls (API, MCP, function) in the audit trail. Returns audit ID, status, and timestamp. Requires Platform v5.1.0+
- `GetAuditLogsByTenant()` — retrieve audit logs for a tenant with optional pagination
- `SearchAuditLogs()` — search audit logs with filters (client ID, request type, limit)

### Fixed

- Telemetry pings now suppressed for localhost/127.0.0.1/[::1] endpoints unless `TelemetryEnabled` is explicitly set to `true`. Prevents telemetry noise during local development.

---

## [4.0.0] - 2026-03-09

### Breaking Changes

- **Module path changed from `v3` to `v4`**: Update imports from
 `github.com/getaxonflow/axonflow-sdk-go/v3` to `github.com/getaxonflow/axonflow-sdk-go/v4`.
- **Removed `TotalSteps` from `CreateWorkflowRequest`**. Requires Platform v4.5.0+ (recommended v5.0.0+).
 Total steps are auto-computed when the workflow reaches a terminal state.
- **`MCPCheckInput()` default `Operation` changed from `"query"` to `"execute"`**: Aligns Go SDK with
 Python/Java behavior. Callers relying on the implicit `"query"` default must now pass
 `Operation: "query"` explicitly.

### Added

- v3 to v4 migration guide in README with import path and `TotalSteps` removal examples

### Note

`MediaAnalysisResult.ExtractedText` was replaced by `HasExtractedText` + `ExtractedTextLength`
in v3.5.0. This major version formally acknowledges that breaking change.

---

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

- **StepComplete Metrics**: `MarkStepCompletedRequest` now accepts post-execution metrics (`tokens_in`, `tokens_out`, `cost_usd`) for per-step LLM usage tracking
- **Media Governance Types**: `MediaContent`, `MediaAnalysisResult`, `MediaAnalysisResponse` for multimodal image governance
- **`ProxyLLMCallWithMedia()`**: Send images (base64 or URL) alongside queries for governance analysis before LLM routing

### Changed

- **Response cache skipped for media requests**: Requests containing media bypass the response cache (binary content makes cache keys unreliable)

### Breaking

- `MediaAnalysisResult.ExtractedText` replaced by `HasExtractedText` (bool) and `ExtractedTextLength` (int). Raw extracted text is no longer exposed in API responses.

---

## [3.4.0] - 2026-02-13

### Added

- **FailWorkflow**: Fail a workflow with optional reason
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

- **WCP Approval Gates**: HITL approval and rejection for workflow steps
 - `ApproveStep(workflowID, stepID)` - Approve a pending workflow step
 - `RejectStep(workflowID, stepID, reason)` - Reject a step with reason
 - `GetPendingApprovals(opts)` - List steps awaiting human approval

- **MAP Plan Cancellation**: Cancel running multi-agent plans
 - `CancelPlan(planID, reason)` - Cancel a plan with optional reason (omits reason from body when empty)

- **MAP Plan Update**: Modify plan configuration before or during execution
 - `UpdatePlan(planID, request)` - Update execution mode, domain, or version

- **MAP Plan Versioning and Rollback**: Version history and rollback support
 - `GetPlanVersions(planID)` - List plan version history
 - `RollbackPlan(planID, version)` - Rollback to a previous version (returns `ErrVersionConflict` on 409)
 - New types: `RollbackPlanResponse`, `PlanVersion`

- **Webhook Subscriptions**: Event notification management
 - `CreateWebhook(request)` - Create a webhook subscription
 - `ListWebhooks()` - List active webhook subscriptions
 - `GetWebhook(webhookID)` - Get webhook details
 - `UpdateWebhook(webhookID, request)` - Update webhook configuration
 - `DeleteWebhook(webhookID)` - Delete a webhook subscription
 - New type: `WebhookSubscription`

- **Unified Execution Cancellation**: Cancel running executions across both MAP and WCP subsystems
 - `CancelExecution(executionID, reason)` - Cancel a unified execution via `POST /api/v1/unified/executions/{id}/cancel`
 - Propagates to MAP `CancelPlan()` or WCP `AbortWorkflow()` based on execution type
 - Reason is optional: pass empty string to cancel without a reason

### Fixed

- **`ExecutePlan` status hardcoded**: `ExecutePlan()` always returned `Status: "completed"` regardless of actual server response. Now reads status from response (`data.status` > `metadata.status` > default), correctly surfacing `"awaiting_approval"` for WCP confirm mode.
- **Unified execution API URLs**: `GetExecutionStatus()` and `ListUnifiedExecutions()` now use correct `/api/v1/unified/executions` path (was incorrectly pointing to `/api/v1/executions` which is the Execution Replay API)
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

- **Unified Execution Tracking**: Consistent status tracking for MAP plans and WCP workflows
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

- **Workflow Policy Enforcement**: Policy transparency for workflow operations
 - `StepGateResponse` now includes `PoliciesEvaluated` and `PoliciesMatched` fields with `PolicyMatch` type
 - `PolicyMatch` type with `PolicyID`, `PolicyName`, `Action`, `Reason` for policy transparency
 - `PolicyEvaluationResult` type for MAP execution with `Allowed`, `AppliedPolicies`, `RiskScore`
 - Workflow operations (`workflow_created`, `workflow_step_gate`, `workflow_completed`) logged to audit trail

---

## [2.5.0] - 2026-01-17

### Added

- **Workflow Control Plane**: Governance gates for external orchestrators
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

- **MCP Exfiltration Detection**: `PolicyInfo` now includes `ExfiltrationCheck` with row/volume limit information
 - `ExfiltrationCheckInfo` type with `RowsReturned`, `RowLimit`, `BytesReturned`, `ByteLimit`, `WithinLimits` fields
 - Prevents large-scale data extraction via MCP queries
 - Configurable via `MCP_MAX_ROWS_PER_QUERY` and `MCP_MAX_BYTES_PER_QUERY` environment variables

- **MCP Dynamic Policies**: `PolicyInfo` now includes `DynamicPolicyInfo` for Orchestrator-evaluated policies
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
client:= axonflow.NewClient(axonflow.AxonFlowConfig{
 Endpoint: "http://localhost:8080",
 ClientID: "my-app", // Used for request identification
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
 - API returns `{"policies": [.]}` and `{"policy": {.}}` wrappers
 - Added `dynamicPoliciesResponse` and `dynamicPolicyResponse` wrapper structs

## [2.0.0] - 2026-01-05

### Breaking Changes

- **BREAKING**: Renamed `AgentURL` to `Endpoint` in `AxonFlowConfig`
- **BREAKING**: Removed `OrchestratorURL` and `PortalURL` config options (Agent now proxies all routes)
- **BREAKING**: Dynamic policy API path changed from `/api/v1/policies/dynamic` to `/api/v1/dynamic-policies`

### Added

- **Audit Log Reading**: Added `SearchAuditLogs()` for searching audit logs with filters (user email, client ID, time range, request type)
- **Tenant Audit Logs**: Added `GetAuditLogsByTenant()` for retrieving audit logs scoped to a specific tenant
- **Audit Types**: Added `AuditLogEntry`, `AuditSearchRequest`, `AuditQueryOptions`, and `AuditSearchResponse` types
- **PII Redaction Support**: Added `RequiresRedaction` field to `PolicyApprovalResult`
 - When `true`, PII was detected with redact action and response should be processed for redaction
 - Supports new detection defaults: PII defaults to redact instead of block

### Changed

- All SDK methods now route through single Agent endpoint
- Simplified configuration - only `Endpoint` field needed
- Removed `getOrchestratorURL()` and `getPortalURL()` helper methods

### Migration Guide

**Before (v1.x):**
```go
client:= axonflow.NewClient(axonflow.AxonFlowConfig{
 AgentURL: "http://localhost:8080",
 OrchestratorURL: "http://localhost:8081",
 PortalURL: "http://localhost:8082",
 ClientID: "my-client",
 ClientSecret: "my-secret",
})
```

**After (v2.x):**
```go
client:= axonflow.NewClient(axonflow.AxonFlowConfig{
 Endpoint: "http://localhost:8080",
 ClientID: "my-client",
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

- **Code Governance Support** - `CodeArtifact` type for detecting and auditing LLM-generated code
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

- **LLM Interceptors** - Transparent governance for LLM API calls
 - `WrapOpenAIClient()` for OpenAI API interception
 - `WrapAnthropicClient()` for Anthropic API interception
 - `WrapGeminiModel()` for Google Generative AI interception
 - Policy enforcement and audit logging for all providers
- Full feature parity with other SDKs for LLM interceptors

## [1.4.1] - 2025-12-15

### Added

- **Contract Testing Suite** - Validates SDK models against real API responses
 - JSON fixtures for all response types
 - Integration test workflow with GitHub Actions
- Unit tests for `parseTimeWithFallback` helper

### Fixed

- Datetime parsing with nanosecond precision
- `GeneratePlan()` and `ExecutePlan()` authentication with explicit user token

## [1.4.0] - 2025-12-10

### Changed

- Prepare for repository rename to `axonflow-sdk-go`
- Updated module path and documentation

## [1.3.0] - 2025-12-08

### Added

- **Gateway Mode API** - Support for direct LLM calls with policy enforcement
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
