# caller_name_audit (getaxonflow/axonflow-enterprise#2912, epic #2905)

Real-stack proof that `AuditToolCallRequest.CallerName` (wire: `caller_name`)
reaches `policy_details.caller_name` on the persisted audit row, driven
entirely through the SDK's real public `client.AuditToolCall` against a live
agent + orchestrator. No mocks.

## Background

`audit_tool_call`'s `tool_type` field was misleadingly named: every real
caller (claude_code/codex/cursor/openclaw) used it to identify WHICH CLIENT
made the call, not any property of the tool. `CallerName` is the field that
matches that contract. `ToolType` is kept as a **deprecated input fallback**,
not removed, not renamed. The server resolves: `caller_name` if supplied,
else the legacy `tool_type`, else a default.

## What this proves

1. **`CallerName` alone** reaches `policy_details.caller_name`, and the legacy
   `tool_type` key is no longer written for new rows.
2. **Legacy `ToolType` alone** (no `CallerName`) falls back correctly into
   `policy_details.caller_name` (backward compatible).
3. **Both supplied** — `CallerName` wins; the stale `tool_type` value never
   leaks into `policy_details`.

The typed SDK audit read does not surface `policy_details` yet, so the
read-back uses a raw HTTP GET to `/api/v1/audit/{id}` through the same agent,
with the identical Basic-auth credentials the SDK's own transport sent for the
write, mirroring `runtime-e2e/decision_context_transfer_basis`.

## Prerequisite: platform support is not yet on `main`

`caller_name` support (axonflow-enterprise#2953) is implemented but, as of this
writing, still an open PR on the `feat/2912-caller-name-tool-type-deprecation`
branch, not yet merged to `axonflow-enterprise` main. Against a stack built
from `axonflow-enterprise` main this test will FAIL (the polling loop times out
waiting for `policy_details.caller_name`, which the server does not write yet).
That is not a bug in this test; it means the platform side is not deployed on
the stack you are pointed at. Point your local `axonflow-enterprise` checkout at
that branch (or a later commit that includes it) before running.

## Run

Community mode needs no license: any client ID is its own tenant. The program
carries `//go:build ignore`, so run it directly:

```bash
AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_TENANT_ID=<registered client id> \
AXONFLOW_TENANT_SECRET=<its secret> \
  go run ./runtime-e2e/caller_name_audit/main.go
```

The defaults target a local community stack. Exits non-zero (and prints
`FAIL: ...`) if any assertion fails, or if the anti-skip guard trips (fewer
assertions ran than expected).
