# caller_name_audit (getaxonflow/axonflow-enterprise#2912, epic #2905)

Real-stack proof that `AuditToolCallRequest.CallerName` (wire: `caller_name`)
reaches `policy_details.caller_name` on the persisted audit row, driven
through the SDK's real public `client.AuditToolCall` against a live
agent + orchestrator. No mocks.

## Background

`audit_tool_call`'s `tool_type` field was misleadingly named: every real
caller (claude_code/codex/cursor/openclaw) used it to identify WHICH CLIENT
made the call, not any property of the tool. `CallerName` is the field that
matches that contract. `ToolType` is kept as a **deprecated input fallback**,
not removed, not renamed. The server resolves: `caller_name` if supplied,
else the legacy `tool_type`, else the default `"unknown"` (#2903 changed
that default from the earlier `"claude_code"` - an unidentified caller must
not be silently attributed to a specific client).

Platform support (axonflow-enterprise#2953, with #2903 folded into the same
merge) is merged and shipped in platform v9.11.0. Against an older stack the
server silently drops `caller_name` and this test fails by timeout; that
means the stack predates v9.11.0, not that the test is broken.

## What this proves

1. **`CallerName` supplied** - it reaches `policy_details.caller_name` on a
   real `audit_logs` row, and the legacy `tool_type` key is no longer
   written for new rows.
2. **Neither `CallerName` nor `ToolType` supplied** - the persisted row
   resolves `policy_details.caller_name` to `"unknown"` (#2903), not the
   old `"claude_code"` default.

(The marshalling-level behaviour, including the legacy `ToolType` fallback
input, is covered by the httptest-based unit tests in `audit_test.go`; this
leg is about what the real platform persists.)

The typed SDK audit read (`AuditLogEntry`) does not surface
`policy_details` (an internal JSONB blob), so the read-back polls a raw
HTTP GET to `/api/v1/audit/tenant/{tenantID}` (the same route
`GetAuditLogsByTenant` hits) through the same agent, with the identical
Basic-auth credentials the SDK's own transport sent for the write. The
orchestrator's AuditLogger batch-writes every 10s, so the poll allows up
to 25s for each row to land.

## Deployment-mode caveat

The read-back route is scoped by caller role/identity in non-community
deployment modes (`resolveCallerReadScope`), so a bare Basic-Auth machine
caller sees an empty page and this test times out even though the row was
written correctly. Run it against a stack with `DEPLOYMENT_MODE=community`,
or against an enterprise stack with a per-user identity header wired in.

## Run

Community mode needs no license: any client ID is its own tenant. The
program carries `//go:build ignore`, so run it directly:

```bash
AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_TENANT_ID=<registered client id> \
AXONFLOW_TENANT_SECRET=<its secret> \
  go run ./runtime-e2e/caller_name_audit/main.go
```

The defaults target a local community stack. See `../README.md` for how to
register a tenant against a local stack. Exits non-zero (and prints
`FAIL: ...`) if any assertion fails or a row does not appear in time.
