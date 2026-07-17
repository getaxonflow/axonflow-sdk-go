# Runtime proof — LangGraph MCP interceptor sends `connector_type` + `tool` as two fields

Verifies the fix in #2908: `LangGraphAdapter.NewMCPToolInterceptor` used to
derive a single `connector_type` string by concatenating
`"{serverName}.{toolName}"`. It now sends `connector_type` (server name) and
`tool` (tool name) as two separate fields on `MCPCheckInputRequest` /
`MCPCheckOutputRequest`, matching the platform's two-field (server, tool)
identity contract added in epic #2905 / #2904
(`platform/agent/mcp_handler.go`).

## Prereqs

A real, currently running AxonFlow agent reachable at `AXONFLOW_AGENT_URL`
(default `http://localhost:8080`) that has the epic #2904/#2905 schema
deployed — i.e. `/api/v1/mcp/check-input` and `/api/v1/mcp/check-output`
accept the optional `tool` field. Community mode requires no license/auth
setup beyond Basic auth derived from `ClientID`/`ClientSecret` (any values
work in community mode).

## Usage

```sh
export AXONFLOW_AGENT_URL=http://localhost:8080   # default, can be omitted
go run runtime-e2e/langgraph_mcp_tool_split/main.go
```

Expected output:

```
PASS [1] NewMCPToolInterceptor sent connector_type="postgres" + tool="query" as two distinct wire fields; live agent allowed input+output checks; result=map[rows:1]
PASS [2] old-style MCPCheckInputRequest (connector_type only, no tool field) still allowed by live agent; decision_id=<uuid>
RESULT: PASS (2/2)
```

## What it asserts

1. `NewMCPToolInterceptor(nil)` — the SDK's actual public surface changed by
   this PR — invoked with `MCPToolRequest{ServerName: "postgres", Name:
   "query"}` sends `connector_type="postgres"` and `tool="query"` as two
   distinct fields (never `"postgres.query"`) on both the check-input and
   check-output calls, and the live agent allows the call end-to-end (the
   wrapped handler actually runs and its result is returned).
2. A direct `Client.MCPCheckInput` call using the OLD single-field wire
   shape (`ConnectorType` only, `Tool` left unset/omitted) is still allowed
   by the same live agent — proving the new optional `tool` field is
   backward compatible with pre-#2904 callers.

## Mutation proof

Revert `langgraph_adapter.go`'s `NewMCPToolInterceptor` to concatenate
`req.ServerName + "." + req.Name` into `ConnectorType` (and drop the `Tool:`
field) and rerun. Assertion [1] does not fail against the live agent (both
old and new shapes are accepted by the platform), but the unit tests in
`langgraph_adapter_test.go` (`TestLangGraphAdapter_MCPToolInterceptor_DefaultConnectorTypeAndTool`)
catch the regression at the wire-body level. This runtime-e2e proof
confirms the *new* shape is genuinely accepted end-to-end by a real,
currently deployed agent — not just accepted by a mock.
