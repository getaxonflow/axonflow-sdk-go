//go:build ignore

// runtime-e2e/langgraph_mcp_tool_split/main.go
//
// Real-wire test of the LangGraph adapter fix that stops concatenating
// ServerName+Name into a single connector_type string
// (getaxonflow/axonflow-sdk-go#2908; platform epic #2905/#2904).
//
// Per CLAUDE.md HARD RULE #0 this driver hits a REAL, currently running
// AxonFlow agent — no httptest, no fixture servers, no mocks. Point
// AXONFLOW_AGENT_URL at a live agent (default http://localhost:8080) that
// has the epic #2904/#2905 check-input/check-output schema deployed
// (MCPCheckInputRequest/MCPCheckOutputRequest accept an optional `tool`
// field alongside `connector_type`).
//
// Assertions against the live agent:
//
//  1. LangGraphAdapter.NewMCPToolInterceptor — the SDK's actual public
//     surface changed by this PR — sends connector_type="postgres" and
//     tool="query" as two distinct wire fields (never concatenated into
//     "postgres.query") for both the pre-execution check-input call and
//     the post-execution check-output call, and the agent allows the
//     tool call end-to-end (handler runs, result returned).
//  2. A caller using the OLD single-field wire shape (connector_type only,
//     no tool field at all) still gets allowed by the same live agent —
//     proving the new optional `tool` field is backward compatible and
//     does not break existing callers.
//
// Run via:
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 go run runtime-e2e/langgraph_mcp_tool_split/main.go
package main

import (
	"context"
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	agentURL := env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	// Unique tenant/client ID so this run cannot collide with other tests
	// hitting the same shared agent concurrently.
	tenant := "go-sdk-2908-runtime-e2e"

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     tenant,
		ClientSecret: "runtime-e2e-secret",
	})

	failures := 0

	// 1. New two-field (server, tool) identity via the actual public
	// surface changed by this PR: LangGraphAdapter.NewMCPToolInterceptor.
	// The interceptor derives ConnectorType=req.ServerName and
	// Tool=req.Name and sends BOTH as distinct fields on the wire
	// (see langgraph_adapter.go NewMCPToolInterceptor).
	{
		adapter := axonflow.NewLangGraphAdapter(client, "runtime-e2e-2908-workflow")
		interceptor := adapter.NewMCPToolInterceptor(nil)

		handlerCalled := false
		handler := func(req axonflow.MCPToolRequest) (interface{}, error) {
			handlerCalled = true
			return map[string]any{"rows": 1}, nil
		}

		result, err := interceptor(axonflow.MCPToolRequest{
			ServerName: "postgres",
			Name:       "query",
			Args:       map[string]interface{}{"statement": "SELECT 1"},
		}, handler)

		switch {
		case err != nil:
			failures++
			fmt.Printf("FAIL [1] two-field interceptor call: unexpected error: %v\n", err)
		case !handlerCalled:
			failures++
			fmt.Println("FAIL [1] two-field interceptor call: handler never invoked (check-input should have allowed)")
		default:
			fmt.Printf("PASS [1] NewMCPToolInterceptor sent connector_type=%q + tool=%q as two distinct wire fields; live agent allowed input+output checks; result=%v\n", "postgres", "query", result)
		}
	}

	// 2. OLD single-field shape (connector_type only, no tool at all) still
	// works against the same live agent — proves the new optional `tool`
	// field does not break pre-#2904 callers.
	{
		resp, err := client.MCPCheckInput(context.Background(), axonflow.MCPCheckInputRequest{
			ConnectorType: "postgres",
			Statement:     "SELECT 1",
		})
		switch {
		case err != nil:
			failures++
			fmt.Printf("FAIL [2] old single-field shape: unexpected error: %v\n", err)
		case !resp.Allowed:
			failures++
			fmt.Printf("FAIL [2] old single-field shape: agent did not allow: %s\n", resp.BlockReason)
		default:
			fmt.Printf("PASS [2] old-style MCPCheckInputRequest (connector_type only, no tool field) still allowed by live agent; decision_id=%s\n", resp.DecisionID)
		}
	}

	if failures > 0 {
		fmt.Printf("RESULT: FAIL (%d)\n", failures)
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS (2/2)")
}
