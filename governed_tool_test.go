// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package axonflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mockTool is a test implementation of the Tool interface.
type mockTool struct {
	name        string
	description string
	invokeFn    func(ctx context.Context, input any) (any, error)
	invoked     atomic.Bool
}

func (m *mockTool) Name() string        { return m.name }
func (m *mockTool) Description() string { return m.description }
func (m *mockTool) Invoke(ctx context.Context, input any) (any, error) {
	m.invoked.Store(true)
	if m.invokeFn != nil {
		return m.invokeFn(ctx, input)
	}
	return "default result", nil
}

// setupGovernedToolTestServer creates a test server for GovernedTool tests.
func setupGovernedToolTestServer(t *testing.T, handlers map[string]http.HandlerFunc) (*httptest.Server, *AxonFlowClient) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		for pattern, handler := range handlers {
			if strings.Contains(r.URL.Path, pattern) {
				handler(w, r)
				return
			}
		}

		// Default: allow everything
		switch {
		case r.URL.Path == "/api/v1/mcp/check-input" && r.Method == "POST":
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:           true,
				PoliciesEvaluated: 3,
			})
		case r.URL.Path == "/api/v1/mcp/check-output" && r.Method == "POST":
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed:           true,
				PoliciesEvaluated: 2,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	t.Cleanup(func() { server.Close() })
	return server, client
}

func TestGovernedTool_CleanCallAllowed(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, nil)

	tool := &mockTool{
		name:        "search",
		description: "Search the web",
		invokeFn: func(_ context.Context, _ any) (any, error) {
			return "search results for AI", nil
		},
	}

	governed := GovernTool(tool, client, nil)
	result, err := governed.Invoke(context.Background(), "latest AI research")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result != "search results for AI" {
		t.Errorf("expected 'search results for AI', got: %v", result)
	}
	if !tool.invoked.Load() {
		t.Error("expected tool to be invoked")
	}
}

func TestGovernedTool_InputBlocked(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:     false,
				BlockReason: "dangerous command detected",
			})
		},
	})

	tool := &mockTool{name: "shell", description: "Run shell commands"}
	governed := GovernTool(tool, client, nil)

	_, err := governed.Invoke(context.Background(), "rm -rf /")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !IsPolicyViolationError(err) {
		t.Errorf("expected PolicyViolationError, got %T: %v", err, err)
	}

	var pve *PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatal("expected errors.As to succeed")
	}
	if pve.Reason != "dangerous command detected" {
		t.Errorf("expected reason 'dangerous command detected', got: %s", pve.Reason)
	}

	if tool.invoked.Load() {
		t.Error("tool should NOT be invoked when input is blocked")
	}
}

func TestGovernedTool_OutputBlocked(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed:     false,
				BlockReason: "PII detected in output",
			})
		},
	})

	tool := &mockTool{
		name:        "db-query",
		description: "Query database",
		invokeFn: func(_ context.Context, _ any) (any, error) {
			return "SSN: 123-45-6789", nil
		},
	}

	governed := GovernTool(tool, client, nil)
	_, err := governed.Invoke(context.Background(), "SELECT * FROM users")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !IsPolicyViolationError(err) {
		t.Errorf("expected PolicyViolationError, got %T: %v", err, err)
	}

	// Tool SHOULD have been invoked (output check happens after execution)
	if !tool.invoked.Load() {
		t.Error("tool should be invoked before output check")
	}
}

func TestGovernedTool_OutputRedacted(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed:      true,
				RedactedData: "SSN: [REDACTED:ssn]",
			})
		},
	})

	tool := &mockTool{
		name:        "db-query",
		description: "Query database",
		invokeFn: func(_ context.Context, _ any) (any, error) {
			return "SSN: 123-45-6789", nil
		},
	}

	governed := GovernTool(tool, client, nil)
	result, err := governed.Invoke(context.Background(), "SELECT * FROM users")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result != "SSN: [REDACTED:ssn]" {
		t.Errorf("expected redacted data, got: %v", result)
	}
}

func TestGovernedTool_CustomConnectorTypeFn(t *testing.T) {
	var capturedConnectorType string

	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			var req MCPCheckInputRequest
			json.NewDecoder(r.Body).Decode(&req)
			capturedConnectorType = req.ConnectorType
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})

	tool := &mockTool{name: "search", description: "Search"}
	governed := GovernTool(tool, client, &GovernedToolOptions{
		ConnectorTypeFn: func(name string) string {
			return "custom." + name
		},
	})

	_, _ = governed.Invoke(context.Background(), "test")

	if capturedConnectorType != "custom.search" {
		t.Errorf("expected connector type 'custom.search', got: %s", capturedConnectorType)
	}
}

func TestGovernedTool_CustomOperation(t *testing.T) {
	var capturedOperation string

	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			var req MCPCheckInputRequest
			json.NewDecoder(r.Body).Decode(&req)
			capturedOperation = req.Operation
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})

	tool := &mockTool{name: "read-db", description: "Read-only DB query"}
	governed := GovernTool(tool, client, &GovernedToolOptions{
		Operation: "query",
	})

	_, _ = governed.Invoke(context.Background(), "SELECT 1")

	if capturedOperation != "query" {
		t.Errorf("expected operation 'query', got: %s", capturedOperation)
	}
}

func TestGovernTools_Batch(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, nil)

	tools := []Tool{
		&mockTool{name: "search", description: "Search the web"},
		&mockTool{name: "calculator", description: "Do math"},
		&mockTool{name: "weather", description: "Get weather"},
	}

	governed := GovernTools(tools, client, nil)

	if len(governed) != 3 {
		t.Fatalf("expected 3 governed tools, got %d", len(governed))
	}

	for i, g := range governed {
		if g.Name() != tools[i].Name() {
			t.Errorf("tool %d: expected name %s, got %s", i, tools[i].Name(), g.Name())
		}
		if g.Description() != tools[i].Description() {
			t.Errorf("tool %d: expected description %s, got %s", i, tools[i].Description(), g.Description())
		}
	}

	// Each tool should be independently invocable
	result, err := governed[0].Invoke(context.Background(), "test query")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result != "default result" {
		t.Errorf("expected 'default result', got: %v", result)
	}
}

func TestGovernedTool_StringInputPassthrough(t *testing.T) {
	var capturedStatement string

	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			var req MCPCheckInputRequest
			json.NewDecoder(r.Body).Decode(&req)
			capturedStatement = req.Statement
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})

	tool := &mockTool{name: "echo", description: "Echo input"}
	governed := GovernTool(tool, client, nil)

	_, _ = governed.Invoke(context.Background(), "hello world")

	if capturedStatement != "hello world" {
		t.Errorf("expected statement 'hello world', got: %s", capturedStatement)
	}
}

func TestGovernedTool_ObjectInputJSONMarshal(t *testing.T) {
	var capturedStatement string

	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			var req MCPCheckInputRequest
			json.NewDecoder(r.Body).Decode(&req)
			capturedStatement = req.Statement
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})

	tool := &mockTool{name: "structured", description: "Structured input"}
	governed := GovernTool(tool, client, nil)

	input := map[string]interface{}{
		"query": "test",
		"limit": 10,
	}
	_, _ = governed.Invoke(context.Background(), input)

	// Verify the statement is valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(capturedStatement), &parsed); err != nil {
		t.Fatalf("expected valid JSON statement, got: %s (error: %v)", capturedStatement, err)
	}
	if parsed["query"] != "test" {
		t.Errorf("expected query='test' in parsed JSON, got: %v", parsed["query"])
	}
}

func TestGovernedTool_NilOptsDefaults(t *testing.T) {
	var capturedConnectorType string
	var capturedOperation string

	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			var req MCPCheckInputRequest
			json.NewDecoder(r.Body).Decode(&req)
			capturedConnectorType = req.ConnectorType
			capturedOperation = req.Operation
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})

	tool := &mockTool{name: "my-tool", description: "My tool"}
	governed := GovernTool(tool, client, nil)

	_, _ = governed.Invoke(context.Background(), "test")

	// Default connector type = tool name
	if capturedConnectorType != "my-tool" {
		t.Errorf("expected default connector type 'my-tool', got: %s", capturedConnectorType)
	}

	// Default operation = "execute"
	if capturedOperation != "execute" {
		t.Errorf("expected default operation 'execute', got: %s", capturedOperation)
	}
}

func TestIsPolicyViolationError(t *testing.T) {
	// Positive case
	pve := &PolicyViolationError{Reason: "blocked"}
	if !IsPolicyViolationError(pve) {
		t.Error("expected IsPolicyViolationError to return true for PolicyViolationError")
	}

	// Wrapped error
	wrapped := fmt.Errorf("wrapper: %w", pve)
	if !IsPolicyViolationError(wrapped) {
		t.Error("expected IsPolicyViolationError to return true for wrapped PolicyViolationError")
	}

	// Negative case
	otherErr := errors.New("some other error")
	if IsPolicyViolationError(otherErr) {
		t.Error("expected IsPolicyViolationError to return false for non-policy errors")
	}

	// Nil error
	if IsPolicyViolationError(nil) {
		t.Error("expected IsPolicyViolationError to return false for nil")
	}
}

func TestGovernedTool_String(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, nil)

	tool := &mockTool{name: "search", description: "Search"}
	governed := GovernTool(tool, client, nil)

	expected := "GovernedTool(name=search, connectorType=search)"
	if governed.String() != expected {
		t.Errorf("expected %q, got %q", expected, governed.String())
	}

	// With custom connector type
	governed2 := GovernTool(tool, client, &GovernedToolOptions{
		ConnectorTypeFn: func(name string) string { return "custom." + name },
	})
	expected2 := "GovernedTool(name=search, connectorType=custom.search)"
	if governed2.String() != expected2 {
		t.Errorf("expected %q, got %q", expected2, governed2.String())
	}
}

func TestGovernedTool_InputBlockedDefaultReason(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:     false,
				BlockReason: "", // empty reason
			})
		},
	})

	tool := &mockTool{name: "shell", description: "Shell"}
	governed := GovernTool(tool, client, nil)

	_, err := governed.Invoke(context.Background(), "test")
	var pve *PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected PolicyViolationError, got %T", err)
	}
	if pve.Reason != "tool call blocked by input policy" {
		t.Errorf("expected default reason, got: %s", pve.Reason)
	}
}

func TestGovernedTool_OutputBlockedDefaultReason(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed:     false,
				BlockReason: "", // empty reason
			})
		},
	})

	tool := &mockTool{name: "db", description: "DB"}
	governed := GovernTool(tool, client, nil)

	_, err := governed.Invoke(context.Background(), "test")
	var pve *PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected PolicyViolationError, got %T", err)
	}
	if pve.Reason != "tool output blocked by policy" {
		t.Errorf("expected default reason, got: %s", pve.Reason)
	}
}

func TestGovernedTool_ToolErrorPropagated(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, nil)

	expectedErr := errors.New("connection refused")
	tool := &mockTool{
		name:        "failing-tool",
		description: "A tool that fails",
		invokeFn: func(_ context.Context, _ any) (any, error) {
			return nil, expectedErr
		},
	}

	governed := GovernTool(tool, client, nil)
	_, err := governed.Invoke(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected original error, got: %v", err)
	}
	if IsPolicyViolationError(err) {
		t.Error("tool errors should not be PolicyViolationError")
	}
}

func TestGovernedTool_ImplementsToolInterface(t *testing.T) {
	_, client := setupGovernedToolTestServer(t, nil)

	tool := &mockTool{name: "test", description: "Test tool"}
	governed := GovernTool(tool, client, nil)

	// GovernedTool should satisfy the Tool interface
	var _ Tool = governed
}

func TestGovernTools_WithOptions(t *testing.T) {
	var capturedTypes []string

	_, client := setupGovernedToolTestServer(t, map[string]http.HandlerFunc{
		"check-input": func(w http.ResponseWriter, r *http.Request) {
			var req MCPCheckInputRequest
			json.NewDecoder(r.Body).Decode(&req)
			capturedTypes = append(capturedTypes, req.ConnectorType)
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})

	tools := []Tool{
		&mockTool{name: "search", description: "Search"},
		&mockTool{name: "calc", description: "Calculator"},
	}

	governed := GovernTools(tools, client, &GovernedToolOptions{
		ConnectorTypeFn: func(name string) string { return "prefix." + name },
		Operation:       "query",
	})

	for _, g := range governed {
		_, _ = g.Invoke(context.Background(), "test")
	}

	if len(capturedTypes) != 2 {
		t.Fatalf("expected 2 captured types, got %d", len(capturedTypes))
	}
	if capturedTypes[0] != "prefix.search" {
		t.Errorf("expected 'prefix.search', got: %s", capturedTypes[0])
	}
	if capturedTypes[1] != "prefix.calc" {
		t.Errorf("expected 'prefix.calc', got: %s", capturedTypes[1])
	}
}

func TestGovernedTool_PolicyViolationErrorMessage(t *testing.T) {
	err := &PolicyViolationError{Reason: "PII detected"}
	expected := "policy violation: PII detected"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
