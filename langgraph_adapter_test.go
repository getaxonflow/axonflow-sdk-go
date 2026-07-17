// Copyright 2026 AxonFlow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setupLangGraphTestServer creates a test server that handles workflow, step gate,
// and MCP endpoints. The handler functions can be overridden per test.
func setupLangGraphTestServer(t *testing.T, handlers map[string]http.HandlerFunc) (*httptest.Server, *AxonFlowClient) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check for a custom handler matching the path
		for pattern, handler := range handlers {
			if strings.Contains(r.URL.Path, pattern) {
				handler(w, r)
				return
			}
		}

		// Default handlers
		switch {
		case r.URL.Path == "/api/v1/workflows" && r.Method == "POST":
			json.NewEncoder(w).Encode(CreateWorkflowResponse{
				WorkflowID:   "wf_test_123",
				WorkflowName: "test-workflow",
				Source:       WorkflowSourceLangGraph,
				Status:       WorkflowStatusInProgress,
				CreatedAt:    time.Now(),
			})
		case strings.Contains(r.URL.Path, "/gate") && r.Method == "POST":
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_abc",
			})
		case strings.Contains(r.URL.Path, "/steps/") && strings.HasSuffix(r.URL.Path, "/complete") && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
		case strings.HasSuffix(r.URL.Path, "/complete") && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
		case strings.HasSuffix(r.URL.Path, "/abort") && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "aborted"})
		case strings.HasSuffix(r.URL.Path, "/fail") && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "failed"})
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
			// For GET workflow status (used in WaitForApproval)
			if strings.HasPrefix(r.URL.Path, "/api/v1/workflows/") && r.Method == "GET" {
				json.NewEncoder(w).Encode(WorkflowStatusResponse{
					WorkflowID: "wf_test_123",
					Status:     WorkflowStatusInProgress,
					Steps:      []WorkflowStepInfo{},
				})
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	return server, client
}

func TestLangGraphAdapter_NewDefaults(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "my-workflow")

	if adapter.workflowName != "my-workflow" {
		t.Errorf("expected workflow name 'my-workflow', got '%s'", adapter.workflowName)
	}
	if adapter.source != WorkflowSourceLangGraph {
		t.Errorf("expected source '%s', got '%s'", WorkflowSourceLangGraph, adapter.source)
	}
	if !adapter.autoBlock {
		t.Error("expected autoBlock to be true by default")
	}
	if adapter.workflowID != "" {
		t.Error("expected empty workflow ID before start")
	}
	if adapter.stepCounter != 0 {
		t.Error("expected step counter to be 0")
	}
}

func TestLangGraphAdapter_NewWithOptions(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "my-workflow",
		WithSource(WorkflowSourceCrewAI),
		WithAutoBlock(false),
	)

	if adapter.source != WorkflowSourceCrewAI {
		t.Errorf("expected source '%s', got '%s'", WorkflowSourceCrewAI, adapter.source)
	}
	if adapter.autoBlock {
		t.Error("expected autoBlock to be false")
	}
}

func TestLangGraphAdapter_StartWorkflow(t *testing.T) {
	server, client := setupLangGraphTestServer(t, nil)
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	workflowID, err := adapter.StartWorkflow(ctx, map[string]interface{}{"key": "value"}, "trace-123")
	if err != nil {
		t.Fatalf("StartWorkflow failed: %v", err)
	}
	if workflowID != "wf_test_123" {
		t.Errorf("expected workflow ID 'wf_test_123', got '%s'", workflowID)
	}
	if adapter.GetWorkflowID() != "wf_test_123" {
		t.Errorf("GetWorkflowID returned '%s', expected 'wf_test_123'", adapter.GetWorkflowID())
	}
}

func TestLangGraphAdapter_StartWorkflow_VerifiesRequest(t *testing.T) {
	var receivedReq CreateWorkflowRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/workflows": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && r.URL.Path == "/api/v1/workflows" {
				json.NewDecoder(r.Body).Decode(&receivedReq)
				json.NewEncoder(w).Encode(CreateWorkflowResponse{
					WorkflowID: "wf_verified",
					Status:     WorkflowStatusInProgress,
				})
			}
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "verified-workflow",
		WithSource(WorkflowSourceCrewAI),
	)
	ctx := context.Background()

	_, err := adapter.StartWorkflow(ctx, map[string]interface{}{"env": "test"}, "trace-abc")
	if err != nil {
		t.Fatalf("StartWorkflow failed: %v", err)
	}
	if receivedReq.WorkflowName != "verified-workflow" {
		t.Errorf("expected workflow name 'verified-workflow', got '%s'", receivedReq.WorkflowName)
	}
	if receivedReq.Source != WorkflowSourceCrewAI {
		t.Errorf("expected source '%s', got '%s'", WorkflowSourceCrewAI, receivedReq.Source)
	}
	if receivedReq.TraceID != "trace-abc" {
		t.Errorf("expected trace ID 'trace-abc', got '%s'", receivedReq.TraceID)
	}
}

func TestLangGraphAdapter_CheckGate_Allow(t *testing.T) {
	server, client := setupLangGraphTestServer(t, nil)
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	adapter.StartWorkflow(ctx, nil, "")

	allowed, err := adapter.CheckGate(ctx, "generate", StepTypeLLMCall, &CheckGateOptions{
		Model:    "gpt-4",
		Provider: "openai",
	})
	if err != nil {
		t.Fatalf("CheckGate failed: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

func TestLangGraphAdapter_CheckGate_Block_AutoBlock(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision:  GateDecisionBlock,
				StepID:    "step-1-generate",
				Reason:    "model not approved",
				PolicyIDs: []string{"pol-1", "pol-2"},
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	allowed, err := adapter.CheckGate(ctx, "generate", StepTypeLLMCall, nil)
	if allowed {
		t.Error("expected allowed=false for blocked step")
	}
	if err == nil {
		t.Fatal("expected error for blocked step with autoBlock=true")
	}

	blockedErr, ok := err.(*WorkflowBlockedError)
	if !ok {
		t.Fatalf("expected WorkflowBlockedError, got %T: %v", err, err)
	}
	if blockedErr.StepID != "step-1-generate" {
		t.Errorf("expected step ID 'step-1-generate', got '%s'", blockedErr.StepID)
	}
	if blockedErr.Reason != "model not approved" {
		t.Errorf("expected reason 'model not approved', got '%s'", blockedErr.Reason)
	}
	if len(blockedErr.PolicyIDs) != 2 {
		t.Errorf("expected 2 policy IDs, got %d", len(blockedErr.PolicyIDs))
	}
}

func TestLangGraphAdapter_CheckGate_Block_NoAutoBlock(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionBlock,
				StepID:   "step-1-generate",
				Reason:   "policy violation",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow", WithAutoBlock(false))
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	allowed, err := adapter.CheckGate(ctx, "generate", StepTypeLLMCall, nil)
	if err != nil {
		t.Fatalf("expected no error with autoBlock=false, got: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false for blocked step")
	}
}

func TestLangGraphAdapter_CheckGate_RequireApproval(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision:    GateDecisionRequireApproval,
				StepID:      "step-1-deploy",
				Reason:      "requires manager approval",
				ApprovalURL: "https://portal.example.com/approve/123",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	allowed, err := adapter.CheckGate(ctx, "deploy", StepTypeHumanTask, nil)
	if allowed {
		t.Error("expected allowed=false for approval-required step")
	}
	if err == nil {
		t.Fatal("expected error for approval-required step")
	}

	approvalErr, ok := err.(*WorkflowApprovalRequiredError)
	if !ok {
		t.Fatalf("expected WorkflowApprovalRequiredError, got %T: %v", err, err)
	}
	if approvalErr.StepID != "step-1-deploy" {
		t.Errorf("expected step ID 'step-1-deploy', got '%s'", approvalErr.StepID)
	}
	if approvalErr.ApprovalURL != "https://portal.example.com/approve/123" {
		t.Errorf("expected approval URL, got '%s'", approvalErr.ApprovalURL)
	}
	if approvalErr.Reason != "requires manager approval" {
		t.Errorf("expected reason 'requires manager approval', got '%s'", approvalErr.Reason)
	}
}

func TestLangGraphAdapter_CheckGate_NotStarted(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	_, err := adapter.CheckGate(ctx, "step1", StepTypeLLMCall, nil)
	if err == nil {
		t.Fatal("expected error for not-started workflow")
	}
	if !strings.Contains(err.Error(), "workflow not started") {
		t.Errorf("expected 'workflow not started' error, got: %v", err)
	}
}

func TestLangGraphAdapter_CheckGate_StepIDGeneration(t *testing.T) {
	var receivedPaths []string
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			receivedPaths = append(receivedPaths, r.URL.Path)
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_abc",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	// First step
	adapter.CheckGate(ctx, "Generate Code", StepTypeLLMCall, nil)
	// Second step
	adapter.CheckGate(ctx, "Review/Approve", StepTypeHumanTask, nil)
	// Step with explicit ID
	adapter.CheckGate(ctx, "Deploy", StepTypeToolCall, &CheckGateOptions{StepID: "custom-id"})

	if len(receivedPaths) != 3 {
		t.Fatalf("expected 3 gate calls, got %d", len(receivedPaths))
	}
	if !strings.Contains(receivedPaths[0], "step-1-generate-code") {
		t.Errorf("expected step-1-generate-code in path, got %s", receivedPaths[0])
	}
	if !strings.Contains(receivedPaths[1], "step-2-review-approve") {
		t.Errorf("expected step-2-review-approve in path, got %s", receivedPaths[1])
	}
	if !strings.Contains(receivedPaths[2], "custom-id") {
		t.Errorf("expected custom-id in path, got %s", receivedPaths[2])
	}
}

func TestLangGraphAdapter_StepCompleted(t *testing.T) {
	var receivedPath string
	var receivedBody map[string]interface{}
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/steps/": func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/complete") && !strings.HasSuffix(r.URL.Path, "workflows/wf_test_123/complete") {
				receivedPath = r.URL.Path
				json.NewDecoder(r.Body).Decode(&receivedBody)
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
				return
			}
			// fall through to gate handler
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_abc",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")
	adapter.CheckGate(ctx, "generate", StepTypeLLMCall, nil)

	tokensIn := 100
	tokensOut := 200
	costUSD := 0.005

	err := adapter.StepCompleted(ctx, "generate", &StepCompletedOptions{
		Output:    map[string]interface{}{"result": "success"},
		TokensIn:  &tokensIn,
		TokensOut: &tokensOut,
		CostUSD:   &costUSD,
	})
	if err != nil {
		t.Fatalf("StepCompleted failed: %v", err)
	}
	if !strings.Contains(receivedPath, "step-1-generate") {
		t.Errorf("expected step-1-generate in path, got %s", receivedPath)
	}
}

func TestLangGraphAdapter_StepCompleted_NotStarted(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	err := adapter.StepCompleted(ctx, "step1", nil)
	if err == nil {
		t.Fatal("expected error for not-started workflow")
	}
	if !strings.Contains(err.Error(), "workflow not started") {
		t.Errorf("expected 'workflow not started' error, got: %v", err)
	}
}

func TestLangGraphAdapter_CheckToolGate(t *testing.T) {
	var receivedBody StepGateRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_tool",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	allowed, err := adapter.CheckToolGate(ctx, "web_search", "function", &CheckToolGateOptions{
		ToolInput: map[string]interface{}{"query": "latest news"},
		Model:     "gpt-4",
		Provider:  "openai",
	})
	if err != nil {
		t.Fatalf("CheckToolGate failed: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}

	if receivedBody.StepType != StepTypeToolCall {
		t.Errorf("expected step type '%s', got '%s'", StepTypeToolCall, receivedBody.StepType)
	}
	if receivedBody.ToolContext == nil {
		t.Fatal("expected tool context to be set")
	}
	if receivedBody.ToolContext.ToolName != "web_search" {
		t.Errorf("expected tool name 'web_search', got '%s'", receivedBody.ToolContext.ToolName)
	}
	if receivedBody.ToolContext.ToolType != "function" {
		t.Errorf("expected tool type 'function', got '%s'", receivedBody.ToolContext.ToolType)
	}
	if receivedBody.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got '%s'", receivedBody.Model)
	}
}

func TestLangGraphAdapter_CheckToolGate_DefaultStepName(t *testing.T) {
	var receivedPath string
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_tool",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	adapter.CheckToolGate(ctx, "calculator", "function", nil)

	// The step ID should be step-1-tools-calculator (tools/calculator -> tools-calculator)
	if !strings.Contains(receivedPath, "step-1-tools-calculator") {
		t.Errorf("expected step-1-tools-calculator in path, got %s", receivedPath)
	}
}

func TestLangGraphAdapter_CheckToolGate_CustomStepName(t *testing.T) {
	var receivedPath string
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_tool",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	adapter.CheckToolGate(ctx, "calculator", "function", &CheckToolGateOptions{
		StepName: "math-step",
	})

	if !strings.Contains(receivedPath, "step-1-math-step") {
		t.Errorf("expected step-1-math-step in path, got %s", receivedPath)
	}
}

func TestLangGraphAdapter_ToolCompleted(t *testing.T) {
	var receivedPath string
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/steps/": func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/complete") {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
				return
			}
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_abc",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")
	adapter.CheckToolGate(ctx, "web_search", "function", nil)

	tokensIn := 50
	err := adapter.ToolCompleted(ctx, "web_search", &ToolCompletedOptions{
		Output:   map[string]interface{}{"results": []string{"result1"}},
		TokensIn: &tokensIn,
	})
	if err != nil {
		t.Fatalf("ToolCompleted failed: %v", err)
	}
	// Should use tools/web_search -> tools-web_search as the step name for ID generation
	if !strings.Contains(receivedPath, "step-1-tools-web_search") {
		t.Errorf("expected tools-web_search in path, got %s", receivedPath)
	}
}

func TestLangGraphAdapter_CompleteWorkflow(t *testing.T) {
	server, client := setupLangGraphTestServer(t, nil)
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	err := adapter.CompleteWorkflow(ctx)
	if err != nil {
		t.Fatalf("CompleteWorkflow failed: %v", err)
	}
}

func TestLangGraphAdapter_CompleteWorkflow_NotStarted(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	err := adapter.CompleteWorkflow(ctx)
	if err == nil {
		t.Fatal("expected error for not-started workflow")
	}
	if !strings.Contains(err.Error(), "workflow not started") {
		t.Errorf("expected 'workflow not started' error, got: %v", err)
	}
}

func TestLangGraphAdapter_AbortWorkflow(t *testing.T) {
	var receivedBody AbortWorkflowRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/abort": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "aborted"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	err := adapter.AbortWorkflow(ctx, "user cancelled")
	if err != nil {
		t.Fatalf("AbortWorkflow failed: %v", err)
	}
	if receivedBody.Reason != "user cancelled" {
		t.Errorf("expected reason 'user cancelled', got '%s'", receivedBody.Reason)
	}
}

func TestLangGraphAdapter_AbortWorkflow_NotStarted(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	err := adapter.AbortWorkflow(ctx, "reason")
	if err == nil {
		t.Fatal("expected error for not-started workflow")
	}
}

func TestLangGraphAdapter_FailWorkflow(t *testing.T) {
	var receivedBody FailWorkflowRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/fail": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "failed"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	err := adapter.FailWorkflow(ctx, "pipeline crashed")
	if err != nil {
		t.Fatalf("FailWorkflow failed: %v", err)
	}
	if receivedBody.Reason != "pipeline crashed" {
		t.Errorf("expected reason 'pipeline crashed', got '%s'", receivedBody.Reason)
	}
}

func TestLangGraphAdapter_FailWorkflow_NotStarted(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	err := adapter.FailWorkflow(ctx, "reason")
	if err == nil {
		t.Fatal("expected error for not-started workflow")
	}
}

func TestLangGraphAdapter_WaitForApproval_Approved(t *testing.T) {
	var callCount int32
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/workflows/wf_test_123": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				count := atomic.AddInt32(&callCount, 1)
				status := ApprovalStatusPending
				if count >= 2 {
					status = ApprovalStatusApproved
				}
				json.NewEncoder(w).Encode(WorkflowStatusResponse{
					WorkflowID: "wf_test_123",
					Status:     WorkflowStatusInProgress,
					Steps: []WorkflowStepInfo{
						{
							StepID:         "step-1-deploy",
							ApprovalStatus: ApprovalStatus(status),
						},
					},
				})
				return
			}
			// POST handlers (complete, abort, etc.)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	adapter.workflowID = "wf_test_123"
	ctx := context.Background()

	approved, err := adapter.WaitForApproval(ctx, "step-1-deploy", 50*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if !approved {
		t.Error("expected approved=true")
	}
}

func TestLangGraphAdapter_WaitForApproval_Rejected(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/workflows/wf_test_123": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(WorkflowStatusResponse{
					WorkflowID: "wf_test_123",
					Status:     WorkflowStatusInProgress,
					Steps: []WorkflowStepInfo{
						{
							StepID:         "step-1-deploy",
							ApprovalStatus: ApprovalStatusRejected,
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	adapter.workflowID = "wf_test_123"
	ctx := context.Background()

	approved, err := adapter.WaitForApproval(ctx, "step-1-deploy", 50*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if approved {
		t.Error("expected approved=false for rejected step")
	}
}

func TestLangGraphAdapter_WaitForApproval_Timeout(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/workflows/wf_test_123": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(WorkflowStatusResponse{
					WorkflowID: "wf_test_123",
					Status:     WorkflowStatusInProgress,
					Steps: []WorkflowStepInfo{
						{
							StepID:         "step-1-deploy",
							ApprovalStatus: ApprovalStatusPending,
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	adapter.workflowID = "wf_test_123"
	ctx := context.Background()

	_, err := adapter.WaitForApproval(ctx, "step-1-deploy", 50*time.Millisecond, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "approval timeout") {
		t.Errorf("expected 'approval timeout' error, got: %v", err)
	}
}

func TestLangGraphAdapter_WaitForApproval_ContextCancelled(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/workflows/wf_test_123": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(WorkflowStatusResponse{
					WorkflowID: "wf_test_123",
					Status:     WorkflowStatusInProgress,
					Steps: []WorkflowStepInfo{
						{
							StepID:         "step-1-deploy",
							ApprovalStatus: ApprovalStatusPending,
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	adapter.workflowID = "wf_test_123"
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := adapter.WaitForApproval(ctx, "step-1-deploy", 50*time.Millisecond, 10*time.Second)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestLangGraphAdapter_WaitForApproval_NotStarted(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()

	_, err := adapter.WaitForApproval(ctx, "step-1", 1*time.Second, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for not-started workflow")
	}
	if !strings.Contains(err.Error(), "workflow not started") {
		t.Errorf("expected 'workflow not started' error, got: %v", err)
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_HappyPath(t *testing.T) {
	server, client := setupLangGraphTestServer(t, nil)
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return map[string]string{"result": "data"}, nil
	}

	req := MCPToolRequest{
		ServerName: "postgres",
		Name:       "query",
		Args:       map[string]interface{}{"sql": "SELECT 1"},
	}

	result, err := interceptor(req, handler)
	if err != nil {
		t.Fatalf("interceptor failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_BlockedInput(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:     false,
				BlockReason: "SQL injection detected",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handlerCalled := false
	handler := func(req MCPToolRequest) (interface{}, error) {
		handlerCalled = true
		return nil, nil
	}

	req := MCPToolRequest{
		ServerName: "postgres",
		Name:       "query",
		Args:       map[string]interface{}{"sql": "DROP TABLE users; --"},
	}

	_, err := interceptor(req, handler)
	if err == nil {
		t.Fatal("expected error for blocked input")
	}
	if !strings.Contains(err.Error(), "SQL injection detected") {
		t.Errorf("expected 'SQL injection detected' error, got: %v", err)
	}
	if handlerCalled {
		t.Error("handler should not be called when input is blocked")
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_BlockedInputDefaultReason(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed: false,
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return nil, nil
	}

	_, err := interceptor(MCPToolRequest{ServerName: "s", Name: "t"}, handler)
	if err == nil {
		t.Fatal("expected error for blocked input")
	}
	if !strings.Contains(err.Error(), "tool call blocked by policy") {
		t.Errorf("expected default block reason, got: %v", err)
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_BlockedOutput(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed:     false,
				BlockReason: "PII detected in output",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return map[string]string{"ssn": "123-45-6789"}, nil
	}

	req := MCPToolRequest{
		ServerName: "postgres",
		Name:       "query",
		Args:       map[string]interface{}{"sql": "SELECT * FROM users"},
	}

	_, err := interceptor(req, handler)
	if err == nil {
		t.Fatal("expected error for blocked output")
	}
	if !strings.Contains(err.Error(), "PII detected in output") {
		t.Errorf("expected 'PII detected in output' error, got: %v", err)
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_BlockedOutputDefaultReason(t *testing.T) {
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed: false,
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return "data", nil
	}

	_, err := interceptor(MCPToolRequest{ServerName: "s", Name: "t"}, handler)
	if err == nil {
		t.Fatal("expected error for blocked output")
	}
	if !strings.Contains(err.Error(), "tool result blocked by policy") {
		t.Errorf("expected default block reason, got: %v", err)
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_RedactedData(t *testing.T) {
	redacted := map[string]interface{}{"ssn": "***-**-****", "name": "John"}
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed:      true,
				RedactedData: redacted,
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return map[string]string{"ssn": "123-45-6789", "name": "John"}, nil
	}

	req := MCPToolRequest{
		ServerName: "postgres",
		Name:       "query",
		Args:       map[string]interface{}{"sql": "SELECT * FROM users"},
	}

	result, err := interceptor(req, handler)
	if err != nil {
		t.Fatalf("interceptor failed: %v", err)
	}

	// Result should be the redacted data
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if resultMap["ssn"] != "***-**-****" {
		t.Errorf("expected redacted SSN, got %v", resultMap["ssn"])
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_CustomOptions(t *testing.T) {
	var receivedInputBody MCPCheckInputRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedInputBody)
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed: true,
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(&MCPInterceptorOptions{
		ConnectorTypeFn: func(serverName, toolName string) string {
			return serverName // only server name
		},
		Operation: "query",
	})

	handler := func(req MCPToolRequest) (interface{}, error) {
		return "ok", nil
	}

	req := MCPToolRequest{
		ServerName: "my-server",
		Name:       "list-items",
		Args:       map[string]interface{}{"limit": 10},
	}

	_, err := interceptor(req, handler)
	if err != nil {
		t.Fatalf("interceptor failed: %v", err)
	}

	if receivedInputBody.ConnectorType != "my-server" {
		t.Errorf("expected connector type 'my-server', got '%s'", receivedInputBody.ConnectorType)
	}
	if receivedInputBody.Tool != "list-items" {
		t.Errorf("expected tool 'list-items', got '%s'", receivedInputBody.Tool)
	}
	if receivedInputBody.Operation != "query" {
		t.Errorf("expected operation 'query', got '%s'", receivedInputBody.Operation)
	}
}

// TestLangGraphAdapter_MCPToolInterceptor_StatementUsesResolvedConnectorType
// pins RULING 2 (epic #2905): the human-readable statement is built from the
// RESOLVED connector type (whatever ConnectorTypeFn returns), not the raw
// req.ServerName — matching the python/typescript/java adapters. Here the
// custom fn returns a value that differs from ServerName, so a statement built
// from raw ServerName would be observably wrong.
func TestLangGraphAdapter_MCPToolInterceptor_StatementUsesResolvedConnectorType(t *testing.T) {
	var receivedInputBody MCPCheckInputRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedInputBody)
			json.NewEncoder(w).Encode(MCPCheckInputResponse{Allowed: true})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(&MCPInterceptorOptions{
		ConnectorTypeFn: func(serverName, toolName string) string {
			return "prod-" + serverName // deliberately != serverName
		},
	})

	handler := func(req MCPToolRequest) (interface{}, error) { return "ok", nil }
	req := MCPToolRequest{ServerName: "my-server", Name: "do-thing", Args: map[string]interface{}{"k": "v"}}

	if _, err := interceptor(req, handler); err != nil {
		t.Fatalf("interceptor failed: %v", err)
	}

	if receivedInputBody.ConnectorType != "prod-my-server" {
		t.Errorf("expected resolved connector type 'prod-my-server', got '%s'", receivedInputBody.ConnectorType)
	}
	if receivedInputBody.Tool != "do-thing" {
		t.Errorf("expected tool 'do-thing', got '%s'", receivedInputBody.Tool)
	}
	// Statement must reflect the RESOLVED connector type, not raw ServerName.
	if !strings.HasPrefix(receivedInputBody.Statement, "prod-my-server.do-thing(") {
		t.Errorf("expected statement to start with 'prod-my-server.do-thing(', got '%s'", receivedInputBody.Statement)
	}
	if strings.HasPrefix(receivedInputBody.Statement, "my-server.do-thing(") {
		t.Errorf("statement was built from raw ServerName, not the resolved connector type: '%s'", receivedInputBody.Statement)
	}
}

// TestLangGraphAdapter_MCPToolInterceptor_EmptyServerName pins the
// missing-server edge (epic #2905). With the default resolver, connector_type
// is the server name, so an empty ServerName sends connector_type="" while the
// tool name still travels in Tool. A real platform rejects an empty
// connector_type with HTTP 400, which the client surfaces as an error — the
// tool call is blocked (fail-closed) and the handler never runs. Before the
// de-concatenation the value was ".tool" (a non-empty string the platform
// accepted), so this is a deliberate, surfaced change for server-less tools.
func TestLangGraphAdapter_MCPToolInterceptor_EmptyServerName(t *testing.T) {
	var receivedInputBody MCPCheckInputRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedInputBody)
			// Emulate the platform rejecting an empty connector_type.
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "connector_type is required"})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handlerCalled := false
	handler := func(req MCPToolRequest) (interface{}, error) {
		handlerCalled = true
		return "ok", nil
	}
	req := MCPToolRequest{ServerName: "", Name: "tool", Args: map[string]interface{}{}}

	if _, err := interceptor(req, handler); err == nil {
		t.Fatal("expected fail-closed error when server rejects the empty connector_type")
	}
	if handlerCalled {
		t.Error("handler must NOT run when the input check fails (fail-closed)")
	}
	// The SDK faithfully sends connector_type="" and the tool name separately.
	if receivedInputBody.ConnectorType != "" {
		t.Errorf("expected empty connector_type on the wire, got '%s'", receivedInputBody.ConnectorType)
	}
	if receivedInputBody.Tool != "tool" {
		t.Errorf("expected tool 'tool' on the wire, got '%s'", receivedInputBody.Tool)
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_HandlerError(t *testing.T) {
	server, client := setupLangGraphTestServer(t, nil)
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return nil, fmt.Errorf("connection refused")
	}

	req := MCPToolRequest{
		ServerName: "postgres",
		Name:       "query",
		Args:       nil,
	}

	_, err := interceptor(req, handler)
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected 'connection refused' error, got: %v", err)
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_DefaultConnectorTypeAndTool(t *testing.T) {
	var receivedInputBody MCPCheckInputRequest
	var receivedOutputBody MCPCheckOutputRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedInputBody)
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed: true,
			})
		},
		"/api/v1/mcp/check-output": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedOutputBody)
			json.NewEncoder(w).Encode(MCPCheckOutputResponse{
				Allowed: true,
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return "ok", nil
	}

	req := MCPToolRequest{
		ServerName: "my-server",
		Name:       "do-thing",
		Args:       map[string]interface{}{"a": 1},
	}

	interceptor(req, handler)

	// connectorType and tool must be sent as two separate, correct values —
	// never concatenated into a single "my-server.do-thing" string.
	if receivedInputBody.ConnectorType != "my-server" {
		t.Errorf("expected connector type 'my-server', got '%s'", receivedInputBody.ConnectorType)
	}
	if receivedInputBody.Tool != "do-thing" {
		t.Errorf("expected tool 'do-thing', got '%s'", receivedInputBody.Tool)
	}
	if receivedOutputBody.ConnectorType != "my-server" {
		t.Errorf("expected output connector type 'my-server', got '%s'", receivedOutputBody.ConnectorType)
	}
	if receivedOutputBody.Tool != "do-thing" {
		t.Errorf("expected output tool 'do-thing', got '%s'", receivedOutputBody.Tool)
	}
	// Statement is a human-readable representation and may still combine
	// server and tool name, independent of the connector_type/tool wire fields.
	if !strings.HasPrefix(receivedInputBody.Statement, "my-server.do-thing(") {
		t.Errorf("expected statement to start with 'my-server.do-thing(', got '%s'", receivedInputBody.Statement)
	}
}

func TestLangGraphAdapter_StepCounterIncrements(t *testing.T) {
	var receivedPaths []string
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/gate": func(w http.ResponseWriter, r *http.Request) {
			receivedPaths = append(receivedPaths, r.URL.Path)
			json.NewEncoder(w).Encode(StepGateResponse{
				Decision: GateDecisionAllow,
				StepID:   "step_abc",
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	ctx := context.Background()
	adapter.StartWorkflow(ctx, nil, "")

	for i := 0; i < 5; i++ {
		adapter.CheckGate(ctx, fmt.Sprintf("step%d", i), StepTypeLLMCall, nil)
	}

	if len(receivedPaths) != 5 {
		t.Fatalf("expected 5 gate calls, got %d", len(receivedPaths))
	}

	for i, path := range receivedPaths {
		expected := fmt.Sprintf("step-%d-step%d", i+1, i)
		if !strings.Contains(path, expected) {
			t.Errorf("call %d: expected '%s' in path, got '%s'", i, expected, path)
		}
	}
}

func TestLangGraphAdapter_ErrorTypes(t *testing.T) {
	// Test WorkflowBlockedError Error() method
	blockedErr := &WorkflowBlockedError{
		StepID:    "step-1",
		Reason:    "not allowed",
		PolicyIDs: []string{"p1"},
	}
	if !strings.Contains(blockedErr.Error(), "step-1") {
		t.Errorf("WorkflowBlockedError.Error() should contain step ID")
	}
	if !strings.Contains(blockedErr.Error(), "not allowed") {
		t.Errorf("WorkflowBlockedError.Error() should contain reason")
	}

	// Test WorkflowApprovalRequiredError Error() method
	approvalErr := &WorkflowApprovalRequiredError{
		StepID:      "step-2",
		ApprovalURL: "https://example.com/approve",
		Reason:      "needs approval",
	}
	if !strings.Contains(approvalErr.Error(), "step-2") {
		t.Errorf("WorkflowApprovalRequiredError.Error() should contain step ID")
	}
	if !strings.Contains(approvalErr.Error(), "needs approval") {
		t.Errorf("WorkflowApprovalRequiredError.Error() should contain reason")
	}
}

func TestLangGraphAdapter_GetWorkflowID_BeforeStart(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test", "secret")
	adapter := NewLangGraphAdapter(client, "test-workflow")

	if adapter.GetWorkflowID() != "" {
		t.Error("expected empty workflow ID before start")
	}
}

func TestLangGraphAdapter_MCPToolInterceptor_NilArgs(t *testing.T) {
	var receivedInputBody MCPCheckInputRequest
	server, client := setupLangGraphTestServer(t, map[string]http.HandlerFunc{
		"/api/v1/mcp/check-input": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedInputBody)
			json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed: true,
			})
		},
	})
	defer server.Close()

	adapter := NewLangGraphAdapter(client, "test-workflow")
	interceptor := adapter.NewMCPToolInterceptor(nil)

	handler := func(req MCPToolRequest) (interface{}, error) {
		return "ok", nil
	}

	req := MCPToolRequest{
		ServerName: "server",
		Name:       "tool",
		Args:       nil,
	}

	_, err := interceptor(req, handler)
	if err != nil {
		t.Fatalf("interceptor should handle nil args, got: %v", err)
	}

	// Statement should contain "null" since json.Marshal(nil) = "null"
	if !strings.Contains(receivedInputBody.Statement, "server.tool(") {
		t.Errorf("expected statement to contain 'server.tool(', got '%s'", receivedInputBody.Statement)
	}
}
