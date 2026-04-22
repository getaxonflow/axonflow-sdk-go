package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Sample workflow test data
var sampleWorkflow = CreateWorkflowResponse{
	WorkflowID:   "wf_test123",
	WorkflowName: "test-workflow",
	Source:       WorkflowSourceLangGraph,
	Status:       WorkflowStatusInProgress,
	CreatedAt:    time.Now(),
}

var sampleStepGateResponse = StepGateResponse{
	Decision:  GateDecisionAllow,
	StepID:    "step_abc123",
	Reason:    "",
	PolicyIDs: []string{},
}

var sampleWorkflowStatus = WorkflowStatusResponse{
	WorkflowID:       "wf_test123",
	WorkflowName:     "test-workflow",
	Source:           WorkflowSourceLangGraph,
	Status:           WorkflowStatusInProgress,
	CurrentStepIndex: 1,
	TotalSteps:       5,
	StartedAt:        time.Now(),
	Steps: []WorkflowStepInfo{
		{
			StepID:        "step_1",
			StepIndex:     0,
			StepName:      "Step 1",
			StepType:      StepTypeLLMCall,
			Decision:      GateDecisionAllow,
			GateCheckedAt: time.Now(),
		},
	},
}

// TestWorkflowStatus tests WorkflowStatus constants and methods
func TestWorkflowStatus(t *testing.T) {
	tests := []struct {
		status     WorkflowStatus
		isTerminal bool
	}{
		{WorkflowStatusInProgress, false},
		{WorkflowStatusCompleted, true},
		{WorkflowStatusAborted, true},
		{WorkflowStatusFailed, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.isTerminal {
				t.Errorf("WorkflowStatus(%s).IsTerminal() = %v, want %v", tt.status, got, tt.isTerminal)
			}
		})
	}
}

// TestGateDecision tests GateDecision constants and methods
func TestGateDecision(t *testing.T) {
	tests := []struct {
		decision         GateDecision
		isAllowed        bool
		isBlocked        bool
		requiresApproval bool
	}{
		{GateDecisionAllow, true, false, false},
		{GateDecisionBlock, false, true, false},
		{GateDecisionRequireApproval, false, false, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			if got := tt.decision.IsAllowed(); got != tt.isAllowed {
				t.Errorf("GateDecision(%s).IsAllowed() = %v, want %v", tt.decision, got, tt.isAllowed)
			}
			if got := tt.decision.IsBlocked(); got != tt.isBlocked {
				t.Errorf("GateDecision(%s).IsBlocked() = %v, want %v", tt.decision, got, tt.isBlocked)
			}
			if got := tt.decision.RequiresApproval(); got != tt.requiresApproval {
				t.Errorf("GateDecision(%s).RequiresApproval() = %v, want %v", tt.decision, got, tt.requiresApproval)
			}
		})
	}
}

// TestStepGateResponseMethods tests StepGateResponse helper methods
func TestStepGateResponseMethods(t *testing.T) {
	tests := []struct {
		name             string
		response         StepGateResponse
		isAllowed        bool
		isBlocked        bool
		requiresApproval bool
	}{
		{
			name:             "allow decision",
			response:         StepGateResponse{Decision: GateDecisionAllow, StepID: "s1"},
			isAllowed:        true,
			isBlocked:        false,
			requiresApproval: false,
		},
		{
			name:             "block decision",
			response:         StepGateResponse{Decision: GateDecisionBlock, StepID: "s2", Reason: "Policy violation"},
			isAllowed:        false,
			isBlocked:        true,
			requiresApproval: false,
		},
		{
			name:             "require_approval decision",
			response:         StepGateResponse{Decision: GateDecisionRequireApproval, StepID: "s3", ApprovalURL: "https://portal.example.com/approve/123"},
			isAllowed:        false,
			isBlocked:        false,
			requiresApproval: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsAllowed(); got != tt.isAllowed {
				t.Errorf("StepGateResponse.IsAllowed() = %v, want %v", got, tt.isAllowed)
			}
			if got := tt.response.IsBlocked(); got != tt.isBlocked {
				t.Errorf("StepGateResponse.IsBlocked() = %v, want %v", got, tt.isBlocked)
			}
			if got := tt.response.RequiresApproval(); got != tt.requiresApproval {
				t.Errorf("StepGateResponse.RequiresApproval() = %v, want %v", got, tt.requiresApproval)
			}
		})
	}
}

// TestWorkflowStatusResponseMethods tests WorkflowStatusResponse helper methods
func TestWorkflowStatusResponseMethods(t *testing.T) {
	tests := []struct {
		name       string
		response   WorkflowStatusResponse
		isTerminal bool
	}{
		{
			name:       "in_progress",
			response:   WorkflowStatusResponse{Status: WorkflowStatusInProgress},
			isTerminal: false,
		},
		{
			name:       "completed",
			response:   WorkflowStatusResponse{Status: WorkflowStatusCompleted},
			isTerminal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsTerminal(); got != tt.isTerminal {
				t.Errorf("WorkflowStatusResponse.IsTerminal() = %v, want %v", got, tt.isTerminal)
			}
		})
	}
}

// TestCreateWorkflow tests workflow creation
func TestCreateWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows" {
			t.Errorf("Expected path /api/v1/workflows, got %s", r.URL.Path)
		}

		var req CreateWorkflowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.WorkflowName != "test-workflow" {
			t.Errorf("Expected workflow_name 'test-workflow', got '%s'", req.WorkflowName)
		}
		if req.Source != WorkflowSourceLangGraph {
			t.Errorf("Expected source 'langgraph', got '%s'", req.Source)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleWorkflow)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	workflow, err := client.CreateWorkflow(CreateWorkflowRequest{
		WorkflowName: "test-workflow",
		Source:       WorkflowSourceLangGraph,
		Metadata:     map[string]interface{}{"key": "value"},
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if workflow.WorkflowID != "wf_test123" {
		t.Errorf("Expected workflow_id 'wf_test123', got '%s'", workflow.WorkflowID)
	}
	if workflow.Status != WorkflowStatusInProgress {
		t.Errorf("Expected status 'in_progress', got '%s'", workflow.Status)
	}
}

// TestGetWorkflow tests getting workflow status
func TestGetWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/wf_test123" {
			t.Errorf("Expected path /api/v1/workflows/wf_test123, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleWorkflowStatus)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	status, err := client.GetWorkflow("wf_test123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.WorkflowID != "wf_test123" {
		t.Errorf("Expected workflow_id 'wf_test123', got '%s'", status.WorkflowID)
	}
	if status.CurrentStepIndex != 1 {
		t.Errorf("Expected current_step_index 1, got %d", status.CurrentStepIndex)
	}
	if len(status.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(status.Steps))
	}
}

// TestGetWorkflowEmptyID tests error when workflow ID is empty
func TestGetWorkflowEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	_, err := client.GetWorkflow("")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}
}

// TestStepGate tests step gate check
func TestStepGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/workflows/wf_test123/steps/step_1/gate"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		var req StepGateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.StepType != StepTypeLLMCall {
			t.Errorf("Expected step_type 'llm_call', got '%s'", req.StepType)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleStepGateResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	gate, err := client.StepGate("wf_test123", "step_1", StepGateRequest{
		StepName:  "Generate Code",
		StepType:  StepTypeLLMCall,
		Model:     "gpt-4",
		Provider:  "openai",
		StepInput: map[string]interface{}{"prompt": "Hello world"},
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if gate.Decision != GateDecisionAllow {
		t.Errorf("Expected decision 'allow', got '%s'", gate.Decision)
	}
	if !gate.IsAllowed() {
		t.Error("Expected IsAllowed() to return true")
	}
}

// TestStepGateBlock tests step gate with block decision
func TestStepGateBlock(t *testing.T) {
	blockResponse := StepGateResponse{
		Decision:  GateDecisionBlock,
		StepID:    "step_blocked",
		Reason:    "Policy violation: SQL injection detected",
		PolicyIDs: []string{"pol_sqli_001"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(blockResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	gate, err := client.StepGate("wf_1", "s1", StepGateRequest{
		StepType: StepTypeLLMCall,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !gate.IsBlocked() {
		t.Error("Expected IsBlocked() to return true")
	}
	if gate.Reason != "Policy violation: SQL injection detected" {
		t.Errorf("Expected reason, got '%s'", gate.Reason)
	}
	if len(gate.PolicyIDs) != 1 || gate.PolicyIDs[0] != "pol_sqli_001" {
		t.Errorf("Expected policy_ids ['pol_sqli_001'], got %v", gate.PolicyIDs)
	}
}

// TestStepGateRequireApproval tests step gate with require_approval decision
func TestStepGateRequireApproval(t *testing.T) {
	approvalResponse := StepGateResponse{
		Decision:    GateDecisionRequireApproval,
		StepID:      "step_approval",
		Reason:      "Human approval required for high-risk operation",
		ApprovalURL: "https://portal.example.com/approve/abc123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(approvalResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	gate, err := client.StepGate("wf_1", "s1", StepGateRequest{
		StepType: StepTypeHumanTask,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !gate.RequiresApproval() {
		t.Error("Expected RequiresApproval() to return true")
	}
	if gate.ApprovalURL != "https://portal.example.com/approve/abc123" {
		t.Errorf("Expected approval_url, got '%s'", gate.ApprovalURL)
	}
}

// TestStepGateEmptyIDs tests error when IDs are empty
func TestStepGateEmptyIDs(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	// Test empty workflow ID
	_, err := client.StepGate("", "step_1", StepGateRequest{StepType: StepTypeLLMCall})
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}

	// Test empty step ID
	_, err = client.StepGate("wf_1", "", StepGateRequest{StepType: StepTypeLLMCall})
	if err == nil {
		t.Error("Expected error for empty step ID")
	}
}

// TestCompleteWorkflow tests completing a workflow
func TestCompleteWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/wf_test123/complete" {
			t.Errorf("Expected path /api/v1/workflows/wf_test123/complete, got %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.CompleteWorkflow("wf_test123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestCompleteWorkflowEmptyID tests error when workflow ID is empty
func TestCompleteWorkflowEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.CompleteWorkflow("")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}
}

// TestAbortWorkflow tests aborting a workflow
func TestAbortWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/wf_test123/abort" {
			t.Errorf("Expected path /api/v1/workflows/wf_test123/abort, got %s", r.URL.Path)
		}

		var req AbortWorkflowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.Reason != "User cancelled" {
			t.Errorf("Expected reason 'User cancelled', got '%s'", req.Reason)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.AbortWorkflow("wf_test123", "User cancelled")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestAbortWorkflowEmptyID tests error when workflow ID is empty
func TestAbortWorkflowEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.AbortWorkflow("", "reason")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}
}

// TestFailWorkflow tests failing a workflow
func TestFailWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/wf_test123/fail" {
			t.Errorf("Expected path /api/v1/workflows/wf_test123/fail, got %s", r.URL.Path)
		}

		var req FailWorkflowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.Reason != "Unrecoverable error in step 3" {
			t.Errorf("Expected reason 'Unrecoverable error in step 3', got '%s'", req.Reason)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.FailWorkflow("wf_test123", "Unrecoverable error in step 3")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestFailWorkflowEmptyID tests error when workflow ID is empty
func TestFailWorkflowEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.FailWorkflow("", "reason")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}
}

// TestResumeWorkflow tests resuming a workflow
func TestResumeWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/wf_test123/resume" {
			t.Errorf("Expected path /api/v1/workflows/wf_test123/resume, got %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.ResumeWorkflow("wf_test123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestResumeWorkflowEmptyID tests error when workflow ID is empty
func TestResumeWorkflowEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.ResumeWorkflow("")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}
}

// TestListWorkflows tests listing workflows
func TestListWorkflows(t *testing.T) {
	listResponse := ListWorkflowsResponse{
		Workflows: []WorkflowStatusResponse{sampleWorkflowStatus},
		Total:     1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows" {
			t.Errorf("Expected path /api/v1/workflows, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	result, err := client.ListWorkflows(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("Expected total 1, got %d", result.Total)
	}
	if len(result.Workflows) != 1 {
		t.Errorf("Expected 1 workflow, got %d", len(result.Workflows))
	}
}

// TestListWorkflowsWithFilters tests listing workflows with filters
func TestListWorkflowsWithFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if query.Get("status") != "in_progress" {
			t.Errorf("Expected status=in_progress, got %s", query.Get("status"))
		}
		if query.Get("source") != "langgraph" {
			t.Errorf("Expected source=langgraph, got %s", query.Get("source"))
		}
		if query.Get("limit") != "10" {
			t.Errorf("Expected limit=10, got %s", query.Get("limit"))
		}
		if query.Get("offset") != "5" {
			t.Errorf("Expected offset=5, got %s", query.Get("offset"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ListWorkflowsResponse{
			Workflows: []WorkflowStatusResponse{},
			Total:     0,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListWorkflows(&ListWorkflowsOptions{
		Status: WorkflowStatusInProgress,
		Source: WorkflowSourceLangGraph,
		Limit:  10,
		Offset: 5,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestStepTypes tests that all step type constants are correct
func TestStepTypes(t *testing.T) {
	expectedTypes := map[StepType]string{
		StepTypeLLMCall:       "llm_call",
		StepTypeToolCall:      "tool_call",
		StepTypeConnectorCall: "connector_call",
		StepTypeHumanTask:     "human_task",
	}

	for stepType, expected := range expectedTypes {
		if string(stepType) != expected {
			t.Errorf("StepType %v should be '%s', got '%s'", stepType, expected, string(stepType))
		}
	}
}

// TestWorkflowSources tests that all workflow source constants are correct
func TestWorkflowSources(t *testing.T) {
	expectedSources := map[WorkflowSource]string{
		WorkflowSourceLangGraph: "langgraph",
		WorkflowSourceLangChain: "langchain",
		WorkflowSourceCrewAI:    "crewai",
		WorkflowSourceExternal:  "external",
	}

	for source, expected := range expectedSources {
		if string(source) != expected {
			t.Errorf("WorkflowSource %v should be '%s', got '%s'", source, expected, string(source))
		}
	}
}

// TestApprovalStatuses tests that all approval status constants are correct
func TestApprovalStatuses(t *testing.T) {
	expectedStatuses := map[ApprovalStatus]string{
		ApprovalStatusPending:  "pending",
		ApprovalStatusApproved: "approved",
		ApprovalStatusRejected: "rejected",
	}

	for status, expected := range expectedStatuses {
		if string(status) != expected {
			t.Errorf("ApprovalStatus %v should be '%s', got '%s'", status, expected, string(status))
		}
	}
}

// TestCreateWorkflowServerError tests error handling for server errors
func TestCreateWorkflowServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.CreateWorkflow(CreateWorkflowRequest{
		WorkflowName: "test",
	})

	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestStepGateWithAllFields tests step gate with all optional fields
func TestStepGateWithAllFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req StepGateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		// Verify all fields are present
		if req.StepName != "Generate Code" {
			t.Errorf("Expected step_name 'Generate Code', got '%s'", req.StepName)
		}
		if req.StepType != StepTypeLLMCall {
			t.Errorf("Expected step_type 'llm_call', got '%s'", req.StepType)
		}
		if req.Model != "gpt-4" {
			t.Errorf("Expected model 'gpt-4', got '%s'", req.Model)
		}
		if req.Provider != "openai" {
			t.Errorf("Expected provider 'openai', got '%s'", req.Provider)
		}
		if req.StepInput == nil || req.StepInput["prompt"] != "Hello" {
			t.Errorf("Expected step_input with prompt, got %v", req.StepInput)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StepGateResponse{
			Decision: GateDecisionAllow,
			StepID:   "step_full",
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.StepGate("wf_1", "s1", StepGateRequest{
		StepName:  "Generate Code",
		StepType:  StepTypeLLMCall,
		Model:     "gpt-4",
		Provider:  "openai",
		StepInput: map[string]interface{}{"prompt": "Hello"},
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// ============================================================================
// WCP Approval Tests (Feature 5)
// ============================================================================

// TestApproveStep tests approving a workflow step
func TestApproveStep(t *testing.T) {
	expectedResponse := ApproveStepResponse{
		WorkflowID: "wf_test123",
		StepID:     "step_456",
		Status:     "approved",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/workflows/wf_test123/steps/step_456/approve"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.ApproveStep("wf_test123", "step_456", "Approved after full audit review")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.WorkflowID != "wf_test123" {
		t.Errorf("Expected workflow_id 'wf_test123', got '%s'", resp.WorkflowID)
	}
	if resp.StepID != "step_456" {
		t.Errorf("Expected step_id 'step_456', got '%s'", resp.StepID)
	}
	if resp.Status != "approved" {
		t.Errorf("Expected status 'approved', got '%s'", resp.Status)
	}
}

// TestApproveStep_RichResponse asserts the SDK deserializes the v7.4.0 rich
// response shape — decision resolves to "allow", retry_context carries the
// first-class state signal, approver metadata is surfaced. Covers the
// Issue #1677 wire change.
func TestApproveStep_RichResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"workflow_id": "wf-abc",
			"step_id": "step-1",
			"decision": "allow",
			"reason": "Approved: High-value transfer requires oversight",
			"approval_status": "approved",
			"approval_id": "318a270f-7b42-5c56-a191-8dbd1bf2e1e4",
			"approved_by": "compliance@example.com",
			"approved_at": "2026-04-22T10:05:00Z",
			"policies_matched": [
				{"policy_id": "hv-oversight", "policy_name": "High-Value Wire Transfer Oversight", "action": "require_approval"}
			],
			"retry_context": {
				"gate_count": 1,
				"completion_count": 0,
				"prior_completion_status": "none",
				"prior_output_available": false,
				"prior_output": null,
				"idempotency_key": "payment-intent-123",
				"last_decision": "require_approval",
				"first_attempt_at": "2026-04-22T10:00:00Z",
				"last_attempt_at": "2026-04-22T10:00:00Z"
			},
			"message": "Step approved"
		}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.ApproveStep("wf-abc", "step-1", "Approved after full audit review")
	if err != nil {
		t.Fatalf("ApproveStep: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", resp.Decision)
	}
	if resp.ApprovalID != "318a270f-7b42-5c56-a191-8dbd1bf2e1e4" {
		t.Errorf("ApprovalID = %q, want deterministic UUID", resp.ApprovalID)
	}
	if resp.ApprovedBy != "compliance@example.com" {
		t.Errorf("ApprovedBy = %q, want compliance@example.com", resp.ApprovedBy)
	}
	if resp.RetryContext.IdempotencyKey != "payment-intent-123" {
		t.Errorf("RetryContext.IdempotencyKey = %q, want payment-intent-123", resp.RetryContext.IdempotencyKey)
	}
	if resp.RetryContext.GateCount != 1 {
		t.Errorf("RetryContext.GateCount = %d, want 1", resp.RetryContext.GateCount)
	}
	if len(resp.PoliciesMatched) != 1 || resp.PoliciesMatched[0].PolicyID != "hv-oversight" {
		t.Errorf("PoliciesMatched = %+v, want one policy 'hv-oversight'", resp.PoliciesMatched)
	}
	if resp.Message != "Step approved" {
		t.Errorf("Message = %q, want 'Step approved'", resp.Message)
	}
}

// TestRejectStep_RichResponse mirrors the approve rich-response test for
// the reject path — rejected_by / rejected_at populate, decision is "block".
func TestRejectStep_RichResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"workflow_id": "wf-abc",
			"step_id": "step-1",
			"decision": "block",
			"reason": "Rejected: PII in output sample",
			"approval_status": "rejected",
			"approval_id": "318a270f-7b42-5c56-a191-8dbd1bf2e1e4",
			"rejected_by": "compliance@example.com",
			"rejected_at": "2026-04-22T10:05:00Z",
			"retry_context": {
				"gate_count": 1, "completion_count": 0,
				"prior_completion_status": "none", "prior_output_available": false,
				"prior_output": null, "idempotency_key": "",
				"last_decision": "require_approval",
				"first_attempt_at": "2026-04-22T10:00:00Z",
				"last_attempt_at": "2026-04-22T10:00:00Z"
			},
			"message": "Step rejected, workflow aborted"
		}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.RejectStep("wf-abc", "step-1", "Rejected for compliance review")
	if err != nil {
		t.Fatalf("RejectStep: %v", err)
	}
	if resp.Decision != "block" {
		t.Errorf("Decision = %q, want block", resp.Decision)
	}
	if resp.RejectedBy != "compliance@example.com" {
		t.Errorf("RejectedBy = %q, want compliance@example.com", resp.RejectedBy)
	}
	if resp.Message != "Step rejected, workflow aborted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

// TestApproveStepEmptyIDs tests error when IDs are empty
func TestApproveStepEmptyIDs(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	// Test empty workflow ID
	_, err := client.ApproveStep("", "step_1", "Approved after full audit review")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}

	// Test empty step ID
	_, err = client.ApproveStep("wf_1", "", "Approved after full audit review")
	if err == nil {
		t.Error("Expected error for empty step ID")
	}
}

// TestApproveStepServerError tests error handling for server errors
func TestApproveStepServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ApproveStep("wf_1", "step_1", "Approved after full audit review")
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestRejectStep tests rejecting a workflow step
func TestRejectStep(t *testing.T) {
	expectedResponse := RejectStepResponse{
		WorkflowID: "wf_test123",
		StepID:     "step_456",
		Status:     "rejected",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/workflows/wf_test123/steps/step_456/reject"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.RejectStep("wf_test123", "step_456", "Rejected for compliance review")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.WorkflowID != "wf_test123" {
		t.Errorf("Expected workflow_id 'wf_test123', got '%s'", resp.WorkflowID)
	}
	if resp.StepID != "step_456" {
		t.Errorf("Expected step_id 'step_456', got '%s'", resp.StepID)
	}
	if resp.Status != "rejected" {
		t.Errorf("Expected status 'rejected', got '%s'", resp.Status)
	}
}

// TestRejectStepEmptyIDs tests error when IDs are empty
func TestRejectStepEmptyIDs(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	// Test empty workflow ID
	_, err := client.RejectStep("", "step_1", "Rejected for compliance review")
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}

	// Test empty step ID
	_, err = client.RejectStep("wf_1", "", "Rejected for compliance review")
	if err == nil {
		t.Error("Expected error for empty step ID")
	}
}

// TestRejectStepServerError tests error handling for server errors
func TestRejectStepServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.RejectStep("wf_1", "step_1", "Rejected for compliance review")
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestGetPendingApprovals tests listing pending approvals
func TestGetPendingApprovals(t *testing.T) {
	expectedResponse := PendingApprovalsResponse{
		PendingApprovals: []PendingApproval{
			{
				WorkflowID:   "wf_test123",
				WorkflowName: "test-workflow",
				StepID:       "step_456",
				StepIndex:    1,
				StepName:     "Generate Code",
				StepType:     "llm_call",
				Decision:     "require_approval",
				CreatedAt:    "2026-02-07T10:00:00Z",
			},
		},
		Count: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/approvals/pending" {
			t.Errorf("Expected path /api/v1/workflows/approvals/pending, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.GetPendingApprovals(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Count != 1 {
		t.Errorf("Expected count 1, got %d", result.Count)
	}
	if len(result.PendingApprovals) != 1 {
		t.Errorf("Expected 1 approval, got %d", len(result.PendingApprovals))
	}
	if result.PendingApprovals[0].WorkflowID != "wf_test123" {
		t.Errorf("Expected workflow_id 'wf_test123', got '%s'", result.PendingApprovals[0].WorkflowID)
	}
	if result.PendingApprovals[0].StepName != "Generate Code" {
		t.Errorf("Expected step_name 'Generate Code', got '%s'", result.PendingApprovals[0].StepName)
	}
	// WCP entries must not carry plan_id
	if result.PendingApprovals[0].PlanID != "" {
		t.Errorf("WCP entry leaked plan_id = %q", result.PendingApprovals[0].PlanID)
	}
}

// TestGetPendingApprovalsWithLimit tests listing pending approvals with limit
func TestGetPendingApprovalsWithLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("limit") != "5" {
			t.Errorf("Expected limit=5, got %s", query.Get("limit"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PendingApprovalsResponse{
			PendingApprovals: []PendingApproval{},
			Count:            0,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetPendingApprovals(&PendingApprovalsOptions{
		Limit: 5,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestGetPendingApprovalsEmpty tests listing pending approvals when there are none
func TestGetPendingApprovalsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PendingApprovalsResponse{
			PendingApprovals: []PendingApproval{},
			Count:            0,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	result, err := client.GetPendingApprovals(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Count != 0 {
		t.Errorf("Expected count 0, got %d", result.Count)
	}
	if len(result.PendingApprovals) != 0 {
		t.Errorf("Expected 0 approvals, got %d", len(result.PendingApprovals))
	}
}

// TestGetPendingApprovalsServerError tests error handling for server errors
func TestGetPendingApprovalsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetPendingApprovals(nil)
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestGetPendingPlanApprovals exercises the MAP-plane listing — the
// counterpart of TestGetPendingApprovals (Issue #1680). Asserts the right
// path is hit and plan_id flows through the deserialization.
func TestGetPendingPlanApprovals(t *testing.T) {
	expectedResponse := PendingApprovalsResponse{
		PendingApprovals: []PendingApproval{
			{
				WorkflowID:   "wf_map_abc",
				WorkflowName: "map-confirm-plan-abc",
				PlanID:       "plan-abc",
				StepID:       "step_0_analyze",
				StepIndex:    0,
				StepName:     "Analyze transaction",
				StepType:     "tool_call",
				Decision:     "require_approval",
				CreatedAt:    "2026-04-22T10:00:00Z",
			},
		},
		Count: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/plans/approvals/pending" {
			t.Errorf("Expected path /api/v1/plans/approvals/pending, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expectedResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.GetPendingPlanApprovals(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Count != 1 {
		t.Errorf("Expected count 1, got %d", result.Count)
	}
	if len(result.PendingApprovals) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(result.PendingApprovals))
	}
	if result.PendingApprovals[0].PlanID != "plan-abc" {
		t.Errorf("plan_id = %q, want plan-abc", result.PendingApprovals[0].PlanID)
	}
}

// TestGetPendingPlanApprovals_PlanIDFilter asserts opts.PlanID propagates to
// the query string as ?plan_id=.
func TestGetPendingPlanApprovals_PlanIDFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("plan_id"); got != "plan-abc" {
			t.Errorf("expected plan_id=plan-abc, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PendingApprovalsResponse{})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "test"})
	if _, err := client.GetPendingPlanApprovals(&PendingApprovalsOptions{PlanID: "plan-abc"}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestGetPendingPlanApprovals_LimitAndPlanID asserts both knobs are encoded.
func TestGetPendingPlanApprovals_LimitAndPlanID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("limit") != "3" || q.Get("plan_id") != "plan-x" {
			t.Errorf("query = %v, want limit=3 plan_id=plan-x", q.Encode())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PendingApprovalsResponse{})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "test"})
	if _, err := client.GetPendingPlanApprovals(&PendingApprovalsOptions{PlanID: "plan-x", Limit: 3}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestGetPendingPlanApprovals_Empty asserts the empty-list case deserializes.
func TestGetPendingPlanApprovals_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PendingApprovalsResponse{
			PendingApprovals: []PendingApproval{},
			Count:            0,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "test"})
	result, err := client.GetPendingPlanApprovals(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Count != 0 || len(result.PendingApprovals) != 0 {
		t.Errorf("empty: got count=%d entries=%d", result.Count, len(result.PendingApprovals))
	}
}

// TestGetPendingPlanApprovals_ServerError covers the error return path.
func TestGetPendingPlanApprovals_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"License tier does not permit approval listing"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "test"})
	if _, err := client.GetPendingPlanApprovals(nil); err == nil {
		t.Error("Expected error for 403 response")
	}
}

// TestPendingApproval_RoundTrip_PlanIDOmittedWhenEmpty asserts plan_id is
// absent from the JSON when empty — the WCP-plane contract.
func TestPendingApproval_RoundTrip_PlanIDOmittedWhenEmpty(t *testing.T) {
	entry := PendingApproval{
		WorkflowID:   "wf-1",
		WorkflowName: "wcp-native",
		StepID:       "step-1",
		StepIndex:    0,
		Decision:     "require_approval",
		CreatedAt:    "2026-04-22T10:00:00Z",
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m["plan_id"]; present {
		t.Errorf("plan_id must be absent on empty; got %s", string(raw))
	}
}

// TestPendingApproval_RoundTrip_PlanIDPresentWhenSet asserts plan_id is
// present on MAP-plane entries.
func TestPendingApproval_RoundTrip_PlanIDPresentWhenSet(t *testing.T) {
	entry := PendingApproval{
		WorkflowID:   "wf-1",
		WorkflowName: "map-confirm-plan-1",
		PlanID:       "plan-1",
		StepID:       "step-1",
		StepIndex:    0,
		Decision:     "require_approval",
		CreatedAt:    "2026-04-22T10:00:00Z",
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["plan_id"] != "plan-1" {
		t.Errorf("plan_id = %v, want plan-1; raw=%s", m["plan_id"], string(raw))
	}
}

// ============================================================================
// MarkStepCompleted Tests
// ============================================================================

// TestMarkStepCompleted tests marking a step as completed with output
func TestMarkStepCompleted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/workflows/wf_test123/steps/step_1/complete"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		var req MarkStepCompletedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.Output == nil || req.Output["result"] != "success" {
			t.Errorf("Expected output with result=success, got %v", req.Output)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.MarkStepCompleted("wf_test123", "step_1", &MarkStepCompletedRequest{
		Output: map[string]interface{}{"result": "success"},
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestMarkStepCompletedNilRequest tests marking a step as completed with nil request
func TestMarkStepCompletedNilRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/workflows/wf_test123/steps/step_1/complete"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.MarkStepCompleted("wf_test123", "step_1", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestMarkStepCompletedEmptyIDs tests error when IDs are empty
func TestMarkStepCompletedEmptyIDs(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	// Test empty workflow ID
	err := client.MarkStepCompleted("", "step_1", nil)
	if err == nil {
		t.Error("Expected error for empty workflow ID")
	}

	// Test empty step ID
	err = client.MarkStepCompleted("wf_1", "", nil)
	if err == nil {
		t.Error("Expected error for empty step ID")
	}
}

// TestMarkStepCompletedServerError tests error handling for server errors
func TestMarkStepCompletedServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.MarkStepCompleted("wf_1", "step_1", &MarkStepCompletedRequest{
		Output: map[string]interface{}{"result": "data"},
	})
	if err == nil {
		t.Error("Expected error for server error response")
	}
}
