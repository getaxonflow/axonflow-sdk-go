// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExecutionStatusValue_IsTerminal(t *testing.T) {
	tests := []struct {
		status   ExecutionStatusValue
		expected bool
	}{
		{ExecutionStatusPending, false},
		{ExecutionStatusRunning, false},
		{ExecutionStatusCompleted, true},
		{ExecutionStatusFailed, true},
		{ExecutionStatusCancelled, true},
		{ExecutionStatusAborted, true},
		{ExecutionStatusExpired, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.expected {
				t.Errorf("ExecutionStatusValue.IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStepStatusValue_IsTerminal(t *testing.T) {
	tests := []struct {
		status   StepStatusValue
		expected bool
	}{
		{StepStatusPending, false},
		{StepStatusRunning, false},
		{StepStatusCompleted, true},
		{StepStatusFailed, true},
		{StepStatusSkipped, true},
		{StepStatusBlocked, false},
		{StepStatusApproval, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.expected {
				t.Errorf("StepStatusValue.IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStepStatusValue_IsBlocking(t *testing.T) {
	tests := []struct {
		status   StepStatusValue
		expected bool
	}{
		{StepStatusPending, false},
		{StepStatusRunning, false},
		{StepStatusCompleted, false},
		{StepStatusFailed, false},
		{StepStatusSkipped, false},
		{StepStatusBlocked, true},
		{StepStatusApproval, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsBlocking(); got != tt.expected {
				t.Errorf("StepStatusValue.IsBlocking() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		status   ExecutionStatusValue
		expected bool
	}{
		{"pending", ExecutionStatusPending, false},
		{"running", ExecutionStatusRunning, false},
		{"completed", ExecutionStatusCompleted, true},
		{"failed", ExecutionStatusFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ExecutionStatus{Status: tt.status}
			if got := e.IsTerminal(); got != tt.expected {
				t.Errorf("ExecutionStatus.IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_GetCurrentStep(t *testing.T) {
	now := time.Now()
	steps := []UnifiedStepStatus{
		{StepID: "step-1", StepIndex: 0, Status: StepStatusCompleted},
		{StepID: "step-2", StepIndex: 1, Status: StepStatusRunning, StartedAt: &now},
		{StepID: "step-3", StepIndex: 2, Status: StepStatusPending},
	}

	t.Run("with running step", func(t *testing.T) {
		e := &ExecutionStatus{Steps: steps}
		current := e.GetCurrentStep()
		if current == nil {
			t.Fatal("GetCurrentStep() returned nil, expected a step")
		}
		if current.StepID != "step-2" {
			t.Errorf("GetCurrentStep().StepID = %v, want step-2", current.StepID)
		}
	})

	t.Run("without running step", func(t *testing.T) {
		e := &ExecutionStatus{
			Steps: []UnifiedStepStatus{
				{StepID: "step-1", Status: StepStatusCompleted},
				{StepID: "step-2", Status: StepStatusPending},
			},
		}
		current := e.GetCurrentStep()
		if current != nil {
			t.Errorf("GetCurrentStep() = %v, want nil", current)
		}
	})

	t.Run("with empty steps", func(t *testing.T) {
		e := &ExecutionStatus{Steps: nil}
		current := e.GetCurrentStep()
		if current != nil {
			t.Errorf("GetCurrentStep() = %v, want nil", current)
		}
	})
}

func TestExecutionStatus_TotalCost(t *testing.T) {
	cost1 := 0.05
	cost2 := 0.10

	tests := []struct {
		name     string
		steps    []UnifiedStepStatus
		expected float64
	}{
		{
			name:     "empty steps",
			steps:    nil,
			expected: 0.0,
		},
		{
			name: "with costs",
			steps: []UnifiedStepStatus{
				{StepID: "step-1", CostUSD: &cost1},
				{StepID: "step-2", CostUSD: &cost2},
			},
			expected: 0.15,
		},
		{
			name: "mixed nil costs",
			steps: []UnifiedStepStatus{
				{StepID: "step-1", CostUSD: &cost1},
				{StepID: "step-2", CostUSD: nil},
			},
			expected: 0.05,
		},
	}

	const tolerance = 0.0001
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ExecutionStatus{Steps: tt.steps}
			got := e.TotalCost()
			diff := got - tt.expected
			if diff < 0 {
				diff = -diff
			}
			if diff > tolerance {
				t.Errorf("ExecutionStatus.TotalCost() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_IsMapPlan(t *testing.T) {
	tests := []struct {
		name          string
		executionType ExecutionType
		expected      bool
	}{
		{"map_plan", ExecutionTypeMAP, true},
		{"wcp_workflow", ExecutionTypeWCP, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ExecutionStatus{ExecutionType: tt.executionType}
			if got := e.IsMapPlan(); got != tt.expected {
				t.Errorf("ExecutionStatus.IsMapPlan() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_IsWcpWorkflow(t *testing.T) {
	tests := []struct {
		name          string
		executionType ExecutionType
		expected      bool
	}{
		{"map_plan", ExecutionTypeMAP, false},
		{"wcp_workflow", ExecutionTypeWCP, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ExecutionStatus{ExecutionType: tt.executionType}
			if got := e.IsWcpWorkflow(); got != tt.expected {
				t.Errorf("ExecutionStatus.IsWcpWorkflow() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionTypeConstants(t *testing.T) {
	if ExecutionTypeMAP != "map_plan" {
		t.Errorf("ExecutionTypeMAP = %v, want map_plan", ExecutionTypeMAP)
	}
	if ExecutionTypeWCP != "wcp_workflow" {
		t.Errorf("ExecutionTypeWCP = %v, want wcp_workflow", ExecutionTypeWCP)
	}
}

func TestUnifiedStepTypeConstants(t *testing.T) {
	expected := map[UnifiedStepType]string{
		UnifiedStepTypeLLMCall:       "llm_call",
		UnifiedStepTypeToolCall:      "tool_call",
		UnifiedStepTypeConnectorCall: "connector_call",
		UnifiedStepTypeHumanTask:     "human_task",
		UnifiedStepTypeSynthesis:     "synthesis",
		UnifiedStepTypeAction:        "action",
		UnifiedStepTypeGate:          "gate",
	}

	for stepType, expectedValue := range expected {
		if string(stepType) != expectedValue {
			t.Errorf("UnifiedStepType %v = %v, want %v", stepType, string(stepType), expectedValue)
		}
	}
}

func TestUnifiedGateDecisionConstants(t *testing.T) {
	if UnifiedGateDecisionAllow != "allow" {
		t.Errorf("UnifiedGateDecisionAllow = %v, want allow", UnifiedGateDecisionAllow)
	}
	if UnifiedGateDecisionBlock != "block" {
		t.Errorf("UnifiedGateDecisionBlock = %v, want block", UnifiedGateDecisionBlock)
	}
	if UnifiedGateDecisionRequireApproval != "require_approval" {
		t.Errorf("UnifiedGateDecisionRequireApproval = %v, want require_approval", UnifiedGateDecisionRequireApproval)
	}
}

func TestUnifiedApprovalStatusConstants(t *testing.T) {
	if UnifiedApprovalStatusPending != "pending" {
		t.Errorf("UnifiedApprovalStatusPending = %v, want pending", UnifiedApprovalStatusPending)
	}
	if UnifiedApprovalStatusApproved != "approved" {
		t.Errorf("UnifiedApprovalStatusApproved = %v, want approved", UnifiedApprovalStatusApproved)
	}
	if UnifiedApprovalStatusRejected != "rejected" {
		t.Errorf("UnifiedApprovalStatusRejected = %v, want rejected", UnifiedApprovalStatusRejected)
	}
}

// ============================================================================
// GetExecutionStatus HTTP Tests
// ============================================================================

func TestGetExecutionStatus(t *testing.T) {
	now := time.Now()
	expectedResp := ExecutionStatus{
		ExecutionID:      "exec_test123",
		ExecutionType:    ExecutionTypeWCP,
		Name:             "test-workflow",
		Source:           "langgraph",
		Status:           ExecutionStatusRunning,
		CurrentStepIndex: 1,
		TotalSteps:       3,
		ProgressPercent:  33.3,
		StartedAt:        now,
		Steps: []UnifiedStepStatus{
			{StepID: "step-1", StepIndex: 0, Status: StepStatusCompleted},
			{StepID: "step-2", StepIndex: 1, Status: StepStatusRunning},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/unified/executions/exec_test123" {
			t.Errorf("Expected path /api/v1/unified/executions/exec_test123, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	status, err := client.GetExecutionStatus("exec_test123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.ExecutionID != "exec_test123" {
		t.Errorf("Expected execution_id 'exec_test123', got '%s'", status.ExecutionID)
	}
	if status.ExecutionType != ExecutionTypeWCP {
		t.Errorf("Expected execution_type 'wcp_workflow', got '%s'", status.ExecutionType)
	}
	if status.Status != ExecutionStatusRunning {
		t.Errorf("Expected status 'running', got '%s'", status.Status)
	}
	if status.TotalSteps != 3 {
		t.Errorf("Expected total_steps 3, got %d", status.TotalSteps)
	}
	if len(status.Steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(status.Steps))
	}
}

func TestGetExecutionStatusEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	_, err := client.GetExecutionStatus("")
	if err == nil {
		t.Error("Expected error for empty execution ID")
	}
}

func TestGetExecutionStatusServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Execution not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetExecutionStatus("nonexistent")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// ============================================================================
// ListUnifiedExecutions HTTP Tests
// ============================================================================

func TestListUnifiedExecutions(t *testing.T) {
	now := time.Now()
	expectedResp := UnifiedListExecutionsResponse{
		Executions: []ExecutionStatus{
			{
				ExecutionID:   "exec_1",
				ExecutionType: ExecutionTypeMAP,
				Name:          "plan-alpha",
				Status:        ExecutionStatusCompleted,
				TotalSteps:    5,
				StartedAt:     now,
			},
			{
				ExecutionID:   "exec_2",
				ExecutionType: ExecutionTypeWCP,
				Name:          "workflow-beta",
				Status:        ExecutionStatusRunning,
				TotalSteps:    3,
				StartedAt:     now,
			},
		},
		Total:   2,
		Limit:   50,
		Offset:  0,
		HasMore: false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/unified/executions" {
			t.Errorf("Expected path /api/v1/unified/executions, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.ListUnifiedExecutions(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("Expected total 2, got %d", result.Total)
	}
	if len(result.Executions) != 2 {
		t.Errorf("Expected 2 executions, got %d", len(result.Executions))
	}
	if result.HasMore {
		t.Error("Expected has_more to be false")
	}
}

func TestListUnifiedExecutionsWithFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if query.Get("execution_type") != "wcp_workflow" {
			t.Errorf("Expected execution_type=wcp_workflow, got %s", query.Get("execution_type"))
		}
		if query.Get("status") != "running" {
			t.Errorf("Expected status=running, got %s", query.Get("status"))
		}
		if query.Get("tenant_id") != "tenant-001" {
			t.Errorf("Expected tenant_id=tenant-001, got %s", query.Get("tenant_id"))
		}
		if query.Get("org_id") != "org-001" {
			t.Errorf("Expected org_id=org-001, got %s", query.Get("org_id"))
		}
		if query.Get("limit") != "10" {
			t.Errorf("Expected limit=10, got %s", query.Get("limit"))
		}
		if query.Get("offset") != "20" {
			t.Errorf("Expected offset=20, got %s", query.Get("offset"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UnifiedListExecutionsResponse{
			Executions: []ExecutionStatus{},
			Total:      0,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListUnifiedExecutions(&UnifiedListExecutionsRequest{
		ExecutionType: ExecutionTypeWCP,
		Status:        ExecutionStatusRunning,
		TenantID:      "tenant-001",
		OrgID:         "org-001",
		Limit:         10,
		Offset:        20,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestListUnifiedExecutionsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListUnifiedExecutions(nil)
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// ============================================================================
// CancelExecution HTTP Tests
// ============================================================================

func TestCancelExecution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/unified/executions/exec_test123/cancel"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req["reason"] != "no longer needed" {
			t.Errorf("Expected reason 'no longer needed', got '%s'", req["reason"])
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

	err := client.CancelExecution("exec_test123", "no longer needed")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestCancelExecutionEmptyReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		// When reason is empty, an empty map should still be sent
		if _, ok := req["reason"]; ok && req["reason"] != "" {
			t.Errorf("Expected empty reason, got '%s'", req["reason"])
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.CancelExecution("exec_test123", "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestCancelExecutionEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.CancelExecution("", "some reason")
	if err == nil {
		t.Error("Expected error for empty execution ID")
	}
}

func TestCancelExecutionServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Execution not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.CancelExecution("nonexistent", "reason")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}
