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
