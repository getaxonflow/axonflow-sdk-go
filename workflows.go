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
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// WorkflowStatus represents the status of a workflow.
type WorkflowStatus string

const (
	WorkflowStatusInProgress WorkflowStatus = "in_progress"
	WorkflowStatusCompleted  WorkflowStatus = "completed"
	WorkflowStatusAborted    WorkflowStatus = "aborted"
	WorkflowStatusFailed     WorkflowStatus = "failed"
)

// IsTerminal returns true if the workflow status is terminal (completed, aborted, or failed).
func (s WorkflowStatus) IsTerminal() bool {
	return s == WorkflowStatusCompleted || s == WorkflowStatusAborted || s == WorkflowStatusFailed
}

// WorkflowSource represents the source orchestrator running the workflow.
type WorkflowSource string

const (
	WorkflowSourceLangGraph WorkflowSource = "langgraph"
	WorkflowSourceLangChain WorkflowSource = "langchain"
	WorkflowSourceCrewAI    WorkflowSource = "crewai"
	WorkflowSourceExternal  WorkflowSource = "external"
)

// GateDecision represents the decision returned by a step gate check.
type GateDecision string

const (
	GateDecisionAllow           GateDecision = "allow"
	GateDecisionBlock           GateDecision = "block"
	GateDecisionRequireApproval GateDecision = "require_approval"
)

// IsAllowed returns true if the gate decision allows the step to proceed.
func (d GateDecision) IsAllowed() bool {
	return d == GateDecisionAllow
}

// IsBlocked returns true if the gate decision blocks the step.
func (d GateDecision) IsBlocked() bool {
	return d == GateDecisionBlock
}

// RequiresApproval returns true if the gate decision requires human approval.
func (d GateDecision) RequiresApproval() bool {
	return d == GateDecisionRequireApproval
}

// ApprovalStatus represents the approval status for steps requiring human approval.
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
)

// StepType indicates what kind of operation the step performs.
type StepType string

const (
	StepTypeLLMCall       StepType = "llm_call"
	StepTypeToolCall      StepType = "tool_call"
	StepTypeConnectorCall StepType = "connector_call"
	StepTypeHumanTask     StepType = "human_task"
)

// CreateWorkflowRequest is the request to create a new workflow.
type CreateWorkflowRequest struct {
	// WorkflowName is the human-readable name for the workflow (required)
	WorkflowName string `json:"workflow_name"`

	// Source is the orchestrator running the workflow (optional)
	Source WorkflowSource `json:"source,omitempty"`

	// TotalSteps is the total number of steps in the workflow, if known (optional)
	TotalSteps int `json:"total_steps,omitempty"`

	// Metadata contains additional key-value metadata for the workflow (optional)
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CreateWorkflowResponse is the response from creating a workflow.
type CreateWorkflowResponse struct {
	// WorkflowID is the unique identifier for the workflow
	WorkflowID string `json:"workflow_id"`

	// WorkflowName is the name of the workflow
	WorkflowName string `json:"workflow_name"`

	// Source is the source orchestrator
	Source WorkflowSource `json:"source"`

	// Status is the current status (always "in_progress" for new workflows)
	Status WorkflowStatus `json:"status"`

	// CreatedAt is when the workflow was created
	CreatedAt time.Time `json:"created_at"`
}

// StepGateRequest is the request to check if a step is allowed to proceed.
type StepGateRequest struct {
	// StepName is the human-readable name for the step (optional)
	StepName string `json:"step_name,omitempty"`

	// StepType is the type of step being executed (required)
	StepType StepType `json:"step_type"`

	// StepInput contains input data for the step, used for policy evaluation (optional)
	StepInput map[string]interface{} `json:"step_input,omitempty"`

	// Model is the LLM model being used, if applicable (optional)
	Model string `json:"model,omitempty"`

	// Provider is the LLM provider, if applicable (optional)
	Provider string `json:"provider,omitempty"`
}

// StepGateResponse is the response from a step gate check.
type StepGateResponse struct {
	// Decision is the gate decision: allow, block, or require_approval
	Decision GateDecision `json:"decision"`

	// StepID is the unique step ID assigned by the system
	StepID string `json:"step_id"`

	// Reason explains the decision (especially for block/require_approval)
	Reason string `json:"reason,omitempty"`

	// PolicyIDs contains IDs of policies that matched and influenced the decision
	PolicyIDs []string `json:"policy_ids,omitempty"`

	// ApprovalURL is the URL to the approval portal (if decision is require_approval)
	ApprovalURL string `json:"approval_url,omitempty"`

	// PoliciesEvaluated contains all policies that were evaluated for this step (Issue #1021)
	PoliciesEvaluated []PolicyMatch `json:"policies_evaluated,omitempty"`

	// PoliciesMatched contains policies that matched and influenced the decision (Issue #1021)
	PoliciesMatched []PolicyMatch `json:"policies_matched,omitempty"`
}

// IsAllowed returns true if the step is allowed to proceed.
func (r *StepGateResponse) IsAllowed() bool {
	return r.Decision.IsAllowed()
}

// IsBlocked returns true if the step is blocked.
func (r *StepGateResponse) IsBlocked() bool {
	return r.Decision.IsBlocked()
}

// RequiresApproval returns true if the step requires human approval.
func (r *StepGateResponse) RequiresApproval() bool {
	return r.Decision.RequiresApproval()
}

// WorkflowStepInfo contains information about a workflow step.
type WorkflowStepInfo struct {
	// StepID is the unique step identifier
	StepID string `json:"step_id"`

	// StepIndex is the step index in the workflow (0-based)
	StepIndex int `json:"step_index"`

	// StepName is the step name
	StepName string `json:"step_name,omitempty"`

	// StepType is the step type
	StepType StepType `json:"step_type"`

	// Decision is the gate decision for this step
	Decision GateDecision `json:"decision"`

	// DecisionReason explains the decision
	DecisionReason string `json:"decision_reason,omitempty"`

	// ApprovalStatus is the approval status (if require_approval decision)
	ApprovalStatus ApprovalStatus `json:"approval_status,omitempty"`

	// ApprovedBy indicates who approved the step (if approved)
	ApprovedBy string `json:"approved_by,omitempty"`

	// GateCheckedAt is when the gate was checked
	GateCheckedAt time.Time `json:"gate_checked_at"`

	// CompletedAt is when the step was completed
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// WorkflowStatusResponse contains the status of a workflow.
type WorkflowStatusResponse struct {
	// WorkflowID is the workflow ID
	WorkflowID string `json:"workflow_id"`

	// WorkflowName is the workflow name
	WorkflowName string `json:"workflow_name"`

	// Source is the source orchestrator
	Source WorkflowSource `json:"source"`

	// Status is the current status
	Status WorkflowStatus `json:"status"`

	// CurrentStepIndex is the current step index (0-based)
	CurrentStepIndex int `json:"current_step_index"`

	// TotalSteps is the total steps in the workflow
	TotalSteps int `json:"total_steps,omitempty"`

	// StartedAt is when the workflow started
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the workflow completed (if completed)
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Steps contains the list of steps in the workflow
	Steps []WorkflowStepInfo `json:"steps,omitempty"`
}

// IsTerminal returns true if the workflow is in a terminal state.
func (r *WorkflowStatusResponse) IsTerminal() bool {
	return r.Status.IsTerminal()
}

// ListWorkflowsOptions contains options for listing workflows.
type ListWorkflowsOptions struct {
	// Status filters by workflow status
	Status WorkflowStatus

	// Source filters by source orchestrator
	Source WorkflowSource

	// Limit is the maximum number of results to return (default 50, max 100)
	Limit int

	// Offset is the offset for pagination
	Offset int
}

// ListWorkflowsResponse is the response from listing workflows.
type ListWorkflowsResponse struct {
	// Workflows is the list of workflows
	Workflows []WorkflowStatusResponse `json:"workflows"`

	// Total is the total count for pagination
	Total int `json:"total"`
}

// AbortWorkflowRequest is the request to abort a workflow.
type AbortWorkflowRequest struct {
	// Reason is the reason for aborting the workflow
	Reason string `json:"reason,omitempty"`
}

// FailWorkflowRequest is the request to fail a workflow.
type FailWorkflowRequest struct {
	// Reason is the reason for failing the workflow
	Reason string `json:"reason,omitempty"`
}

// MarkStepCompletedRequest is the request to mark a step as completed.
type MarkStepCompletedRequest struct {
	// Output is the output of the completed step
	Output map[string]interface{} `json:"output,omitempty"`

	// TokensIn is the number of input tokens consumed by this step (optional)
	TokensIn *int `json:"tokens_in,omitempty"`

	// TokensOut is the number of output tokens produced by this step (optional)
	TokensOut *int `json:"tokens_out,omitempty"`

	// CostUSD is the estimated cost in USD for this step (optional)
	CostUSD *float64 `json:"cost_usd,omitempty"`
}

// CreateWorkflow creates a new workflow for governance tracking.
//
// Call this at the start of your external orchestrator workflow (LangChain, LangGraph, CrewAI, etc.)
// to register it with AxonFlow for governance tracking.
//
// Example:
//
//	workflow, err := client.CreateWorkflow(CreateWorkflowRequest{
//	    WorkflowName: "customer-support-agent",
//	    Source:       WorkflowSourceLangGraph,
//	    TotalSteps:   5,
//	    Metadata:     map[string]interface{}{"customer_id": "cust-123"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Workflow created: %s\n", workflow.WorkflowID)
func (c *AxonFlowClient) CreateWorkflow(req CreateWorkflowRequest) (*CreateWorkflowResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/workflows"
	var result CreateWorkflowResponse

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to create workflow: %w", err)
	}

	return &result, nil
}

// GetWorkflow retrieves the status of a workflow.
//
// Example:
//
//	status, err := client.GetWorkflow("wf_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Status: %s, Current Step: %d\n", status.Status, status.CurrentStepIndex)
func (c *AxonFlowClient) GetWorkflow(workflowID string) (*WorkflowStatusResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s", c.config.Endpoint, workflowID)
	var result WorkflowStatusResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get workflow: %w", err)
	}

	return &result, nil
}

// StepGate checks if a workflow step is allowed to proceed.
//
// This is the core governance method. Call this before executing each step
// in your workflow to check if the step is allowed based on policies.
//
// Example:
//
//	gate, err := client.StepGate("wf_123", "step-generate-code", StepGateRequest{
//	    StepName:  "Generate Code",
//	    StepType:  StepTypeLLMCall,
//	    Model:     "gpt-4",
//	    Provider:  "openai",
//	    StepInput: map[string]interface{}{"prompt": "Generate a hello world function"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if gate.IsBlocked() {
//	    log.Fatalf("Step blocked: %s", gate.Reason)
//	}
//	if gate.RequiresApproval() {
//	    fmt.Printf("Approval required: %s\n", gate.ApprovalURL)
//	    return
//	}
//	// Step is allowed, proceed with execution
func (c *AxonFlowClient) StepGate(workflowID, stepID string, req StepGateRequest) (*StepGateResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}
	if stepID == "" {
		return nil, fmt.Errorf("step ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/gate", c.config.Endpoint, workflowID, stepID)
	var result StepGateResponse

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to check step gate: %w", err)
	}

	return &result, nil
}

// CompleteWorkflow marks a workflow as completed successfully.
//
// Call this when your workflow has completed all steps successfully.
//
// Example:
//
//	err := client.CompleteWorkflow("wf_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) CompleteWorkflow(workflowID string) error {
	if workflowID == "" {
		return fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/complete", c.config.Endpoint, workflowID)

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, struct{}{}, nil); err != nil {
		return fmt.Errorf("failed to complete workflow: %w", err)
	}

	return nil
}

// AbortWorkflow aborts a workflow with an optional reason.
//
// Call this when you need to stop a workflow due to an error or user request.
//
// Example:
//
//	err := client.AbortWorkflow("wf_123", "User cancelled the operation")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) AbortWorkflow(workflowID string, reason string) error {
	if workflowID == "" {
		return fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/abort", c.config.Endpoint, workflowID)
	req := AbortWorkflowRequest{Reason: reason}

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, nil); err != nil {
		return fmt.Errorf("failed to abort workflow: %w", err)
	}

	return nil
}

// FailWorkflow fails a workflow with a reason.
//
// Call this when a workflow encounters an unrecoverable error and cannot continue.
//
// Example:
//
//	err := client.FailWorkflow("wf_123", "Step 3 encountered an unrecoverable error")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) FailWorkflow(workflowID string, reason string) error {
	if workflowID == "" {
		return fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/fail", c.config.Endpoint, workflowID)
	req := FailWorkflowRequest{Reason: reason}

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, nil); err != nil {
		return fmt.Errorf("failed to fail workflow: %w", err)
	}

	return nil
}

// ResumeWorkflow resumes a workflow after approval.
//
// Call this after a step has been approved to continue the workflow.
//
// Example:
//
//	// After approval received via webhook or polling
//	err := client.ResumeWorkflow("wf_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) ResumeWorkflow(workflowID string) error {
	if workflowID == "" {
		return fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/resume", c.config.Endpoint, workflowID)

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, struct{}{}, nil); err != nil {
		return fmt.Errorf("failed to resume workflow: %w", err)
	}

	return nil
}

// MarkStepCompleted marks a workflow step as completed.
//
// Call this after a step has been executed successfully.
//
// Example:
//
//	err := client.MarkStepCompleted("wf_123", "step-1", &MarkStepCompletedRequest{
//	    Output: map[string]interface{}{"result": "success"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) MarkStepCompleted(workflowID, stepID string, req *MarkStepCompletedRequest) error {
	if workflowID == "" {
		return fmt.Errorf("workflow ID is required")
	}
	if stepID == "" {
		return fmt.Errorf("step ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/complete", c.config.Endpoint, workflowID, stepID)

	body := struct{}{}
	if req != nil {
		if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, nil); err != nil {
			return fmt.Errorf("failed to mark step completed: %w", err)
		}
	} else {
		if err := c.makeJSONRequest(context.Background(), "POST", fullURL, body, nil); err != nil {
			return fmt.Errorf("failed to mark step completed: %w", err)
		}
	}

	return nil
}

// ListWorkflows lists workflows with optional filters.
//
// Example:
//
//	result, err := client.ListWorkflows(&ListWorkflowsOptions{
//	    Status: WorkflowStatusInProgress,
//	    Source: WorkflowSourceLangGraph,
//	    Limit:  10,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d workflows\n", result.Total)
func (c *AxonFlowClient) ListWorkflows(opts *ListWorkflowsOptions) (*ListWorkflowsResponse, error) {
	params := url.Values{}

	if opts != nil {
		if opts.Status != "" {
			params.Set("status", string(opts.Status))
		}
		if opts.Source != "" {
			params.Set("source", string(opts.Source))
		}
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
		if opts.Offset > 0 {
			params.Set("offset", strconv.Itoa(opts.Offset))
		}
	}

	fullURL := c.config.Endpoint + "/api/v1/workflows"
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var result ListWorkflowsResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to list workflows: %w", err)
	}

	return &result, nil
}

// ============================================================================
// WCP Approval Types (Feature 5)
// ============================================================================

// ApproveStepRequest is the request to approve a workflow step.
type ApproveStepRequest struct {
	// ApprovedBy identifies who approved the step (optional)
	ApprovedBy string `json:"approved_by,omitempty"`
}

// ApproveStepResponse is the response from approving a workflow step.
type ApproveStepResponse struct {
	// WorkflowID is the workflow containing the step
	WorkflowID string `json:"workflow_id"`

	// StepID is the step that was approved
	StepID string `json:"step_id"`

	// Status is the new status of the step after approval
	Status string `json:"status"`
}

// RejectStepRequest is the request to reject a workflow step.
type RejectStepRequest struct {
	// Reason explains why the step was rejected (optional)
	Reason string `json:"reason,omitempty"`
}

// RejectStepResponse is the response from rejecting a workflow step.
type RejectStepResponse struct {
	// WorkflowID is the workflow containing the step
	WorkflowID string `json:"workflow_id"`

	// StepID is the step that was rejected
	StepID string `json:"step_id"`

	// Status is the new status of the step after rejection
	Status string `json:"status"`
}

// PendingApproval represents a workflow step awaiting human approval.
type PendingApproval struct {
	// WorkflowID is the workflow containing the pending step
	WorkflowID string `json:"workflow_id"`

	// WorkflowName is the human-readable name of the workflow
	WorkflowName string `json:"workflow_name"`

	// StepID is the step awaiting approval
	StepID string `json:"step_id"`

	// StepName is the human-readable name of the step
	StepName string `json:"step_name"`

	// StepType is the type of the step
	StepType string `json:"step_type"`

	// CreatedAt is when the approval request was created
	CreatedAt string `json:"created_at"`
}

// PendingApprovalsResponse is the response from listing pending approvals.
type PendingApprovalsResponse struct {
	// Approvals is the list of pending approvals
	Approvals []PendingApproval `json:"approvals"`

	// Total is the total count of pending approvals
	Total int `json:"total"`
}

// PendingApprovalsOptions contains options for listing pending approvals.
type PendingApprovalsOptions struct {
	// Limit is the maximum number of results to return
	Limit int
}

// ============================================================================
// WCP Approval Methods (Feature 5)
// ============================================================================

// ApproveStep approves a workflow step that requires human approval.
//
// Call this to approve a step that returned GateDecisionRequireApproval from StepGate.
//
// Example:
//
//	resp, err := client.ApproveStep("wf_123", "step_456")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Step %s approved, status: %s\n", resp.StepID, resp.Status)
func (c *AxonFlowClient) ApproveStep(workflowID, stepID string) (*ApproveStepResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}
	if stepID == "" {
		return nil, fmt.Errorf("step ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflow-control/%s/steps/%s/approve", c.config.Endpoint, workflowID, stepID)
	req := ApproveStepRequest{}
	var result ApproveStepResponse

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to approve step: %w", err)
	}

	return &result, nil
}

// RejectStep rejects a workflow step that requires human approval.
//
// Call this to reject a step that returned GateDecisionRequireApproval from StepGate.
//
// Example:
//
//	resp, err := client.RejectStep("wf_123", "step_456")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Step %s rejected, status: %s\n", resp.StepID, resp.Status)
func (c *AxonFlowClient) RejectStep(workflowID, stepID string) (*RejectStepResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}
	if stepID == "" {
		return nil, fmt.Errorf("step ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflow-control/%s/steps/%s/reject", c.config.Endpoint, workflowID, stepID)
	req := RejectStepRequest{}
	var result RejectStepResponse

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to reject step: %w", err)
	}

	return &result, nil
}

// GetPendingApprovals lists all workflow steps awaiting human approval.
//
// Example:
//
//	pending, err := client.GetPendingApprovals(&PendingApprovalsOptions{Limit: 10})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d pending approvals\n", pending.Total)
//	for _, a := range pending.Approvals {
//	    fmt.Printf("  Workflow %s, Step %s (%s)\n", a.WorkflowID, a.StepID, a.StepName)
//	}
func (c *AxonFlowClient) GetPendingApprovals(opts *PendingApprovalsOptions) (*PendingApprovalsResponse, error) {
	params := url.Values{}

	if opts != nil {
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
	}

	fullURL := c.config.Endpoint + "/api/v1/workflow-control/pending-approvals"
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var result PendingApprovalsResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get pending approvals: %w", err)
	}

	return &result, nil
}
