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

// ToolContext provides tool-level context for per-tool governance within tool_call steps.
type ToolContext struct {
	ToolName  string                 `json:"tool_name"`
	ToolType  string                 `json:"tool_type,omitempty"`
	ToolInput map[string]interface{} `json:"tool_input,omitempty"`
}

// CreateWorkflowRequest is the request to create a new workflow.
type CreateWorkflowRequest struct {
	// WorkflowName is the human-readable name for the workflow (required)
	WorkflowName string `json:"workflow_name"`

	// Source is the orchestrator running the workflow (optional)
	Source WorkflowSource `json:"source,omitempty"`

	// Metadata contains additional key-value metadata for the workflow (optional)
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// TraceID is an optional trace ID for correlating workflows with external tracing systems
	TraceID string `json:"trace_id,omitempty"`
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

	// TraceID is the trace ID for correlating with external tracing systems
	TraceID string `json:"trace_id,omitempty"`
}

// RetryPolicy controls how step gate decisions behave on repeated calls for the
// same (workflow_id, step_id) pair.
type RetryPolicy string

const (
	// RetryPolicyIdempotent returns the cached decision if the step was already evaluated.
	// This is the default behavior when RetryPolicy is empty.
	RetryPolicyIdempotent RetryPolicy = "idempotent"

	// RetryPolicyReevaluate forces a fresh policy evaluation even if the step was
	// previously evaluated. Use when external state has changed.
	RetryPolicyReevaluate RetryPolicy = "reevaluate"
)

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

	// ToolContext provides tool-level context for per-tool governance within tool_call steps (optional)
	ToolContext *ToolContext `json:"tool_context,omitempty"`

	// RetryPolicy controls behavior on repeated calls for the same (workflow_id, step_id).
	// Default (empty or "idempotent"): return cached decision. "reevaluate": force fresh evaluation.
	RetryPolicy RetryPolicy `json:"retry_policy,omitempty"`

	// IdempotencyKey is a caller-supplied opaque business-level key (max 255 chars).
	// Once set on the first gate call for a (workflow_id, step_id), it is immutable —
	// subsequent gate/complete calls must pass the same key or receive IdempotencyKeyMismatchError.
	// The key is echoed on RetryContext.IdempotencyKey in every subsequent gate response.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// StepGateOptions controls gate-call behavior that lives outside the request body.
type StepGateOptions struct {
	// IncludePriorOutput opts into populating RetryContext.PriorOutput on the
	// response when a prior /complete exists. Default false because prior output
	// may be large and/or contain sensitive data. Sent as ?include_prior_output=true.
	IncludePriorOutput bool
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

	// Cached indicates whether this response was served from a prior decision
	// rather than a fresh policy evaluation.
	//
	// Deprecated: use RetryContext.GateCount > 1 instead. Will be removed in a future major version.
	Cached bool `json:"cached"`

	// DecisionSource indicates how the decision was produced: "fresh" or "cached".
	//
	// Deprecated: use RetryContext.PriorCompletionStatus instead. Will be removed in a future major version.
	DecisionSource string `json:"decision_source"`

	// RetryContext is the first-class state signal for (workflow_id, step_id). Always
	// present on every gate response, including the first call. See RetryContext for
	// field semantics.
	RetryContext RetryContext `json:"retry_context"`
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

	// TraceID is the trace ID for correlating with external tracing systems
	TraceID string `json:"trace_id,omitempty"`

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

	// TraceID filters by trace ID
	TraceID string
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

	// TokensIn is the number of input tokens consumed by this step
	TokensIn *int `json:"tokens_in,omitempty"`

	// TokensOut is the number of output tokens produced by this step
	TokensOut *int `json:"tokens_out,omitempty"`

	// CostUSD is the estimated cost in USD for this step's LLM usage
	CostUSD *float64 `json:"cost_usd,omitempty"`

	// IdempotencyKey must match the key passed on the corresponding gate call, if any.
	// Mismatch (including empty vs set on either side) yields IdempotencyKeyMismatchError.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
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
	return c.StepGateWithOptions(workflowID, stepID, req, StepGateOptions{})
}

// StepGateWithOptions is StepGate with explicit call-level options (e.g. IncludePriorOutput).
//
// Use this variant when you need RetryContext.PriorOutput populated for retry/replay flows.
// The opts.IncludePriorOutput flag is sent as the ?include_prior_output=true query param.
//
// Example:
//
//	gate, err := client.StepGateWithOptions("wf_123", "step-1",
//	    StepGateRequest{StepType: StepTypeLLMCall, IdempotencyKey: "payment:wire:acct4471:invoice-7721"},
//	    StepGateOptions{IncludePriorOutput: true})
//	if err != nil {
//	    var idemErr *IdempotencyKeyMismatchError
//	    if errors.As(err, &idemErr) {
//	        // expected_idempotency_key / received_idempotency_key available on idemErr
//	    }
//	    return err
//	}
//	if gate.RetryContext.PriorCompletionStatus == PriorCompletionStatusCompleted {
//	    // prior result is in gate.RetryContext.PriorOutput
//	}
func (c *AxonFlowClient) StepGateWithOptions(workflowID, stepID string, req StepGateRequest, opts StepGateOptions) (*StepGateResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}
	if stepID == "" {
		return nil, fmt.Errorf("step ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/gate", c.config.Endpoint, workflowID, stepID)
	if opts.IncludePriorOutput {
		fullURL += "?include_prior_output=true"
	}
	var result StepGateResponse

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		if idemErr := parseIdempotencyKeyMismatch(err); idemErr != nil {
			return nil, idemErr
		}
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

// GetCheckpoints returns all step-gate checkpoints for a workflow.
//
// Checkpoints are created automatically at each step gate evaluation and capture
// the decision and policy context. Available in all tiers.
//
// Example:
//
//	resp, err := client.GetCheckpoints("wf_123")
//	for _, cp := range resp.Checkpoints {
//	    fmt.Printf("Step %s: %s (resumable=%v)\n", cp.StepID, cp.GateDecision, cp.IsResumable)
//	}
func (c *AxonFlowClient) GetCheckpoints(workflowID string) (*CheckpointListResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/checkpoints", c.config.Endpoint, workflowID)

	var resp CheckpointListResponse
	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &resp); err != nil {
		return nil, fmt.Errorf("failed to get checkpoints: %w", err)
	}

	return &resp, nil
}

// ResumeFromLastCheckpoint resumes a workflow from its last resumable checkpoint
// with fresh policy evaluation. Evaluation+ tier.
//
// Example:
//
//	resp, err := client.ResumeFromLastCheckpoint("wf_123")
//	fmt.Printf("Resumed from %s, new decision: %s\n", resp.ResumedFromCheckpoint, resp.NewDecision)
func (c *AxonFlowClient) ResumeFromLastCheckpoint(workflowID string) (*ResumeFromCheckpointResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/checkpoints/resume", c.config.Endpoint, workflowID)

	var resp ResumeFromCheckpointResponse
	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, struct{}{}, &resp); err != nil {
		return nil, fmt.Errorf("failed to resume from last checkpoint: %w", err)
	}

	return &resp, nil
}

// ResumeFromCheckpoint resumes a workflow from a specific checkpoint with fresh
// policy evaluation. Enterprise only.
//
// The step gate at the checkpoint boundary is re-evaluated with current policies,
// so any policy changes since the checkpoint was created are reflected.
//
// Example:
//
//	resp, err := client.ResumeFromCheckpoint("wf_123", 42)
//	fmt.Printf("Resumed from %s, new decision: %s\n", resp.ResumedFromCheckpoint, resp.NewDecision)
func (c *AxonFlowClient) ResumeFromCheckpoint(workflowID string, checkpointID int64) (*ResumeFromCheckpointResponse, error) {
	if workflowID == "" {
		return nil, fmt.Errorf("workflow ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/checkpoints/%d/resume", c.config.Endpoint, workflowID, checkpointID)

	var resp ResumeFromCheckpointResponse
	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, struct{}{}, &resp); err != nil {
		return nil, fmt.Errorf("failed to resume from checkpoint: %w", err)
	}

	return &resp, nil
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

	var payload interface{} = struct{}{}
	if req != nil {
		payload = req
	}
	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, payload, nil); err != nil {
		if idemErr := parseIdempotencyKeyMismatch(err); idemErr != nil {
			return idemErr
		}
		return fmt.Errorf("failed to mark step completed: %w", err)
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
		if opts.TraceID != "" {
			params.Set("trace_id", opts.TraceID)
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

// --- Checkpoint Types ---

// Checkpoint represents a governance-aware resume boundary at a step-gate evaluation.
type Checkpoint struct {
	// ID is the database identifier for this checkpoint
	ID int64 `json:"id"`

	// WorkflowID is the workflow this checkpoint belongs to
	WorkflowID string `json:"workflow_id"`

	// StepID is the step this checkpoint was created at
	StepID string `json:"step_id"`

	// StepIndex is the position of the step in the workflow
	StepIndex int `json:"step_index"`

	// StepType is the type of step (llm_call, tool_call, etc.)
	StepType string `json:"step_type,omitempty"`

	// CheckpointType classifies the checkpoint: "step_gate" or "approval_boundary"
	CheckpointType string `json:"checkpoint_type"`

	// GateDecision is the decision recorded at this checkpoint
	GateDecision string `json:"gate_decision"`

	// GateReason explains the decision
	GateReason string `json:"gate_reason,omitempty"`

	// IsResumable indicates whether the workflow can be resumed from this checkpoint
	IsResumable bool `json:"is_resumable"`

	// ResumeCount is how many times the workflow has been resumed from this checkpoint
	ResumeCount int `json:"resume_count"`

	// CreatedAt is when the checkpoint was created
	CreatedAt string `json:"created_at"`
}

// CheckpointListResponse is the response from listing checkpoints.
type CheckpointListResponse struct {
	// Checkpoints is the ordered list of checkpoints for the workflow
	Checkpoints []Checkpoint `json:"checkpoints"`

	// WorkflowID is the workflow the checkpoints belong to
	WorkflowID string `json:"workflow_id"`
}

// ResumeFromCheckpointResponse is the response after resuming from a checkpoint.
type ResumeFromCheckpointResponse struct {
	// WorkflowID is the workflow that was resumed
	WorkflowID string `json:"workflow_id"`

	// ResumedFromCheckpoint is the step_id of the checkpoint that was resumed from
	ResumedFromCheckpoint string `json:"resumed_from_checkpoint"`

	// ResumedFromIndex is the step_index of the checkpoint
	ResumedFromIndex int `json:"resumed_from_index"`

	// NewDecision is the fresh policy decision after re-evaluation
	NewDecision string `json:"new_decision"`

	// DecisionSource is always "fresh" since resume forces re-evaluation
	DecisionSource string `json:"decision_source"`

	// ResumeCount is the updated resume count for this checkpoint
	ResumeCount int `json:"resume_count"`

	// Message is a human-readable summary
	Message string `json:"message"`
}

// ApproveStepRequest is the request to approve a workflow step.
type ApproveStepRequest struct {
	// ApprovedBy identifies who approved the step (optional)
	ApprovedBy string `json:"approved_by,omitempty"`
}

// ApproveStepResponse is the response from approving a workflow step.
//
// Starting with v5.6.0 the server returns the same rich shape as the step-gate
// response — decision resolves to "allow" once approved, retry_context carries
// the first-class state signal, approved_by / approved_at track the reviewer,
// and policies_matched reconstructs the governance trail. The legacy
// workflow_id / step_id / status fields remain for back-compat (status mirrors
// approval_status so older code keeps working).
//
// See ADR-046 (HITL response parity) for why the same shape is returned by
// both the WCP endpoint and the MAP plan-scoped equivalent, and ADR-045 for
// the retry_context wire contract.
type ApproveStepResponse struct {
	// WorkflowID is the workflow containing the step
	WorkflowID string `json:"workflow_id"`

	// PlanID is the MAP plan id on MAP-plane responses. Empty on WCP-plane
	// responses.
	PlanID string `json:"plan_id,omitempty"`

	// StepID is the step that was approved
	StepID string `json:"step_id"`

	// Status is the new status of the step after approval (approved/rejected/pending).
	// Mirrors ApprovalStatus — retained for v5.x back-compat.
	Status string `json:"status,omitempty"`

	// Decision resolves to "allow" on a successful approval — the agent that
	// re-calls /gate will see the step cleared.
	Decision string `json:"decision,omitempty"`

	// Reason is the decision reason text. On the approve path, prefixed with
	// "Approved: ".
	Reason string `json:"reason,omitempty"`

	// ApprovalStatus is the terminal approval status: pending / approved / rejected.
	ApprovalStatus string `json:"approval_status,omitempty"`

	// ApprovalID is the deterministic HITL queue entry UUID.
	ApprovalID string `json:"approval_id,omitempty"`

	// ApprovedBy is the identity that approved the step.
	ApprovedBy string `json:"approved_by,omitempty"`

	// ApprovedAt is when the approval was persisted (RFC3339).
	ApprovedAt string `json:"approved_at,omitempty"`

	// PoliciesMatched are the policies that triggered the original require_approval decision.
	PoliciesMatched []PolicyMatch `json:"policies_matched,omitempty"`

	// RetryContext mirrors the gate response retry_context block.
	RetryContext RetryContext `json:"retry_context"`

	// Message is a human-readable status summary.
	Message string `json:"message,omitempty"`
}

// RejectStepRequest is the request to reject a workflow step.
type RejectStepRequest struct {
	// Reason explains why the step was rejected (optional)
	Reason string `json:"reason,omitempty"`
}

// RejectStepResponse is the response from rejecting a workflow step.
//
// Starting with v5.6.0 the server returns the same rich shape as ApproveStepResponse
// with rejected_by / rejected_at populated instead of approved_by / approved_at.
// See ADR-046.
type RejectStepResponse struct {
	WorkflowID string `json:"workflow_id"`

	// PlanID is the MAP plan id on MAP-plane responses. Empty on WCP-plane responses.
	PlanID string `json:"plan_id,omitempty"`

	StepID string `json:"step_id"`

	// Status mirrors ApprovalStatus (legacy back-compat field).
	Status string `json:"status,omitempty"`

	// Decision resolves to "block" on a successful rejection; the workflow is aborted.
	Decision string `json:"decision,omitempty"`

	// Reason is the decision reason text, prefixed with "Rejected: " on the reject path.
	Reason string `json:"reason,omitempty"`

	// ApprovalStatus is the terminal approval status.
	ApprovalStatus string `json:"approval_status,omitempty"`

	// ApprovalID is the deterministic HITL queue entry UUID.
	ApprovalID string `json:"approval_id,omitempty"`

	// RejectedBy is the identity that rejected the step.
	RejectedBy string `json:"rejected_by,omitempty"`

	// RejectedAt is when the rejection was persisted (RFC3339).
	RejectedAt string `json:"rejected_at,omitempty"`

	// PoliciesMatched are the policies that triggered the require_approval decision.
	PoliciesMatched []PolicyMatch `json:"policies_matched,omitempty"`

	// RetryContext mirrors the gate response retry_context block.
	RetryContext RetryContext `json:"retry_context"`

	// Message is a human-readable status summary.
	Message string `json:"message,omitempty"`
}

// PendingApproval represents a workflow step awaiting human approval.
//
// Populated by both `GetPendingApprovals` (WCP plane) and
// `GetPendingPlanApprovals` (MAP plane). The `PlanID` field is the intentional
// asymmetry between the two planes — populated on MAP-plane entries, empty on
// WCP-plane entries. Mirrors the server-side ADR-046 parity rule.
type PendingApproval struct {
	// WorkflowID is the workflow containing the pending step
	WorkflowID string `json:"workflow_id"`

	// WorkflowName is the human-readable name of the workflow
	WorkflowName string `json:"workflow_name"`

	// PlanID is populated on MAP-plane entries (from GetPendingPlanApprovals);
	// empty on WCP-plane entries.
	PlanID string `json:"plan_id,omitempty"`

	// StepID is the step awaiting approval
	StepID string `json:"step_id"`

	// StepIndex is the zero-based step position within the workflow.
	StepIndex int `json:"step_index"`

	// StepName is the human-readable name of the step
	StepName string `json:"step_name,omitempty"`

	// StepType is the type of the step
	StepType string `json:"step_type,omitempty"`

	// Decision is the gate decision that paused the step — always
	// "require_approval" for pending entries.
	Decision string `json:"decision"`

	// DecisionReason is the reason the policy engine paused the step.
	DecisionReason string `json:"decision_reason,omitempty"`

	// PoliciesMatched is the list of policies that triggered the approval.
	PoliciesMatched []map[string]any `json:"policies_matched,omitempty"`

	// StepInput is the step input payload (may be redacted).
	StepInput map[string]any `json:"step_input,omitempty"`

	// ApprovalStatus is the current approval state — "pending" for listed
	// entries. Typed as *string so callers can distinguish absent from pending.
	ApprovalStatus *string `json:"approval_status,omitempty"`

	// CreatedAt is when the approval request was created
	CreatedAt string `json:"created_at"`
}

// PendingApprovalsResponse is the response from listing pending approvals.
// Shape matches the server wire contract: `pending_approvals` array + `count`.
type PendingApprovalsResponse struct {
	// PendingApprovals is the list of entries awaiting human approval.
	PendingApprovals []PendingApproval `json:"pending_approvals"`

	// Count is the total number of pending approvals matching the request scope.
	Count int `json:"count"`
}

// PendingApprovalsOptions contains options for listing pending approvals.
type PendingApprovalsOptions struct {
	// Limit is the maximum number of results to return
	Limit int

	// PlanID (MAP-plane only) scopes the listing to a single plan. Ignored by
	// GetPendingApprovals; honored by GetPendingPlanApprovals.
	PlanID string
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

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/approve", c.config.Endpoint, workflowID, stepID)
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

	fullURL := fmt.Sprintf("%s/api/v1/workflows/%s/steps/%s/reject", c.config.Endpoint, workflowID, stepID)
	req := RejectStepRequest{}
	var result RejectStepResponse

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to reject step: %w", err)
	}

	return &result, nil
}

// GetPendingApprovals lists all workflow steps awaiting human approval across
// all planes for the caller's tenant — the WCP-plane listing.
//
// Use GetPendingPlanApprovals for the MAP-plane listing (scopes to MAP-backed
// workflows and populates PendingApproval.PlanID on every entry).
//
// Example:
//
//	pending, err := client.GetPendingApprovals(&PendingApprovalsOptions{Limit: 10})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d pending approvals\n", pending.Count)
//	for _, a := range pending.PendingApprovals {
//	    fmt.Printf("  Workflow %s, Step %s (%s)\n", a.WorkflowID, a.StepID, a.StepName)
//	}
func (c *AxonFlowClient) GetPendingApprovals(opts *PendingApprovalsOptions) (*PendingApprovalsResponse, error) {
	params := url.Values{}

	if opts != nil {
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
	}

	fullURL := c.config.Endpoint + "/api/v1/workflows/approvals/pending"
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var result PendingApprovalsResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get pending approvals: %w", err)
	}

	return &result, nil
}

// GetPendingPlanApprovals lists pending approvals for MAP-backed workflows —
// the MAP-plane counterpart of GetPendingApprovals. Every entry has PlanID
// populated; WCP-only approvals are not returned.
//
// Pass opts.PlanID to scope the listing to a single plan.
//
// Requires an Evaluation or Enterprise license (same tier as the MAP
// step approve/reject endpoints).
//
// Example:
//
//	pending, err := client.GetPendingPlanApprovals(&PendingApprovalsOptions{
//	    PlanID: "plan-abc123",
//	    Limit:  10,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, a := range pending.PendingApprovals {
//	    fmt.Printf("  Plan %s step %s awaiting approval\n", a.PlanID, a.StepID)
//	}
func (c *AxonFlowClient) GetPendingPlanApprovals(opts *PendingApprovalsOptions) (*PendingApprovalsResponse, error) {
	params := url.Values{}

	if opts != nil {
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
		if opts.PlanID != "" {
			params.Set("plan_id", opts.PlanID)
		}
	}

	fullURL := c.config.Endpoint + "/api/v1/plans/approvals/pending"
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var result PendingApprovalsResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get pending plan approvals: %w", err)
	}

	return &result, nil
}
