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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ExecutionType distinguishes between MAP plans and WCP workflows.
type ExecutionType string

const (
	// ExecutionTypeMAP represents a Multi-Agent Planning execution.
	ExecutionTypeMAP ExecutionType = "map_plan"
	// ExecutionTypeWCP represents a Workflow Control Plane execution.
	ExecutionTypeWCP ExecutionType = "wcp_workflow"
)

// ExecutionStatusValue represents the status of an execution.
type ExecutionStatusValue string

const (
	ExecutionStatusPending   ExecutionStatusValue = "pending"
	ExecutionStatusRunning   ExecutionStatusValue = "running"
	ExecutionStatusCompleted ExecutionStatusValue = "completed"
	ExecutionStatusFailed    ExecutionStatusValue = "failed"
	ExecutionStatusCancelled ExecutionStatusValue = "cancelled"
	ExecutionStatusAborted   ExecutionStatusValue = "aborted" // WCP-specific
	ExecutionStatusExpired   ExecutionStatusValue = "expired" // MAP-specific
)

// IsTerminal returns true if the execution status is terminal (no more updates expected).
func (s ExecutionStatusValue) IsTerminal() bool {
	return s == ExecutionStatusCompleted ||
		s == ExecutionStatusFailed ||
		s == ExecutionStatusCancelled ||
		s == ExecutionStatusAborted ||
		s == ExecutionStatusExpired
}

// StepStatusValue represents the status of an individual step.
type StepStatusValue string

const (
	StepStatusPending   StepStatusValue = "pending"
	StepStatusRunning   StepStatusValue = "running"
	StepStatusCompleted StepStatusValue = "completed"
	StepStatusFailed    StepStatusValue = "failed"
	StepStatusSkipped   StepStatusValue = "skipped"
	StepStatusBlocked   StepStatusValue = "blocked"  // WCP: blocked by policy
	StepStatusApproval  StepStatusValue = "approval" // WCP: waiting for approval
)

// IsTerminal returns true if the step status is terminal.
func (s StepStatusValue) IsTerminal() bool {
	return s == StepStatusCompleted || s == StepStatusFailed || s == StepStatusSkipped
}

// IsBlocking returns true if the step is in a blocking state.
func (s StepStatusValue) IsBlocking() bool {
	return s == StepStatusBlocked || s == StepStatusApproval
}

// UnifiedStepType indicates what kind of operation the step performs.
type UnifiedStepType string

const (
	UnifiedStepTypeLLMCall       UnifiedStepType = "llm_call"
	UnifiedStepTypeToolCall      UnifiedStepType = "tool_call"
	UnifiedStepTypeConnectorCall UnifiedStepType = "connector_call"
	UnifiedStepTypeHumanTask     UnifiedStepType = "human_task"
	UnifiedStepTypeSynthesis     UnifiedStepType = "synthesis" // MAP: result synthesis step
	UnifiedStepTypeAction        UnifiedStepType = "action"    // Generic action step
	UnifiedStepTypeGate          UnifiedStepType = "gate"      // WCP: policy gate evaluation
)

// UnifiedGateDecision represents the policy decision for a step.
type UnifiedGateDecision string

const (
	UnifiedGateDecisionAllow           UnifiedGateDecision = "allow"
	UnifiedGateDecisionBlock           UnifiedGateDecision = "block"
	UnifiedGateDecisionRequireApproval UnifiedGateDecision = "require_approval"
)

// UnifiedApprovalStatus represents the approval state for require_approval decisions.
type UnifiedApprovalStatus string

const (
	UnifiedApprovalStatusPending  UnifiedApprovalStatus = "pending"
	UnifiedApprovalStatusApproved UnifiedApprovalStatus = "approved"
	UnifiedApprovalStatusRejected UnifiedApprovalStatus = "rejected"
)

// UnifiedStepStatus provides detailed information about an individual execution step.
type UnifiedStepStatus struct {
	// StepID is the unique step identifier
	StepID string `json:"step_id"`

	// StepIndex is the step index in the execution (0-based)
	StepIndex int `json:"step_index"`

	// StepName is the human-readable step name
	StepName string `json:"step_name"`

	// StepType is the type of operation the step performs
	StepType UnifiedStepType `json:"step_type"`

	// Status is the current status of the step
	Status StepStatusValue `json:"status"`

	// StartedAt is when the step started executing
	StartedAt *time.Time `json:"started_at,omitempty"`

	// EndedAt is when the step finished
	EndedAt *time.Time `json:"ended_at,omitempty"`

	// Duration is the duration of step execution (human-readable)
	Duration string `json:"duration,omitempty"`

	// Decision is the policy decision for this step
	Decision UnifiedGateDecision `json:"decision,omitempty"`

	// DecisionReason explains the policy decision
	DecisionReason string `json:"decision_reason,omitempty"`

	// PoliciesMatched contains IDs of policies that matched during evaluation
	PoliciesMatched []string `json:"policies_matched,omitempty"`

	// ApprovalStatus is the approval status (for require_approval decisions)
	ApprovalStatus UnifiedApprovalStatus `json:"approval_status,omitempty"`

	// ApprovedBy indicates who approved the step
	ApprovedBy string `json:"approved_by,omitempty"`

	// ApprovedAt is when the step was approved
	ApprovedAt *time.Time `json:"approved_at,omitempty"`

	// Model is the LLM model used
	Model string `json:"model,omitempty"`

	// Provider is the LLM provider
	Provider string `json:"provider,omitempty"`

	// CostUSD is the cost in USD for this step
	CostUSD *float64 `json:"cost_usd,omitempty"`

	// Input is the step input data
	Input interface{} `json:"input,omitempty"`

	// Output is the step output data
	Output interface{} `json:"output,omitempty"`

	// ResultSummary is a human-readable result summary
	ResultSummary string `json:"result_summary,omitempty"`

	// Error is the error message if step failed
	Error string `json:"error,omitempty"`
}

// ExecutionStatus is the unified execution status for both MAP plans and WCP workflows.
type ExecutionStatus struct {
	// ExecutionID is the unique execution identifier
	ExecutionID string `json:"execution_id"`

	// ExecutionType is the type of execution (MAP plan or WCP workflow)
	ExecutionType ExecutionType `json:"execution_type"`

	// Name is the human-readable name of the execution
	Name string `json:"name"`

	// Source is the source orchestrator (WCP-specific: langchain, crewai, etc.)
	Source string `json:"source,omitempty"`

	// Status is the current execution status
	Status ExecutionStatusValue `json:"status"`

	// CurrentStepIndex is the current step being executed (0-based index)
	CurrentStepIndex int `json:"current_step_index"`

	// TotalSteps is the total number of steps in the execution
	TotalSteps int `json:"total_steps"`

	// ProgressPercent is progress as a percentage (0-100)
	ProgressPercent float64 `json:"progress_percent"`

	// StartedAt is when execution started
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when execution completed
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Duration is the duration of execution (human-readable)
	Duration string `json:"duration,omitempty"`

	// EstimatedCostUSD is the estimated cost in USD (pre-execution)
	EstimatedCostUSD *float64 `json:"estimated_cost_usd,omitempty"`

	// ActualCostUSD is the actual cost in USD (post-execution)
	ActualCostUSD *float64 `json:"actual_cost_usd,omitempty"`

	// Steps contains detailed step information
	Steps []UnifiedStepStatus `json:"steps,omitempty"`

	// Error is the error message if execution failed
	Error string `json:"error,omitempty"`

	// TenantID is the tenant ID for multi-tenancy
	TenantID string `json:"tenant_id,omitempty"`

	// OrgID is the organization ID
	OrgID string `json:"org_id,omitempty"`

	// UserID is the user ID who initiated the execution
	UserID string `json:"user_id,omitempty"`

	// ClientID is the client/application ID
	ClientID string `json:"client_id,omitempty"`

	// Metadata contains additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// CreatedAt is when the execution record was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the execution record was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// IsTerminal returns true if the execution is in a terminal state.
func (e *ExecutionStatus) IsTerminal() bool {
	return e.Status.IsTerminal()
}

// GetCurrentStep returns the currently running step, if any.
func (e *ExecutionStatus) GetCurrentStep() *UnifiedStepStatus {
	for i := range e.Steps {
		if e.Steps[i].Status == StepStatusRunning {
			return &e.Steps[i]
		}
	}
	return nil
}

// TotalCost returns the sum of all step costs.
func (e *ExecutionStatus) TotalCost() float64 {
	var total float64
	for _, step := range e.Steps {
		if step.CostUSD != nil {
			total += *step.CostUSD
		}
	}
	return total
}

// IsMapPlan returns true if this is a MAP plan execution.
func (e *ExecutionStatus) IsMapPlan() bool {
	return e.ExecutionType == ExecutionTypeMAP
}

// IsWcpWorkflow returns true if this is a WCP workflow execution.
func (e *ExecutionStatus) IsWcpWorkflow() bool {
	return e.ExecutionType == ExecutionTypeWCP
}

// UnifiedListExecutionsRequest contains filters for listing executions.
type UnifiedListExecutionsRequest struct {
	// ExecutionType filters by execution type
	ExecutionType ExecutionType

	// Status filters by execution status
	Status ExecutionStatusValue

	// TenantID filters by tenant ID
	TenantID string

	// OrgID filters by organization ID
	OrgID string

	// Limit is the maximum number of results to return (default 50, max 100)
	Limit int

	// Offset is the offset for pagination
	Offset int
}

// UnifiedListExecutionsResponse is the paginated response for listing executions.
type UnifiedListExecutionsResponse struct {
	// Executions is the list of executions
	Executions []ExecutionStatus `json:"executions"`

	// Total is the total count of matching executions
	Total int `json:"total"`

	// Limit is the limit used in the request
	Limit int `json:"limit"`

	// Offset is the offset used in the request
	Offset int `json:"offset"`

	// HasMore indicates whether more results are available
	HasMore bool `json:"has_more"`
}

// GetExecutionStatus retrieves the unified execution status for a MAP plan or WCP workflow.
//
// This method provides a consistent interface for tracking execution progress
// regardless of whether the underlying execution is a MAP plan or WCP workflow.
//
// Example:
//
//	status, err := client.GetExecutionStatus("exec_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Type: %s\n", status.ExecutionType)
//	fmt.Printf("Status: %s\n", status.Status)
//	fmt.Printf("Progress: %.1f%%\n", status.ProgressPercent)
//
//	for _, step := range status.Steps {
//	    fmt.Printf("  Step %d: %s - %s\n", step.StepIndex, step.StepName, step.Status)
//	}
func (c *AxonFlowClient) GetExecutionStatus(executionID string) (*ExecutionStatus, error) {
	if executionID == "" {
		return nil, fmt.Errorf("execution ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/unified/executions/%s", c.config.Endpoint, executionID)
	var result ExecutionStatus

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get execution status: %w", err)
	}

	return &result, nil
}

// ListUnifiedExecutions lists executions (both MAP plans and WCP workflows) with optional filters.
//
// This method provides a unified view across all execution types.
//
// Example:
//
//	// List all running executions
//	result, err := client.ListUnifiedExecutions(&UnifiedListExecutionsRequest{
//	    Status: ExecutionStatusRunning,
//	    Limit:  20,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d running executions\n", result.Total)
//
//	// List only MAP plans
//	mapPlans, err := client.ListUnifiedExecutions(&UnifiedListExecutionsRequest{
//	    ExecutionType: ExecutionTypeMAP,
//	    Limit:         50,
//	})
func (c *AxonFlowClient) ListUnifiedExecutions(opts *UnifiedListExecutionsRequest) (*UnifiedListExecutionsResponse, error) {
	params := url.Values{}

	if opts != nil {
		if opts.ExecutionType != "" {
			params.Set("execution_type", string(opts.ExecutionType))
		}
		if opts.Status != "" {
			params.Set("status", string(opts.Status))
		}
		if opts.TenantID != "" {
			params.Set("tenant_id", opts.TenantID)
		}
		if opts.OrgID != "" {
			params.Set("org_id", opts.OrgID)
		}
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
		if opts.Offset > 0 {
			params.Set("offset", strconv.Itoa(opts.Offset))
		}
	}

	fullURL := c.config.Endpoint + "/api/v1/unified/executions"
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var result UnifiedListExecutionsResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to list executions: %w", err)
	}

	return &result, nil
}

// CancelExecution cancels a running execution (MAP plan or WCP workflow).
//
// The cancellation is propagated to the appropriate subsystem:
//   - WCP workflows are aborted via AbortWorkflow
//   - MAP plans are cancelled via CancelPlan
//
// Example:
//
//	err := client.CancelExecution("wf_abc123", "no longer needed")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) CancelExecution(executionID string, reason string) error {
	if executionID == "" {
		return fmt.Errorf("execution ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/unified/executions/%s/cancel", c.config.Endpoint, executionID)
	var body interface{}
	if reason != "" {
		body = map[string]string{"reason": reason}
	} else {
		body = map[string]string{}
	}

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, body, nil); err != nil {
		return fmt.Errorf("failed to cancel execution: %w", err)
	}

	return nil
}

// StreamExecutionStatus connects to the SSE streaming endpoint and returns
// channels that receive real-time ExecutionStatus updates.
//
// The method establishes a Server-Sent Events (SSE) connection to
// GET /api/v1/executions/{executionID}/stream and parses incoming events
// into ExecutionStatus objects.
//
// Returns:
//   - A read-only channel of ExecutionStatus updates
//   - A read-only error channel for stream errors
//   - An error if the initial connection fails
//
// Both channels are closed when the stream ends (terminal status received),
// the context is cancelled, or the server closes the connection.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
//	defer cancel()
//
//	statusCh, errCh, err := client.StreamExecutionStatus(ctx, "exec_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for status := range statusCh {
//	    fmt.Printf("Status: %s, Progress: %.1f%%\n", status.Status, status.ProgressPercent)
//	    if status.IsTerminal() {
//	        fmt.Println("Execution finished:", status.Status)
//	    }
//	}
//	// Check for stream errors
//	if err := <-errCh; err != nil {
//	    log.Printf("Stream error: %v", err)
//	}
func (c *AxonFlowClient) StreamExecutionStatus(ctx context.Context, executionID string) (<-chan ExecutionStatus, <-chan error, error) {
	if executionID == "" {
		return nil, nil, fmt.Errorf("execution ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/executions/%s/stream", c.config.Endpoint, executionID)

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stream request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	c.addAuthHeaders(req)

	// Use a client without timeout for SSE streaming — context controls lifetime
	streamClient := &http.Client{
		Transport: c.httpClient.Transport,
		// No timeout — SSE connections are long-lived
	}

	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to stream: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, &httpError{
			statusCode: resp.StatusCode,
			message:    fmt.Sprintf("stream connection failed for execution %s", executionID),
		}
	}

	statusCh := make(chan ExecutionStatus, 16)
	errCh := make(chan error, 1)

	go func() {
		defer close(statusCh)
		defer close(errCh)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)

		for scanner.Scan() {
			line := scanner.Text()

			// Check context cancellation
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			// SSE protocol: skip empty lines and comments
			if line == "" || strings.HasPrefix(line, ":") {
				continue
			}

			// Parse "data: {json}" lines
			if !strings.HasPrefix(line, "data: ") && !strings.HasPrefix(line, "data:") {
				continue
			}

			// Extract JSON payload
			data := strings.TrimPrefix(line, "data: ")
			data = strings.TrimPrefix(data, "data:")
			data = strings.TrimSpace(data)

			if data == "" {
				continue
			}

			var status ExecutionStatus
			if err := json.Unmarshal([]byte(data), &status); err != nil {
				if c.config.Debug {
					log.Printf("[AxonFlow] SSE: failed to parse status event: %v", err)
				}
				continue
			}

			// Send status update
			select {
			case statusCh <- status:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}

			if c.config.Debug {
				log.Printf("[AxonFlow] SSE: execution %s status=%s progress=%.1f%%",
					executionID, status.Status, status.ProgressPercent)
			}

			// Stop reading if terminal status reached
			if status.Status.IsTerminal() {
				return
			}
		}

		if err := scanner.Err(); err != nil {
			// Context cancellation produces an error from the scanner — only
			// report it if the context is still active
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
			default:
				errCh <- fmt.Errorf("SSE stream read error: %w", err)
			}
		}
	}()

	if c.config.Debug {
		log.Printf("[AxonFlow] SSE: connected to execution stream for %s", executionID)
	}

	return statusCh, errCh, nil
}
