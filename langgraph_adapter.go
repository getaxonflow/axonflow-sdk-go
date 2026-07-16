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

// LangGraph Adapter for AxonFlow Workflow Control Plane.
//
// This adapter wraps LangGraph workflows with AxonFlow governance gates,
// providing policy enforcement at step transitions.
//
// "LangGraph runs the workflow. AxonFlow decides when it's allowed to move forward."
package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WorkflowBlockedError is returned when a workflow step is blocked by policy.
type WorkflowBlockedError struct {
	StepID    string
	Reason    string
	PolicyIDs []string
}

func (e *WorkflowBlockedError) Error() string {
	return fmt.Sprintf("step '%s' blocked: %s", e.StepID, e.Reason)
}

// WorkflowApprovalRequiredError is returned when a workflow step requires human approval.
type WorkflowApprovalRequiredError struct {
	StepID      string
	ApprovalURL string
	Reason      string
}

func (e *WorkflowApprovalRequiredError) Error() string {
	return fmt.Sprintf("step '%s' requires approval: %s", e.StepID, e.Reason)
}

// MCPInterceptorOptions configures the behavior of NewMCPToolInterceptor.
type MCPInterceptorOptions struct {
	// ConnectorTypeFn maps a server name and tool name to a connector type
	// string. It exists for callers who want to derive a custom
	// connector_type from both dimensions (e.g., grouping several MCP
	// servers under one connector type); most callers can leave it nil.
	// The tool name is always sent separately as the "tool" field
	// alongside connector_type (see MCPCheckInputRequest.Tool /
	// MCPCheckOutputRequest.Tool) — it is never concatenated into
	// connector_type. Defaults to returning serverName unchanged.
	ConnectorTypeFn func(serverName, toolName string) string

	// Operation is the operation type passed to MCPCheckInput. Defaults to "execute".
	Operation string
}

// MCPToolRequest represents an MCP tool invocation request.
type MCPToolRequest struct {
	ServerName string
	Name       string
	Args       map[string]interface{}
}

// MCPToolHandler is a function that executes an MCP tool request.
type MCPToolHandler func(req MCPToolRequest) (interface{}, error)

// MCPToolInterceptor wraps an MCP tool handler with policy enforcement.
type MCPToolInterceptor func(req MCPToolRequest, handler MCPToolHandler) (interface{}, error)

// CheckGateOptions contains optional parameters for CheckGate.
type CheckGateOptions struct {
	StepID      string
	StepInput   map[string]interface{}
	Model       string
	Provider    string
	ToolContext *ToolContext
}

// StepCompletedOptions contains optional parameters for StepCompleted.
type StepCompletedOptions struct {
	StepID    string
	Output    map[string]interface{}
	TokensIn  *int
	TokensOut *int
	CostUSD   *float64
}

// CheckToolGateOptions contains optional parameters for CheckToolGate.
type CheckToolGateOptions struct {
	StepName  string
	StepID    string
	ToolInput map[string]interface{}
	Model     string
	Provider  string
}

// ToolCompletedOptions contains optional parameters for ToolCompleted.
type ToolCompletedOptions struct {
	StepName  string
	StepID    string
	Output    map[string]interface{}
	TokensIn  *int
	TokensOut *int
	CostUSD   *float64
}

// LangGraphAdapter wraps LangGraph workflows with AxonFlow governance.
//
// It provides a simple interface for integrating AxonFlow's Workflow Control
// Plane with LangGraph workflows. It handles workflow registration, step gate
// checks, and workflow lifecycle management.
// LangGraphAdapter is not safe for concurrent use. Each workflow execution
// should use its own adapter instance from a single goroutine.
type LangGraphAdapter struct {
	client       *AxonFlowClient
	workflowName string
	source       WorkflowSource
	workflowID   string
	stepCounter  int
	autoBlock    bool
}

// LangGraphAdapterOption configures optional parameters for NewLangGraphAdapter.
type LangGraphAdapterOption func(*LangGraphAdapter)

// WithSource sets the workflow source. Defaults to WorkflowSourceLangGraph.
func WithSource(source WorkflowSource) LangGraphAdapterOption {
	return func(a *LangGraphAdapter) {
		a.source = source
	}
}

// WithAutoBlock sets whether CheckGate raises WorkflowBlockedError on block.
// If false, CheckGate returns false and the caller handles it. Defaults to true.
func WithAutoBlock(autoBlock bool) LangGraphAdapterOption {
	return func(a *LangGraphAdapter) {
		a.autoBlock = autoBlock
	}
}

// NewLangGraphAdapter creates a new LangGraph adapter for AxonFlow governance.
//
// Example:
//
//	adapter := axonflow.NewLangGraphAdapter(client, "code-review-pipeline")
//	workflowID, err := adapter.StartWorkflow(ctx, nil, "")
func NewLangGraphAdapter(client *AxonFlowClient, workflowName string, opts ...LangGraphAdapterOption) *LangGraphAdapter {
	a := &LangGraphAdapter{
		client:       client,
		workflowName: workflowName,
		source:       WorkflowSourceLangGraph,
		autoBlock:    true,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// GetWorkflowID returns the workflow ID assigned after StartWorkflow, or empty string if not started.
func (a *LangGraphAdapter) GetWorkflowID() string {
	return a.workflowID
}

// StartWorkflow registers the workflow with AxonFlow.
//
// Call this at the start of your LangGraph workflow execution.
// Returns the assigned workflow ID.
func (a *LangGraphAdapter) StartWorkflow(ctx context.Context, metadata map[string]interface{}, traceID string) (string, error) {
	// Note: underlying client methods do not yet accept context.Context;
	// we honor cancellation by checking ctx.Done() before each call.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	req := CreateWorkflowRequest{
		WorkflowName: a.workflowName,
		Source:       a.source,
		Metadata:     metadata,
		TraceID:      traceID,
	}

	resp, err := a.client.CreateWorkflow(req)
	if err != nil {
		return "", err
	}

	a.workflowID = resp.WorkflowID
	return a.workflowID, nil
}

// safeName converts a step name to a URL-safe identifier.
func safeName(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}

// CheckGate checks if a step is allowed to proceed.
//
// Call this before executing each LangGraph node to check policy approval.
// Returns true if the step is allowed, false if blocked (when autoBlock=false).
//
// Errors:
//   - WorkflowBlockedError if the step is blocked and autoBlock is true.
//   - WorkflowApprovalRequiredError if the step requires human approval.
//   - An error if the workflow has not been started.
func (a *LangGraphAdapter) CheckGate(ctx context.Context, stepName string, stepType StepType, opts *CheckGateOptions) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	if a.workflowID == "" {
		return false, fmt.Errorf("workflow not started, call StartWorkflow() first")
	}

	var stepID string
	stepInput := map[string]interface{}{}
	var model, provider string
	var toolCtx *ToolContext

	if opts != nil {
		stepID = opts.StepID
		if opts.StepInput != nil {
			stepInput = opts.StepInput
		}
		model = opts.Model
		provider = opts.Provider
		toolCtx = opts.ToolContext
	}

	if stepID == "" {
		a.stepCounter++
		stepID = fmt.Sprintf("step-%d-%s", a.stepCounter, safeName(stepName))
	}

	req := StepGateRequest{
		StepName:    stepName,
		StepType:    stepType,
		StepInput:   stepInput,
		Model:       model,
		Provider:    provider,
		ToolContext: toolCtx,
	}

	resp, err := a.client.StepGate(a.workflowID, stepID, req)
	if err != nil {
		return false, err
	}

	if resp.Decision == GateDecisionBlock {
		if a.autoBlock {
			return false, &WorkflowBlockedError{
				StepID:    resp.StepID,
				Reason:    resp.Reason,
				PolicyIDs: resp.PolicyIDs,
			}
		}
		return false, nil
	}

	if resp.Decision == GateDecisionRequireApproval {
		return false, &WorkflowApprovalRequiredError{
			StepID:      resp.StepID,
			ApprovalURL: resp.ApprovalURL,
			Reason:      resp.Reason,
		}
	}

	return true, nil
}

// StepCompleted marks a step as completed.
//
// Call this after successfully executing a LangGraph node.
func (a *LangGraphAdapter) StepCompleted(ctx context.Context, stepName string, opts *StepCompletedOptions) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if a.workflowID == "" {
		return fmt.Errorf("workflow not started, call StartWorkflow() first")
	}

	var stepID string
	req := MarkStepCompletedRequest{
		Output: map[string]interface{}{},
	}

	if opts != nil {
		stepID = opts.StepID
		if opts.Output != nil {
			req.Output = opts.Output
		}
		req.TokensIn = opts.TokensIn
		req.TokensOut = opts.TokensOut
		req.CostUSD = opts.CostUSD
	}

	if stepID == "" {
		stepID = fmt.Sprintf("step-%d-%s", a.stepCounter, safeName(stepName))
	}

	return a.client.MarkStepCompleted(a.workflowID, stepID, &req)
}

// CheckToolGate checks if a specific tool invocation is allowed.
//
// This is a convenience wrapper around CheckGate that sets the step type to
// StepTypeToolCall and includes ToolContext for per-tool governance.
func (a *LangGraphAdapter) CheckToolGate(ctx context.Context, toolName string, toolType string, opts *CheckToolGateOptions) (bool, error) {
	stepName := "tools/" + toolName
	var stepID string
	var toolInput map[string]interface{}
	var model, provider string

	if opts != nil {
		if opts.StepName != "" {
			stepName = opts.StepName
		}
		stepID = opts.StepID
		toolInput = opts.ToolInput
		model = opts.Model
		provider = opts.Provider
	}

	tc := &ToolContext{
		ToolName:  toolName,
		ToolType:  toolType,
		ToolInput: toolInput,
	}

	return a.CheckGate(ctx, stepName, StepTypeToolCall, &CheckGateOptions{
		StepID:      stepID,
		Model:       model,
		Provider:    provider,
		ToolContext: tc,
	})
}

// ToolCompleted marks a tool invocation as completed.
//
// This is a convenience wrapper around StepCompleted for tool-level tracking.
func (a *LangGraphAdapter) ToolCompleted(ctx context.Context, toolName string, opts *ToolCompletedOptions) error {
	stepName := "tools/" + toolName
	var sopts *StepCompletedOptions

	if opts != nil {
		if opts.StepName != "" {
			stepName = opts.StepName
		}
		sopts = &StepCompletedOptions{
			StepID:    opts.StepID,
			Output:    opts.Output,
			TokensIn:  opts.TokensIn,
			TokensOut: opts.TokensOut,
			CostUSD:   opts.CostUSD,
		}
	}

	return a.StepCompleted(ctx, stepName, sopts)
}

// CompleteWorkflow marks the workflow as completed successfully.
func (a *LangGraphAdapter) CompleteWorkflow(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if a.workflowID == "" {
		return fmt.Errorf("workflow not started, call StartWorkflow() first")
	}

	return a.client.CompleteWorkflow(a.workflowID)
}

// AbortWorkflow aborts the workflow with an optional reason.
func (a *LangGraphAdapter) AbortWorkflow(ctx context.Context, reason string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if a.workflowID == "" {
		return fmt.Errorf("workflow not started, call StartWorkflow() first")
	}

	return a.client.AbortWorkflow(a.workflowID, reason)
}

// FailWorkflow fails the workflow with a reason.
func (a *LangGraphAdapter) FailWorkflow(ctx context.Context, reason string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if a.workflowID == "" {
		return fmt.Errorf("workflow not started, call StartWorkflow() first")
	}

	return a.client.FailWorkflow(a.workflowID, reason)
}

// WaitForApproval polls the workflow status until the step is approved or rejected.
//
// Returns true if approved, false if rejected. Returns an error if the timeout
// is reached or the context is cancelled.
func (a *LangGraphAdapter) WaitForApproval(ctx context.Context, stepID string, pollInterval, timeout time.Duration) (bool, error) {
	if a.workflowID == "" {
		return false, fmt.Errorf("workflow not started, call StartWorkflow() first")
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		status, err := a.client.GetWorkflow(a.workflowID)
		if err != nil {
			return false, fmt.Errorf("failed to get workflow status: %w", err)
		}

		for _, step := range status.Steps {
			if step.StepID == stepID {
				if step.ApprovalStatus == ApprovalStatusApproved {
					return true, nil
				}
				if step.ApprovalStatus == ApprovalStatusRejected {
					return false, nil
				}
				break
			}
		}

		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return false, fmt.Errorf("approval timeout after %s for step %s", timeout, stepID)
		case <-ticker.C:
			// continue polling
		}
	}
}

// NewMCPToolInterceptor returns an MCP tool interceptor that enforces AxonFlow
// input and output policies around every MCP tool call.
//
// Example:
//
//	interceptor := adapter.NewMCPToolInterceptor(nil)
//	result, err := interceptor(req, handler)
func (a *LangGraphAdapter) NewMCPToolInterceptor(opts *MCPInterceptorOptions) MCPToolInterceptor {
	var connectorTypeFn func(string, string) string
	operation := "execute"

	if opts != nil {
		connectorTypeFn = opts.ConnectorTypeFn
		if opts.Operation != "" {
			operation = opts.Operation
		}
	}

	if connectorTypeFn == nil {
		connectorTypeFn = func(serverName, toolName string) string {
			return serverName
		}
	}

	return func(req MCPToolRequest, handler MCPToolHandler) (interface{}, error) {
		// connectorType and tool are two genuinely separate identity fields
		// on the wire (see MCPCheckInputRequest.Tool) — they are no longer
		// concatenated into a single string.
		connectorType := connectorTypeFn(req.ServerName, req.Name)
		tool := req.Name

		argsJSON, err := json.Marshal(req.Args)
		if err != nil {
			argsJSON = []byte("{}")
		}
		statement := fmt.Sprintf("%s.%s(%s)", req.ServerName, req.Name, string(argsJSON))

		preCheck, err := a.client.MCPCheckInput(context.Background(), MCPCheckInputRequest{
			ConnectorType: connectorType,
			Tool:          tool,
			Statement:     statement,
			Operation:     operation,
			Parameters:    req.Args,
		})
		if err != nil {
			return nil, fmt.Errorf("mcp input policy check failed: %w", err)
		}
		if !preCheck.Allowed {
			reason := preCheck.BlockReason
			if reason == "" {
				reason = "tool call blocked by policy"
			}
			return nil, fmt.Errorf("%s", reason)
		}

		result, err := handler(req)
		if err != nil {
			return nil, err
		}

		resultStr, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			resultStr = []byte(fmt.Sprintf("%v", result))
		}

		outputCheck, err := a.client.MCPCheckOutput(context.Background(), MCPCheckOutputRequest{
			ConnectorType: connectorType,
			Tool:          tool,
			Message:       string(resultStr),
		})
		if err != nil {
			return nil, fmt.Errorf("mcp output policy check failed: %w", err)
		}
		if !outputCheck.Allowed {
			reason := outputCheck.BlockReason
			if reason == "" {
				reason = "tool result blocked by policy"
			}
			return nil, fmt.Errorf("%s", reason)
		}
		if outputCheck.RedactedData != nil {
			return outputCheck.RedactedData, nil
		}

		return result, nil
	}
}
