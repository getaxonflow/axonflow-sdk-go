// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// GovernedTool — framework-agnostic tool governance adapter.
//
// Wraps any Tool implementation with AxonFlow input/output policy enforcement.
// Works transparently with any framework that accepts the Tool interface.
//
// "Your tools run the logic. AxonFlow decides when they're allowed to."
package axonflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Tool is a framework-agnostic interface for any callable tool.
type Tool interface {
	Name() string
	Description() string
	Invoke(ctx context.Context, input any) (any, error)
}

// PolicyViolationError is returned when a tool call is blocked by policy.
type PolicyViolationError struct {
	Reason string
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("policy violation: %s", e.Reason)
}

// IsPolicyViolationError checks if an error is a PolicyViolationError.
func IsPolicyViolationError(err error) bool {
	var pve *PolicyViolationError
	return errors.As(err, &pve)
}

// GovernedToolOptions configures a GovernedTool.
type GovernedToolOptions struct {
	// ConnectorTypeFn maps a tool name to a connector type string.
	// Defaults to using the tool's Name().
	ConnectorTypeFn func(name string) string

	// Operation is the operation type passed to MCPCheckInput.
	// Defaults to "execute". Use "query" for read-only tools.
	Operation string
}

// GovernedTool wraps a Tool with AxonFlow input/output governance.
//
// Every Invoke call runs through two policy checks:
//
//  1. Input check (MCPCheckInput): evaluates tool arguments before execution.
//     Blocked calls return PolicyViolationError and the tool never runs.
//  2. Output check (MCPCheckOutput): evaluates tool results after execution.
//     Can block (return error), redact (return cleaned data), or allow.
type GovernedTool struct {
	wrapped       Tool
	client        *AxonFlowClient
	connectorType string
	operation     string
}

// GovernTool wraps a single tool with governance.
func GovernTool(tool Tool, client *AxonFlowClient, opts *GovernedToolOptions) *GovernedTool {
	connectorType := tool.Name()
	operation := "execute"

	if opts != nil {
		if opts.ConnectorTypeFn != nil {
			connectorType = opts.ConnectorTypeFn(tool.Name())
		}
		if opts.Operation != "" {
			operation = opts.Operation
		}
	}

	return &GovernedTool{
		wrapped:       tool,
		client:        client,
		connectorType: connectorType,
		operation:     operation,
	}
}

// GovernTools wraps multiple tools with governance.
func GovernTools(tools []Tool, client *AxonFlowClient, opts *GovernedToolOptions) []*GovernedTool {
	governed := make([]*GovernedTool, len(tools))
	for i, t := range tools {
		governed[i] = GovernTool(t, client, opts)
	}
	return governed
}

// Name returns the governed tool's name.
func (g *GovernedTool) Name() string { return g.wrapped.Name() }

// Description returns the governed tool's description.
func (g *GovernedTool) Description() string { return g.wrapped.Description() }

// Invoke executes the tool with input/output policy checks.
func (g *GovernedTool) Invoke(ctx context.Context, input any) (any, error) {
	// 1. Serialize input
	statement, err := serializeContent(input)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize input: %w", err)
	}

	// 2. Input policy check
	inputCheck, err := g.client.MCPCheckInput(ctx, MCPCheckInputRequest{
		ConnectorType: g.connectorType,
		Statement:     statement,
		Operation:     g.operation,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp input policy check failed: %w", err)
	}

	// 3. If blocked, return PolicyViolationError — tool never runs
	if !inputCheck.Allowed {
		reason := inputCheck.BlockReason
		if reason == "" {
			reason = "tool call blocked by input policy"
		}
		return nil, &PolicyViolationError{Reason: reason}
	}

	// 4. Execute the wrapped tool
	result, err := g.wrapped.Invoke(ctx, input)
	if err != nil {
		return nil, err
	}

	// 5. Serialize result
	serialized, err := serializeContent(result)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize output: %w", err)
	}

	// 6. Output policy check
	outputCheck, err := g.client.MCPCheckOutput(ctx, MCPCheckOutputRequest{
		ConnectorType: g.connectorType,
		Message:       serialized,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp output policy check failed: %w", err)
	}

	// 7. If blocked, return PolicyViolationError
	if !outputCheck.Allowed {
		reason := outputCheck.BlockReason
		if reason == "" {
			reason = "tool output blocked by policy"
		}
		return nil, &PolicyViolationError{Reason: reason}
	}

	// 8. If redacted, return redacted data
	if outputCheck.RedactedData != nil {
		return outputCheck.RedactedData, nil
	}

	// 9. Return original result
	return result, nil
}

// String returns a string representation.
func (g *GovernedTool) String() string {
	return fmt.Sprintf("GovernedTool(name=%s, connectorType=%s)", g.wrapped.Name(), g.connectorType)
}

// serializeContent converts input/output to a string for policy evaluation.
func serializeContent(content any) (string, error) {
	if s, ok := content.(string); ok {
		return s, nil
	}
	b, err := json.Marshal(content)
	if err != nil {
		return fmt.Sprintf("%v", content), nil
	}
	return string(b), nil
}
