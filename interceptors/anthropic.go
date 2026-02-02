// Package interceptors provides transparent LLM governance wrappers for popular AI clients.
//
// Example using anthropic-sdk-go:
//
//	import (
//		"github.com/anthropics/anthropic-sdk-go"
//		"github.com/getaxonflow/axonflow-sdk-go/v3"
//		"github.com/getaxonflow/axonflow-sdk-go/v3/interceptors"
//	)
//
//	client := anthropic.NewClient()
//	axonflow := axonflow.NewClient(axonflow.AxonFlowConfig{...})
//
//	// Wrap the client - governance is now automatic
//	wrapped := interceptors.WrapAnthropicClient(client, axonflow, "user-token")
//
//	// Use as normal
//	resp, err := wrapped.CreateMessage(ctx, anthropic.MessageRequest{...})
package interceptors

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v3"
)

// AnthropicContentBlock represents a content block in an Anthropic message
type AnthropicContentBlock struct {
	Type string `json:"type"` // "text" or "image"
	Text string `json:"text,omitempty"`
}

// AnthropicMessage represents a message in the Anthropic API
type AnthropicMessage struct {
	Role    string                  `json:"role"` // "user" or "assistant"
	Content []AnthropicContentBlock `json:"content"`
}

// AnthropicMessageRequest represents a message creation request to Anthropic
type AnthropicMessageRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Messages    []AnthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	Temperature float32            `json:"temperature,omitempty"`
	TopP        float32            `json:"top_p,omitempty"`
	TopK        int                `json:"top_k,omitempty"`
	StopSeqs    []string           `json:"stop_sequences,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
}

// AnthropicMessageResponse represents a message response from Anthropic
type AnthropicMessageResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []AnthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason"`
	StopSequence string                  `json:"stop_sequence,omitempty"`
	Usage        AnthropicUsage          `json:"usage"`
}

// AnthropicUsage represents token usage in Anthropic responses
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AnthropicMessageCreator is the interface that Anthropic-compatible clients must implement
type AnthropicMessageCreator interface {
	CreateMessage(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error)
}

// AnthropicCreateFunc is the function signature for creating messages
type AnthropicCreateFunc func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error)

// WrappedAnthropicClient wraps an Anthropic client with AxonFlow governance
type WrappedAnthropicClient struct {
	client    AnthropicMessageCreator
	axonflow  *axonflow.AxonFlowClient
	userToken string
}

// WrapAnthropicClient wraps an Anthropic client with AxonFlow governance.
// The wrapped client automatically checks policies before making LLM calls.
//
// Parameters:
//   - client: Anthropic-compatible client implementing AnthropicMessageCreator
//   - axonflowClient: AxonFlow client for governance
//   - userToken: User token for policy evaluation
//
// Returns a WrappedAnthropicClient that can be used like the original client.
func WrapAnthropicClient(client AnthropicMessageCreator, axonflowClient *axonflow.AxonFlowClient, userToken string) *WrappedAnthropicClient {
	return &WrappedAnthropicClient{
		client:    client,
		axonflow:  axonflowClient,
		userToken: userToken,
	}
}

// CreateMessage creates a message with automatic governance.
// It first checks with AxonFlow to ensure the request is allowed by policy,
// then makes the actual LLM call if approved.
func (w *WrappedAnthropicClient) CreateMessage(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
	// Extract prompt from messages
	prompt := extractAnthropicPrompt(req.Messages, req.System)

	// Build context for policy evaluation
	evalContext := map[string]interface{}{
		"provider":    "anthropic",
		"model":       req.Model,
		"temperature": req.Temperature,
		"max_tokens":  req.MaxTokens,
	}

	// Check with AxonFlow
	startTime := time.Now()
	response, err := w.axonflow.ProxyLLMCall(w.userToken, prompt, "llm_chat", evalContext)
	if err != nil {
		return AnthropicMessageResponse{}, err
	}

	// Check if request was blocked
	if response.Blocked {
		policies := []string{}
		if response.PolicyInfo != nil {
			policies = response.PolicyInfo.PoliciesEvaluated
		}
		return AnthropicMessageResponse{}, &PolicyViolationError{
			BlockReason: response.BlockReason,
			Policies:    policies,
		}
	}

	// Make the actual Anthropic call
	result, err := w.client.CreateMessage(ctx, req)
	if err != nil {
		return result, err
	}

	// Calculate latency
	latencyMs := time.Since(startTime).Milliseconds()

	// Audit the call (best effort - don't fail the response if audit fails)
	go func() {
		summary := extractAnthropicResponseSummary(result)

		tokenUsage := axonflow.TokenUsage{
			PromptTokens:     result.Usage.InputTokens,
			CompletionTokens: result.Usage.OutputTokens,
			TotalTokens:      result.Usage.InputTokens + result.Usage.OutputTokens,
		}

		// Get context ID from response metadata if available
		contextID := ""
		if response.RequestID != "" {
			contextID = response.RequestID
		}

		if contextID != "" {
			_, _ = w.axonflow.AuditLLMCall(
				contextID,
				summary,
				"anthropic",
				req.Model,
				tokenUsage,
				latencyMs,
				nil,
			)
		}
	}()

	return result, nil
}

// extractAnthropicPrompt extracts a combined prompt from Anthropic messages
func extractAnthropicPrompt(messages []AnthropicMessage, system string) string {
	var parts []string

	// Include system prompt if present
	if system != "" {
		parts = append(parts, system)
	}

	// Extract content from messages
	for _, msg := range messages {
		for _, block := range msg.Content {
			if block.Type == "text" && block.Text != "" {
				parts = append(parts, block.Text)
			}
		}
	}

	return strings.Join(parts, " ")
}

// extractAnthropicResponseSummary extracts a summary from the Anthropic response
func extractAnthropicResponseSummary(resp AnthropicMessageResponse) string {
	for _, block := range resp.Content {
		if block.Type == "text" && block.Text != "" {
			text := block.Text
			if len(text) > 100 {
				return text[:100]
			}
			return text
		}
	}
	return ""
}

// WrapAnthropicFunc wraps a message creation function with AxonFlow governance.
// This is useful when you don't have a full client interface but just the function.
func WrapAnthropicFunc(
	fn AnthropicCreateFunc,
	axonflowClient *axonflow.AxonFlowClient,
	userToken string,
) AnthropicCreateFunc {
	return func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
		// Extract prompt from messages
		prompt := extractAnthropicPrompt(req.Messages, req.System)

		// Build context for policy evaluation
		evalContext := map[string]interface{}{
			"provider":    "anthropic",
			"model":       req.Model,
			"temperature": req.Temperature,
			"max_tokens":  req.MaxTokens,
		}

		// Check with AxonFlow
		startTime := time.Now()
		response, err := axonflowClient.ProxyLLMCall(userToken, prompt, "llm_chat", evalContext)
		if err != nil {
			return AnthropicMessageResponse{}, err
		}

		// Check if request was blocked
		if response.Blocked {
			policies := []string{}
			if response.PolicyInfo != nil {
				policies = response.PolicyInfo.PoliciesEvaluated
			}
			return AnthropicMessageResponse{}, &PolicyViolationError{
				BlockReason: response.BlockReason,
				Policies:    policies,
			}
		}

		// Make the actual call
		result, err := fn(ctx, req)
		if err != nil {
			return result, err
		}

		// Calculate latency
		latencyMs := time.Since(startTime).Milliseconds()

		// Audit the call (best effort)
		go func() {
			summary := extractAnthropicResponseSummary(result)

			tokenUsage := axonflow.TokenUsage{
				PromptTokens:     result.Usage.InputTokens,
				CompletionTokens: result.Usage.OutputTokens,
				TotalTokens:      result.Usage.InputTokens + result.Usage.OutputTokens,
			}

			if response.RequestID != "" {
				_, _ = axonflowClient.AuditLLMCall(
					response.RequestID,
					summary,
					"anthropic",
					req.Model,
					tokenUsage,
					latencyMs,
					nil,
				)
			}
		}()

		return result, nil
	}
}

// AnthropicAdapter adapts any Anthropic-compatible client to our interface.
// Use this when your client doesn't directly implement AnthropicMessageCreator.
type AnthropicAdapter struct {
	CreateFn AnthropicCreateFunc
}

// CreateMessage implements AnthropicMessageCreator
func (a *AnthropicAdapter) CreateMessage(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
	return a.CreateFn(ctx, req)
}

// NewAnthropicAdapter creates an adapter from a create function
func NewAnthropicAdapter(fn AnthropicCreateFunc) *AnthropicAdapter {
	return &AnthropicAdapter{CreateFn: fn}
}

// AnthropicBridge bridges anthropic-sdk-go client to our interface.
// This allows direct use with the official Anthropic Go SDK.
type AnthropicBridge struct {
	// Client is the underlying anthropic client
	// We use interface{} to avoid importing the library
	Client interface{}
	// CreateFn is the function to call for message creation
	// Set this in the constructor based on your client type
	CreateFn func(ctx context.Context, model string, maxTokens int, messages []AnthropicMessage, system string, opts map[string]interface{}) (AnthropicMessageResponse, error)
}

// CreateMessage implements AnthropicMessageCreator
func (b *AnthropicBridge) CreateMessage(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
	if b.CreateFn == nil {
		return AnthropicMessageResponse{}, errors.New("AnthropicBridge.CreateFn not set - use the helper function for your specific client")
	}
	opts := map[string]interface{}{
		"temperature": req.Temperature,
		"top_p":       req.TopP,
		"top_k":       req.TopK,
	}
	return b.CreateFn(ctx, req.Model, req.MaxTokens, req.Messages, req.System, opts)
}

// CreateAnthropicMessage is a helper to create a simple text message
func CreateAnthropicMessage(role, text string) AnthropicMessage {
	return AnthropicMessage{
		Role: role,
		Content: []AnthropicContentBlock{
			{Type: "text", Text: text},
		},
	}
}

// CreateUserMessage creates a user message with text content
func CreateUserMessage(text string) AnthropicMessage {
	return CreateAnthropicMessage("user", text)
}

// CreateAssistantMessage creates an assistant message with text content
func CreateAssistantMessage(text string) AnthropicMessage {
	return CreateAnthropicMessage("assistant", text)
}
