// Package interceptors provides transparent LLM governance wrappers for popular AI clients.
//
// The interceptors automatically apply AxonFlow governance to LLM calls without
// requiring changes to application code. Simply wrap your client and use it as normal.
//
// Example using sashabaranov/go-openai:
//
//	import (
//		"github.com/sashabaranov/go-openai"
//		"github.com/getaxonflow/axonflow-sdk-go/v5"
//		"github.com/getaxonflow/axonflow-sdk-go/v5/interceptors"
//	)
//
//	client := openai.NewClient("your-api-key")
//	axonflow := axonflow.NewClient(axonflow.AxonFlowConfig{...})
//
//	// Wrap the client - governance is now automatic
//	wrapped := interceptors.WrapOpenAIClient(client, axonflow, "user-token")
//
//	// Use as normal
//	resp, err := wrapped.CreateChatCompletion(ctx, openai.ChatCompletionRequest{...})
package interceptors

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v5"
)

// ChatMessage represents a chat message for LLM calls
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest represents a chat completion request
type ChatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature float32       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	TopP        float32       `json:"top_p,omitempty"`
	N           int           `json:"n,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
	Stop        []string      `json:"stop,omitempty"`
}

// ChatCompletionChoice represents a choice in the completion response
type ChatCompletionChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// Usage represents token usage information
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletionResponse represents a chat completion response
type ChatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []ChatCompletionChoice `json:"choices"`
	Usage   Usage                  `json:"usage"`
}

// OpenAIChatCompleter is the interface that OpenAI-compatible clients must implement
type OpenAIChatCompleter interface {
	CreateChatCompletion(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error)
}

// OpenAICreateFunc is the function signature for creating chat completions
type OpenAICreateFunc func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error)

// PolicyViolationError is returned when a request is blocked by policy
type PolicyViolationError struct {
	BlockReason string
	Policies    []string
}

func (e *PolicyViolationError) Error() string {
	return "request blocked by policy: " + e.BlockReason
}

// WrappedOpenAIClient wraps an OpenAI client with AxonFlow governance
type WrappedOpenAIClient struct {
	client    OpenAIChatCompleter
	axonflow  *axonflow.AxonFlowClient
	userToken string
}

// WrapOpenAIClient wraps an OpenAI client with AxonFlow governance.
// The wrapped client automatically checks policies before making LLM calls.
//
// Parameters:
//   - client: OpenAI-compatible client implementing OpenAIChatCompleter
//   - axonflowClient: AxonFlow client for governance
//   - userToken: User token for policy evaluation
//
// Returns a WrappedOpenAIClient that can be used like the original client.
func WrapOpenAIClient(client OpenAIChatCompleter, axonflowClient *axonflow.AxonFlowClient, userToken string) *WrappedOpenAIClient {
	return &WrappedOpenAIClient{
		client:    client,
		axonflow:  axonflowClient,
		userToken: userToken,
	}
}

// CreateChatCompletion creates a chat completion with automatic governance.
// It first checks with AxonFlow to ensure the request is allowed by policy,
// then makes the actual LLM call if approved.
func (w *WrappedOpenAIClient) CreateChatCompletion(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
	// Extract prompt from messages
	prompt := extractOpenAIPrompt(req.Messages)

	// Build context for policy evaluation
	evalContext := map[string]interface{}{
		"provider":    "openai",
		"model":       req.Model,
		"temperature": req.Temperature,
		"max_tokens":  req.MaxTokens,
	}

	// Check with AxonFlow
	startTime := time.Now()
	response, err := w.axonflow.ProxyLLMCall(w.userToken, prompt, "llm_chat", evalContext)
	if err != nil {
		return ChatCompletionResponse{}, err
	}

	// Check if request was blocked
	if response.Blocked {
		policies := []string{}
		if response.PolicyInfo != nil {
			policies = response.PolicyInfo.PoliciesEvaluated
		}
		return ChatCompletionResponse{}, &PolicyViolationError{
			BlockReason: response.BlockReason,
			Policies:    policies,
		}
	}

	// Make the actual OpenAI call
	result, err := w.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return result, err
	}

	// Calculate latency
	latencyMs := time.Since(startTime).Milliseconds()

	// Audit the call (best effort - don't fail the response if audit fails)
	go func() {
		summary := ""
		if len(result.Choices) > 0 {
			content := result.Choices[0].Message.Content
			if len(content) > 100 {
				summary = content[:100]
			} else {
				summary = content
			}
		}

		tokenUsage := axonflow.TokenUsage{
			PromptTokens:     result.Usage.PromptTokens,
			CompletionTokens: result.Usage.CompletionTokens,
			TotalTokens:      result.Usage.TotalTokens,
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
				"openai",
				req.Model,
				tokenUsage,
				latencyMs,
				nil,
			)
		}
	}()

	return result, nil
}

// extractOpenAIPrompt extracts a combined prompt from chat messages
func extractOpenAIPrompt(messages []ChatMessage) string {
	var parts []string
	for _, msg := range messages {
		if msg.Content != "" {
			parts = append(parts, msg.Content)
		}
	}
	return strings.Join(parts, " ")
}

// WrapOpenAIFunc wraps a chat completion function with AxonFlow governance.
// This is useful when you don't have a full client interface but just the function.
//
// Example:
//
//	wrapped := interceptors.WrapOpenAIFunc(
//		func(ctx context.Context, req interceptors.ChatCompletionRequest) (interceptors.ChatCompletionResponse, error) {
//			// Your OpenAI call here
//		},
//		axonflowClient,
//		"user-token",
//	)
func WrapOpenAIFunc(
	fn OpenAICreateFunc,
	axonflowClient *axonflow.AxonFlowClient,
	userToken string,
) OpenAICreateFunc {
	return func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
		// Extract prompt from messages
		prompt := extractOpenAIPrompt(req.Messages)

		// Build context for policy evaluation
		evalContext := map[string]interface{}{
			"provider":    "openai",
			"model":       req.Model,
			"temperature": req.Temperature,
			"max_tokens":  req.MaxTokens,
		}

		// Check with AxonFlow
		startTime := time.Now()
		response, err := axonflowClient.ProxyLLMCall(userToken, prompt, "llm_chat", evalContext)
		if err != nil {
			return ChatCompletionResponse{}, err
		}

		// Check if request was blocked
		if response.Blocked {
			policies := []string{}
			if response.PolicyInfo != nil {
				policies = response.PolicyInfo.PoliciesEvaluated
			}
			return ChatCompletionResponse{}, &PolicyViolationError{
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
			summary := ""
			if len(result.Choices) > 0 {
				content := result.Choices[0].Message.Content
				if len(content) > 100 {
					summary = content[:100]
				} else {
					summary = content
				}
			}

			tokenUsage := axonflow.TokenUsage{
				PromptTokens:     result.Usage.PromptTokens,
				CompletionTokens: result.Usage.CompletionTokens,
				TotalTokens:      result.Usage.TotalTokens,
			}

			if response.RequestID != "" {
				_, _ = axonflowClient.AuditLLMCall(
					response.RequestID,
					summary,
					"openai",
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

// OpenAIAdapter adapts any OpenAI-compatible client to our interface.
// Use this when your client doesn't directly implement OpenAIChatCompleter.
type OpenAIAdapter struct {
	CreateFn OpenAICreateFunc
}

// CreateChatCompletion implements OpenAIChatCompleter
func (a *OpenAIAdapter) CreateChatCompletion(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
	return a.CreateFn(ctx, req)
}

// NewOpenAIAdapter creates an adapter from a create function
func NewOpenAIAdapter(fn OpenAICreateFunc) *OpenAIAdapter {
	return &OpenAIAdapter{CreateFn: fn}
}

// IsPolicyViolationError checks if an error is a PolicyViolationError
func IsPolicyViolationError(err error) bool {
	var pve *PolicyViolationError
	return errors.As(err, &pve)
}

// GetPolicyViolation extracts PolicyViolationError details from an error
func GetPolicyViolation(err error) (*PolicyViolationError, bool) {
	var pve *PolicyViolationError
	if errors.As(err, &pve) {
		return pve, true
	}
	return nil, false
}

// GoOpenAIBridge bridges sashabaranov/go-openai client to our interface.
// This allows direct use with the popular go-openai library.
//
// Example:
//
//	import "github.com/sashabaranov/go-openai"
//
//	client := openai.NewClient("your-api-key")
//	bridge := interceptors.NewGoOpenAIBridge(client)
//	wrapped := interceptors.WrapOpenAIClient(bridge, axonflowClient, "user-token")
type GoOpenAIBridge struct {
	// Client is the underlying go-openai client
	// We use interface{} to avoid importing the library
	Client interface{}
	// CreateFn is the function to call for chat completions
	// Set this in the constructor based on your client type
	CreateFn func(ctx context.Context, model string, messages []ChatMessage, opts map[string]interface{}) (ChatCompletionResponse, error)
}

// CreateChatCompletion implements OpenAIChatCompleter for go-openai
func (b *GoOpenAIBridge) CreateChatCompletion(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
	if b.CreateFn == nil {
		return ChatCompletionResponse{}, errors.New("GoOpenAIBridge.CreateFn not set - use the helper function for your specific client")
	}
	opts := map[string]interface{}{
		"temperature": req.Temperature,
		"max_tokens":  req.MaxTokens,
	}
	return b.CreateFn(ctx, req.Model, req.Messages, opts)
}

// MarshalRequest marshals a ChatCompletionRequest to JSON
func MarshalRequest(req ChatCompletionRequest) ([]byte, error) {
	return json.Marshal(req)
}

// UnmarshalResponse unmarshals a ChatCompletionResponse from JSON
func UnmarshalResponse(data []byte) (ChatCompletionResponse, error) {
	var resp ChatCompletionResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}
