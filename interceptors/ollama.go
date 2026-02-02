// Package interceptors provides transparent LLM governance wrappers for popular AI clients.
//
// Ollama interceptor wraps Ollama's local LLM server for automatic governance.
// Ollama typically runs on localhost:11434 and requires no authentication.
//
// Example:
//
//	import (
//		"github.com/ollama/ollama/api"
//		"github.com/getaxonflow/axonflow-sdk-go/v3"
//		"github.com/getaxonflow/axonflow-sdk-go/v3/interceptors"
//	)
//
//	client, _ := api.ClientFromEnvironment()
//	axonflow := axonflow.NewClient(axonflow.AxonFlowConfig{...})
//
//	// Wrap the client - governance is now automatic
//	wrapped := interceptors.WrapOllamaClient(client, axonflow, "user-token")
//
//	// Use as normal
//	resp, err := wrapped.Chat(ctx, &api.ChatRequest{...})
package interceptors

import (
	"context"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v3"
)

// OllamaMessage represents a message in an Ollama chat
type OllamaMessage struct {
	Role    string   `json:"role"`
	Content string   `json:"content"`
	Images  []string `json:"images,omitempty"`
}

// OllamaChatRequest represents a chat request to Ollama
type OllamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool            `json:"stream,omitempty"`
	Format   string          `json:"format,omitempty"`
	Options  *OllamaOptions  `json:"options,omitempty"`
}

// OllamaOptions contains generation options
type OllamaOptions struct {
	Temperature float32  `json:"temperature,omitempty"`
	TopP        float32  `json:"top_p,omitempty"`
	TopK        int      `json:"top_k,omitempty"`
	NumPredict  int      `json:"num_predict,omitempty"`
	Stop        []string `json:"stop,omitempty"`
}

// OllamaChatResponse represents a chat response from Ollama
type OllamaChatResponse struct {
	Model              string        `json:"model"`
	CreatedAt          string        `json:"created_at"`
	Message            OllamaMessage `json:"message"`
	Done               bool          `json:"done"`
	TotalDuration      int64         `json:"total_duration,omitempty"`
	LoadDuration       int64         `json:"load_duration,omitempty"`
	PromptEvalCount    int           `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64         `json:"prompt_eval_duration,omitempty"`
	EvalCount          int           `json:"eval_count,omitempty"`
	EvalDuration       int64         `json:"eval_duration,omitempty"`
}

// OllamaGenerateRequest represents a generate (completion) request
type OllamaGenerateRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream,omitempty"`
	Format  string         `json:"format,omitempty"`
	Options *OllamaOptions `json:"options,omitempty"`
}

// OllamaGenerateResponse represents a generate response
type OllamaGenerateResponse struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	TotalDuration      int64  `json:"total_duration,omitempty"`
	LoadDuration       int64  `json:"load_duration,omitempty"`
	PromptEvalCount    int    `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64  `json:"prompt_eval_duration,omitempty"`
	EvalCount          int    `json:"eval_count,omitempty"`
	EvalDuration       int64  `json:"eval_duration,omitempty"`
}

// OllamaChatFunc is the function signature for Ollama chat
type OllamaChatFunc func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error)

// OllamaGenerateFunc is the function signature for Ollama generate
type OllamaGenerateFunc func(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error)

// OllamaChatClient is the interface for Ollama chat operations
type OllamaChatClient interface {
	Chat(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error)
}

// OllamaGenerateClient is the interface for Ollama generate operations
type OllamaGenerateClient interface {
	Generate(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error)
}

// WrappedOllamaClient wraps an Ollama client with AxonFlow governance
type WrappedOllamaClient struct {
	chatClient     OllamaChatClient
	generateClient OllamaGenerateClient
	axonflow       *axonflow.AxonFlowClient
	userToken      string
}

// WrapOllamaChatClient wraps an Ollama chat client with AxonFlow governance.
//
// Example:
//
//	client := &MyOllamaClient{host: "http://localhost:11434"}
//	wrapped := interceptors.WrapOllamaChatClient(client, axonflowClient, "user-123")
//	resp, err := wrapped.Chat(ctx, &OllamaChatRequest{...})
func WrapOllamaChatClient(client OllamaChatClient, axonflowClient *axonflow.AxonFlowClient, userToken string) *WrappedOllamaClient {
	return &WrappedOllamaClient{
		chatClient: client,
		axonflow:   axonflowClient,
		userToken:  userToken,
	}
}

// Chat executes a chat request with automatic governance
func (w *WrappedOllamaClient) Chat(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
	// Extract prompt from messages
	prompt := extractOllamaPrompt(req.Messages)

	// Pre-check with AxonFlow
	preCheckCtx := map[string]interface{}{
		"provider": "ollama",
		"model":    req.Model,
	}

	policyResult, err := w.axonflow.GetPolicyApprovedContext(w.userToken, prompt, nil, preCheckCtx)
	if err != nil {
		return nil, err
	}

	if !policyResult.Approved {
		return nil, &PolicyViolationError{
			BlockReason: policyResult.BlockReason,
			Policies:    policyResult.Policies,
		}
	}

	// Execute the actual call
	startTime := time.Now()
	resp, err := w.chatClient.Chat(ctx, req)
	latencyMs := time.Since(startTime).Milliseconds()

	if err != nil {
		return nil, err
	}

	// Audit the call
	if policyResult.ContextID != "" {
		summary := ""
		if resp != nil {
			summary = truncateString(resp.Message.Content, 200)
		}

		tokenUsage := axonflow.TokenUsage{
			PromptTokens:     resp.PromptEvalCount,
			CompletionTokens: resp.EvalCount,
			TotalTokens:      resp.PromptEvalCount + resp.EvalCount,
		}

		_, _ = w.axonflow.AuditLLMCall(
			policyResult.ContextID,
			summary,
			"ollama",
			req.Model,
			tokenUsage,
			latencyMs,
			nil,
		)
	}

	return resp, nil
}

// WrapOllamaChatFunc wraps an Ollama chat function for governance.
//
// Example:
//
//	wrapped := interceptors.WrapOllamaChatFunc(
//		func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
//			return client.Chat(ctx, req)
//		},
//		axonflow,
//		"user-123",
//	)
func WrapOllamaChatFunc(fn OllamaChatFunc, axonflowClient *axonflow.AxonFlowClient, userToken string) OllamaChatFunc {
	return func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
		prompt := extractOllamaPrompt(req.Messages)

		preCheckCtx := map[string]interface{}{
			"provider": "ollama",
			"model":    req.Model,
		}

		policyResult, err := axonflowClient.GetPolicyApprovedContext(userToken, prompt, nil, preCheckCtx)
		if err != nil {
			return nil, err
		}

		if !policyResult.Approved {
			return nil, &PolicyViolationError{
				BlockReason: policyResult.BlockReason,
				Policies:    policyResult.Policies,
			}
		}

		startTime := time.Now()
		resp, err := fn(ctx, req)
		latencyMs := time.Since(startTime).Milliseconds()

		if err != nil {
			return nil, err
		}

		if policyResult.ContextID != "" {
			summary := ""
			if resp != nil {
				summary = truncateString(resp.Message.Content, 200)
			}

			tokenUsage := axonflow.TokenUsage{
				PromptTokens:     resp.PromptEvalCount,
				CompletionTokens: resp.EvalCount,
				TotalTokens:      resp.PromptEvalCount + resp.EvalCount,
			}

			_, _ = axonflowClient.AuditLLMCall(
				policyResult.ContextID,
				summary,
				"ollama",
				req.Model,
				tokenUsage,
				latencyMs,
				nil,
			)
		}

		return resp, nil
	}
}

// WrapOllamaGenerateFunc wraps an Ollama generate function for governance.
func WrapOllamaGenerateFunc(fn OllamaGenerateFunc, axonflowClient *axonflow.AxonFlowClient, userToken string) OllamaGenerateFunc {
	return func(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error) {
		preCheckCtx := map[string]interface{}{
			"provider": "ollama",
			"model":    req.Model,
		}

		policyResult, err := axonflowClient.GetPolicyApprovedContext(userToken, req.Prompt, nil, preCheckCtx)
		if err != nil {
			return nil, err
		}

		if !policyResult.Approved {
			return nil, &PolicyViolationError{
				BlockReason: policyResult.BlockReason,
				Policies:    policyResult.Policies,
			}
		}

		startTime := time.Now()
		resp, err := fn(ctx, req)
		latencyMs := time.Since(startTime).Milliseconds()

		if err != nil {
			return nil, err
		}

		if policyResult.ContextID != "" {
			summary := ""
			if resp != nil {
				summary = truncateString(resp.Response, 200)
			}

			tokenUsage := axonflow.TokenUsage{
				PromptTokens:     resp.PromptEvalCount,
				CompletionTokens: resp.EvalCount,
				TotalTokens:      resp.PromptEvalCount + resp.EvalCount,
			}

			_, _ = axonflowClient.AuditLLMCall(
				policyResult.ContextID,
				summary,
				"ollama",
				req.Model,
				tokenUsage,
				latencyMs,
				nil,
			)
		}

		return resp, nil
	}
}

// extractOllamaPrompt extracts text content from Ollama messages
func extractOllamaPrompt(messages []OllamaMessage) string {
	var texts []string
	for _, msg := range messages {
		texts = append(texts, msg.Content)
	}
	return strings.Join(texts, " ")
}
