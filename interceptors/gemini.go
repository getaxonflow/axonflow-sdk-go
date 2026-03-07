// Package interceptors provides transparent LLM governance wrappers for popular AI clients.
//
// Gemini interceptor wraps Google's Generative AI SDK for automatic governance.
//
// Example using google/generative-ai-go:
//
//	import (
//		"github.com/google/generative-ai-go/genai"
//		"github.com/getaxonflow/axonflow-sdk-go/v4"
//		"github.com/getaxonflow/axonflow-sdk-go/v4/interceptors"
//	)
//
//	client, _ := genai.NewClient(ctx, option.WithAPIKey(apiKey))
//	model := client.GenerativeModel("gemini-pro")
//	axonflow := axonflow.NewClient(axonflow.AxonFlowConfig{...})
//
//	// Wrap the model - governance is now automatic
//	wrapped := interceptors.WrapGeminiModel(model, axonflow, "user-token")
//
//	// Use as normal
//	resp, err := wrapped.GenerateContent(ctx, genai.Text("What is AI governance?"))
package interceptors

import (
	"context"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v4"
)

// GeminiPart represents a part of Gemini content
type GeminiPart interface {
	isGeminiPart()
}

// GeminiText represents text content
type GeminiText string

func (GeminiText) isGeminiPart() {}

// GeminiBlob represents binary data (images, etc.)
type GeminiBlob struct {
	MIMEType string
	Data     []byte
}

func (GeminiBlob) isGeminiPart() {}

// GeminiContent represents a message in the conversation
type GeminiContent struct {
	Parts []GeminiPart
	Role  string
}

// GeminiGenerationConfig contains generation parameters
type GeminiGenerationConfig struct {
	Temperature     float32
	TopP            float32
	TopK            int32
	MaxOutputTokens int32
	StopSequences   []string
}

// GeminiCandidate represents a generated response candidate
type GeminiCandidate struct {
	Content      *GeminiContent
	FinishReason string
}

// GeminiUsageMetadata contains token usage information
type GeminiUsageMetadata struct {
	PromptTokenCount     int32
	CandidatesTokenCount int32
	TotalTokenCount      int32
}

// GeminiGenerateContentResponse represents the response from GenerateContent
type GeminiGenerateContentResponse struct {
	Candidates    []*GeminiCandidate
	UsageMetadata *GeminiUsageMetadata
}

// GetText returns the text content from the first candidate
func (r *GeminiGenerateContentResponse) GetText() string {
	if len(r.Candidates) == 0 || r.Candidates[0].Content == nil {
		return ""
	}
	var texts []string
	for _, part := range r.Candidates[0].Content.Parts {
		if text, ok := part.(GeminiText); ok {
			texts = append(texts, string(text))
		}
	}
	return strings.Join(texts, "")
}

// GeminiContentGenerator is the interface for Gemini content generation
type GeminiContentGenerator interface {
	GenerateContent(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error)
}

// GeminiGenerateFunc is the function signature for generating content
type GeminiGenerateFunc func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error)

// WrappedGeminiModel wraps a Gemini model with AxonFlow governance
type WrappedGeminiModel struct {
	model     GeminiContentGenerator
	axonflow  *axonflow.AxonFlowClient
	userToken string
	modelName string
}

// WrapGeminiModel wraps a Gemini GenerativeModel with AxonFlow governance.
//
// This allows automatic policy checking and audit logging for all
// GenerateContent calls without changing application code.
//
// Example:
//
//	client, _ := genai.NewClient(ctx, option.WithAPIKey(apiKey))
//	model := client.GenerativeModel("gemini-pro")
//	wrapped := interceptors.WrapGeminiModel(model, axonflowClient, "user-123")
//	resp, err := wrapped.GenerateContent(ctx, genai.Text("Hello"))
func WrapGeminiModel(model GeminiContentGenerator, axonflow *axonflow.AxonFlowClient, userToken string) *WrappedGeminiModel {
	return &WrappedGeminiModel{
		model:     model,
		axonflow:  axonflow,
		userToken: userToken,
		modelName: "gemini-pro", // Default, can be extracted from model if needed
	}
}

// WrapGeminiModelWithName wraps a Gemini model with a specific model name
func WrapGeminiModelWithName(model GeminiContentGenerator, axonflow *axonflow.AxonFlowClient, userToken, modelName string) *WrappedGeminiModel {
	return &WrappedGeminiModel{
		model:     model,
		axonflow:  axonflow,
		userToken: userToken,
		modelName: modelName,
	}
}

// GenerateContent generates content with automatic governance
func (w *WrappedGeminiModel) GenerateContent(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
	// Extract prompt from parts
	prompt := extractGeminiPrompt(parts)

	// Pre-check with AxonFlow
	preCheckCtx := map[string]interface{}{
		"provider": "gemini",
		"model":    w.modelName,
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

	// Execute the actual LLM call
	startTime := time.Now()
	resp, err := w.model.GenerateContent(ctx, parts...)
	latencyMs := time.Since(startTime).Milliseconds()

	if err != nil {
		return nil, err
	}

	// Audit the call
	if policyResult.ContextID != "" {
		summary := ""
		if resp != nil {
			summary = truncateString(resp.GetText(), 200)
		}

		tokenUsage := axonflow.TokenUsage{}
		if resp.UsageMetadata != nil {
			tokenUsage = axonflow.TokenUsage{
				PromptTokens:     int(resp.UsageMetadata.PromptTokenCount),
				CompletionTokens: int(resp.UsageMetadata.CandidatesTokenCount),
				TotalTokens:      int(resp.UsageMetadata.TotalTokenCount),
			}
		}

		_, auditErr := w.axonflow.AuditLLMCall(
			policyResult.ContextID,
			summary,
			"gemini",
			w.modelName,
			tokenUsage,
			latencyMs,
			nil,
		)
		if auditErr != nil {
			// Log but don't fail the request
			// In production, you might want to use a proper logger
		}
	}

	return resp, nil
}

// WrapGeminiFunc wraps a Gemini generate function for governance
//
// This is useful when you don't want to wrap the entire model but just
// specific function calls.
//
// Example:
//
//	wrapped := interceptors.WrapGeminiFunc(
//		func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
//			return model.GenerateContent(ctx, parts...)
//		},
//		axonflow,
//		"user-123",
//		"gemini-pro",
//	)
func WrapGeminiFunc(fn GeminiGenerateFunc, axonflowClient *axonflow.AxonFlowClient, userToken, modelName string) GeminiGenerateFunc {
	return func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
		prompt := extractGeminiPrompt(parts)

		preCheckCtx := map[string]interface{}{
			"provider": "gemini",
			"model":    modelName,
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
		resp, err := fn(ctx, parts...)
		latencyMs := time.Since(startTime).Milliseconds()

		if err != nil {
			return nil, err
		}

		if policyResult.ContextID != "" {
			summary := ""
			if resp != nil {
				summary = truncateString(resp.GetText(), 200)
			}

			tokenUsage := axonflow.TokenUsage{}
			if resp.UsageMetadata != nil {
				tokenUsage = axonflow.TokenUsage{
					PromptTokens:     int(resp.UsageMetadata.PromptTokenCount),
					CompletionTokens: int(resp.UsageMetadata.CandidatesTokenCount),
					TotalTokens:      int(resp.UsageMetadata.TotalTokenCount),
				}
			}

			_, _ = axonflowClient.AuditLLMCall(
				policyResult.ContextID,
				summary,
				"gemini",
				modelName,
				tokenUsage,
				latencyMs,
				nil,
			)
		}

		return resp, nil
	}
}

// extractGeminiPrompt extracts text content from Gemini parts
func extractGeminiPrompt(parts []GeminiPart) string {
	var texts []string
	for _, part := range parts {
		if text, ok := part.(GeminiText); ok {
			texts = append(texts, string(text))
		}
	}
	return strings.Join(texts, " ")
}
