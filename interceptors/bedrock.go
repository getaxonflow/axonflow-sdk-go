// Package interceptors provides transparent LLM governance wrappers for popular AI clients.
//
// Bedrock interceptor wraps AWS Bedrock Runtime for automatic governance.
// Bedrock uses AWS IAM authentication (no API keys required).
//
// Example:
//
//	import (
//		"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
//		"github.com/getaxonflow/axonflow-sdk-go/v4"
//		"github.com/getaxonflow/axonflow-sdk-go/v4/interceptors"
//	)
//
//	client := bedrockruntime.NewFromConfig(cfg)
//	axonflow := axonflow.NewClient(axonflow.AxonFlowConfig{...})
//
//	// Wrap InvokeModel calls
//	wrapped := interceptors.WrapBedrockInvokeModel(
//		client.InvokeModel,
//		axonflow,
//		"user-token",
//	)
package interceptors

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v4"
)

// BedrockModels contains common Bedrock model IDs
var BedrockModels = struct {
	// Anthropic Claude models
	Claude3Opus   string
	Claude3Sonnet string
	Claude3Haiku  string
	Claude2       string
	ClaudeInstant string
	// Amazon Titan models
	TitanTextExpress string
	TitanTextLite    string
	// Meta Llama models
	Llama2_70B string
	Llama3_70B string
}{
	Claude3Opus:      "anthropic.claude-3-opus-20240229-v1:0",
	Claude3Sonnet:    "anthropic.claude-3-sonnet-20240229-v1:0",
	Claude3Haiku:     "anthropic.claude-3-haiku-20240307-v1:0",
	Claude2:          "anthropic.claude-v2:1",
	ClaudeInstant:    "anthropic.claude-instant-v1",
	TitanTextExpress: "amazon.titan-text-express-v1",
	TitanTextLite:    "amazon.titan-text-lite-v1",
	Llama2_70B:       "meta.llama2-70b-chat-v1",
	Llama3_70B:       "meta.llama3-70b-instruct-v1:0",
}

// BedrockClaudeMessage represents a message in Claude format
type BedrockClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// BedrockClaudeRequest represents a request body for Claude on Bedrock
type BedrockClaudeRequest struct {
	AnthropicVersion string                 `json:"anthropic_version"`
	MaxTokens        int                    `json:"max_tokens"`
	Messages         []BedrockClaudeMessage `json:"messages"`
	Temperature      float32                `json:"temperature,omitempty"`
	TopP             float32                `json:"top_p,omitempty"`
	TopK             int                    `json:"top_k,omitempty"`
	StopSequences    []string               `json:"stop_sequences,omitempty"`
	System           string                 `json:"system,omitempty"`
}

// BedrockClaudeResponse represents a response from Claude on Bedrock
type BedrockClaudeResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// BedrockTitanRequest represents a request body for Titan
type BedrockTitanRequest struct {
	InputText            string `json:"inputText"`
	TextGenerationConfig *struct {
		MaxTokenCount int      `json:"maxTokenCount,omitempty"`
		Temperature   float32  `json:"temperature,omitempty"`
		TopP          float32  `json:"topP,omitempty"`
		StopSequences []string `json:"stopSequences,omitempty"`
	} `json:"textGenerationConfig,omitempty"`
}

// BedrockTitanResponse represents a response from Titan
type BedrockTitanResponse struct {
	InputTextTokenCount int `json:"inputTextTokenCount"`
	Results             []struct {
		TokenCount       int    `json:"tokenCount"`
		OutputText       string `json:"outputText"`
		CompletionReason string `json:"completionReason"`
	} `json:"results"`
}

// BedrockInvokeInput represents the input for InvokeModel
type BedrockInvokeInput struct {
	ModelId     string
	Body        []byte
	ContentType string
	Accept      string
}

// BedrockInvokeOutput represents the output from InvokeModel
type BedrockInvokeOutput struct {
	Body        []byte
	ContentType string
}

// BedrockInvokeFunc is the function signature for InvokeModel
type BedrockInvokeFunc func(ctx context.Context, input *BedrockInvokeInput) (*BedrockInvokeOutput, error)

// WrapBedrockInvokeModel wraps a Bedrock InvokeModel function with governance.
//
// Example:
//
//	wrapped := interceptors.WrapBedrockInvokeModel(
//		func(ctx context.Context, input *BedrockInvokeInput) (*BedrockInvokeOutput, error) {
//			return client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
//				ModelId:     aws.String(input.ModelId),
//				Body:        input.Body,
//				ContentType: aws.String(input.ContentType),
//				Accept:      aws.String(input.Accept),
//			})
//		},
//		axonflow,
//		"user-123",
//	)
func WrapBedrockInvokeModel(fn BedrockInvokeFunc, axonflowClient *axonflow.AxonFlowClient, userToken string) BedrockInvokeFunc {
	return func(ctx context.Context, input *BedrockInvokeInput) (*BedrockInvokeOutput, error) {
		// Extract prompt from body
		prompt := extractBedrockPrompt(input.Body, input.ModelId)

		preCheckCtx := map[string]interface{}{
			"provider": "bedrock",
			"model":    input.ModelId,
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
		output, err := fn(ctx, input)
		latencyMs := time.Since(startTime).Milliseconds()

		if err != nil {
			return nil, err
		}

		// Audit the call
		if policyResult.ContextID != "" && output != nil {
			summary, promptTokens, completionTokens := extractBedrockResponseInfo(output.Body, input.ModelId)

			tokenUsage := axonflow.TokenUsage{
				PromptTokens:     promptTokens,
				CompletionTokens: completionTokens,
				TotalTokens:      promptTokens + completionTokens,
			}

			_, _ = axonflowClient.AuditLLMCall(
				policyResult.ContextID,
				summary,
				"bedrock",
				input.ModelId,
				tokenUsage,
				latencyMs,
				nil,
			)
		}

		return output, nil
	}
}

// extractBedrockPrompt extracts the prompt from a Bedrock request body
func extractBedrockPrompt(body []byte, modelId string) string {
	if strings.Contains(modelId, "anthropic.claude") {
		var req BedrockClaudeRequest
		if err := json.Unmarshal(body, &req); err == nil {
			var texts []string
			for _, msg := range req.Messages {
				texts = append(texts, msg.Content)
			}
			return strings.Join(texts, " ")
		}
	} else if strings.Contains(modelId, "amazon.titan") {
		var req BedrockTitanRequest
		if err := json.Unmarshal(body, &req); err == nil {
			return req.InputText
		}
	}

	// Fallback: try generic prompt field
	var generic map[string]interface{}
	if err := json.Unmarshal(body, &generic); err == nil {
		if prompt, ok := generic["prompt"].(string); ok {
			return prompt
		}
	}

	return ""
}

// extractBedrockResponseInfo extracts summary and token counts from response
func extractBedrockResponseInfo(body []byte, modelId string) (summary string, promptTokens, completionTokens int) {
	if strings.Contains(modelId, "anthropic.claude") {
		var resp BedrockClaudeResponse
		if err := json.Unmarshal(body, &resp); err == nil {
			if len(resp.Content) > 0 {
				summary = truncateString(resp.Content[0].Text, 200)
			}
			promptTokens = resp.Usage.InputTokens
			completionTokens = resp.Usage.OutputTokens
			return
		}
	} else if strings.Contains(modelId, "amazon.titan") {
		var resp BedrockTitanResponse
		if err := json.Unmarshal(body, &resp); err == nil {
			if len(resp.Results) > 0 {
				summary = truncateString(resp.Results[0].OutputText, 200)
				completionTokens = resp.Results[0].TokenCount
			}
			promptTokens = resp.InputTextTokenCount
			return
		}
	}

	return "", 0, 0
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
