package interceptors

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

// createMockAxonFlowServer creates a test server that mimics AxonFlow responses
func createMockAxonFlowServer(t *testing.T, response map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
}

// createBlockedServer creates a server that returns blocked response
func createBlockedServer(t *testing.T) *httptest.Server {
	return createMockAxonFlowServer(t, map[string]interface{}{
		"success":      false,
		"blocked":      true,
		"block_reason": "Policy violation: PII detected",
	})
}

// createApprovedServer creates a server that returns approved response
func createApprovedServer(t *testing.T) *httptest.Server {
	return createMockAxonFlowServer(t, map[string]interface{}{
		"success":    true,
		"blocked":    false,
		"request_id": "req-123",
	})
}

// createGatewayModeServer creates a server that handles both ProxyLLMCall and Gateway Mode endpoints
func createGatewayModeServer(t *testing.T, approved bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle different endpoints
		if r.URL.Path == "/api/policy/pre-check" {
			// Gateway Mode pre-check endpoint
			if approved {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"approved":   true,
					"context_id": "ctx-123",
					"policies":   []string{"policy-1"},
					"expires_at": "2025-12-31T23:59:59Z",
				})
			} else {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"approved":     false,
					"block_reason": "Policy violation: PII detected",
					"policies":     []string{"pii-detection"},
				})
			}
		} else if r.URL.Path == "/api/audit" {
			// Audit endpoint
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"audit_id": "audit-456",
			})
		} else {
			// Default response for other endpoints (ProxyLLMCall)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    approved,
				"blocked":    !approved,
				"request_id": "req-123",
			})
		}
	}))
}

// ===== OpenAI Interceptor Tests =====

func TestWrapOpenAIClient_Success(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOpenAIClient{
		CreateChatCompletionFn: func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
			return ChatCompletionResponse{
				ID:    "chatcmpl-123",
				Model: req.Model,
				Choices: []ChatCompletionChoice{
					{
						Index:        0,
						Message:      ChatMessage{Role: "assistant", Content: "Hello! How can I help?"},
						FinishReason: "stop",
					},
				},
				Usage: Usage{
					PromptTokens:     10,
					CompletionTokens: 8,
					TotalTokens:      18,
				},
			}, nil
		},
	}

	wrapped := WrapOpenAIClient(mockClient, axonflowClient, "user-token")

	resp, err := wrapped.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []ChatMessage{
			{Role: "user", Content: "Hello"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "chatcmpl-123" {
		t.Errorf("unexpected response ID: %s", resp.ID)
	}
	if len(resp.Choices) == 0 {
		t.Error("expected choices in response")
	}
}

func TestWrapOpenAIClient_Blocked(t *testing.T) {
	server := createBlockedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox", // Disable fail-open
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOpenAIClient{}
	wrapped := WrapOpenAIClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Tell me SSN"}},
	})

	if err == nil {
		t.Error("expected policy violation error")
	}

	if !IsPolicyViolationError(err) {
		t.Errorf("expected PolicyViolationError, got %T: %v", err, err)
	}
}

func TestWrapOpenAIClient_LLMError(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOpenAIClient{
		CreateChatCompletionFn: func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
			return ChatCompletionResponse{}, errors.New("OpenAI API error: rate limit exceeded")
		},
	}

	wrapped := WrapOpenAIClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
	if IsPolicyViolationError(err) {
		t.Error("should not be a policy violation error")
	}
}

func TestWrapOpenAIFunc_Success(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	called := false
	fn := func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
		called = true
		return ChatCompletionResponse{
			ID: "func-response",
			Choices: []ChatCompletionChoice{
				{Message: ChatMessage{Content: "Response from func"}},
			},
		}, nil
	}

	wrapped := WrapOpenAIFunc(fn, axonflowClient, "user-token")

	resp, err := wrapped(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("wrapped function was not called")
	}
	if resp.ID != "func-response" {
		t.Errorf("unexpected response ID: %s", resp.ID)
	}
}

func TestWrapOpenAIFunc_Blocked(t *testing.T) {
	server := createBlockedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	called := false
	fn := func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
		called = true
		return ChatCompletionResponse{}, nil
	}

	wrapped := WrapOpenAIFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if called {
		t.Error("wrapped function should not be called when blocked")
	}
}

// ===== Anthropic Interceptor Tests =====

func TestWrapAnthropicClient_Success(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockAnthropicClient{
		CreateMessageFn: func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
			return AnthropicMessageResponse{
				ID:    "msg-123",
				Type:  "message",
				Role:  "assistant",
				Model: req.Model,
				Content: []AnthropicContentBlock{
					{Type: "text", Text: "Hello from Claude!"},
				},
				StopReason: "end_turn",
				Usage: AnthropicUsage{
					InputTokens:  15,
					OutputTokens: 10,
				},
			}, nil
		},
	}

	wrapped := WrapAnthropicClient(mockClient, axonflowClient, "user-token")

	resp, err := wrapped.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Hello")},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "msg-123" {
		t.Errorf("unexpected response ID: %s", resp.ID)
	}
}

func TestWrapAnthropicClient_Blocked(t *testing.T) {
	server := createBlockedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockAnthropicClient{}
	wrapped := WrapAnthropicClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Sensitive request")},
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if !IsPolicyViolationError(err) {
		t.Errorf("expected PolicyViolationError, got %T", err)
	}
}

func TestWrapAnthropicClient_WithSystemPrompt(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockAnthropicClient{
		CreateMessageFn: func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
			// Verify system prompt was passed
			if req.System == "" {
				t.Error("expected system prompt to be passed")
			}
			return AnthropicMessageResponse{
				ID:      "msg-sys",
				Content: []AnthropicContentBlock{{Type: "text", Text: "Response"}},
			}, nil
		},
	}

	wrapped := WrapAnthropicClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		System:    "You are a helpful assistant",
		Messages:  []AnthropicMessage{CreateUserMessage("Hello")},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWrapAnthropicFunc_Success(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
		return AnthropicMessageResponse{
			ID:      "func-msg",
			Content: []AnthropicContentBlock{{Type: "text", Text: "OK"}},
		}, nil
	}

	wrapped := WrapAnthropicFunc(fn, axonflowClient, "user-token")

	resp, err := wrapped(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "func-msg" {
		t.Errorf("unexpected ID: %s", resp.ID)
	}
}

func TestWrapAnthropicFunc_Blocked(t *testing.T) {
	server := createBlockedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	called := false
	fn := func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
		called = true
		return AnthropicMessageResponse{}, nil
	}

	wrapped := WrapAnthropicFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if called {
		t.Error("function should not be called when blocked")
	}
}

// ===== Bridge Tests =====

func TestGoOpenAIBridge_WithCreateFn(t *testing.T) {
	called := false
	bridge := &GoOpenAIBridge{
		CreateFn: func(ctx context.Context, model string, messages []ChatMessage, opts map[string]interface{}) (ChatCompletionResponse, error) {
			called = true
			if model != "gpt-4" {
				t.Errorf("unexpected model: %s", model)
			}
			return ChatCompletionResponse{
				ID: "bridge-response",
				Choices: []ChatCompletionChoice{
					{Message: ChatMessage{Content: "Bridge response"}},
				},
			}, nil
		},
	}

	resp, err := bridge.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model:       "gpt-4",
		Messages:    []ChatMessage{{Role: "user", Content: "Test"}},
		Temperature: 0.7,
		MaxTokens:   100,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("CreateFn was not called")
	}
	if resp.ID != "bridge-response" {
		t.Errorf("unexpected ID: %s", resp.ID)
	}
}

func TestAnthropicBridge_WithCreateFn(t *testing.T) {
	called := false
	bridge := &AnthropicBridge{
		CreateFn: func(ctx context.Context, model string, maxTokens int, messages []AnthropicMessage, system string, opts map[string]interface{}) (AnthropicMessageResponse, error) {
			called = true
			if model != "claude-3-sonnet-20240229" {
				t.Errorf("unexpected model: %s", model)
			}
			if system != "Be helpful" {
				t.Errorf("unexpected system: %s", system)
			}
			return AnthropicMessageResponse{
				ID:      "bridge-msg",
				Content: []AnthropicContentBlock{{Type: "text", Text: "OK"}},
			}, nil
		},
	}

	resp, err := bridge.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		System:    "Be helpful",
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("CreateFn was not called")
	}
	if resp.ID != "bridge-msg" {
		t.Errorf("unexpected ID: %s", resp.ID)
	}
}

// ===== Utility Tests =====

func TestUnmarshalResponse(t *testing.T) {
	jsonData := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"created": 1234567890,
		"model": "gpt-4",
		"choices": [{
			"index": 0,
			"message": {"role": "assistant", "content": "Hello!"},
			"finish_reason": "stop"
		}],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 5,
			"total_tokens": 15
		}
	}`

	resp, err := UnmarshalResponse([]byte(jsonData))
	if err != nil {
		t.Fatalf("UnmarshalResponse failed: %v", err)
	}

	if resp.ID != "chatcmpl-123" {
		t.Errorf("unexpected ID: %s", resp.ID)
	}
	if resp.Model != "gpt-4" {
		t.Errorf("unexpected model: %s", resp.Model)
	}
	if len(resp.Choices) != 1 {
		t.Errorf("unexpected choices count: %d", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content != "Hello!" {
		t.Errorf("unexpected content: %s", resp.Choices[0].Message.Content)
	}
	if resp.Usage.TotalTokens != 15 {
		t.Errorf("unexpected total tokens: %d", resp.Usage.TotalTokens)
	}
}

func TestUnmarshalResponse_InvalidJSON(t *testing.T) {
	_, err := UnmarshalResponse([]byte("invalid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ===== Gemini Tests =====

// MockGeminiModel implements GeminiContentGenerator
type MockGeminiModel struct {
	GenerateContentFn func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error)
}

func (m *MockGeminiModel) GenerateContent(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
	if m.GenerateContentFn != nil {
		return m.GenerateContentFn(ctx, parts...)
	}
	return &GeminiGenerateContentResponse{
		Candidates: []*GeminiCandidate{
			{
				Content: &GeminiContent{
					Parts: []GeminiPart{GeminiText("Default response")},
					Role:  "model",
				},
				FinishReason: "STOP",
			},
		},
		UsageMetadata: &GeminiUsageMetadata{
			PromptTokenCount:     10,
			CandidatesTokenCount: 5,
			TotalTokenCount:      15,
		},
	}, nil
}

func TestWrapGeminiModel_Success(t *testing.T) {
	server := createGatewayModeServer(t, true) // Use gateway mode server with approved response
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockModel := &MockGeminiModel{
		GenerateContentFn: func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
			return &GeminiGenerateContentResponse{
				Candidates: []*GeminiCandidate{
					{
						Content: &GeminiContent{
							Parts: []GeminiPart{GeminiText("Gemini response")},
							Role:  "model",
						},
						FinishReason: "STOP",
					},
				},
				UsageMetadata: &GeminiUsageMetadata{
					PromptTokenCount:     5,
					CandidatesTokenCount: 3,
					TotalTokenCount:      8,
				},
			}, nil
		},
	}

	wrapped := WrapGeminiModel(mockModel, axonflowClient, "user-token")

	resp, err := wrapped.GenerateContent(context.Background(), GeminiText("Hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := resp.GetText()
	if text != "Gemini response" {
		t.Errorf("unexpected response text: %s", text)
	}
}

func TestWrapGeminiModelWithName(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockModel := &MockGeminiModel{}
	wrapped := WrapGeminiModelWithName(mockModel, axonflowClient, "user-token", "gemini-1.5-pro")

	if wrapped.modelName != "gemini-1.5-pro" {
		t.Errorf("unexpected model name: %s", wrapped.modelName)
	}
}

func TestWrapGeminiModel_Blocked(t *testing.T) {
	server := createGatewayModeServer(t, false) // Use gateway mode with blocked response
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Mode:         "sandbox",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockModel := &MockGeminiModel{}
	wrapped := WrapGeminiModel(mockModel, axonflowClient, "user-token")

	_, err := wrapped.GenerateContent(context.Background(), GeminiText("Sensitive query"))
	if err == nil {
		t.Error("expected policy violation error")
	}
	if !IsPolicyViolationError(err) {
		t.Errorf("expected PolicyViolationError, got %T", err)
	}
}

func TestGeminiText_Part(t *testing.T) {
	text := GeminiText("Hello")
	text.isGeminiPart() // Should compile - verifies interface implementation
}

func TestGeminiBlob_Part(t *testing.T) {
	blob := GeminiBlob{MIMEType: "image/png", Data: []byte{1, 2, 3}}
	blob.isGeminiPart() // Should compile - verifies interface implementation
}

func TestGeminiResponse_GetText(t *testing.T) {
	tests := []struct {
		name     string
		resp     *GeminiGenerateContentResponse
		expected string
	}{
		{
			name:     "no candidates",
			resp:     &GeminiGenerateContentResponse{},
			expected: "",
		},
		{
			name: "nil content",
			resp: &GeminiGenerateContentResponse{
				Candidates: []*GeminiCandidate{{}},
			},
			expected: "",
		},
		{
			name: "text content",
			resp: &GeminiGenerateContentResponse{
				Candidates: []*GeminiCandidate{
					{
						Content: &GeminiContent{
							Parts: []GeminiPart{GeminiText("Hello"), GeminiText(" World")},
						},
					},
				},
			},
			expected: "Hello World",
		},
		{
			name: "mixed content",
			resp: &GeminiGenerateContentResponse{
				Candidates: []*GeminiCandidate{
					{
						Content: &GeminiContent{
							Parts: []GeminiPart{
								GeminiBlob{MIMEType: "image/png", Data: []byte{}},
								GeminiText("Description"),
							},
						},
					},
				},
			},
			expected: "Description",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resp.GetText()
			if result != tt.expected {
				t.Errorf("GetText() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// ===== Additional OpenAI Tests for Coverage =====

func TestWrapOpenAIClient_LongResponse(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	// Create a response longer than 100 chars to test truncation logic
	longContent := "This is a very long response that exceeds one hundred characters and will be truncated when creating the audit summary for logging purposes."

	mockClient := &MockOpenAIClient{
		CreateChatCompletionFn: func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
			return ChatCompletionResponse{
				ID: "long-response",
				Choices: []ChatCompletionChoice{
					{Message: ChatMessage{Content: longContent}},
				},
				Usage: Usage{TotalTokens: 50},
			}, nil
		},
	}

	wrapped := WrapOpenAIClient(mockClient, axonflowClient, "user-token")

	resp, err := wrapped.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Choices[0].Message.Content != longContent {
		t.Error("response content should not be truncated")
	}
}

func TestWrapOpenAIClient_EmptyChoices(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOpenAIClient{
		CreateChatCompletionFn: func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
			return ChatCompletionResponse{
				ID:      "empty-choices",
				Choices: []ChatCompletionChoice{}, // Empty choices
			}, nil
		},
	}

	wrapped := WrapOpenAIClient(mockClient, axonflowClient, "user-token")

	resp, err := wrapped.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Choices) != 0 {
		t.Error("expected empty choices")
	}
}

// ===== Anthropic LLM Error Test =====

func TestWrapAnthropicClient_LLMError(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockAnthropicClient{
		CreateMessageFn: func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
			return AnthropicMessageResponse{}, errors.New("Anthropic API error")
		},
	}

	wrapped := WrapAnthropicClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
}

// ===== AxonFlow Error Tests =====

func TestWrapOpenAIClient_AxonFlowError(t *testing.T) {
	// Server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox", // Disable fail-open
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOpenAIClient{}
	wrapped := WrapOpenAIClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected error from AxonFlow")
	}
}

func TestWrapAnthropicClient_AxonFlowError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockAnthropicClient{}
	wrapped := WrapAnthropicClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err == nil {
		t.Error("expected error from AxonFlow")
	}
}

// ===== OpenAI Func Error Tests =====

func TestWrapOpenAIFunc_AxonFlowError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
		return ChatCompletionResponse{}, nil
	}

	wrapped := WrapOpenAIFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected error from AxonFlow")
	}
}

func TestWrapOpenAIFunc_LLMError(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
		return ChatCompletionResponse{}, errors.New("LLM error")
	}

	wrapped := WrapOpenAIFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
}

// ===== Anthropic Func Error Tests =====

func TestWrapAnthropicFunc_AxonFlowError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
		return AnthropicMessageResponse{}, nil
	}

	wrapped := WrapAnthropicFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err == nil {
		t.Error("expected error from AxonFlow")
	}
}

func TestWrapAnthropicFunc_LLMError(t *testing.T) {
	server := createApprovedServer(t)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
		return AnthropicMessageResponse{}, errors.New("LLM error")
	}

	wrapped := WrapAnthropicFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages:  []AnthropicMessage{CreateUserMessage("Test")},
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
}

func TestWrapGeminiModel_LLMError(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockModel := &MockGeminiModel{
		GenerateContentFn: func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
			return nil, errors.New("Gemini API error")
		},
	}

	wrapped := WrapGeminiModel(mockModel, axonflowClient, "user-token")

	_, err := wrapped.GenerateContent(context.Background(), GeminiText("Test"))
	if err == nil {
		t.Error("expected error from LLM")
	}
}

func TestWrapGeminiModel_AxonFlowError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Mode:         "sandbox",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockModel := &MockGeminiModel{}
	wrapped := WrapGeminiModel(mockModel, axonflowClient, "user-token")

	_, err := wrapped.GenerateContent(context.Background(), GeminiText("Test"))
	if err == nil {
		t.Error("expected error from AxonFlow")
	}
}

func TestWrapGeminiModel_NilUsageMetadata(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockModel := &MockGeminiModel{
		GenerateContentFn: func(ctx context.Context, parts ...GeminiPart) (*GeminiGenerateContentResponse, error) {
			return &GeminiGenerateContentResponse{
				Candidates: []*GeminiCandidate{
					{
						Content: &GeminiContent{
							Parts: []GeminiPart{GeminiText("Response without metadata")},
						},
					},
				},
				UsageMetadata: nil, // No usage metadata
			}, nil
		},
	}

	wrapped := WrapGeminiModel(mockModel, axonflowClient, "user-token")

	resp, err := wrapped.GenerateContent(context.Background(), GeminiText("Test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetText() != "Response without metadata" {
		t.Errorf("unexpected text: %s", resp.GetText())
	}
}

// ===== Ollama Interceptor Tests =====

// MockOllamaChatClient implements OllamaChatClient
type MockOllamaChatClient struct {
	ChatFn func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error)
}

func (m *MockOllamaChatClient) Chat(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
	if m.ChatFn != nil {
		return m.ChatFn(ctx, req)
	}
	return &OllamaChatResponse{
		Model: req.Model,
		Message: OllamaMessage{
			Role:    "assistant",
			Content: "Ollama response",
		},
		Done:            true,
		PromptEvalCount: 10,
		EvalCount:       8,
	}, nil
}

// MockOllamaGenerateClient implements OllamaGenerateClient
type MockOllamaGenerateClient struct {
	GenerateFn func(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error)
}

func (m *MockOllamaGenerateClient) Generate(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error) {
	if m.GenerateFn != nil {
		return m.GenerateFn(ctx, req)
	}
	return &OllamaGenerateResponse{
		Model:           req.Model,
		Response:        "Generated text",
		Done:            true,
		PromptEvalCount: 5,
		EvalCount:       10,
	}, nil
}

func TestWrapOllamaChatClient_Success(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOllamaChatClient{
		ChatFn: func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
			return &OllamaChatResponse{
				Model:   req.Model,
				Message: OllamaMessage{Role: "assistant", Content: "Hello from Ollama!"},
				Done:    true,
			}, nil
		},
	}

	wrapped := WrapOllamaChatClient(mockClient, axonflowClient, "user-token")

	resp, err := wrapped.Chat(context.Background(), &OllamaChatRequest{
		Model: "llama3",
		Messages: []OllamaMessage{
			{Role: "user", Content: "Hello"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Message.Content != "Hello from Ollama!" {
		t.Errorf("unexpected response: %s", resp.Message.Content)
	}
}

func TestWrapOllamaChatClient_Blocked(t *testing.T) {
	server := createGatewayModeServer(t, false)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Mode:         "sandbox",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOllamaChatClient{}
	wrapped := WrapOllamaChatClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.Chat(context.Background(), &OllamaChatRequest{
		Model:    "llama3",
		Messages: []OllamaMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if !IsPolicyViolationError(err) {
		t.Errorf("expected PolicyViolationError, got %T", err)
	}
}

func TestWrapOllamaChatClient_LLMError(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	mockClient := &MockOllamaChatClient{
		ChatFn: func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
			return nil, errors.New("Ollama API error")
		},
	}

	wrapped := WrapOllamaChatClient(mockClient, axonflowClient, "user-token")

	_, err := wrapped.Chat(context.Background(), &OllamaChatRequest{
		Model:    "llama3",
		Messages: []OllamaMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
}

func TestWrapOllamaChatFunc_Success(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
		return &OllamaChatResponse{
			Model:   req.Model,
			Message: OllamaMessage{Content: "Wrapped func response"},
			Done:    true,
		}, nil
	}

	wrapped := WrapOllamaChatFunc(fn, axonflowClient, "user-token")

	resp, err := wrapped(context.Background(), &OllamaChatRequest{
		Model:    "llama3",
		Messages: []OllamaMessage{{Role: "user", Content: "Test"}},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Message.Content != "Wrapped func response" {
		t.Errorf("unexpected response: %s", resp.Message.Content)
	}
}

func TestWrapOllamaChatFunc_Blocked(t *testing.T) {
	server := createGatewayModeServer(t, false)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Mode:         "sandbox",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	called := false
	fn := func(ctx context.Context, req *OllamaChatRequest) (*OllamaChatResponse, error) {
		called = true
		return nil, nil
	}

	wrapped := WrapOllamaChatFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), &OllamaChatRequest{
		Model:    "llama3",
		Messages: []OllamaMessage{{Role: "user", Content: "Test"}},
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if called {
		t.Error("function should not be called when blocked")
	}
}

func TestWrapOllamaGenerateFunc_Blocked(t *testing.T) {
	server := createGatewayModeServer(t, false)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Mode:         "sandbox",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	called := false
	fn := func(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error) {
		called = true
		return nil, nil
	}

	wrapped := WrapOllamaGenerateFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), &OllamaGenerateRequest{
		Model:  "llama3",
		Prompt: "Test",
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if called {
		t.Error("function should not be called when blocked")
	}
}

func TestWrapOllamaGenerateFunc_LLMError(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error) {
		return nil, errors.New("Generate error")
	}

	wrapped := WrapOllamaGenerateFunc(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), &OllamaGenerateRequest{
		Model:  "llama3",
		Prompt: "Test",
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
}

func TestWrapOllamaGenerateFunc_Success(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, req *OllamaGenerateRequest) (*OllamaGenerateResponse, error) {
		return &OllamaGenerateResponse{
			Model:    req.Model,
			Response: "Func response",
			Done:     true,
		}, nil
	}

	wrapped := WrapOllamaGenerateFunc(fn, axonflowClient, "user-token")

	resp, err := wrapped(context.Background(), &OllamaGenerateRequest{
		Model:  "llama3",
		Prompt: "Test",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Response != "Func response" {
		t.Errorf("unexpected response: %s", resp.Response)
	}
}

func TestExtractOllamaPrompt(t *testing.T) {
	messages := []OllamaMessage{
		{Role: "system", Content: "You are helpful"},
		{Role: "user", Content: "Hello"},
		{Role: "assistant", Content: "Hi there"},
	}

	result := extractOllamaPrompt(messages)
	expected := "You are helpful Hello Hi there"
	if result != expected {
		t.Errorf("extractOllamaPrompt() = %q, want %q", result, expected)
	}
}

// ===== Bedrock Interceptor Tests =====

func TestWrapBedrockInvokeModel_Success(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, input *BedrockInvokeInput) (*BedrockInvokeOutput, error) {
		return &BedrockInvokeOutput{
			ContentType: "application/json",
			Body:        []byte(`{"content":[{"text":"Hello from Bedrock!"}]}`),
		}, nil
	}

	wrapped := WrapBedrockInvokeModel(fn, axonflowClient, "user-token")

	resp, err := wrapped(context.Background(), &BedrockInvokeInput{
		ModelId:     "anthropic.claude-3-sonnet-20240229-v1:0",
		ContentType: "application/json",
		Body:        []byte(`{"messages":[{"role":"user","content":"Hello"}]}`),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Body) != `{"content":[{"text":"Hello from Bedrock!"}]}` {
		t.Errorf("unexpected response: %s", string(resp.Body))
	}
}

func TestWrapBedrockInvokeModel_Blocked(t *testing.T) {
	server := createGatewayModeServer(t, false)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Mode:         "sandbox",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	called := false
	fn := func(ctx context.Context, input *BedrockInvokeInput) (*BedrockInvokeOutput, error) {
		called = true
		return nil, nil
	}

	wrapped := WrapBedrockInvokeModel(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), &BedrockInvokeInput{
		ModelId:     "anthropic.claude-3-sonnet-20240229-v1:0",
		ContentType: "application/json",
		Body:        []byte(`{"messages":[{"role":"user","content":"Test"}]}`),
	})

	if err == nil {
		t.Error("expected policy violation error")
	}
	if called {
		t.Error("function should not be called when blocked")
	}
}

func TestWrapBedrockInvokeModel_LLMError(t *testing.T) {
	server := createGatewayModeServer(t, true)
	defer server.Close()

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Cache:        axonflow.CacheConfig{Enabled: false},
	})

	fn := func(ctx context.Context, input *BedrockInvokeInput) (*BedrockInvokeOutput, error) {
		return nil, errors.New("Bedrock API error")
	}

	wrapped := WrapBedrockInvokeModel(fn, axonflowClient, "user-token")

	_, err := wrapped(context.Background(), &BedrockInvokeInput{
		ModelId:     "anthropic.claude-3-sonnet-20240229-v1:0",
		ContentType: "application/json",
		Body:        []byte(`{"messages":[{"role":"user","content":"Test"}]}`),
	})

	if err == nil {
		t.Error("expected error from LLM")
	}
}

func TestBedrockModelsStruct(t *testing.T) {
	// Verify model constants are defined correctly
	if BedrockModels.Claude3Sonnet == "" {
		t.Error("BedrockModels.Claude3Sonnet should not be empty")
	}
	if BedrockModels.Claude3Haiku == "" {
		t.Error("BedrockModels.Claude3Haiku should not be empty")
	}
	if BedrockModels.TitanTextExpress == "" {
		t.Error("BedrockModels.TitanTextExpress should not be empty")
	}
	if BedrockModels.Llama3_70B == "" {
		t.Error("BedrockModels.Llama3_70B should not be empty")
	}
}

func TestExtractBedrockPrompt_Claude(t *testing.T) {
	// Test with Claude format messages
	body := []byte(`{"messages":[{"role":"user","content":"Hello world"}]}`)
	result := extractBedrockPrompt(body, "anthropic.claude-3-sonnet-20240229-v1:0")
	if result != "Hello world" {
		t.Errorf("unexpected result for Claude body: %s", result)
	}
}

func TestExtractBedrockPrompt_Titan(t *testing.T) {
	// Test with Titan format
	body := []byte(`{"inputText":"Hello from Titan"}`)
	result := extractBedrockPrompt(body, "amazon.titan-text-express-v1")
	if result != "Hello from Titan" {
		t.Errorf("unexpected result for Titan body: %s", result)
	}
}

func TestExtractBedrockPrompt_InvalidJSON(t *testing.T) {
	// Test with invalid JSON - should return empty string
	invalidBody := []byte(`not valid json`)
	result := extractBedrockPrompt(invalidBody, "anthropic.claude-3-sonnet-20240229-v1:0")
	if result != "" {
		t.Errorf("expected empty string for invalid JSON, got: %s", result)
	}
}

func TestBedrockClaudeRequestResponse(t *testing.T) {
	// Test Claude request structure
	req := BedrockClaudeRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		MaxTokens:        100,
		Messages: []BedrockClaudeMessage{
			{Role: "user", Content: "Hello"},
		},
		Temperature: 0.7,
	}
	if req.MaxTokens != 100 {
		t.Errorf("unexpected MaxTokens: %d", req.MaxTokens)
	}

	// Test Claude response structure
	resp := BedrockClaudeResponse{
		ID:         "resp-123",
		Type:       "message",
		Role:       "assistant",
		Model:      "claude-3-sonnet",
		StopReason: "end_turn",
	}
	if resp.ID != "resp-123" {
		t.Errorf("unexpected ID: %s", resp.ID)
	}
}

func TestBedrockTitanRequestResponse(t *testing.T) {
	// Test Titan request structure
	req := BedrockTitanRequest{
		InputText: "Hello world",
	}
	if req.InputText != "Hello world" {
		t.Errorf("unexpected InputText: %s", req.InputText)
	}

	// Test Titan response structure
	resp := BedrockTitanResponse{
		InputTextTokenCount: 5,
	}
	if resp.InputTextTokenCount != 5 {
		t.Errorf("unexpected InputTextTokenCount: %d", resp.InputTextTokenCount)
	}
}
