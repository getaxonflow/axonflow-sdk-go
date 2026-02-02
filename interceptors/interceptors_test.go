package interceptors

import (
	"context"
	"errors"
	"testing"
)

// MockAxonFlowClient is a mock for testing
type MockAxonFlowClient struct {
	ProxyLLMCallFn func(userToken, query, requestType string, context map[string]interface{}) (*MockClientResponse, error)
	AuditLLMCallFn func(contextID, summary, provider, model string, tokenUsage MockTokenUsage, latencyMs int64, metadata map[string]interface{}) (*MockAuditResult, error)
}

type MockClientResponse struct {
	Success     bool
	Blocked     bool
	BlockReason string
	RequestID   string
	PolicyInfo  *MockPolicyInfo
}

type MockPolicyInfo struct {
	PoliciesEvaluated []string
}

type MockTokenUsage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

type MockAuditResult struct {
	Success bool
	AuditID string
}

// MockOpenAIClient is a mock OpenAI client for testing
type MockOpenAIClient struct {
	CreateChatCompletionFn func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error)
}

func (m *MockOpenAIClient) CreateChatCompletion(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
	if m.CreateChatCompletionFn != nil {
		return m.CreateChatCompletionFn(ctx, req)
	}
	return ChatCompletionResponse{
		ID:      "test-id",
		Model:   req.Model,
		Created: 1234567890,
		Choices: []ChatCompletionChoice{
			{
				Index: 0,
				Message: ChatMessage{
					Role:    "assistant",
					Content: "Hello! How can I help you today?",
				},
				FinishReason: "stop",
			},
		},
		Usage: Usage{
			PromptTokens:     10,
			CompletionTokens: 8,
			TotalTokens:      18,
		},
	}, nil
}

// MockAnthropicClient is a mock Anthropic client for testing
type MockAnthropicClient struct {
	CreateMessageFn func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error)
}

func (m *MockAnthropicClient) CreateMessage(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
	if m.CreateMessageFn != nil {
		return m.CreateMessageFn(ctx, req)
	}
	return AnthropicMessageResponse{
		ID:    "test-id",
		Type:  "message",
		Role:  "assistant",
		Model: req.Model,
		Content: []AnthropicContentBlock{
			{Type: "text", Text: "Hello! How can I assist you today?"},
		},
		StopReason: "end_turn",
		Usage: AnthropicUsage{
			InputTokens:  10,
			OutputTokens: 8,
		},
	}, nil
}

func TestExtractOpenAIPrompt(t *testing.T) {
	tests := []struct {
		name     string
		messages []ChatMessage
		expected string
	}{
		{
			name:     "empty messages",
			messages: []ChatMessage{},
			expected: "",
		},
		{
			name: "single message",
			messages: []ChatMessage{
				{Role: "user", Content: "Hello world"},
			},
			expected: "Hello world",
		},
		{
			name: "multiple messages",
			messages: []ChatMessage{
				{Role: "system", Content: "You are a helpful assistant"},
				{Role: "user", Content: "Hello"},
				{Role: "assistant", Content: "Hi there"},
				{Role: "user", Content: "How are you?"},
			},
			expected: "You are a helpful assistant Hello Hi there How are you?",
		},
		{
			name: "message with empty content",
			messages: []ChatMessage{
				{Role: "user", Content: "Hello"},
				{Role: "assistant", Content: ""},
				{Role: "user", Content: "World"},
			},
			expected: "Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractOpenAIPrompt(tt.messages)
			if result != tt.expected {
				t.Errorf("extractOpenAIPrompt() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractAnthropicPrompt(t *testing.T) {
	tests := []struct {
		name     string
		messages []AnthropicMessage
		system   string
		expected string
	}{
		{
			name:     "empty messages no system",
			messages: []AnthropicMessage{},
			system:   "",
			expected: "",
		},
		{
			name:     "only system prompt",
			messages: []AnthropicMessage{},
			system:   "You are a helpful assistant",
			expected: "You are a helpful assistant",
		},
		{
			name: "single message with text",
			messages: []AnthropicMessage{
				{
					Role: "user",
					Content: []AnthropicContentBlock{
						{Type: "text", Text: "Hello world"},
					},
				},
			},
			system:   "",
			expected: "Hello world",
		},
		{
			name: "system plus messages",
			messages: []AnthropicMessage{
				CreateUserMessage("Hello"),
				CreateAssistantMessage("Hi there"),
			},
			system:   "Be helpful",
			expected: "Be helpful Hello Hi there",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAnthropicPrompt(tt.messages, tt.system)
			if result != tt.expected {
				t.Errorf("extractAnthropicPrompt() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestPolicyViolationError(t *testing.T) {
	err := &PolicyViolationError{
		BlockReason: "PII detected",
		Policies:    []string{"pii-detection", "ssn-blocker"},
	}

	if err.Error() != "request blocked by policy: PII detected" {
		t.Errorf("unexpected error message: %s", err.Error())
	}

	if !IsPolicyViolationError(err) {
		t.Error("IsPolicyViolationError should return true")
	}

	pve, ok := GetPolicyViolation(err)
	if !ok {
		t.Error("GetPolicyViolation should return true")
	}
	if pve.BlockReason != "PII detected" {
		t.Errorf("unexpected block reason: %s", pve.BlockReason)
	}

	// Test with non-policy error
	otherErr := errors.New("some other error")
	if IsPolicyViolationError(otherErr) {
		t.Error("IsPolicyViolationError should return false for non-policy errors")
	}

	_, ok = GetPolicyViolation(otherErr)
	if ok {
		t.Error("GetPolicyViolation should return false for non-policy errors")
	}
}

func TestCreateAnthropicMessage(t *testing.T) {
	msg := CreateAnthropicMessage("user", "Hello world")

	if msg.Role != "user" {
		t.Errorf("unexpected role: %s", msg.Role)
	}
	if len(msg.Content) != 1 {
		t.Errorf("unexpected content length: %d", len(msg.Content))
	}
	if msg.Content[0].Type != "text" {
		t.Errorf("unexpected content type: %s", msg.Content[0].Type)
	}
	if msg.Content[0].Text != "Hello world" {
		t.Errorf("unexpected content text: %s", msg.Content[0].Text)
	}
}

func TestCreateUserMessage(t *testing.T) {
	msg := CreateUserMessage("Test message")
	if msg.Role != "user" {
		t.Errorf("expected role 'user', got %s", msg.Role)
	}
}

func TestCreateAssistantMessage(t *testing.T) {
	msg := CreateAssistantMessage("Test response")
	if msg.Role != "assistant" {
		t.Errorf("expected role 'assistant', got %s", msg.Role)
	}
}

func TestMarshalUnmarshalRequest(t *testing.T) {
	req := ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []ChatMessage{
			{Role: "user", Content: "Hello"},
		},
		Temperature: 0.7,
		MaxTokens:   100,
	}

	data, err := MarshalRequest(req)
	if err != nil {
		t.Fatalf("MarshalRequest failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("MarshalRequest returned empty data")
	}

	// Verify it contains expected fields
	jsonStr := string(data)
	if jsonStr == "" {
		t.Error("JSON should not be empty")
	}
}

func TestOpenAIAdapter(t *testing.T) {
	called := false
	adapter := NewOpenAIAdapter(func(ctx context.Context, req ChatCompletionRequest) (ChatCompletionResponse, error) {
		called = true
		return ChatCompletionResponse{
			ID: "test-id",
			Choices: []ChatCompletionChoice{
				{Message: ChatMessage{Role: "assistant", Content: "Hello"}},
			},
		}, nil
	})

	resp, err := adapter.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []ChatMessage{
			{Role: "user", Content: "Hi"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("CreateFn was not called")
	}
	if resp.ID != "test-id" {
		t.Errorf("unexpected response ID: %s", resp.ID)
	}
}

func TestAnthropicAdapter(t *testing.T) {
	called := false
	adapter := NewAnthropicAdapter(func(ctx context.Context, req AnthropicMessageRequest) (AnthropicMessageResponse, error) {
		called = true
		return AnthropicMessageResponse{
			ID: "test-id",
			Content: []AnthropicContentBlock{
				{Type: "text", Text: "Hello"},
			},
		}, nil
	})

	resp, err := adapter.CreateMessage(context.Background(), AnthropicMessageRequest{
		Model:     "claude-3-sonnet-20240229",
		MaxTokens: 100,
		Messages: []AnthropicMessage{
			CreateUserMessage("Hi"),
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("CreateFn was not called")
	}
	if resp.ID != "test-id" {
		t.Errorf("unexpected response ID: %s", resp.ID)
	}
}

func TestExtractAnthropicResponseSummary(t *testing.T) {
	tests := []struct {
		name     string
		resp     AnthropicMessageResponse
		expected string
	}{
		{
			name: "short response",
			resp: AnthropicMessageResponse{
				Content: []AnthropicContentBlock{
					{Type: "text", Text: "Hello world"},
				},
			},
			expected: "Hello world",
		},
		{
			name: "long response truncated",
			resp: AnthropicMessageResponse{
				Content: []AnthropicContentBlock{
					{Type: "text", Text: "This is a very long response that exceeds one hundred characters and should be truncated to exactly one hundred characters."},
				},
			},
			expected: "This is a very long response that exceeds one hundred characters and should be truncated to exactly ",
		},
		{
			name: "empty content",
			resp: AnthropicMessageResponse{
				Content: []AnthropicContentBlock{},
			},
			expected: "",
		},
		{
			name: "image block ignored",
			resp: AnthropicMessageResponse{
				Content: []AnthropicContentBlock{
					{Type: "image"},
					{Type: "text", Text: "Description"},
				},
			},
			expected: "Description",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAnthropicResponseSummary(tt.resp)
			if result != tt.expected {
				t.Errorf("extractAnthropicResponseSummary() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGoOpenAIBridgeError(t *testing.T) {
	bridge := &GoOpenAIBridge{}

	_, err := bridge.CreateChatCompletion(context.Background(), ChatCompletionRequest{})
	if err == nil {
		t.Error("expected error when CreateFn is not set")
	}
}

func TestAnthropicBridgeError(t *testing.T) {
	bridge := &AnthropicBridge{}

	_, err := bridge.CreateMessage(context.Background(), AnthropicMessageRequest{})
	if err == nil {
		t.Error("expected error when CreateFn is not set")
	}
}
