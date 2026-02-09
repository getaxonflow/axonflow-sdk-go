package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Sample webhook test data
var sampleWebhook = WebhookSubscription{
	ID:        "wh_test123",
	URL:       "https://example.com/webhooks",
	Events:    []string{"workflow.completed", "step.approval_required"},
	Active:    true,
	CreatedAt: "2026-02-07T10:00:00Z",
	UpdatedAt: "2026-02-07T10:00:00Z",
}

// TestCreateWebhook tests creating a webhook subscription
func TestCreateWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/webhooks" {
			t.Errorf("Expected path /api/v1/webhooks, got %s", r.URL.Path)
		}

		var req CreateWebhookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.URL != "https://example.com/webhooks" {
			t.Errorf("Expected URL 'https://example.com/webhooks', got '%s'", req.URL)
		}
		if len(req.Events) != 2 {
			t.Errorf("Expected 2 events, got %d", len(req.Events))
		}
		if !req.Active {
			t.Error("Expected active to be true")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleWebhook)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	webhook, err := client.CreateWebhook(CreateWebhookRequest{
		URL:    "https://example.com/webhooks",
		Events: []string{"workflow.completed", "step.approval_required"},
		Active: true,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if webhook.ID != "wh_test123" {
		t.Errorf("Expected ID 'wh_test123', got '%s'", webhook.ID)
	}
	if webhook.URL != "https://example.com/webhooks" {
		t.Errorf("Expected URL 'https://example.com/webhooks', got '%s'", webhook.URL)
	}
	if len(webhook.Events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(webhook.Events))
	}
	if !webhook.Active {
		t.Error("Expected webhook to be active")
	}
}

// TestCreateWebhookWithSecret tests creating a webhook with a shared secret
func TestCreateWebhookWithSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req CreateWebhookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.Secret != "my-secret-key" {
			t.Errorf("Expected secret 'my-secret-key', got '%s'", req.Secret)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleWebhook)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.CreateWebhook(CreateWebhookRequest{
		URL:    "https://example.com/webhooks",
		Events: []string{"workflow.completed"},
		Secret: "my-secret-key",
		Active: true,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestCreateWebhookServerError tests error handling for server errors
func TestCreateWebhookServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.CreateWebhook(CreateWebhookRequest{
		URL:    "https://example.com/webhooks",
		Events: []string{"workflow.completed"},
		Active: true,
	})

	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestGetWebhook tests getting a specific webhook
func TestGetWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/webhooks/wh_test123" {
			t.Errorf("Expected path /api/v1/webhooks/wh_test123, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleWebhook)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	webhook, err := client.GetWebhook("wh_test123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if webhook.ID != "wh_test123" {
		t.Errorf("Expected ID 'wh_test123', got '%s'", webhook.ID)
	}
	if webhook.URL != "https://example.com/webhooks" {
		t.Errorf("Expected URL 'https://example.com/webhooks', got '%s'", webhook.URL)
	}
}

// TestGetWebhookEmptyID tests error when webhook ID is empty
func TestGetWebhookEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	_, err := client.GetWebhook("")
	if err == nil {
		t.Error("Expected error for empty webhook ID")
	}
}

// TestGetWebhookServerError tests error handling for server errors
func TestGetWebhookServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Webhook not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetWebhook("wh_nonexistent")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// TestUpdateWebhook tests updating a webhook
func TestUpdateWebhook(t *testing.T) {
	updatedWebhook := sampleWebhook
	updatedWebhook.URL = "https://example.com/new-webhooks"
	updatedWebhook.Active = false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("Expected PUT method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/webhooks/wh_test123" {
			t.Errorf("Expected path /api/v1/webhooks/wh_test123, got %s", r.URL.Path)
		}

		var req UpdateWebhookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if req.URL != "https://example.com/new-webhooks" {
			t.Errorf("Expected URL 'https://example.com/new-webhooks', got '%s'", req.URL)
		}
		if req.Active == nil || *req.Active != false {
			t.Error("Expected active to be false")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updatedWebhook)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	active := false
	webhook, err := client.UpdateWebhook("wh_test123", UpdateWebhookRequest{
		URL:    "https://example.com/new-webhooks",
		Active: &active,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if webhook.URL != "https://example.com/new-webhooks" {
		t.Errorf("Expected URL 'https://example.com/new-webhooks', got '%s'", webhook.URL)
	}
	if webhook.Active {
		t.Error("Expected webhook to be inactive")
	}
}

// TestUpdateWebhookEmptyID tests error when webhook ID is empty
func TestUpdateWebhookEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	_, err := client.UpdateWebhook("", UpdateWebhookRequest{URL: "https://example.com"})
	if err == nil {
		t.Error("Expected error for empty webhook ID")
	}
}

// TestUpdateWebhookEvents tests updating webhook events
func TestUpdateWebhookEvents(t *testing.T) {
	updatedWebhook := sampleWebhook
	updatedWebhook.Events = []string{"workflow.completed", "workflow.failed", "step.rejected"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req UpdateWebhookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if len(req.Events) != 3 {
			t.Errorf("Expected 3 events, got %d", len(req.Events))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updatedWebhook)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	webhook, err := client.UpdateWebhook("wh_test123", UpdateWebhookRequest{
		Events: []string{"workflow.completed", "workflow.failed", "step.rejected"},
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(webhook.Events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(webhook.Events))
	}
}

// TestDeleteWebhook tests deleting a webhook
func TestDeleteWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/webhooks/wh_test123" {
			t.Errorf("Expected path /api/v1/webhooks/wh_test123, got %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.DeleteWebhook("wh_test123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestDeleteWebhookEmptyID tests error when webhook ID is empty
func TestDeleteWebhookEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.DeleteWebhook("")
	if err == nil {
		t.Error("Expected error for empty webhook ID")
	}
}

// TestDeleteWebhookServerError tests error handling for server errors
func TestDeleteWebhookServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Webhook not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.DeleteWebhook("wh_nonexistent")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// TestListWebhooks tests listing all webhooks
func TestListWebhooks(t *testing.T) {
	listResponse := ListWebhooksResponse{
		Webhooks: []WebhookSubscription{sampleWebhook},
		Total:    1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/webhooks" {
			t.Errorf("Expected path /api/v1/webhooks, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listResponse)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.ListWebhooks()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("Expected total 1, got %d", result.Total)
	}
	if len(result.Webhooks) != 1 {
		t.Errorf("Expected 1 webhook, got %d", len(result.Webhooks))
	}
	if result.Webhooks[0].ID != "wh_test123" {
		t.Errorf("Expected webhook ID 'wh_test123', got '%s'", result.Webhooks[0].ID)
	}
}

// TestListWebhooksEmpty tests listing webhooks when there are none
func TestListWebhooksEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ListWebhooksResponse{
			Webhooks: []WebhookSubscription{},
			Total:    0,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	result, err := client.ListWebhooks()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("Expected total 0, got %d", result.Total)
	}
	if len(result.Webhooks) != 0 {
		t.Errorf("Expected 0 webhooks, got %d", len(result.Webhooks))
	}
}

// TestListWebhooksServerError tests error handling for server errors
func TestListWebhooksServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListWebhooks()
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestWebhookSubscriptionDeserialization tests WebhookSubscription JSON deserialization
func TestWebhookSubscriptionDeserialization(t *testing.T) {
	jsonData := `{
		"id": "wh_deser_001",
		"url": "https://hooks.example.com/endpoint",
		"events": ["workflow.completed", "step.approval_required", "plan.rollback"],
		"active": true,
		"created_at": "2026-02-07T10:00:00Z",
		"updated_at": "2026-02-07T12:30:00Z"
	}`

	var webhook WebhookSubscription
	err := json.Unmarshal([]byte(jsonData), &webhook)
	if err != nil {
		t.Fatalf("Failed to unmarshal WebhookSubscription: %v", err)
	}

	if webhook.ID != "wh_deser_001" {
		t.Errorf("Expected ID 'wh_deser_001', got '%s'", webhook.ID)
	}
	if webhook.URL != "https://hooks.example.com/endpoint" {
		t.Errorf("Expected URL 'https://hooks.example.com/endpoint', got '%s'", webhook.URL)
	}
	if len(webhook.Events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(webhook.Events))
	}
	if !webhook.Active {
		t.Error("Expected active to be true")
	}
	if webhook.CreatedAt != "2026-02-07T10:00:00Z" {
		t.Errorf("Expected created_at '2026-02-07T10:00:00Z', got '%s'", webhook.CreatedAt)
	}
	if webhook.UpdatedAt != "2026-02-07T12:30:00Z" {
		t.Errorf("Expected updated_at '2026-02-07T12:30:00Z', got '%s'", webhook.UpdatedAt)
	}
}
