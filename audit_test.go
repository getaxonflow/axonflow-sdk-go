package axonflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAuditToolCall tests the AuditToolCall method
func TestAuditToolCall(t *testing.T) {
	t.Run("success with all fields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/audit/tool-call" {
				t.Errorf("expected path /api/v1/audit/tool-call, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}

			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}

			if reqBody["tool_name"] != "getUserInfo" {
				t.Errorf("expected tool_name getUserInfo, got %v", reqBody["tool_name"])
			}
			if reqBody["tool_type"] != "mcp" {
				t.Errorf("expected tool_type mcp, got %v", reqBody["tool_type"])
			}
			if reqBody["workflow_id"] != "wf_abc123" {
				t.Errorf("expected workflow_id wf_abc123, got %v", reqBody["workflow_id"])
			}
			if reqBody["step_id"] != "step-3" {
				t.Errorf("expected step_id step-3, got %v", reqBody["step_id"])
			}
			if reqBody["user_id"] != "user@example.com" {
				t.Errorf("expected user_id user@example.com, got %v", reqBody["user_id"])
			}
			if reqBody["duration_ms"].(float64) != 45 {
				t.Errorf("expected duration_ms 45, got %v", reqBody["duration_ms"])
			}
			if reqBody["success"] != true {
				t.Errorf("expected success true, got %v", reqBody["success"])
			}
			if reqBody["error_message"] != "something went wrong" {
				t.Errorf("expected error_message, got %v", reqBody["error_message"])
			}

			// Verify input/output maps
			input, ok := reqBody["input"].(map[string]interface{})
			if !ok || input["user_id"] != "u123" {
				t.Errorf("expected input.user_id u123, got %v", reqBody["input"])
			}
			output, ok := reqBody["output"].(map[string]interface{})
			if !ok || output["name"] != "Alice" {
				t.Errorf("expected output.name Alice, got %v", reqBody["output"])
			}

			// Verify policies_applied
			policies, ok := reqBody["policies_applied"].([]interface{})
			if !ok || len(policies) != 2 {
				t.Errorf("expected 2 policies_applied, got %v", reqBody["policies_applied"])
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"audit_id":  "aud_abc123",
				"status":    "recorded",
				"timestamp": "2026-03-14T10:30:00Z",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		success := true
		resp, err := client.AuditToolCall(context.Background(), AuditToolCallRequest{
			ToolName:        "getUserInfo",
			ToolType:        "mcp",
			Input:           map[string]interface{}{"user_id": "u123"},
			Output:          map[string]interface{}{"name": "Alice"},
			WorkflowID:      "wf_abc123",
			StepID:          "step-3",
			UserID:          "user@example.com",
			DurationMs:      45,
			PoliciesApplied: []string{"pii", "rbac"},
			Success:         &success,
			ErrorMessage:    "something went wrong",
		})
		if err != nil {
			t.Fatalf("AuditToolCall failed: %v", err)
		}

		if resp.AuditID != "aud_abc123" {
			t.Errorf("expected audit_id aud_abc123, got %s", resp.AuditID)
		}
		if resp.Status != "recorded" {
			t.Errorf("expected status recorded, got %s", resp.Status)
		}
		if resp.Timestamp != "2026-03-14T10:30:00Z" {
			t.Errorf("expected timestamp 2026-03-14T10:30:00Z, got %s", resp.Timestamp)
		}
	})

	t.Run("success with required fields only", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody["tool_name"] != "simpleFunc" {
				t.Errorf("expected tool_name simpleFunc, got %v", reqBody["tool_name"])
			}

			// Optional fields should not be present
			if _, exists := reqBody["tool_type"]; exists {
				t.Errorf("expected tool_type to be omitted, got %v", reqBody["tool_type"])
			}
			if _, exists := reqBody["workflow_id"]; exists {
				t.Errorf("expected workflow_id to be omitted, got %v", reqBody["workflow_id"])
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"audit_id":  "aud_minimal",
				"status":    "recorded",
				"timestamp": "2026-03-14T11:00:00Z",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		resp, err := client.AuditToolCall(context.Background(), AuditToolCallRequest{
			ToolName: "simpleFunc",
		})
		if err != nil {
			t.Fatalf("AuditToolCall failed: %v", err)
		}

		if resp.AuditID != "aud_minimal" {
			t.Errorf("expected audit_id aud_minimal, got %s", resp.AuditID)
		}
	})

	t.Run("empty tool_name returns error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{
			Endpoint: "http://localhost:8080",
		})

		_, err := client.AuditToolCall(context.Background(), AuditToolCallRequest{})
		if err == nil {
			t.Fatal("expected error for empty tool_name")
		}
		if err.Error() != "tool_name is required" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.AuditToolCall(context.Background(), AuditToolCallRequest{
			ToolName: "failingTool",
		})
		if err == nil {
			t.Fatal("expected error for 500 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 500 {
			t.Errorf("expected status 500, got %d", httpErr.statusCode)
		}
	})

	t.Run("includes auth headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client:my-secret"))
			if authHeader != expectedAuth {
				t.Errorf("expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
			}

			tenantHeader := r.Header.Get("X-Tenant-ID")
			if tenantHeader != "my-client" {
				t.Errorf("expected X-Tenant-ID my-client, got %s", tenantHeader)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"audit_id":  "aud_auth",
				"status":    "recorded",
				"timestamp": "2026-03-14T12:00:00Z",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "my-client",
			ClientSecret: "my-secret",
		})

		_, err := client.AuditToolCall(context.Background(), AuditToolCallRequest{
			ToolName: "authTest",
		})
		if err != nil {
			t.Fatalf("AuditToolCall failed: %v", err)
		}
	})

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{
			Endpoint: "http://localhost:99999",
		})

		_, err := client.AuditToolCall(context.Background(), AuditToolCallRequest{
			ToolName: "networkFail",
		})
		if err == nil {
			t.Fatal("expected network error")
		}
	})
}

// TestSearchAuditLogs tests the SearchAuditLogs method
func TestSearchAuditLogs(t *testing.T) {
	t.Run("successful search with all filters", func(t *testing.T) {
		startTime := time.Now().Add(-24 * time.Hour)
		endTime := time.Now()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.URL.Path != "/api/v1/audit/search" {
				t.Errorf("expected path /api/v1/audit/search, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			// Parse request body
			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}

			// Verify filters are passed
			if reqBody["user_email"] != "test@example.com" {
				t.Errorf("expected user_email test@example.com, got %v", reqBody["user_email"])
			}
			if reqBody["client_id"] != "test-client" {
				t.Errorf("expected client_id test-client, got %v", reqBody["client_id"])
			}
			if reqBody["request_type"] != "llm_chat" {
				t.Errorf("expected request_type llm_chat, got %v", reqBody["request_type"])
			}
			if reqBody["limit"].(float64) != 50 {
				t.Errorf("expected limit 50, got %v", reqBody["limit"])
			}

			// Return mock response
			entries := []AuditLogEntry{
				{
					ID:           "audit-1",
					RequestID:    "req-1",
					Timestamp:    time.Now(),
					UserEmail:    "test@example.com",
					ClientID:     "test-client",
					TenantID:     "tenant-1",
					RequestType:  "llm_chat",
					QuerySummary: "Test query",
					Success:      true,
					Blocked:      false,
					RiskScore:    0.1,
					Provider:     "openai",
					Model:        "gpt-4",
					TokensUsed:   150,
					LatencyMs:    250,
				},
				{
					ID:               "audit-2",
					RequestID:        "req-2",
					Timestamp:        time.Now(),
					UserEmail:        "test@example.com",
					ClientID:         "test-client",
					TenantID:         "tenant-1",
					RequestType:      "llm_chat",
					QuerySummary:     "Another query",
					Success:          true,
					Blocked:          true,
					RiskScore:        0.9,
					Provider:         "openai",
					Model:            "gpt-4",
					TokensUsed:       0,
					LatencyMs:        50,
					PolicyViolations: []string{"policy-1"},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(entries)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		req := &AuditSearchRequest{
			UserEmail:   "test@example.com",
			ClientID:    "test-client",
			StartTime:   &startTime,
			EndTime:     &endTime,
			RequestType: "llm_chat",
			Limit:       50,
		}

		result, err := client.SearchAuditLogs(context.Background(), req)
		if err != nil {
			t.Fatalf("SearchAuditLogs failed: %v", err)
		}

		if len(result.Entries) != 2 {
			t.Errorf("expected 2 entries, got %d", len(result.Entries))
		}
		if result.Entries[0].ID != "audit-1" {
			t.Errorf("expected first entry ID audit-1, got %s", result.Entries[0].ID)
		}
		if result.Entries[1].Blocked != true {
			t.Errorf("expected second entry to be blocked")
		}
		if len(result.Entries[1].PolicyViolations) != 1 {
			t.Errorf("expected 1 policy violation, got %d", len(result.Entries[1].PolicyViolations))
		}
	})

	t.Run("empty search with defaults", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			// Verify default limit is applied
			if reqBody["limit"].(float64) != 100 {
				t.Errorf("expected default limit 100, got %v", reqBody["limit"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		result, err := client.SearchAuditLogs(context.Background(), nil)
		if err != nil {
			t.Fatalf("SearchAuditLogs failed: %v", err)
		}

		if len(result.Entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(result.Entries))
		}
		if result.Limit != 100 {
			t.Errorf("expected limit 100, got %d", result.Limit)
		}
	})

	t.Run("limit capped at 1000", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			// Verify limit is capped at 1000
			if reqBody["limit"].(float64) != 1000 {
				t.Errorf("expected limit capped at 1000, got %v", reqBody["limit"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		req := &AuditSearchRequest{Limit: 5000} // Request more than max
		_, err := client.SearchAuditLogs(context.Background(), req)
		if err != nil {
			t.Fatalf("SearchAuditLogs failed: %v", err)
		}
	})

	t.Run("handles 400 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid request"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.SearchAuditLogs(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for 400 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 400 {
			t.Errorf("expected status 400, got %d", httpErr.statusCode)
		}
	})

	t.Run("handles 401 unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.SearchAuditLogs(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for 401 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 401 {
			t.Errorf("expected status 401, got %d", httpErr.statusCode)
		}
	})

	t.Run("handles 500 server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.SearchAuditLogs(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for 500 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 500 {
			t.Errorf("expected status 500, got %d", httpErr.statusCode)
		}
	})

	t.Run("handles network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{
			Endpoint: "http://localhost:99999", // Invalid port - will cause network error
		})

		_, err := client.SearchAuditLogs(context.Background(), nil)
		if err == nil {
			t.Fatal("expected network error")
		}
	})

	t.Run("handles wrapped response format", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := AuditSearchResponse{
				Entries: []AuditLogEntry{
					{ID: "audit-1", RequestID: "req-1"},
				},
				Total:  100,
				Limit:  10,
				Offset: 0,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		result, err := client.SearchAuditLogs(context.Background(), nil)
		if err != nil {
			t.Fatalf("SearchAuditLogs failed: %v", err)
		}

		if result.Total != 100 {
			t.Errorf("expected total 100, got %d", result.Total)
		}
	})

	t.Run("with pagination offset", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody["offset"].(float64) != 50 {
				t.Errorf("expected offset 50, got %v", reqBody["offset"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		req := &AuditSearchRequest{Offset: 50}
		_, err := client.SearchAuditLogs(context.Background(), req)
		if err != nil {
			t.Fatalf("SearchAuditLogs failed: %v", err)
		}
	})

	t.Run("includes auth headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for OAuth2 Basic auth header
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:my-secret"))
			if authHeader != expectedAuth {
				t.Errorf("expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "my-secret",
		})

		_, err := client.SearchAuditLogs(context.Background(), nil)
		if err != nil {
			t.Fatalf("SearchAuditLogs failed: %v", err)
		}
	})
}

// TestGetAuditLogsByTenant tests the GetAuditLogsByTenant method
func TestGetAuditLogsByTenant(t *testing.T) {
	t.Run("successful query with defaults", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.URL.Path != "/api/v1/audit/tenant/tenant-abc" {
				t.Errorf("expected path /api/v1/audit/tenant/tenant-abc, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			// Verify default query params
			if r.URL.Query().Get("limit") != "50" {
				t.Errorf("expected default limit 50, got %s", r.URL.Query().Get("limit"))
			}
			if r.URL.Query().Get("offset") != "0" {
				t.Errorf("expected default offset 0, got %s", r.URL.Query().Get("offset"))
			}

			entries := []AuditLogEntry{
				{
					ID:        "audit-1",
					TenantID:  "tenant-abc",
					Success:   true,
					Timestamp: time.Now(),
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(entries)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		result, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", nil)
		if err != nil {
			t.Fatalf("GetAuditLogsByTenant failed: %v", err)
		}

		if len(result.Entries) != 1 {
			t.Errorf("expected 1 entry, got %d", len(result.Entries))
		}
		if result.Limit != 50 {
			t.Errorf("expected limit 50, got %d", result.Limit)
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("limit") != "100" {
				t.Errorf("expected limit 100, got %s", r.URL.Query().Get("limit"))
			}
			if r.URL.Query().Get("offset") != "25" {
				t.Errorf("expected offset 25, got %s", r.URL.Query().Get("offset"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		opts := &AuditQueryOptions{
			Limit:  100,
			Offset: 25,
		}

		_, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", opts)
		if err != nil {
			t.Fatalf("GetAuditLogsByTenant failed: %v", err)
		}
	})

	t.Run("empty tenant ID returns error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{
			Endpoint: "http://localhost:8080", // URL doesn't matter - error before HTTP call
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "", nil)
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if err.Error() != "tenantID is required" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("limit capped at 1000", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("limit") != "1000" {
				t.Errorf("expected limit capped at 1000, got %s", r.URL.Query().Get("limit"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		opts := &AuditQueryOptions{Limit: 5000}
		_, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", opts)
		if err != nil {
			t.Fatalf("GetAuditLogsByTenant failed: %v", err)
		}
	})

	t.Run("handles 400 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid tenant ID"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "invalid!", nil)
		if err == nil {
			t.Fatal("expected error for 400 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 400 {
			t.Errorf("expected status 400, got %d", httpErr.statusCode)
		}
	})

	t.Run("handles 403 forbidden", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "not authorized for this tenant"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "other-tenant", nil)
		if err == nil {
			t.Fatal("expected error for 403 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 403 {
			t.Errorf("expected status 403, got %d", httpErr.statusCode)
		}
	})

	t.Run("handles 404 not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "tenant not found"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "nonexistent", nil)
		if err == nil {
			t.Fatal("expected error for 404 response")
		}

		httpErr, ok := err.(*httpError)
		if !ok {
			t.Fatalf("expected httpError, got %T", err)
		}
		if httpErr.statusCode != 404 {
			t.Errorf("expected status 404, got %d", httpErr.statusCode)
		}
	})

	t.Run("handles network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{
			Endpoint: "http://localhost:99999", // Invalid port - will cause network error
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", nil)
		if err == nil {
			t.Fatal("expected network error")
		}
	})

	t.Run("handles wrapped response format", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := AuditSearchResponse{
				Entries: []AuditLogEntry{
					{ID: "audit-1", TenantID: "tenant-abc"},
				},
				Total:  50,
				Limit:  50,
				Offset: 0,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
		})

		result, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", nil)
		if err != nil {
			t.Fatalf("GetAuditLogsByTenant failed: %v", err)
		}

		if result.Total != 50 {
			t.Errorf("expected total 50, got %d", result.Total)
		}
	})

	t.Run("includes auth headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for OAuth2 Basic auth header
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
			if authHeader != expectedAuth {
				t.Errorf("expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", nil)
		if err != nil {
			t.Fatalf("GetAuditLogsByTenant failed: %v", err)
		}
	})

	t.Run("debug mode logging", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AuditLogEntry{})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
			Debug:    true,
		})

		_, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", nil)
		if err != nil {
			t.Fatalf("GetAuditLogsByTenant failed: %v", err)
		}
	})
}

// TestAuditLogEntryFields tests that AuditLogEntry correctly unmarshals all fields
func TestAuditLogEntryFields(t *testing.T) {
	jsonData := `{
		"id": "audit-123",
		"request_id": "req-456",
		"timestamp": "2026-01-05T10:30:00Z",
		"user_email": "user@example.com",
		"client_id": "client-1",
		"tenant_id": "tenant-1",
		"request_type": "llm_chat",
		"query_summary": "What is AI?",
		"success": true,
		"blocked": false,
		"risk_score": 0.25,
		"provider": "openai",
		"model": "gpt-4",
		"tokens_used": 500,
		"latency_ms": 1200,
		"policy_violations": ["pol-1", "pol-2"],
		"metadata": {"key": "value"}
	}`

	var entry AuditLogEntry
	if err := json.Unmarshal([]byte(jsonData), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if entry.ID != "audit-123" {
		t.Errorf("expected ID audit-123, got %s", entry.ID)
	}
	if entry.RequestID != "req-456" {
		t.Errorf("expected RequestID req-456, got %s", entry.RequestID)
	}
	if entry.UserEmail != "user@example.com" {
		t.Errorf("expected UserEmail user@example.com, got %s", entry.UserEmail)
	}
	if entry.RiskScore != 0.25 {
		t.Errorf("expected RiskScore 0.25, got %f", entry.RiskScore)
	}
	if entry.TokensUsed != 500 {
		t.Errorf("expected TokensUsed 500, got %d", entry.TokensUsed)
	}
	if len(entry.PolicyViolations) != 2 {
		t.Errorf("expected 2 policy violations, got %d", len(entry.PolicyViolations))
	}
	if entry.Metadata["key"] != "value" {
		t.Errorf("expected metadata key=value")
	}
}

// TestAuditSearchRequestSerialization tests request serialization
func TestAuditSearchRequestSerialization(t *testing.T) {
	startTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 1, 5, 23, 59, 59, 0, time.UTC)

	req := AuditSearchRequest{
		UserEmail:   "test@example.com",
		ClientID:    "client-1",
		StartTime:   &startTime,
		EndTime:     &endTime,
		RequestType: "llm_chat",
		Limit:       50,
		Offset:      10,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed["user_email"] != "test@example.com" {
		t.Errorf("expected user_email test@example.com")
	}
	if parsed["limit"].(float64) != 50 {
		t.Errorf("expected limit 50")
	}
}

// TestContextCancellation tests that context cancellation is respected
func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]AuditLogEntry{})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.SearchAuditLogs(ctx, nil)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}
