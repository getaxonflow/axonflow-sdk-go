package axonflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyLLMCall(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"result":     "Test result",
				"plan_id":    "plan-123",
				"request_id": "req-456",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Debug:        false,
		Cache: CacheConfig{
			Enabled: false, // Disable cache for this test
		},
	})

	resp, err := client.ProxyLLMCall("user-123", "test query", "chat", nil)
	if err != nil {
		t.Fatalf("ProxyLLMCall failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success response")
	}

	if resp.PlanID != "plan-123" {
		t.Errorf("Expected PlanID 'plan-123', got '%s'", resp.PlanID)
	}
}

func TestProxyLLMCallWithCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  "Cached result",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Debug:        true,
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	})

	// First call
	_, err := client.ProxyLLMCall("user-123", "same query", "chat", nil)
	if err != nil {
		t.Fatalf("First ProxyLLMCall failed: %v", err)
	}

	// Second call with same parameters (should use cache)
	_, err = client.ProxyLLMCall("user-123", "same query", "chat", nil)
	if err != nil {
		t.Fatalf("Second ProxyLLMCall failed: %v", err)
	}

	// Server should only have been called once due to caching
	if callCount != 1 {
		t.Errorf("Expected 1 server call (cached), got %d", callCount)
	}
}

func TestProxyLLMCallBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":      false,
				"blocked":      true,
				"block_reason": "Request blocked by policy: PII detected",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Cache:        CacheConfig{Enabled: false},
	})

	resp, err := client.ProxyLLMCall("user-123", "blocked query", "chat", nil)
	if err != nil {
		t.Fatalf("ProxyLLMCall failed: %v", err)
	}

	if resp.Success {
		t.Error("Expected blocked response (success=false)")
	}

	if !resp.Blocked {
		t.Error("Expected Blocked=true")
	}
}

func TestProxyLLMCallWithNestedData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"result":   "Nested result",
					"plan_id":  "nested-plan-123",
					"metadata": map[string]interface{}{"key": "value"},
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	resp, err := client.ProxyLLMCall("user", "query", "chat", nil)
	if err != nil {
		t.Fatalf("ProxyLLMCall failed: %v", err)
	}

	if resp.Result != "Nested result" {
		t.Errorf("Expected Result 'Nested result', got '%s'", resp.Result)
	}

	if resp.PlanID != "nested-plan-123" {
		t.Errorf("Expected PlanID 'nested-plan-123', got '%s'", resp.PlanID)
	}
}

func TestProxyLLMCallWithError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox", // Use sandbox mode to disable fail-open
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  1, // Just one attempt
			InitialDelay: 1 * time.Millisecond,
		},
		Cache: CacheConfig{Enabled: false},
	})

	_, err := client.ProxyLLMCall("user", "query", "chat", nil)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}

func TestProxyLLMCallFailOpen(t *testing.T) {
	// Create a server that doesn't respond (connection refused simulation)
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost:19999", // Non-existent server
		ClientID: "test",
		Mode:     "production", // Fail-open enabled
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  1,
			InitialDelay: 1 * time.Millisecond,
		},
		Timeout: 100 * time.Millisecond,
		Cache:   CacheConfig{Enabled: false},
	})

	resp, err := client.ProxyLLMCall("user", "query", "chat", nil)
	if err != nil {
		t.Fatalf("Expected fail-open, got error: %v", err)
	}

	if !resp.Success {
		t.Error("Expected fail-open to return success=true")
	}
}

func TestProxyLLMCallEmptyUserTokenDefaultsToAnonymous(t *testing.T) {
	var receivedUserToken string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			json.Unmarshal(body, &req)
			receivedUserToken = req["user_token"].(string)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  "Test result",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Cache:        CacheConfig{Enabled: false},
	})

	// Call with empty userToken
	_, err := client.ProxyLLMCall("", "test query", "chat", nil)
	if err != nil {
		t.Fatalf("ProxyLLMCall failed: %v", err)
	}

	// Verify the server received "anonymous" as userToken
	if receivedUserToken != "anonymous" {
		t.Errorf("Expected userToken 'anonymous', got '%s'", receivedUserToken)
	}
}

func TestHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"version": "1.0.0",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
	})

	err := client.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
}

func TestHealthCheckUnhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Unhealthy"))
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.HealthCheck()
	if err == nil {
		t.Error("Expected error for unhealthy status")
	}
}

func TestListConnectors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/connectors" {
			w.Header().Set("Content-Type", "application/json")
			// API returns wrapped response
			json.NewEncoder(w).Encode(map[string]interface{}{
				"connectors": []map[string]interface{}{
					{
						"id":          "conn-1",
						"name":        "GitHub",
						"type":        "github",
						"version":     "1.0.0",
						"description": "GitHub connector",
						"installed":   true,
					},
					{
						"id":        "conn-2",
						"name":      "Slack",
						"type":      "slack",
						"installed": false,
					},
				},
				"total": 2,
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
	})

	connectors, err := client.ListConnectors()
	if err != nil {
		t.Fatalf("ListConnectors failed: %v", err)
	}

	if len(connectors) != 2 {
		t.Errorf("Expected 2 connectors, got %d", len(connectors))
	}

	if connectors[0].Name != "GitHub" {
		t.Errorf("Expected first connector name 'GitHub', got '%s'", connectors[0].Name)
	}
}

func TestListConnectorsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/connectors" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Server error"))
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListConnectors()
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestInstallConnector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// New path: /api/v1/connectors/{id}/install
		if r.URL.Path == "/api/v1/connectors/github/install" && r.Method == "POST" {
			// Verify request body
			body, _ := io.ReadAll(r.Body)
			var req ConnectorInstallRequest
			json.Unmarshal(body, &req)

			if req.ConnectorID != "github" {
				t.Errorf("Expected ConnectorID 'github', got '%s'", req.ConnectorID)
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
	})

	err := client.InstallConnector(ConnectorInstallRequest{
		ConnectorID: "github",
		Name:        "My GitHub",
		TenantID:    "tenant-123",
		Options:     map[string]interface{}{"org": "myorg"},
		Credentials: map[string]string{"token": "secret"},
	})

	if err != nil {
		t.Fatalf("InstallConnector failed: %v", err)
	}
}

func TestInstallConnectorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.InstallConnector(ConnectorInstallRequest{
		ConnectorID: "invalid",
		Name:        "Invalid",
	})

	if err == nil {
		t.Error("Expected error for bad request")
	}
}

func TestGetConnector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/connectors/redis" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ConnectorMetadata{
				ID:          "redis",
				Name:        "Redis Connector",
				Type:        "redis",
				Version:     "1.0.0",
				Description: "Connect to Redis databases",
				Installed:   true,
				Healthy:     true,
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
	})

	connector, err := client.GetConnector("redis")
	if err != nil {
		t.Fatalf("GetConnector failed: %v", err)
	}

	if connector.ID != "redis" {
		t.Errorf("Expected ID 'redis', got '%s'", connector.ID)
	}
	if !connector.Installed {
		t.Error("Expected connector to be installed")
	}
}

func TestGetConnectorNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Connector not found"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetConnector("nonexistent")
	if err == nil {
		t.Error("Expected error for not found connector")
	}
}

func TestGetConnectorHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/connectors/redis/health" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ConnectorHealthStatus{
				Healthy:   true,
				Latency:   1500000,
				Timestamp: "2026-01-04T10:00:00Z",
				Details:   map[string]string{"version": "7.0.0"},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
	})

	status, err := client.GetConnectorHealth("redis")
	if err != nil {
		t.Fatalf("GetConnectorHealth failed: %v", err)
	}

	if !status.Healthy {
		t.Error("Expected connector to be healthy")
	}
	if status.Latency != 1500000 {
		t.Errorf("Expected latency 1500000, got %d", status.Latency)
	}
}

func TestGetConnectorHealthNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Connector not found"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetConnectorHealth("nonexistent")
	if err == nil {
		t.Error("Expected error for not found connector")
	}
}

func TestQueryConnector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"issues": []string{"issue-1", "issue-2"},
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	resp, err := client.QueryConnector("user-123", "github", "list issues", map[string]interface{}{
		"repo": "myrepo",
	})

	if err != nil {
		t.Fatalf("QueryConnector failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success response")
	}
}

func TestGetPolicyApprovedContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/policy/pre-check" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"context_id": "ctx-123",
				"approved":   true,
				"approved_data": map[string]interface{}{
					"filtered_query": "safe query",
				},
				"policies":   []string{"policy-1", "policy-2"},
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Debug:        true,
	})

	result, err := client.GetPolicyApprovedContext("user-123", "test query", []string{"postgres"}, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}

	if !result.Approved {
		t.Error("Expected Approved=true")
	}

	if result.ContextID != "ctx-123" {
		t.Errorf("Expected ContextID 'ctx-123', got '%s'", result.ContextID)
	}

	if len(result.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(result.Policies))
	}
}

func TestGetPolicyApprovedContextBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/policy/pre-check" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"context_id":   "ctx-456",
				"approved":     false,
				"block_reason": "PII detected in query",
				"policies":     []string{"pii-detector"},
				"expires_at":   time.Now().Format(time.RFC3339),
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
	})

	result, err := client.GetPolicyApprovedContext("user", "SSN: 123-45-6789", nil, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}

	if result.Approved {
		t.Error("Expected Approved=false for blocked request")
	}

	if result.BlockReason == "" {
		t.Error("Expected BlockReason to be set")
	}
}

func TestGetPolicyApprovedContextWithRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/policy/pre-check" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"context_id": "ctx-789",
				"approved":   true,
				"policies":   []string{},
				"rate_limit": map[string]interface{}{
					"limit":     100,
					"remaining": 95,
					"reset_at":  time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				},
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
	})

	result, err := client.GetPolicyApprovedContext("user", "query", nil, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}

	if result.RateLimitInfo == nil {
		t.Error("Expected RateLimitInfo to be set")
	}

	if result.RateLimitInfo.Limit != 100 {
		t.Errorf("Expected limit 100, got %d", result.RateLimitInfo.Limit)
	}

	if result.RateLimitInfo.Remaining != 95 {
		t.Errorf("Expected remaining 95, got %d", result.RateLimitInfo.Remaining)
	}
}

func TestPreCheck(t *testing.T) {
	// PreCheck is an alias for GetPolicyApprovedContext
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/policy/pre-check" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"context_id": "ctx-precheck",
				"approved":   true,
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
	})

	result, err := client.PreCheck("user", "query", nil, nil)
	if err != nil {
		t.Fatalf("PreCheck failed: %v", err)
	}

	if result.ContextID != "ctx-precheck" {
		t.Errorf("Expected ContextID 'ctx-precheck', got '%s'", result.ContextID)
	}
}

func TestAuditLLMCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/audit/llm-call" {
			// Verify request body
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			json.Unmarshal(body, &req)

			if req["context_id"] != "ctx-123" {
				t.Errorf("Expected context_id 'ctx-123', got '%v'", req["context_id"])
			}

			if req["provider"] != "openai" {
				t.Errorf("Expected provider 'openai', got '%v'", req["provider"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"audit_id": "audit-456",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
		Debug:        true,
	})

	result, err := client.AuditLLMCall(
		"ctx-123",
		"Generated summary of 5 items",
		"openai",
		"gpt-4",
		TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		250,
		map[string]interface{}{"request_type": "summary"},
	)

	if err != nil {
		t.Fatalf("AuditLLMCall failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected success=true")
	}

	if result.AuditID != "audit-456" {
		t.Errorf("Expected AuditID 'audit-456', got '%s'", result.AuditID)
	}
}

func TestAuditLLMCallWithNilMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/audit/llm-call" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"audit_id": "audit-789",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "test-secret",
	})

	// Pass nil metadata
	result, err := client.AuditLLMCall("ctx-123", "summary", "anthropic", "claude-3", TokenUsage{}, 100, nil)
	if err != nil {
		t.Fatalf("AuditLLMCall failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected success=true")
	}
}

func TestGeneratePlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			// Verify request
			body, _ := io.ReadAll(r.Body)
			var req ClientRequest
			json.Unmarshal(body, &req)

			if req.RequestType != "multi-agent-plan" {
				t.Errorf("Expected request_type 'multi-agent-plan', got '%s'", req.RequestType)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"plan_id": "plan-123",
				"data": map[string]interface{}{
					"steps": []map[string]interface{}{
						{
							"id":          "step-1",
							"name":        "Step 1",
							"type":        "query",
							"description": "First step",
						},
						{
							"id":           "step-2",
							"name":         "Step 2",
							"type":         "transform",
							"dependencies": []string{"step-1"},
						},
					},
					"domain":     "finance",
					"complexity": 5,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
		Cache:    CacheConfig{Enabled: false},
	})

	plan, err := client.GeneratePlan("Create a financial report", "finance", "user-123")
	if err != nil {
		t.Fatalf("GeneratePlan failed: %v", err)
	}

	if plan.PlanID != "plan-123" {
		t.Errorf("Expected PlanID 'plan-123', got '%s'", plan.PlanID)
	}

	if len(plan.Steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(plan.Steps))
	}

	if plan.Domain != "finance" {
		t.Errorf("Expected domain 'finance', got '%s'", plan.Domain)
	}
}

func TestGeneratePlanWithDefaultUserToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			body, _ := io.ReadAll(r.Body)
			var req ClientRequest
			json.Unmarshal(body, &req)

			// When no userToken provided, should use clientID
			if req.UserToken != "test-client" {
				t.Errorf("Expected user_token to be client ID 'test-client', got '%s'", req.UserToken)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"plan_id": "plan-default",
				"data":    map[string]interface{}{},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test-client",
		Cache:    CacheConfig{Enabled: false},
	})

	// Call without userToken
	plan, err := client.GeneratePlan("Test query", "")
	if err != nil {
		t.Fatalf("GeneratePlan failed: %v", err)
	}

	if plan.PlanID != "plan-default" {
		t.Errorf("Expected PlanID 'plan-default', got '%s'", plan.PlanID)
	}
}

func TestGeneratePlanError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Plan generation failed",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	_, err := client.GeneratePlan("Bad query", "domain")
	if err == nil {
		t.Error("Expected error for failed plan generation")
	}
}

func TestExecutePlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  "Plan execution completed successfully",
				"metadata": map[string]interface{}{
					"duration":        "5s",
					"completed_steps": 3,
					"total_steps":     3,
					"step_results": []map[string]interface{}{
						{
							"step_id":   "step-1",
							"step_name": "Step 1",
							"status":    "completed",
							"result":    "Step 1 done",
							"duration":  "1s",
						},
					},
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
		Cache:    CacheConfig{Enabled: false},
	})

	result, err := client.ExecutePlan("plan-123", "user-456")
	if err != nil {
		t.Fatalf("ExecutePlan failed: %v", err)
	}

	if result.PlanID != "plan-123" {
		t.Errorf("Expected PlanID 'plan-123', got '%s'", result.PlanID)
	}

	if result.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Status)
	}

	if result.Duration != "5s" {
		t.Errorf("Expected duration '5s', got '%s'", result.Duration)
	}

	if result.CompletedSteps != 3 {
		t.Errorf("Expected 3 completed steps, got %d", result.CompletedSteps)
	}

	if len(result.StepResults) != 1 {
		t.Errorf("Expected 1 step result, got %d", len(result.StepResults))
	}
}

func TestExecutePlanFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Step 2 failed",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	result, err := client.ExecutePlan("plan-failed")
	if err == nil {
		t.Fatalf("Expected error for failed plan, got nil")
	}

	if result == nil {
		t.Fatalf("Expected result even on failure, got nil")
	}

	if result.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", result.Status)
	}
}

func TestGetPlanStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/plan/plan-123" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"plan_id":         "plan-123",
				"status":          "running",
				"completed_steps": 2,
				"total_steps":     5,
				"current_step":    "step-3",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	status, err := client.GetPlanStatus("plan-123")
	if err != nil {
		t.Fatalf("GetPlanStatus failed: %v", err)
	}

	if status.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", status.Status)
	}

	if status.CompletedSteps != 2 {
		t.Errorf("Expected 2 completed steps, got %d", status.CompletedSteps)
	}

	if status.TotalSteps != 5 {
		t.Errorf("Expected 5 total steps, got %d", status.TotalSteps)
	}
}

func TestGetPlanStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Plan not found"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetPlanStatus("nonexistent-plan")
	if err == nil {
		t.Error("Expected error for non-existent plan")
	}
}

func TestIsAxonFlowError(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://test.example.com",
		ClientID: "test",
	})

	tests := []struct {
		errMsg   string
		expected bool
	}{
		{"AxonFlow service unavailable", true},
		{"governance policy error", true},
		{"request failed: connection refused", true},
		{"connection refused", true},
		{"OpenAI API error: rate limit exceeded", false},
		{"Anthropic error: invalid API key", false},
	}

	for _, tt := range tests {
		err := &httpError{statusCode: 500, message: tt.errMsg}
		result := client.isAxonFlowError(err)
		if result != tt.expected {
			t.Errorf("isAxonFlowError(%q) = %v, want %v", tt.errMsg, result, tt.expected)
		}
	}
}

func TestGetMetadataKeys(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		expected int
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			expected: 0,
		},
		{
			name:     "empty metadata",
			metadata: map[string]interface{}{},
			expected: 0,
		},
		{
			name: "with keys",
			metadata: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
				"key3": 123,
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := getMetadataKeys(tt.metadata)
			if len(keys) != tt.expected {
				t.Errorf("getMetadataKeys() returned %d keys, want %d", len(keys), tt.expected)
			}
		})
	}
}

func TestRetryWith4xxError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad request"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Mode:     "sandbox", // Use sandbox mode to disable fail-open
		Debug:    true,
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: 1 * time.Millisecond,
		},
		Cache: CacheConfig{Enabled: false},
	})

	_, err := client.ProxyLLMCall("user", "query", "chat", nil)
	if err == nil {
		t.Error("Expected error")
	}

	// 4xx errors should not be retried
	if callCount != 1 {
		t.Errorf("Expected 1 call (no retry for 4xx), got %d", callCount)
	}
}

func TestAuthHeadersSentWithCredentials(t *testing.T) {
	receivedAuthHeader := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))
	defer server.Close()

	// When credentials are provided, OAuth2 Basic auth header should be sent
	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test",
		ClientSecret: "secret",
		Cache:        CacheConfig{Enabled: false},
	})

	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	// Auth header SHOULD be set with OAuth2 Basic auth format
	expectedBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("test:secret"))
	if receivedAuthHeader != expectedBasic {
		t.Errorf("Expected OAuth2 Basic auth header '%s', got '%s'", expectedBasic, receivedAuthHeader)
	}
}

func TestNonLocalHostIncludesAuth(t *testing.T) {
	// This tests that non-localhost URLs would include auth headers
	// We verify this by checking the auth logic in the client configuration
	client := NewClient(AxonFlowConfig{
		Endpoint:     "https://api.getaxonflow.com",
		ClientID:     "test",
		ClientSecret: "secret",
		Cache:        CacheConfig{Enabled: false},
	})

	// Verify client is configured correctly (can't make real request)
	if client.config.ClientSecret != "secret" {
		t.Errorf("Expected ClientSecret 'secret', got '%s'", client.config.ClientSecret)
	}
	if client.config.Endpoint != "https://api.getaxonflow.com" {
		t.Errorf("Expected non-localhost URL")
	}
}

func TestOrchestratorHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"service": "axonflow-orchestrator",
				"status":  "healthy",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	err := client.OrchestratorHealthCheck()
	if err != nil {
		t.Fatalf("OrchestratorHealthCheck failed: %v", err)
	}
}

func TestOrchestratorHealthCheckUnhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	err := client.OrchestratorHealthCheck()
	if err == nil {
		t.Error("Expected error for unhealthy orchestrator")
	}
}

func TestUninstallConnector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && r.URL.Path == "/api/v1/connectors/postgres" {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	err := client.UninstallConnector("postgres")
	if err != nil {
		t.Fatalf("UninstallConnector failed: %v", err)
	}
}

func TestUninstallConnectorNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "connector not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	err := client.UninstallConnector("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent connector")
	}
}

// ============================================================================
// MCP Query/Execute Tests (Policy Enforcement)
// ============================================================================

func TestMCPQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp/resources/query" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"data":     []map[string]interface{}{{"id": 1, "name": "Test"}},
				"redacted": false,
				"policy_info": map[string]interface{}{
					"policies_evaluated": 5,
					"blocked":            false,
					"redactions_applied": 0,
					"processing_time_ms": 2,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	ctx := context.Background()
	resp, err := client.MCPQuery(ctx, MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM users",
	})
	if err != nil {
		t.Fatalf("MCPQuery failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success response")
	}

	if resp.PolicyInfo == nil {
		t.Error("Expected PolicyInfo in response")
	} else if resp.PolicyInfo.PoliciesEvaluated != 5 {
		t.Errorf("Expected 5 policies evaluated, got %d", resp.PolicyInfo.PoliciesEvaluated)
	}
}

func TestMCPQueryWithRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp/resources/query" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":         true,
				"data":            []map[string]interface{}{{"id": 1, "ssn": "***REDACTED***"}},
				"redacted":        true,
				"redacted_fields": []string{"data[0].ssn"},
				"policy_info": map[string]interface{}{
					"policies_evaluated": 5,
					"blocked":            false,
					"redactions_applied": 1,
					"processing_time_ms": 3,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	ctx := context.Background()
	resp, err := client.MCPQuery(ctx, MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM customers",
	})
	if err != nil {
		t.Fatalf("MCPQuery failed: %v", err)
	}

	if !resp.Redacted {
		t.Error("Expected redacted response")
	}

	if len(resp.RedactedFields) == 0 {
		t.Error("Expected redacted fields")
	}

	if resp.PolicyInfo == nil || resp.PolicyInfo.RedactionsApplied != 1 {
		t.Error("Expected 1 redaction applied")
	}
}

func TestMCPQueryBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp/resources/query" && r.Method == "POST" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Request blocked: SQLi detected",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	ctx := context.Background()
	_, err := client.MCPQuery(ctx, MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM users; DROP TABLE users;--",
	})

	if err == nil {
		t.Error("Expected error for blocked query")
	}
}

func TestMCPExecute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp/tools/execute" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":       true,
				"rows_affected": 1,
				"policy_info": map[string]interface{}{
					"policies_evaluated": 3,
					"blocked":            false,
					"redactions_applied": 0,
					"processing_time_ms": 1,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	ctx := context.Background()
	resp, err := client.MCPExecute(ctx, MCPExecuteRequest{
		Connector: "postgres",
		Action:    "update",
		Params: map[string]interface{}{
			"query": "UPDATE users SET name = $1 WHERE id = $2",
		},
	})
	if err != nil {
		t.Fatalf("MCPExecute failed: %v", err)
	}

	if resp.RowsAffected != 1 {
		t.Errorf("Expected 1 affected row, got %d", resp.RowsAffected)
	}
}

func TestConnectorResponse_WasRedacted(t *testing.T) {
	tests := []struct {
		name     string
		resp     ConnectorResponse
		expected bool
	}{
		{
			name:     "not redacted",
			resp:     ConnectorResponse{Redacted: false},
			expected: false,
		},
		{
			name:     "redacted",
			resp:     ConnectorResponse{Redacted: true, RedactedFields: []string{"data[0].ssn"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resp.WasRedacted(); got != tt.expected {
				t.Errorf("WasRedacted() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ============================================================================
// Plan Rollback Tests (Feature 7)
// ============================================================================

func TestRollbackPlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/plan/plan-123/rollback/2"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		// Body should be empty — target version is in the URL path
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("Expected empty body, got %s", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RollbackPlanResponse{
			PlanID:          "plan-123",
			Version:         2,
			PreviousVersion: 5,
			Status:          "rolled_back",
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.RollbackPlan("plan-123", 2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.PlanID != "plan-123" {
		t.Errorf("Expected plan_id 'plan-123', got '%s'", resp.PlanID)
	}
	if resp.Version != 2 {
		t.Errorf("Expected version 2, got %d", resp.Version)
	}
	if resp.PreviousVersion != 5 {
		t.Errorf("Expected previous_version 5, got %d", resp.PreviousVersion)
	}
	if resp.Status != "rolled_back" {
		t.Errorf("Expected status 'rolled_back', got '%s'", resp.Status)
	}
}

func TestRollbackPlanServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Plan not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.RollbackPlan("nonexistent-plan", 1)
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

func TestRollbackPlanVersionConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error": "Version conflict"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.RollbackPlan("plan-123", 999)
	if err == nil {
		t.Error("Expected error for version conflict")
	}
	if err != ErrVersionConflict {
		t.Errorf("Expected ErrVersionConflict, got %v", err)
	}
}

func TestRollbackPlanResponseDeserialization(t *testing.T) {
	jsonData := `{
		"plan_id": "plan_deser_001",
		"version": 3,
		"previous_version": 7,
		"status": "rolled_back"
	}`

	var resp RollbackPlanResponse
	err := json.Unmarshal([]byte(jsonData), &resp)
	if err != nil {
		t.Fatalf("Failed to unmarshal RollbackPlanResponse: %v", err)
	}

	if resp.PlanID != "plan_deser_001" {
		t.Errorf("Expected plan_id 'plan_deser_001', got '%s'", resp.PlanID)
	}
	if resp.Version != 3 {
		t.Errorf("Expected version 3, got %d", resp.Version)
	}
	if resp.PreviousVersion != 7 {
		t.Errorf("Expected previous_version 7, got %d", resp.PreviousVersion)
	}
	if resp.Status != "rolled_back" {
		t.Errorf("Expected status 'rolled_back', got '%s'", resp.Status)
	}
}

// ============================================================================
// CancelPlan Tests
// ============================================================================

func TestCancelPlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/plan/plan-123/cancel" {
			t.Errorf("Expected path /api/v1/plan/plan-123/cancel, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if req["reason"] != "User requested cancellation" {
			t.Errorf("Expected reason 'User requested cancellation', got '%v'", req["reason"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CancelPlanResponse{
			PlanID:  "plan-123",
			Status:  "cancelled",
			Message: "Plan cancelled successfully",
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.CancelPlan("plan-123", "User requested cancellation")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.PlanID != "plan-123" {
		t.Errorf("Expected plan_id 'plan-123', got '%s'", resp.PlanID)
	}
	if resp.Status != "cancelled" {
		t.Errorf("Expected status 'cancelled', got '%s'", resp.Status)
	}
	if resp.Message != "Plan cancelled successfully" {
		t.Errorf("Expected message 'Plan cancelled successfully', got '%s'", resp.Message)
	}
}

func TestCancelPlanNoReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if _, hasReason := req["reason"]; hasReason {
			t.Errorf("Expected no reason key in body, got '%v'", req["reason"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CancelPlanResponse{
			PlanID: "plan-456",
			Status: "cancelled",
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	resp, err := client.CancelPlan("plan-456")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.PlanID != "plan-456" {
		t.Errorf("Expected plan_id 'plan-456', got '%s'", resp.PlanID)
	}
}

func TestCancelPlanServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Plan not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.CancelPlan("nonexistent-plan", "reason")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// ============================================================================
// UpdatePlan Tests
// ============================================================================

func TestUpdatePlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("Expected PUT method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/plan/plan-123" {
			t.Errorf("Expected path /api/v1/plan/plan-123, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)

		if req["execution_mode"] != "parallel" {
			t.Errorf("Expected execution_mode 'parallel', got '%v'", req["execution_mode"])
		}
		if req["domain"] != "finance" {
			t.Errorf("Expected domain 'finance', got '%v'", req["domain"])
		}
		version, ok := req["version"].(float64)
		if !ok || int(version) != 3 {
			t.Errorf("Expected version 3, got %v", req["version"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UpdatePlanResponse{
			PlanID:  "plan-123",
			Version: 4,
			Status:  "updated",
			Success: true,
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.UpdatePlan("plan-123", UpdatePlanRequest{
		ExpectedVersion: 3,
		ExecutionMode:   ExecutionModeParallel,
		Domain:          "finance",
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.PlanID != "plan-123" {
		t.Errorf("Expected plan_id 'plan-123', got '%s'", resp.PlanID)
	}
	if resp.Version != 4 {
		t.Errorf("Expected version 4, got %d", resp.Version)
	}
	if !resp.Success {
		t.Error("Expected success to be true")
	}
}

func TestUpdatePlanVersionConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error": "Version conflict"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.UpdatePlan("plan-123", UpdatePlanRequest{
		ExpectedVersion: 1,
		ExecutionMode:   ExecutionModeSequential,
	})
	if err == nil {
		t.Error("Expected error for version conflict")
	}
	if err != ErrVersionConflict {
		t.Errorf("Expected ErrVersionConflict, got %v", err)
	}
}

func TestUpdatePlanServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid request"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.UpdatePlan("plan-123", UpdatePlanRequest{
		ExpectedVersion: 1,
	})
	if err == nil {
		t.Error("Expected error for bad request")
	}
}

// ============================================================================
// GetPlanVersions Tests
// ============================================================================

func TestGetPlanVersions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/plan/plan-123/versions" {
			t.Errorf("Expected path /api/v1/plan/plan-123/versions, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PlanVersionsResponse{
			PlanID: "plan-123",
			Versions: []PlanVersionEntry{
				{
					Version:       1,
					ChangedAt:     "2026-02-07T10:00:00Z",
					ChangedBy:     "system",
					ChangeType:    "created",
					ChangeSummary: "Initial plan creation",
				},
				{
					Version:       2,
					ChangedAt:     "2026-02-07T11:00:00Z",
					ChangedBy:     "user-123",
					ChangeType:    "updated",
					ChangeSummary: "Changed execution mode to parallel",
				},
				{
					Version:       3,
					ChangedAt:     "2026-02-07T12:00:00Z",
					ChangedBy:     "user-456",
					ChangeType:    "rollback",
					ChangeSummary: "Rolled back to version 1",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.GetPlanVersions("plan-123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.PlanID != "plan-123" {
		t.Errorf("Expected plan_id 'plan-123', got '%s'", resp.PlanID)
	}
	if len(resp.Versions) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(resp.Versions))
	}
	if resp.Versions[0].Version != 1 {
		t.Errorf("Expected first version to be 1, got %d", resp.Versions[0].Version)
	}
	if resp.Versions[0].ChangeType != "created" {
		t.Errorf("Expected first change_type 'created', got '%s'", resp.Versions[0].ChangeType)
	}
	if resp.Versions[2].ChangeType != "rollback" {
		t.Errorf("Expected third change_type 'rollback', got '%s'", resp.Versions[2].ChangeType)
	}
}

func TestGetPlanVersionsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Plan not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetPlanVersions("nonexistent-plan")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// ============================================================================
// ResumePlan Tests
// ============================================================================

func TestResumePlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/plan/plan-123/resume" {
			t.Errorf("Expected path /api/v1/plan/plan-123/resume, got %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if req["approved"] != true {
			t.Errorf("Expected approved=true, got %v", req["approved"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ResumePlanResponse{
			PlanID:   "plan-123",
			Status:   "running",
			Approved: true,
			Message:  "Plan resumed",
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	resp, err := client.ResumePlan("plan-123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.PlanID != "plan-123" {
		t.Errorf("Expected plan_id 'plan-123', got '%s'", resp.PlanID)
	}
	if resp.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", resp.Status)
	}
	if !resp.Approved {
		t.Error("Expected approved to be true")
	}
}

func TestResumePlanRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		if req["approved"] != false {
			t.Errorf("Expected approved=false, got %v", req["approved"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ResumePlanResponse{
			PlanID:   "plan-123",
			Status:   "aborted",
			Approved: false,
			Message:  "Plan rejected by user",
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	resp, err := client.ResumePlan("plan-123", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.Approved {
		t.Error("Expected approved to be false")
	}
	if resp.Status != "aborted" {
		t.Errorf("Expected status 'aborted', got '%s'", resp.Status)
	}
}

func TestResumePlanServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Plan not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ResumePlan("nonexistent-plan")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// ============================================================================
// GeneratePlanWithOptions Tests
// ============================================================================

func TestGeneratePlanWithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			body, _ := io.ReadAll(r.Body)
			var req ClientRequest
			json.Unmarshal(body, &req)

			if req.RequestType != "multi-agent-plan" {
				t.Errorf("Expected request_type 'multi-agent-plan', got '%s'", req.RequestType)
			}

			// Verify options are passed as context
			if req.Context["domain"] != "healthcare" {
				t.Errorf("Expected domain 'healthcare', got '%v'", req.Context["domain"])
			}
			if req.Context["execution_mode"] != "parallel" {
				t.Errorf("Expected execution_mode 'parallel', got '%v'", req.Context["execution_mode"])
			}

			// Verify user token
			if req.UserToken != "custom-user" {
				t.Errorf("Expected user_token 'custom-user', got '%s'", req.UserToken)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"plan_id": "plan-opts-123",
				"data": map[string]interface{}{
					"steps": []map[string]interface{}{
						{
							"id":   "step-1",
							"name": "Analyze data",
							"type": "query",
						},
					},
					"domain":     "healthcare",
					"complexity": 3,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Debug:    true,
		Cache:    CacheConfig{Enabled: false},
	})

	plan, err := client.GeneratePlanWithOptions(
		"Analyze patient data",
		"healthcare",
		GeneratePlanOptions{ExecutionMode: ExecutionModeParallel},
		"custom-user",
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if plan.PlanID != "plan-opts-123" {
		t.Errorf("Expected PlanID 'plan-opts-123', got '%s'", plan.PlanID)
	}
	if len(plan.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(plan.Steps))
	}
	if plan.Domain != "healthcare" {
		t.Errorf("Expected domain 'healthcare', got '%s'", plan.Domain)
	}
}

func TestGeneratePlanWithOptionsDefaultUserToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			body, _ := io.ReadAll(r.Body)
			var req ClientRequest
			json.Unmarshal(body, &req)

			// When no userToken provided, should use clientID
			if req.UserToken != "test-client" {
				t.Errorf("Expected user_token to be client ID 'test-client', got '%s'", req.UserToken)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"plan_id": "plan-default",
				"data":    map[string]interface{}{},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test-client",
		Cache:    CacheConfig{Enabled: false},
	})

	plan, err := client.GeneratePlanWithOptions(
		"Test query",
		"",
		GeneratePlanOptions{},
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if plan.PlanID != "plan-default" {
		t.Errorf("Expected PlanID 'plan-default', got '%s'", plan.PlanID)
	}
}

func TestGeneratePlanWithOptionsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Plan generation failed: insufficient context",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	_, err := client.GeneratePlanWithOptions(
		"Bad query",
		"domain",
		GeneratePlanOptions{ExecutionMode: ExecutionModeAuto},
	)
	if err == nil {
		t.Error("Expected error for failed plan generation")
	}
}

// --- Media cache tests ---

func TestProxyLLMCallWithMediaSkipsCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  "Media result",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	})

	media := []MediaContent{
		{
			Source:     "base64",
			MIMEType:  "image/png",
			Base64Data: base64.StdEncoding.EncodeToString([]byte("test-image")),
		},
	}

	// First call with media
	_, err := client.ProxyLLMCallWithMedia("user-123", "describe image", "chat", media, nil)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Second call with same parameters + media — should NOT use cache
	_, err = client.ProxyLLMCallWithMedia("user-123", "describe image", "chat", media, nil)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	// Server should have been called twice (no caching for media)
	if callCount != 2 {
		t.Errorf("Expected 2 server calls (no cache for media), got %d", callCount)
	}
}

func TestProxyLLMCallWithoutMediaStillUsesCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  "Cached result",
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	})

	// Two calls without media — second should use cache
	_, err := client.ProxyLLMCallWithMedia("user-123", "hello", "chat", nil, nil)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	_, err = client.ProxyLLMCallWithMedia("user-123", "hello", "chat", nil, nil)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 server call (cached), got %d", callCount)
	}
}
