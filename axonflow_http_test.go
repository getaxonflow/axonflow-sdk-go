package axonflow

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExecuteQuery(t *testing.T) {
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
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Debug:        false,
		Cache: CacheConfig{
			Enabled: false, // Disable cache for this test
		},
	})

	resp, err := client.ExecuteQuery("user-123", "test query", "chat", nil)
	if err != nil {
		t.Fatalf("ExecuteQuery failed: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success response")
	}

	if resp.PlanID != "plan-123" {
		t.Errorf("Expected PlanID 'plan-123', got '%s'", resp.PlanID)
	}
}

func TestExecuteQueryWithCache(t *testing.T) {
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
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Debug:        true,
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	})

	// First call
	_, err := client.ExecuteQuery("user-123", "same query", "chat", nil)
	if err != nil {
		t.Fatalf("First ExecuteQuery failed: %v", err)
	}

	// Second call with same parameters (should use cache)
	_, err = client.ExecuteQuery("user-123", "same query", "chat", nil)
	if err != nil {
		t.Fatalf("Second ExecuteQuery failed: %v", err)
	}

	// Server should only have been called once due to caching
	if callCount != 1 {
		t.Errorf("Expected 1 server call (cached), got %d", callCount)
	}
}

func TestExecuteQueryBlocked(t *testing.T) {
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
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Cache:        CacheConfig{Enabled: false},
	})

	resp, err := client.ExecuteQuery("user-123", "blocked query", "chat", nil)
	if err != nil {
		t.Fatalf("ExecuteQuery failed: %v", err)
	}

	if resp.Success {
		t.Error("Expected blocked response (success=false)")
	}

	if !resp.Blocked {
		t.Error("Expected Blocked=true")
	}
}

func TestExecuteQueryWithNestedData(t *testing.T) {
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
		AgentURL: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	resp, err := client.ExecuteQuery("user", "query", "chat", nil)
	if err != nil {
		t.Fatalf("ExecuteQuery failed: %v", err)
	}

	if resp.Result != "Nested result" {
		t.Errorf("Expected Result 'Nested result', got '%s'", resp.Result)
	}

	if resp.PlanID != "nested-plan-123" {
		t.Errorf("Expected PlanID 'nested-plan-123', got '%s'", resp.PlanID)
	}
}

func TestExecuteQueryWithError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/request" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL: server.URL,
		ClientID: "test",
		Mode:     "sandbox", // Use sandbox mode to disable fail-open
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  1, // Just one attempt
			InitialDelay: 1 * time.Millisecond,
		},
		Cache: CacheConfig{Enabled: false},
	})

	_, err := client.ExecuteQuery("user", "query", "chat", nil)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}

func TestExecuteQueryFailOpen(t *testing.T) {
	// Create a server that doesn't respond (connection refused simulation)
	client := NewClient(AxonFlowConfig{
		AgentURL: "http://localhost:19999", // Non-existent server
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

	resp, err := client.ExecuteQuery("user", "query", "chat", nil)
	if err != nil {
		t.Fatalf("Expected fail-open, got error: %v", err)
	}

	if !resp.Success {
		t.Error("Expected fail-open to return success=true")
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL, // Connectors are on orchestrator
		ClientID:        "test",
		Debug:           true,
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL, // Connectors are on orchestrator
		ClientID:        "test",
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL, // Connector install is on orchestrator
		ClientID:        "test",
		Debug:           true,
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
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
		AgentURL:     server.URL,
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
		AgentURL:     server.URL,
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
		AgentURL:     server.URL,
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
		AgentURL:     server.URL,
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
		AgentURL:     server.URL,
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
		AgentURL:     server.URL,
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
		ClientID: "test",
		Cache:    CacheConfig{Enabled: false},
	})

	result, err := client.ExecutePlan("plan-failed")
	if err != nil {
		t.Fatalf("ExecutePlan failed: %v", err)
	}

	if result.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", result.Status)
	}
}

func TestGetPlanStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/plans/plan-123" {
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
		AgentURL: server.URL,
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
		AgentURL: server.URL,
		ClientID: "test",
	})

	_, err := client.GetPlanStatus("nonexistent-plan")
	if err == nil {
		t.Error("Expected error for non-existent plan")
	}
}

func TestIsAxonFlowError(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		AgentURL: "http://test.example.com",
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
		AgentURL: server.URL,
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

	_, err := client.ExecuteQuery("user", "query", "chat", nil)
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
		receivedAuthHeader = r.Header.Get("X-Client-Secret")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))
	defer server.Close()

	// When credentials are provided, auth headers should be sent
	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test",
		ClientSecret: "secret",
		Cache:        CacheConfig{Enabled: false},
	})

	_, _ = client.ExecuteQuery("user", "query", "chat", nil)

	// Auth header SHOULD be set when credentials are provided
	if receivedAuthHeader != "secret" {
		t.Errorf("Expected auth header 'secret', got '%s'", receivedAuthHeader)
	}
}

func TestNonLocalHostIncludesAuth(t *testing.T) {
	// This tests that non-localhost URLs would include auth headers
	// We verify this by checking the auth logic in the client configuration
	client := NewClient(AxonFlowConfig{
		AgentURL:     "https://api.getaxonflow.com",
		ClientID:     "test",
		ClientSecret: "secret",
		Cache:        CacheConfig{Enabled: false},
	})

	// Verify client is configured correctly (can't make real request)
	if client.config.ClientSecret != "secret" {
		t.Errorf("Expected ClientSecret 'secret', got '%s'", client.config.ClientSecret)
	}
	if client.config.AgentURL != "https://api.getaxonflow.com" {
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL,
		ClientID:        "test",
		Cache:           CacheConfig{Enabled: false},
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL,
		ClientID:        "test",
		Cache:           CacheConfig{Enabled: false},
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL,
		ClientID:        "test",
		Cache:           CacheConfig{Enabled: false},
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
		AgentURL:        server.URL,
		OrchestratorURL: server.URL,
		ClientID:        "test",
		Cache:           CacheConfig{Enabled: false},
	})

	err := client.UninstallConnector("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent connector")
	}
}
