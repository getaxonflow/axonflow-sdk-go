package axonflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetCircuitBreakerStatus tests the GetCircuitBreakerStatus method
func TestGetCircuitBreakerStatus(t *testing.T) {
	t.Run("success with active circuits", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/circuit-breaker/status" {
				t.Errorf("expected path /api/v1/circuit-breaker/status, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"active_circuits": []map[string]interface{}{
						{
							"id":              "cb-1",
							"scope":           "provider",
							"scope_id":        "openai",
							"org_id":          "org-123",
							"state":           "open",
							"trip_reason":     "error_threshold",
							"tripped_by":      "system",
							"tripped_at":      "2026-03-16T10:00:00Z",
							"expires_at":      "2026-03-16T10:30:00Z",
							"error_count":     15,
							"violation_count": 0,
						},
						{
							"id":              "cb-2",
							"scope":           "tenant",
							"scope_id":        "tenant-abc",
							"org_id":          "org-123",
							"state":           "open",
							"trip_reason":     "violation_threshold",
							"tripped_by":      "admin@example.com",
							"tripped_at":      "2026-03-16T09:45:00Z",
							"error_count":     3,
							"violation_count": 10,
						},
					},
					"count":                 2,
					"emergency_stop_active": false,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		status, err := client.GetCircuitBreakerStatus(context.Background())
		if err != nil {
			t.Fatalf("GetCircuitBreakerStatus failed: %v", err)
		}

		if status.Count != 2 {
			t.Errorf("expected count 2, got %d", status.Count)
		}
		if status.EmergencyStopActive {
			t.Error("expected emergency_stop_active false")
		}
		if len(status.ActiveCircuits) != 2 {
			t.Fatalf("expected 2 active circuits, got %d", len(status.ActiveCircuits))
		}
		if status.ActiveCircuits[0].ID != "cb-1" {
			t.Errorf("expected first circuit ID cb-1, got %s", status.ActiveCircuits[0].ID)
		}
		if status.ActiveCircuits[0].Scope != "provider" {
			t.Errorf("expected scope provider, got %s", status.ActiveCircuits[0].Scope)
		}
		if status.ActiveCircuits[0].TripReason != "error_threshold" {
			t.Errorf("expected trip_reason error_threshold, got %s", status.ActiveCircuits[0].TripReason)
		}
		if status.ActiveCircuits[1].ViolationCount != 10 {
			t.Errorf("expected violation_count 10, got %d", status.ActiveCircuits[1].ViolationCount)
		}
	})

	t.Run("success with no active circuits", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"active_circuits":       []interface{}{},
					"count":                 0,
					"emergency_stop_active": false,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		status, err := client.GetCircuitBreakerStatus(context.Background())
		if err != nil {
			t.Fatalf("GetCircuitBreakerStatus failed: %v", err)
		}

		if status.Count != 0 {
			t.Errorf("expected count 0, got %d", status.Count)
		}
		if len(status.ActiveCircuits) != 0 {
			t.Errorf("expected 0 active circuits, got %d", len(status.ActiveCircuits))
		}
	})

	t.Run("includes auth headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client:my-secret"))
			if authHeader != expectedAuth {
				t.Errorf("expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"active_circuits":       []interface{}{},
					"count":                 0,
					"emergency_stop_active": false,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "my-client",
			ClientSecret: "my-secret",
		})

		_, err := client.GetCircuitBreakerStatus(context.Background())
		if err != nil {
			t.Fatalf("GetCircuitBreakerStatus failed: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetCircuitBreakerStatus(context.Background())
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

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{Endpoint: "http://localhost:99999"})

		_, err := client.GetCircuitBreakerStatus(context.Background())
		if err == nil {
			t.Fatal("expected network error")
		}
	})
}

// TestGetCircuitBreakerHistory tests the GetCircuitBreakerHistory method
func TestGetCircuitBreakerHistory(t *testing.T) {
	t.Run("success with history entries", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/circuit-breaker/history" {
				t.Errorf("expected path /api/v1/circuit-breaker/history, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"history": []map[string]interface{}{
						{
							"id":               "cbh-1",
							"org_id":           "org-123",
							"scope":            "provider",
							"scope_id":         "openai",
							"state":            "open",
							"trip_reason":      "error_threshold",
							"tripped_by":       "system",
							"tripped_by_email": "",
							"trip_comment":     "Auto-tripped: 15 errors in 60s window",
							"tripped_at":       "2026-03-16T10:00:00Z",
							"expires_at":       "2026-03-16T10:30:00Z",
							"reset_by":         "admin@example.com",
							"reset_at":         "2026-03-16T10:15:00Z",
							"error_count":      15,
							"violation_count":  0,
						},
					},
					"count": 1,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		history, err := client.GetCircuitBreakerHistory(context.Background(), 0)
		if err != nil {
			t.Fatalf("GetCircuitBreakerHistory failed: %v", err)
		}

		if history.Count != 1 {
			t.Errorf("expected count 1, got %d", history.Count)
		}
		if len(history.History) != 1 {
			t.Fatalf("expected 1 history entry, got %d", len(history.History))
		}
		entry := history.History[0]
		if entry.ID != "cbh-1" {
			t.Errorf("expected ID cbh-1, got %s", entry.ID)
		}
		if entry.TripComment != "Auto-tripped: 15 errors in 60s window" {
			t.Errorf("unexpected trip_comment: %s", entry.TripComment)
		}
		if entry.ResetBy != "admin@example.com" {
			t.Errorf("expected reset_by admin@example.com, got %s", entry.ResetBy)
		}
	})

	t.Run("limit query param", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limitParam := r.URL.Query().Get("limit")
			if limitParam != "25" {
				t.Errorf("expected limit=25, got %s", limitParam)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"history": []interface{}{},
					"count":   0,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetCircuitBreakerHistory(context.Background(), 25)
		if err != nil {
			t.Fatalf("GetCircuitBreakerHistory failed: %v", err)
		}
	})

	t.Run("no limit param when zero", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "" {
				t.Errorf("expected no query params, got %s", r.URL.RawQuery)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"history": []interface{}{},
					"count":   0,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetCircuitBreakerHistory(context.Background(), 0)
		if err != nil {
			t.Fatalf("GetCircuitBreakerHistory failed: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetCircuitBreakerHistory(context.Background(), 10)
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

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{Endpoint: "http://localhost:99999"})

		_, err := client.GetCircuitBreakerHistory(context.Background(), 0)
		if err == nil {
			t.Fatal("expected network error")
		}
	})
}

// TestGetCircuitBreakerConfig tests the GetCircuitBreakerConfig method
func TestGetCircuitBreakerConfig(t *testing.T) {
	t.Run("global config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/circuit-breaker/config" {
				t.Errorf("expected path /api/v1/circuit-breaker/config, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}
			if r.URL.RawQuery != "" {
				t.Errorf("expected no query params for global config, got %s", r.URL.RawQuery)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"source":                  "global",
					"error_threshold":         10,
					"violation_threshold":     5,
					"window_seconds":          60,
					"default_timeout_seconds": 300,
					"max_timeout_seconds":     3600,
					"enable_auto_recovery":    true,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		config, err := client.GetCircuitBreakerConfig(context.Background(), "")
		if err != nil {
			t.Fatalf("GetCircuitBreakerConfig failed: %v", err)
		}

		if config.Source != "global" {
			t.Errorf("expected source global, got %s", config.Source)
		}
		if config.ErrorThreshold != 10 {
			t.Errorf("expected error_threshold 10, got %d", config.ErrorThreshold)
		}
		if config.ViolationThreshold != 5 {
			t.Errorf("expected violation_threshold 5, got %d", config.ViolationThreshold)
		}
		if config.WindowSeconds != 60 {
			t.Errorf("expected window_seconds 60, got %d", config.WindowSeconds)
		}
		if config.DefaultTimeoutSeconds != 300 {
			t.Errorf("expected default_timeout_seconds 300, got %d", config.DefaultTimeoutSeconds)
		}
		if config.MaxTimeoutSeconds != 3600 {
			t.Errorf("expected max_timeout_seconds 3600, got %d", config.MaxTimeoutSeconds)
		}
		if !config.EnableAutoRecovery {
			t.Error("expected enable_auto_recovery true")
		}
	})

	t.Run("tenant-specific config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := r.URL.Query().Get("tenant_id")
			if tenantID != "tenant-abc" {
				t.Errorf("expected tenant_id=tenant-abc, got %s", tenantID)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"source":                  "tenant",
					"error_threshold":         20,
					"violation_threshold":     10,
					"window_seconds":          120,
					"default_timeout_seconds": 600,
					"max_timeout_seconds":     7200,
					"enable_auto_recovery":    false,
					"tenant_id":               "tenant-abc",
					"overrides": map[string]interface{}{
						"error_threshold": 20,
					},
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		config, err := client.GetCircuitBreakerConfig(context.Background(), "tenant-abc")
		if err != nil {
			t.Fatalf("GetCircuitBreakerConfig failed: %v", err)
		}

		if config.Source != "tenant" {
			t.Errorf("expected source tenant, got %s", config.Source)
		}
		if config.TenantID != "tenant-abc" {
			t.Errorf("expected tenant_id tenant-abc, got %s", config.TenantID)
		}
		if config.ErrorThreshold != 20 {
			t.Errorf("expected error_threshold 20, got %d", config.ErrorThreshold)
		}
		if config.Overrides == nil {
			t.Fatal("expected non-nil overrides")
		}
	})

	t.Run("tenant_id with special characters is escaped", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := r.URL.Query().Get("tenant_id")
			if tenantID != "tenant with spaces" {
				t.Errorf("expected tenant_id 'tenant with spaces', got '%s'", tenantID)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"source":                  "global",
					"error_threshold":         10,
					"violation_threshold":     5,
					"window_seconds":          60,
					"default_timeout_seconds": 300,
					"max_timeout_seconds":     3600,
					"enable_auto_recovery":    true,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetCircuitBreakerConfig(context.Background(), "tenant with spaces")
		if err != nil {
			t.Fatalf("GetCircuitBreakerConfig failed: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetCircuitBreakerConfig(context.Background(), "")
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

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{Endpoint: "http://localhost:99999"})

		_, err := client.GetCircuitBreakerConfig(context.Background(), "")
		if err == nil {
			t.Fatal("expected network error")
		}
	})
}

// TestUpdateCircuitBreakerConfig tests the UpdateCircuitBreakerConfig method
func TestUpdateCircuitBreakerConfig(t *testing.T) {
	t.Run("success with all fields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/circuit-breaker/config" {
				t.Errorf("expected path /api/v1/circuit-breaker/config, got %s", r.URL.Path)
			}
			if r.Method != "PUT" {
				t.Errorf("expected method PUT, got %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}

			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}

			if reqBody["tenant_id"] != "tenant-abc" {
				t.Errorf("expected tenant_id tenant-abc, got %v", reqBody["tenant_id"])
			}
			if reqBody["error_threshold"].(float64) != 20 {
				t.Errorf("expected error_threshold 20, got %v", reqBody["error_threshold"])
			}
			if reqBody["violation_threshold"].(float64) != 10 {
				t.Errorf("expected violation_threshold 10, got %v", reqBody["violation_threshold"])
			}
			if reqBody["window_seconds"].(float64) != 120 {
				t.Errorf("expected window_seconds 120, got %v", reqBody["window_seconds"])
			}
			if reqBody["enable_auto_recovery"] != true {
				t.Errorf("expected enable_auto_recovery true, got %v", reqBody["enable_auto_recovery"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"tenant_id": "tenant-abc",
					"message":   "Circuit breaker config updated for tenant",
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		errThreshold := 20
		violThreshold := 10
		window := 120
		autoRecovery := true
		result, err := client.UpdateCircuitBreakerConfig(context.Background(), CircuitBreakerConfigUpdate{
			TenantID:           "tenant-abc",
			ErrorThreshold:     &errThreshold,
			ViolationThreshold: &violThreshold,
			WindowSeconds:      &window,
			EnableAutoRecovery: &autoRecovery,
		})
		if err != nil {
			t.Fatalf("UpdateCircuitBreakerConfig failed: %v", err)
		}

		if result.TenantID != "tenant-abc" {
			t.Errorf("expected tenant_id tenant-abc, got %s", result.TenantID)
		}
		if result.Message == "" {
			t.Error("expected non-empty message")
		}
	})

	t.Run("success with partial update", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody["tenant_id"] != "tenant-xyz" {
				t.Errorf("expected tenant_id tenant-xyz, got %v", reqBody["tenant_id"])
			}
			// Only error_threshold should be present
			if reqBody["error_threshold"].(float64) != 5 {
				t.Errorf("expected error_threshold 5, got %v", reqBody["error_threshold"])
			}
			// Other optional fields should not be present
			if _, exists := reqBody["violation_threshold"]; exists {
				t.Errorf("expected violation_threshold to be omitted")
			}
			if _, exists := reqBody["window_seconds"]; exists {
				t.Errorf("expected window_seconds to be omitted")
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"tenant_id": "tenant-xyz",
					"message":   "Circuit breaker config updated for tenant",
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		threshold := 5
		_, err := client.UpdateCircuitBreakerConfig(context.Background(), CircuitBreakerConfigUpdate{
			TenantID:       "tenant-xyz",
			ErrorThreshold: &threshold,
		})
		if err != nil {
			t.Fatalf("UpdateCircuitBreakerConfig failed: %v", err)
		}
	})

	t.Run("empty tenant_id returns error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{
			Endpoint: "http://localhost:8080",
		})

		threshold := 10
		_, err := client.UpdateCircuitBreakerConfig(context.Background(), CircuitBreakerConfigUpdate{
			ErrorThreshold: &threshold,
		})
		if err == nil {
			t.Fatal("expected error for empty tenant_id")
		}
		if err.Error() != "tenant_id is required" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("includes auth headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client:my-secret"))
			if authHeader != expectedAuth {
				t.Errorf("expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"source":                  "tenant",
					"error_threshold":         10,
					"violation_threshold":     5,
					"window_seconds":          60,
					"default_timeout_seconds": 300,
					"max_timeout_seconds":     3600,
					"enable_auto_recovery":    true,
					"tenant_id":               "tenant-abc",
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "my-client",
			ClientSecret: "my-secret",
		})

		threshold := 10
		_, err := client.UpdateCircuitBreakerConfig(context.Background(), CircuitBreakerConfigUpdate{
			TenantID:       "tenant-abc",
			ErrorThreshold: &threshold,
		})
		if err != nil {
			t.Fatalf("UpdateCircuitBreakerConfig failed: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		threshold := 10
		_, err := client.UpdateCircuitBreakerConfig(context.Background(), CircuitBreakerConfigUpdate{
			TenantID:       "tenant-abc",
			ErrorThreshold: &threshold,
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

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{Endpoint: "http://localhost:99999"})

		threshold := 10
		_, err := client.UpdateCircuitBreakerConfig(context.Background(), CircuitBreakerConfigUpdate{
			TenantID:       "tenant-abc",
			ErrorThreshold: &threshold,
		})
		if err == nil {
			t.Fatal("expected network error")
		}
	})
}

// TestCircuitBreakerDebugMode tests that debug logging works without panic
func TestCircuitBreakerDebugMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"active_circuits":       []interface{}{},
				"count":                 0,
				"emergency_stop_active": false,
			},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		Debug:    true,
	})

	_, err := client.GetCircuitBreakerStatus(context.Background())
	if err != nil {
		t.Fatalf("GetCircuitBreakerStatus with debug failed: %v", err)
	}
}
