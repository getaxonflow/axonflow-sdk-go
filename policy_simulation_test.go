package axonflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSimulatePolicies tests the SimulatePolicies method
func TestSimulatePolicies(t *testing.T) {
	t.Run("success with applied policies", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/policies/simulate" {
				t.Errorf("expected path /api/v1/policies/simulate, got %s", r.URL.Path)
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

			if reqBody["query"] != "SELECT * FROM users WHERE ssn = '123-45-6789'" {
				t.Errorf("unexpected query: %v", reqBody["query"])
			}
			if reqBody["request_type"] != "sql" {
				t.Errorf("expected request_type sql, got %v", reqBody["request_type"])
			}
			user, ok := reqBody["user"].(map[string]interface{})
			if !ok {
				t.Fatal("expected user map in request body")
			}
			if user["role"] != "analyst" {
				t.Errorf("expected user role analyst, got %v", user["role"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"allowed":            false,
				"applied_policies":   []string{"sys_pii_ssn", "sql_injection_block"},
				"risk_score":         0.92,
				"required_actions":   []string{"redact_pii", "block_query"},
				"processing_time_ms": 45,
				"total_policies":     12,
				"dry_run":            true,
				"simulated_at":       "2026-03-24T10:00:00Z",
				"tier":               "evaluation",
				"daily_usage": map[string]interface{}{
					"used":  3,
					"limit": 100,
				},
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		result, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query:       "SELECT * FROM users WHERE ssn = '123-45-6789'",
			RequestType: "sql",
			User:        map[string]interface{}{"role": "analyst"},
		})
		if err != nil {
			t.Fatalf("SimulatePolicies failed: %v", err)
		}

		if result.Allowed {
			t.Error("expected allowed false")
		}
		if len(result.AppliedPolicies) != 2 {
			t.Fatalf("expected 2 applied policies, got %d", len(result.AppliedPolicies))
		}
		if result.AppliedPolicies[0] != "sys_pii_ssn" {
			t.Errorf("expected first policy sys_pii_ssn, got %s", result.AppliedPolicies[0])
		}
		if result.AppliedPolicies[1] != "sql_injection_block" {
			t.Errorf("expected second policy sql_injection_block, got %s", result.AppliedPolicies[1])
		}
		if result.RiskScore != 0.92 {
			t.Errorf("expected risk_score 0.92, got %f", result.RiskScore)
		}
		if len(result.RequiredActions) != 2 {
			t.Fatalf("expected 2 required actions, got %d", len(result.RequiredActions))
		}
		if result.ProcessingTimeMs != 45 {
			t.Errorf("expected processing_time_ms 45, got %d", result.ProcessingTimeMs)
		}
		if result.TotalPolicies != 12 {
			t.Errorf("expected total_policies 12, got %d", result.TotalPolicies)
		}
		if !result.DryRun {
			t.Error("expected dry_run true")
		}
		if result.Tier != "evaluation" {
			t.Errorf("expected tier evaluation, got %s", result.Tier)
		}
		if result.DailyUsage == nil {
			t.Fatal("expected non-nil daily_usage")
		}
		if result.DailyUsage.Used != 3 {
			t.Errorf("expected daily_usage.used 3, got %d", result.DailyUsage.Used)
		}
		if result.DailyUsage.Limit != 100 {
			t.Errorf("expected daily_usage.limit 100, got %d", result.DailyUsage.Limit)
		}
	})

	t.Run("success with no violations", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"allowed":            true,
				"applied_policies":   []string{},
				"risk_score":         0.05,
				"required_actions":   []string{},
				"processing_time_ms": 12,
				"total_policies":     12,
				"dry_run":            true,
				"simulated_at":       "2026-03-24T10:01:00Z",
				"tier":               "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		result, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query: "What is the weather today?",
		})
		if err != nil {
			t.Fatalf("SimulatePolicies failed: %v", err)
		}

		if !result.Allowed {
			t.Error("expected allowed true")
		}
		if len(result.AppliedPolicies) != 0 {
			t.Errorf("expected 0 applied policies, got %d", len(result.AppliedPolicies))
		}
		if result.RiskScore != 0.05 {
			t.Errorf("expected risk_score 0.05, got %f", result.RiskScore)
		}
		if result.DailyUsage != nil {
			t.Error("expected nil daily_usage when omitted")
		}
	})

	t.Run("sends optional fields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody["query"] != "test query" {
				t.Errorf("unexpected query: %v", reqBody["query"])
			}
			if _, ok := reqBody["client"]; !ok {
				t.Error("expected client field in request body")
			}
			if _, ok := reqBody["context"]; !ok {
				t.Error("expected context field in request body")
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"allowed":            true,
				"applied_policies":   []string{},
				"risk_score":         0.0,
				"required_actions":   []string{},
				"processing_time_ms": 5,
				"total_policies":     8,
				"dry_run":            true,
				"simulated_at":       "2026-03-24T10:02:00Z",
				"tier":               "enterprise",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query:   "test query",
			Client:  map[string]interface{}{"app": "dashboard"},
			Context: map[string]interface{}{"region": "us-east-1"},
		})
		if err != nil {
			t.Fatalf("SimulatePolicies failed: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query: "test",
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

	t.Run("403 tier gating error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "policy simulation requires evaluation tier or above"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query: "test",
		})
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

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{Endpoint: "http://localhost:99999"})

		_, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query: "test",
		})
		if err == nil {
			t.Fatal("expected network error")
		}
	})

	t.Run("debug mode does not panic", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"allowed":            true,
				"applied_policies":   []string{},
				"risk_score":         0.1,
				"required_actions":   []string{},
				"processing_time_ms": 10,
				"total_policies":     5,
				"dry_run":            true,
				"simulated_at":       "2026-03-24T10:03:00Z",
				"tier":               "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
			Debug:    true,
		})

		_, err := client.SimulatePolicies(context.Background(), &SimulatePoliciesRequest{
			Query: "test",
		})
		if err != nil {
			t.Fatalf("SimulatePolicies with debug failed: %v", err)
		}
	})
}

// TestGetPolicyImpactReport tests the GetPolicyImpactReport method
func TestGetPolicyImpactReport(t *testing.T) {
	t.Run("success with mixed results", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/policies/impact-report" {
				t.Errorf("expected path /api/v1/policies/impact-report, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}

			if reqBody["policy_id"] != "policy-pii-block" {
				t.Errorf("expected policy_id policy-pii-block, got %v", reqBody["policy_id"])
			}
			inputs, ok := reqBody["inputs"].([]interface{})
			if !ok {
				t.Fatal("expected inputs array in request body")
			}
			if len(inputs) != 3 {
				t.Fatalf("expected 3 inputs, got %d", len(inputs))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"policy_id":    "policy-pii-block",
				"policy_name":  "PII Detection - Block",
				"total_inputs": 3,
				"matched":      2,
				"blocked":      1,
				"match_rate":   0.6667,
				"block_rate":   0.3333,
				"results": []map[string]interface{}{
					{
						"input_index": 0,
						"matched":     true,
						"blocked":     true,
						"actions":     []string{"block", "log_violation"},
					},
					{
						"input_index": 1,
						"matched":     true,
						"blocked":     false,
						"actions":     []string{"redact_pii"},
					},
					{
						"input_index": 2,
						"matched":     false,
						"blocked":     false,
					},
				},
				"processing_time_ms": 78,
				"generated_at":       "2026-03-24T10:05:00Z",
				"tier":               "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		report, err := client.GetPolicyImpactReport(context.Background(), &ImpactReportRequest{
			PolicyID: "policy-pii-block",
			Inputs: []ImpactReportInput{
				{Query: "My SSN is 123-45-6789", RequestType: "llm_chat"},
				{Query: "Email me at user@example.com"},
				{Query: "What is the weather today?"},
			},
		})
		if err != nil {
			t.Fatalf("GetPolicyImpactReport failed: %v", err)
		}

		if report.PolicyID != "policy-pii-block" {
			t.Errorf("expected policy_id policy-pii-block, got %s", report.PolicyID)
		}
		if report.PolicyName != "PII Detection - Block" {
			t.Errorf("expected policy_name 'PII Detection - Block', got %s", report.PolicyName)
		}
		if report.TotalInputs != 3 {
			t.Errorf("expected total_inputs 3, got %d", report.TotalInputs)
		}
		if report.Matched != 2 {
			t.Errorf("expected matched 2, got %d", report.Matched)
		}
		if report.Blocked != 1 {
			t.Errorf("expected blocked 1, got %d", report.Blocked)
		}
		if report.MatchRate != 0.6667 {
			t.Errorf("expected match_rate 0.6667, got %f", report.MatchRate)
		}
		if report.BlockRate != 0.3333 {
			t.Errorf("expected block_rate 0.3333, got %f", report.BlockRate)
		}
		if len(report.Results) != 3 {
			t.Fatalf("expected 3 results, got %d", len(report.Results))
		}

		// First result: matched and blocked
		if !report.Results[0].Matched {
			t.Error("expected result[0].matched true")
		}
		if !report.Results[0].Blocked {
			t.Error("expected result[0].blocked true")
		}
		if len(report.Results[0].Actions) != 2 {
			t.Errorf("expected 2 actions for result[0], got %d", len(report.Results[0].Actions))
		}

		// Second result: matched but not blocked
		if !report.Results[1].Matched {
			t.Error("expected result[1].matched true")
		}
		if report.Results[1].Blocked {
			t.Error("expected result[1].blocked false")
		}

		// Third result: not matched
		if report.Results[2].Matched {
			t.Error("expected result[2].matched false")
		}
		if report.Results[2].Actions != nil {
			t.Errorf("expected nil actions for result[2], got %v", report.Results[2].Actions)
		}

		if report.ProcessingTimeMs != 78 {
			t.Errorf("expected processing_time_ms 78, got %d", report.ProcessingTimeMs)
		}
		if report.Tier != "evaluation" {
			t.Errorf("expected tier evaluation, got %s", report.Tier)
		}
	})

	t.Run("success with no matches", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"policy_id":          "policy-xyz",
				"total_inputs":       1,
				"matched":            0,
				"blocked":            0,
				"match_rate":         0.0,
				"block_rate":         0.0,
				"results":            []map[string]interface{}{{"input_index": 0, "matched": false, "blocked": false}},
				"processing_time_ms": 5,
				"generated_at":       "2026-03-24T10:06:00Z",
				"tier":               "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		report, err := client.GetPolicyImpactReport(context.Background(), &ImpactReportRequest{
			PolicyID: "policy-xyz",
			Inputs:   []ImpactReportInput{{Query: "harmless text"}},
		})
		if err != nil {
			t.Fatalf("GetPolicyImpactReport failed: %v", err)
		}

		if report.Matched != 0 {
			t.Errorf("expected matched 0, got %d", report.Matched)
		}
		if report.MatchRate != 0.0 {
			t.Errorf("expected match_rate 0.0, got %f", report.MatchRate)
		}
	})

	t.Run("sends input context fields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			inputs := reqBody["inputs"].([]interface{})
			input0 := inputs[0].(map[string]interface{})
			if input0["request_type"] != "sql" {
				t.Errorf("expected request_type sql, got %v", input0["request_type"])
			}
			user := input0["user"].(map[string]interface{})
			if user["department"] != "finance" {
				t.Errorf("expected user.department finance, got %v", user["department"])
			}
			ctx := input0["context"].(map[string]interface{})
			if ctx["source"] != "dashboard" {
				t.Errorf("expected context.source dashboard, got %v", ctx["source"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"policy_id":          "policy-abc",
				"total_inputs":       1,
				"matched":            0,
				"blocked":            0,
				"match_rate":         0.0,
				"block_rate":         0.0,
				"results":            []map[string]interface{}{{"input_index": 0, "matched": false, "blocked": false}},
				"processing_time_ms": 3,
				"generated_at":       "2026-03-24T10:07:00Z",
				"tier":               "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetPolicyImpactReport(context.Background(), &ImpactReportRequest{
			PolicyID: "policy-abc",
			Inputs: []ImpactReportInput{
				{
					Query:       "SELECT balance FROM accounts",
					RequestType: "sql",
					User:        map[string]interface{}{"department": "finance"},
					Context:     map[string]interface{}{"source": "dashboard"},
				},
			},
		})
		if err != nil {
			t.Fatalf("GetPolicyImpactReport failed: %v", err)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.GetPolicyImpactReport(context.Background(), &ImpactReportRequest{
			PolicyID: "policy-123",
			Inputs:   []ImpactReportInput{{Query: "test"}},
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

		_, err := client.GetPolicyImpactReport(context.Background(), &ImpactReportRequest{
			PolicyID: "policy-123",
			Inputs:   []ImpactReportInput{{Query: "test"}},
		})
		if err == nil {
			t.Fatal("expected network error")
		}
	})

	t.Run("debug mode does not panic", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"policy_id":          "policy-abc",
				"total_inputs":       1,
				"matched":            1,
				"blocked":            0,
				"match_rate":         1.0,
				"block_rate":         0.0,
				"results":            []map[string]interface{}{{"input_index": 0, "matched": true, "blocked": false}},
				"processing_time_ms": 10,
				"generated_at":       "2026-03-24T10:08:00Z",
				"tier":               "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
			Debug:    true,
		})

		_, err := client.GetPolicyImpactReport(context.Background(), &ImpactReportRequest{
			PolicyID: "policy-abc",
			Inputs:   []ImpactReportInput{{Query: "test"}},
		})
		if err != nil {
			t.Fatalf("GetPolicyImpactReport with debug failed: %v", err)
		}
	})
}

// TestDetectPolicyConflicts tests the DetectPolicyConflicts method
func TestDetectPolicyConflicts(t *testing.T) {
	t.Run("success with conflicts found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/policies/conflicts" {
				t.Errorf("expected path /api/v1/policies/conflicts, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			// When checking all policies, policy_id should be omitted
			if _, exists := reqBody["policy_id"]; exists && reqBody["policy_id"] != "" {
				t.Errorf("expected empty or missing policy_id for all-policy check, got %v", reqBody["policy_id"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"conflicts": []map[string]interface{}{
					{
						"policy_a": map[string]interface{}{
							"id":   "policy-allow-all",
							"name": "Allow All Queries",
							"type": "allow",
						},
						"policy_b": map[string]interface{}{
							"id":   "policy-block-pii",
							"name": "Block PII",
							"type": "block",
						},
						"conflict_type":     "contradiction",
						"description":       "policy-allow-all allows queries that policy-block-pii blocks",
						"severity":          "high",
						"overlapping_field": "query",
					},
					{
						"policy_a": map[string]interface{}{
							"id":   "policy-rate-limit-10",
							"name": "Rate Limit 10/min",
							"type": "rate_limit",
						},
						"policy_b": map[string]interface{}{
							"id":   "policy-rate-limit-100",
							"name": "Rate Limit 100/min",
							"type": "rate_limit",
						},
						"conflict_type":     "overlap",
						"description":       "Both policies apply rate limiting to the same scope",
						"severity":          "medium",
						"overlapping_field": "rate_limit",
					},
				},
				"total_policies": 15,
				"conflict_count": 2,
				"checked_at":     "2026-03-24T10:10:00Z",
				"tier":           "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		result, err := client.DetectPolicyConflicts(context.Background(), "")
		if err != nil {
			t.Fatalf("DetectPolicyConflicts failed: %v", err)
		}

		if result.TotalPolicies != 15 {
			t.Errorf("expected total_policies 15, got %d", result.TotalPolicies)
		}
		if result.ConflictCount != 2 {
			t.Errorf("expected conflict_count 2, got %d", result.ConflictCount)
		}
		if len(result.Conflicts) != 2 {
			t.Fatalf("expected 2 conflicts, got %d", len(result.Conflicts))
		}
		if result.Tier != "evaluation" {
			t.Errorf("expected tier evaluation, got %s", result.Tier)
		}

		// Verify first conflict
		c0 := result.Conflicts[0]
		if c0.PolicyA.ID != "policy-allow-all" {
			t.Errorf("expected policy_a.id policy-allow-all, got %s", c0.PolicyA.ID)
		}
		if c0.PolicyA.Name != "Allow All Queries" {
			t.Errorf("expected policy_a.name 'Allow All Queries', got %s", c0.PolicyA.Name)
		}
		if c0.PolicyB.ID != "policy-block-pii" {
			t.Errorf("expected policy_b.id policy-block-pii, got %s", c0.PolicyB.ID)
		}
		if c0.ConflictType != "contradiction" {
			t.Errorf("expected conflict_type contradiction, got %s", c0.ConflictType)
		}
		if c0.Severity != "high" {
			t.Errorf("expected severity high, got %s", c0.Severity)
		}
		if c0.OverlappingField != "query" {
			t.Errorf("expected overlapping_field query, got %s", c0.OverlappingField)
		}

		// Verify second conflict
		c1 := result.Conflicts[1]
		if c1.ConflictType != "overlap" {
			t.Errorf("expected conflict_type overlap, got %s", c1.ConflictType)
		}
		if c1.Severity != "medium" {
			t.Errorf("expected severity medium, got %s", c1.Severity)
		}
	})

	t.Run("success with specific policy_id", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)

			if reqBody["policy_id"] != "policy-block-pii" {
				t.Errorf("expected policy_id policy-block-pii, got %v", reqBody["policy_id"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"conflicts": []map[string]interface{}{
					{
						"policy_a": map[string]interface{}{
							"id":   "policy-block-pii",
							"name": "Block PII",
							"type": "block",
						},
						"policy_b": map[string]interface{}{
							"id":   "policy-allow-all",
							"name": "Allow All Queries",
							"type": "allow",
						},
						"conflict_type":     "contradiction",
						"description":       "These policies contradict each other",
						"severity":          "high",
						"overlapping_field": "query",
					},
				},
				"total_policies": 15,
				"conflict_count": 1,
				"checked_at":     "2026-03-24T10:11:00Z",
				"tier":           "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		result, err := client.DetectPolicyConflicts(context.Background(), "policy-block-pii")
		if err != nil {
			t.Fatalf("DetectPolicyConflicts failed: %v", err)
		}

		if result.ConflictCount != 1 {
			t.Errorf("expected conflict_count 1, got %d", result.ConflictCount)
		}
		if result.Conflicts[0].PolicyA.ID != "policy-block-pii" {
			t.Errorf("expected policy_a.id policy-block-pii, got %s", result.Conflicts[0].PolicyA.ID)
		}
	})

	t.Run("success with no conflicts", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"conflicts":      []interface{}{},
				"total_policies": 8,
				"conflict_count": 0,
				"checked_at":     "2026-03-24T10:12:00Z",
				"tier":           "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		result, err := client.DetectPolicyConflicts(context.Background(), "")
		if err != nil {
			t.Fatalf("DetectPolicyConflicts failed: %v", err)
		}

		if result.ConflictCount != 0 {
			t.Errorf("expected conflict_count 0, got %d", result.ConflictCount)
		}
		if len(result.Conflicts) != 0 {
			t.Errorf("expected 0 conflicts, got %d", len(result.Conflicts))
		}
		if result.TotalPolicies != 8 {
			t.Errorf("expected total_policies 8, got %d", result.TotalPolicies)
		}
	})

	t.Run("server error handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal server error"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.DetectPolicyConflicts(context.Background(), "")
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

	t.Run("403 tier gating error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "conflict detection requires evaluation tier or above"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{Endpoint: server.URL})

		_, err := client.DetectPolicyConflicts(context.Background(), "policy-123")
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

	t.Run("network error", func(t *testing.T) {
		client := NewClient(AxonFlowConfig{Endpoint: "http://localhost:99999"})

		_, err := client.DetectPolicyConflicts(context.Background(), "")
		if err == nil {
			t.Fatal("expected network error")
		}
	})

	t.Run("debug mode does not panic", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"conflicts":      []interface{}{},
				"total_policies": 5,
				"conflict_count": 0,
				"checked_at":     "2026-03-24T10:13:00Z",
				"tier":           "evaluation",
			})
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint: server.URL,
			Debug:    true,
		})

		_, err := client.DetectPolicyConflicts(context.Background(), "")
		if err != nil {
			t.Fatalf("DetectPolicyConflicts with debug failed: %v", err)
		}
	})
}
