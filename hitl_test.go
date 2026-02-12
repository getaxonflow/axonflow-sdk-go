// Copyright 2026 AxonFlow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// HITL Queue API Tests
// ============================================================================

// TestListHITLQueue tests listing approval requests in the HITL queue
func TestListHITLQueue(t *testing.T) {
	envelope := hitlListEnvelope{
		Success: true,
		Data: []HITLApprovalRequest{
			{
				RequestID:           "req_001",
				OrgID:               "org_test",
				TenantID:            "tenant_test",
				ClientID:            "client_test",
				OriginalQuery:       "DROP TABLE users",
				RequestType:         "sql",
				TriggeredPolicyID:   "pol_sqli_001",
				TriggeredPolicyName: "SQL Injection Prevention",
				TriggerReason:       "Destructive SQL detected",
				Severity:            "critical",
				Status:              "pending",
				ExpiresAt:           "2026-02-13T10:00:00Z",
				CreatedAt:           "2026-02-12T10:00:00Z",
				UpdatedAt:           "2026-02-12T10:00:00Z",
			},
			{
				RequestID:           "req_002",
				OrgID:               "org_test",
				TenantID:            "tenant_test",
				ClientID:            "client_test",
				OriginalQuery:       "Access medical records",
				RequestType:         "chat",
				TriggeredPolicyID:   "pol_hipaa_001",
				TriggeredPolicyName: "HIPAA Compliance",
				TriggerReason:       "PHI access requires approval",
				Severity:            "high",
				Status:              "pending",
				ExpiresAt:           "2026-02-13T10:00:00Z",
				CreatedAt:           "2026-02-12T09:00:00Z",
				UpdatedAt:           "2026-02-12T09:00:00Z",
			},
		},
	}
	envelope.Meta.Total = 2
	envelope.Meta.Limit = 50
	envelope.Meta.Offset = 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hitl/queue" {
			t.Errorf("Expected path /api/v1/hitl/queue, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.ListHITLQueue(HITLQueueListOptions{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("Expected total 2, got %d", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(result.Items))
	}
	if result.HasMore {
		t.Error("Expected HasMore to be false")
	}
	if result.Items[0].RequestID != "req_001" {
		t.Errorf("Expected first item request_id 'req_001', got '%s'", result.Items[0].RequestID)
	}
	if result.Items[0].Severity != "critical" {
		t.Errorf("Expected first item severity 'critical', got '%s'", result.Items[0].Severity)
	}
	if result.Items[1].TriggeredPolicyName != "HIPAA Compliance" {
		t.Errorf("Expected second item policy name 'HIPAA Compliance', got '%s'", result.Items[1].TriggeredPolicyName)
	}
}

// TestListHITLQueueWithFilters tests listing with query parameters
func TestListHITLQueueWithFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if query.Get("status") != "pending" {
			t.Errorf("Expected status=pending, got %s", query.Get("status"))
		}
		if query.Get("severity") != "high,critical" {
			t.Errorf("Expected severity=high,critical, got %s", query.Get("severity"))
		}
		if query.Get("limit") != "10" {
			t.Errorf("Expected limit=10, got %s", query.Get("limit"))
		}
		if query.Get("offset") != "20" {
			t.Errorf("Expected offset=20, got %s", query.Get("offset"))
		}

		envelope := hitlListEnvelope{
			Success: true,
			Data:    []HITLApprovalRequest{},
		}
		envelope.Meta.Total = 0
		envelope.Meta.Limit = 10
		envelope.Meta.Offset = 20

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListHITLQueue(HITLQueueListOptions{
		Status:   "pending",
		Severity: "high,critical",
		Limit:    10,
		Offset:   20,
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestListHITLQueueHasMore tests the HasMore pagination flag
func TestListHITLQueueHasMore(t *testing.T) {
	envelope := hitlListEnvelope{
		Success: true,
		Data: []HITLApprovalRequest{
			{RequestID: "req_001", Status: "pending"},
		},
	}
	envelope.Meta.Total = 5
	envelope.Meta.Limit = 1
	envelope.Meta.Offset = 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	result, err := client.ListHITLQueue(HITLQueueListOptions{Limit: 1})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.HasMore {
		t.Error("Expected HasMore to be true when total > offset + items")
	}
}

// TestListHITLQueueServerError tests error handling for server errors
func TestListHITLQueueServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.ListHITLQueue(HITLQueueListOptions{})
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestGetHITLRequest tests retrieving a specific approval request
func TestGetHITLRequest(t *testing.T) {
	envelope := hitlItemEnvelope{
		Success: true,
		Data: HITLApprovalRequest{
			RequestID:           "req_abc123",
			OrgID:               "org_test",
			TenantID:            "tenant_test",
			ClientID:            "client_test",
			UserID:              "user_001",
			OriginalQuery:       "Delete all customer data",
			RequestType:         "chat",
			TriggeredPolicyID:   "pol_data_001",
			TriggeredPolicyName: "Data Deletion Policy",
			TriggerReason:       "Bulk data deletion requires approval",
			Severity:            "critical",
			ComplianceFramework: "GDPR",
			RiskClassification:  "high",
			Status:              "pending",
			ExpiresAt:           "2026-02-13T10:00:00Z",
			CreatedAt:           "2026-02-12T10:00:00Z",
			UpdatedAt:           "2026-02-12T10:00:00Z",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		expectedPath := "/api/v1/hitl/queue/req_abc123"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	request, err := client.GetHITLRequest("req_abc123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if request.RequestID != "req_abc123" {
		t.Errorf("Expected request_id 'req_abc123', got '%s'", request.RequestID)
	}
	if request.Severity != "critical" {
		t.Errorf("Expected severity 'critical', got '%s'", request.Severity)
	}
	if request.TriggeredPolicyName != "Data Deletion Policy" {
		t.Errorf("Expected policy name 'Data Deletion Policy', got '%s'", request.TriggeredPolicyName)
	}
	if request.ComplianceFramework != "GDPR" {
		t.Errorf("Expected compliance_framework 'GDPR', got '%s'", request.ComplianceFramework)
	}
	if request.UserID != "user_001" {
		t.Errorf("Expected user_id 'user_001', got '%s'", request.UserID)
	}
}

// TestGetHITLRequestEmptyID tests error when request ID is empty
func TestGetHITLRequestEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	_, err := client.GetHITLRequest("")
	if err == nil {
		t.Error("Expected error for empty request ID")
	}
}

// TestGetHITLRequestServerError tests error handling for server errors
func TestGetHITLRequestServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Request not found"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetHITLRequest("req_nonexistent")
	if err == nil {
		t.Error("Expected error for not found response")
	}
}

// TestApproveHITLRequest tests approving a pending request
func TestApproveHITLRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/hitl/queue/req_abc123/approve"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		var review HITLReviewInput
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if review.ReviewerID != "user_reviewer1" {
			t.Errorf("Expected reviewer_id 'user_reviewer1', got '%s'", review.ReviewerID)
		}
		if review.ReviewerEmail != "reviewer@example.com" {
			t.Errorf("Expected reviewer_email 'reviewer@example.com', got '%s'", review.ReviewerEmail)
		}
		if review.Comment != "Approved after review" {
			t.Errorf("Expected comment 'Approved after review', got '%s'", review.Comment)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hitlActionEnvelope{Success: true})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.ApproveHITLRequest("req_abc123", HITLReviewInput{
		ReviewerID:    "user_reviewer1",
		ReviewerEmail: "reviewer@example.com",
		Comment:       "Approved after review",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestApproveHITLRequestWithRole tests approving with optional reviewer role
func TestApproveHITLRequestWithRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review HITLReviewInput
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if review.ReviewerRole != "compliance_officer" {
			t.Errorf("Expected reviewer_role 'compliance_officer', got '%s'", review.ReviewerRole)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hitlActionEnvelope{Success: true})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.ApproveHITLRequest("req_001", HITLReviewInput{
		ReviewerID:    "user_1",
		ReviewerEmail: "user@example.com",
		ReviewerRole:  "compliance_officer",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestApproveHITLRequestEmptyID tests error when request ID is empty
func TestApproveHITLRequestEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.ApproveHITLRequest("", HITLReviewInput{
		ReviewerID:    "user_1",
		ReviewerEmail: "user@example.com",
	})
	if err == nil {
		t.Error("Expected error for empty request ID")
	}
}

// TestApproveHITLRequestServerError tests error handling for server errors
func TestApproveHITLRequestServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.ApproveHITLRequest("req_001", HITLReviewInput{
		ReviewerID:    "user_1",
		ReviewerEmail: "user@example.com",
	})
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestRejectHITLRequest tests rejecting a pending request
func TestRejectHITLRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		expectedPath := "/api/v1/hitl/queue/req_abc123/reject"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		var review HITLReviewInput
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		if review.ReviewerID != "user_reviewer1" {
			t.Errorf("Expected reviewer_id 'user_reviewer1', got '%s'", review.ReviewerID)
		}
		if review.ReviewerEmail != "reviewer@example.com" {
			t.Errorf("Expected reviewer_email 'reviewer@example.com', got '%s'", review.ReviewerEmail)
		}
		if review.Comment != "Rejected: violates compliance" {
			t.Errorf("Expected comment 'Rejected: violates compliance', got '%s'", review.Comment)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hitlActionEnvelope{Success: true})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.RejectHITLRequest("req_abc123", HITLReviewInput{
		ReviewerID:    "user_reviewer1",
		ReviewerEmail: "reviewer@example.com",
		Comment:       "Rejected: violates compliance",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestRejectHITLRequestEmptyID tests error when request ID is empty
func TestRejectHITLRequestEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	err := client.RejectHITLRequest("", HITLReviewInput{
		ReviewerID:    "user_1",
		ReviewerEmail: "user@example.com",
	})
	if err == nil {
		t.Error("Expected error for empty request ID")
	}
}

// TestRejectHITLRequestServerError tests error handling for server errors
func TestRejectHITLRequestServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	err := client.RejectHITLRequest("req_001", HITLReviewInput{
		ReviewerID:    "user_1",
		ReviewerEmail: "user@example.com",
	})
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestGetHITLStats tests retrieving HITL dashboard statistics
func TestGetHITLStats(t *testing.T) {
	oldestHours := 4.5
	envelope := hitlStatsEnvelope{
		Success: true,
		Data: HITLStats{
			TotalPending:       12,
			HighPriority:       5,
			CriticalPriority:   3,
			OldestPendingHours: &oldestHours,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hitl/stats" {
			t.Errorf("Expected path /api/v1/hitl/stats, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	stats, err := client.GetHITLStats()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if stats.TotalPending != 12 {
		t.Errorf("Expected total_pending 12, got %d", stats.TotalPending)
	}
	if stats.HighPriority != 5 {
		t.Errorf("Expected high_priority 5, got %d", stats.HighPriority)
	}
	if stats.CriticalPriority != 3 {
		t.Errorf("Expected critical_priority 3, got %d", stats.CriticalPriority)
	}
	if stats.OldestPendingHours == nil {
		t.Error("Expected oldest_pending_hours to be set")
	} else if *stats.OldestPendingHours != 4.5 {
		t.Errorf("Expected oldest_pending_hours 4.5, got %f", *stats.OldestPendingHours)
	}
}

// TestGetHITLStatsNilOldestPending tests stats with no oldest pending
func TestGetHITLStatsNilOldestPending(t *testing.T) {
	envelope := hitlStatsEnvelope{
		Success: true,
		Data: HITLStats{
			TotalPending:       0,
			HighPriority:       0,
			CriticalPriority:   0,
			OldestPendingHours: nil,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	stats, err := client.GetHITLStats()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if stats.TotalPending != 0 {
		t.Errorf("Expected total_pending 0, got %d", stats.TotalPending)
	}
	if stats.OldestPendingHours != nil {
		t.Error("Expected oldest_pending_hours to be nil")
	}
}

// TestGetHITLStatsServerError tests error handling for server errors
func TestGetHITLStatsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, err := client.GetHITLStats()
	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestHITLApprovalRequestJSON tests JSON serialization of HITLApprovalRequest
func TestHITLApprovalRequestJSON(t *testing.T) {
	reviewedAt := "2026-02-12T12:00:00Z"
	request := HITLApprovalRequest{
		RequestID:           "req_json_test",
		OrgID:               "org_1",
		TenantID:            "tenant_1",
		ClientID:            "client_1",
		UserID:              "user_1",
		OriginalQuery:       "test query",
		RequestType:         "chat",
		TriggeredPolicyID:   "pol_1",
		TriggeredPolicyName: "Test Policy",
		TriggerReason:       "Test reason",
		Severity:            "high",
		EUAIActArticle:      "Article 14",
		ComplianceFramework: "EU AI Act",
		RiskClassification:  "high-risk",
		Status:              "approved",
		ReviewerID:          "reviewer_1",
		ReviewerEmail:       "reviewer@test.com",
		ReviewComment:       "Looks good",
		ReviewedAt:          &reviewedAt,
		ExpiresAt:           "2026-02-13T10:00:00Z",
		CreatedAt:           "2026-02-12T10:00:00Z",
		UpdatedAt:           "2026-02-12T12:00:00Z",
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded HITLApprovalRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.RequestID != "req_json_test" {
		t.Errorf("Expected request_id 'req_json_test', got '%s'", decoded.RequestID)
	}
	if decoded.EUAIActArticle != "Article 14" {
		t.Errorf("Expected eu_ai_act_article 'Article 14', got '%s'", decoded.EUAIActArticle)
	}
	if decoded.ReviewedAt == nil || *decoded.ReviewedAt != "2026-02-12T12:00:00Z" {
		t.Errorf("Expected reviewed_at '2026-02-12T12:00:00Z', got %v", decoded.ReviewedAt)
	}
}

// TestHITLApprovalRequestJSONOmitEmpty tests that optional fields are omitted when empty
func TestHITLApprovalRequestJSONOmitEmpty(t *testing.T) {
	request := HITLApprovalRequest{
		RequestID:           "req_minimal",
		OrgID:               "org_1",
		TenantID:            "tenant_1",
		ClientID:            "client_1",
		OriginalQuery:       "test",
		RequestType:         "chat",
		TriggeredPolicyID:   "pol_1",
		TriggeredPolicyName: "Policy",
		TriggerReason:       "Reason",
		Severity:            "low",
		Status:              "pending",
		ExpiresAt:           "2026-02-13T10:00:00Z",
		CreatedAt:           "2026-02-12T10:00:00Z",
		UpdatedAt:           "2026-02-12T10:00:00Z",
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	// These fields should be omitted when empty
	omitFields := []string{"user_id", "request_context", "eu_ai_act_article", "compliance_framework",
		"risk_classification", "reviewer_id", "reviewer_email", "review_comment", "reviewed_at"}
	for _, field := range omitFields {
		if _, exists := raw[field]; exists {
			t.Errorf("Expected field '%s' to be omitted when empty, but it was present", field)
		}
	}
}

// TestHITLReviewInputJSON tests JSON serialization of HITLReviewInput
func TestHITLReviewInputJSON(t *testing.T) {
	review := HITLReviewInput{
		ReviewerID:    "user_1",
		ReviewerEmail: "user@example.com",
		ReviewerRole:  "admin",
		Comment:       "Approved",
	}

	data, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded HITLReviewInput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.ReviewerID != "user_1" {
		t.Errorf("Expected reviewer_id 'user_1', got '%s'", decoded.ReviewerID)
	}
	if decoded.ReviewerRole != "admin" {
		t.Errorf("Expected reviewer_role 'admin', got '%s'", decoded.ReviewerRole)
	}
}
