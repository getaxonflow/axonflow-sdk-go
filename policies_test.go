package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Sample test data
var sampleStaticPolicy = StaticPolicy{
	ID:          "pol_123",
	Name:        "Block SQL Injection",
	Description: "Blocks SQL injection attempts",
	Category:    CategorySecuritySQLI,
	Tier:        TierSystem,
	Pattern:     "(?i)(union\\s+select|drop\\s+table)",
	Severity:    SeverityCritical,
	Enabled:     true,
	Action:      ActionBlock,
	CreatedAt:   time.Now(),
	UpdatedAt:   time.Now(),
	Version:     1,
}

var sampleDynamicPolicy = DynamicPolicy{
	ID:             "dpol_456",
	Name:           "Rate Limit API",
	Description:    "Rate limit API calls",
	Type:           "cost",
	Category:       "dynamic-cost",
	Tier:           TierTenant,
	OrganizationID: "org_acme",
	Conditions: []DynamicPolicyCondition{
		{Field: "requests_per_minute", Operator: "greater_than", Value: 100},
	},
	Actions: []DynamicPolicyAction{
		{Type: "block", Config: map[string]interface{}{"reason": "Rate limit exceeded"}},
	},
	Priority:  50,
	Enabled:   true,
	CreatedAt: time.Now(),
	UpdatedAt: time.Now(),
}

var sampleOverride = PolicyOverride{
	PolicyID:  "pol_123",
	Action:    OverrideActionWarn,
	Reason:    "Testing override",
	CreatedAt: time.Now(),
	Active:    true,
}

// TestListStaticPolicies tests listing static policies
func TestListStaticPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/static-policies" {
			t.Errorf("Expected path /api/v1/static-policies, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Return wrapped response format
		resp := map[string]interface{}{
			"policies": []StaticPolicy{sampleStaticPolicy},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policies, err := client.ListStaticPolicies(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].ID != "pol_123" {
		t.Errorf("Expected policy ID pol_123, got %s", policies[0].ID)
	}
}

// TestListStaticPoliciesWithFilters tests listing with filters
func TestListStaticPoliciesWithFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("category") != "security-sqli" {
			t.Errorf("Expected category=security-sqli, got %s", query.Get("category"))
		}
		if query.Get("tier") != "system" {
			t.Errorf("Expected tier=system, got %s", query.Get("tier"))
		}
		w.Header().Set("Content-Type", "application/json")
		// Return wrapped response format
		resp := map[string]interface{}{
			"policies": []StaticPolicy{sampleStaticPolicy},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	enabled := true
	options := &ListStaticPoliciesOptions{
		Category: CategorySecuritySQLI,
		Tier:     TierSystem,
		Enabled:  &enabled,
	}

	policies, err := client.ListStaticPolicies(options)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
}

// TestGetStaticPolicy tests getting a specific policy
func TestGetStaticPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/static-policies/pol_123" {
			t.Errorf("Expected path /api/v1/static-policies/pol_123, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleStaticPolicy)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policy, err := client.GetStaticPolicy("pol_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.ID != "pol_123" {
		t.Errorf("Expected policy ID pol_123, got %s", policy.ID)
	}
}

// TestCreateStaticPolicy tests creating a new policy
func TestCreateStaticPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleStaticPolicy)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	req := &CreateStaticPolicyRequest{
		Name:     "Block SQL Injection",
		Category: CategorySecuritySQLI,
		Pattern:  "(?i)(union\\s+select|drop\\s+table)",
		Severity: SeverityCritical,
		Enabled:  true,
	}

	policy, err := client.CreateStaticPolicy(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.ID != "pol_123" {
		t.Errorf("Expected policy ID pol_123, got %s", policy.ID)
	}
}

// TestUpdateStaticPolicy tests updating a policy
func TestUpdateStaticPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT method, got %s", r.Method)
		}
		updated := sampleStaticPolicy
		updated.Severity = SeverityHigh
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	severity := SeverityHigh
	req := &UpdateStaticPolicyRequest{
		Severity: &severity,
	}

	policy, err := client.UpdateStaticPolicy("pol_123", req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.Severity != SeverityHigh {
		t.Errorf("Expected severity high, got %s", policy.Severity)
	}
}

// TestDeleteStaticPolicy tests deleting a policy
func TestDeleteStaticPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.DeleteStaticPolicy("pol_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestToggleStaticPolicy tests toggling a policy
func TestToggleStaticPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("Expected PATCH method, got %s", r.Method)
		}
		toggled := sampleStaticPolicy
		toggled.Enabled = false
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(toggled)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policy, err := client.ToggleStaticPolicy("pol_123", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.Enabled {
		t.Errorf("Expected policy to be disabled")
	}
}

// TestGetEffectiveStaticPolicies tests getting effective policies
func TestGetEffectiveStaticPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/static-policies/effective" {
			t.Errorf("Expected path /api/v1/static-policies/effective, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Return wrapped response format with static and dynamic fields
		resp := map[string]interface{}{
			"static":  []StaticPolicy{sampleStaticPolicy},
			"dynamic": []DynamicPolicy{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policies, err := client.GetEffectiveStaticPolicies(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
}

// TestTestPattern tests pattern testing
func TestTestPattern(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		result := TestPatternResult{
			Valid: true,
			Matches: []TestPatternMatch{
				{Input: "SELECT * FROM users", Matched: true},
				{Input: "Hello world", Matched: false},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.TestPattern("(?i)select", []string{"SELECT * FROM users", "Hello world"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("Expected pattern to be valid")
	}
	if len(result.Matches) != 2 {
		t.Errorf("Expected 2 matches, got %d", len(result.Matches))
	}
}

// TestGetStaticPolicyVersions tests getting version history
func TestGetStaticPolicyVersions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/static-policies/pol_123/versions" {
			t.Errorf("Expected path /api/v1/static-policies/pol_123/versions, got %s", r.URL.Path)
		}
		response := map[string]interface{}{
			"policy_id": "pol_123",
			"versions": []PolicyVersion{
				{Version: 2, ChangeType: "updated", ChangedAt: time.Now()},
				{Version: 1, ChangeType: "created", ChangedAt: time.Now()},
			},
			"count": 2,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	versions, err := client.GetStaticPolicyVersions("pol_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}
}

// TestCreatePolicyOverride tests creating an override
func TestCreatePolicyOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/static-policies/pol_123/override" {
			t.Errorf("Expected path /api/v1/static-policies/pol_123/override, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleOverride)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	req := &CreatePolicyOverrideRequest{
		Action: OverrideActionWarn,
		Reason: "Testing override",
	}

	override, err := client.CreatePolicyOverride("pol_123", req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if override.Action != OverrideActionWarn {
		t.Errorf("Expected action warn, got %s", override.Action)
	}
}

// TestDeletePolicyOverride tests deleting an override
func TestDeletePolicyOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.DeletePolicyOverride("pol_123")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestListDynamicPolicies tests listing dynamic policies
func TestListDynamicPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dynamic policies are on orchestrator at /api/v1/dynamic-policies
		if r.URL.Path != "/api/v1/dynamic-policies" {
			t.Errorf("Expected path /api/v1/dynamic-policies, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Agent proxy (Issue #886) returns {"policies": [...]} wrapper
		resp := map[string]interface{}{
			"policies": []DynamicPolicy{sampleDynamicPolicy},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policies, err := client.ListDynamicPolicies(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
}

// TestGetDynamicPolicy tests getting a specific dynamic policy
func TestGetDynamicPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dynamic policies are on orchestrator at /api/v1/dynamic-policies/{id}
		if r.URL.Path != "/api/v1/dynamic-policies/dpol_456" {
			t.Errorf("Expected path /api/v1/dynamic-policies/dpol_456, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Agent proxy (Issue #886) returns {"policy": {...}} wrapper
		resp := map[string]interface{}{
			"policy": sampleDynamicPolicy,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policy, err := client.GetDynamicPolicy("dpol_456")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.ID != "dpol_456" {
		t.Errorf("Expected policy ID dpol_456, got %s", policy.ID)
	}
}

// TestCreateDynamicPolicy tests creating a dynamic policy
func TestCreateDynamicPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dynamic policies are on orchestrator at POST /api/v1/dynamic-policies
		if r.Method != "POST" || r.URL.Path != "/api/v1/dynamic-policies" {
			t.Errorf("Expected POST /api/v1/dynamic-policies, got %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Agent proxy (Issue #886) returns {"policy": {...}} wrapper
		resp := map[string]interface{}{
			"policy": sampleDynamicPolicy,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	req := &CreateDynamicPolicyRequest{
		Name: "Rate Limit API",
		Type: "cost",
		Conditions: []DynamicPolicyCondition{
			{Field: "requests_per_minute", Operator: "greater_than", Value: 100},
		},
		Actions: []DynamicPolicyAction{
			{Type: "block", Config: map[string]interface{}{"reason": "Rate limit exceeded"}},
		},
		Priority: 50,
		Enabled:  true,
	}

	policy, err := client.CreateDynamicPolicy(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.ID != "dpol_456" {
		t.Errorf("Expected policy ID dpol_456, got %s", policy.ID)
	}
}

// TestDeleteDynamicPolicy tests deleting a dynamic policy
func TestDeleteDynamicPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dynamic policies are on orchestrator at DELETE /api/v1/dynamic-policies/{id}
		if r.Method != "DELETE" || r.URL.Path != "/api/v1/dynamic-policies/dpol_456" {
			t.Errorf("Expected DELETE /api/v1/dynamic-policies/dpol_456, got %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.DeleteDynamicPolicy("dpol_456")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestGetEffectiveDynamicPolicies tests getting effective dynamic policies
func TestGetEffectiveDynamicPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/dynamic-policies/effective" {
			t.Errorf("Expected path /api/v1/dynamic-policies/effective, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Agent proxy (Issue #886) returns {"policies": [...]} wrapper
		resp := map[string]interface{}{
			"policies": []DynamicPolicy{sampleDynamicPolicy},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policies, err := client.GetEffectiveDynamicPolicies(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
}

// TestCreateDynamicPolicyWithTierAndOrg tests creating a dynamic policy with tier and organization_id fields
func TestCreateDynamicPolicyWithTierAndOrg(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/dynamic-policies" {
			t.Errorf("Expected POST /api/v1/dynamic-policies, got %s %s", r.Method, r.URL.Path)
		}

		// Decode request body to verify tier and organization_id are sent
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		if body["tier"] != "organization" {
			t.Errorf("Expected tier=organization in request body, got %v", body["tier"])
		}
		if body["organization_id"] != "org_enterprise_123" {
			t.Errorf("Expected organization_id=org_enterprise_123 in request body, got %v", body["organization_id"])
		}
		if body["category"] != "dynamic-compliance" {
			t.Errorf("Expected category=dynamic-compliance in request body, got %v", body["category"])
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policy": DynamicPolicy{
				ID:             "dpol_org_789",
				Name:           "GDPR Compliance Check",
				Description:    "Enforce GDPR data residency",
				Type:           "content",
				Category:       "dynamic-compliance",
				Tier:           TierOrganization,
				OrganizationID: "org_enterprise_123",
				Priority:       10,
				Enabled:        true,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	req := &CreateDynamicPolicyRequest{
		Name:           "GDPR Compliance Check",
		Description:    "Enforce GDPR data residency",
		Type:           "content",
		Category:       "dynamic-compliance",
		Tier:           TierOrganization,
		OrganizationID: "org_enterprise_123",
		Conditions: []DynamicPolicyCondition{
			{Field: "data_region", Operator: "not_in", Value: []string{"eu-west-1", "eu-central-1"}},
		},
		Actions: []DynamicPolicyAction{
			{Type: "block", Config: map[string]interface{}{"reason": "GDPR: data must stay in EU"}},
		},
		Priority: 10,
		Enabled:  true,
	}

	policy, err := client.CreateDynamicPolicy(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.ID != "dpol_org_789" {
		t.Errorf("Expected policy ID dpol_org_789, got %s", policy.ID)
	}
	if policy.Tier != TierOrganization {
		t.Errorf("Expected tier organization, got %s", policy.Tier)
	}
	if policy.OrganizationID != "org_enterprise_123" {
		t.Errorf("Expected organization_id org_enterprise_123, got %s", policy.OrganizationID)
	}
}

// TestCreateDynamicPolicyDefaultTier tests that CreateDynamicPolicy defaults to TierTenant when tier is not specified
func TestCreateDynamicPolicyDefaultTier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decode request body to verify default tier is set
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		if body["tier"] != "tenant" {
			t.Errorf("Expected default tier=tenant in request body, got %v", body["tier"])
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policy": sampleDynamicPolicy,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	// Do NOT set Tier - should default to TierTenant
	req := &CreateDynamicPolicyRequest{
		Name:     "Default Tier Policy",
		Type:     "risk",
		Priority: 50,
		Enabled:  true,
	}

	policy, err := client.CreateDynamicPolicy(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.ID != "dpol_456" {
		t.Errorf("Expected policy ID dpol_456, got %s", policy.ID)
	}
	// Verify the request object was mutated to have default tier
	if req.Tier != TierTenant {
		t.Errorf("Expected req.Tier to be set to tenant after call, got %s", req.Tier)
	}
}

// TestUpdateDynamicPolicyWithTier tests updating a dynamic policy with tier pointer set
func TestUpdateDynamicPolicyWithTier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/v1/dynamic-policies/dpol_456" {
			t.Errorf("Expected PUT /api/v1/dynamic-policies/dpol_456, got %s %s", r.Method, r.URL.Path)
		}

		// Decode request body to verify tier and organization_id are sent
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		if body["tier"] != "organization" {
			t.Errorf("Expected tier=organization in update body, got %v", body["tier"])
		}
		if body["organization_id"] != "org_updated_456" {
			t.Errorf("Expected organization_id=org_updated_456, got %v", body["organization_id"])
		}

		w.Header().Set("Content-Type", "application/json")
		updated := sampleDynamicPolicy
		updated.Tier = TierOrganization
		updated.OrganizationID = "org_updated_456"
		resp := map[string]interface{}{
			"policy": updated,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	orgTier := TierOrganization
	orgID := "org_updated_456"
	newName := "Updated Rate Limiter"
	req := &UpdateDynamicPolicyRequest{
		Name:           &newName,
		Tier:           &orgTier,
		OrganizationID: &orgID,
	}

	policy, err := client.UpdateDynamicPolicy("dpol_456", req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.Tier != TierOrganization {
		t.Errorf("Expected tier organization, got %s", policy.Tier)
	}
	if policy.OrganizationID != "org_updated_456" {
		t.Errorf("Expected organization_id org_updated_456, got %s", policy.OrganizationID)
	}
}

// TestDynamicPolicyResponseDeserialization tests that DynamicPolicy correctly deserializes tier and organization_id from JSON
func TestDynamicPolicyResponseDeserialization(t *testing.T) {
	jsonData := `{
		"id": "dpol_deser_001",
		"name": "Deserialization Test",
		"description": "Test tier deserialization",
		"type": "risk",
		"category": "dynamic-risk",
		"tier": "system",
		"organization_id": "org_sys_global",
		"conditions": [{"field": "risk_score", "operator": "greater_than", "value": 90}],
		"actions": [{"type": "block", "config": {"reason": "High risk"}}],
		"priority": 1,
		"enabled": true,
		"version": 3,
		"tenant_id": "tenant_abc",
		"created_at": "2026-01-15T10:00:00Z",
		"updated_at": "2026-02-01T12:00:00Z"
	}`

	var policy DynamicPolicy
	err := json.Unmarshal([]byte(jsonData), &policy)
	if err != nil {
		t.Fatalf("Failed to unmarshal DynamicPolicy: %v", err)
	}

	if policy.ID != "dpol_deser_001" {
		t.Errorf("Expected ID dpol_deser_001, got %s", policy.ID)
	}
	if policy.Tier != TierSystem {
		t.Errorf("Expected tier system, got %s", policy.Tier)
	}
	if policy.OrganizationID != "org_sys_global" {
		t.Errorf("Expected organization_id org_sys_global, got %s", policy.OrganizationID)
	}
	if policy.Category != "dynamic-risk" {
		t.Errorf("Expected category dynamic-risk, got %s", policy.Category)
	}
	if policy.Version != 3 {
		t.Errorf("Expected version 3, got %d", policy.Version)
	}
	if policy.TenantID != "tenant_abc" {
		t.Errorf("Expected tenant_id tenant_abc, got %s", policy.TenantID)
	}
	if len(policy.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(policy.Conditions))
	}
	if len(policy.Actions) != 1 {
		t.Errorf("Expected 1 action, got %d", len(policy.Actions))
	}
}

// TestDynamicPolicyResponseDeserializationEmptyTier tests DynamicPolicy with no tier field (omitempty)
func TestDynamicPolicyResponseDeserializationEmptyTier(t *testing.T) {
	jsonData := `{
		"id": "dpol_notier",
		"name": "No Tier Policy",
		"type": "content",
		"priority": 5,
		"enabled": true,
		"created_at": "2026-01-15T10:00:00Z",
		"updated_at": "2026-02-01T12:00:00Z"
	}`

	var policy DynamicPolicy
	err := json.Unmarshal([]byte(jsonData), &policy)
	if err != nil {
		t.Fatalf("Failed to unmarshal DynamicPolicy: %v", err)
	}

	if policy.Tier != "" {
		t.Errorf("Expected empty tier when not present in JSON, got %s", policy.Tier)
	}
	if policy.OrganizationID != "" {
		t.Errorf("Expected empty organization_id when not present, got %s", policy.OrganizationID)
	}
}

// TestListDynamicPoliciesWithTierAndOrgFilters tests listing dynamic policies with tier and organization_id query params
func TestListDynamicPoliciesWithTierAndOrgFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("tier") != "organization" {
			t.Errorf("Expected tier=organization query param, got %s", query.Get("tier"))
		}
		if query.Get("organization_id") != "org_filter_789" {
			t.Errorf("Expected organization_id=org_filter_789 query param, got %s", query.Get("organization_id"))
		}
		if query.Get("type") != "risk" {
			t.Errorf("Expected type=risk query param, got %s", query.Get("type"))
		}
		if query.Get("enabled") != "true" {
			t.Errorf("Expected enabled=true query param, got %s", query.Get("enabled"))
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policies": []DynamicPolicy{sampleDynamicPolicy},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	enabled := true
	options := &ListDynamicPoliciesOptions{
		Type:           "risk",
		Tier:           TierOrganization,
		OrganizationID: "org_filter_789",
		Enabled:        &enabled,
	}

	policies, err := client.ListDynamicPolicies(options)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].Tier != TierTenant {
		t.Errorf("Expected policy tier tenant from fixture, got %s", policies[0].Tier)
	}
	if policies[0].OrganizationID != "org_acme" {
		t.Errorf("Expected organization_id org_acme from fixture, got %s", policies[0].OrganizationID)
	}
}

// TestListDynamicPoliciesWithAllQueryParams tests that all ListDynamicPoliciesOptions fields are serialized to query params
func TestListDynamicPoliciesWithAllQueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("tier") != "system" {
			t.Errorf("Expected tier=system, got %s", query.Get("tier"))
		}
		if query.Get("organization_id") != "org_all" {
			t.Errorf("Expected organization_id=org_all, got %s", query.Get("organization_id"))
		}
		if query.Get("limit") != "25" {
			t.Errorf("Expected limit=25, got %s", query.Get("limit"))
		}
		if query.Get("offset") != "10" {
			t.Errorf("Expected offset=10, got %s", query.Get("offset"))
		}
		if query.Get("sort_by") != "priority" {
			t.Errorf("Expected sort_by=priority, got %s", query.Get("sort_by"))
		}
		if query.Get("sort_order") != "desc" {
			t.Errorf("Expected sort_order=desc, got %s", query.Get("sort_order"))
		}
		if query.Get("search") != "compliance" {
			t.Errorf("Expected search=compliance, got %s", query.Get("search"))
		}
		if query.Get("enabled") != "false" {
			t.Errorf("Expected enabled=false, got %s", query.Get("enabled"))
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policies": []DynamicPolicy{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	disabled := false
	options := &ListDynamicPoliciesOptions{
		Type:           "content",
		Tier:           TierSystem,
		OrganizationID: "org_all",
		Enabled:        &disabled,
		Limit:          25,
		Offset:         10,
		SortBy:         "priority",
		SortOrder:      "desc",
		Search:         "compliance",
	}

	policies, err := client.ListDynamicPolicies(options)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies, got %d", len(policies))
	}
}

// TestToggleDynamicPolicy tests toggling a dynamic policy
func TestToggleDynamicPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/dynamic-policies/dpol_456" {
			t.Errorf("Expected path /api/v1/dynamic-policies/dpol_456, got %s", r.URL.Path)
		}
		toggled := sampleDynamicPolicy
		toggled.Enabled = false
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policy": toggled,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	policy, err := client.ToggleDynamicPolicy("dpol_456", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.Enabled {
		t.Errorf("Expected policy to be disabled")
	}
	if policy.Tier != TierTenant {
		t.Errorf("Expected policy tier tenant from fixture, got %s", policy.Tier)
	}
}

// TestListPolicyOverrides tests listing all policy overrides
func TestListPolicyOverrides(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/static-policies/overrides" {
			t.Errorf("Expected path /api/v1/static-policies/overrides, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"overrides": []PolicyOverride{sampleOverride},
			"count":     1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	overrides, err := client.ListPolicyOverrides()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(overrides) != 1 {
		t.Errorf("Expected 1 override, got %d", len(overrides))
	}
	if overrides[0].PolicyID != "pol_123" {
		t.Errorf("Expected policy ID pol_123, got %s", overrides[0].PolicyID)
	}
}

// TestCreateDynamicPolicyWithSystemTier tests creating a system-tier dynamic policy
func TestCreateDynamicPolicyWithSystemTier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		if body["tier"] != "system" {
			t.Errorf("Expected tier=system in request body, got %v", body["tier"])
		}
		// system tier should not have organization_id
		if body["organization_id"] != nil && body["organization_id"] != "" {
			t.Errorf("Expected no organization_id for system tier, got %v", body["organization_id"])
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policy": DynamicPolicy{
				ID:        "dpol_sys_001",
				Name:      "Global Rate Limit",
				Type:      "cost",
				Tier:      TierSystem,
				Priority:  1,
				Enabled:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	req := &CreateDynamicPolicyRequest{
		Name:     "Global Rate Limit",
		Type:     "cost",
		Tier:     TierSystem,
		Priority: 1,
		Enabled:  true,
	}

	policy, err := client.CreateDynamicPolicy(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy.Tier != TierSystem {
		t.Errorf("Expected tier system, got %s", policy.Tier)
	}
}

// TestListStaticPoliciesWithOrgFilter tests listing static policies with organization_id filter
func TestListStaticPoliciesWithOrgFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("organization_id") != "org_static_test" {
			t.Errorf("Expected organization_id=org_static_test, got %s", query.Get("organization_id"))
		}
		if query.Get("tier") != "organization" {
			t.Errorf("Expected tier=organization, got %s", query.Get("tier"))
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"policies": []StaticPolicy{sampleStaticPolicy},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	options := &ListStaticPoliciesOptions{
		Tier:           TierOrganization,
		OrganizationID: "org_static_test",
	}

	policies, err := client.ListStaticPolicies(options)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
}

// TestDynamicPolicyBuildQueryParamsEmpty tests buildQueryParams with no options set
func TestDynamicPolicyBuildQueryParamsEmpty(t *testing.T) {
	opts := &ListDynamicPoliciesOptions{}
	result := opts.buildQueryParams()
	if result != "" {
		t.Errorf("Expected empty query string for empty options, got %s", result)
	}
}

// TestDynamicPolicyBuildQueryParamsTierOnly tests buildQueryParams with only tier set
func TestDynamicPolicyBuildQueryParamsTierOnly(t *testing.T) {
	opts := &ListDynamicPoliciesOptions{
		Tier: TierOrganization,
	}
	result := opts.buildQueryParams()
	if result != "?tier=organization" {
		t.Errorf("Expected ?tier=organization, got %s", result)
	}
}
