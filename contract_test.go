// contract_test.go - Contract tests validating SDK deserialization against real Agent API responses
//
// These tests use fixtures recorded from the actual Agent API to ensure the SDK
// correctly parses responses. This prevents regressions like:
// - Datetime parsing failures (nanoseconds precision)
// - Missing fields in response structs
// - Policy name extraction issues
//
// To update fixtures, run against the community stack:
//   cd ../axonflow && docker-compose up -d
//   curl ... > testdata/fixture.json
//
// See Issue #6 for full context.

package axonflow

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// loadFixture reads a fixture file from testdata/
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	return data
}

// TestContractQuerySuccessResponse validates parsing of a successful query response
func TestContractQuerySuccessResponse(t *testing.T) {
	data := loadFixture(t, "query_success.json")

	var response ClientResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("failed to unmarshal query response: %v", err)
	}

	// Validate top-level fields
	if !response.Success {
		t.Error("expected success=true for success response")
	}
	if response.Blocked {
		t.Error("expected blocked=false for success response")
	}
	if response.Data == nil {
		t.Error("expected data to be non-nil")
	}

	// Validate policy_info
	if response.PolicyInfo == nil {
		t.Fatal("expected policy_info to be present")
	}
	if len(response.PolicyInfo.StaticChecks) == 0 {
		t.Error("expected static_checks to be non-empty")
	}
	if response.PolicyInfo.ProcessingTime == "" {
		t.Error("expected processing_time to be non-empty")
	}
	if response.PolicyInfo.TenantID != "demo-client" {
		t.Errorf("expected tenant_id 'demo-client', got '%s'", response.PolicyInfo.TenantID)
	}

	// Validate data structure (nested response)
	dataMap, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be a map")
	}
	if _, hasData := dataMap["data"]; !hasData {
		t.Error("expected data.data field to be present")
	}
	if _, hasMetadata := dataMap["metadata"]; !hasMetadata {
		t.Error("expected data.metadata field to be present")
	}

	t.Logf("Successfully parsed query_success.json - tenant_id: %s, static_checks: %v",
		response.PolicyInfo.TenantID, response.PolicyInfo.StaticChecks)
}

// TestContractQueryBlockedResponse validates parsing of a blocked PII response
func TestContractQueryBlockedResponse(t *testing.T) {
	data := loadFixture(t, "query_blocked_pii.json")

	var response ClientResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("failed to unmarshal blocked response: %v", err)
	}

	// Validate blocked response
	if response.Success {
		t.Error("expected success=false for blocked response")
	}
	if !response.Blocked {
		t.Error("expected blocked=true for PII response")
	}
	if response.BlockReason == "" {
		t.Error("expected block_reason to be non-empty")
	}
	if response.BlockReason != "US Social Security Number pattern detected" {
		t.Errorf("expected specific block reason, got '%s'", response.BlockReason)
	}

	// Validate policy_info with policies_evaluated
	if response.PolicyInfo == nil {
		t.Fatal("expected policy_info to be present")
	}
	if len(response.PolicyInfo.PoliciesEvaluated) == 0 {
		t.Error("expected policies_evaluated to be non-empty")
	}
	if response.PolicyInfo.PoliciesEvaluated[0] != "pii_ssn_detection" {
		t.Errorf("expected policy 'pii_ssn_detection', got '%s'",
			response.PolicyInfo.PoliciesEvaluated[0])
	}

	t.Logf("Successfully parsed query_blocked_pii.json - block_reason: %s, policies: %v",
		response.BlockReason, response.PolicyInfo.PoliciesEvaluated)
}

// TestContractPolicyContextResponse validates parsing of Gateway Mode pre-check response
// This specifically tests datetime parsing with nanosecond precision (bug fix from PR #4)
func TestContractPolicyContextResponse(t *testing.T) {
	data := loadFixture(t, "policy_context.json")

	// Use the same parsing logic as the SDK's GetPolicyApprovedContext
	var rawResp struct {
		ContextID   string   `json:"context_id"`
		Approved    bool     `json:"approved"`
		Policies    []string `json:"policies"`
		ExpiresAt   string   `json:"expires_at"`
		BlockReason string   `json:"block_reason,omitempty"`
	}

	if err := json.Unmarshal(data, &rawResp); err != nil {
		t.Fatalf("failed to unmarshal policy context: %v", err)
	}

	// Validate required fields - use flexible assertions (don't hardcode UUIDs)
	if rawResp.ContextID == "" {
		t.Error("expected context_id to be non-empty")
	}
	// Validate UUID format (36 chars with dashes)
	if len(rawResp.ContextID) != 36 {
		t.Errorf("expected context_id to be UUID format (36 chars), got %d chars", len(rawResp.ContextID))
	}
	if !rawResp.Approved {
		t.Error("expected approved=true")
	}

	// CRITICAL: Test datetime parsing with nanoseconds
	// This was the bug fixed in PR #4 - server returns timestamps with nanosecond precision
	expiresAt, err := parseTimeWithFallback(rawResp.ExpiresAt)
	if err != nil {
		t.Fatalf("failed to parse expires_at with nanoseconds '%s': %v", rawResp.ExpiresAt, err)
	}
	if expiresAt.IsZero() {
		t.Error("expected expires_at to be parsed to non-zero time")
	}

	// Verify nanoseconds were preserved (should be non-zero for nanosecond precision)
	if expiresAt.Nanosecond() == 0 {
		t.Error("expected nanoseconds to be preserved (non-zero), got 0")
	}

	t.Logf("Successfully parsed policy_context.json - context_id: %s, expires_at: %v (ns: %d)",
		rawResp.ContextID, expiresAt, expiresAt.Nanosecond())
}

// TestContractPlanResponse validates parsing of multi-agent plan generation response
func TestContractPlanResponse(t *testing.T) {
	data := loadFixture(t, "plan_generate.json")

	// First parse as ClientResponse (this is what ProxyLLMCall returns)
	var response ClientResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("failed to unmarshal plan response: %v", err)
	}

	// Validate top-level response
	if !response.Success {
		t.Error("expected success=true for plan response")
	}
	if response.Blocked {
		t.Error("expected blocked=false for plan response")
	}
	if response.PlanID == "" {
		t.Error("expected plan_id to be non-empty at top level")
	}

	// Extract plan data from response
	planData, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be a map")
	}

	// Validate plan structure
	if planID, ok := planData["plan_id"].(string); !ok || planID == "" {
		t.Error("expected plan_id in data to be non-empty")
	}

	// Validate steps array
	steps, ok := planData["steps"].([]interface{})
	if !ok {
		t.Fatal("expected steps to be an array")
	}
	if len(steps) == 0 {
		t.Error("expected steps to be non-empty")
	}

	// Validate first step structure
	step1, ok := steps[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected first step to be a map")
	}
	if step1["id"] != "step-1" {
		t.Errorf("expected first step id 'step-1', got '%v'", step1["id"])
	}
	if step1["name"] != "Search Flights" {
		t.Errorf("expected first step name 'Search Flights', got '%v'", step1["name"])
	}

	// Convert to PlanResponse struct to test full parsing
	planBytes, err := json.Marshal(planData)
	if err != nil {
		t.Fatalf("failed to marshal plan data: %v", err)
	}

	var plan PlanResponse
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		t.Fatalf("failed to unmarshal into PlanResponse: %v", err)
	}

	if len(plan.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(plan.Steps))
	}
	if plan.Domain != "travel" {
		t.Errorf("expected domain 'travel', got '%s'", plan.Domain)
	}
	if plan.Complexity != 3 {
		t.Errorf("expected complexity 3, got %d", plan.Complexity)
	}

	// Validate step dependencies
	if len(plan.Steps[1].Dependencies) != 1 || plan.Steps[1].Dependencies[0] != "step-1" {
		t.Errorf("expected step-2 to depend on step-1, got %v", plan.Steps[1].Dependencies)
	}

	// Test datetime in metadata (created_at with nanoseconds)
	if plan.Metadata != nil {
		if createdAtStr, ok := plan.Metadata["created_at"].(string); ok {
			createdAt, err := parseTimeWithFallback(createdAtStr)
			if err != nil {
				t.Errorf("failed to parse metadata.created_at '%s': %v", createdAtStr, err)
			}
			// Verify nanoseconds were preserved (should be non-zero)
			if createdAt.Nanosecond() == 0 {
				t.Error("expected nanoseconds to be preserved in created_at, got 0")
			}
		}
	}

	t.Logf("Successfully parsed plan_generate.json - plan_id: %s, steps: %d, domain: %s",
		plan.PlanID, len(plan.Steps), plan.Domain)
}

// TestContractPolicyInfoExtraction validates that policy names are correctly extracted
// This was one of the bugs that affected other SDKs (Go SDK was already correct)
func TestContractPolicyInfoExtraction(t *testing.T) {
	data := loadFixture(t, "query_blocked_pii.json")

	var response ClientResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// The SDK exposes PolicyInfo.PoliciesEvaluated directly
	if response.PolicyInfo == nil {
		t.Fatal("expected policy_info to be present")
	}

	policies := response.PolicyInfo.PoliciesEvaluated
	if len(policies) == 0 {
		t.Fatal("expected policies_evaluated to be non-empty")
	}

	// Verify we can iterate and access policy names
	for i, policy := range policies {
		if policy == "" {
			t.Errorf("policy at index %d is empty", i)
		}
		t.Logf("Policy %d: %s", i, policy)
	}

	// Verify specific policy detection
	found := false
	for _, p := range policies {
		if p == "pii_ssn_detection" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find 'pii_ssn_detection' in policies: %v", policies)
	}
}

// TestContractDatetimeFormats validates all datetime format variations
// The Agent API may return timestamps with or without nanoseconds
func TestContractDatetimeFormats(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		wantNano int
	}{
		{
			name:     "RFC3339 without fractional seconds",
			input:    "2025-12-15T17:48:53Z",
			wantNano: 0,
		},
		{
			name:     "RFC3339Nano with nanoseconds",
			input:    "2025-12-15T17:48:53.414286714Z",
			wantNano: 414286714,
		},
		{
			name:     "RFC3339Nano with microseconds",
			input:    "2025-12-15T17:48:53.414286Z",
			wantNano: 414286000,
		},
		{
			name:     "RFC3339Nano with milliseconds",
			input:    "2025-12-15T17:48:53.414Z",
			wantNano: 414000000,
		},
		{
			name:     "RFC3339 with timezone offset",
			input:    "2025-12-15T17:48:53+00:00",
			wantNano: 0,
		},
		{
			name:     "RFC3339Nano with timezone offset",
			input:    "2025-12-15T17:48:53.123456789+00:00",
			wantNano: 123456789,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseTimeWithFallback(tc.input)
			if err != nil {
				t.Fatalf("failed to parse '%s': %v", tc.input, err)
			}

			if parsed.Nanosecond() != tc.wantNano {
				t.Errorf("expected nanoseconds %d, got %d", tc.wantNano, parsed.Nanosecond())
			}

			// Verify the parsed time is valid
			if parsed.Year() != 2025 || parsed.Month() != time.December || parsed.Day() != 15 {
				t.Errorf("date components wrong: got %v", parsed)
			}
		})
	}
}

// TestContractResponseWithEmptyPolicies validates handling of empty policies array
func TestContractResponseWithEmptyPolicies(t *testing.T) {
	data := loadFixture(t, "query_success.json")

	var response ClientResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Success responses may have empty policies_evaluated
	if response.PolicyInfo == nil {
		t.Fatal("expected policy_info to be present")
	}

	// Empty slice is valid (no policies were triggered)
	if response.PolicyInfo.PoliciesEvaluated == nil {
		// This is acceptable - JSON null becomes nil slice
		t.Log("policies_evaluated is nil (JSON null)")
	} else if len(response.PolicyInfo.PoliciesEvaluated) == 0 {
		t.Log("policies_evaluated is empty array")
	}

	// Static checks should still be present
	if len(response.PolicyInfo.StaticChecks) == 0 {
		t.Error("expected static_checks to be non-empty even for successful queries")
	}
}

// TestContractMalformedJSON validates graceful handling of invalid JSON
func TestContractMalformedJSON(t *testing.T) {
	testCases := []struct {
		name string
		json string
	}{
		{
			name: "empty string",
			json: "",
		},
		{
			name: "invalid JSON",
			json: "{invalid}",
		},
		{
			name: "truncated JSON",
			json: `{"success": true, "data":`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var response ClientResponse
			err := json.Unmarshal([]byte(tc.json), &response)
			if err == nil {
				t.Errorf("expected error for malformed JSON: %s", tc.name)
			}
		})
	}
}

// TestContractPartialResponse validates handling of responses with missing optional fields
func TestContractPartialResponse(t *testing.T) {
	// Minimal valid response - tests that SDK doesn't crash on missing optional fields
	minimalJSON := `{"success": true, "blocked": false}`

	var response ClientResponse
	if err := json.Unmarshal([]byte(minimalJSON), &response); err != nil {
		t.Fatalf("failed to unmarshal minimal response: %v", err)
	}

	if !response.Success {
		t.Error("expected success=true")
	}
	if response.Blocked {
		t.Error("expected blocked=false")
	}
	// Optional fields should be nil/empty, not cause panics
	if response.PolicyInfo != nil {
		t.Log("policy_info is present (unexpected but not an error)")
	}
	if response.Data != nil {
		t.Log("data is present (unexpected but not an error)")
	}
}
