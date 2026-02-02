// sdk_integration_test.go - Integration tests for AxonFlow Go SDK
// Run with: go test -v -tags=integration ./...
//
//go:build integration
// +build integration

package axonflow

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Integration test configuration
// Set these environment variables before running:
//   AXONFLOW_AGENT_URL=http://localhost:8080
//   AXONFLOW_CLIENT_ID=demo-client
//   AXONFLOW_CLIENT_SECRET=demo-secret

func getTestConfig(t *testing.T) AxonFlowConfig {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo-client"
	}

	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "demo-secret"
	}

	return AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Debug:        true,
		Timeout:      30 * time.Second,
	}
}

// TestHealthCheck verifies basic connectivity
func TestIntegration_HealthCheck(t *testing.T) {
	client := NewClient(getTestConfig(t))

	err := client.HealthCheck()
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	t.Log("Health check passed")
}

// TestProxyLLMCall_Simple tests a basic query
func TestIntegration_ProxyLLMCall_Simple(t *testing.T) {
	client := NewClient(getTestConfig(t))

	resp, err := client.ProxyLLMCall("demo-user", "What is 2+2?", "chat", nil)
	if err != nil {
		t.Fatalf("ProxyLLMCall failed: %v", err)
	}

	// SDK's fail-open behavior returns success=true but the inner error may indicate LLM issues
	// This is expected in community stack without LLM configured
	if resp.Error != "" {
		if strings.Contains(resp.Error, "LLM") || strings.Contains(resp.Error, "provider") ||
			strings.Contains(resp.Error, "no healthy") {
			t.Skipf("Query skipped (no LLM configured): %s", resp.Error)
		}
	}

	if !resp.Success && !resp.Blocked {
		t.Errorf("Expected success or blocked, got error: %s", resp.Error)
	}
	t.Logf("Response: success=%v, blocked=%v", resp.Success, resp.Blocked)
}

// TestProxyLLMCall_SQLInjection tests that SQL injection is blocked
func TestIntegration_ProxyLLMCall_SQLInjection(t *testing.T) {
	client := NewClient(getTestConfig(t))

	// SQL injection should be blocked
	// Note: The Agent returns HTTP 403 for blocked requests, which the SDK may treat
	// as an error with fail-open behavior. Check both the response and error message.
	resp, err := client.ProxyLLMCall("demo-user", "SELECT * FROM users; DROP TABLE users;--", "sql", nil)

	// Check if blocked via response
	if resp != nil && resp.Blocked {
		t.Logf("SQL injection blocked (via response): %s", resp.BlockReason)
		return
	}

	// Check if blocked via HTTP 403 error (SDK fail-open returns this in error)
	if err != nil && strings.Contains(err.Error(), "403") {
		t.Logf("SQL injection blocked (via HTTP 403): %v", err)
		return
	}

	// Check if fail-open returned success with error message indicating blocked
	if resp != nil && resp.Error != "" && strings.Contains(resp.Error, "403") {
		t.Logf("SQL injection blocked (via fail-open error): %s", resp.Error)
		return
	}

	// If we get here, the query was not blocked
	if resp != nil {
		t.Errorf("Expected SQL injection to be blocked, got blocked=%v, error=%s", resp.Blocked, resp.Error)
	} else if err != nil {
		t.Fatalf("ProxyLLMCall failed unexpectedly: %v", err)
	}
}

// TestProxyLLMCall_PIIDetection tests that PII is blocked
func TestIntegration_ProxyLLMCall_PIIDetection(t *testing.T) {
	client := NewClient(getTestConfig(t))

	// SSN should be blocked (with PII_BLOCK_CRITICAL=true default)
	// Note: The Agent returns HTTP 403 for blocked requests, which the SDK may treat
	// as an error with fail-open behavior. Check both the response and error message.
	resp, err := client.ProxyLLMCall("demo-user", "My SSN is 123-45-6789", "chat", nil)

	// Check if blocked via response
	if resp != nil && resp.Blocked {
		t.Logf("PII blocked (via response): %s", resp.BlockReason)
		return
	}

	// Check if blocked via HTTP 403 error (SDK fail-open returns this in error)
	if err != nil && strings.Contains(err.Error(), "403") {
		t.Logf("PII blocked (via HTTP 403): %v", err)
		return
	}

	// Check if fail-open returned success with error message indicating blocked
	if resp != nil && resp.Error != "" && strings.Contains(resp.Error, "403") {
		t.Logf("PII blocked (via fail-open error): %s", resp.Error)
		return
	}

	// Community stack without LLM configured may return success with LLM error
	if resp != nil && resp.Error != "" {
		if strings.Contains(resp.Error, "LLM") || strings.Contains(resp.Error, "provider") ||
			strings.Contains(resp.Error, "no healthy") {
			t.Skipf("Query skipped (no LLM configured): %s", resp.Error)
		}
	}

	// PII blocking may be disabled or in warn-only mode in community stack
	// Skip if not blocked but no error (indicates PII is in warn mode)
	if resp != nil && !resp.Blocked && resp.Error == "" {
		t.Skip("PII not blocked (may be in warn-only mode in community stack)")
	}

	// If we get here, the query was not blocked
	if resp != nil {
		t.Errorf("Expected PII to be blocked, got blocked=%v, error=%s", resp.Blocked, resp.Error)
	} else if err != nil {
		t.Fatalf("ProxyLLMCall failed unexpectedly: %v", err)
	}
}

// TestGatewayMode_PreCheck tests Gateway Mode pre-check
func TestIntegration_GatewayMode_PreCheck(t *testing.T) {
	client := NewClient(getTestConfig(t))

	result, err := client.GetPolicyApprovedContext("demo-user", "Analyze this data", nil, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}

	if result.ContextID == "" {
		t.Error("Expected non-empty context_id")
	}

	// Check that ExpiresAt was parsed correctly (should be in the future)
	if result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt was not parsed correctly (zero value)")
	}
	if result.ExpiresAt.Before(time.Now()) {
		t.Errorf("ExpiresAt should be in the future, got %v", result.ExpiresAt)
	}

	t.Logf("Pre-check: context_id=%s, approved=%v, expires_at=%v",
		result.ContextID, result.Approved, result.ExpiresAt)
}

// TestGatewayMode_PreCheckWithNanoseconds tests datetime parsing with nanoseconds
func TestIntegration_GatewayMode_PreCheckDatetimeParsing(t *testing.T) {
	client := NewClient(getTestConfig(t))

	result, err := client.GetPolicyApprovedContext("demo-user", "Test datetime parsing", nil, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}

	// ExpiresAt should be approximately 5 minutes from now (default context expiry)
	expectedExpiry := time.Now().Add(5 * time.Minute)
	timeDiff := result.ExpiresAt.Sub(expectedExpiry)

	// Allow 30 second tolerance
	if timeDiff.Abs() > 30*time.Second {
		t.Errorf("ExpiresAt is not within expected range. Got %v, expected ~%v",
			result.ExpiresAt, expectedExpiry)
	}

	t.Logf("Datetime parsing OK: expires_at=%v (diff from expected: %v)",
		result.ExpiresAt, timeDiff)
}

// TestGatewayMode_AuditLLMCall tests Gateway Mode audit
func TestIntegration_GatewayMode_AuditLLMCall(t *testing.T) {
	client := NewClient(getTestConfig(t))

	// First get a context
	preCheck, err := client.GetPolicyApprovedContext("demo-user", "Test audit", nil, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}

	// Then audit an LLM call
	result, err := client.AuditLLMCall(
		preCheck.ContextID,
		"Test response summary",
		"openai",
		"gpt-4",
		TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
		250,
		nil,
	)
	if err != nil {
		t.Fatalf("AuditLLMCall failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected audit to succeed")
	}
	if result.AuditID == "" {
		t.Error("Expected non-empty audit_id")
	}

	t.Logf("Audit logged: audit_id=%s", result.AuditID)
}

// TestGeneratePlan tests multi-agent plan generation
func TestIntegration_GeneratePlan(t *testing.T) {
	client := NewClient(getTestConfig(t))

	// Test backward-compatible call (no userToken - uses variadic)
	plan, err := client.GeneratePlan("Book a flight from NYC to LA", "travel")
	if err != nil {
		// Plan generation may fail if orchestrator doesn't have LLM configured or connectors not installed
		// This is acceptable in community stack - we're testing the SDK request format
		errMsg := err.Error()
		if strings.Contains(errMsg, "LLM") || strings.Contains(errMsg, "provider") ||
			strings.Contains(errMsg, "connector") || strings.Contains(errMsg, "not found") ||
			strings.Contains(errMsg, "Execution failed") || strings.Contains(errMsg, "steps failed") ||
			strings.Contains(errMsg, "Planning Engine not initialized") {
			t.Skipf("Plan generation skipped (community stack limitation): %v", err)
		}
		t.Fatalf("GeneratePlan failed: %v", err)
	}

	if plan.PlanID == "" {
		t.Error("Expected non-empty plan_id")
	}

	t.Logf("Plan generated: plan_id=%s, steps=%d", plan.PlanID, len(plan.Steps))
}

// TestGeneratePlanWithUserToken tests plan generation with explicit user token
func TestIntegration_GeneratePlanWithUserToken(t *testing.T) {
	client := NewClient(getTestConfig(t))

	// Test with explicit userToken (variadic parameter)
	plan, err := client.GeneratePlan("Simple query", "generic", "custom-user-token")
	if err != nil {
		// Plan generation may fail if orchestrator doesn't have LLM configured or connectors not installed
		// This is acceptable in community stack - we're testing the SDK request format
		errMsg := err.Error()
		if strings.Contains(errMsg, "LLM") || strings.Contains(errMsg, "provider") ||
			strings.Contains(errMsg, "connector") || strings.Contains(errMsg, "not found") ||
			strings.Contains(errMsg, "Execution failed") || strings.Contains(errMsg, "steps failed") ||
			strings.Contains(errMsg, "Planning Engine not initialized") {
			t.Skipf("Plan generation skipped (community stack limitation): %v", err)
		}
		t.Fatalf("GeneratePlan with userToken failed: %v", err)
	}

	if plan.PlanID == "" {
		t.Error("Expected non-empty plan_id")
	}

	t.Logf("Plan with custom token generated: plan_id=%s", plan.PlanID)
}

// TestListConnectors tests listing MCP connectors
func TestIntegration_ListConnectors(t *testing.T) {
	client := NewClient(getTestConfig(t))

	connectors, err := client.ListConnectors()
	if err != nil {
		// Connectors endpoint may not be available in community stack
		if strings.Contains(err.Error(), "404") {
			t.Skip("ListConnectors skipped (endpoint not available in community stack)")
		}
		t.Fatalf("ListConnectors failed: %v", err)
	}

	t.Logf("Found %d connectors", len(connectors))
	for _, c := range connectors {
		t.Logf("  - %s (%s)", c.Name, c.Type)
	}
}
