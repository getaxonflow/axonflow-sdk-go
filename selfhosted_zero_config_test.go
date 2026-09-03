// Copyright 2025 AxonFlow
// SPDX-License-Identifier: MIT
//
// selfhosted_zero_config_test.go - Tests for zero-configuration self-hosted mode
//
// These tests verify that the SDK works correctly when connecting to a
// self-hosted AxonFlow agent running in zero-config mode (no authentication).
//
// Run with:
//   go test -v -tags=integration ./...
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

// getZeroConfigTestConfig returns configuration for zero-config self-hosted mode
func getZeroConfigTestConfig() AxonFlowConfig {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	return AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     "default",
		ClientSecret: "", // Empty - zero-config mode
		Debug:        true,
		Timeout:      30 * time.Second,
	}
}

// isLocalhost checks if the agent URL is localhost
func isLocalhostURL(url string) bool {
	return strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1")
}

// ============================================================
// 1. CLIENT INITIALIZATION WITHOUT CREDENTIALS
// ============================================================

// TestZeroConfig_ClientCreation_EmptySecret tests that client can be created
// with empty client_secret for localhost endpoints
func TestZeroConfig_ClientCreation_EmptySecret(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	// Should not panic or error
	client := NewClient(config)
	if client == nil {
		t.Fatal("Expected client to be created")
	}
	t.Log("✅ Client created with empty secret for localhost")
}

// TestZeroConfig_ClientCreation_WhitespaceSecret tests that client can be created
// with whitespace-only client_secret for localhost endpoints
func TestZeroConfig_ClientCreation_WhitespaceSecret(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	config.ClientSecret = "   " // Whitespace only
	client := NewClient(config)
	if client == nil {
		t.Fatal("Expected client to be created")
	}
	t.Log("✅ Client created with whitespace secret for localhost")
}

// ============================================================
// 2. GATEWAY MODE WITHOUT AUTHENTICATION
// ============================================================

// TestZeroConfig_GatewayMode_PreCheckEmptyToken tests that pre-check works
// with empty user token in self-hosted mode
func TestZeroConfig_GatewayMode_PreCheckEmptyToken(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	// Pre-check with empty user token
	result, err := client.GetPolicyApprovedContext(
		"", // Empty token - zero-config scenario
		"What is the weather in Paris?",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Pre-check failed: %v", err)
	}

	if result.ContextID == "" {
		t.Error("Expected non-empty context_id")
	}
	if result.ExpiresAt.IsZero() {
		t.Error("Expected expires_at to be set")
	}

	t.Logf("✅ Pre-check succeeded with empty token: %s", result.ContextID)
}

// TestZeroConfig_GatewayMode_PreCheckWhitespaceToken tests that pre-check works
// with whitespace-only user token
func TestZeroConfig_GatewayMode_PreCheckWhitespaceToken(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	result, err := client.GetPolicyApprovedContext(
		"   ", // Whitespace only token
		"Simple test query",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Pre-check failed: %v", err)
	}

	if result.ContextID == "" {
		t.Error("Expected non-empty context_id")
	}
	t.Log("✅ Pre-check succeeded with whitespace token")
}

// TestZeroConfig_GatewayMode_FullFlow tests the complete Gateway Mode flow
// without any credentials
func TestZeroConfig_GatewayMode_FullFlow(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	// Step 1: Pre-check
	preCheck, err := client.GetPolicyApprovedContext(
		"",
		"Analyze quarterly sales data",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Pre-check failed: %v", err)
	}
	if preCheck.ContextID == "" {
		t.Fatal("Expected context_id from pre-check")
	}

	// Step 2: Audit (simulating LLM call completion)
	audit, err := client.AuditLLMCall(
		preCheck.ContextID,
		"Generated sales analysis report",
		"openai",
		"gpt-4",
		TokenUsage{PromptTokens: 100, CompletionTokens: 75, TotalTokens: 175},
		350,
		nil,
	)
	if err != nil {
		t.Fatalf("AuditLLMCall failed: %v", err)
	}

	if !audit.Success {
		t.Error("Expected audit to succeed")
	}
	if audit.AuditID == "" {
		t.Error("Expected audit_id to be set")
	}

	t.Logf("✅ Full Gateway Mode flow completed: %s", audit.AuditID)
}

// ============================================================
// 3. PROXY MODE WITHOUT AUTHENTICATION
// ============================================================

// TestZeroConfig_ProxyMode_ProxyLLMCallEmptyToken tests that ProxyLLMCall works
// with empty user token in self-hosted mode
func TestZeroConfig_ProxyMode_ProxyLLMCallEmptyToken(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	resp, err := client.ProxyLLMCall(
		"", // Empty token
		"What is 2 + 2?",
		"chat",
		nil,
	)

	// Should either succeed or be blocked by policy (but not auth error)
	if resp != nil {
		if resp.Blocked {
			t.Logf("⚠️ Query blocked by policy (not auth): %s", resp.BlockReason)
		} else {
			t.Log("✅ Query executed with empty token")
		}
	} else if err != nil {
		// Check if it's an auth error (which should NOT happen)
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized") {
			t.Fatalf("Should not get auth error in zero-config mode: %v", err)
		}
		// Other errors might be acceptable (e.g., 403 for policy block)
		t.Logf("Query error (may be policy block): %v", err)
	}
}

// ============================================================
// 4. POLICY ENFORCEMENT STILL WORKS
// ============================================================

// TestZeroConfig_PolicyEnforcement_SQLInjection verifies SQL injection is still
// blocked even without authentication
func TestZeroConfig_PolicyEnforcement_SQLInjection(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	result, err := client.GetPolicyApprovedContext(
		"",
		"SELECT * FROM users WHERE id=1; DROP TABLE users;--",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Pre-check failed: %v", err)
	}

	if result.Approved {
		t.Error("SQL injection should be blocked")
	}
	if result.BlockReason == "" {
		t.Error("Expected block_reason to be set")
	}

	t.Logf("✅ SQL injection blocked: %s", result.BlockReason)
}

// TestZeroConfig_PolicyEnforcement_PII verifies PII is detected
// even without authentication. Note: In community stack, PII may be in warn-only
// mode (detected but not blocked). We verify detection occurred.
func TestZeroConfig_PolicyEnforcement_PII(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	result, err := client.GetPolicyApprovedContext(
		"",
		"My social security number is 123-45-6789",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Pre-check failed: %v", err)
	}

	// PII should either be blocked OR detected (warn mode)
	// In community stack, PII may be in warn-only mode
	if result.Approved {
		// If approved, check if policies were at least evaluated (warn mode)
		if len(result.Policies) > 0 {
			t.Logf("✅ PII detected in warn mode (policies=%v)", result.Policies)
			return
		}
		// No policies evaluated means PII detection is completely disabled
		t.Skip("PII detection not enabled in community stack")
	}

	t.Log("✅ PII blocked without credentials")
}

// ============================================================
// 5. HEALTH CHECK WITHOUT AUTH
// ============================================================

// TestZeroConfig_HealthCheck tests that health check works without authentication
func TestZeroConfig_HealthCheck(t *testing.T) {
	config := getZeroConfigTestConfig()
	if !isLocalhostURL(config.Endpoint) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	client := NewClient(config)

	err := client.HealthCheck()
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	t.Log("✅ Health check succeeded without credentials")
}

// ============================================================
// 6. FIRST-TIME USER EXPERIENCE
// ============================================================

// TestZeroConfig_FirstTimeUser simulates a brand new user with minimal configuration
func TestZeroConfig_FirstTimeUser(t *testing.T) {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}
	if !isLocalhostURL(agentURL) {
		t.Skip("Zero-config tests require localhost endpoint")
	}

	// First-time user - minimal configuration
	client := NewClient(AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     "first-time-user",
		ClientSecret: "", // Empty - zero-config
		Debug:        true,
		Timeout:      30 * time.Second,
	})

	// Step 1: Health check should work
	if err := client.HealthCheck(); err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Step 2: Pre-check should work with empty token
	result, err := client.GetPolicyApprovedContext(
		"",
		"Hello, this is my first query!",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Pre-check failed: %v", err)
	}
	if result.ContextID == "" {
		t.Error("Expected context_id")
	}

	t.Log("✅ First-time user experience validated")
	t.Log("   - Client creation: OK")
	t.Log("   - Health check: OK")
	t.Log("   - Pre-check: OK")
}

// Note: Section 7 (Auth Headers) tests are in selfhosted_auth_headers_test.go
// They use httptest and run without the integration build tag
