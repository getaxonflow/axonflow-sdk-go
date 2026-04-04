// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// selfhosted_auth_headers_test.go - Auth header verification tests
//
// These tests verify that auth headers are:
// - Sent when credentials are provided
// - NOT sent when credentials are not provided (community/self-hosted mode)
//
// Run with:
//   go test -v -run TestAuthHeaders

package axonflow

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================
// AUTH HEADERS TESTS - Community Mode (no credentials)
// ============================================================

// TestAuthHeaders_DefaultsToCommunityCreds verifies that Basic auth with
// "community:" is sent when no credentials are configured (community mode).
func TestAuthHeaders_DefaultsToCommunityCreds(t *testing.T) {
	receivedAuthHeader := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"answer": "test"},
		})
	}))
	defer server.Close()

	// Create client WITHOUT credentials — should default to "community"
	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		Cache:    CacheConfig{Enabled: false},
	})

	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	// Basic auth with community: should always be sent
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("community:"))
	if receivedAuthHeader != expectedAuth {
		t.Errorf("Expected Basic auth with community default, got '%s'", receivedAuthHeader)
	}

	t.Log("✅ Basic auth correctly sent with community default")
}

// ============================================================
// AUTH HEADERS TESTS - Enterprise Mode (with credentials)
// ============================================================

// TestAuthHeaders_OAuth2Basic verifies OAuth2 Basic auth header
// is sent when ClientID + ClientSecret are configured
func TestAuthHeaders_OAuth2Basic(t *testing.T) {
	receivedAuthHeader := ""
	receivedLicenseHeader := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedLicenseHeader = r.Header.Get("X-License-Key")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"answer": "test"},
		})
	}))
	defer server.Close()

	// Create client WITH OAuth2 credentials
	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		Cache:        CacheConfig{Enabled: false},
	})

	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	// Should send Authorization: Basic header (OAuth2-style)
	expectedBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client:my-secret"))
	if receivedAuthHeader != expectedBasic {
		t.Errorf("Expected Authorization '%s', got '%s'", expectedBasic, receivedAuthHeader)
	}
	// Should NOT send X-License-Key when using OAuth2
	if receivedLicenseHeader != "" {
		t.Errorf("Expected no X-License-Key when using OAuth2, got '%s'", receivedLicenseHeader)
	}

	t.Log("✅ OAuth2 Basic auth header correctly sent")
}

// TestAuthHeaders_ClientIDWithoutSecret verifies Basic auth with empty
// secret is sent when only ClientID is configured (community mode with custom tenant).
func TestAuthHeaders_ClientIDWithoutSecret(t *testing.T) {
	receivedAuthHeader := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"answer": "test"},
		})
	}))
	defer server.Close()

	// Create client with only ClientID (no ClientSecret)
	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "my-client",
		Cache:    CacheConfig{Enabled: false},
	})

	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	// Should send Basic auth with empty secret — server uses clientId as tenant
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client:"))
	if receivedAuthHeader != expectedAuth {
		t.Errorf("Expected Basic auth with clientId and empty secret, got '%s'", receivedAuthHeader)
	}

	t.Log("✅ Basic auth correctly sent with clientId and empty secret")
}
