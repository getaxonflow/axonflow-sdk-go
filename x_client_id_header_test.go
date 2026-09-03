// Copyright 2025 AxonFlow
// SPDX-License-Identifier: MIT
//
// x_client_id_header_test.go - X-Client-ID header verification (v9)
//
// The agent's apiAuthMiddleware overwrites incoming X-Client-ID with the
// auth-derived value, so a missing or wrong client-side header is
// harmless server-side. These tests pin SDK-emitted behaviour so future
// regressions are caught early.

package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestXClientIDHeader_CommunityDefault asserts the SDK emits
// X-Client-ID: "community" when no ClientID is configured.
func TestXClientIDHeader_CommunityDefault(t *testing.T) {
	received := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Client-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"answer": "ok"},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		Cache:    CacheConfig{Enabled: false},
	})
	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	if received != "community" {
		t.Errorf("X-Client-ID: want %q, got %q", "community", received)
	}
}

// TestXClientIDHeader_ConfiguredClient asserts the SDK emits the
// configured ClientID as X-Client-ID when set.
func TestXClientIDHeader_ConfiguredClient(t *testing.T) {
	received := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Client-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"answer": "ok"},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "acme-corp",
		ClientSecret: "secret",
		Cache:        CacheConfig{Enabled: false},
	})
	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	if received != "acme-corp" {
		t.Errorf("X-Client-ID: want %q, got %q", "acme-corp", received)
	}
}

// TestXClientIDHeader_NoLegacyTenantHeader asserts the SDK does NOT send
// X-Tenant-ID — the agent's middleware accepts it as an alias through v9
// for back-compat, but the SDK itself only emits X-Client-ID + Basic Auth.
func TestXClientIDHeader_NoLegacyTenantHeader(t *testing.T) {
	tenantHeader := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantHeader = r.Header.Get("X-Tenant-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"answer": "ok"},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "acme",
		ClientSecret: "secret",
		Cache:        CacheConfig{Enabled: false},
	})
	_, _ = client.ProxyLLMCall("user", "query", "chat", nil)

	if tenantHeader != "" {
		t.Errorf("X-Tenant-ID should not be sent by SDK; got %q", tenantHeader)
	}
}
