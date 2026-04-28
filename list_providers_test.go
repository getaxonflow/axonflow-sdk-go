// Regression tests for ListProviders.
//
// Pins the wire-shape contract for GET /api/v1/llm-providers and confirms
// the optional Type and Enabled filters get passed through as query strings.
package axonflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListProviders_DecodesProvidersAndHealth(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/llm-providers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []map[string]interface{}{
				{
					"name":        "anthropic",
					"type":        "anthropic",
					"enabled":     true,
					"priority":    0,
					"weight":      0,
					"has_api_key": true,
					"health": map[string]interface{}{
						"status":       "healthy",
						"message":      "provider is operational",
						"last_checked": "2026-04-28T08:45:12Z",
					},
				},
				{
					"name":        "openai",
					"type":        "openai",
					"enabled":     true,
					"has_api_key": true,
					"health": map[string]interface{}{
						"status":  "unhealthy",
						"message": "billing exceeded",
					},
				},
			},
			"pagination": map[string]interface{}{"page": 1, "page_size": 20, "total": 2, "has_more": false},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	providers, err := client.ListProviders(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListProviders returned error: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("got %d providers, want 2", len(providers))
	}
	if providers[0].Name != "anthropic" || providers[0].Type != "anthropic" {
		t.Errorf("provider[0] = %+v, want anthropic/anthropic", providers[0])
	}
	if providers[0].Health == nil || providers[0].Health.Status != "healthy" {
		t.Errorf("provider[0].Health = %+v, want healthy", providers[0].Health)
	}
	if providers[1].Health == nil || providers[1].Health.Status != "unhealthy" {
		t.Errorf("provider[1].Health = %+v, want unhealthy", providers[1].Health)
	}
}

func TestListProviders_FiltersAreQueryParams(t *testing.T) {
	t.Parallel()
	var seenQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []map[string]interface{}{},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	enabledFalse := false
	if _, err := client.ListProviders(context.Background(), &ListProvidersOptions{
		Type:    "anthropic",
		Enabled: &enabledFalse,
	}); err != nil {
		t.Fatalf("ListProviders returned error: %v", err)
	}
	// Order of params is irrelevant — just check both are present.
	wantPairs := []string{"type=anthropic", "enabled=false"}
	for _, p := range wantPairs {
		if !contains(seenQuery, p) {
			t.Errorf("query %q missing %q", seenQuery, p)
		}
	}
}

func TestListProviders_ProviderWithoutHealth(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []map[string]interface{}{
				{"name": "ollama", "type": "ollama", "enabled": true},
			},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	providers, err := client.ListProviders(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListProviders returned error: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(providers))
	}
	if providers[0].Health != nil {
		t.Errorf("provider Health should be nil when omitted by server, got %+v", providers[0].Health)
	}
}

func TestListProviders_HTTPError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	_, err := client.ListProviders(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from 403, got nil")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
