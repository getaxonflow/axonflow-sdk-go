// Regression tests for the review-feedback fixes on ListProviders:
//
//  1. Wire-shape: LLMProvider surfaces Endpoint, Model, Region, RateLimit,
//     TimeoutSeconds, and Settings.
//  2. Pagination: ListProvidersPaged returns LLMProviderListResponse with
//     PaginationMeta; ListAllProviders walks every page.
//  3. context.Context propagation: cancelled context surfaces as a
//     request error, not a hang.
//  4. SDK version-mismatch warning actually fires when min_sdk_version
//     declares the local Version as out-of-date.
package axonflow

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLLMProvider_FullShapeRoundTrip(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []map[string]interface{}{
				{
					"name":            "anthropic",
					"type":            "anthropic",
					"enabled":         true,
					"priority":        0,
					"weight":          100,
					"has_api_key":     true,
					"endpoint":        "https://api.anthropic.com",
					"model":           "claude-haiku-4-5",
					"region":          "us-east-1",
					"rate_limit":      60,
					"timeout_seconds": 30,
					"settings": map[string]interface{}{
						"temperature_default": 0.2,
					},
					"health": map[string]interface{}{"status": "healthy"},
				},
			},
			"pagination": map[string]interface{}{
				"page": 1, "page_size": 20, "total_items": 1, "total_pages": 1,
			},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	providers, err := client.ListProviders(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(providers))
	}
	p := providers[0]
	if p.Endpoint != "https://api.anthropic.com" {
		t.Errorf("Endpoint = %q, want https://api.anthropic.com", p.Endpoint)
	}
	if p.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q, want claude-haiku-4-5", p.Model)
	}
	if p.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", p.Region)
	}
	if p.RateLimit != 60 {
		t.Errorf("RateLimit = %d, want 60", p.RateLimit)
	}
	if p.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds = %d, want 30", p.TimeoutSeconds)
	}
	if p.Settings == nil || p.Settings["temperature_default"] != 0.2 {
		t.Errorf("Settings = %+v, want map with temperature_default=0.2", p.Settings)
	}
}

func TestListProvidersPaged_ReturnsPaginationMeta(t *testing.T) {
	t.Parallel()
	var seenQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []map[string]interface{}{
				{"name": "p1", "type": "openai", "enabled": true, "has_api_key": true},
			},
			"pagination": map[string]interface{}{
				"page": 2, "page_size": 5, "total_items": 7, "total_pages": 2,
			},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	resp, err := client.ListProvidersPaged(context.Background(), &ListProvidersOptions{
		Page:     2,
		PageSize: 5,
	})
	if err != nil {
		t.Fatalf("ListProvidersPaged: %v", err)
	}
	if resp.Pagination.Page != 2 || resp.Pagination.PageSize != 5 ||
		resp.Pagination.TotalItems != 7 || resp.Pagination.TotalPages != 2 {
		t.Errorf("Pagination = %+v, want page=2 size=5 items=7 pages=2", resp.Pagination)
	}
	for _, p := range []string{"page=2", "page_size=5"} {
		if !strings.Contains(seenQuery, p) {
			t.Errorf("query %q missing %q", seenQuery, p)
		}
	}
}

func TestListAllProviders_WalksEveryPage(t *testing.T) {
	t.Parallel()
	var pageSeen int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := atomic.AddInt32(&pageSeen, 1)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"providers": []map[string]interface{}{
					{"name": "a", "type": "openai", "enabled": true, "has_api_key": true},
					{"name": "b", "type": "openai", "enabled": true, "has_api_key": true},
				},
				"pagination": map[string]interface{}{
					"page": 1, "page_size": 2, "total_items": 3, "total_pages": 2,
				},
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"providers": []map[string]interface{}{
					{"name": "c", "type": "anthropic", "enabled": true, "has_api_key": true},
				},
				"pagination": map[string]interface{}{
					"page": 2, "page_size": 2, "total_items": 3, "total_pages": 2,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	all, err := client.ListAllProviders(context.Background(), &ListProvidersOptions{PageSize: 2})
	if err != nil {
		t.Fatalf("ListAllProviders: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d providers across pages, want 3", len(all))
	}
	wantNames := []string{"a", "b", "c"}
	for i, p := range all {
		if p.Name != wantNames[i] {
			t.Errorf("provider[%d].Name = %q, want %q", i, p.Name, wantNames[i])
		}
	}
}

func TestListProviders_RespectsContextCancellation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.ListProviders(ctx, nil)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !strings.Contains(err.Error(), "context") &&
		!strings.Contains(err.Error(), "deadline") &&
		!strings.Contains(err.Error(), "canceled") {
		t.Errorf("error %q does not mention context/deadline/canceled", err.Error())
	}
}

func TestListProviders_EmptyProvidersArray(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers":[],"pagination":{"page":1,"page_size":20,"total_items":0,"total_pages":1}}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	providers, err := client.ListProviders(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("expected empty providers slice, got %+v", providers)
	}
}

func TestListProviders_MalformedJSON(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers": [garbage`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	_, err := client.ListProviders(context.Background(), nil)
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error %q does not mention decoding", err.Error())
	}
}

func TestHealthCheckDetailed_FiresWarningWhenSDKBelowMinimum(t *testing.T) {
	// NOT t.Parallel() — captures global log.SetOutput which races with the
	// "no warning when empty min version" test below.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":      "axonflow-agent",
			"status":       "healthy",
			"version":      "7.4.4",
			"capabilities": []map[string]interface{}{},
			"sdk_compatibility": map[string]interface{}{
				"min_sdk_version":         map[string]string{"go": "99.0.0"},
				"recommended_sdk_version": map[string]string{"go": "99.0.0"},
			},
		})
	}))
	defer server.Close()

	var buf bytes.Buffer
	defaultOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(defaultOut)

	client := NewClient(AxonFlowConfig{Endpoint: server.URL, Debug: true})
	if _, err := client.HealthCheckDetailed(); err != nil {
		t.Fatalf("HealthCheckDetailed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "below minimum supported version") {
		t.Errorf("expected upgrade warning in log output, got: %s", out)
	}
}

func TestHealthCheckDetailed_NoWarningWhenEmptyMinVersion(t *testing.T) {
	// NOT t.Parallel() — captures global log.SetOutput which races with the
	// "fires warning" test above.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":      "axonflow-agent",
			"status":       "healthy",
			"version":      "7.4.4",
			"capabilities": []map[string]interface{}{},
			"sdk_compatibility": map[string]interface{}{
				"min_sdk_version":         map[string]string{"go": ""},
				"recommended_sdk_version": map[string]string{"go": ""},
			},
		})
	}))
	defer server.Close()

	var buf bytes.Buffer
	defaultOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(defaultOut)

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	if _, err := client.HealthCheckDetailed(); err != nil {
		t.Fatalf("HealthCheckDetailed: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "below minimum supported version") {
		t.Errorf("upgrade warning fired on empty min version: %s", out)
	}
}
