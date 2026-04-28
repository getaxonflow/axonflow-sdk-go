// Regression tests for HealthCheckDetailed and SDKCompatibility.
//
// The platform /health endpoint returns sdk_compatibility.min_sdk_version
// and recommended_sdk_version as per-language maps. An older SDK declared
// both fields as plain strings, so JSON unmarshal silently produced empty
// strings and the SDK version-mismatch warning logic became dead code.
// These tests pin the dict-shape contract.
package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSDKCompatibility_MinSDKVersionFor(t *testing.T) {
	t.Parallel()
	c := &SDKCompatibility{
		MinSDKVersion: map[string]string{
			"go":         "5.0.0",
			"java":       "5.0.0",
			"python":     "6.0.0",
			"typescript": "5.0.0",
		},
		RecommendedSDKVersion: map[string]string{
			"go":         "5.8.0",
			"java":       "6.1.0",
			"python":     "6.8.0",
			"typescript": "6.1.0",
		},
	}
	if got := c.MinSDKVersionFor("go"); got != "5.0.0" {
		t.Errorf("MinSDKVersionFor(go) = %q, want %q", got, "5.0.0")
	}
	if got := c.RecommendedSDKVersionFor("typescript"); got != "6.1.0" {
		t.Errorf("RecommendedSDKVersionFor(typescript) = %q, want %q", got, "6.1.0")
	}
	if got := c.MinSDKVersionFor("rust"); got != "" {
		t.Errorf("MinSDKVersionFor(rust) = %q, want \"\" (unknown language)", got)
	}
}

func TestSDKCompatibility_NilSafe(t *testing.T) {
	t.Parallel()
	var c *SDKCompatibility
	if got := c.MinSDKVersionFor("go"); got != "" {
		t.Errorf("MinSDKVersionFor on nil receiver = %q, want \"\"", got)
	}
	if got := c.RecommendedSDKVersionFor("go"); got != "" {
		t.Errorf("RecommendedSDKVersionFor on nil receiver = %q, want \"\"", got)
	}

	empty := &SDKCompatibility{}
	if got := empty.MinSDKVersionFor("go"); got != "" {
		t.Errorf("MinSDKVersionFor on empty struct = %q, want \"\"", got)
	}
}

func TestHealthCheckDetailed_DictShapeMinSDKVersion(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service": "axonflow-agent",
			"status":  "healthy",
			"version": "7.4.4",
			"capabilities": []map[string]interface{}{
				{"name": "health_check", "since": "1.0.0", "description": "Basic health endpoint"},
			},
			"sdk_compatibility": map[string]interface{}{
				"min_sdk_version": map[string]string{
					"go":         "5.0.0",
					"java":       "5.0.0",
					"python":     "6.0.0",
					"typescript": "5.0.0",
				},
				"recommended_sdk_version": map[string]string{
					"go":         "5.8.0",
					"java":       "6.1.0",
					"python":     "6.8.0",
					"typescript": "6.1.0",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{Endpoint: server.URL})
	health, err := client.HealthCheckDetailed()
	if err != nil {
		t.Fatalf("HealthCheckDetailed returned error: %v", err)
	}
	if health.SDKCompat == nil {
		t.Fatal("SDKCompat is nil; expected populated dict")
	}
	if got := health.SDKCompat.MinSDKVersionFor("go"); got != "5.0.0" {
		t.Errorf("MinSDKVersionFor(go) = %q, want %q", got, "5.0.0")
	}
	if got := health.SDKCompat.RecommendedSDKVersionFor("go"); got != "5.8.0" {
		t.Errorf("RecommendedSDKVersionFor(go) = %q, want %q", got, "5.8.0")
	}
}
