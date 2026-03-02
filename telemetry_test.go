package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// isTelemetryEnabled tests
// ---------------------------------------------------------------------------

func TestIsTelemetryEnabled_Default(t *testing.T) {
	t.Run("off for sandbox mode", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:     "sandbox",
				ClientID: "id", ClientSecret: "sec",
			},
		}
		if client.isTelemetryEnabled() {
			t.Error("expected telemetry disabled for sandbox mode")
		}
	})

	t.Run("off when no credentials", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{Mode: "production"},
		}
		if client.isTelemetryEnabled() {
			t.Error("expected telemetry disabled when no credentials are set")
		}
	})

	t.Run("on for production with credentials", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:         "production",
				ClientID:     "id",
				ClientSecret: "sec",
			},
		}
		if !client.isTelemetryEnabled() {
			t.Error("expected telemetry enabled for production mode with credentials")
		}
	})
}

func TestIsTelemetryEnabled_EnvVarOverride(t *testing.T) {
	prodClient := func() *AxonFlowClient {
		return &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:         "production",
				ClientID:     "id",
				ClientSecret: "sec",
			},
		}
	}

	t.Run("DO_NOT_TRACK=1 disables", func(t *testing.T) {
		t.Setenv("DO_NOT_TRACK", "1")
		if prodClient().isTelemetryEnabled() {
			t.Error("expected telemetry disabled when DO_NOT_TRACK=1")
		}
	})

	t.Run("AXONFLOW_TELEMETRY=off disables", func(t *testing.T) {
		t.Setenv("AXONFLOW_TELEMETRY", "off")
		if prodClient().isTelemetryEnabled() {
			t.Error("expected telemetry disabled when AXONFLOW_TELEMETRY=off")
		}
	})

	t.Run("AXONFLOW_TELEMETRY=OFF disables (case insensitive)", func(t *testing.T) {
		t.Setenv("AXONFLOW_TELEMETRY", "OFF")
		if prodClient().isTelemetryEnabled() {
			t.Error("expected telemetry disabled when AXONFLOW_TELEMETRY=OFF")
		}
	})
}

func TestIsTelemetryEnabled_ConfigOverride(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	t.Run("config true overrides sandbox default", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:             "sandbox",
				TelemetryEnabled: boolPtr(true),
			},
		}
		if !client.isTelemetryEnabled() {
			t.Error("expected config override to enable telemetry in sandbox")
		}
	})

	t.Run("config false overrides production default", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:             "production",
				ClientID:         "id",
				ClientSecret:     "sec",
				TelemetryEnabled: boolPtr(false),
			},
		}
		if client.isTelemetryEnabled() {
			t.Error("expected config override to disable telemetry in production")
		}
	})

	t.Run("config true overrides DO_NOT_TRACK env", func(t *testing.T) {
		t.Setenv("DO_NOT_TRACK", "1")
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:             "production",
				ClientID:         "id",
				ClientSecret:     "sec",
				TelemetryEnabled: boolPtr(true),
			},
		}
		if !client.isTelemetryEnabled() {
			t.Error("expected config override to take priority over DO_NOT_TRACK")
		}
	})
}

// ---------------------------------------------------------------------------
// generateInstanceID tests
// ---------------------------------------------------------------------------

func TestGenerateInstanceID(t *testing.T) {
	id := generateInstanceID()

	// UUID v4 format: 8-4-4-4-12 hex characters
	uuidV4Re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidV4Re.MatchString(id) {
		t.Errorf("expected valid UUID v4 format, got %q", id)
	}

	// Verify uniqueness across calls
	id2 := generateInstanceID()
	if id == id2 {
		t.Error("expected unique instance IDs across calls")
	}
}

// ---------------------------------------------------------------------------
// sendTelemetryPing tests
// ---------------------------------------------------------------------------

func TestSendTelemetryPing_Success(t *testing.T) {
	var received telemetryPayload
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)

		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		resp := telemetryResponse{LatestVersion: Version}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "test-id",
			ClientSecret: "test-secret",
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 1 {
		t.Fatalf("expected exactly 1 request, got %d", called.Load())
	}

	if received.SDK != "go" {
		t.Errorf("expected sdk=go, got %q", received.SDK)
	}
	if received.SDKVersion != Version {
		t.Errorf("expected sdk_version=%s, got %q", Version, received.SDKVersion)
	}
	if received.OS == "" {
		t.Error("expected os to be non-empty")
	}
	if received.Arch == "" {
		t.Error("expected arch to be non-empty")
	}
	if received.RuntimeVersion == "" {
		t.Error("expected runtime_version to be non-empty")
	}
	if received.DeploymentMode != "production" {
		t.Errorf("expected deployment_mode=production, got %q", received.DeploymentMode)
	}
	if received.Features == nil {
		t.Error("expected features to be non-nil (empty array)")
	}
	if received.InstanceID == "" {
		t.Error("expected instance_id to be non-empty")
	}
}

func TestSendTelemetryPing_Timeout(t *testing.T) {
	// Server that delays longer than telemetry timeout. Use a channel to
	// allow the handler goroutine to exit promptly once the test finishes.
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(30 * time.Second):
		case <-handlerDone:
		}
	}))
	defer func() {
		close(handlerDone)
		srv.Close()
	}()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	done := make(chan struct{})
	go func() {
		client.sendTelemetryPing()
		close(done)
	}()

	select {
	case <-done:
		// Completed within timeout - good
	case <-time.After(5 * time.Second):
		t.Fatal("sendTelemetryPing did not complete within 5 seconds (expected ~3s timeout)")
	}
}

func TestSendTelemetryPing_OptOut(t *testing.T) {
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)
	t.Setenv("DO_NOT_TRACK", "1")

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 0 {
		t.Error("expected no HTTP request when telemetry is opted out")
	}
}

func TestSendTelemetryPing_SilentFailure(t *testing.T) {
	// Server that returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	// Should not panic or return error
	client.sendTelemetryPing()
}

func TestSendTelemetryPing_CustomEndpoint(t *testing.T) {
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		json.NewEncoder(w).Encode(telemetryResponse{})
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 1 {
		t.Error("expected request to custom checkpoint URL")
	}
}

func TestSendTelemetryPing_InvalidURL(t *testing.T) {
	t.Setenv("AXONFLOW_CHECKPOINT_URL", "://invalid-url")

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	// Should not panic
	client.sendTelemetryPing()
}
