package axonflow

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// isTelemetryEnabled tests
// ---------------------------------------------------------------------------

func TestIsTelemetryEnabled_Default(t *testing.T) {
	// Clear DO_NOT_TRACK so tests can verify default behavior.
	// CI sets DO_NOT_TRACK=1 to prevent telemetry pings.
	t.Setenv("DO_NOT_TRACK", "")
	t.Setenv("AXONFLOW_TELEMETRY", "")

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

	t.Run("on for production without credentials", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{Mode: "production"},
		}
		if !client.isTelemetryEnabled() {
			t.Error("expected telemetry enabled for production mode even without credentials")
		}
	})

	t.Run("on for production with only client ID", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{Mode: "production", ClientID: "id"},
		}
		if !client.isTelemetryEnabled() {
			t.Error("expected telemetry enabled for production mode even with only ClientID set")
		}
	})

	t.Run("on for production with only client secret", func(t *testing.T) {
		client := &AxonFlowClient{
			config: AxonFlowConfig{Mode: "production", ClientSecret: "sec"},
		}
		if !client.isTelemetryEnabled() {
			t.Error("expected telemetry enabled for production mode even with only ClientSecret set")
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
	t.Setenv("DO_NOT_TRACK", "")
	t.Setenv("AXONFLOW_TELEMETRY", "")
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

	t.Run("DO_NOT_TRACK beats config true", func(t *testing.T) {
		t.Setenv("DO_NOT_TRACK", "1")
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:             "production",
				ClientID:         "id",
				ClientSecret:     "sec",
				TelemetryEnabled: boolPtr(true),
			},
		}
		if client.isTelemetryEnabled() {
			t.Error("expected DO_NOT_TRACK=1 to disable telemetry even with config override")
		}
	})

	t.Run("AXONFLOW_TELEMETRY=off beats config true", func(t *testing.T) {
		t.Setenv("AXONFLOW_TELEMETRY", "off")
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:             "production",
				ClientID:         "id",
				ClientSecret:     "sec",
				TelemetryEnabled: boolPtr(true),
			},
		}
		if client.isTelemetryEnabled() {
			t.Error("expected AXONFLOW_TELEMETRY=off to disable telemetry even with config override")
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
	t.Setenv("DO_NOT_TRACK", "")
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
	if strings.HasPrefix(received.RuntimeVersion, "go") {
		t.Errorf("runtime_version should not have 'go' prefix, got %q", received.RuntimeVersion)
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
	t.Setenv("DO_NOT_TRACK", "")
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
	t.Setenv("DO_NOT_TRACK", "")
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
	t.Setenv("DO_NOT_TRACK", "")
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
	t.Setenv("DO_NOT_TRACK", "")
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

// ---------------------------------------------------------------------------
// buildPayload tests (test #12: mode propagated)
// ---------------------------------------------------------------------------

func TestBuildPayload(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "")
	t.Run("mode propagated to deployment_mode", func(t *testing.T) {
		modes := []string{"production", "sandbox", "staging", "development"}
		for _, mode := range modes {
			t.Run(mode, func(t *testing.T) {
				var received telemetryPayload

				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					json.NewDecoder(r.Body).Decode(&received)
					json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
				}))
				defer srv.Close()

				t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

				boolPtr := func(v bool) *bool { return &v }
				client := &AxonFlowClient{
					config: AxonFlowConfig{
						Mode:             mode,
						ClientID:         "id",
						ClientSecret:     "sec",
						TelemetryEnabled: boolPtr(true), // force enable for non-prod modes
					},
				}

				client.sendTelemetryPing()

				if received.DeploymentMode != mode {
					t.Errorf("expected deployment_mode=%q, got %q", mode, received.DeploymentMode)
				}
			})
		}
	})

	t.Run("empty mode defaults to production", func(t *testing.T) {
		var received telemetryPayload

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&received)
			json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
		}))
		defer srv.Close()

		t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

		boolPtr := func(v bool) *bool { return &v }
		client := &AxonFlowClient{
			config: AxonFlowConfig{
				ClientID:         "id",
				ClientSecret:     "sec",
				TelemetryEnabled: boolPtr(true),
			},
		}

		client.sendTelemetryPing()

		if received.DeploymentMode != "production" {
			t.Errorf("expected deployment_mode=production when mode is empty, got %q", received.DeploymentMode)
		}
	})
}

// ---------------------------------------------------------------------------
// Additional sendTelemetryPing tests for parity with Python SDK (24-test matrix)
// ---------------------------------------------------------------------------

func TestSendTelemetryPing_SandboxDefaultOff(t *testing.T) {
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "sandbox",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 0 {
		t.Error("expected no HTTP request for sandbox mode (telemetry default off)")
	}
}

func TestSendTelemetryPing_SandboxExplicitEnable(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "")
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	boolPtr := func(v bool) *bool { return &v }
	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:             "sandbox",
			ClientID:         "id",
			ClientSecret:     "sec",
			TelemetryEnabled: boolPtr(true),
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 1 {
		t.Errorf("expected exactly 1 request when sandbox + config true, got %d", called.Load())
	}
}

func TestSendTelemetryPing_ConfigDisableInProduction(t *testing.T) {
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	boolPtr := func(v bool) *bool { return &v }
	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:             "production",
			ClientID:         "id",
			ClientSecret:     "sec",
			TelemetryEnabled: boolPtr(false),
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 0 {
		t.Error("expected no HTTP request when production + config false")
	}
}

func TestSendTelemetryPing_ConnectionRefused(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "")
	// Port 1 is reserved and should refuse connections on all platforms.
	t.Setenv("AXONFLOW_CHECKPOINT_URL", "http://127.0.0.1:1")

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	// Must not panic or hang — silent failure on connection error.
	done := make(chan struct{})
	go func() {
		client.sendTelemetryPing()
		close(done)
	}()

	select {
	case <-done:
		// Completed without crashing - good
	case <-time.After(10 * time.Second):
		t.Fatal("sendTelemetryPing did not complete within 10 seconds on connection refused")
	}
}

func TestSendTelemetryPing_OutdatedVersion(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "")
	// Server returns a newer version to trigger the debug warning.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: "99.99.99"})
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
			Debug:        true,
		},
	}

	// Capture log output to verify the version warning is emitted.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // restore default

	client.sendTelemetryPing()

	logOutput := buf.String()
	if logOutput == "" {
		t.Error("expected version warning log output in debug mode, got nothing")
	}
	if !bytes.Contains(buf.Bytes(), []byte("newer SDK version")) {
		t.Errorf("expected log to contain 'newer SDK version', got %q", logOutput)
	}
	if !bytes.Contains(buf.Bytes(), []byte("99.99.99")) {
		t.Errorf("expected log to contain new version '99.99.99', got %q", logOutput)
	}
	if !bytes.Contains(buf.Bytes(), []byte(Version)) {
		t.Errorf("expected log to contain current version '%s', got %q", Version, logOutput)
	}
}

func TestSendTelemetryPing_ProductionNoCreds(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "")
	var called atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode: "production",
			// No ClientID or ClientSecret — telemetry still ON (credentials no longer affect default)
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 1 {
		t.Errorf("expected exactly 1 HTTP request for production mode without credentials, got %d", called.Load())
	}
}
