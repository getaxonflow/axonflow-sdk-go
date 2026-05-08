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
	// Clear AXONFLOW_TELEMETRY so tests can verify default behavior.
	// TestMain sets AXONFLOW_TELEMETRY=off to prevent telemetry pings.
	t.Setenv("AXONFLOW_TELEMETRY", "")

	// v8: telemetry is ON by default for every mode. The mode-based
	// suppression that used to disable sandbox-mode pings was removed —
	// sandbox-mode pings now fire and are tagged Stream="sandbox" in the
	// payload so analytics can distinguish them server-side.
	cases := []struct {
		name string
		cfg  AxonFlowConfig
	}{
		{"on for sandbox mode (was suppressed in v7.x)", AxonFlowConfig{Mode: "sandbox", ClientID: "id", ClientSecret: "sec"}},
		{"on for production without credentials", AxonFlowConfig{Mode: "production"}},
		{"on for production with only client ID", AxonFlowConfig{Mode: "production", ClientID: "id"}},
		{"on for production with only client secret", AxonFlowConfig{Mode: "production", ClientSecret: "sec"}},
		{"on for production with credentials", AxonFlowConfig{Mode: "production", ClientID: "id", ClientSecret: "sec"}},
		{"on for empty mode (legacy default)", AxonFlowConfig{ClientID: "id", ClientSecret: "sec"}},
		{"on for unknown custom mode", AxonFlowConfig{Mode: "staging", ClientID: "id", ClientSecret: "sec"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &AxonFlowClient{config: tc.cfg}
			if !client.isTelemetryEnabled() {
				t.Errorf("expected telemetry enabled, got disabled (config=%+v)", tc.cfg)
			}
		})
	}
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

	t.Run("DO_NOT_TRACK=1 alone does NOT disable (DNT no longer honored)", func(t *testing.T) {
		t.Setenv("DO_NOT_TRACK", "1")
		t.Setenv("AXONFLOW_TELEMETRY", "")
		if !prodClient().isTelemetryEnabled() {
			t.Error("expected telemetry enabled — DO_NOT_TRACK is no longer honored as an AxonFlow opt-out")
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

	t.Run("AXONFLOW_TELEMETRY=off disables even with DO_NOT_TRACK=1 also set", func(t *testing.T) {
		t.Setenv("DO_NOT_TRACK", "1")
		t.Setenv("AXONFLOW_TELEMETRY", "off")
		if prodClient().isTelemetryEnabled() {
			t.Error("expected telemetry disabled — AXONFLOW_TELEMETRY=off is the canonical opt-out")
		}
	})
}

// TestIsTelemetryEnabled_ConfigOverride was removed in v8.0 along with the
// TelemetryEnabled config field. AXONFLOW_TELEMETRY=off is the SOLE opt-out
// path; programmatic suppression is no longer supported. See CHANGELOG.

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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "off")

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}

	client.sendTelemetryPing()

	if called.Load() != 0 {
		t.Error("expected no HTTP request when telemetry is opted out via AXONFLOW_TELEMETRY=off")
	}
}

func TestSendTelemetryPing_SilentFailure(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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

				client := &AxonFlowClient{
					config: AxonFlowConfig{
						Mode:         mode,
						ClientID:     "id",
						ClientSecret: "sec",
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

		client := &AxonFlowClient{
			config: AxonFlowConfig{
				ClientID:     "id",
				ClientSecret: "sec",
			},
		}

		client.sendTelemetryPing()

		if received.DeploymentMode != "production" {
			t.Errorf("expected deployment_mode=production when mode is empty, got %q", received.DeploymentMode)
		}
	})

	t.Run("stream=sandbox tag emitted only for sandbox mode", func(t *testing.T) {
		// New v8 contract: sandbox-mode pings carry stream="sandbox" so
		// analytics can distinguish them. Production and other modes omit
		// the field — the server defaults empty to "heartbeat". This is the
		// payload-side companion to the server-side wire-allowlist gate.
		cases := []struct {
			mode       string
			wantStream string
		}{
			{"production", ""},
			{"sandbox", "sandbox"},
			{"staging", ""},
			{"", ""},
		}
		for _, tc := range cases {
			t.Run(tc.mode, func(t *testing.T) {
				var received telemetryPayload
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					json.NewDecoder(r.Body).Decode(&received)
					json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
				}))
				defer srv.Close()
				t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)
				client := &AxonFlowClient{
					config: AxonFlowConfig{Mode: tc.mode, ClientID: "id", ClientSecret: "sec"},
				}
				client.sendTelemetryPing()
				if received.Stream != tc.wantStream {
					t.Errorf("Stream = %q, want %q (mode=%q)", received.Stream, tc.wantStream, tc.mode)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// Sandbox-mode + stream classification tests (v8)
// ---------------------------------------------------------------------------

// TestSendTelemetryPing_SandboxFiresWithStreamTag verifies the new v8 contract:
// sandbox-mode clients fire telemetry (no longer suppressed) and tag their
// payload with stream="sandbox" so analytics can distinguish dev/test pings
// from production heartbeat. Pre-v8 this test would have asserted no ping was
// sent — see CHANGELOG v8.0.0 for the rationale of the behavior flip.
func TestSendTelemetryPing_SandboxFiresWithStreamTag(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")
	var called atomic.Int32
	var received telemetryPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		json.NewDecoder(r.Body).Decode(&received)
		json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
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

	if called.Load() != 1 {
		t.Errorf("expected exactly 1 HTTP request for sandbox mode (v8: no longer suppressed), got %d", called.Load())
	}
	if received.Stream != "sandbox" {
		t.Errorf("expected payload Stream=%q, got %q", "sandbox", received.Stream)
	}
	if received.DeploymentMode != "sandbox" {
		t.Errorf("expected payload DeploymentMode=%q, got %q", "sandbox", received.DeploymentMode)
	}
}

func TestSendTelemetryPing_ConnectionRefused(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
	t.Setenv("AXONFLOW_TELEMETRY", "")
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
