package axonflow

import (
	"bytes"
	"encoding/json"
	"io"
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
	t.Setenv("ORG_ID", "") // exercise sentinel path
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
	// v1 telemetry-schema: deployment_mode now derives from endpoint host
	// (not config.Mode). Empty endpoint resolves to "unknown".
	if received.DeploymentMode != "unknown" {
		t.Errorf("expected deployment_mode=unknown (empty endpoint), got %q", received.DeploymentMode)
	}
	if received.TelemetryType != "sdk" {
		t.Errorf("expected telemetry_type=sdk, got %q", received.TelemetryType)
	}
	if received.Features == nil {
		t.Error("expected features to be non-nil (empty array)")
	}
	if received.InstanceID == "" {
		t.Error("expected instance_id to be non-empty")
	}
	if received.OrgID != OrgIDLocalDevSentinel {
		t.Errorf("expected org_id=%q (sentinel, ORG_ID unset), got %q", OrgIDLocalDevSentinel, received.OrgID)
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
// buildPayload tests
// ---------------------------------------------------------------------------

func TestBuildPayload(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Run("deployment_mode classifies from endpoint host (v1 schema)", func(t *testing.T) {
		cases := []struct {
			name     string
			endpoint string
			tryFlag  string
			want     string
		}{
			{"try.getaxonflow.com", "https://try.getaxonflow.com", "", "community_saas"},
			{"AXONFLOW_TRY=1 wins on remote host", "https://my-proxy.example.com", "1", "community_saas"},
			{"public host -> self_hosted", "https://api.example.com", "", "self_hosted"},
			{"unparseable -> unknown", "not a url", "", "unknown"},
			{"empty -> unknown", "", "", "unknown"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var received telemetryPayload

				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					json.NewDecoder(r.Body).Decode(&received)
					json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
				}))
				defer srv.Close()

				t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)
				t.Setenv("AXONFLOW_TRY", tc.tryFlag)

				client := &AxonFlowClient{
					config: AxonFlowConfig{
						Endpoint:     tc.endpoint,
						Mode:         "production",
						ClientID:     "id",
						ClientSecret: "sec",
					},
				}

				client.sendTelemetryPing()

				if received.DeploymentMode != tc.want {
					t.Errorf("expected deployment_mode=%q, got %q", tc.want, received.DeploymentMode)
				}
				if received.TelemetryType != "sdk" {
					t.Errorf("expected telemetry_type=sdk, got %q", received.TelemetryType)
				}
			})
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
	// v1 schema: deployment_mode classifies from endpoint host, not config.Mode.
	// The empty endpoint here resolves to "unknown".
	if received.DeploymentMode != "unknown" {
		t.Errorf("expected payload DeploymentMode=%q (empty endpoint), got %q", "unknown", received.DeploymentMode)
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

// TestTelemetryOrgID_HelperUnit asserts the env→sentinel fallback. Issue #2277.
func TestTelemetryOrgID_HelperUnit(t *testing.T) {
	t.Run("ORG_ID set wins", func(t *testing.T) {
		t.Setenv("ORG_ID", "acme-corp")
		if got := telemetryOrgID(); got != "acme-corp" {
			t.Errorf("expected ORG_ID env to win, got %q", got)
		}
	})
	t.Run("ORG_ID unset returns local-dev-org sentinel", func(t *testing.T) {
		t.Setenv("ORG_ID", "")
		if got := telemetryOrgID(); got != OrgIDLocalDevSentinel {
			t.Errorf("expected sentinel %q, got %q", OrgIDLocalDevSentinel, got)
		}
	})
	t.Run("cs_-prefixed Community SaaS shape", func(t *testing.T) {
		t.Setenv("ORG_ID", "cs_abc12345-6789-4def-9012-345678901234")
		if got := telemetryOrgID(); got != "cs_abc12345-6789-4def-9012-345678901234" {
			t.Errorf("expected ORG_ID to pass through, got %q", got)
		}
	})
}

// TestSendTelemetryPing_OrgIDOnWire asserts the org_id field actually
// reaches the wire payload — the functional end-to-end check that
// closes #2277 R2. Uses httptest.Server (the same pattern existing
// tests use) which is the real net/http stack on both sides.
func TestSendTelemetryPing_OrgIDOnWire(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")

	cases := []struct {
		name     string
		orgIDEnv string
		want     string
	}{
		{"operator-supplied ORG_ID (self-hosted)", "acme-corp", "acme-corp"},
		{"cs_-prefixed tenant identifier (Community SaaS)", "cs_e3a4b5c6-d7e8-4f90-a1b2-c3d4e5f6a7b8", "cs_e3a4b5c6-d7e8-4f90-a1b2-c3d4e5f6a7b8"},
		{"unset becomes local-dev-org sentinel", "", OrgIDLocalDevSentinel},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ORG_ID", tc.orgIDEnv)

			var received telemetryPayload
			// Capture the raw JSON too so we can prove the field is
			// physically on the wire (not just decoded by our local
			// struct tag — a mutation that drops the json tag would
			// be silently re-attached by Go's struct-name fallback).
			var rawBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rawBody, _ = io.ReadAll(r.Body)
				_ = json.Unmarshal(rawBody, &received)
				json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
			}))
			defer srv.Close()
			t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

			client := &AxonFlowClient{
				config: AxonFlowConfig{Mode: "production", ClientID: "id", ClientSecret: "sec"},
			}
			client.sendTelemetryPing()

			if received.OrgID != tc.want {
				t.Errorf("decoded OrgID = %q, want %q", received.OrgID, tc.want)
			}

			// Wire-level assertion: the literal JSON field name "org_id"
			// must appear in the body alongside the expected value. Defends
			// against tag-removal mutations.
			if !strings.Contains(string(rawBody), `"org_id":"`+tc.want+`"`) {
				t.Errorf("wire JSON missing literal \"org_id\":%q field; got body: %s", tc.want, string(rawBody))
			}
		})
	}
}

// TestSendTelemetryPing_OrgIDAlwaysPresent guards against a future
// refactor accidentally tagging the field with omitempty + emitting an
// empty value. Mutation-test trigger: remove the OrgID population line
// in payload construction → this test fails because the literal
// "org_id" string is absent from the wire body.
func TestSendTelemetryPing_OrgIDAlwaysPresent(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Setenv("ORG_ID", "")

	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ = io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
	}))
	defer srv.Close()
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{Mode: "production", ClientID: "id", ClientSecret: "sec"},
	}
	client.sendTelemetryPing()

	if !strings.Contains(string(rawBody), `"org_id":"local-dev-org"`) {
		t.Errorf("expected wire body to ALWAYS contain org_id (sentinel when env unset), got: %s", string(rawBody))
	}
}
