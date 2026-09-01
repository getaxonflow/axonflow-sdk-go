package axonflow

import (
	"bytes"
	"context"
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

// ---------------------------------------------------------------------------
// license_tier telemetry field (#3619)
//
// Contract under test: the platform's licence tier rides along on the /health
// response the SDK ALREADY fetches for platform_version, is forwarded to the
// checkpoint receiver verbatim, and is OMITTED — never defaulted — whenever it
// could not be learned.
// ---------------------------------------------------------------------------

// newTierHealthServer starts a stand-in platform whose /health returns the
// supplied raw JSON body and status code. Returns the base endpoint the SDK
// should be configured with.
func newTierHealthServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// captureTelemetryWire runs one ping against a capturing checkpoint receiver
// with the client pointed at platformEndpoint, and returns the raw wire body.
func captureTelemetryWire(t *testing.T, platformEndpoint string) []byte {
	t.Helper()
	t.Setenv("AXONFLOW_TELEMETRY", "")

	var rawBody atomic.Value
	rawBody.Store([]byte{})
	checkpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rawBody.Store(b)
		_ = json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
	}))
	defer checkpoint.Close()
	t.Setenv("AXONFLOW_CHECKPOINT_URL", checkpoint.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
			Endpoint:     platformEndpoint,
		},
	}
	client.sendTelemetryPing()
	return rawBody.Load().([]byte)
}

// TestTelemetryWireCarriesTierVerbatimForEveryPlatformEmittedValue asserts
// that each value the platform's currentLicenseTier() can produce reaches the
// wire byte-for-byte, with no client-side case folding or alias mapping —
// normalization is the receiver's job (checkpoint-service
// NormalizeLicenseTier), and folding here would mask a tier this SDK build
// predates.
func TestTelemetryWireCarriesTierVerbatimForEveryPlatformEmittedValue(t *testing.T) {
	// Exactly the values platform/agent/run.go currentLicenseTier() can
	// return, plus the csaas "Plus" alias its health serializer emits.
	cases := []string{
		"community",  // unlicensed default
		"evaluation", // trial licence
		"Enterprise", // paid tier
		"Plus",       // csaas alias for EnterprisePlus
		"starting",   // transient pre-init — a real signal, not an error
	}

	for _, tier := range cases {
		t.Run(tier, func(t *testing.T) {
			endpoint := newTierHealthServer(t, http.StatusOK,
				`{"status":"healthy","version":"10.3.0","tier":"`+tier+`"}`)

			body := captureTelemetryWire(t, endpoint)

			// Wire-level assertion on the literal JSON, not on a struct
			// decode: a mutation dropping the `json:"license_tier"` tag
			// would otherwise be silently re-attached by Go's field-name
			// fallback and the test would still pass.
			want := `"license_tier":"` + tier + `"`
			if !strings.Contains(string(body), want) {
				t.Errorf("wire body missing %s\ngot: %s", want, string(body))
			}
		})
	}
}

// TestTelemetryWireOmitsTierWheneverHealthDidNotYieldOne is the load-bearing
// fail-open assertion. For every way the health probe can fail, the ping must
// still be delivered and the field must be ABSENT from the JSON — never ""
// and never a substituted default. Emitting "community" for a platform we
// could not reach would be a false claim about a customer's deployment.
func TestTelemetryWireOmitsTierWheneverHealthDidNotYieldOne(t *testing.T) {
	unreachable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unreachableURL := unreachable.URL
	unreachable.Close() // nothing is listening at this address any more

	cases := []struct {
		name     string
		endpoint func(t *testing.T) string
	}{
		{
			name:     "endpoint not configured",
			endpoint: func(*testing.T) string { return "" },
		},
		{
			name:     "platform unreachable (connection refused)",
			endpoint: func(*testing.T) string { return unreachableURL },
		},
		{
			name: "health returns 500",
			endpoint: func(t *testing.T) string {
				return newTierHealthServer(t, http.StatusInternalServerError, `{"tier":"Enterprise"}`)
			},
		},
		{
			name: "health returns malformed JSON",
			endpoint: func(t *testing.T) string {
				return newTierHealthServer(t, http.StatusOK, `{"tier":"Enterprise"`)
			},
		},
		{
			name: "health returns JSON without a tier key",
			endpoint: func(t *testing.T) string {
				return newTierHealthServer(t, http.StatusOK, `{"status":"healthy","version":"10.3.0"}`)
			},
		},
		{
			name: "health returns an empty tier value",
			endpoint: func(t *testing.T) string {
				return newTierHealthServer(t, http.StatusOK, `{"version":"10.3.0","tier":""}`)
			},
		},
		{
			name: "health returns a body over the parse cap",
			endpoint: func(t *testing.T) string {
				oversized := `{"tier":"Enterprise","pad":"` + strings.Repeat("x", maxHealthBodyBytes+1) + `"}`
				return newTierHealthServer(t, http.StatusOK, oversized)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := captureTelemetryWire(t, tc.endpoint(t))

			// The ping itself must still have been delivered — telemetry
			// degrades, it does not stop.
			if len(body) == 0 {
				t.Fatalf("no ping delivered; the health-probe failure must not suppress the ping")
			}
			if !strings.Contains(string(body), `"telemetry_type":"sdk"`) {
				t.Errorf("ping body is not a well-formed sdk ping: %s", string(body))
			}
			// The field must be absent entirely, not present-and-empty.
			if strings.Contains(string(body), "license_tier") {
				t.Errorf("license_tier must be OMITTED when not learned, got: %s", string(body))
			}
		})
	}
}

// TestHealthProbeLearnsVersionAndTierIndependently pins that one field's
// absence never discards the other. The pre-#3619 probe returned early when
// `version` was empty; had the tier been read after that guard, a platform
// answering with a tier but no version would have reported no tier at all.
func TestHealthProbeLearnsVersionAndTierIndependently(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantVersion *string
		wantTier    *string
	}{
		{
			name:        "both present",
			body:        `{"version":"10.3.0","tier":"Enterprise"}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    strPtr("Enterprise"),
		},
		{
			name:        "tier present, version absent",
			body:        `{"tier":"Enterprise"}`,
			wantVersion: nil,
			wantTier:    strPtr("Enterprise"),
		},
		{
			name:        "version present, tier absent",
			body:        `{"version":"10.3.0"}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    nil,
		},
		{
			name:        "neither present",
			body:        `{"status":"healthy"}`,
			wantVersion: nil,
			wantTier:    nil,
		},
		// The rows that matter most: a badly-TYPED member must not take the
		// other field down with it. With a typed struct carrying both fields,
		// one bad member fails the whole decode — so adding the tier would
		// have silently regressed platform_version, a field that worked
		// before. These pin that it cannot happen again.
		{
			name:        "numeric tier does not discard a good version",
			body:        `{"version":"10.3.0","tier":42}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    nil,
		},
		{
			name:        "object tier does not discard a good version",
			body:        `{"version":"10.3.0","tier":{"name":"Enterprise"}}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    nil,
		},
		{
			name:        "array tier does not discard a good version",
			body:        `{"version":"10.3.0","tier":["Enterprise"]}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    nil,
		},
		{
			name:        "numeric version does not discard a good tier",
			body:        `{"version":42,"tier":"Enterprise"}`,
			wantVersion: nil,
			wantTier:    strPtr("Enterprise"),
		},
		{
			name:        "boolean tier is not coerced onto the wire",
			body:        `{"version":"10.3.0","tier":true}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    nil,
		},
		{
			name:        "null tier is not learned",
			body:        `{"version":"10.3.0","tier":null}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    nil,
		},
		{
			name:        "a JSON array body yields nothing",
			body:        `[1,2,3]`,
			wantVersion: nil,
			wantTier:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTierHealthServer(t, http.StatusOK, tc.body)
			ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
			defer cancel()

			probe := probePlatformHealth(ctx, endpoint)

			assertStrPtr(t, "PlatformVersion", probe.PlatformVersion, tc.wantVersion)
			assertStrPtr(t, "LicenseTier", probe.LicenseTier, tc.wantTier)
		})
	}
}

// TestTierProbeDoesNotStackASecondTimeoutOntoTheTelemetryBudget guards issue
// #1693: the health probe and the checkpoint POST share ONE caller-supplied
// deadline. Reading the tier must not introduce a second request or a second
// timeout. A slow /health therefore consumes the shared budget and the whole
// ping returns within it, rather than blocking for probe+POST back to back.
func TestTierProbeDoesNotStackASecondTimeoutOntoTheTelemetryBudget(t *testing.T) {
	// A platform that accepts the connection and then never answers.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()

	budget := 400 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	probe := probePlatformHealth(ctx, slow.URL)
	elapsed := time.Since(start)

	if probe.LicenseTier != nil || probe.PlatformVersion != nil {
		t.Errorf("a stalled /health must yield nothing, got %+v", probe)
	}
	// Bounded by the shared deadline, not by an independent per-probe
	// timeout. Generous slack for CI scheduling, but far below the ~2x
	// that a stacked second timeout would produce.
	if elapsed > budget+300*time.Millisecond {
		t.Errorf("probe took %v, exceeds the shared %v budget — a second timeout is stacking", elapsed, budget)
	}
}

// TestTheWholePingHonoursOneDeadlineWhenHealthStalls exercises the CALL SITE,
// not just the probe. TestTierProbeDoesNotStackASecondTimeoutOntoTheTelemetryBudget
// hands probePlatformHealth a budget directly, so it stays green even if
// sendTelemetryPingNow stops passing the shared ctx — the exact mutation that
// would restore issue #1693. Testing the predicate is not testing the wiring.
//
// probePlatformHealth uses an http.Client with NO timeout of its own, so ctx is
// the only bound: a call site that passed context.Background() would block
// forever against a blackholed /health.
func TestTheWholePingHonoursOneDeadlineWhenHealthStalls(t *testing.T) {
	t.Setenv("AXONFLOW_TELEMETRY", "")

	// A platform that accepts the connection and never answers.
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer stalled.Close()

	checkpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
	}))
	defer checkpoint.Close()
	t.Setenv("AXONFLOW_CHECKPOINT_URL", checkpoint.URL)

	client := &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
			Endpoint:     stalled.URL,
		},
	}

	budget := 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	_ = client.sendTelemetryPingNow(ctx)
	elapsed := time.Since(start)

	if elapsed > budget+500*time.Millisecond {
		t.Errorf("the whole ping took %v against a %v budget — the call site is not "+
			"passing the shared deadline into the health probe (issue #1693)", elapsed, budget)
	}
}

// TestLicenseTierDoesNotAlterDeploymentMode pins that the three
// similarly-named concepts stay separate: the SDK's endpoint-derived
// TOPOLOGY dimension must be byte-identical whether or not the platform
// reported a tier.
func TestLicenseTierDoesNotAlterDeploymentMode(t *testing.T) {
	withTier := newTierHealthServer(t, http.StatusOK, `{"version":"10.3.0","tier":"Enterprise"}`)
	withoutTier := newTierHealthServer(t, http.StatusOK, `{"version":"10.3.0"}`)

	for _, endpoint := range []string{withTier, withoutTier} {
		body := captureTelemetryWire(t, endpoint)
		// Both stand-ins are 127.0.0.1 httptest servers => self_hosted.
		if !strings.Contains(string(body), `"deployment_mode":"`+DeploymentModeSelfHosted+`"`) {
			t.Errorf("deployment_mode changed by the tier field; body: %s", string(body))
		}
	}
}

// newCountingTierHealthServer starts a stand-in platform whose /health
// returns the supplied 200 body, and additionally counts every GET /health it
// serves. Returns the base endpoint and the live counter.
func newCountingTierHealthServer(t *testing.T, body string) (string, *atomic.Int64) {
	t.Helper()
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		served.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &served
}

// TestExactlyOneHealthRequestPerPing pins the headline contract of this
// change: the tier rides along on the /health response ALREADY fetched for
// platform_version, so adding it costs NO new network call.
//
// Nothing else in this suite counts requests, so a second probe added to the
// telemetry path would leave every other test green while doubling the
// telemetry path's blocking budget and its failure surface. The Java SDK pins
// the same contract in TelemetryLicenseTierTest.exactlyOneHealthRequestPerPing;
// this is that test's Go twin.
func TestExactlyOneHealthRequestPerPing(t *testing.T) {
	endpoint, healthRequests := newCountingTierHealthServer(t,
		`{"status":"healthy","version":"10.3.0","tier":"Enterprise"}`)

	body := captureTelemetryWire(t, endpoint)

	// Anti-vacuity: a count is only evidence if a complete ping actually ran.
	// Without this, a change that stopped probing altogether would report
	// zero requests and could be mistaken for a passing "no extra call".
	if !strings.Contains(string(body), `"license_tier":"Enterprise"`) {
		t.Fatalf("the ping did not carry the probed tier, so the request count "+
			"below would prove nothing; body: %s", string(body))
	}

	if got := healthRequests.Load(); got != 1 {
		t.Errorf("GET /health served %d times for one ping, want exactly 1 — "+
			"the licence tier must come from the response already fetched for "+
			"platform_version, never from a second request", got)
	}
}

func strPtr(s string) *string { return &s }

func assertStrPtr(t *testing.T, field string, got, want *string) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s = %q, want nil (not learned)", field, *got)
	case want != nil && got == nil:
		t.Errorf("%s = nil, want %q", field, *want)
	case want != nil && got != nil && *got != *want:
		t.Errorf("%s = %q, want %q", field, *got, *want)
	}
}
