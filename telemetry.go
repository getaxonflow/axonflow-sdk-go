package axonflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	defaultCheckpointURL = "https://checkpoint.getaxonflow.com/v1/ping"
	telemetryTimeout     = 3 * time.Second
)

// telemetryPayload is the JSON body sent to the checkpoint endpoint.
type telemetryPayload struct {
	SDK             string  `json:"sdk"`
	SDKVersion      string  `json:"sdk_version"`
	PlatformVersion *string `json:"platform_version"`
	OS              string  `json:"os"`
	Arch            string  `json:"arch"`
	RuntimeVersion  string  `json:"runtime_version"`
	DeploymentMode  string  `json:"deployment_mode"`
	// EndpointType: SDK-derived classification of the configured endpoint.
	// One of: "localhost", "private_network", "remote", "unknown". See
	// ClassifyEndpoint. The raw URL is never sent. Issue #1525.
	EndpointType string   `json:"endpoint_type"`
	Features     []string `json:"features"`
	InstanceID   string   `json:"instance_id"`
}

// EndpointType classifications for telemetry.
const (
	EndpointTypeLocalhost      = "localhost"
	EndpointTypePrivateNetwork = "private_network"
	EndpointTypeRemote         = "remote"
	EndpointTypeUnknown        = "unknown"
)

// ClassifyEndpoint classifies the configured AxonFlow endpoint URL into one
// of localhost | private_network | remote | unknown.
//
// The raw URL is never sent to the checkpoint service — only the classification.
// See issue #1525.
//
//   - "localhost": localhost, 127/8, ::1, 0.0.0.0, *.localhost
//   - "private_network": RFC1918 v4, link-local (169.254/16), ULA (fc00::/7),
//     and the suffixes .local, .internal, .lan, .intranet
//   - "remote": everything else
//   - "unknown": on parse failure
func ClassifyEndpoint(endpoint string) string {
	if os.Getenv("AXONFLOW_TRY") == "1" {
		return "community-saas"
	}
	if endpoint == "" {
		return EndpointTypeUnknown
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return EndpointTypeUnknown
	}
	host := strings.ToLower(u.Hostname())

	if host == "localhost" || host == "0.0.0.0" || strings.HasSuffix(host, ".localhost") {
		return EndpointTypeLocalhost
	}
	for _, suffix := range []string{".local", ".internal", ".lan", ".intranet"} {
		if strings.HasSuffix(host, suffix) {
			return EndpointTypePrivateNetwork
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return EndpointTypeRemote
	}
	if ip.IsLoopback() {
		return EndpointTypeLocalhost
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return EndpointTypePrivateNetwork
	}
	return EndpointTypeRemote
}

// telemetryResponse is the JSON response from the checkpoint endpoint.
type telemetryResponse struct {
	LatestVersion string `json:"latest_version"`
}

// healthVersionResponse is a minimal struct for extracting the version from /health.
type healthVersionResponse struct {
	Version string `json:"version"`
}

// detectPlatformVersion calls the agent's /health endpoint to get the platform
// version. Returns nil on any failure. The caller's context controls the
// deadline so the health probe and the checkpoint POST share one budget —
// preventing the two 3-second timeouts from stacking into ~6s of blocking on
// unreachable endpoints (see issue #1693).
func detectPlatformVersion(ctx context.Context, endpoint string) *string {
	if endpoint == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/health", nil)
	if err != nil {
		return nil
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var health healthVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil
	}
	if health.Version == "" {
		return nil
	}
	return &health.Version
}

// generateInstanceID creates a random UUID v4 string without external dependencies.
func generateInstanceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version 4
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// isTelemetryEnabled determines whether telemetry should be sent for this client.
//
// Priority order:
//  1. AXONFLOW_TELEMETRY=off in the environment disables telemetry (always wins).
//  2. Config override (TelemetryEnabled *bool) — if non-nil, use its value.
//  3. Default — ON for all modes except sandbox.
//
// DO_NOT_TRACK is intentionally NOT honored. It is commonly inherited from
// host tools and developer environments (CLIs like Codex and Claude Code
// inject it unconditionally), which makes it an unreliable expression of
// user intent for AxonFlow telemetry.
func (c *AxonFlowClient) isTelemetryEnabled() bool {
	// 1. Environment-level opt-out always wins (cannot be overridden by config).
	if strings.EqualFold(strings.TrimSpace(os.Getenv("AXONFLOW_TELEMETRY")), "off") {
		return false
	}

	// 2. Explicit config override.
	if c.config.TelemetryEnabled != nil {
		return *c.config.TelemetryEnabled
	}

	// 3. Default: ON everywhere except sandbox mode.
	return c.config.Mode != "sandbox"
}

// sendTelemetryPing sends a synchronous telemetry ping to the checkpoint
// service under a single shared context deadline covering both the /health
// probe and the checkpoint POST. Never returns an error — all failures are
// silently ignored. In debug mode, a version-outdated warning may be logged.
//
// Previously invoked as a goroutine (`go client.sendTelemetryPing()`), but
// short-lived processes (CLI, serverless, quickstart scripts) returned from
// main() before the goroutine's POST could complete, silently dropping the
// ping. The function is now called synchronously from NewClient.
//
// Worst-case blocking time: telemetryTimeout (3s). Both detectPlatformVersion
// and the checkpoint POST share the same context, so the individual
// timeouts no longer stack. See issue #1693.
func (c *AxonFlowClient) sendTelemetryPing() {
	if !c.isTelemetryEnabled() {
		return
	}

	log.Printf("[AxonFlow] Anonymous telemetry enabled. Opt out: AXONFLOW_TELEMETRY=off | https://docs.getaxonflow.com/docs/telemetry")

	// Determine the checkpoint URL.
	checkpointURL := os.Getenv("AXONFLOW_CHECKPOINT_URL")
	if checkpointURL == "" {
		checkpointURL = defaultCheckpointURL
	}

	// Determine deployment mode.
	deploymentMode := c.config.Mode
	if deploymentMode == "" {
		deploymentMode = "production"
	}

	// Single shared deadline covering the ENTIRE telemetry path (health
	// probe + checkpoint POST). Without this, the /health GET and the
	// checkpoint POST each had their own timeout (2s + 3s), stacking into
	// ~5s of potential blocking on NewClient when endpoints are
	// unreachable — defeating the "bounded at telemetryTimeout" guarantee.
	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()

	// Detect platform version from health endpoint (uses the shared deadline).
	platformVersion := detectPlatformVersion(ctx, c.config.Endpoint)

	payload := telemetryPayload{
		SDK:             "go",
		SDKVersion:      Version,
		PlatformVersion: platformVersion,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		RuntimeVersion:  strings.TrimPrefix(runtime.Version(), "go"),
		DeploymentMode:  deploymentMode,
		EndpointType:    ClassifyEndpoint(c.config.Endpoint),
		Features:        []string{},
		InstanceID:      generateInstanceID(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	// POST uses whatever budget remains after the health probe.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, checkpointURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: telemetryTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Parse response for version check (debug mode only).
	if c.config.Debug {
		var telResp telemetryResponse
		if err := json.NewDecoder(resp.Body).Decode(&telResp); err == nil {
			if telResp.LatestVersion != "" && telResp.LatestVersion != Version {
				log.Printf("[AxonFlow] A newer SDK version is available: %s (current: %s)", telResp.LatestVersion, Version)
			}
		}
	}
}
