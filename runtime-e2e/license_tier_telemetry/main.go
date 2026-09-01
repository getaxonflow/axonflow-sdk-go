//go:build ignore

// runtime-e2e/license_tier_telemetry/main.go
//
// Real-wire proof of the SDK's license_tier telemetry field (#3619).
//
// The SDK does not expose its internal http.Client, so this proof runs real
// listeners on both sides of the telemetry path: a stand-in platform serving
// /health, and a stand-in checkpoint receiver capturing the outgoing POST.
// Bytes flow real -> real through net/http; nothing is mocked or injected.
//
// TWO MODES:
//
//	# 1. MATRIX (default) — every tier value and every fail-open path,
//	#    against a local stand-in platform.
//	go run runtime-e2e/license_tier_telemetry/main.go
//
//	# 2. REAL PLATFORM — drive the SDK against an actual running agent and
//	#    cross-check the wire value against that agent's own /health.
//	AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
//	  go run runtime-e2e/license_tier_telemetry/main.go
//
// Mode 2 is the one that proves the contract end to end: it reads the tier
// from the live platform independently, then asserts the SDK put THAT value
// on the telemetry wire verbatim.
//
// What it asserts:
//
//  1. Each value the platform's currentLicenseTier() can emit — community,
//     evaluation, Enterprise, the csaas "Plus" alias, and the transient
//     "starting" — reaches the wire byte-for-byte, unfolded.
//  2. license_tier is ABSENT from the JSON on every path where the tier was
//     not learned (platform down, 500, malformed body, no tier key, empty
//     tier value), and the ping is still delivered on each of them.
//  3. deployment_mode is unaffected by the tier — the two dimensions stay
//     separate.
//
// Mutation proof: delete `LicenseTier: probe.LicenseTier,` from the payload
// literal in telemetry.go and rerun; case 1 fails with
// "license_tier absent from wire". Drop the `health.Tier != ""` guard in
// probePlatformHealth and case 2's empty-tier rows fail with
// "license_tier present as \"\"".

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures int

func fail(format string, args ...any) {
	failures++
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
}

func pass(format string, args ...any) {
	fmt.Printf("PASS: "+format+"\n", args...)
}

// clearStamp removes the 7-day heartbeat stamp so the ping actually fires.
// Env injection is too late here — the shared heartbeat gate is a package
// var initialized before main() runs.
func clearStamp() {
	if cacheDir, err := os.UserCacheDir(); err == nil {
		_ = os.Remove(filepath.Join(cacheDir, "axonflow", "go-telemetry-last-sent"))
	}
}

// childEnvVar marks the re-executed child process that actually constructs
// the SDK client. Each case needs a FRESH PROCESS: sharedHeartbeat is a
// process-global singleton (see heartbeat.go), so a single process emits at
// most one ping no matter how many clients it builds. Driving the matrix
// in-process would silently assert against the first case's body every time.
const childEnvVar = "AXONFLOW_E2E_TIER_CHILD"

// runChild is the re-executed half: it builds one real client against the
// endpoints the parent supplied and lets the SDK's own startup goroutine
// deliver the ping to the parent's receiver.
func runChild() {
	clearStamp()
	_ = axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     os.Getenv("AXONFLOW_E2E_PLATFORM_ENDPOINT"),
		ClientID:     "rt-e2e",
		ClientSecret: "rt-e2e",
		Mode:         "production",
	})
	// The SDK fires telemetry on a startup goroutine; hold the process open
	// long enough for the health probe + POST to complete under their
	// shared 3s budget.
	time.Sleep(5 * time.Second)
}

// captureOnePing runs one real client — in a fresh child process — against
// platformEndpoint and returns the raw telemetry body the parent received.
func captureOnePing(platformEndpoint string) []byte {
	var captured atomic.Value
	captured.Store([]byte{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()

	done := make(chan struct{})
	var once sync.Once
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured.Store(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"latest_version": "0.0.0"})
		once.Do(func() { close(done) })
	})}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve self: %v\n", err)
		os.Exit(2)
	}

	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(),
		childEnvVar+"=1",
		"AXONFLOW_E2E_PLATFORM_ENDPOINT="+platformEndpoint,
		"AXONFLOW_CHECKPOINT_URL=http://"+listener.Addr().String()+"/v1/ping",
		"AXONFLOW_TELEMETRY=",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "spawn child: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = cmd.Process.Kill() }()

	select {
	case <-done:
	case <-time.After(12 * time.Second):
	}
	return captured.Load().([]byte)
}

// startStandInPlatform serves /health with the given status and raw body.
func startStandInPlatform(status int, body string) (endpoint string, stop func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(listener) }()
	return "http://" + listener.Addr().String(), func() { _ = srv.Shutdown(context.Background()) }
}

func tierOnWire(body []byte) (value string, present bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	raw, ok := payload["license_tier"]
	if !ok {
		return "", false
	}
	s, _ := raw.(string)
	return s, true
}

func main() {
	if os.Getenv(childEnvVar) != "" {
		runChild()
		return
	}

	if endpoint := os.Getenv("AXONFLOW_E2E_PLATFORM_ENDPOINT"); endpoint != "" {
		runAgainstRealPlatform(endpoint)
	} else {
		runMatrix()
	}

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "\n%d assertion(s) FAILED\n", failures)
		os.Exit(1)
	}
	fmt.Printf("\nAll assertions passed.\n")
}

// runAgainstRealPlatform drives the SDK at a live agent, then cross-checks
// the telemetry wire value against that agent's own /health response.
func runAgainstRealPlatform(endpoint string) {
	fmt.Printf("=== REAL PLATFORM MODE: %s ===\n\n", endpoint)

	// Read the tier straight from the live platform, independently of the
	// SDK, so the assertion compares the wire against ground truth rather
	// than against a value this proof supplied.
	resp, err := http.Get(endpoint + "/health")
	if err != nil {
		// The platform is DOWN. This is a first-class real-world case,
		// not a harness error: telemetry must degrade, never stop. Assert
		// the ping still lands and the field is omitted rather than
		// defaulted — a substituted "community" here would be a false
		// claim about a customer whose platform we simply could not reach.
		fmt.Printf("Platform unreachable at %s (%v)\n  -> asserting the DOWN contract instead.\n\n", endpoint, err)
		body := captureOnePing(endpoint)
		if len(body) == 0 {
			fail("platform down: the ping was SUPPRESSED — telemetry must degrade, not stop")
			return
		}
		fmt.Printf("Telemetry wire body: %s\n\n", string(body))
		if got, present := tierOnWire(body); present {
			fail("platform down: license_tier present as %q — must be omitted when not learned", got)
			return
		}
		pass("platform down: ping still delivered, license_tier omitted (not defaulted)")
		return
	}
	defer resp.Body.Close()
	rawHealth, _ := io.ReadAll(resp.Body)
	fmt.Printf("Live /health body: %s\n\n", strings.TrimSpace(string(rawHealth)))

	var health struct {
		Tier    string `json:"tier"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rawHealth, &health); err != nil {
		fail("live /health body is not JSON: %v", err)
		return
	}
	if health.Tier == "" {
		fail("live platform reported no tier — cannot cross-check")
		return
	}

	body := captureOnePing(endpoint)
	if len(body) == 0 {
		fail("no telemetry ping captured against the live platform")
		return
	}
	fmt.Printf("Telemetry wire body: %s\n\n", string(body))

	got, present := tierOnWire(body)
	switch {
	case !present:
		fail("license_tier absent from wire; the live platform reported tier=%q", health.Tier)
	case got != health.Tier:
		fail("license_tier on wire = %q, live platform /health said %q", got, health.Tier)
	default:
		pass("license_tier=%q on the wire matches the live platform's own /health verbatim", got)
	}
}

// runMatrix exercises every tier value and every fail-open path against a
// local stand-in platform.
func runMatrix() {
	fmt.Printf("=== MATRIX MODE (stand-in platform) ===\n\n")

	// --- 1. Every value the platform can emit, forwarded verbatim. -------
	fmt.Println("-- 1. verbatim round-trip of every platform-emitted tier --")
	for _, tier := range []string{"community", "evaluation", "Enterprise", "Plus", "starting"} {
		endpoint, stop := startStandInPlatform(http.StatusOK,
			`{"status":"healthy","version":"10.3.0","tier":"`+tier+`"}`)
		body := captureOnePing(endpoint)
		stop()

		if len(body) == 0 {
			fail("tier=%s: no ping captured", tier)
			continue
		}
		got, present := tierOnWire(body)
		switch {
		case !present:
			fail("tier=%s: license_tier absent from wire; body: %s", tier, string(body))
		case got != tier:
			fail("tier=%s: license_tier on wire = %q, want verbatim %q", tier, got, tier)
		default:
			pass("tier=%-11q forwarded verbatim", got)
		}
	}

	// --- 2. Fail-open: the field is OMITTED, the ping still lands. -------
	fmt.Println("\n-- 2. fail-open paths: field omitted, ping still delivered --")
	unreachable, stopUnreachable := startStandInPlatform(http.StatusOK, `{}`)
	stopUnreachable() // free the port; nothing is listening there now

	cases := []struct {
		name     string
		endpoint string
		stop     func()
	}{}
	cases = append(cases, struct {
		name     string
		endpoint string
		stop     func()
	}{"endpoint not configured", "", func() {}})
	cases = append(cases, struct {
		name     string
		endpoint string
		stop     func()
	}{"platform unreachable", unreachable, func() {}})

	for _, spec := range []struct {
		name   string
		status int
		body   string
	}{
		{"health returns 500", http.StatusInternalServerError, `{"tier":"Enterprise"}`},
		{"health returns malformed JSON", http.StatusOK, `{"tier":"Enterprise"`},
		{"health has no tier key", http.StatusOK, `{"status":"healthy","version":"10.3.0"}`},
		{"health has an empty tier", http.StatusOK, `{"version":"10.3.0","tier":""}`},
	} {
		endpoint, stop := startStandInPlatform(spec.status, spec.body)
		cases = append(cases, struct {
			name     string
			endpoint string
			stop     func()
		}{spec.name, endpoint, stop})
	}

	for _, tc := range cases {
		body := captureOnePing(tc.endpoint)
		tc.stop()

		if len(body) == 0 {
			fail("%s: the ping was SUPPRESSED — telemetry must degrade, not stop", tc.name)
			continue
		}
		if !strings.Contains(string(body), `"telemetry_type":"sdk"`) {
			fail("%s: ping body is not a well-formed sdk ping: %s", tc.name, string(body))
			continue
		}
		got, present := tierOnWire(body)
		if present {
			fail("%s: license_tier present as %q — must be omitted when not learned", tc.name, got)
			continue
		}
		pass("%-30s ping delivered, license_tier omitted", tc.name)
	}

	// --- 3. deployment_mode is untouched by the tier. --------------------
	fmt.Println("\n-- 3. deployment_mode is independent of the tier --")
	for _, spec := range []struct{ name, body string }{
		{"with tier", `{"version":"10.3.0","tier":"Enterprise"}`},
		{"without tier", `{"version":"10.3.0"}`},
	} {
		endpoint, stop := startStandInPlatform(http.StatusOK, spec.body)
		body := captureOnePing(endpoint)
		stop()

		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		mode, _ := payload["deployment_mode"].(string)
		if mode != axonflow.DeploymentModeSelfHosted {
			fail("%s: deployment_mode = %q, want %q — the tier must not alter topology",
				spec.name, mode, axonflow.DeploymentModeSelfHosted)
			continue
		}
		pass("%-13s deployment_mode=%q unchanged", spec.name, mode)
	}
}
