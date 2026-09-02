//go:build ignore

// runtime-e2e/health_identity_relay/main.go
//
// Real-wire proof of the SDK's platform-identity relay: `edition` and
// `platform_deployment_mode`, read from the platform's /health and forwarded on
// the heartbeat (axonflow-enterprise#3660).
//
// The SDK does not expose its internal http.Client, so this proof runs real
// listeners on BOTH sides of the telemetry path: a stand-in platform serving
// /health, and a stand-in checkpoint receiver capturing the outgoing POST.
// Bytes flow real -> real through net/http. The client under test is a real
// axonflow.NewClient in a real process; nothing is mocked or injected into it.
//
// TWO MODES:
//
//	# 1. MATRIX (default) — every relay path and every not-learned path,
//	#    against a local stand-in platform.
//	go run runtime-e2e/health_identity_relay/main.go
//
//	# 2. REAL PLATFORM — drive the SDK at an actual running agent and
//	#    cross-check the wire values against that agent's own /health.
//	AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
//	  go run runtime-e2e/health_identity_relay/main.go
//
// Mode 2 is the one that proves the contract end to end. It reads /health
// INDEPENDENTLY of the SDK first, then asserts the SDK put those values on the
// wire — so the assertion compares the wire against ground truth rather than
// against a value this proof supplied. It also handles the pre-10.4.0 platform
// honestly: an agent that serves neither member must produce a ping with
// neither KEY, which is a real assertion rather than a skip.
//
// WHAT IT ASSERTS:
//
//  1. Both members reach the wire VERBATIM, and land on the right FIELDS:
//     /health's `edition` -> ping `edition`, and /health's `deployment_mode`
//     -> ping `platform_deployment_mode`.
//  2. THE MAPPING TRAP. The ping's own `deployment_mode` keeps carrying the
//     TOPOLOGY the SDK derived from its endpoint URL, never the platform's
//     own mode. This is the single most likely thing to be got wrong, because
//     the two dimensions share a name across the two documents.
//  3. Both keys are ABSENT — not empty, not defaulted — on every path where
//     the value was not learned: a pre-10.4.0 platform, a platform that is
//     down, a 500, a non-JSON body, and an explicitly empty value. The ping is
//     still DELIVERED on every one of them.
//  4. A badly-typed new member does not regress the ones beside it:
//     `"edition": 42` must still leave platform_version and license_tier on
//     the wire. That is the regression the per-field decode exists to prevent.
//
// MUTATION PROOFS (each was run):
//
//   - Delete `Edition: probe.Edition,` from the payload literal in
//     telemetry.go -> case 1 fails with "edition absent from wire".
//   - Assign probe.PlatformDeploymentMode to payload.DeploymentMode ->
//     case 2 fails with "deployment_mode on the wire = in-vpc-enterprise,
//     want the SDK-derived topology".
//   - Drop the `!= ""` guard in the promotion -> case 3's empty-value rows
//     fail with "edition present as \"\"".

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
// Env injection is too late: the shared heartbeat gate is a package var
// initialised before main() runs.
func clearStamp() {
	if cacheDir, err := os.UserCacheDir(); err == nil {
		_ = os.Remove(filepath.Join(cacheDir, "axonflow", "go-telemetry-last-sent"))
	}
}

// childEnvVar marks the re-executed child that actually constructs the client.
// EACH CASE NEEDS A FRESH PROCESS: the shared heartbeat is a process-global
// singleton, so one process emits at most one ping however many clients it
// builds. Driving the matrix in-process would silently assert against the first
// case's body every time — a whole suite passing on one observation.
const childEnvVar = "AXONFLOW_E2E_IDENTITY_CHILD"

func runChild() {
	clearStamp()
	_ = axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     os.Getenv("AXONFLOW_E2E_PLATFORM_ENDPOINT"),
		ClientID:     "rt-e2e",
		ClientSecret: "rt-e2e",
		Mode:         "production",
	})
	// The SDK fires telemetry on a startup goroutine; hold the process open
	// long enough for the health probe + POST under their shared budget.
	time.Sleep(5 * time.Second)
}

// captureOnePing runs one real client, in a fresh child process, against
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

// field returns one wire field's value and whether the KEY was present.
// Presence is the whole contract for these two dimensions, so it is returned
// separately rather than collapsed into an empty string.
func field(body []byte, name string) (value string, present bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	raw, ok := payload[name]
	if !ok {
		return "", false
	}
	s, _ := raw.(string)
	return s, true
}

// assertAbsent asserts a key is missing AND that the ping still landed.
func assertAbsent(label string, body []byte, names ...string) {
	if len(body) == 0 {
		fail("%s: the ping was SUPPRESSED — telemetry must degrade, not stop", label)
		return
	}
	for _, n := range names {
		if got, present := field(body, n); present {
			fail("%s: %s present as %q — a value that was not learned must be OMITTED, "+
				"so the receiver can tell \"not reported\" from a real value", label, n, got)
			return
		}
	}
	pass("%s: ping delivered, %s omitted (not defaulted)", label, strings.Join(names, " + "))
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

// runAgainstRealPlatform drives the SDK at a live agent, then cross-checks the
// wire values against that agent's own /health.
func runAgainstRealPlatform(endpoint string) {
	fmt.Printf("=== REAL PLATFORM MODE: %s ===\n\n", endpoint)

	resp, err := http.Get(endpoint + "/health")
	if err != nil {
		// The platform is DOWN. A first-class real-world case, not a harness
		// error: telemetry must degrade, never stop, and a substituted
		// "community" here would be a false claim about a customer whose
		// platform we simply could not reach.
		fmt.Printf("Platform unreachable at %s (%v)\n  -> asserting the DOWN contract instead.\n\n", endpoint, err)
		assertAbsent("platform down", captureOnePing(endpoint), "edition", "platform_deployment_mode")
		return
	}
	defer resp.Body.Close()
	rawHealth, _ := io.ReadAll(resp.Body)
	fmt.Printf("Live /health body: %s\n\n", strings.TrimSpace(string(rawHealth)))

	var health struct {
		Edition        string `json:"edition"`
		DeploymentMode string `json:"deployment_mode"`
		Version        string `json:"version"`
	}
	if err := json.Unmarshal(rawHealth, &health); err != nil {
		fail("live /health body is not JSON: %v", err)
		return
	}

	body := captureOnePing(endpoint)
	if len(body) == 0 {
		fail("no telemetry ping captured against the live platform")
		return
	}
	fmt.Printf("Telemetry wire body: %s\n\n", string(body))

	// A PRE-10.4.0 PLATFORM IS AN ASSERTION, NOT A SKIP. Most agents in the
	// field serve neither member; the contract for that case is that the ping
	// carries neither KEY, and it is checkable here.
	if health.Edition == "" && health.DeploymentMode == "" {
		fmt.Printf("This platform serves neither member (pre-10.4.0).\n  -> asserting the NOT-REPORTED contract.\n\n")
		assertAbsent("pre-10.4.0 platform", body, "edition", "platform_deployment_mode")
	} else {
		if health.Edition != "" {
			got, present := field(body, "edition")
			switch {
			case !present:
				fail("edition absent from wire; the live platform reported %q", health.Edition)
			case got != health.Edition:
				fail("edition on wire = %q, live /health said %q", got, health.Edition)
			default:
				pass("edition=%q on the wire matches the live platform's own /health verbatim", got)
			}
		}
		if health.DeploymentMode != "" {
			got, present := field(body, "platform_deployment_mode")
			switch {
			case !present:
				fail("platform_deployment_mode absent from wire; live /health said %q", health.DeploymentMode)
			case got != health.DeploymentMode:
				fail("platform_deployment_mode on wire = %q, live /health said %q", got, health.DeploymentMode)
			default:
				pass("platform_deployment_mode=%q matches the live platform's own /health verbatim", got)
			}
		}
	}

	// THE MAPPING TRAP, against the live platform. The ping's own
	// deployment_mode must still be the SDK-derived topology.
	assertTopologyUnmoved("live platform", body, health.DeploymentMode)

	// The pre-existing relays must be undisturbed by the new ones.
	if health.Version != "" {
		if got, present := field(body, "platform_version"); !present || got != health.Version {
			fail("platform_version on wire = %q (present=%v), live /health said %q — a new "+
				"dimension regressed one that worked before it", got, present, health.Version)
		} else {
			pass("platform_version=%q still relayed correctly alongside the new members", got)
		}
	}
}

// assertTopologyUnmoved pins that the ping's own `deployment_mode` still
// carries the SDK-derived TOPOLOGY, never the platform's own mode.
//
// This is the single most likely thing to be got wrong in this change: the two
// dimensions share a name across the two documents, so a relay that promotes
// /health's member into the field of the same name looks correct and silently
// overwrites a value every existing deployment-mode dashboard reads.
func assertTopologyUnmoved(label string, body []byte, platformMode string) {
	got, present := field(body, "deployment_mode")
	if !present {
		fail("%s: deployment_mode absent from the ping; it is a required topology field", label)
		return
	}
	switch got {
	case axonflow.DeploymentModeSelfHosted, axonflow.DeploymentModeCommunitySaaS, axonflow.DeploymentModeUnknown:
		if platformMode != "" && got == platformMode {
			fail("%s: deployment_mode on the wire = %q, which is ALSO what /health reported as "+
				"the platform's own mode — the relay has overwritten the topology field", label, got)
			return
		}
		pass("%s: deployment_mode=%q is still the SDK-derived topology, not the platform's own mode", label, got)
	default:
		fail("%s: deployment_mode on the wire = %q, want the SDK-derived topology "+
			"(self_hosted | community_saas | unknown). /health's member must map onto "+
			"platform_deployment_mode, NEVER onto this field", label, got)
	}
}

// runMatrix exercises every relay path and every not-learned path against a
// local stand-in platform.
func runMatrix() {
	fmt.Printf("=== MATRIX MODE (stand-in platform) ===\n\n")

	// --- 1. Both members forwarded verbatim, onto the right fields. ------
	fmt.Println("-- 1. verbatim relay onto the correct wire fields --")
	for _, tc := range []struct{ edition, mode string }{
		{"community", "community"},
		{"enterprise", "in-vpc-enterprise"},
		{"enterprise", "community-saas"},
		{"enterprise", "saas"},
		{"unknown", "unknown"},
	} {
		endpoint, stop := startStandInPlatform(http.StatusOK,
			`{"status":"healthy","version":"10.4.0","tier":"Enterprise","edition":"`+tc.edition+
				`","deployment_mode":"`+tc.mode+`"}`)
		body := captureOnePing(endpoint)
		stop()

		if len(body) == 0 {
			fail("edition=%s mode=%s: no ping captured", tc.edition, tc.mode)
			continue
		}
		okAll := true
		if got, present := field(body, "edition"); !present || got != tc.edition {
			fail("edition=%s: on wire = %q (present=%v), want verbatim", tc.edition, got, present)
			okAll = false
		}
		if got, present := field(body, "platform_deployment_mode"); !present || got != tc.mode {
			fail("mode=%s: platform_deployment_mode on wire = %q (present=%v), want verbatim", tc.mode, got, present)
			okAll = false
		}
		// THE MAPPING TRAP. A stand-in on 127.0.0.1 is self_hosted topology.
		assertTopologyUnmoved(fmt.Sprintf("edition=%s mode=%s", tc.edition, tc.mode), body, tc.mode)
		if okAll {
			pass("edition=%q + platform_deployment_mode=%q relayed verbatim onto the right fields", tc.edition, tc.mode)
		}
	}

	// --- 2. Not learned => the KEY is absent, and the ping still lands. --
	fmt.Println("\n-- 2. not-learned paths: key absent, ping still delivered --")
	notLearned := []struct {
		name   string
		status int
		body   string
	}{
		{"pre-10.4.0 platform (neither member)", http.StatusOK, `{"status":"healthy","version":"10.3.0","tier":"Enterprise"}`},
		{"platform 500", http.StatusInternalServerError, `{"edition":"enterprise","deployment_mode":"saas"}`},
		{"non-JSON body (a proxy error page)", http.StatusOK, `<html>502 Bad Gateway</html>`},
		{"explicitly empty values", http.StatusOK, `{"version":"10.4.0","edition":"","deployment_mode":""}`},
		{"explicit nulls", http.StatusOK, `{"version":"10.4.0","edition":null,"deployment_mode":null}`},
		{"badly-typed values", http.StatusOK, `{"version":"10.4.0","edition":42,"deployment_mode":{"a":1}}`},
	}
	for _, tc := range notLearned {
		endpoint, stop := startStandInPlatform(tc.status, tc.body)
		body := captureOnePing(endpoint)
		stop()
		assertAbsent(tc.name, body, "edition", "platform_deployment_mode")
	}

	// A platform that is simply not there.
	fmt.Println("\n-- 2b. platform unreachable --")
	deadEndpoint, stopDead := startStandInPlatform(http.StatusOK, `{}`)
	stopDead() // shut it down; the address now refuses connections
	assertAbsent("platform unreachable", captureOnePing(deadEndpoint), "edition", "platform_deployment_mode")

	// --- 3. A bad new member must not regress the old ones. --------------
	fmt.Println("\n-- 3. a badly-typed new member does not regress its neighbours --")
	endpoint, stop := startStandInPlatform(http.StatusOK,
		`{"status":"healthy","version":"10.4.0","tier":"Enterprise","edition":42,"deployment_mode":"saas"}`)
	body := captureOnePing(endpoint)
	stop()
	if len(body) == 0 {
		fail("badly-typed edition: no ping captured")
	} else {
		fmt.Printf("   wire body: %s\n", string(body))
		if got, present := field(body, "platform_version"); !present || got != "10.4.0" {
			fail("a numeric edition discarded platform_version (got %q, present=%v) — this is the "+
				"regression the per-field decode exists to prevent", got, present)
		} else if got, present := field(body, "license_tier"); !present || got != "Enterprise" {
			fail("a numeric edition discarded license_tier (got %q, present=%v)", got, present)
		} else if got, present := field(body, "platform_deployment_mode"); !present || got != "saas" {
			fail("a numeric edition discarded its SIBLING member (got %q, present=%v)", got, present)
		} else {
			pass("a numeric edition was not learned, and platform_version, license_tier and " +
				"platform_deployment_mode all survived it")
		}
	}
}
