//go:build ignore

// runtime-e2e/adapter_telemetry/main.go
//
// Real-wire proof of the adapter registry (axonflow-enterprise#3682, items
// 1-3): RegisterAdapter puts `adapter:<name>` into the `features` array of the
// heartbeat that already fires, adds no request of its own, drops an
// over-cap name whole, and refuses a redirect on BOTH telemetry legs.
//
// WHY THERE ARE LISTENERS HERE, AND WHAT IS STILL REAL. The SDK does not
// expose its internal telemetry http.Client, and the real checkpoint service
// is PRODUCTION — a runtime proof must not deliver test pings to it. So this
// driver runs real listeners on both sides of the telemetry path and the
// bytes flow real -> real through net/http: a real client, its real startup
// goroutine, its real /health probe, its real POST. Nothing about the SDK is
// mocked, injected or stubbed; the stand-ins are the two PEERS, exactly as in
// the neighbouring license_tier_telemetry driver. Raw net.Listen rather than
// httptest, which is what the no-mocks lint forbids.
//
// In REAL PLATFORM mode the platform side stops being a stand-in and becomes
// the live agent.
//
// TWO MODES:
//
//	# 1. MATRIX (default) — the registry, the cap, and both redirect legs.
//	go run runtime-e2e/adapter_telemetry/main.go
//
//	# 2. REAL PLATFORM — drive the SDK against an actual running agent and
//	#    assert the adapter rides the SAME ping that carries that agent's
//	#    own version and tier.
//	AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
//	  go run runtime-e2e/adapter_telemetry/main.go
//
// Mutation proof: replace `Features: registeredFeatures()` in telemetry.go
// with `[]string{}` and case 1 fails with "adapter:langchain absent from the
// wire". Drop the length guard in RegisterAdapter and case 3 fails with a
// truncated name present. Remove the CheckRedirect on either client and the
// matching redirect case fails, because the second listener records the hit.

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
// Env injection is too late — the shared heartbeat gate is a package var
// initialized before main() runs.
func clearStamp() {
	if cacheDir, err := os.UserCacheDir(); err == nil {
		_ = os.Remove(filepath.Join(cacheDir, "axonflow", "go-telemetry-last-sent"))
	}
}

// childEnvVar marks the re-executed child that actually constructs the SDK
// client. Each case needs a FRESH PROCESS: the heartbeat gate is a
// process-global singleton and the adapter registry is a package-global set,
// so a single process would emit one ping carrying the union of every case's
// registrations. Driving the matrix in-process would silently assert against
// the first case's body every time.
const (
	childEnvVar      = "AXONFLOW_E2E_ADAPTER_CHILD"
	childAdaptersVar = "AXONFLOW_E2E_ADAPTER_NAMES"
	// When set, the child declares its adapter by CONSTRUCTING the real
	// first-party LangGraph adapter through the exported public surface,
	// rather than by calling RegisterAdapter directly. That is the leg that
	// proves shipping an adapter is enough — no application code required.
	childViaConstructorVar = "AXONFLOW_E2E_ADAPTER_VIA_CONSTRUCTOR"
	// When set, the child registers an adapter AFTER its first request, i.e.
	// after the ping has already been sent.
	childRegisterLateVar = "AXONFLOW_E2E_ADAPTER_REGISTER_LATE"
	childSeparator       = "\x1f" // unit separator: cannot occur in a name we would send
	childHoldSeconds     = 5
	captureWaitSeconds   = 12
)

// runChild registers whatever the parent asked for, then builds one real
// client and lets the SDK's own startup goroutine deliver the ping.
func runChild() {
	clearStamp()
	if raw := os.Getenv(childAdaptersVar); raw != "" {
		for _, name := range strings.Split(raw, childSeparator) {
			axonflow.RegisterAdapter(name)
		}
	}
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     os.Getenv("AXONFLOW_E2E_PLATFORM_ENDPOINT"),
		ClientID:     "rt-e2e",
		ClientSecret: "rt-e2e",
		Mode:         "production",
	})
	if os.Getenv(childViaConstructorVar) != "" {
		// The REAL public surface, not a RegisterAdapter call. Constructed
		// after the client (it takes one) but BEFORE the first request, which
		// is what makes it reach the first ping now that the heartbeat
		// triggers on first use rather than at construction.
		_ = axonflow.NewLangGraphAdapter(client, "rt-e2e-adapter-telemetry")
	}

	// THE HEARTBEAT FIRES HERE, not at NewClient (#3682). One outbound call
	// is what triggers it. The call itself fails against the stand-in
	// platform, which is fine and deliberate: the heartbeat rides the ATTEMPT
	// to make a request, so a caller whose first API call fails is still a
	// caller.
	_, _ = client.ListDecisions(context.Background(), axonflow.ListDecisionsOptions{})

	if os.Getenv(childRegisterLateVar) != "" {
		// Registered AFTER the first request, i.e. after the ping has already
		// gone. Must NOT appear on that ping.
		axonflow.RegisterAdapter("registered-too-late")
	}

	// The ping is synchronous on a cold gate, but hold the process open a
	// moment so a slow local listener still records it.
	time.Sleep(childHoldSeconds * time.Second)
}

// capture is what one child run produced.
type capture struct {
	body         []byte
	checkpointOK bool // the checkpoint listener saw the POST at all
}

// captureOnePing runs one real client in a fresh child process, registering
// `adapters`, and returns the raw telemetry body the parent received.
func captureOnePing(platformEndpoint string, adapters ...string) capture {
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

	body := runChildAgainst(platformEndpoint, "http://"+listener.Addr().String()+"/v1/ping", done, &captured, adapters)
	return capture{body: body, checkpointOK: len(body) > 0}
}

// viaConstructor asks the next child to declare its adapter by constructing
// the real LangGraphAdapter instead of calling RegisterAdapter.
var viaConstructor bool

// registerLate asks the next child to register an adapter AFTER its first
// request, to prove such a registration does not reach that request's ping.
var registerLate bool

func runChildAgainst(platformEndpoint, checkpointURL string, done chan struct{}, captured *atomic.Value, adapters []string) []byte {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve self: %v\n", err)
		os.Exit(2)
	}

	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(),
		childEnvVar+"=1",
		childAdaptersVar+"="+strings.Join(adapters, childSeparator),
		"AXONFLOW_E2E_PLATFORM_ENDPOINT="+platformEndpoint,
		"AXONFLOW_CHECKPOINT_URL="+checkpointURL,
		"AXONFLOW_TELEMETRY=",
	)
	if viaConstructor {
		cmd.Env = append(cmd.Env, childViaConstructorVar+"=1")
	}
	if registerLate {
		cmd.Env = append(cmd.Env, childRegisterLateVar+"=1")
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "spawn child: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = cmd.Process.Kill() }()

	select {
	case <-done:
	case <-time.After(captureWaitSeconds * time.Second):
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

// featuresOnWire extracts the features array and whether the key was present.
func featuresOnWire(body []byte) (values []string, present bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false
	}
	raw, ok := payload["features"]
	if !ok {
		return nil, false
	}
	list, _ := raw.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out, true
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
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

// runAgainstRealPlatform drives the SDK at a live agent and asserts the
// adapter rides the SAME ping that carries that agent's own dimensions —
// which is what "no new request" means in practice.
func runAgainstRealPlatform(endpoint string) {
	fmt.Printf("=== REAL PLATFORM MODE: %s ===\n\n", endpoint)

	cap := captureOnePing(endpoint, "langchain")
	if len(cap.body) == 0 {
		fail("no telemetry ping captured against the live platform")
		return
	}
	fmt.Printf("Telemetry wire body: %s\n\n", string(cap.body))

	features, present := featuresOnWire(cap.body)
	if !present {
		fail("`features` absent from the wire against a live platform")
		return
	}
	if !contains(features, "adapter:langchain") {
		fail("features = %v against a live platform; want adapter:langchain", features)
		return
	}
	pass("adapter:langchain rides the live ping (features = %v)", features)

	// The point of "no new request": the adapter did NOT arrive on a ping of
	// its own. The same body must still carry the platform dimensions this
	// heartbeat has always carried.
	var payload map[string]any
	_ = json.Unmarshal(cap.body, &payload)
	if _, ok := payload["platform_version"]; !ok {
		fail("the ping carrying the adapter has no platform_version — the adapter must ride " +
			"the EXISTING heartbeat, not a ping of its own")
		return
	}
	pass("the adapter rode the existing heartbeat: same body carries platform_version=%v tier=%v",
		payload["platform_version"], payload["license_tier"])
}

// runMatrix exercises the registry, the cap, and both redirect legs against
// local stand-in peers.
func runMatrix() {
	fmt.Printf("=== MATRIX MODE (stand-in platform + checkpoint) ===\n\n")

	const healthBody = `{"status":"healthy","version":"10.4.0","tier":"Enterprise","edition":"enterprise","deployment_mode":"self_hosted"}`

	// --- 1. A registered adapter reaches the wire. -----------------------
	fmt.Println("-- 1. a registered adapter reaches the wire --")
	endpoint, stop := startStandInPlatform(http.StatusOK, healthBody)
	cap := captureOnePing(endpoint, "langchain")
	stop()
	features, present := featuresOnWire(cap.body)
	switch {
	case len(cap.body) == 0:
		fail("no ping captured")
	case !present:
		fail("`features` key absent from the wire; body: %s", string(cap.body))
	case !contains(features, "adapter:langchain"):
		fail("features = %v, want it to contain adapter:langchain", features)
	default:
		pass("features = %v", features)
	}

	// --- 2. An unregistered adapter does NOT. ----------------------------
	//
	// Paired with case 1 on purpose: on its own, "adapter:langgraph is
	// absent" is satisfied by a ping that carried nothing at all, or by no
	// ping. Case 1 above is the positive control that the mechanism works.
	fmt.Println("\n-- 2. an unregistered adapter does not --")
	endpoint, stop = startStandInPlatform(http.StatusOK, healthBody)
	cap = captureOnePing(endpoint, "langchain")
	stop()
	features, present = featuresOnWire(cap.body)
	switch {
	case !present:
		fail("`features` absent, so this case cannot distinguish absence from a failed run")
	case contains(features, "adapter:langgraph"):
		fail("features = %v contains adapter:langgraph, which nothing registered", features)
	case !contains(features, "adapter:langchain"):
		fail("features = %v does not contain the adapter that WAS registered — the absence "+
			"assertion above is vacuous without this", features)
	default:
		pass("features = %v: carries what was declared and nothing else", features)
	}

	// --- 3. An over-cap name is dropped WHOLE. ---------------------------
	fmt.Println("\n-- 3. a 65-byte adapter name is dropped whole, not truncated --")
	sixtyFive := strings.Repeat("a", 65)
	endpoint, stop = startStandInPlatform(http.StatusOK, healthBody)
	cap = captureOnePing(endpoint, sixtyFive, "langchain")
	stop()
	features, present = featuresOnWire(cap.body)
	switch {
	case !present:
		fail("`features` absent; body: %s", string(cap.body))
	case contains(features, "adapter:"+sixtyFive):
		fail("the 65-byte name reached the wire in full")
	case contains(features, "adapter:"+strings.Repeat("a", 64)):
		fail("the 65-byte name was TRUNCATED to 64 and sent; a truncated adapter name is a " +
			"name nothing is running, and the receiver buckets it as a real value")
	case !contains(features, "adapter:langchain"):
		fail("features = %v lost the VALID name too — an over-cap value must be dropped "+
			"alone, not take the array with it", features)
	default:
		pass("features = %v: the over-cap name dropped whole, the valid one kept", features)
	}

	// --- 4. Unhappy /health paths still deliver the adapter. -------------
	//
	// The adapter is the SDK's own knowledge; it must not depend on the
	// platform being reachable or well-formed.
	fmt.Println("\n-- 4. the adapter survives every /health failure mode --")
	unreachable, stopUnreachable := startStandInPlatform(http.StatusOK, `{}`)
	stopUnreachable() // free the port; nothing is listening there now

	for _, tc := range []struct {
		name     string
		endpoint string
		status   int
		body     string
		serve    bool
	}{
		{name: "endpoint not configured", endpoint: "", serve: false},
		{name: "platform unreachable", endpoint: unreachable, serve: false},
		{name: "health returns 500", status: http.StatusInternalServerError, body: `{}`, serve: true},
		{name: "health returns malformed JSON", status: http.StatusOK, body: `{"version":`, serve: true},
		{name: "health carries none of the relayed fields", status: http.StatusOK, body: `{"status":"healthy"}`, serve: true},
	} {
		ep := tc.endpoint
		stopFn := func() {}
		if tc.serve {
			ep, stopFn = startStandInPlatform(tc.status, tc.body)
		}
		c := captureOnePing(ep, "langchain")
		stopFn()

		if len(c.body) == 0 {
			fail("%s: the ping was SUPPRESSED — telemetry must degrade, not stop", tc.name)
			continue
		}
		f, ok := featuresOnWire(c.body)
		if !ok || !contains(f, "adapter:langchain") {
			fail("%s: adapter:langchain absent (features=%v). The adapter is the SDK's own "+
				"knowledge and must not depend on /health", tc.name, f)
			continue
		}
		pass("%-45s ping delivered, features = %v", tc.name, f)
	}

	// --- 5. Redirects are refused on BOTH legs. --------------------------
	fmt.Println("\n-- 5. redirects are refused on both telemetry legs --")
	assertHealthRedirectRefused(healthBody)
	assertCheckpointRedirectRefused(healthBody)

	// --- 6. The FIRST-PARTY adapter reaches the wire on its own. ---------
	//
	// This is the case the trigger move exists for. The heartbeat now fires on
	// the client's FIRST OUTBOUND REQUEST rather than inside NewClient, so an
	// adapter constructed between the two — which is every real usage shape,
	// because an adapter takes a client — is on the wire for the very first
	// ping. No application telemetry code at all.
	//
	// Before the move this was impossible: NewClient pinged synchronously
	// before returning, so no adapter could exist yet, and the 7-day stamp
	// then suppressed the next ping for a week. A short-lived process using an
	// adapter reported it NEVER. The e2e leg written to assert otherwise
	// failed, which is how that was found.
	fmt.Println("\n-- 6a. the shipped LangGraphAdapter declares itself, no caller telemetry code --")
	endpoint, stop = startStandInPlatform(http.StatusOK, healthBody)
	viaConstructor = true
	cap = captureOnePing(endpoint) // NOTE: no adapter names passed
	viaConstructor = false
	stop()
	features, present = featuresOnWire(cap.body)
	switch {
	case len(cap.body) == 0:
		fail("no ping captured")
	case !present:
		fail("`features` key absent from the wire; body: %s", string(cap.body))
	case !contains(features, "adapter:langgraph"):
		fail("features = %v; constructing NewLangGraphAdapter must declare adapter:langgraph "+
			"on the first ping without the application calling RegisterAdapter itself", features)
	default:
		pass("NewLangGraphAdapter alone put features = %v on the first ping", features)
	}

	// --- 6b. Registering AFTER the first request misses that ping. -------
	//
	// The honest other half: the trigger moved, it did not disappear. A name
	// registered after the ping has gone rides the NEXT cadence ping, and
	// this asserts the boundary rather than implying registration is
	// timing-free.
	fmt.Println("\n-- 6b. an adapter registered AFTER the first request misses that ping --")
	endpoint, stop = startStandInPlatform(http.StatusOK, healthBody)
	viaConstructor = true
	registerLate = true
	cap = captureOnePing(endpoint)
	registerLate = false
	viaConstructor = false
	stop()
	features, present = featuresOnWire(cap.body)
	switch {
	case !present:
		fail("`features` absent, so this case cannot distinguish absence from a failed run")
	case contains(features, "adapter:registered-too-late"):
		fail("features = %v carries an adapter registered AFTER the ping was sent", features)
	case !contains(features, "adapter:langgraph"):
		fail("features = %v lost the adapter registered BEFORE the request — without this the "+
			"absence assertion above is vacuous", features)
	default:
		pass("features = %v: declared-before is on the wire, registered-after is not", features)
	}
}

// assertHealthRedirectRefused: a 30x from /health must relay NOTHING from the
// redirect TARGET.
//
// TWO listeners, and the second one RECORDS. A single-listener fixture cannot
// express this defect at all: if the redirector and the target are the same
// process, a followed redirect and a refused one are indistinguishable. The
// target here serves a complete, plausible /health with DIFFERENT values
// precisely so that following would be visible in the payload.
func assertHealthRedirectRefused(healthBody string) {
	var targetHits atomic.Int32

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
		return
	}
	targetSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"healthy","version":"6.6.6-REDIRECT-TARGET","tier":"Plus"}`)
	})}
	go func() { _ = targetSrv.Serve(targetListener) }()
	defer func() { _ = targetSrv.Shutdown(context.Background()) }()
	targetURL := "http://" + targetListener.Addr().String()

	var redirectorHits atomic.Int32
	redirectorListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
		return
	}
	redirectorSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectorHits.Add(1)
		http.Redirect(w, r, targetURL+"/health", http.StatusFound)
	})}
	go func() { _ = redirectorSrv.Serve(redirectorListener) }()
	defer func() { _ = redirectorSrv.Shutdown(context.Background()) }()

	c := captureOnePing("http://"+redirectorListener.Addr().String(), "langchain")
	if len(c.body) == 0 {
		fail("health redirect: no ping captured; the ping must still be DELIVERED, only unenriched")
		return
	}

	// POSITIVE CONTROL: the first listener was actually asked. Without this,
	// "the target saw nothing" is equally true of a run that never happened.
	if redirectorHits.Load() == 0 {
		fail("health redirect: the redirector was never contacted, so 'the target saw nothing' " +
			"proves nothing about redirect handling")
		return
	}
	if n := targetHits.Load(); n != 0 {
		fail("health redirect: the redirect TARGET was fetched %d times — the 30x was followed, "+
			"and every relayed value would describe a platform the caller never pointed at", n)
		return
	}
	if strings.Contains(string(c.body), "6.6.6-REDIRECT-TARGET") {
		fail("health redirect: the target's version reached the wire: %s", string(c.body))
		return
	}
	f, _ := featuresOnWire(c.body)
	if !contains(f, "adapter:langchain") {
		fail("health redirect: the adapter was lost along with the relay; only the RELAYED " +
			"fields should degrade")
		return
	}
	pass("health 302 refused: redirector hit %d time(s), target hit 0, adapter still delivered",
		redirectorHits.Load())
}

// assertCheckpointRedirectRefused is the more dangerous half.
//
// net/http does not re-POST across a 302: it converts the request to a
// bodyless GET. So a followed redirect yields a 200 for a request that
// carried NO PAYLOAD, the SDK reads that 200 as delivery, and the 7-day stamp
// advances on a ping that was never sent — the installation goes silent for a
// week. A 200 meaning "we delivered nothing" is the worst possible shape here
// because it is indistinguishable from success at every layer above.
func assertCheckpointRedirectRefused(healthBody string) {
	platform, stopPlatform := startStandInPlatform(http.StatusOK, healthBody)
	defer stopPlatform()

	var targetHits atomic.Int32
	var targetSawBody atomic.Int32
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
		return
	}
	targetSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			targetSawBody.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"latest_version":"0.0.0"}`)
	})}
	go func() { _ = targetSrv.Serve(targetListener) }()
	defer func() { _ = targetSrv.Shutdown(context.Background()) }()
	targetURL := "http://" + targetListener.Addr().String()

	var redirectorHits atomic.Int32
	redirectorListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
		return
	}
	redirectorSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectorHits.Add(1)
		http.Redirect(w, r, targetURL+"/v1/ping", http.StatusFound)
	})}
	go func() { _ = redirectorSrv.Serve(redirectorListener) }()
	defer func() { _ = redirectorSrv.Shutdown(context.Background()) }()

	// Drive a child straight at the redirector as its checkpoint URL.
	done := make(chan struct{})
	var unusedCaptured atomic.Value
	unusedCaptured.Store([]byte{})
	// Nothing will close `done`; the child is bounded by the wait below.
	_ = runChildAgainst(platform, "http://"+redirectorListener.Addr().String()+"/v1/ping",
		done, &unusedCaptured, []string{"langchain"})

	// POSITIVE CONTROL: the redirector was actually asked.
	if redirectorHits.Load() == 0 {
		fail("checkpoint redirect: the redirector was never contacted, so the assertions below " +
			"prove nothing")
		return
	}
	if n := targetHits.Load(); n != 0 {
		fail("checkpoint redirect: the redirect TARGET received %d request(s) (%d carrying a body). "+
			"net/http turns a redirected POST into a bodyless GET, so a followed redirect reports "+
			"DELIVERY for a ping that was never sent and the 7-day stamp advances on it",
			n, targetSawBody.Load())
		return
	}
	pass("checkpoint 302 refused: redirector hit %d time(s), target hit 0 — the stamp cannot "+
		"advance on a ping that never landed", redirectorHits.Load())
}
