package axonflow

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Heartbeat cadence constants. Declared as `var` rather than `const` so
// tests can override them — the test files in this package back up the
// original values and restore them on cleanup.
var (
	// heartbeatInterval bounds how often a single machine sends a
	// telemetry ping. Aligned with the plugin "7-day heartbeat" contract:
	// "at most one heartbeat per environment every 7 days during
	// SDK activity."
	heartbeatInterval = 7 * 24 * time.Hour

	// heartbeatGuardInterval bounds how often a single client process
	// re-consults the stamp file. Without this, every API call would
	// stat() the stamp file. With it, a hot service stat()s at most once
	// per hour even under load.
	heartbeatGuardInterval = time.Hour
)

// heartbeatState holds the per-client mutable state used to gate telemetry
// pings. The stamp file at stampPath is the source of truth across process
// restarts; the in-memory fields handle within-process gating.
//
// Stamp semantics: stamp-on-DELIVERY. A failed ping does NOT update the
// stamp, so the next call after the in-memory cache expires retries.
// Concurrent goroutines crossing the boundary are coalesced via inFlight
// so we send at most one POST, not one per goroutine.
type heartbeatState struct {
	mu               sync.Mutex
	lastChecked      time.Time    // last wall-clock instant the gate ran (read under mu)
	lastCheckedNanos atomic.Int64 // mirror of lastChecked.UnixNano(), for lock-free pre-check on the request hot path
	inFlight         bool         // true while a ping POST is in progress
	stampPath        string       // empty when no user cache dir is available

	// consecutiveFailures counts attempts in a row that did NOT deliver.
	// Widens the re-check interval so a deployment that can never reach the
	// checkpoint service stops probing its own platform every hour forever.
	// Reset on delivery.
	//
	// Without it the SDK has no backoff at all, and two deliberate design
	// choices combine into a defect: the 7-day stamp only advances on
	// DELIVERY, and the gate is re-evaluated on every request. In a
	// deployment where egress to the checkpoint service is blocked — the
	// normal state of the air-gapped and in-VPC self-hosted topologies this
	// SDK supports — every process would issue a /health GET against the
	// CUSTOMER'S OWN platform once an hour, indefinitely, with a failed POST
	// beside it. Unsolicited hourly traffic against someone else's platform,
	// for a heartbeat disclosed as weekly, is not defensible.
	//
	// Backing off loses no ping: the stamp is still untouched, so the first
	// attempt after the widened interval sends normally.
	consecutiveFailures int

	// lastDelivered is when this PROCESS last delivered a ping.
	//
	// The stamp file is the cross-restart record of that, but it is not
	// always available: resolveStampPath returns "" where there is no usable
	// cache dir (HOME unset — distroless and scratch containers, Lambda
	// custom runtimes), and writeStampAtomic fails on a read-only root
	// filesystem (readOnlyRootFilesystem: true is ordinary Kubernetes
	// hardening). In both, readStampMtime returns the zero time forever.
	//
	// The failure backoff above cannot bound this case, because it resets on
	// delivery and these deliveries SUCCEED: the gate re-opens every hour,
	// the ping lands, the stamp cannot be written, and the next hour repeats
	// it — 168x the "at most one ping per machine every 7 days" this SDK
	// discloses, in exactly the environments least able to notice.
	//
	// So the cadence is enforced in memory too. Redundant whenever the stamp
	// works, and the only bound when it does not. Same shape as the Rust
	// SDK's GateInner.last_delivered (sdk-rust#89).
	lastDelivered time.Time
}

// guardIntervalFor returns how long the gate waits before re-consulting,
// given how many attempts in a row have failed to deliver: heartbeatGuardInterval
// doubled per failure, capped at heartbeatInterval.
func guardIntervalFor(consecutiveFailures int) time.Duration {
	// Clamped before shifting: the counter is unbounded, and shifting by 63
	// or more is undefined. 16 doublings already exceed the 7-day cap by
	// orders of magnitude.
	doublings := consecutiveFailures
	if doublings > 16 {
		doublings = 16
	}
	interval := heartbeatGuardInterval << doublings
	// The shift can overflow into a negative duration for a large base if
	// heartbeatInterval is ever raised; compare defensively rather than
	// trusting the arithmetic.
	if interval <= 0 || interval > heartbeatInterval {
		return heartbeatInterval
	}
	return interval
}

// recordAttempt records what an attempt achieved so the next one can back
// off. Called ONLY when an attempt was actually made — a pass that stopped at
// a fresh stamp is not a failure and must not widen the interval.
func (h *heartbeatState) recordAttempt(delivered bool, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if delivered {
		h.consecutiveFailures = 0
		h.lastDelivered = now
		return
	}
	h.consecutiveFailures++
}

// resolveStampPath returns the OS-native path to the SDK's heartbeat stamp
// file, or "" if the user cache dir is unavailable (e.g. AWS Lambda where
// HOME is unset). When the path is empty, the SDK falls back to the
// pre-heartbeat behavior of one ping per process — no regression.
func resolveStampPath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(cacheDir, "axonflow", "go-telemetry-last-sent")
}

// newHeartbeatState constructs a heartbeat state ready for first use.
func newHeartbeatState() *heartbeatState {
	return &heartbeatState{stampPath: resolveStampPath()}
}

// sharedHeartbeat is the process-global heartbeat singleton. ALL AxonFlow
// clients in this process consult the same gate, so concurrent NewClient
// calls before any stamp exists coalesce onto a single ping (per the
// "at most one heartbeat per environment" contract). Tests override via
// replaceHeartbeatStateForTest.
var (
	sharedHeartbeat   = newHeartbeatState()
	sharedHeartbeatMu sync.Mutex // guards swapping the singleton in tests
)

// getSharedHeartbeat returns the current process-global heartbeat state.
// Reads are wrapped in the swap-mutex so a test that calls
// replaceHeartbeatStateForTest concurrently with another test cannot tear
// the pointer.
func getSharedHeartbeat() *heartbeatState {
	sharedHeartbeatMu.Lock()
	defer sharedHeartbeatMu.Unlock()
	return sharedHeartbeat
}

// replaceHeartbeatStateForTest installs a fresh heartbeat state at the
// given stamp path (or "" for "no persistence"), returning the previous
// instance so the caller can restore it on cleanup. Production code does
// NOT call this — use only in tests.
func replaceHeartbeatStateForTest(stampPath string) *heartbeatState {
	sharedHeartbeatMu.Lock()
	defer sharedHeartbeatMu.Unlock()
	previous := sharedHeartbeat
	sharedHeartbeat = &heartbeatState{stampPath: stampPath}
	return previous
}

// restoreHeartbeatStateForTest restores a previously-saved state. Pair
// with replaceHeartbeatStateForTest; typical use:
//
//	prev := replaceHeartbeatStateForTest(t.TempDir() + "/stamp")
//	t.Cleanup(func() { restoreHeartbeatStateForTest(prev) })
func restoreHeartbeatStateForTest(state *heartbeatState) {
	sharedHeartbeatMu.Lock()
	defer sharedHeartbeatMu.Unlock()
	sharedHeartbeat = state
}

// readStampMtime returns the modification time of the stamp file, or the
// zero time if the file is absent / unreadable / has no resolvable cache
// dir. A zero return means "treat as never sent" — the caller should fire
// a fresh ping.
func (h *heartbeatState) readStampMtime() time.Time {
	if h.stampPath == "" {
		return time.Time{}
	}
	info, err := os.Stat(h.stampPath)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// writeStampAtomic writes a fresh timestamp at h.stampPath via tmp+rename
// so concurrent writers never observe torn state. The single line of
// human-readable content (`last_sent=<RFC3339>`) is advisory only — the
// SDK reads mtime, not the contents.
//
// Returns nil on success or a non-nil error when the cache dir or write
// fails. Errors are non-fatal — the caller may log in debug mode and
// continue. A failed stamp write means the next process retries on
// schedule, which is preferable to silent dropping.
func (h *heartbeatState) writeStampAtomic(now time.Time) error {
	if h.stampPath == "" {
		return nil
	}
	dir := filepath.Dir(h.stampPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "telemetry-last-sent-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Ensure cleanup if rename never happens; rename is atomic and removes
	// the source name from the directory entry, so this no-ops on success.
	defer os.Remove(tmpName)
	if _, err := fmt.Fprintf(tmp, "last_sent=%s\n", now.UTC().Format(time.RFC3339)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, h.stampPath)
}

// maybeSendHeartbeat is the central gate for telemetry pings. Called from
// NewClient (synchronously, to preserve short-lived-process delivery from
// issue #1693) and from doHttpRequest (asynchronously via goroutine to
// keep API call latency unaffected).
//
// Algorithm (in order — order matters):
//
//  1. AXONFLOW_TELEMETRY=off / mode-disabled: short-circuit immediately.
//     Re-evaluated every call (lock-free) so a mid-process opt-out works.
//  2. In-flight: another goroutine is already sending — fast-path out.
//  3. In-memory guard: skip the stat() syscall on hot paths. One hour
//     normally, WIDENED by guardIntervalFor after consecutive undelivered
//     attempts so a deployment that cannot reach the checkpoint stops
//     probing its own platform hourly.
//  4. In-memory delivery record: skip if THIS PROCESS delivered less than
//     heartbeatInterval ago. Redundant whenever the stamp file works, and
//     the only bound when it cannot be written.
//  5. Stamp file mtime: skip if last delivered <heartbeatInterval ago.
//  6. Send ping under bounded timeout. Record the attempt either way
//     (recordAttempt) — that is what drives 3 and 4. On success, write the
//     stamp; on failure, leave it unchanged so the next call retries.
func (c *AxonFlowClient) maybeSendHeartbeat() {
	if !c.isTelemetryEnabled() {
		return
	}

	// Process-global singleton — concurrent NewClient calls on the same
	// machine coalesce onto a single ping per heartbeatInterval. See the
	// sharedHeartbeat declaration above for the rationale.
	h := getSharedHeartbeat()
	now := time.Now()

	h.mu.Lock()
	if h.inFlight {
		h.mu.Unlock()
		return
	}
	if !h.lastChecked.IsZero() && now.Sub(h.lastChecked) < guardIntervalFor(h.consecutiveFailures) {
		h.mu.Unlock()
		return
	}
	h.lastChecked = now
	h.lastCheckedNanos.Store(now.UnixNano())

	// The 7-day cadence enforced IN MEMORY, before the stamp is consulted.
	// See heartbeatState.lastDelivered: where the stamp cannot be persisted
	// this is the only thing standing between a delivered ping and an hourly
	// one.
	if !h.lastDelivered.IsZero() && now.Sub(h.lastDelivered) < heartbeatInterval {
		h.mu.Unlock()
		return
	}

	if mtime := h.readStampMtime(); !mtime.IsZero() && now.Sub(mtime) < heartbeatInterval {
		h.mu.Unlock()
		return
	}

	h.inFlight = true
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()
	err := c.sendTelemetryPingNow(ctx)

	// Clear inFlight first so other callers can fast-path through, then do
	// the stamp write OUTSIDE the lock — os.Rename + tmp file IO are
	// blocking and would otherwise serialize concurrent gate runs through
	// disk syscalls.
	h.mu.Lock()
	h.inFlight = false
	h.mu.Unlock()

	// Recorded for EVERY attempt, delivered or not: the failure counter is
	// what widens the guard, and the delivery instant is what bounds the
	// success cadence when the stamp file is unavailable.
	h.recordAttempt(err == nil, time.Now())

	if err == nil {
		if writeErr := h.writeStampAtomic(time.Now()); writeErr != nil && c.config.Debug {
			log.Printf("[AxonFlow] heartbeat stamp write failed: %v", writeErr)
		}
	}
}

// maybeSendHeartbeatOnRequest is the SINGLE trigger for the telemetry
// heartbeat, called by the doHttpRequest middleware that wraps every public
// API call.
//
// IT MOVED HERE FROM NewClient, and the move is the point (#3682). The boot
// ping used to fire synchronously inside NewClient, before the constructor
// returned. Every framework adapter takes a *client, so an adapter could not
// possibly exist yet — which meant an adapter registering from its own
// constructor could NEVER reach the first ping, and the 7-day stamp then
// suppressed the next one for a week. For a short-lived process (a CLI, a
// Lambda, a CI job) that pings once and exits, the adapter was never reported
// at all: precisely the population the registry exists to measure.
//
// Triggering on the first outbound REQUEST instead means the ping describes a
// client that is actually being used, by which time constructors have run.
// A client that is constructed and never used no longer pings — which is
// also more honest about what a heartbeat is claiming.
//
// THE SYNC/ASYNC SPLIT PRESERVES ISSUE #1693. That issue was a real measured
// drop: a short-lived process exited before a backgrounded POST completed.
// So when the gate is COLD — meaning this call might actually send — the
// heartbeat runs SYNCHRONOUSLY on the caller's goroutine, exactly as the
// constructor used to, and the process cannot exit underneath it.
//
// The latency that costs is bounded and rare, and worth stating precisely
// rather than hand-waving: the cold branch is reachable at most once per
// heartbeatGuardInterval per process, and on that branch the only work that
// blocks is a stat() of the stamp file unless a ping is genuinely DUE — which
// the 7-day stamp limits to at most once per machine per week. Steady state
// is one atomic load per request.
func (c *AxonFlowClient) maybeSendHeartbeatOnRequest() {
	if !c.isTelemetryEnabled() {
		return
	}
	h := getSharedHeartbeat()
	// Hot-path pre-check: on a service handling 10k req/s with a warm gate,
	// every request would otherwise take a mutex. The atomic load brings
	// per-request overhead to a single load.
	//
	// It deliberately uses the BASE guard interval, not
	// guardIntervalFor(consecutiveFailures): reading the counter needs the
	// mutex, and taking it here would undo the point of a lock-free
	// pre-check. Using the base interval only ever errs toward entering
	// maybeSendHeartbeat, which then declines under the widened interval —
	// the backoff still holds, it is just enforced one frame in.
	if last := h.lastCheckedNanos.Load(); last != 0 &&
		time.Since(time.Unix(0, last)) < heartbeatGuardInterval {
		return
	}
	c.maybeSendHeartbeat()
}

// doHttpRequest is the single HTTP middleware that wraps every public-API
// HTTP call in this SDK. It calls maybeSendHeartbeatOnRequest as a side effect
// so the 7-day heartbeat gate is consulted on every request — but
// asynchronously, so the user's API call is never delayed by telemetry.
//
// The httpClient parameter selects between c.httpClient (default) and
// c.mapHttpClient (longer timeout for MAP plan operations). The wrapper
// is used uniformly across both to ensure no code path bypasses the
// heartbeat gate — and since #3682 this is the ONLY trigger, NewClient
// having stopped pinging at construction.
//
// IMPORTANT: This wrapper must NOT be called from telemetry code itself
// (sendTelemetryPingNow, probePlatformHealth). Those use raw http.Client
// instances to avoid recursive heartbeat triggering.
func (c *AxonFlowClient) doHttpRequest(httpClient *http.Client, req *http.Request) (*http.Response, error) {
	c.maybeSendHeartbeatOnRequest()
	return httpClient.Do(req)
}
