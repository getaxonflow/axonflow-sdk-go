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
//  3. In-memory 1-hour cache: skip the stat() syscall on hot paths.
//  4. Stamp file mtime: skip if last delivered <heartbeatInterval ago.
//  5. Send ping under bounded timeout. On success, write stamp. On
//     failure, leave stamp unchanged so the next call retries.
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
	if !h.lastChecked.IsZero() && now.Sub(h.lastChecked) < heartbeatGuardInterval {
		h.mu.Unlock()
		return
	}
	h.lastChecked = now
	h.lastCheckedNanos.Store(now.UnixNano())

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
	if err == nil {
		if writeErr := h.writeStampAtomic(time.Now()); writeErr != nil && c.config.Debug {
			log.Printf("[AxonFlow] heartbeat stamp write failed: %v", writeErr)
		}
	}
}

// maybeSendHeartbeatAsync schedules maybeSendHeartbeat on a goroutine so
// it never blocks the caller. Used by the doHttpRequest middleware to
// keep user API calls latency-free; NewClient still calls maybeSendHeartbeat
// synchronously to preserve issue #1693 short-lived-process delivery.
//
// Hot-path pre-check: on a service handling 10k req/s with a fresh stamp,
// every request would otherwise spawn a goroutine that does a single
// mutex acquire + cache compare + return. The atomic load of
// lastCheckedNanos lets us skip the spawn entirely when we know the
// 1-hour cache is still warm — bringing per-request overhead from
// "goroutine + mutex" to "single atomic load".
func (c *AxonFlowClient) maybeSendHeartbeatAsync() {
	if !c.isTelemetryEnabled() {
		return
	}
	h := getSharedHeartbeat()
	if last := h.lastCheckedNanos.Load(); last != 0 &&
		time.Since(time.Unix(0, last)) < heartbeatGuardInterval {
		return
	}
	go c.maybeSendHeartbeat()
}

// doHttpRequest is the single HTTP middleware that wraps every public-API
// HTTP call in this SDK. It calls maybeSendHeartbeatAsync as a side effect
// so the 7-day heartbeat gate is consulted on every request — but
// asynchronously, so the user's API call is never delayed by telemetry.
//
// The httpClient parameter selects between c.httpClient (default) and
// c.mapHttpClient (longer timeout for MAP plan operations). The wrapper
// is used uniformly across both to ensure no code path bypasses the
// heartbeat gate.
//
// IMPORTANT: This wrapper must NOT be called from telemetry code itself
// (sendTelemetryPingNow, detectPlatformVersion). Those use raw http.Client
// instances to avoid recursive heartbeat triggering.
func (c *AxonFlowClient) doHttpRequest(httpClient *http.Client, req *http.Request) (*http.Response, error) {
	c.maybeSendHeartbeatAsync()
	return httpClient.Do(req)
}
