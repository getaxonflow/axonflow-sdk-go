package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Helpers shared across heartbeat tests --------------------------------------

// newHeartbeatClient builds a minimal *AxonFlowClient suitable for exercising
// maybeSendHeartbeat in isolation, AND swaps the package-global heartbeat
// singleton for one pointing at a fresh stamp file under stampDir
// (typically t.TempDir()). Restores the original singleton on test
// cleanup. The dev machine env var (AXONFLOW_TELEMETRY=off) is cleared
// here so the heartbeat gate is the assertion under test, not env-var
// contamination — defends against developer shell rcfiles that opt out.
func newHeartbeatClient(t *testing.T, stampDir string) *AxonFlowClient {
	t.Helper()
	stampPath := filepath.Join(stampDir, "go-telemetry-last-sent")
	previous := replaceHeartbeatStateForTest(stampPath)
	t.Cleanup(func() { restoreHeartbeatStateForTest(previous) })
	t.Setenv("AXONFLOW_TELEMETRY", "")

	return &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:         "production",
			ClientID:     "id",
			ClientSecret: "sec",
		},
	}
}

// startCheckpointMock spins up an httptest server that counts pings and
// optionally returns a configured status code. Returns the server's URL
// and a *atomic.Int32 the caller reads after the gate runs.
func startCheckpointMock(t *testing.T, statusCode int) (string, *atomic.Int32) {
	t.Helper()
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		w.WriteHeader(statusCode)
		if statusCode >= 200 && statusCode < 300 {
			json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)
	t.Setenv("AXONFLOW_TELEMETRY", "")
	return srv.URL, &called
}

// withFastIntervals replaces the package heartbeat constants with values
// that make the assertions deterministic in test time, restoring originals
// on cleanup. Using time.Hour-scale defaults in tests would make case-4
// (1-hour cache holds within a process) impossible to verify in a
// reasonable test runtime.
func withFastIntervals(t *testing.T, heartbeat, guard time.Duration) {
	t.Helper()
	origH, origG := heartbeatInterval, heartbeatGuardInterval
	heartbeatInterval = heartbeat
	heartbeatGuardInterval = guard
	t.Cleanup(func() {
		heartbeatInterval = origH
		heartbeatGuardInterval = origG
	})
}

// 9-case matrix --------------------------------------------------------------

// Case 1: cold start with no stamp → exactly 1 ping fires, stamp written.
func TestHeartbeat_NoStamp_FiresOnce(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 1 {
		t.Errorf("expected 1 ping on cold start, got %d", got)
	}
	if _, err := os.Stat(getSharedHeartbeat().stampPath); err != nil {
		t.Errorf("expected stamp file at %s after successful ping, got error: %v", getSharedHeartbeat().stampPath, err)
	}
}

// Case 2: stamp written 1 day ago (well within heartbeatInterval) → 0 pings.
func TestHeartbeat_FreshStamp_DoesNotFire(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	// Pre-create the stamp file with a recent mtime.
	if err := getSharedHeartbeat().writeStampAtomic(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}
	// writeStampAtomic uses now() for the mtime regardless of the parameter
	// value (the parameter is for the human-readable contents). Force the
	// mtime to 1 day ago so the freshness check is deterministic.
	oneDayAgo := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(getSharedHeartbeat().stampPath, oneDayAgo, oneDayAgo); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 0 {
		t.Errorf("expected 0 pings with fresh stamp, got %d", got)
	}
}

// Case 3: stamp written 8 days ago (past heartbeatInterval) → 1 ping fires,
// stamp updated to now.
func TestHeartbeat_StaleStamp_FiresAndUpdates(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	if err := getSharedHeartbeat().writeStampAtomic(time.Now()); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(getSharedHeartbeat().stampPath, eightDaysAgo, eightDaysAgo); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 1 {
		t.Errorf("expected 1 ping with stale stamp, got %d", got)
	}
	mtime := getSharedHeartbeat().readStampMtime()
	if time.Since(mtime) > 5*time.Second {
		t.Errorf("expected stamp mtime to be very recent, got %v ago", time.Since(mtime))
	}
}

// Case 4: NewClient + 5 immediate API calls within the 1-hour cache window
// → exactly 1 ping (the first call hits the gate and records lastChecked;
// subsequent calls fast-path through the in-memory cache).
func TestHeartbeat_RateLimitWithin1Hour_FiresOnce(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	for i := 0; i < 5; i++ {
		client.maybeSendHeartbeat()
	}

	if got := called.Load(); got != 1 {
		t.Errorf("expected 1 ping for 5 calls inside 1h cache window, got %d", got)
	}
}

// Case 5: rate-limit cache expires (lastChecked backdated 2h) + stale stamp
// (8d ago) → second ping fires, stamp updated.
func TestHeartbeat_AfterRateLimitExpiry_FiresAgain(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	// First call: ping fires, stamp written.
	client.maybeSendHeartbeat()
	if got := called.Load(); got != 1 {
		t.Fatalf("setup: expected 1st ping, got %d", got)
	}

	// Backdate both lastChecked (memory) and stamp (file) so the gate lets
	// the next call through.
	getSharedHeartbeat().mu.Lock()
	getSharedHeartbeat().lastChecked = time.Now().Add(-2 * time.Hour)
	getSharedHeartbeat().mu.Unlock()
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(getSharedHeartbeat().stampPath, eightDaysAgo, eightDaysAgo); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 2 {
		t.Errorf("expected 2 pings after cache + stamp expiry, got %d", got)
	}
}

// Case 6: AXONFLOW_TELEMETRY=off mid-process → 0 pings, stamp NOT written.
// Re-evaluated on every call so the toggle works without a new process.
func TestHeartbeat_OptOutMidProcess_StopsPings(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	// First call without opt-out: fires.
	client.maybeSendHeartbeat()
	if got := called.Load(); got != 1 {
		t.Fatalf("setup: expected 1st ping, got %d", got)
	}

	// Toggle opt-out, force the cache + stamp gates to be open, call again.
	t.Setenv("AXONFLOW_TELEMETRY", "off")
	getSharedHeartbeat().mu.Lock()
	getSharedHeartbeat().lastChecked = time.Now().Add(-2 * time.Hour)
	getSharedHeartbeat().mu.Unlock()
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	_ = os.Chtimes(getSharedHeartbeat().stampPath, eightDaysAgo, eightDaysAgo)
	// Snapshot stamp mtime AFTER the chtimes manipulation so the assertion
	// only catches changes the SDK code itself makes.
	stampMtimeBefore := getSharedHeartbeat().readStampMtime()

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 1 {
		t.Errorf("expected opt-out to suppress 2nd ping, got %d total", got)
	}
	stampMtimeAfter := getSharedHeartbeat().readStampMtime()
	if !stampMtimeAfter.Equal(stampMtimeBefore) {
		t.Errorf("expected stamp mtime unchanged after opt-out call, before=%v after=%v", stampMtimeBefore, stampMtimeAfter)
	}
}

// Case 7: 100 concurrent goroutines all crossing the boundary at once →
// exactly 1 ping (in-flight gate coalesces stampede).
func TestHeartbeat_ConcurrentCallers_CoalesceToOnePing(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			client.maybeSendHeartbeat()
		}()
	}
	close(start)
	wg.Wait()

	if got := called.Load(); got != 1 {
		t.Errorf("expected exactly 1 ping under 100-goroutine stampede, got %d", got)
	}
}

// Case 8: no writable cache dir (stampPath="") → ping fires per call,
// but no crash and no stamp persistence. Mirrors AWS Lambda where HOME is
// unset. Net effect is the same as today's pre-heartbeat behavior — no
// regression for that runtime.
func TestHeartbeat_NoCacheDir_PingsButNoStamp(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	// Override the singleton with an empty stamp path to simulate a runtime
	// where os.UserCacheDir() returned an error (Lambda-like). newHeartbeatClient
	// installs a tmp-dir state which we immediately swap; we capture the tmp
	// state and restore on cleanup.
	tmpClient := newHeartbeatClient(t, t.TempDir())
	previous := replaceHeartbeatStateForTest("")
	t.Cleanup(func() { restoreHeartbeatStateForTest(previous) })
	client := tmpClient // suppress unused-variable; we still need the *AxonFlowClient

	// First call fires.
	client.maybeSendHeartbeat()
	if got := called.Load(); got != 1 {
		t.Fatalf("expected 1st ping, got %d", got)
	}

	// 1h cache holds inside the same process even without a stamp file.
	client.maybeSendHeartbeat()
	if got := called.Load(); got != 1 {
		t.Errorf("expected in-memory cache to suppress 2nd call, got %d", got)
	}

	// Backdate cache, call again — fires again because no stamp exists to
	// gate the 7-day path.
	getSharedHeartbeat().mu.Lock()
	getSharedHeartbeat().lastChecked = time.Now().Add(-2 * time.Hour)
	getSharedHeartbeat().mu.Unlock()
	client.maybeSendHeartbeat()
	if got := called.Load(); got != 2 {
		t.Errorf("expected 2nd ping when stamp absent and cache expired, got %d", got)
	}
}

// Case 7b (regression for P1: per-client → per-process singleton): 50
// AxonFlow clients constructed concurrently before any stamp exists must
// coalesce onto exactly 1 ping (per the "at most one heartbeat per
// environment" contract). Pre-fix this test would observe up to 50
// pings because each client carried its own heartbeatState.
func TestHeartbeat_ConcurrentMultiClient_CoalesceToOnePing(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	// Install a single shared heartbeat state pointing at the temp stamp.
	// All clients constructed below will use this singleton — that's the
	// invariant the P1 fix enforces.
	stampPath := filepath.Join(dir, "go-telemetry-last-sent")
	previous := replaceHeartbeatStateForTest(stampPath)
	t.Cleanup(func() { restoreHeartbeatStateForTest(previous) })

	const clientCount = 50
	var wg sync.WaitGroup
	wg.Add(clientCount)
	start := make(chan struct{})
	for i := 0; i < clientCount; i++ {
		go func() {
			defer wg.Done()
			<-start
			c := &AxonFlowClient{
				config: AxonFlowConfig{
					Mode:         "production",
					ClientID:     "id",
					ClientSecret: "sec",
				},
			}
			c.maybeSendHeartbeat()
		}()
	}
	close(start)
	wg.Wait()

	if got := called.Load(); got != 1 {
		t.Errorf("expected exactly 1 ping for %d concurrent clients sharing the heartbeat singleton, got %d", clientCount, got)
	}
}

// Case 9: ping returns network failure (5xx) → stamp NOT written, next
// call after cache expiry retries. Stamp-on-DELIVERY semantics.
func TestHeartbeat_PingFailure_StampNotWritten(t *testing.T) {
	// First server returns 503 (failure); we'll swap to 200 for the retry.
	_, called := startCheckpointMock(t, http.StatusServiceUnavailable)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	client.maybeSendHeartbeat()
	if got := called.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
	// Stamp must NOT be written on 5xx.
	if _, err := os.Stat(getSharedHeartbeat().stampPath); err == nil {
		t.Errorf("expected NO stamp file after failed ping, but found one at %s", getSharedHeartbeat().stampPath)
	}

	// Backdate the in-memory rate limit so the next call passes.
	getSharedHeartbeat().mu.Lock()
	getSharedHeartbeat().lastChecked = time.Now().Add(-2 * time.Hour)
	getSharedHeartbeat().mu.Unlock()

	// Swap mock to success and call again — should retry and now succeed.
	successHits := atomic.Int32{}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		successHits.Add(1)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(telemetryResponse{LatestVersion: Version})
	}))
	defer srv2.Close()
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv2.URL)

	client.maybeSendHeartbeat()
	if got := successHits.Load(); got != 1 {
		t.Errorf("expected retry to land 1 successful ping, got %d", got)
	}
	if _, err := os.Stat(getSharedHeartbeat().stampPath); err != nil {
		t.Errorf("expected stamp file after successful retry, got error: %v", err)
	}
}
