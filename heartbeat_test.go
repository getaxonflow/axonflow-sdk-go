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
// maybeSendHeartbeat in isolation. The caller supplies a stamp directory
// (typically t.TempDir()) so the test doesn't touch the user's real cache
// dir. Telemetry is forced ON via TelemetryEnabled=true so the gating
// decision under test is the heartbeat gate, not the mode-default check.
func newHeartbeatClient(t *testing.T, stampDir string) *AxonFlowClient {
	t.Helper()
	boolPtr := func(v bool) *bool { return &v }
	return &AxonFlowClient{
		config: AxonFlowConfig{
			Mode:             "production",
			ClientID:         "id",
			ClientSecret:     "sec",
			TelemetryEnabled: boolPtr(true),
		},
		heartbeat: &heartbeatState{
			stampPath: filepath.Join(stampDir, "go-telemetry-last-sent"),
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
	if _, err := os.Stat(client.heartbeat.stampPath); err != nil {
		t.Errorf("expected stamp file at %s after successful ping, got error: %v", client.heartbeat.stampPath, err)
	}
}

// Case 2: stamp written 1 day ago (well within heartbeatInterval) → 0 pings.
func TestHeartbeat_FreshStamp_DoesNotFire(t *testing.T) {
	_, called := startCheckpointMock(t, http.StatusOK)
	dir := t.TempDir()
	client := newHeartbeatClient(t, dir)

	// Pre-create the stamp file with a recent mtime.
	if err := client.heartbeat.writeStampAtomic(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}
	// writeStampAtomic uses now() for the mtime regardless of the parameter
	// value (the parameter is for the human-readable contents). Force the
	// mtime to 1 day ago so the freshness check is deterministic.
	oneDayAgo := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(client.heartbeat.stampPath, oneDayAgo, oneDayAgo); err != nil {
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

	if err := client.heartbeat.writeStampAtomic(time.Now()); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(client.heartbeat.stampPath, eightDaysAgo, eightDaysAgo); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 1 {
		t.Errorf("expected 1 ping with stale stamp, got %d", got)
	}
	mtime := client.heartbeat.readStampMtime()
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
	client.heartbeat.mu.Lock()
	client.heartbeat.lastChecked = time.Now().Add(-2 * time.Hour)
	client.heartbeat.mu.Unlock()
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(client.heartbeat.stampPath, eightDaysAgo, eightDaysAgo); err != nil {
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
	client.heartbeat.mu.Lock()
	client.heartbeat.lastChecked = time.Now().Add(-2 * time.Hour)
	client.heartbeat.mu.Unlock()
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	_ = os.Chtimes(client.heartbeat.stampPath, eightDaysAgo, eightDaysAgo)
	// Snapshot stamp mtime AFTER the chtimes manipulation so the assertion
	// only catches changes the SDK code itself makes.
	stampMtimeBefore := client.heartbeat.readStampMtime()

	client.maybeSendHeartbeat()

	if got := called.Load(); got != 1 {
		t.Errorf("expected opt-out to suppress 2nd ping, got %d total", got)
	}
	stampMtimeAfter := client.heartbeat.readStampMtime()
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
	client := newHeartbeatClient(t, t.TempDir())
	client.heartbeat.stampPath = "" // simulate UserCacheDir() failure

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
	client.heartbeat.mu.Lock()
	client.heartbeat.lastChecked = time.Now().Add(-2 * time.Hour)
	client.heartbeat.mu.Unlock()
	client.maybeSendHeartbeat()
	if got := called.Load(); got != 2 {
		t.Errorf("expected 2nd ping when stamp absent and cache expired, got %d", got)
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
	if _, err := os.Stat(client.heartbeat.stampPath); err == nil {
		t.Errorf("expected NO stamp file after failed ping, but found one at %s", client.heartbeat.stampPath)
	}

	// Backdate the in-memory rate limit so the next call passes.
	client.heartbeat.mu.Lock()
	client.heartbeat.lastChecked = time.Now().Add(-2 * time.Hour)
	client.heartbeat.mu.Unlock()

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
	if _, err := os.Stat(client.heartbeat.stampPath); err != nil {
		t.Errorf("expected stamp file after successful retry, got error: %v", err)
	}
}
