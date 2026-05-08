package axonflow

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestHeartbeatE2E_FourRunCycle exercises the 7-day delivered-heartbeat
// contract end-to-end against a real httptest checkpoint server, walking
// through the four scenarios the spec requires:
//
//	Run 1: cold start (no stamp)                    → 1 ping;  stamp present
//	Run 2: immediate re-run (fresh stamp)           → 0 pings; stamp unchanged
//	Run 3: backdate stamp 8d via os.Chtimes         → 1 ping;  stamp re-touched
//	Run 4: backdate stamp 8d, mock returns 503      → 0 successful pings;
//	                                                  stamp NOT advanced;
//	                                                  retry against 200-mock
//	                                                  fires + lands cleanly
//
// This is the "exceptional quality" verification the spec calls for: it
// validates the delivered-stamp semantics (Run 4 — failed POST does not
// advance the stamp) and the cross-run behavior (Run 1→2→3 — the stamp
// file is the source of truth across "process restarts" simulated by
// fresh AxonFlowClient construction with the same stamp path).
func TestHeartbeatE2E_FourRunCycle(t *testing.T) {
	stampDir := t.TempDir()
	stampPath := filepath.Join(stampDir, "go-telemetry-last-sent")

	// Always-200 checkpoint server for runs 1, 2, 3 and the retry leg of run 4.
	var pings200 atomic.Int32
	srv200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pings200.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"latest_version":"` + Version + `"}`))
	}))
	defer srv200.Close()

	// Always-503 checkpoint server for run 4's failure leg.
	var pings503 atomic.Int32
	srv503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pings503.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv503.Close()

	t.Setenv("AXONFLOW_TELEMETRY", "")

	// Save the current process-global heartbeat singleton and restore it on
	// cleanup so we don't leak test state into subsequent test files.
	originalHeartbeat := getSharedHeartbeat()
	t.Cleanup(func() { restoreHeartbeatStateForTest(originalHeartbeat) })

	// Helper: build a fresh client pointing at the chosen checkpoint URL,
	// AND swap the package-global heartbeat singleton to a fresh state at
	// the same stamp file location. Each call simulates a "new process" —
	// stamp file persists across runs (the cross-run invariant the
	// contract pins), in-memory gate state is fresh.
	newClient := func(checkpointURL string) *AxonFlowClient {
		t.Helper()
		t.Setenv("AXONFLOW_CHECKPOINT_URL", checkpointURL)
		// Defend against the dev machine having AXONFLOW_TELEMETRY=off in
		// the shell env — clear it for this test process so telemetry
		// actually fires per the gate (env-var is the SOLE off path in v8).
		t.Setenv("AXONFLOW_TELEMETRY", "")
		replaceHeartbeatStateForTest(stampPath)
		return &AxonFlowClient{
			config: AxonFlowConfig{
				Mode:         "production",
				ClientID:     "id",
				ClientSecret: "sec",
			},
		}
	}

	// --- Run 1: cold start, no stamp → 1 ping, stamp written ----------------
	pings200.Store(0)
	c1 := newClient(srv200.URL)
	c1.maybeSendHeartbeat()
	if got := pings200.Load(); got != 1 {
		t.Fatalf("Run 1 (cold): expected 1 ping, got %d", got)
	}
	if _, err := os.Stat(stampPath); err != nil {
		t.Fatalf("Run 1 (cold): expected stamp file at %s, got %v", stampPath, err)
	}

	// --- Run 2: immediate re-run, fresh stamp → 0 pings ---------------------
	pings200.Store(0)
	c2 := newClient(srv200.URL)
	c2.maybeSendHeartbeat()
	if got := pings200.Load(); got != 0 {
		t.Errorf("Run 2 (warm): expected 0 pings with fresh stamp, got %d", got)
	}

	// --- Run 3: backdate stamp 8d, expect 1 ping + stamp updated ------------
	eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(stampPath, eightDaysAgo, eightDaysAgo); err != nil {
		t.Fatalf("Run 3 setup: chtimes: %v", err)
	}

	pings200.Store(0)
	c3 := newClient(srv200.URL)
	c3.maybeSendHeartbeat()
	if got := pings200.Load(); got != 1 {
		t.Errorf("Run 3 (stale): expected 1 ping after backdating stamp, got %d", got)
	}
	stampInfo, err := os.Stat(stampPath)
	if err != nil {
		t.Fatalf("Run 3: stat stamp: %v", err)
	}
	if time.Since(stampInfo.ModTime()) > 5*time.Second {
		t.Errorf("Run 3: expected stamp mtime to be very recent after successful ping, got %v ago",
			time.Since(stampInfo.ModTime()))
	}

	// --- Run 4: backdate stamp 8d, point at 503 mock ------------------------
	// Expectation: ping is attempted (counts on the 503 server) but stamp
	// is NOT advanced. Then a follow-up run against the 200 server lands
	// cleanly and advances the stamp.
	if err := os.Chtimes(stampPath, eightDaysAgo, eightDaysAgo); err != nil {
		t.Fatalf("Run 4 setup: chtimes: %v", err)
	}
	stampMtimeBeforeFailedRun, err := os.Stat(stampPath)
	if err != nil {
		t.Fatalf("Run 4: pre-run stat: %v", err)
	}

	pings503.Store(0)
	c4a := newClient(srv503.URL)
	c4a.maybeSendHeartbeat()
	if got := pings503.Load(); got != 1 {
		t.Errorf("Run 4 (failure): expected 1 attempt on 503 server, got %d", got)
	}
	stampInfoAfterFail, err := os.Stat(stampPath)
	if err != nil {
		t.Fatalf("Run 4: post-failure stat: %v", err)
	}
	if !stampInfoAfterFail.ModTime().Equal(stampMtimeBeforeFailedRun.ModTime()) {
		t.Errorf("Run 4: stamp mtime ADVANCED after failed POST — expected unchanged.\nbefore=%v\nafter=%v",
			stampMtimeBeforeFailedRun.ModTime(), stampInfoAfterFail.ModTime())
	}

	// --- Run 4 retry: same backdated stamp, point at 200 mock ---------------
	// In real life the stamp would still be 8d old (because the failed POST
	// didn't advance it) and the next process startup hits the 200 path.
	pings200.Store(0)
	c4b := newClient(srv200.URL)
	c4b.maybeSendHeartbeat()
	if got := pings200.Load(); got != 1 {
		t.Errorf("Run 4 (retry): expected 1 ping when stamp still stale and server now 200, got %d", got)
	}
	stampInfoAfterRetry, err := os.Stat(stampPath)
	if err != nil {
		t.Fatalf("Run 4 retry: stat: %v", err)
	}
	if time.Since(stampInfoAfterRetry.ModTime()) > 5*time.Second {
		t.Errorf("Run 4 retry: expected stamp mtime advanced to ~now after successful retry, got %v ago",
			time.Since(stampInfoAfterRetry.ModTime()))
	}
}
