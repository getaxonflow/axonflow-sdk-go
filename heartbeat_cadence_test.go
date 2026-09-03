package axonflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// Cadence tests for the two bounds added alongside the adapter registry
// (axonflow-enterprise#3682, item 3): a bounded FAILURE backoff and a bounded
// SUCCESS cadence.
//
// These two are separate defects with separate blast radii, and a test for
// one does not cover the other:
//
//   - No failure backoff: a deployment that cannot reach the checkpoint (the
//     normal state of air-gapped and in-VPC self-hosted topologies) probes
//     the CUSTOMER'S OWN /health once an hour, forever.
//   - No success cadence: where the stamp file cannot be persisted (HOME
//     unset in distroless/scratch containers and Lambda custom runtimes, or
//     a read-only root filesystem — ordinary Kubernetes hardening) a
//     SUCCESSFUL ping recurs hourly, 168x the disclosed weekly rate. The
//     failure backoff cannot bound this one: it resets on delivery, and
//     these deliveries succeed.
//
// WHAT THIS HARNESS CAN AND CANNOT VARY. It varies the gate's own state
// directly (last-checked instant, failure count, last-delivered instant),
// because the alternative — waiting out a real one-hour guard — is not a
// test. It CANNOT vary wall-clock time, so "an hour really elapsed" is
// modelled by backdating lastChecked rather than observed. That is the same
// compromise the Rust suite makes (set_gate_state_for_tests) and it is why
// guardIntervalFor is ALSO tested as a pure function below: the pure test
// pins the arithmetic, the gate tests pin that the call site uses it.

func TestGuardIntervalForDoublesAndCaps(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
		about    string
	}{
		{0, heartbeatGuardInterval, "no failures: the base interval, unchanged"},
		{1, 2 * heartbeatGuardInterval, "one failure doubles it"},
		{2, 4 * heartbeatGuardInterval, "two failures quadruple it"},
		{7, 128 * heartbeatGuardInterval, "128h is still under the 168h cap"},
		{8, heartbeatInterval, "256h would exceed 7 days, so it caps"},
		{64, heartbeatInterval, "a large counter must cap, not overflow the shift"},
		{1 << 20, heartbeatInterval, "an unbounded counter must not shift by >=63"},
	} {
		if got := guardIntervalFor(tc.failures); got != tc.want {
			t.Errorf("guardIntervalFor(%d) = %v, want %v (%s)", tc.failures, got, tc.want, tc.about)
		}
	}
}

// reopenGuard models "the short guard interval has elapsed" and NOTHING
// else. Deliberately distinct from a full reset: clearing the failure counter
// here would mean "time passed" also erased the backoff, and the backoff test
// would then measure one failure over and over instead of consecutive ones.
func reopenGuard(h *heartbeatState, checkedAgo time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastChecked = time.Now().Add(-checkedAgo)
	h.lastCheckedNanos.Store(h.lastChecked.UnixNano())
	h.inFlight = false
}

// TestGateRefusesWithinTheWidenedInterval pins the CALL SITE, not the
// arithmetic — and it drives the REAL gate to do it.
//
// An earlier version of this test recomputed guardIntervalFor itself and
// asserted on the result. That version passed with the call site reverted to
// the bare heartbeatGuardInterval: it was testing a lookalike of the gate
// rather than the gate, so the mutant survived. It now calls
// maybeSendHeartbeat and counts what reached the checkpoint, which is the
// only thing that can tell the two intervals apart.
//
// MUTATION GATE: revert the call site to `heartbeatGuardInterval` and this
// fails with "the checkpoint was called 2 times" — 90 minutes is past the
// base 1-hour interval but inside the widened 2-hour one.
func TestGateRefusesWithinTheWidenedInterval(t *testing.T) {
	dir := t.TempDir()
	c := newHeartbeatClient(t, dir)
	_, called := startCheckpointMock(t, 500) // every attempt FAILS, so the backoff accumulates

	h := getSharedHeartbeat()

	// Attempt 1: the gate is cold, so it runs; the 500 makes it a failure.
	c.maybeSendHeartbeat()
	if n := called.Load(); n != 1 {
		t.Fatalf("the checkpoint was called %d times on the first pass, want 1 — "+
			"the fixture never got an attempt to fail, so nothing below is measurable", n)
	}
	if h.consecutiveFailures != 1 {
		t.Fatalf("consecutiveFailures = %d after one 500, want 1", h.consecutiveFailures)
	}

	// Model 90 minutes passing. That is PAST the base 1-hour guard and
	// INSIDE the widened 2-hour one, which is what makes this case able to
	// distinguish them at all.
	reopenGuard(h, 90*time.Minute)

	c.maybeSendHeartbeat()

	if n := called.Load(); n != 1 {
		t.Errorf("the checkpoint was called %d times, want 1. 90 minutes is inside the widened "+
			"%v interval one failure earns; a gate still using the base %v probes the customer's "+
			"own platform hourly forever when egress is blocked",
			n, guardIntervalFor(1), heartbeatGuardInterval)
	}
}

// TestGateAdmitsOnceTheWidenedIntervalElapses is the other direction. Without
// it, a "backoff" that simply never re-opened would pass the test above — a
// permanent mute is not a backoff.
func TestGateAdmitsOnceTheWidenedIntervalElapses(t *testing.T) {
	dir := t.TempDir()
	c := newHeartbeatClient(t, dir)
	_, called := startCheckpointMock(t, 500)

	h := getSharedHeartbeat()
	c.maybeSendHeartbeat()
	if n := called.Load(); n != 1 {
		t.Fatalf("first pass called the checkpoint %d times, want 1", n)
	}

	// Past the widened 2-hour interval this time.
	reopenGuard(h, 3*time.Hour)
	c.maybeSendHeartbeat()

	if n := called.Load(); n != 2 {
		t.Errorf("the checkpoint was called %d times, want 2 — once the widened interval has "+
			"elapsed the gate must retry; a backoff that never re-opens is a permanent mute", n)
	}
}

// TestDeliverySucceedingResetsTheBackoff — a deployment that recovers must
// return to the ordinary cadence rather than staying backed off.
func TestDeliverySucceedingResetsTheBackoff(t *testing.T) {
	h := &heartbeatState{}
	h.recordAttempt(false, time.Now())
	h.recordAttempt(false, time.Now())
	if h.consecutiveFailures != 2 {
		t.Fatalf("consecutiveFailures = %d, want 2", h.consecutiveFailures)
	}

	delivered := time.Now()
	h.recordAttempt(true, delivered)
	if h.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures = %d after a delivery, want 0", h.consecutiveFailures)
	}
	if !h.lastDelivered.Equal(delivered) {
		t.Errorf("lastDelivered = %v, want %v", h.lastDelivered, delivered)
	}
}

// TestSuccessCadenceIsBoundedWithNoStampFile is the defect the failure
// backoff cannot reach.
//
// The state has stampPath == "" — the distroless / Lambda / read-only-rootfs
// case, where readStampMtime returns the zero time forever, so the stamp gate
// can never suppress anything. Before this change, a DELIVERED ping left no
// record at all and the gate re-opened every hour.
//
// MUTATION GATE: delete the lastDelivered check from maybeSendHeartbeat and
// this fails with "the checkpoint was called 2 times" — the gate re-opens an
// hour after a SUCCESSFUL delivery because nothing recorded that it happened.
//
// Like the backoff test above, this drives the real gate. The first version
// recomputed the gate's predicate in the test body and survived the mutant.
func TestSuccessCadenceIsBoundedWithNoStampFile(t *testing.T) {
	// The empty stamp path is the whole point: distroless / scratch / Lambda
	// custom runtimes (HOME unset) and read-only root filesystems. There
	// readStampMtime returns the zero time forever, so the FILE gate can
	// never suppress anything and the in-memory cadence is the only bound.
	previous := replaceHeartbeatStateForTest("")
	t.Cleanup(func() { restoreHeartbeatStateForTest(previous) })
	t.Setenv("AXONFLOW_TELEMETRY", "")
	_, called := startCheckpointMock(t, 200) // deliveries SUCCEED

	c := &AxonFlowClient{config: AxonFlowConfig{Mode: "production", ClientID: "id", ClientSecret: "sec"}}
	h := getSharedHeartbeat()

	// Premise check: the file gate really is inert here.
	if mtime := h.readStampMtime(); !mtime.IsZero() {
		t.Fatalf("readStampMtime() = %v with an empty stampPath, want the zero time — "+
			"this test's premise is that the file gate cannot fire", mtime)
	}

	c.maybeSendHeartbeat()
	if n := called.Load(); n != 1 {
		t.Fatalf("the checkpoint was called %d times on the first pass, want 1 — no delivery "+
			"happened, so there is no success for the cadence to bound", n)
	}
	if h.lastDelivered.IsZero() {
		t.Fatal("lastDelivered was not recorded after a 2xx; nothing below can be measured")
	}

	// An hour later. The guard is open and the stamp gate is inert, so
	// lastDelivered is the ONLY thing that can refuse this.
	reopenGuard(h, 2*heartbeatGuardInterval)
	c.maybeSendHeartbeat()

	if n := called.Load(); n != 1 {
		t.Errorf("the checkpoint was called %d times, want 1. With no stamp file a DELIVERED "+
			"ping must still be bounded in memory; without it a success recurs hourly — 168x "+
			"the weekly rate this SDK discloses, in exactly the environments least able to notice", n)
	}
}

// TestSuccessCadenceReopensAfterTheInterval — the other direction, so a
// cadence that permanently muted a process would not pass as a fix.
func TestSuccessCadenceReopensAfterTheInterval(t *testing.T) {
	previous := replaceHeartbeatStateForTest("")
	t.Cleanup(func() { restoreHeartbeatStateForTest(previous) })
	t.Setenv("AXONFLOW_TELEMETRY", "")
	_, called := startCheckpointMock(t, 200)

	c := &AxonFlowClient{config: AxonFlowConfig{Mode: "production", ClientID: "id", ClientSecret: "sec"}}
	h := getSharedHeartbeat()

	c.maybeSendHeartbeat()
	if n := called.Load(); n != 1 {
		t.Fatalf("first pass called the checkpoint %d times, want 1", n)
	}

	// Backdate the delivery past the 7-day interval, and re-open the guard.
	h.mu.Lock()
	h.lastDelivered = time.Now().Add(-heartbeatInterval - time.Hour)
	h.mu.Unlock()
	reopenGuard(h, 2*heartbeatGuardInterval)

	c.maybeSendHeartbeat()
	if n := called.Load(); n != 2 {
		t.Errorf("the checkpoint was called %d times, want 2 — the cadence must re-open once "+
			"the 7-day interval has passed", n)
	}
}

// TestASuppressedPassIsNotCountedAsAFailure guards the distinction the Rust
// SDK spells out on record_attempt: a pass that stopped at a FRESH STAMP is
// not a failure. Counting it would widen the interval for a gate that is
// working exactly as designed, and a healthy deployment's backoff would
// ratchet to its 7-day cap on nothing but successful suppression.
//
// The checkpoint here answers 500. That is deliberate: if the gate wrongly
// let a ping through, it would fail, and consecutiveFailures would move —
// so a single assertion distinguishes "correctly suppressed" from both
// "wrongly sent" and "wrongly counted".
//
// MUTATION GATE: move the recordAttempt(false, ...) call above the stamp
// check in maybeSendHeartbeat and this test fails with
// "consecutiveFailures = 1".
func TestASuppressedPassIsNotCountedAsAFailure(t *testing.T) {
	dir := t.TempDir()
	c := newHeartbeatClient(t, dir)
	_, called := startCheckpointMock(t, 500)

	h := getSharedHeartbeat()
	// A stamp written NOW: the 7-day gate must suppress.
	if err := h.writeStampAtomic(time.Now()); err != nil {
		t.Fatalf("stamp write failed, so this case cannot run: %v", err)
	}

	c.maybeSendHeartbeat()

	// Positive control that the suppression is the stamp's doing and the run
	// genuinely reached the stamp check: the ping must NOT have fired.
	if n := called.Load(); n != 0 {
		t.Fatalf("the checkpoint was called %d times despite a fresh stamp; this case can no longer "+
			"distinguish a suppressed pass from a sent one", n)
	}
	if h.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures = %d after a pass suppressed by a fresh stamp, want 0. "+
			"A suppressed pass is the gate working, not an attempt that failed", h.consecutiveFailures)
	}
}

// TestStreamOnlyProcessStillPings is the regression for the bypass the
// request-site census was written to prevent recurring.
//
// StreamExecutionStatus builds its own http.Client — SSE needs one with no
// timeout — and called .Do directly, so it never reached doHttpRequest and
// never reached the heartbeat trigger. Once the heartbeat moved from client
// construction to first request (#3682), a process whose ONLY outbound call is
// a stream stopped pinging entirely. That is a real deployment shape: a
// monitor or a dashboard backend that opens one long-lived stream and does
// nothing else.
//
// MUTATION GATE: delete the maybeSendHeartbeatOnRequest call from
// StreamExecutionStatus and this fails with "the checkpoint was called 0
// times".
func TestStreamOnlyProcessStillPings(t *testing.T) {
	// A REAL client via NewClient, not the bare struct the other cadence tests
	// use: StreamExecutionStatus reaches into c.httpClient.Transport, and a
	// hand-built client has none. Safe to construct here precisely because of
	// this change — NewClient no longer pings, so constructing one does not
	// consume the gate the assertion below depends on.
	previous := replaceHeartbeatStateForTest(filepath.Join(t.TempDir(), "stamp"))
	t.Cleanup(func() { restoreHeartbeatStateForTest(previous) })
	_, called := startCheckpointMock(t, 200)

	// A stream endpoint that accepts the connection and closes it. The stream
	// itself is not under test — reaching the trigger is.
	stream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(stream.Close)

	c := NewClient(AxonFlowConfig{
		Endpoint:     stream.URL,
		ClientID:     "id",
		ClientSecret: "sec",
		Mode:         "production",
	})

	// POSITIVE CONTROL for the whole point of this test: constructing the
	// client pinged NOTHING. Everything below is therefore attributable to the
	// stream call, not to construction.
	if n := called.Load(); n != 0 {
		t.Fatalf("constructing the client sent %d ping(s); the heartbeat must fire on the "+
			"first REQUEST, and this case can no longer attribute a ping to the stream", n)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The call may succeed or fail; either way the trigger must have run
	// BEFORE the .Do, because the heartbeat rides the ATTEMPT to make a
	// request.
	events, errs, _ := c.StreamExecutionStatus(ctx, "exec-1")
	_ = events
	_ = errs

	if n := called.Load(); n != 1 {
		t.Errorf("the checkpoint was called %d times, want 1. A process whose only outbound "+
			"call is a stream must still ping — StreamExecutionStatus builds its own client "+
			"and bypasses doHttpRequest, so it has to call the trigger itself", n)
	}
}
