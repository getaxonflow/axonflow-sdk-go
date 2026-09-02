//go:build ignore

// runtime-e2e/read_path_identity/main.go
//
// Real-wire proof of the read-path per-user identity (platform #2922) through
// the Go SDK's own runtime, against a LIVE enterprise agent + orchestrator.
//
// The defect this pins: every SDK carried `user_token` as a write-path body
// field only, so ExplainDecision and ListDecisions asked the platform
// anonymously. On an enterprise stack that is not "a caller who sees
// everything" — it is a caller the platform cannot scope, so explain answered
// not-found for ids that plainly existed and list answered a confident empty
// page. Both looked exactly like "there is nothing there".
//
// # What this driver asserts, and why each assertion cannot pass vacuously
//
//	 1. WRITE      three decisions through the real /decide plane as dev-a,
//	                attributed to dev-a's validated identity.
//	 2. LIST       as dev-a: the page must contain AT LEAST the three ids this
//	                run wrote and must contain each one BY ID. The floor is
//	                derived from what this test itself wrote, so it cannot be
//	                satisfied by a stale row or by a lucky non-empty page.
//	 3. EXPLAIN    as dev-a: the explanation must carry the decision id asked
//	                for AND the context keys THIS RUN chose — a field the test
//	                controls, so a populated-looking stub cannot satisfy it.
//	 4. NO IDENTITY  the same list, unscoped: must be REFUSED as a typed
//	                ReadScopeError with IdentityMissing, not answered [].
//	 5. OTHER USER   explain dev-a's decision as dev-b: must be refused, and
//	                must NOT report a missing identity — dev-b presented one.
//	 6. MALFORMED / EXPIRED / WRONG-ORG tokens: each must fail CLOSED (401),
//	                never fall back to the tenant credential's visibility.
//	 7. TENANT-WIDE  as admin: must see dev-a's decision (proves the own-rows
//	                narrowing in 5 is a scoping decision, not a broken read).
//	 8. NO LEAK    the token must appear in NO captured log line and in NO
//	                request reaching the telemetry collector this driver hosts.
//	 9. OBSERVABLE the platform must leave a record of the unscoped read.
//
// # Run
//
//	Bring up an ENTERPRISE stack per
//	axonflow-internal-docs/engineering/E2E_EXAMPLES_TESTING_WORKFLOW.md
//	(./scripts/setup-e2e-testing.sh enterprise), then:
//
//	  source /tmp/axonflow-e2e-env.sh
//	  go run runtime-e2e/read_path_identity/main.go
//
//	Env: AXONFLOW_AGENT_URL, AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET,
//	     AXONFLOW_JWT_SECRET (or JWT_SECRET) — the HS256 secret the stack
//	     validates per-user tokens with, so this driver can mint the several
//	     distinct identities the scoping assertions need. One shared env token
//	     cannot express "dev-a", "dev-b", "expired" and "another org".
//	Optional: AXONFLOW_ORCH_CONTAINER (default axonflow-orchestrator) for the
//	     step-9 platform-record check.

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

// runTag makes every assertion in this run specific to this run: the context
// values below are unique per invocation, so "the explanation is populated"
// becomes "the explanation carries the value THIS process chose".
var runTag = fmt.Sprintf("s3-%d", time.Now().UnixNano())

func main() {
	endpoint := getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := mustEnv("AXONFLOW_CLIENT_ID")
	clientSecret := mustEnv("AXONFLOW_CLIENT_SECRET")
	jwtSecret := os.Getenv("AXONFLOW_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = mustEnv("JWT_SECRET")
	}

	// Capture everything the SDK logs, for step 8. Kept for the whole run so
	// a leak anywhere is caught, not just around the call we suspected.
	var logs syncBuffer
	log.SetOutput(io.MultiWriter(os.Stderr, &logs))

	// A real listener standing in for the telemetry checkpoint — a THIRD
	// PARTY. Not a mock of the system under test: it is the far end of a
	// request the SDK sends on its own initiative, and the point is to read
	// what actually arrives there.
	collector, collectorURL, collectorSeen := startCollector()
	defer collector.Close()
	os.Setenv("AXONFLOW_CHECKPOINT_URL", collectorURL)

	// The heartbeat fires from the FIRST NewClient in the process, gated by a
	// 7-day stamp file and a process-global singleton. Both have to be cleared
	// here, before any client exists, or step 8's collector stays empty and
	// its leak assertions assert nothing. The E2E setup script sets
	// AXONFLOW_TELEMETRY=off for exactly the opposite reason (keeping test
	// runs out of real checkpoint data); here the ping is the thing under
	// test, and it is pointed at a listener this process owns.
	os.Setenv("AXONFLOW_TELEMETRY", "on")
	clearHeartbeatStamp()

	// ---- Identities. Claim shape mirrors scripts/generate-jwt.sh --kind user
	// exactly (iss/sub/email/jti/org_id/exp), which is what the platform's
	// HS256 per-user validator requires.
	//
	// The addresses are @example.com and NOT @axonflow.local, which matters
	// more than it looks. The platform reserves that whole domain (and
	// @axonflow.internal) for SHARED, non-personal identities and censuses
	// them to nothing before scoping — so a perfectly valid developer token
	// minted at @axonflow.local reads ZERO rows and reports scope "none",
	// indistinguishable from presenting no token at all. Verified live on this
	// stack: the same token differs only in domain and yields none vs own-rows.
	// generate-jwt.sh's own default (demo-user@axonflow.local) lands in the
	// reserved domain, which is why a driver that used it would prove nothing
	// about own-rows scoping while appearing to.
	devA := mintUserToken(jwtSecret, "dev-a-"+runTag+"@example.com", clientID, "developer", time.Hour)
	devB := mintUserToken(jwtSecret, "dev-b-"+runTag+"@example.com", clientID, "developer", time.Hour)
	admin := mintUserToken(jwtSecret, "admin-"+runTag+"@example.com", clientID, "admin", time.Hour)
	expired := mintUserToken(jwtSecret, "stale-"+runTag+"@example.com", clientID, "developer", -time.Hour)
	wrongOrg := mintUserToken(jwtSecret, "outsider-"+runTag+"@example.com", "some-other-org-"+runTag, "admin", time.Hour)
	malformed := "not.a.jwt"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// ================================================================= 1. WRITE
	// Three, not one: the anti-vacuity floor in step 2 is "at least the number
	// this run wrote", and a floor of one is satisfied by almost any page.
	const wrote = 3
	written := make([]string, 0, wrote)
	for i := 0; i < wrote; i++ {
		id, err := decideAs(endpoint, clientID, clientSecret, devA, i)
		if err != nil {
			fail("step 1: writing decision %d as dev-a: %v", i, err)
		}
		written = append(written, id)
	}
	fmt.Printf("step 1 PASS: wrote %d decisions as dev-a: %v\n", len(written), written)

	// The audit write is asynchronous; give it a bounded chance to land
	// before reading, and say so rather than sleeping silently.
	waitForVisible(ctx, endpoint, clientID, clientSecret, devA, written[0])

	// ================================================================== 2. LIST
	asDevA := client(endpoint, clientID, clientSecret, devA)
	rows, err := asDevA.ListDecisions(ctx, axonflow.ListDecisionsOptions{Limit: 50})
	if err != nil {
		fail("step 2: ListDecisions as dev-a: %v", err)
	}
	if len(rows) < wrote {
		fail("step 2: dev-a's page has %d rows, want at least the %d this run wrote — "+
			"a page smaller than what we just wrote cannot be a correctly-scoped read", len(rows), wrote)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.DecisionID] = true
	}
	for _, id := range written {
		if !seen[id] {
			fail("step 2: dev-a's page does not contain %s, which dev-a wrote in this run", id)
		}
	}
	fmt.Printf("step 2 PASS: dev-a's page (%d rows) contains all %d ids this run wrote\n", len(rows), wrote)

	// =============================================================== 3. EXPLAIN
	exp, err := asDevA.ExplainDecision(ctx, written[0])
	if err != nil {
		fail("step 3: ExplainDecision as dev-a: %v", err)
	}
	if exp.DecisionID != written[0] {
		fail("step 3: explanation decision_id = %q, want %q", exp.DecisionID, written[0])
	}
	// A field THIS RUN controls. "Non-empty" would pass on any stub.
	if got := exp.Context["x_session_id"]; got != runTag {
		fail("step 3: explanation context[x_session_id] = %q, want %q — the explanation must carry "+
			"the value this run wrote, not merely be non-empty (context: %v)", got, runTag, exp.Context)
	}
	if exp.Decision == "" {
		fail("step 3: explanation carries no verdict")
	}
	fmt.Printf("step 3 PASS: explanation for %s is populated and carries this run's context (%s=%q, decision=%q)\n",
		written[0], "x_session_id", runTag, exp.Decision)

	// =========================================================== 4. NO IDENTITY
	// The whole point. An unscoped list must not answer [] and nil.
	anon := client(endpoint, clientID, clientSecret, "")
	anonRows, anonErr := anon.ListDecisions(ctx, axonflow.ListDecisionsOptions{Limit: 50})
	rse, ok := axonflow.AsReadScopeError(anonErr)
	switch {
	case anonErr == nil && len(anonRows) == 0:
		fail("step 4: the unscoped list returned 0 rows and NO error. That is the defect: the read " +
			"could not have returned a row, and reporting it as an empty page is a confident lie")
	case anonErr == nil:
		fail("step 4: the unscoped list returned %d rows — this stack is not enforcing role-scoped "+
			"reads, so every scoping assertion in this driver is vacuous. Check DEPLOYMENT_MODE=enterprise", len(anonRows))
	case !ok:
		fail("step 4: the unscoped list failed with %T (%v), want a typed *ReadScopeError", anonErr, anonErr)
	case !rse.IdentityMissing():
		fail("step 4: the unscoped list was refused with scope %q, want %q", rse.Scope, axonflow.ReadScopeNone)
	}
	fmt.Printf("step 4 PASS: the unscoped list is refused, not answered empty: %v\n", anonErr)

	// ============================================================ 5. OTHER USER
	asDevB := client(endpoint, clientID, clientSecret, devB)
	_, errB := asDevB.ExplainDecision(ctx, written[0])
	rseB, okB := axonflow.AsReadScopeError(errB)
	switch {
	case errB == nil:
		fail("step 5: dev-b explained dev-a's decision %s — that is the cross-user leak #2922 closed", written[0])
	case !okB:
		fail("step 5: dev-b's refusal is %T (%v), want a typed *ReadScopeError naming the scope", errB, errB)
	case rseB.IdentityMissing():
		fail("step 5: dev-b's refusal reports a MISSING identity; dev-b presented one. "+
			"Reporting the wrong cause is the confidently-wrong-diagnosis class (scope=%q)", rseB.Scope)
	case rseB.Scope != axonflow.ReadScopeOwnRows:
		fail("step 5: dev-b's refusal reports scope %q, want %q", rseB.Scope, axonflow.ReadScopeOwnRows)
	}
	fmt.Printf("step 5 PASS: dev-b is refused dev-a's decision, with the RIGHT cause: %v\n", errB)

	// ================================= 6. MALFORMED / EXPIRED / WRONG-ORG
	// The common real-world state, not the exception. Each must fail closed:
	// a rejected token must never degrade into "no token", which would hand
	// the caller the tenant credential's visibility.
	for _, bad := range []struct {
		name  string
		token string
	}{
		{"malformed", malformed},
		{"expired", expired},
		{"another org", wrongOrg},
	} {
		_, err := client(endpoint, clientID, clientSecret, bad.token).
			ListDecisions(ctx, axonflow.ListDecisionsOptions{Limit: 5})
		if err == nil {
			fail("step 6 (%s): a rejected per-user token produced a SUCCESSFUL read. A present-but-invalid "+
				"identity must fail closed, never degrade to the unscoped path", bad.name)
		}
		if !strings.Contains(err.Error(), "401") {
			fail("step 6 (%s): want a 401 (the platform rejecting the token outright), got: %v", bad.name, err)
		}
		if strings.Contains(err.Error(), bad.token) {
			fail("step 6 (%s): the error message echoes the rejected credential", bad.name)
		}
		fmt.Printf("step 6 PASS (%s): rejected fail-closed with 401, credential not echoed\n", bad.name)
	}

	// =========================================================== 7. TENANT-WIDE
	// Without this, step 5 is unfalsifiable: a read that is broken for
	// everyone would also "refuse dev-b".
	asAdmin := client(endpoint, clientID, clientSecret, admin)
	adminExp, err := asAdmin.ExplainDecision(ctx, written[0])
	if err != nil {
		fail("step 7: an admin identity could not explain dev-a's decision %s: %v — "+
			"then step 5's refusal is a broken read, not a scoping decision", written[0], err)
	}
	if adminExp.DecisionID != written[0] {
		fail("step 7: admin explanation decision_id = %q, want %q", adminExp.DecisionID, written[0])
	}
	fmt.Printf("step 7 PASS: an admin identity reads tenant-wide — step 5's refusal is scoping, not breakage\n")

	// ============================================================== 8. NO LEAK
	// The ping was sent by the first NewClient above (stamp cleared, telemetry
	// forced on before any client existed), and every read since has gone
	// through the SDK's own transport carrying a token.

	for _, tok := range []struct {
		name  string
		value string
	}{{"dev-a", devA}, {"dev-b", devB}, {"admin", admin}} {
		if strings.Contains(logs.String(), tok.value) {
			fail("step 8: the %s token appears in the SDK's log output — a per-user credential must never be logged", tok.name)
		}
		for i, req := range collectorSeen() {
			if strings.Contains(req, tok.value) {
				fail("step 8: the %s token reached the telemetry collector in request %d", tok.name, i)
			}
		}
	}
	if n := len(collectorSeen()); n == 0 {
		fail("step 8: the telemetry collector received NOTHING, so its leak assertions asserted nothing. " +
			"Set AXONFLOW_TELEMETRY=on for this driver")
	}
	fmt.Printf("step 8 PASS: no token in %d captured log bytes or in any of %d telemetry requests\n",
		len(logs.String()), len(collectorSeen()))

	// =========================================================== 9. OBSERVABLE
	// A fail-closed read the platform leaves no trace of is a read nobody can
	// audit. The orchestrator logs the unscoped read from step 4.
	assertPlatformRecordedTheUnscopedRead()

	fmt.Println("\nALL PASS: read-path identity verified end to end through the Go SDK runtime")
}

// ---------------------------------------------------------------- helpers

func client(endpoint, clientID, secret, userToken string) *axonflow.AxonFlowClient {
	return axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: secret,
		UserToken:    userToken,
		Timeout:      30 * time.Second,
	})
}

// decideAs drives the real /decide plane as a given per-user identity. That
// endpoint reads identity from the request BODY (`user_token`), not from
// X-User-Token — the write path and the read path are deliberately different
// seams, which is exactly why the read path needed its own surface.
func decideAs(endpoint, clientID, secret, userToken string, i int) (string, error) {
	body := map[string]any{
		"stage":      "llm",
		"query":      fmt.Sprintf("summarize support ticket %d for run %s", i, runTag),
		"user_token": userToken,
		"target":     map[string]any{"type": "llm", "model": "gpt-4", "provider": "openai"},
		"context": map[string]any{
			"x-session-id": runTag,
			"x-ai-agent":   "read-path-identity-e2e",
		},
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", endpoint+"/api/v1/decide", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-ID", clientID)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("decide HTTP %d: %s", resp.StatusCode, rb)
	}
	var out struct {
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	if out.DecisionID == "" {
		return "", fmt.Errorf("no decision_id in /decide response: %s", rb)
	}
	return out.DecisionID, nil
}

// waitForVisible polls until the asynchronous audit write has landed, so a
// later assertion fails on SCOPE rather than on timing.
func waitForVisible(ctx context.Context, endpoint, clientID, secret, userToken, decisionID string) {
	c := client(endpoint, clientID, secret, userToken)
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.ExplainDecision(ctx, decisionID); err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	fail("the decision %s never became visible to the identity that wrote it within 45s — "+
		"the audit write did not land, so every read assertion below would be about timing, not scope", decisionID)
}

// mintUserToken builds the per-user HS256 JWT the platform's own validator
// requires, with the same claim set scripts/generate-jwt.sh --kind user emits.
// Minted here rather than shelled out to because the scoping assertions need
// SEVERAL distinct identities (two developers, an admin, an expired one, one
// from another org) and a single shared env token cannot express them.
func mintUserToken(secret, email, orgID, role string, validFor time.Duration) string {
	now := time.Now()
	claims := map[string]any{
		"iss":         "axonflow-user-token-mint",
		"sub":         email,
		"email":       email,
		"user_id":     email,
		"tenant_id":   orgID,
		"org_id":      orgID,
		"role":        role,
		"region":      "local",
		"jti":         fmt.Sprintf("%s-%d", runTag, now.UnixNano()),
		"permissions": []string{"query", "llm", "mcp_query"},
		"iat":         now.Add(-time.Minute).Unix(),
		"nbf":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(validFor).Unix(),
	}
	header := b64(`{"alg":"HS256","typ":"JWT"}`)
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		fail("minting a token: %v", err)
	}
	signing := header + "." + b64(string(payloadJSON))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// startCollector stands up a real listener as the telemetry checkpoint and
// records every request body + header block that reaches it.
//
// allow-mocks-here: this is not a stand-in for the system under test. It is
// the far end of a request the SDK sends to a THIRD PARTY on its own
// initiative, and the assertion is about what actually arrives there — which
// cannot be observed at all without owning that end.
func startCollector() (*http.Server, string, func() []string) {
	var mu sync.Mutex
	var seen []string

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("starting the telemetry collector: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var sb strings.Builder
		for k, vs := range r.Header {
			fmt.Fprintf(&sb, "%s: %s\n", k, strings.Join(vs, ","))
		}
		sb.Write(body)
		mu.Lock()
		seen = append(seen, sb.String())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})}
	go func() { _ = srv.Serve(ln) }()

	return srv, "http://" + ln.Addr().String() + "/telemetry", func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// assertPlatformRecordedTheUnscopedRead checks the platform's own account of
// step 4. An unscoped read that leaves no trace is one nobody can audit after
// the fact, so "it failed closed" is only half the property.
func assertPlatformRecordedTheUnscopedRead() {
	container := getenv("AXONFLOW_ORCH_CONTAINER", "axonflow-orchestrator")
	out, err := exec.Command("docker", "logs", "--tail", "500", container).CombinedOutput()
	if err != nil {
		// Loudly inconclusive, never a silent pass.
		fail("step 9: could not read %s's logs to confirm the platform recorded the unscoped read "+
			"(%v). Set AXONFLOW_ORCH_CONTAINER, or run this driver where the stack's logs are reachable — "+
			"an unverified observability claim is not evidence", container, err)
	}
	if !strings.Contains(string(out), "[read-scope]") {
		fail("step 9: the orchestrator logged no [read-scope] line for the unscoped read in step 4. " +
			"The read failed closed but left no platform-side record of having done so")
	}
	fmt.Println("step 9 PASS: the orchestrator recorded the unscoped read ([read-scope] diagnostic present)")
}

// clearHeartbeatStamp removes the 7-day telemetry stamp so this process's
// first client actually sends a ping. Mirrors heartbeat.go resolveStampPath.
func clearHeartbeatStamp() {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	_ = os.Remove(filepath.Join(cacheDir, "axonflow", "go-telemetry-last-sent"))
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fail("%s must be set (source /tmp/axonflow-e2e-env.sh after ./scripts/setup-e2e-testing.sh enterprise)", k)
	}
	return v
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
