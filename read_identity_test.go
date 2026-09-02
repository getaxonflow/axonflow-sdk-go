package axonflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The token used throughout. Distinctive on purpose: the leak tests grep whole
// captured streams for it, and a value like "tok" would match by accident.
const testUserToken = "eyJhbGciOiJIUzI1NiJ9.SENTINEL-USER-TOKEN-a7f3c91e.sig"

// captureHeaders stands up a server that records the headers of every request
// it receives and answers with body/status/extra response headers.
func captureHeaders(t *testing.T, status int, body string, respHeaders map[string]string) (*httptest.Server, *[]http.Header) {
	t.Helper()
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Clone())
		for k, v := range respHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func clientFor(srv *httptest.Server, cfg AxonFlowConfig) *AxonFlowClient {
	cfg.Endpoint = srv.URL
	return NewClient(cfg)
}

// ============================================================================
// Option plumbing: present when configured, absent when not, exactly once
// ============================================================================

func TestReadIdentity_HeaderAbsentWhenNotConfigured(t *testing.T) {
	srv, seen := captureHeaders(t, http.StatusOK, `{"decisions":[{"decision_id":"d1"}]}`, nil)
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

	if _, err := c.ListDecisions(context.Background(), ListDecisionsOptions{}); err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("requests = %d, want 1", len(*seen))
	}
	if _, ok := (*seen)[0][http.CanonicalHeaderKey(headerUserToken)]; ok {
		t.Fatalf("%s was sent by a client that has no identity configured; "+
			"an unconfigured client must send no identity header at all, not an empty one", headerUserToken)
	}
}

func TestReadIdentity_ClientLevelTokenTravelsOnEveryRead(t *testing.T) {
	// Both read methods, one client-level identity, and the header asserted
	// once per request — a per-method sprinkle would show up here as a
	// duplicate or as a method that silently omits it.
	for _, tc := range []struct {
		name string
		body string
		call func(*AxonFlowClient) error
	}{
		{"explain", `{"decision_id":"d1"}`, func(c *AxonFlowClient) error {
			_, err := c.ExplainDecision(context.Background(), "d1")
			return err
		}},
		{"list", `{"decisions":[{"decision_id":"d1"}]}`, func(c *AxonFlowClient) error {
			_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, seen := captureHeaders(t, http.StatusOK, tc.body, nil)
			c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: testUserToken})

			if err := tc.call(c); err != nil {
				t.Fatalf("call: %v", err)
			}
			values := (*seen)[0].Values(headerUserToken)
			if len(values) != 1 {
				t.Fatalf("%s appeared %d times, want exactly 1 (values=%q)", headerUserToken, len(values), values)
			}
			if values[0] != testUserToken {
				t.Fatalf("%s = %q, want the configured token", headerUserToken, values[0])
			}
		})
	}
}

func TestReadIdentity_PerCallOverridesClientLevel(t *testing.T) {
	srv, seen := captureHeaders(t, http.StatusOK, `{"decision_id":"d1"}`, nil)
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: "client-level-token"})

	if _, err := c.ExplainDecision(context.Background(), "d1", WithUserToken(testUserToken)); err != nil {
		t.Fatalf("ExplainDecision: %v", err)
	}
	if got := (*seen)[0].Get(headerUserToken); got != testUserToken {
		t.Fatalf("%s = %q, want the per-call token to win over the client-level one", headerUserToken, got)
	}
}

func TestReadIdentity_PerCallEmptyTokenClearsClientLevel(t *testing.T) {
	// WithUserToken("") is a caller deliberately making one read
	// unidentified. It must NOT fall back to the client-level identity —
	// falling back would make the option silently unable to express the very
	// state the platform treats as distinct (ReadScopeNone).
	srv, seen := captureHeaders(t, http.StatusOK, `{"decisions":[]}`,
		map[string]string{headerReadScope: string(ReadScopeOwnRows)})
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: testUserToken})

	if _, err := c.ListDecisions(context.Background(), ListDecisionsOptions{}, WithUserToken("   ")); err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if _, ok := (*seen)[0][http.CanonicalHeaderKey(headerUserToken)]; ok {
		t.Fatalf("%s was sent even though the call passed an explicitly empty identity", headerUserToken)
	}
}

func TestReadIdentity_PerCallDoesNotLeakIntoTheNextCall(t *testing.T) {
	srv, seen := captureHeaders(t, http.StatusOK, `{"decision_id":"d1"}`, nil)
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

	if _, err := c.ExplainDecision(context.Background(), "d1", WithUserToken(testUserToken)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := c.ExplainDecision(context.Background(), "d1"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := (*seen)[1].Get(headerUserToken); got != "" {
		t.Fatalf("the second call carried %s = %q; a per-call identity must not become client state", headerUserToken, got)
	}
}

func TestReadIdentity_TokenIsTrimmed(t *testing.T) {
	srv, seen := captureHeaders(t, http.StatusOK, `{"decision_id":"d1"}`, nil)
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: "  " + testUserToken + "\n"})

	if _, err := c.ExplainDecision(context.Background(), "d1"); err != nil {
		t.Fatalf("ExplainDecision: %v", err)
	}
	if got := (*seen)[0].Get(headerUserToken); got != testUserToken {
		t.Fatalf("%s = %q, want the trimmed token — a trailing newline in a header value is a protocol error", headerUserToken, got)
	}
}

// TestReadIdentity_OneTransportSite is the structural half of "do not build a
// second identity plumbing": it counts, in non-test source, the places that
// name the header. Exactly one may SET it.
func TestReadIdentity_OneTransportSite(t *testing.T) {
	// Deliberately wider than the one spelling the fix uses. A guard is only
	// as wide as the syntax it matches, and there are several ways to write a
	// header into a request: Header.Set/Add, direct map assignment, and the
	// textproto helpers. All of them are counted, plus any use of the constant
	// as an assignment target, so a second identity site cannot be introduced
	// by choosing different syntax.
	setter := regexp.MustCompile(
		`Header\.(Set|Add)\(\s*(headerUserToken|"[Xx]-[Uu]ser-[Tt]oken")` +
			`|Header\[\s*(headerUserToken|"[Xx]-[Uu]ser-[Tt]oken")` +
			`|Header\)\.Set\(\s*(headerUserToken|"[Xx]-[Uu]ser-[Tt]oken")` +
			`|textproto\.MIMEHeader\{`)
	literal := regexp.MustCompile(`(?i)"x-user-token"`)

	var setters, literals []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// runtime-e2e drives the platform over raw HTTP by design; it is
			// not the SDK's transport.
			if d.Name() == "runtime-e2e" || d.Name() == "testdata" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(src), "\n") {
			if setter.MatchString(line) {
				setters = append(setters, fmt.Sprintf("%s:%d", path, i+1))
			}
			if literal.MatchString(line) {
				literals = append(literals, fmt.Sprintf("%s:%d", path, i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the source tree: %v", err)
	}

	if len(setters) != 1 {
		t.Errorf("%s is set at %d sites (%v); it must be set at exactly one — "+
			"the platform reads it once in its proxy middleware, not per route, so a per-method "+
			"sprinkle here is a second copy of a decision that is made in one place on both sides",
			headerUserToken, len(setters), setters)
	}
	if len(literals) != 1 {
		t.Errorf("the literal %q appears at %d sites (%v); it must be spelled once, in the "+
			"headerUserToken constant, so a rename cannot leave a stale spelling behind",
			"X-User-Token", len(literals), literals)
	}
}

// ============================================================================
// The token is a credential: never logged, never in an error, never in telemetry
// ============================================================================

// TestReadIdentity_TokenNeverLeaves asserts the token reaches the header and
// NOTHING else: not the debug log, not an error string, not the telemetry
// heartbeat's request.
func TestReadIdentity_TokenNeverLeaves(t *testing.T) {
	// Debug mode is the loudest the SDK gets; if the token survives anywhere
	// in the log stream it survives everywhere quieter.
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })

	// A 404 whose BODY echoes the token back: the strongest form of the
	// mistake, since the natural implementation puts the response body into
	// the error message verbatim.
	body := fmt.Sprintf(`{"error":"not found","echo":%q}`, testUserToken)
	srv, seen := captureHeaders(t, http.StatusNotFound, body,
		map[string]string{headerReadScope: string(ReadScopeOwnRows)})
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: testUserToken, Debug: true})

	_, err := c.ExplainDecision(context.Background(), "d1")
	if err == nil {
		t.Fatal("expected an error from a 404")
	}

	// The header did carry it — otherwise the rest of this test is vacuous.
	if got := (*seen)[0].Get(headerUserToken); got != testUserToken {
		t.Fatalf("precondition: %s = %q, want the token (the leak assertions below would be vacuous)", headerUserToken, got)
	}

	if strings.Contains(err.Error(), testUserToken) {
		t.Errorf("the error message carries the user token: %q", err.Error())
	}
	if strings.Contains(logs.String(), testUserToken) {
		t.Errorf("the debug log carries the user token:\n%s", logs.String())
	}
}

// TestReadIdentity_TelemetryCarriesNoIdentity drives the REAL telemetry ping —
// both requests it makes: the /health probe against the caller's own endpoint
// and the POST to the checkpoint host — and asserts neither carries the
// per-user identity.
//
// The checkpoint is a third party. A credential belonging to one of our
// customers' employees must not reach it, and "the code path happens not to
// call addAuthHeaders today" is a property one refactor can remove silently.
func TestReadIdentity_TelemetryCarriesNoIdentity(t *testing.T) {
	collector, seen := captureHeaders(t, http.StatusOK, `{"version":"10.4.0","license_tier":"enterprise"}`, nil)
	t.Setenv("AXONFLOW_CHECKPOINT_URL", collector.URL)
	t.Setenv("AXONFLOW_TELEMETRY", "on")

	c := NewClient(AxonFlowConfig{
		Endpoint:     collector.URL, // so the /health probe lands here too
		ClientID:     "org",
		ClientSecret: "s",
		UserToken:    testUserToken,
	})
	if err := c.sendTelemetryPingNow(context.Background()); err != nil {
		t.Fatalf("sendTelemetryPingNow: %v", err)
	}

	if len(*seen) < 2 {
		t.Fatalf("captured %d telemetry-path requests, want at least 2 (the /health probe and the "+
			"checkpoint POST); with fewer, the assertions below are vacuous", len(*seen))
	}
	for i, h := range *seen {
		if got := h.Get(headerUserToken); got != "" {
			t.Errorf("telemetry-path request %d carried %s = %q; the per-user identity must never "+
				"reach the telemetry endpoint", i, headerUserToken, got)
		}
		for key, values := range h {
			for _, v := range values {
				if strings.Contains(v, testUserToken) {
					t.Errorf("telemetry-path request %d leaked the user token in header %s", i, key)
				}
			}
		}
	}
}

// ============================================================================
// The three read outcomes
// ============================================================================

func TestExplainDecision_ScopeSurfacing(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		scopeHeader   string // "" = header absent
		wantTyped     bool
		wantMissingID bool
	}{
		{"no identity presented", http.StatusNotFound, "none", true, true},
		{"not this identity's row", http.StatusNotFound, "own-rows", true, false},
		{"tenant-wide caller: a real miss", http.StatusNotFound, "tenant", false, false},
		{"pre-#2922 platform states no scope", http.StatusNotFound, "", false, false},
		{"a scope this build does not know", http.StatusNotFound, "segment-rows", false, false},
		{"a server fault under a scoped read", http.StatusInternalServerError, "none", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.scopeHeader != "" {
				headers[headerReadScope] = tc.scopeHeader
			}
			// The platform sends this same body for "not attributed to you"
			// and for "genuinely gone" — which is the point. The assertions
			// below are about the SCOPE the read ran under, never about which
			// of those two it was; claiming to know would be inventing a fact
			// the platform deliberately withholds.
			srv, _ := captureHeaders(t, tc.status, `{"error":"Decision not found or past retention window"}`, headers)
			c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

			_, err := c.ExplainDecision(context.Background(), "dec-1")
			if err == nil {
				t.Fatal("expected an error")
			}
			rse, ok := AsReadScopeError(err)
			if ok != tc.wantTyped {
				t.Fatalf("AsReadScopeError = %v, want %v (err=%v)", ok, tc.wantTyped, err)
			}
			if !tc.wantTyped {
				return
			}
			if rse.IdentityMissing() != tc.wantMissingID {
				t.Errorf("IdentityMissing() = %v, want %v", rse.IdentityMissing(), tc.wantMissingID)
			}
			if rse.ID != "dec-1" || rse.Resource != "decision" {
				t.Errorf("subject = %s %q, want decision \"dec-1\"", rse.Resource, rse.ID)
			}
			if rse.Scope != ReadScope(tc.scopeHeader) {
				t.Errorf("Scope = %q, want %q", rse.Scope, tc.scopeHeader)
			}
			// errors.As must find it through any future wrapping.
			var viaAs *ReadScopeError
			if !errors.As(err, &viaAs) {
				t.Error("errors.As did not find the *ReadScopeError")
			}
		})
	}
}

func TestListDecisions_EmptyUnderScopeNoneIsRefused(t *testing.T) {
	srv, _ := captureHeaders(t, http.StatusOK, `{"decisions":[]}`,
		map[string]string{headerReadScope: "none"})
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

	got, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
	if err == nil {
		t.Fatalf("an empty page under %s: none was returned as %d rows and no error — "+
			"that page could not have contained a row, so reporting it as data is the vacuous "+
			"read this fix exists to remove", headerReadScope, len(got))
	}
	rse, ok := AsReadScopeError(err)
	if !ok {
		t.Fatalf("err = %T (%v), want *ReadScopeError", err, err)
	}
	if !rse.IdentityMissing() {
		t.Error("IdentityMissing() = false, want true")
	}
	if rse.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200 — the platform answered successfully; it is the SCOPE that makes the page meaningless", rse.StatusCode)
	}
}

func TestListDecisions_LegitimateEmptyIsNotAnError(t *testing.T) {
	// The two ways a read can honestly return nothing. Refusing either would
	// replace one wrong report with another.
	for _, scope := range []string{"own-rows", "tenant", "", "segment-rows"} {
		t.Run("scope="+scope, func(t *testing.T) {
			headers := map[string]string{}
			if scope != "" {
				headers[headerReadScope] = scope
			}
			srv, _ := captureHeaders(t, http.StatusOK, `{"decisions":[]}`, headers)
			c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

			got, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
			if err != nil {
				t.Fatalf("an honestly-empty read under scope %q was refused: %v", scope, err)
			}
			if len(got) != 0 {
				t.Fatalf("rows = %d, want 0", len(got))
			}
		})
	}
}

func TestListDecisions_NonEmptyIsNeverRefused(t *testing.T) {
	// Belt and braces: even if a platform contradicts itself and stamps
	// "none" over a populated page, rows that arrived are never discarded.
	srv, _ := captureHeaders(t, http.StatusOK, `{"decisions":[{"decision_id":"d1"}]}`,
		map[string]string{headerReadScope: "none"})
	c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

	got, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
	if err != nil {
		t.Fatalf("a populated page was refused on the strength of a header: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows = %d, want 1", len(got))
	}
}

func TestReadScopeError_MessageNamesTheRemedyAndNotTheCredential(t *testing.T) {
	missing := &ReadScopeError{Resource: "decision", ID: "d1", Scope: ReadScopeNone, StatusCode: 404}
	if !strings.Contains(missing.Error(), "UserToken") {
		t.Errorf("the no-identity message does not name the remedy: %q", missing.Error())
	}
	notYours := &ReadScopeError{Resource: "decision", ID: "d1", Scope: ReadScopeOwnRows, StatusCode: 404}
	if strings.Contains(notYours.Error(), "resolved no per-user identity") {
		t.Errorf("the own-rows message diagnoses a missing identity, which is a different cause: %q", notYours.Error())
	}
	if notYours.IdentityMissing() {
		t.Error("own-rows must not report IdentityMissing")
	}
	// It must NOT assert that the row exists and belongs to someone else. The
	// platform answers "not yours" and "not there" identically, on purpose, so
	// a message claiming the first is a fact this SDK cannot have.
	if strings.Contains(notYours.Error(), "is not visible to the identity") {
		t.Errorf("the own-rows message asserts the row exists and is someone else's; the platform "+
			"does not distinguish that from a row that is simply gone: %q", notYours.Error())
	}
	if !strings.Contains(notYours.Error(), "not there at all") {
		t.Errorf("the own-rows message does not admit the row may simply not exist: %q", notYours.Error())
	}
}

// ============================================================================
// go#205 — a required primitive that went missing must be REFUSED, not defaulted
// ============================================================================

func TestAuthZENDecode_RefusesAbsentRequiredPrimitive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		target  func() any
		member  string
	}{
		{
			// The issue's case: `mandatory` decides whether an unsupported
			// obligation must DENY. Absent must never read as advisory.
			name:    "obligation without mandatory",
			payload: `{"type":"redact","source_policy":"p1","schema_version":1}`,
			target:  func() any { return new(AuthZENObligation) },
			member:  "mandatory",
		},
		{
			name:    "obligation with mandatory null",
			payload: `{"type":"redact","mandatory":null,"source_policy":"p1","schema_version":1}`,
			target:  func() any { return new(AuthZENObligation) },
			member:  "mandatory",
		},
		{
			name:    "obligation without schema_version",
			payload: `{"type":"redact","mandatory":true,"source_policy":"p1"}`,
			target:  func() any { return new(AuthZENObligation) },
			member:  "schema_version",
		},
		{
			// Not named in the issue, found by sweeping the class: an
			// approval clause without a quorum reads as needing nobody.
			name:    "approval clause without quorum",
			payload: `{"eligible":[{"kind":"group","type":"g","local":"risk"}]}`,
			target:  func() any { return new(AuthZENApprovalClause) },
			member:  "quorum",
		},
		{
			// Also not named in the issue: absent separation_of_duties reads
			// as "self-approval is fine".
			name:    "approval requirement without separation_of_duties",
			payload: `{"all_of":[],"expires_at":"2026-01-01T00:00:00Z"}`,
			target:  func() any { return new(AuthZENApprovalRequirement) },
			member:  "separation_of_duties",
		},
		{
			name:    "response without decision",
			payload: `{"context":{}}`,
			target:  func() any { return new(AuthZENResponse) },
			member:  "decision",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := json.Unmarshal([]byte(tc.payload), tc.target())
			if err == nil {
				t.Fatalf("decoding %s succeeded; an absent required primitive decodes to its zero "+
					"value, which is a legitimate value of the type, so nothing downstream can tell "+
					"it apart from one the server sent", tc.payload)
			}
			if !strings.Contains(err.Error(), tc.member) {
				t.Errorf("the refusal does not name the member %q: %v", tc.member, err)
			}
		})
	}
}

func TestAuthZENDecode_AcceptsTheZeroValueWhenIT_WAS_Sent(t *testing.T) {
	// The other failure direction. A recogniser that refuses absence must not
	// also refuse a legitimately-false member, or every advisory obligation
	// the platform sends becomes undecodable.
	var o AuthZENObligation
	if err := json.Unmarshal([]byte(`{"type":"redact","mandatory":false,"source_policy":"p1","schema_version":0}`), &o); err != nil {
		t.Fatalf("a sent-and-false mandatory was refused: %v", err)
	}
	if o.Mandatory {
		t.Error("Mandatory decoded as true from a false payload")
	}
	if o.SourcePolicy != "p1" {
		t.Errorf("SourcePolicy = %q, want p1 — the second decode pass must still populate every field", o.SourcePolicy)
	}
}

func TestAuthZENDecode_NestedObligationIsRefusedThroughItsParent(t *testing.T) {
	// The obligation that matters arrives inside a response context, not on
	// its own. A presence check the parent decode routes around is no check.
	payload := `{"profile":"p","state":"allow","category":"c","decision_id":"d",` +
		`"schema_version":"2026-08-29","obligations":[{"type":"redact","source_policy":"p1","schema_version":1}]}`
	var ctxOut AuthZENResponseContext
	if err := json.Unmarshal([]byte(payload), &ctxOut); err == nil {
		t.Fatal("a response context carrying an obligation with no `mandatory` decoded cleanly; " +
			"the refusal must survive being nested one level down")
	}
}

// TestAuthZENDecode_DiffersFromAPlainDecode is a DIFFERENTIAL test, not a
// mutation gate: it reconstructs the pre-fix behaviour (a plain decode with no
// presence check) beside the shipped one and asserts the two disagree on
// exactly the payload that matters. It cannot fail if the presence check is
// removed from the generator — TestAuthZENGenerator_CoversEveryRequiredPrimitive
// is what does that — so it is named for what it asserts.
func TestAuthZENDecode_DiffersFromAPlainDecode(t *testing.T) {
	type plain AuthZENObligation
	var mutant plain
	if err := json.Unmarshal([]byte(`{"type":"redact","source_policy":"p1","schema_version":1}`), &mutant); err != nil {
		t.Fatalf("the mutant should decode — that is the defect: %v", err)
	}
	if mutant.Mandatory {
		t.Fatal("the mutant decoded Mandatory as true; the fixture is wrong")
	}
	// The mutant is silently WRONG in exactly the direction that matters: an
	// obligation the server marked mandatory-or-not now reads as advisory.
	// The real type refuses it, which is what makes the gate meaningful.
	var real AuthZENObligation
	if err := json.Unmarshal([]byte(`{"type":"redact","source_policy":"p1","schema_version":1}`), &real); err == nil {
		t.Fatal("the shipped type accepted what the mutant accepted; the presence check is not wired in")
	}
}

// presenceCheckedMembersInGeneratedFile parses authzen_types_gen.go and
// returns, per type, the members named in the []string{...} literal its
// UnmarshalJSON iterates.
//
// It reads the AST rather than grepping for the member name, because the
// member name is ALREADY in the file — in the struct tag `json:"mandatory"` —
// so a substring test is satisfied by the field's mere existence and reports
// green against a file with no presence check in it at all. That is the
// anti-vacuity floor built from its own subject: derived from the artifact,
// and still unable to see the thing it was written to protect.
func presenceCheckedMembersInGeneratedFile(t *testing.T) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "authzen_types_gen.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing the generated file: %v", err)
	}

	out := map[string]map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "UnmarshalJSON" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		ident, ok := star.X.(*ast.Ident)
		if !ok {
			continue
		}
		members := map[string]bool{}
		ast.Inspect(fn, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			arr, ok := lit.Type.(*ast.ArrayType)
			if !ok {
				return true
			}
			if elt, ok := arr.Elt.(*ast.Ident); !ok || elt.Name != "string" {
				return true
			}
			for _, e := range lit.Elts {
				if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if unquoted, uerr := strconv.Unquote(bl.Value); uerr == nil {
						members[unquoted] = true
					}
				}
			}
			return true
		})
		out[ident.Name] = members
	}
	return out
}

// TestAuthZENGenerator_CoversEveryRequiredPrimitive is the census: it derives
// the expected set from the ARTIFACT and checks it against the presence list
// the generator actually EMITTED, so a required primitive added to the surface
// later cannot ship unchecked.
func TestAuthZENGenerator_CoversEveryRequiredPrimitive(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "authzen-surface.json"))
	if err != nil {
		t.Fatalf("reading the surface artifact: %v", err)
	}
	var surface struct {
		Types []struct {
			Name   string `json:"name"`
			Fields []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
				Type     struct {
					Kind string `json:"kind"`
				} `json:"type"`
			} `json:"fields"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &surface); err != nil {
		t.Fatalf("parsing the surface artifact: %v", err)
	}

	emitted := presenceCheckedMembersInGeneratedFile(t)

	// The generator's own boundary, restated from the artifact side: a
	// required member whose zero value is a value the wire may legitimately
	// carry cannot be checked after the decode, so it must be checked during.
	zeroIsLegal := map[string]bool{"bool": true, "int": true, "number": true}
	checked := 0
	for _, ty := range surface.Types {
		goName := goTypeNameForTest(ty.Name)
		for _, f := range ty.Fields {
			if !f.Required || !zeroIsLegal[f.Type.Kind] {
				continue
			}
			checked++
			if !emitted[goName][f.Name] {
				t.Errorf("%s.%s is a required %s — its zero value is a legal wire value — but "+
					"%s.UnmarshalJSON does not presence-check it (emitted: %v). An absent one "+
					"would decode to its zero value and nothing downstream could tell it from a "+
					"value the server sent.", ty.Name, f.Name, f.Type.Kind, goName, emitted[goName])
			}
		}
	}
	if checked == 0 {
		t.Fatal("the artifact declares no required primitive at all; this census asserted nothing")
	}

	// The mirror direction: nothing may be presence-checked that the artifact
	// does not declare as a required primitive, or the generator has invented
	// a rule the contract does not have.
	declared := map[string]map[string]bool{}
	for _, ty := range surface.Types {
		goName := goTypeNameForTest(ty.Name)
		declared[goName] = map[string]bool{}
		for _, f := range ty.Fields {
			if f.Required && zeroIsLegal[f.Type.Kind] {
				declared[goName][f.Name] = true
			}
		}
	}
	for goName, members := range emitted {
		for member := range members {
			if !declared[goName][member] {
				t.Errorf("%s.UnmarshalJSON presence-checks %q, which the artifact does not "+
					"declare as a required primitive of that type", goName, member)
			}
		}
	}
	t.Logf("required primitives covered: %d across %d types", checked, len(emitted))
}

// goTypeNameForTest mirrors the generator's artifact-name -> Go-name mapping.
// Duplicated here rather than imported because the generator is package main
// in a subdirectory; the census below pins that the two agree.
func goTypeNameForTest(artifactName string) string {
	parts := strings.Split(artifactName, "_")
	var b strings.Builder
	if !strings.HasPrefix(artifactName, "authzen") {
		b.WriteString("AuthZEN")
	}
	for _, part := range parts {
		if part == "authzen" {
			b.WriteString("AuthZEN")
			continue
		}
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// TestGoTypeNameForTestAgreesWithTheGeneratedFile keeps the mapping above
// honest: every name it produces for an artifact type must be a type that
// actually exists in the generated file. Without this the census could silently
// look up the wrong key and find nothing to complain about.
func TestGoTypeNameForTestAgreesWithTheGeneratedFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "authzen-surface.json"))
	if err != nil {
		t.Fatalf("reading the surface artifact: %v", err)
	}
	var surface struct {
		Types []struct {
			Name string `json:"name"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &surface); err != nil {
		t.Fatalf("parsing the surface artifact: %v", err)
	}
	gen, err := os.ReadFile("authzen_types_gen.go")
	if err != nil {
		t.Fatalf("reading the generated file: %v", err)
	}
	for _, ty := range surface.Types {
		want := "type " + goTypeNameForTest(ty.Name) + " struct"
		if !strings.Contains(string(gen), want) {
			t.Errorf("the artifact type %q maps to %q, which the generated file does not declare; "+
				"the census would look up a key that never matches and pass vacuously",
				ty.Name, goTypeNameForTest(ty.Name))
		}
	}
}

// TestReadIdentity_DefensiveBranches covers the paths that exist so a caller
// cannot make the SDK panic on their behalf: a nil response, a nil context, a
// nil option in the variadic list, a nil request.
func TestReadIdentity_DefensiveBranches(t *testing.T) {
	if got := readScopeOf(nil); got != ReadScopeAbsent {
		t.Errorf("readScopeOf(nil) = %q, want absent", got)
	}
	//nolint:staticcheck // a nil ctx is exactly what this branch defends against
	ctx := applyReadOptions(nil, nil, WithUserToken(testUserToken))
	c := &AxonFlowClient{config: AxonFlowConfig{}}
	if got := c.effectiveUserToken(ctx); got != testUserToken {
		t.Errorf("effectiveUserToken through a nil ctx + nil option = %q, want the token", got)
	}
	c.applyReadIdentity(nil) // must not panic
}

// TestReadIdentity_NotForwardedAcrossACrossHostRedirect is the redirect half of
// "the token goes to the header and nowhere else".
//
// net/http strips Authorization on a host change and X-User-Token is not on
// its fixed sensitive-header list, so without a CheckRedirect policy the SDK
// forwards the PER-USER credential to a host the caller never named on exactly
// the hop where the TENANT credential is dropped.
func TestReadIdentity_NotForwardedAcrossACrossHostRedirect(t *testing.T) {
	var elsewhereSaw http.Header
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereSaw = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decisions":[]}`))
	}))
	t.Cleanup(elsewhere.Close)

	// Same server, addressed by a different host name, so this is a genuine
	// cross-origin hop rather than a same-host path change.
	crossHost := strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)
	if crossHost == elsewhere.URL {
		t.Skip("the test server is not addressable under a second host name")
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossHost+"/api/v1/decisions", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	c := NewClient(AxonFlowConfig{
		Endpoint:     origin.URL,
		ClientID:     "org",
		ClientSecret: "s",
		UserToken:    testUserToken,
	})
	_, _ = c.ListDecisions(context.Background(), ListDecisionsOptions{})

	if elsewhereSaw == nil {
		t.Fatal("the redirect was not followed, so this test asserted nothing about what a " +
			"followed redirect carries")
	}
	// Precondition: net/http did strip the tenant credential here. If it did
	// not, this is not the cross-origin hop the test believes it is.
	if got := elsewhereSaw.Get("Authorization"); got != "" {
		t.Fatalf("net/http forwarded Authorization to the redirect target, so this is not a "+
			"cross-origin hop and the assertion below is vacuous (got %q)", got)
	}
	if got := elsewhereSaw.Get(headerUserToken); got != "" {
		t.Errorf("%s was forwarded to a host the caller never named (%q) on the very hop where "+
			"net/http drops Authorization; a per-user credential must not outlive the origin it "+
			"was configured for", headerUserToken, got)
	}
}

// TestReadIdentity_KeptAcrossASameHostRedirect is the other failure direction:
// a policy that strips too eagerly turns an ordinary same-origin redirect into
// an unscoped read, which now REFUSES — a self-inflicted outage.
func TestReadIdentity_KeptAcrossASameHostRedirect(t *testing.T) {
	var finalSaw http.Header
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		finalSaw = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decisions":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(AxonFlowConfig{
		Endpoint:     srv.URL,
		ClientID:     "org",
		ClientSecret: "s",
		UserToken:    testUserToken,
	})
	_, _ = c.ListDecisions(context.Background(), ListDecisionsOptions{})

	if hops < 2 || finalSaw == nil {
		t.Fatalf("the same-host redirect was not followed (hops=%d); nothing was asserted", hops)
	}
	if got := finalSaw.Get(headerUserToken); got != testUserToken {
		t.Errorf("%s = %q after a SAME-host redirect, want the token — stripping here would make "+
			"an ordinary redirect silently unscope the read", headerUserToken, got)
	}
}

// TestReadIdentity_TravelsOnNonReadMethodsToo pins H2: the header is NOT a
// read-only convenience.
//
// The agent validates X-User-Token in proxyAuthMiddleware, in front of every
// route it proxies, and 401s a present-but-invalid one there. So a client-wide
// UserToken reaches ListConnectors, plan status and policy CRUD, and a stale
// token breaks them. That is the correct direction, but it is a real
// operational consequence and the docstrings must not claim otherwise —
// so it is pinned rather than left as prose.
func TestReadIdentity_TravelsOnNonReadMethodsToo(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		call func(*AxonFlowClient) error
	}{
		{"ListConnectors", `{"connectors":[]}`, func(c *AxonFlowClient) error {
			_, err := c.ListConnectors()
			return err
		}},
		{"SearchAuditLogs", `[]`, func(c *AxonFlowClient) error {
			_, err := c.SearchAuditLogs(context.Background(), &AuditSearchRequest{Limit: 1})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, seen := captureHeaders(t, http.StatusOK, tc.body, nil)
			c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: testUserToken})

			_ = tc.call(c)

			if len(*seen) == 0 {
				t.Fatal("no request was made; this test asserted nothing")
			}
			if got := (*seen)[0].Get(headerUserToken); got != testUserToken {
				t.Errorf("%s carried %s = %q, want the token. The agent validates this header on "+
					"every proxied route, so a method that omits it and a method that sends a stale "+
					"one behave differently for reasons the caller cannot see",
					tc.name, headerUserToken, got)
			}
		})
	}
}

// TestAuditReads_EmptyUnderScopeNoneAreRefused closes M1: the audit reads are
// in the same role-scoped family and used to answer the same vacuous empty
// page, while the config docstring promised a refusal.
func TestAuditReads_EmptyUnderScopeNoneAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string // both shapes the platform sends
		call func(*AxonFlowClient) error
	}{
		{"search, array shape", `[]`, func(c *AxonFlowClient) error {
			_, err := c.SearchAuditLogs(context.Background(), &AuditSearchRequest{Limit: 10})
			return err
		}},
		{"search, wrapped shape", `{"entries":[],"total":0}`, func(c *AxonFlowClient) error {
			_, err := c.SearchAuditLogs(context.Background(), &AuditSearchRequest{Limit: 10})
			return err
		}},
		{"tenant, array shape", `[]`, func(c *AxonFlowClient) error {
			_, err := c.GetAuditLogsByTenant(context.Background(), "t1", nil)
			return err
		}},
		{"tenant, wrapped shape", `{"entries":[],"total":0}`, func(c *AxonFlowClient) error {
			_, err := c.GetAuditLogsByTenant(context.Background(), "t1", nil)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := captureHeaders(t, http.StatusOK, tc.body,
				map[string]string{headerReadScope: "none"})
			c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

			err := tc.call(c)
			rse, ok := AsReadScopeError(err)
			if !ok {
				t.Fatalf("err = %T (%v), want *ReadScopeError — an empty audit page under scope "+
					"none could not have held a row, and BOTH decode shapes must refuse it or the "+
					"rule holds on whichever branch the server happened to take", err, err)
			}
			if !rse.IdentityMissing() {
				t.Error("IdentityMissing() = false, want true")
			}
		})
	}
}

func TestAuditReads_LegitimateEmptyAndPopulatedPagesAreNotRefused(t *testing.T) {
	// The two directions a refusal must NOT fire in.
	t.Run("empty under own-rows", func(t *testing.T) {
		srv, _ := captureHeaders(t, http.StatusOK, `[]`,
			map[string]string{headerReadScope: "own-rows"})
		c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})
		if _, err := c.SearchAuditLogs(context.Background(), &AuditSearchRequest{Limit: 10}); err != nil {
			t.Fatalf("an honestly-empty own-rows audit read was refused: %v", err)
		}
	})
	t.Run("populated under a contradictory none", func(t *testing.T) {
		srv, _ := captureHeaders(t, http.StatusOK, `[{"id":"a1"}]`,
			map[string]string{headerReadScope: "none"})
		c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})
		got, err := c.SearchAuditLogs(context.Background(), &AuditSearchRequest{Limit: 10})
		if err != nil {
			t.Fatalf("a populated page was discarded on the strength of a header: %v", err)
		}
		if len(got.Entries) != 1 {
			t.Fatalf("entries = %d, want 1", len(got.Entries))
		}
	})
}

// TestAsUser_ReachesEveryMethod is the answer to the split-identity trap: a
// context-carried identity is only seen by the methods that thread a context
// into their request, and falls back to the client's — BROADER — identity on
// the rest. AsUser has no such carve-out.
func TestAsUser_ReachesEveryMethod(t *testing.T) {
	const alice = "ALICE-TOKEN"
	srv, seen := captureHeaders(t, http.StatusOK, `{"connectors":[]}`, nil)
	admin := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s", UserToken: "ADMIN-TOKEN"})

	// ListConnectors builds its request with no context, so a ctx-carried
	// identity cannot reach it — the exact widening AsUser removes.
	ctx := ContextWithUserToken(context.Background(), alice)
	_ = ctx // planted, and deliberately unreachable by this method
	if _, err := admin.ListConnectors(); err != nil {
		t.Fatalf("ListConnectors: %v", err)
	}
	if got := (*seen)[0].Get(headerUserToken); got != "ADMIN-TOKEN" {
		t.Fatalf("precondition: a non-context method should carry the client identity, got %q", got)
	}

	if _, err := admin.AsUser(alice).ListConnectors(); err != nil {
		t.Fatalf("AsUser(...).ListConnectors: %v", err)
	}
	if got := (*seen)[1].Get(headerUserToken); got != alice {
		t.Errorf("AsUser did not reach a non-context method: %s = %q, want %q", headerUserToken, got, alice)
	}

	// The derived client must not mutate the one it came from.
	if admin.config.UserToken != "ADMIN-TOKEN" {
		t.Errorf("AsUser mutated the receiver: UserToken = %q", admin.config.UserToken)
	}
	// ...and it shares the transport rather than building a new pool.
	if admin.AsUser(alice).httpClient != admin.httpClient {
		t.Error("AsUser built a new HTTP client; it is documented as a view, and deriving one " +
			"per request would leak connection pools")
	}
}

func TestReadScope_IsMatchedCaseInsensitively(t *testing.T) {
	// The platform emits these from shared constants today, so a differently
	// cased value is latent rather than live — but a scope of "None" silently
	// degrading to "no opinion" would restore the vacuous empty list, which is
	// too quiet a failure to leave to a constant staying put.
	for _, spelling := range []string{"none", "None", "NONE", " none "} {
		t.Run(spelling, func(t *testing.T) {
			srv, _ := captureHeaders(t, http.StatusOK, `{"decisions":[]}`,
				map[string]string{headerReadScope: spelling})
			c := clientFor(srv, AxonFlowConfig{ClientID: "org", ClientSecret: "s"})

			_, err := c.ListDecisions(context.Background(), ListDecisionsOptions{})
			if _, ok := AsReadScopeError(err); !ok {
				t.Errorf("a scope header spelled %q was not recognised as `none`; the vacuous "+
					"empty page came back as data (err=%v)", spelling, err)
			}
		})
	}
}

func TestAuthZENDecode_NullObjectSaysSo(t *testing.T) {
	// A whole-object null decodes the member map to NIL, so every required
	// member would otherwise be reported as "absent" — a diagnostic naming a
	// cause the code never observed.
	err := json.Unmarshal([]byte(`null`), new(AuthZENObligation))
	if err == nil {
		t.Fatal("a null obligation decoded cleanly")
	}
	if strings.Contains(err.Error(), "is absent") {
		t.Errorf("a null object was diagnosed as a missing member, which is not what happened: %v", err)
	}
	if !strings.Contains(err.Error(), "null") {
		t.Errorf("the refusal does not say what it actually saw: %v", err)
	}
}
