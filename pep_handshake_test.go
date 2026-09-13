package axonflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The PEP capability handshake: the declaration, its bytes, and where it goes.
//
//  1. PARITY. A declaration encodes to exactly the bytes the platform's
//     reference encoder produces for it (pep_handshake_golden_test.go), and a
//     declaration the platform would refuse fails here, naming the same member.
//  2. PLACEMENT. The declaration reaches the wire on every request of every
//     method whose route reads it, and on no other route, even when a caller's
//     context carries one.
//  3. PRECEDENCE. A per-call declaration replaces the client's on that call
//     only; an invalid one fails the call before anything is sent.

func mustPEPHandshake(t *testing.T, pepID, audience string, capabilities []PEPCapability) *PEPHandshake {
	t.Helper()
	h, err := NewPEPHandshake(pepID, audience, capabilities)
	if err != nil {
		t.Fatalf("NewPEPHandshake(%q, %q): %v", pepID, audience, err)
	}
	return h
}

func mustPEPHeader(t *testing.T, h *PEPHandshake) string {
	t.Helper()
	v, err := h.HeaderValue()
	if err != nil {
		t.Fatalf("HeaderValue: %v", err)
	}
	return v
}

func TestPEPHandshakeEncodesToThePlatformsBytes(t *testing.T) {
	for _, g := range goldenPEPHandshakes {
		t.Run(g.name, func(t *testing.T) {
			if got := mustPEPHeader(t, mustPEPHandshake(t, g.pepID, g.audience, g.capabilities)); got != g.header {
				t.Errorf("header\n got %s\nwant %s", got, g.header)
			}
		})
	}
}

func TestSixtyFourPEPCapabilitiesEncodeUnderTheByteCap(t *testing.T) {
	kinds := AllAuthZENObligationTypes()
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	var capabilities []PEPCapability
	for v := 1; v <= 5; v++ {
		for _, k := range kinds {
			capabilities = append(capabilities, PEPCapability{Type: k, Version: v})
		}
	}
	capabilities = capabilities[:MaxPEPHandshakeCapabilities]
	header := mustPEPHeader(t, mustPEPHandshake(t, "p", "a", capabilities))
	sum := sha256.Sum256([]byte(header))
	if len(header) != sixtyFourPEPHandshakeLen || hex.EncodeToString(sum[:]) != sixtyFourPEPHandshakeSHA256 {
		t.Errorf("64-capability header: %d bytes, sha256 %x; want %d bytes, sha256 %s",
			len(header), sum, sixtyFourPEPHandshakeLen, sixtyFourPEPHandshakeSHA256)
	}
}

func TestAPEPHandshakePastTheByteCapIsRefusedAsAWhole(t *testing.T) {
	capabilities := make([]PEPCapability, MaxPEPHandshakeCapabilities)
	for i := range capabilities {
		capabilities[i] = PEPCapability{Type: AuthZENObligationTypeStepUpAuthentication, Version: 1_000_000_000 + i}
	}
	_, err := NewPEPHandshake("p", "a", capabilities)
	var refusal *PEPHandshakeError
	if !errors.As(err, &refusal) || refusal.Pointer != "" {
		t.Fatalf("want a refusal of the whole document (empty pointer), got %v", err)
	}
	if want := PEPHandshakeHeader + ": encodes to "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("message %q does not lead with %q", err.Error(), want)
	}
}

func TestTheOrderOfDeclarationDoesNotChangeThePEPHandshakeBytes(t *testing.T) {
	given := []PEPCapability{{"notification", 3}, {"field_redact", 2}, {"approval_challenge", 1}}
	reversed := []PEPCapability{given[2], given[1], given[0]}
	one := mustPEPHandshake(t, "gw", "a", given)
	other := mustPEPHandshake(t, "gw", "a", reversed)
	if mustPEPHeader(t, one) != mustPEPHeader(t, other) {
		t.Error("the same set in a different order encoded differently")
	}
	want := []PEPCapability{{"approval_challenge", 1}, {"field_redact", 2}, {"notification", 3}}
	for i := range want {
		if one.Capabilities[i] != want[i] {
			t.Fatalf("capabilities %v, want canonical order %v", one.Capabilities, want)
		}
	}
}

func TestThePEPHandshakeHeaderIsUnpaddedBase64URLOfTheCanonicalDocument(t *testing.T) {
	v := mustPEPHeader(t, mustPEPHandshake(t, "gw", "https://pep.example.test",
		[]PEPCapability{{"field_redact", 2}, {"field_redact", 1}}))
	if strings.ContainsAny(v, "=+/") {
		t.Errorf("header %q is not unpadded base64url", v)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := `{"profile_version":1,"pep_id":"gw","audience":"https://pep.example.test",` +
		`"capabilities":[{"type":"field_redact","version":1},{"type":"field_redact","version":2}]}`
	if string(raw) != want {
		t.Errorf("document\n got %s\nwant %s", raw, want)
	}
}

func TestAnEmptyPEPCapabilityListIsADeclaration(t *testing.T) {
	raw, err := base64.RawURLEncoding.DecodeString(mustPEPHeader(t, mustPEPHandshake(t, "gw", "a", []PEPCapability{})))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(doc["capabilities"]) != "[]" {
		t.Errorf("capabilities %s, want []", doc["capabilities"])
	}
}

func TestTheCallersPEPCapabilitySliceIsCopied(t *testing.T) {
	given := []PEPCapability{{"field_redact", 1}}
	h := mustPEPHandshake(t, "gw", "a", given)
	before := mustPEPHeader(t, h)
	given[0] = PEPCapability{"field_mask", 1}
	if h.Capabilities[0] != (PEPCapability{"field_redact", 1}) || mustPEPHeader(t, h) != before {
		t.Errorf("the declaration changed when the caller's slice did: %v", h.Capabilities)
	}
}

func TestThePEPHandshakeRefusalsAreThePlatforms(t *testing.T) {
	sixtyFive := make([]PEPCapability, 65)
	for i := range sixtyFive {
		sixtyFive[i] = PEPCapability{"field_redact", i + 1}
	}
	empty := []PEPCapability{}
	cases := []struct {
		name, pepID, audience string
		capabilities          []PEPCapability
		pointer               string
	}{
		{"pep_id empty", "", "a", empty, "/pep_id"},
		{"pep_id upper case", "Gateway", "a", empty, "/pep_id"},
		{"pep_id colon", "client:gw", "a", empty, "/pep_id"},
		{"pep_id leading dash", "-gw", "a", empty, "/pep_id"},
		{"pep_id trailing newline", "gw\n", "a", empty, "/pep_id"},
		{"pep_id 129 bytes", strings.Repeat("g", 129), "a", empty, "/pep_id"},
		{"audience empty", "gw", "", empty, "/audience"},
		{"audience leading slash", "gw", "/aud", empty, "/audience"},
		{"audience space", "gw", "a b", empty, "/audience"},
		{"audience trailing newline", "gw", "aud\n", empty, "/audience"},
		{"audience 129 bytes", "gw", strings.Repeat("a", 129), empty, "/audience"},
		{"capabilities absent", "gw", "a", nil, "/capabilities"},
		{"capabilities repeated", "gw", "a", []PEPCapability{{"field_redact", 1}, {"field_redact", 1}}, "/capabilities"},
		{"capabilities 65", "gw", "a", sixtyFive, "/capabilities"},
		{"a legacy obligation name", "gw", "a", []PEPCapability{{"redact_pii", 1}}, "/capabilities"},
		{"wrong case", "gw", "a", []PEPCapability{{"Field_Redact", 1}}, "/capabilities"},
		{"no type", "gw", "a", []PEPCapability{{"", 1}}, "/capabilities"},
		{"version zero", "gw", "a", []PEPCapability{{"field_redact", 0}}, "/capabilities"},
		{"version negative", "gw", "a", []PEPCapability{{"field_redact", -1}}, "/capabilities"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPEPHandshake(tc.pepID, tc.audience, tc.capabilities)
			var refusal *PEPHandshakeError
			if !errors.As(err, &refusal) || refusal.Pointer != tc.pointer {
				t.Fatalf("want a refusal at %s, got %v", tc.pointer, err)
			}
			if !strings.HasPrefix(err.Error(), PEPHandshakeHeader+": "+tc.pointer+": ") {
				t.Errorf("message %q does not lead with the header and the member", err.Error())
			}
		})
	}
	t.Run("a hand-built declaration at another profile", func(t *testing.T) {
		_, err := (&PEPHandshake{ProfileVersion: 2, PEPID: "gw", Audience: "a", Capabilities: empty}).HeaderValue()
		var refusal *PEPHandshakeError
		if !errors.As(err, &refusal) || refusal.Pointer != "/profile_version" {
			t.Fatalf("want a refusal at /profile_version, got %v", err)
		}
	})
	t.Run("no declaration", func(t *testing.T) {
		var none *PEPHandshake
		if _, err := none.HeaderValue(); err == nil {
			t.Fatal("a nil declaration encoded")
		}
	})
}

func TestThePEPHandshakeAcceptsWhatThePlatformAccepts(t *testing.T) {
	mustPEPHandshake(t, strings.Repeat("g", 128), strings.Repeat("A", 128), []PEPCapability{})
	mustPEPHandshake(t, "gw.request-1", "https://api.example.com/v1", []PEPCapability{})
	for _, k := range AllAuthZENObligationTypes() {
		mustPEPHandshake(t, "gw", "a", []PEPCapability{{k, 1}})
	}
}

// pepPlaneServer answers every route the tests below call, and records each
// request as "path=<X-Axonflow-PEP-Handshake value>" ("" when absent).
type pepPlaneServer struct {
	mu  sync.Mutex
	got []string
}

func newPEPPlaneServer(t *testing.T) (*httptest.Server, *pepPlaneServer) {
	t.Helper()
	rec := &pepPlaneServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.got = append(rec.got, r.URL.Path+"="+r.Header.Get(PEPHandshakeHeader))
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case decidePath:
			_ = json.NewEncoder(w).Encode(decideAllow(nil))
		case authzenPath:
			_ = json.NewEncoder(w).Encode(AuthZENResponse{
				Decision: true,
				Context: &AuthZENResponseContext{
					Profile: AuthZENProfileV1, State: AuthZENOperationalStateAllow,
					Category: AuthZENCategoryAllowed, DecisionID: "d-1",
					SchemaVersion: AuthZENContractSchemaVersion,
				},
			})
		case "/api/v1/mcp/check-input":
			_, _ = w.Write([]byte(`{"allowed":true,"policies_evaluated":1,"redacted":true,` +
				`"redacted_statement":"email [REDACTED]","redaction_evaluated":true}`))
		case "/api/v1/mcp/check-output":
			_, _ = w.Write([]byte(`{"allowed":true,"policies_evaluated":1}`))
		case "/api/policy/pre-check":
			_, _ = w.Write([]byte(`{"context_id":"ctx-1","approved":true,"policies":[],"expires_at":"2030-01-01T00:00:00Z"}`))
		case "/api/request":
			_, _ = w.Write([]byte(`{"success":true,"result":"ok"}`))
		case "/mcp/resources/query":
			_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
		default:
			_, _ = w.Write([]byte(`{"policies":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func (s *pepPlaneServer) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.got
	s.got = nil
	return out
}

func pepPlaneClient(endpoint string, declared *PEPHandshake) *AxonFlowClient {
	return NewClient(AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Retry:        RetryConfig{Enabled: false, MaxAttempts: 1},
		PEPHandshake: declared,
	})
}

var (
	pepDeclared = []PEPCapability{{AuthZENObligationTypeFieldRedact, 1}}
	pepOverride = []PEPCapability{{AuthZENObligationTypeFieldMask, 1}}
)

// planeCalls is every method whose route reads the declaration, with the
// request paths one call makes.
func planeCalls(c *AxonFlowClient, ctx context.Context) []struct {
	name  string
	call  func() error
	paths []string
} {
	decide := DecideRequest{Stage: "tool", Query: "q"}
	redacting := decideAllow([]Obligation{redactObligation()})
	return []struct {
		name  string
		call  func() error
		paths []string
	}{
		{"Decide", func() error { _, err := c.Decide(ctx, decide); return err }, []string{decidePath}},
		{"DecideAndFulfill", func() error { _, _, _, err := c.DecideAndFulfill(ctx, decide); return err }, []string{decidePath}},
		{"FulfillRequest", func() error {
			_, _, err := c.FulfillRequest(ctx, &redacting, "email jane.doe@example.com")
			return err
		}, []string{"/api/v1/mcp/check-input"}},
		{"Evaluate", func() error { _, err := c.Evaluate(ctx, okRequest()); return err }, []string{authzenPath}},
		{"EvaluateAll", func() error {
			_, err := c.EvaluateAll(ctx, AuthZENBulk{
				Subject:     &AuthZENSubject{Type: "gateway", ID: "g"},
				Action:      &AuthZENAction{Name: "tool.call"},
				Context:     map[string]any{"args": map[string]any{"query": "q"}},
				Evaluations: []AuthZENRequest{{Resource: &AuthZENResource{Type: "tool", ID: "jira/move_issue"}}},
			})
			return err
		}, []string{authzenPath}},
		{"MCPCheckInput", func() error {
			_, err := c.MCPCheckInput(ctx, MCPCheckInputRequest{ConnectorType: "postgres", Statement: "SELECT 1"})
			return err
		}, []string{"/api/v1/mcp/check-input"}},
		{"CheckToolInput", func() error {
			_, err := c.CheckToolInput(ctx, MCPCheckInputRequest{ConnectorType: "postgres", Statement: "SELECT 1"})
			return err
		}, []string{"/api/v1/mcp/check-input"}},
		{"MCPCheckOutput", func() error {
			_, err := c.MCPCheckOutput(ctx, MCPCheckOutputRequest{ConnectorType: "postgres", Message: "hello"})
			return err
		}, []string{"/api/v1/mcp/check-output"}},
		{"CheckToolOutput", func() error {
			_, err := c.CheckToolOutput(ctx, MCPCheckOutputRequest{ConnectorType: "postgres", Message: "hello"})
			return err
		}, []string{"/api/v1/mcp/check-output"}},
		{"PreCheckWithContext", func() error {
			_, err := c.PreCheckWithContext(ctx, "tok", "hello", nil, nil)
			return err
		}, []string{"/api/policy/pre-check"}},
	}
}

func TestThePEPHandshakeReachesEveryPlaneRequest(t *testing.T) {
	srv, rec := newPEPPlaneServer(t)
	declared := mustPEPHandshake(t, "request-path", "https://pep.example.test", pepDeclared)
	want := mustPEPHeader(t, declared)
	c := pepPlaneClient(srv.URL, declared)
	calls := planeCalls(c, context.Background())
	calls = append(calls,
		struct {
			name  string
			call  func() error
			paths []string
		}{"PreCheck", func() error { _, err := c.PreCheck("tok", "hello", nil, nil); return err }, []string{"/api/policy/pre-check"}},
		struct {
			name  string
			call  func() error
			paths []string
		}{"GetPolicyApprovedContext", func() error {
			_, err := c.GetPolicyApprovedContext("tok", "hello", nil, nil)
			return err
		}, []string{"/api/policy/pre-check"}},
	)
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			rec.take()
			if err := tc.call(); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got := rec.take()
			if len(got) != len(tc.paths) {
				t.Fatalf("requests %v, want one each to %v", got, tc.paths)
			}
			for i, p := range tc.paths {
				if got[i] != p+"="+want {
					t.Errorf("request %d = %q, want the declaration on %s", i, got[i], p)
				}
			}
		})
	}
}

func TestNoOtherRouteReceivesThePEPHandshake(t *testing.T) {
	srv, rec := newPEPPlaneServer(t)
	declared := mustPEPHandshake(t, "request-path", "https://pep.example.test", pepDeclared)
	c := pepPlaneClient(srv.URL, declared)
	// A context carrying a declaration, passed to routes that do not read it.
	ctx := ContextWithPEPHandshake(context.Background(), declared)
	rec.take()
	if _, err := c.ProxyLLMCall("tok", "hello", "chat", nil); err != nil {
		t.Fatalf("ProxyLLMCall: %v", err)
	}
	if _, err := c.MCPQuery(ctx, MCPQueryRequest{Connector: "postgres", Statement: "SELECT 1"}); err != nil {
		t.Fatalf("MCPQuery: %v", err)
	}
	if _, err := c.ListStaticPolicies(nil); err != nil {
		t.Fatalf("ListStaticPolicies: %v", err)
	}
	got := rec.take()
	if len(got) != 3 {
		t.Fatalf("requests %v, want 3", got)
	}
	for _, g := range got {
		if !strings.HasSuffix(g, "=") {
			t.Errorf("%s carried the declaration; only the four planes may", g)
		}
	}
}

func TestAPerCallPEPHandshakeReplacesTheClientsOnThatCallOnly(t *testing.T) {
	srv, rec := newPEPPlaneServer(t)
	declared := mustPEPHandshake(t, "request-path", "https://pep.example.test", pepDeclared)
	override := mustPEPHandshake(t, "response-path", "https://pep.example.test", pepOverride)
	c := pepPlaneClient(srv.URL, declared)
	ctx := context.Background()
	decide := DecideRequest{Stage: "tool", Query: "q"}
	steps := []struct {
		name string
		call func() error
		want *PEPHandshake
	}{
		{"per-call", func() error { _, err := c.Decide(ContextWithPEPHandshake(ctx, override), decide); return err }, override},
		{"the next call", func() error { _, err := c.Decide(ctx, decide); return err }, declared},
		{"a nil per-call declaration", func() error { _, err := c.Decide(ContextWithPEPHandshake(ctx, nil), decide); return err }, declared},
		{"per-call on the pre-check", func() error {
			_, err := c.PreCheckWithContext(ContextWithPEPHandshake(ctx, override), "tok", "hello", nil, nil)
			return err
		}, override},
		{"the pre-check with no context", func() error { _, err := c.PreCheck("tok", "hello", nil, nil); return err }, declared},
	}
	for _, s := range steps {
		rec.take()
		if err := s.call(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		got := rec.take()
		if len(got) != 1 || !strings.HasSuffix(got[0], "="+mustPEPHeader(t, s.want)) {
			t.Errorf("%s: requests %v, want the %s declaration", s.name, got, s.want.PEPID)
		}
	}
}

func TestAClientWithNoPEPHandshakeSendsNone(t *testing.T) {
	srv, rec := newPEPPlaneServer(t)
	c := pepPlaneClient(srv.URL, nil)
	for _, tc := range planeCalls(c, context.Background()) {
		rec.take()
		if err := tc.call(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, g := range rec.take() {
			if !strings.HasSuffix(g, "=") {
				t.Errorf("%s: %s carried a declaration nobody made", tc.name, g)
			}
		}
	}
	override := mustPEPHandshake(t, "response-path", "https://pep.example.test", pepOverride)
	rec.take()
	if _, err := c.Decide(ContextWithPEPHandshake(context.Background(), override), DecideRequest{Stage: "tool", Query: "q"}); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got := rec.take(); len(got) != 1 || !strings.HasSuffix(got[0], "="+mustPEPHeader(t, override)) {
		t.Errorf("a per-call declaration on a client with none: requests %v", got)
	}
}

func TestAPEPHandshakeThePlatformWouldRefuseFailsBeforeAnythingIsSent(t *testing.T) {
	srv, rec := newPEPPlaneServer(t)
	// Built by hand, bypassing NewPEPHandshake: an upper-case pep_id.
	invalid := &PEPHandshake{ProfileVersion: PEPHandshakeProfileV1, PEPID: "Gateway", Audience: "a", Capabilities: []PEPCapability{}}
	c := pepPlaneClient(srv.URL, invalid)
	for _, tc := range planeCalls(c, context.Background()) {
		rec.take()
		err := tc.call()
		var refusal *PEPHandshakeError
		if !errors.As(err, &refusal) || refusal.Pointer != "/pep_id" {
			t.Errorf("%s: want a refusal at /pep_id, got %v", tc.name, err)
		}
		if got := rec.take(); len(got) != 0 {
			t.Errorf("%s: sent %v with a declaration the platform would refuse", tc.name, got)
		}
	}
}
