package axonflow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// countingAuthzenServer is authzenServer plus a request counter, for the tests
// whose assertion is that NOTHING was sent. Counting at the server rather than
// wrapping the transport means the count observes the same seam the product
// uses; a refusal test that passed while a request slipped out would be
// vacuous.
func countingAuthzenServer(t *testing.T) (*AxonFlowClient, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	c := authzenServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthZENResponse{
			Decision: true,
			Context: &AuthZENResponseContext{
				Profile: AuthZENProfileV1, State: AuthZENOperationalStateAllow,
				Category: AuthZENCategoryAllowed, DecisionID: "d-attr",
				SchemaVersion: AuthZENContractSchemaVersion,
			},
		})
	})
	return c, &requests
}

// capturingAuthzenServer allows the request and hands back the raw body it
// received, so a test can assert on the WIRE, not on an intermediate value.
func capturingAuthzenServer(t *testing.T) (*AxonFlowClient, *[]byte) {
	t.Helper()
	var raw []byte
	c := authzenServer(t, func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the request body: %v", err)
		}
		raw = buf
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthZENResponse{
			Decision: true,
			Context: &AuthZENResponseContext{
				Profile: AuthZENProfileV1, State: AuthZENOperationalStateAllow,
				Category: AuthZENCategoryAllowed, DecisionID: "d-attr",
				SchemaVersion: AuthZENContractSchemaVersion,
			},
		})
	})
	return c, &raw
}

// wireContext decodes the captured body down to the singular evaluation's
// context object.
func wireContext(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var body struct {
		Evaluation struct {
			Context map[string]any `json:"context"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decoding the captured wire body: %v; body=%s", err, raw)
	}
	return body.Evaluation.Context
}

// requireUnresolved asserts the error is the LOCAL typed refusal - not a
// server refusal, not a transport error - at the given pointer.
func requireUnresolved(t *testing.T, err error, wantPointer string) *AuthZENUnresolvedError {
	t.Helper()
	if err == nil {
		t.Fatal("no error: the request was evaluated though it carried an unknown attribute")
	}
	unres, ok := AsAuthZENUnresolvedError(err)
	if !ok {
		t.Fatalf("error is %T (%v), want *AuthZENUnresolvedError", err, err)
	}
	if _, isServer := AsAuthZENError(err); isServer {
		t.Fatalf("the local refusal is ALSO recoverable as a server *AuthZENError; the two must be distinguishable")
	}
	if unres.Pointer != wantPointer {
		t.Fatalf("pointer = %q, want %q", unres.Pointer, wantPointer)
	}
	return unres
}

// TestAuthZENKnownAttributeIsSentAsItsValue: known -> the member, with its
// value, exactly as if the caller had written the value directly.
func TestAuthZENKnownAttributeIsSentAsItsValue(t *testing.T) {
	c, raw := capturingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": map[string]any{"query": "q"},
		"dept": AuthZENKnown("finance"),
	}
	if _, err := c.Evaluate(context.Background(), req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	ctx := wireContext(t, *raw)
	if got := ctx["dept"]; got != "finance" {
		t.Fatalf("context.dept = %v (%T), want the resolved value \"finance\"", got, got)
	}
}

// TestAuthZENAbsentAttributeIsOmittedNotNull: absent -> the member is not on
// the wire AT ALL. A null member would be a different statement (the value
// null), and a policy comparing against null would read it.
func TestAuthZENAbsentAttributeIsOmittedNotNull(t *testing.T) {
	c, raw := capturingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": map[string]any{"query": "q"},
		"dept": AuthZENAbsent(),
	}
	if _, err := c.Evaluate(context.Background(), req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	ctx := wireContext(t, *raw)
	if _, present := ctx["dept"]; present {
		t.Fatalf("context.dept is on the wire (value %v); an absent member must be omitted, not sent as null", ctx["dept"])
	}
	if _, present := ctx["args"]; !present {
		t.Fatal("context.args was dropped alongside the absent member; absence must not cascade")
	}
}

// TestAuthZENUnknownAttributeRefusesLocallyWithZeroRequests is the property
// the whole type exists for: an attribute nobody could resolve refuses the
// request BEFORE the round trip. Silently converting it to absent - dropping
// the member and sending anyway - is the fail-open this pins shut.
func TestAuthZENUnknownAttributeRefusesLocallyWithZeroRequests(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": map[string]any{"query": "q"},
		"dept": AuthZENUnknown(AuthZENUnknownResolutionFailed),
	}
	_, err := c.Evaluate(context.Background(), req)
	unres := requireUnresolved(t, err, "/evaluation/context/dept")
	if unres.Reason != AuthZENUnknownResolutionFailed {
		t.Errorf("reason = %q, want %q", unres.Reason, AuthZENUnknownResolutionFailed)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent; a request carrying an unknown attribute must never reach the wire", n)
	}
}

// TestAuthZENUnknownAttributeNestedOneLevelDownIsStillRefused pins the
// guard-the-container-miss-the-leaf defect: a rule enforced at the bag's top
// level and not at the leaf write one level down let an unknown ride to the
// wire inside a nested bag. One walker at every depth, or no guarantee at any.
func TestAuthZENUnknownAttributeNestedOneLevelDownIsStillRefused(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": map[string]any{
			"query": "q",
			"dept":  AuthZENUnknown("the directory timed out"),
		},
	}
	_, err := c.Evaluate(context.Background(), req)
	requireUnresolved(t, err, "/evaluation/context/args/dept")
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent for a nested unknown attribute", n)
	}
}

// TestAuthZENUnknownAttributeDeepInPropertiesAndSlicesIsStillRefused walks the
// other bags and the other container kinds: subject properties, a slice, and a
// typed container the fast paths do not name.
func TestAuthZENUnknownAttributeDeepInPropertiesAndSlicesIsStillRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate  func(*AuthZENRequest)
		pointer string
	}{
		"subject properties": {
			mutate: func(r *AuthZENRequest) {
				r.Subject.Properties = map[string]any{"clearance": AuthZENUnknown("idp unreachable")}
			},
			pointer: "/evaluation/subject/properties/clearance",
		},
		"inside a slice": {
			mutate: func(r *AuthZENRequest) {
				r.Context = map[string]any{"args": map[string]any{
					"query": "q",
					"tags":  []any{"a", AuthZENUnknown("tag source down")},
				}}
			},
			pointer: "/evaluation/context/args/tags/1",
		},
		"inside a typed container": {
			mutate: func(r *AuthZENRequest) {
				r.Context = map[string]any{"args": map[string]any{
					"query": "q",
					"attrs": map[string]AuthZENAttribute{"dept": AuthZENUnknown("no resolver")},
				}}
			},
			pointer: "/evaluation/context/args/attrs/dept",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, requests := countingAuthzenServer(t)
			req := okRequest()
			tc.mutate(&req)
			_, err := c.Evaluate(context.Background(), req)
			requireUnresolved(t, err, tc.pointer)
			if n := requests.Load(); n != 0 {
				t.Fatalf("%d HTTP request(s) were sent", n)
			}
		})
	}
}

// TestAuthZENUnknownInAPluralEntryRefusesTheEnvelope: the plural envelope's
// entries go through the same walker, under the server's own pointer
// vocabulary for them.
func TestAuthZENUnknownInAPluralEntryRefusesTheEnvelope(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	_, err := c.EvaluateAll(context.Background(), AuthZENBulk{
		Subject: &AuthZENSubject{Type: "gateway", ID: "g"},
		Action:  &AuthZENAction{Name: "tool.call"},
		Context: map[string]any{"args": map[string]any{"query": "q"}},
		Evaluations: []AuthZENRequest{
			{Resource: &AuthZENResource{Type: "tool", ID: "jira/move_issue"}},
			{Resource: &AuthZENResource{
				Type: "tool", ID: "jira/update_project",
				Properties: map[string]any{"owner": AuthZENUnknown("ownership lookup failed")},
			}},
		},
	})
	requireUnresolved(t, err, "/evaluations/evaluations/1/resource/properties/owner")
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}
}

// TestAuthZENUnknownInTheSharedBaseRefusesTheEnvelope: the bulk envelope's
// shared base is inherited by every entry, so an unknown there taints the
// whole operation.
func TestAuthZENUnknownInTheSharedBaseRefusesTheEnvelope(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	_, err := c.EvaluateAll(context.Background(), AuthZENBulk{
		Subject: &AuthZENSubject{Type: "gateway", ID: "g"},
		Action:  &AuthZENAction{Name: "tool.call"},
		Context: map[string]any{
			"args":    map[string]any{"query": "q"},
			"session": AuthZENUnknown(AuthZENUnknownStale),
		},
		Evaluations: []AuthZENRequest{
			{Resource: &AuthZENResource{Type: "tool", ID: "jira/move_issue"}},
		},
	})
	requireUnresolved(t, err, "/evaluations/context/session")
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}
}

// TestAuthZENUnresolvedRefusalIsNotRetryable: the refusal is frozen inside
// the request, so resending identical bytes reproduces it forever. A caller
// keying a retry loop on Retryable must never spin on it.
func TestAuthZENUnresolvedRefusalIsNotRetryable(t *testing.T) {
	c, _ := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{"dept": AuthZENUnknown("x")}
	_, err := c.Evaluate(context.Background(), req)
	unres := requireUnresolved(t, err, "/evaluation/context/dept")
	if unres.Retryable() {
		t.Fatal("Retryable() = true; the refusal is local and frozen inside the request, a retry cannot succeed")
	}
	if unres.Code() != AuthZENErrorCodeUnevaluableAttribute {
		t.Errorf("Code() = %q, want %q", unres.Code(), AuthZENErrorCodeUnevaluableAttribute)
	}
	if !unres.Code().Retryable() {
		// Belt and braces: the shared vocabulary agrees the code is not
		// worth retrying either.
		return
	}
	t.Fatal("the shared code vocabulary reports unevaluable_attribute as retryable")
}

// TestAuthZENRequestWithNoAttributesIsUnchanged: the resolver is invisible to
// a request that uses none of this - byte-of-wire identical to what the SDK
// sent before the type existed.
func TestAuthZENRequestWithNoAttributesIsUnchanged(t *testing.T) {
	c, raw := capturingAuthzenServer(t)
	req := okRequest()
	if _, err := c.Evaluate(context.Background(), req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want, err := json.Marshal(AuthZENEnvelope{Evaluation: &req})
	if err != nil {
		t.Fatal(err)
	}
	var gotAny, wantAny any
	if err := json.Unmarshal(*raw, &gotAny); err != nil {
		t.Fatalf("decoding wire body: %v", err)
	}
	if err := json.Unmarshal(want, &wantAny); err != nil {
		t.Fatal(err)
	}
	gotBytes, _ := json.Marshal(gotAny)
	wantBytes, _ := json.Marshal(wantAny)
	if string(gotBytes) != string(wantBytes) {
		t.Fatalf("the wire body changed for a request with no attributes:\n got %s\nwant %s", gotBytes, wantBytes)
	}
}

// TestAuthZENMarkerDocumentIsRecognisedAcrossAJSONBoundary: an attribute that
// crossed a queue or a cache is an ordinary map carrying the marker; an
// UNKNOWN one must still refuse. Recognition by Go type alone would resolve
// it as ordinary data and send it - the fail-open, reintroduced by a copy.
func TestAuthZENMarkerDocumentIsRecognisedAcrossAJSONBoundary(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": map[string]any{"query": "q"},
		"dept": map[string]any{
			AuthZENAttributeMarker: true,
			"state":                "unknown",
			"reason":               "came back from the queue unresolved",
		},
	}
	_, err := c.Evaluate(context.Background(), req)
	requireUnresolved(t, err, "/evaluation/context/dept")
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}

	// A marker document declaring a state this build does not know is an
	// attribute this build cannot parse, and the fail-open reading of that is
	// exactly the collapse the type prevents: refused, not passed through.
	c2, requests2 := countingAuthzenServer(t)
	req2 := okRequest()
	req2.Context = map[string]any{
		"dept": map[string]any{AuthZENAttributeMarker: true, "state": "shrug"},
	}
	_, err = c2.Evaluate(context.Background(), req2)
	if _, ok := AsAuthZENUnresolvedError(err); !ok {
		t.Fatalf("a marker document with an unrecognised state was not refused: %v", err)
	}
	if n := requests2.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}

	// A caller's own map that happens to carry state/value members but NO
	// marker is ordinary data: sent, not refused.
	c3, raw := capturingAuthzenServer(t)
	req3 := okRequest()
	req3.Context = map[string]any{
		"args":    map[string]any{"query": "q"},
		"machine": map[string]any{"state": "unknown", "reason": "it is a state machine"},
	}
	if _, err := c3.Evaluate(context.Background(), req3); err != nil {
		t.Fatalf("a plain bag shaped like an attribute was refused: %v", err)
	}
	ctx := wireContext(t, *raw)
	machine, ok := ctx["machine"].(map[string]any)
	if !ok || machine["state"] != "unknown" {
		t.Fatalf("the caller's own data was rewritten: %v", ctx["machine"])
	}
}

// TestAuthZENAttributeInACallerStructIsCaughtByTheEncoderBackstop: the
// resolver does not walk a caller's own structs, so the encoder is the last
// line - a known value is sent as its value, and an unknown one still refuses
// the request with the same typed error and zero requests.
func TestAuthZENAttributeInACallerStructIsCaughtByTheEncoderBackstop(t *testing.T) {
	type payload struct {
		Dept AuthZENAttribute `json:"dept"`
	}

	c, requests := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": map[string]any{"query": "q"},
		"blob": payload{Dept: AuthZENUnknown("struct-borne unknown")},
	}
	_, err := c.Evaluate(context.Background(), req)
	if err == nil {
		t.Fatal("no error: a struct-borne unknown attribute was sent")
	}
	if _, ok := AsAuthZENUnresolvedError(err); !ok {
		t.Fatalf("error is %T (%v), want *AuthZENUnresolvedError from the encoder backstop", err, err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}

	c2, raw := capturingAuthzenServer(t)
	req2 := okRequest()
	req2.Context = map[string]any{
		"args": map[string]any{"query": "q"},
		"blob": payload{Dept: AuthZENKnown("finance")},
	}
	if _, err := c2.Evaluate(context.Background(), req2); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	ctx := wireContext(t, *raw)
	blob, ok := ctx["blob"].(map[string]any)
	if !ok || blob["dept"] != "finance" {
		t.Fatalf("a struct-borne known attribute did not encode as its value: %v", ctx["blob"])
	}
}

// TestAuthZENSelfReferentialBagIsRefusedNotOverflowed: a bag that refers to
// itself must produce the typed refusal, never a stack overflow out of
// Evaluate.
func TestAuthZENSelfReferentialBagIsRefusedNotOverflowed(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	cycle := map[string]any{}
	cycle["self"] = cycle
	req := okRequest()
	req.Context = map[string]any{"args": cycle}
	_, err := c.Evaluate(context.Background(), req)
	if err == nil {
		t.Fatal("no error for a self-referential bag")
	}
	unres, ok := AsAuthZENUnresolvedError(err)
	if !ok {
		t.Fatalf("error is %T (%v), want the typed refusal", err, err)
	}
	if !strings.Contains(unres.Reason, "nests deeper") {
		t.Fatalf("reason = %q", unres.Reason)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}
}

// TestAuthZENKnownWrappingAContainerResolvesItsContents: a known attribute
// may hold a container that itself carries attributes; the rule is uniform at
// every depth, whichever side of a known() the value sits on.
func TestAuthZENKnownWrappingAContainerResolvesItsContents(t *testing.T) {
	c, raw := capturingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		"args": AuthZENKnown(map[string]any{
			"query": "q",
			"dept":  AuthZENAbsent(),
		}),
	}
	if _, err := c.Evaluate(context.Background(), req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	ctx := wireContext(t, *raw)
	args, ok := ctx["args"].(map[string]any)
	if !ok {
		t.Fatalf("context.args is %T", ctx["args"])
	}
	if args["query"] != "q" {
		t.Fatalf("args.query = %v", args["query"])
	}
	if _, present := args["dept"]; present {
		t.Fatal("an absent attribute inside a known container reached the wire")
	}

	// And an unknown inside a known container still refuses.
	c2, requests := countingAuthzenServer(t)
	req2 := okRequest()
	req2.Context = map[string]any{
		"args": AuthZENKnown(map[string]any{"query": "q", "dept": AuthZENUnknown("x")}),
	}
	_, err := c2.Evaluate(context.Background(), req2)
	requireUnresolved(t, err, "/evaluation/context/args/dept")
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}
}

// TestAuthZENCallerContainersAreNotMutatedByResolution: a caller may reuse a
// request after a refusal; resolution must build new bags, not edit theirs.
func TestAuthZENCallerContainersAreNotMutatedByResolution(t *testing.T) {
	c, _ := capturingAuthzenServer(t)
	args := map[string]any{"query": "q", "dept": AuthZENAbsent()}
	req := okRequest()
	req.Context = map[string]any{"args": args}
	if _, err := c.Evaluate(context.Background(), req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if _, present := args["dept"]; !present {
		t.Fatal("resolution deleted the member from the CALLER's map")
	}
	if _, isAttr := args["dept"].(AuthZENAttribute); !isAttr {
		t.Fatalf("resolution rewrote the caller's attribute: %T", args["dept"])
	}
}

// TestAuthZENAttributeShapedBagIsRefusedAsMalformed: an attribute where a BAG
// belongs (context itself is a marker document) is not a bag, and resolving
// it to a scalar or a hole would build a request the caller did not write.
// Refused with the same code and message the sibling SDKs give.
func TestAuthZENAttributeShapedBagIsRefusedAsMalformed(t *testing.T) {
	c, requests := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{
		AuthZENAttributeMarker: true,
		"state":                "absent",
	}
	_, err := c.Evaluate(context.Background(), req)
	azErr, ok := AsAuthZENError(err)
	if !ok {
		t.Fatalf("error is %T (%v), want *AuthZENError", err, err)
	}
	if azErr.Code != AuthZENErrorCodeMalformedEnvelope {
		t.Errorf("code = %q, want %q", azErr.Code, AuthZENErrorCodeMalformedEnvelope)
	}
	if azErr.Pointer != "/evaluation/context" {
		t.Errorf("pointer = %q", azErr.Pointer)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d HTTP request(s) were sent", n)
	}
}

// TestAuthZENPointerTokensAreEscaped: a key containing / or ~ must produce an
// RFC 6901 pointer that names the member, on the refusal whose entire
// diagnostic value is the pointer.
func TestAuthZENPointerTokensAreEscaped(t *testing.T) {
	c, _ := countingAuthzenServer(t)
	req := okRequest()
	req.Context = map[string]any{"a/b~c": AuthZENUnknown("x")}
	_, err := c.Evaluate(context.Background(), req)
	requireUnresolved(t, err, "/evaluation/context/a~1b~0c")
}

// TestAuthZENAttributeAccessors pins the small readers the states are told
// apart with.
func TestAuthZENAttributeAccessors(t *testing.T) {
	k := AuthZENKnown("v")
	if !k.IsKnown() || k.IsAbsent() || k.IsUnknown() || k.State() != AuthZENAttributeKnown {
		t.Errorf("known state readers: %v", k)
	}
	if v, ok := k.Value(); !ok || v != "v" {
		t.Errorf("Value() = %v, %v", v, ok)
	}
	a := AuthZENAbsent()
	if !a.IsAbsent() || a.IsKnown() || a.IsUnknown() {
		t.Errorf("absent state readers: %v", a)
	}
	if _, ok := a.Value(); ok {
		t.Error("Value() reported an absent attribute as known")
	}
	u := AuthZENUnknown("why")
	if !u.IsUnknown() || u.Reason() != "why" {
		t.Errorf("unknown state readers: %v", u)
	}
	// An empty reason still refuses; it must not weaken the state.
	e := AuthZENUnknown("  ")
	if !e.IsUnknown() || e.Reason() == "" {
		t.Errorf("an unknown with a blank reason lost its state or its reason: %v", e)
	}
	// The zero value is unusable, not silently one of the states.
	var zero AuthZENAttribute
	if zero.IsKnown() || zero.IsAbsent() || zero.IsUnknown() {
		t.Error("the zero value claims a state")
	}
	if !strings.Contains(zero.String(), "no state") {
		t.Errorf("zero value String() = %q", zero.String())
	}
}
