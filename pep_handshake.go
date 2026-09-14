package axonflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
)

// This file is the PEP capability handshake, which the platform reads from
// v10.4.0: an enforcement point (a PEP) declares, on each governed call, the
// exact obligation types and schema versions it can discharge. The declaration
// rides the X-Axonflow-PEP-Handshake header as the unpadded base64url encoding
// of a JSON document:
//
//	{"profile_version":1,"pep_id":"...","audience":"...",
//	 "capabilities":[{"type":"field_redact","version":1}]}
//
// From platform v11.0.0, on every edition, the engine refuses with
// unsupported_obligation a mandatory obligation the caller's declaration
// cannot discharge, and a caller that presents no declaration can discharge
// none: Decide under an organization's redact override refuses a caller that
// does not declare redaction (field_redact at version 1), where v10 allowed it
// with a redact_pii obligation. What only Enterprise adds happens at the
// handler, for an enforcement point that presented a declaration: an allow
// carrying a mandatory obligation outside the declared set becomes a deny, so
// the enforcement point is never handed an instruction it would drop; a
// refusal names the capability the declaration lacks; and on the MCP
// check-input round-trip, a redaction the declaration cannot discharge is
// refused rather than handed back masked.
//
// WHERE IT IS SENT. Four request planes read the header: Decide (and
// DecideAndFulfill and FulfillRequest's engine round-trip), the AuthZEN
// evaluation route (Evaluate, EvaluateAll), the MCP check routes
// (MCPCheckInput, MCPCheckOutput and their CheckTool aliases) and the gateway
// pre-check (PreCheck, GetPolicyApprovedContext, PreCheckWithContext). No
// other route reads it, and the client never sends it anywhere else:
// ProxyLLMCall (/api/request) and the OpenAI-compatible route do not read it.
//
// ABSENT IS NOT EMPTY. A client with no declaration sends no header, and the
// platform takes the path it took before the handshake existed, except that
// from v11.0.0 Decide refuses it under an organization's redact override (see
// above); there is no default declaration, because only the caller knows what
// its enforcement point can discharge. An empty capability list is a
// declaration that it discharges nothing, which on Enterprise turns every allow
// carrying a mandatory obligation into a deny. A nil capability list is
// refused.
//
// The rules below are the platform's own (platform/decision/contract
// DecodePEPHandshake): a declaration this file accepts is one the platform's
// decoder accepts, and one it would refuse fails here, naming the member,
// rather than as a 400 on the first governed call.

// PEPHandshakeHeader is the request header the declaration rides on.
const PEPHandshakeHeader = "X-Axonflow-PEP-Handshake"

// PEPHandshakeProfileV1 is the only handshake profile the platform reads,
// matched exactly, never as a floor.
const PEPHandshakeProfileV1 = 1

const (
	// MaxPEPHandshakeBytes is the longest header value the platform reads, in
	// bytes of base64.
	MaxPEPHandshakeBytes = 4096
	// MaxPEPHandshakeCapabilities is the most capabilities one declaration may
	// carry. A surplus is refused, not truncated.
	MaxPEPHandshakeCapabilities = 64

	maxPEPHandshakeIdentifier = 128
)

// The pep_id excludes ":" because the platform builds the enforcement point's
// identifier as "client:<authenticated credential>:<pep_id>"; the audience is
// composed into nothing, and admits ":" and "/" so a URI is usable as one.
var (
	pepIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	pepAudiencePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

// PEPCapability is one obligation type, at one schema version, that the
// enforcement point can discharge. Matching is exact on both members.
type PEPCapability struct {
	Type    AuthZENObligationType `json:"type"`
	Version int                   `json:"version"`
}

// PEPHandshake is a capability declaration: the platform's PEPHandshake
// document. Build one with NewPEPHandshake, which validates it and puts the
// capabilities in the platform's canonical order, and present it with
// AxonFlowConfig.PEPHandshake (every call to a plane that reads it) or
// ContextWithPEPHandshake (one call).
//
// A value built by hand is validated when it is sent: a call presenting a
// declaration the platform would refuse fails with *PEPHandshakeError before
// anything is sent.
type PEPHandshake struct {
	// ProfileVersion is PEPHandshakeProfileV1.
	ProfileVersion int `json:"profile_version"`
	// PEPID names this enforcement point within the client's credential:
	// lower-case letters, digits, ".", "_" and "-", starting with a letter or
	// digit, at most 128 bytes. The platform prefixes it with the
	// authenticated credential, so it cannot name another client's
	// enforcement point.
	PEPID string `json:"pep_id"`
	// Audience is the audience this enforcement point expects a decision proof
	// to be bound to, at most 128 bytes; a URI is the usual form. It is
	// recorded and bound, and authorises nothing.
	Audience string `json:"audience"`
	// Capabilities is the exact set this enforcement point can discharge. An
	// empty, non-nil list declares that it discharges nothing; nil is refused.
	Capabilities []PEPCapability `json:"capabilities"`
}

// PEPHandshakeError is a declaration the platform would refuse. Pointer names
// the member at fault ("/profile_version", "/pep_id", "/audience" or
// "/capabilities"), or is empty when the whole document encodes past the
// header's size limit.
type PEPHandshakeError struct {
	Pointer string
	Detail  string
}

func (e *PEPHandshakeError) Error() string {
	if e.Pointer == "" {
		return PEPHandshakeHeader + ": " + e.Detail
	}
	return PEPHandshakeHeader + ": " + e.Pointer + ": " + e.Detail
}

func refusePEPHandshake(pointer, format string, args ...interface{}) *PEPHandshakeError {
	return &PEPHandshakeError{Pointer: pointer, Detail: fmt.Sprintf(format, args...)}
}

// NewPEPHandshake returns a validated declaration for pepID and audience with
// capabilities in canonical order. The caller's slice is copied. Pass an empty,
// non-nil slice to declare that the enforcement point discharges nothing; a nil
// slice is refused.
func NewPEPHandshake(pepID, audience string, capabilities []PEPCapability) (*PEPHandshake, error) {
	h := &PEPHandshake{ProfileVersion: PEPHandshakeProfileV1, PEPID: pepID, Audience: audience}
	if capabilities != nil {
		h.Capabilities = canonicalPEPCapabilities(capabilities)
	}
	if _, err := h.HeaderValue(); err != nil {
		return nil, err
	}
	return h, nil
}

// HeaderValue validates the declaration and returns the X-Axonflow-PEP-Handshake
// value it is sent as: the unpadded base64url encoding of its canonical JSON
// document. Two declarations of the same set in a different order encode to
// the same bytes. The error, when there is one, is a *PEPHandshakeError.
func (h *PEPHandshake) HeaderValue() (string, error) {
	if h == nil {
		return "", refusePEPHandshake("", "no declaration")
	}
	if err := h.validate(); err != nil {
		return "", err
	}
	doc := *h
	doc.Capabilities = canonicalPEPCapabilities(h.Capabilities)
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("%s: failed to encode the declaration: %w", PEPHandshakeHeader, err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > MaxPEPHandshakeBytes {
		return "", refusePEPHandshake("", "encodes to %d bytes; the header carries at most %d", len(encoded), MaxPEPHandshakeBytes)
	}
	return encoded, nil
}

func (h *PEPHandshake) validate() *PEPHandshakeError {
	if h.ProfileVersion != PEPHandshakeProfileV1 {
		return refusePEPHandshake("/profile_version", "declares profile version %d; the platform reads profile version %d only", h.ProfileVersion, PEPHandshakeProfileV1)
	}
	if err := validatePEPIdentifier(h.PEPID, pepIdentifierPattern, "/pep_id"); err != nil {
		return err
	}
	if err := validatePEPIdentifier(h.Audience, pepAudiencePattern, "/audience"); err != nil {
		return err
	}
	if h.Capabilities == nil {
		return refusePEPHandshake("/capabilities", "is absent; a handshake exists to declare capabilities, and an enforcement point that discharges nothing declares an empty list")
	}
	if len(h.Capabilities) > MaxPEPHandshakeCapabilities {
		return refusePEPHandshake("/capabilities", "declares %d capabilities; the platform reads at most %d", len(h.Capabilities), MaxPEPHandshakeCapabilities)
	}
	known := make(map[AuthZENObligationType]bool)
	for _, t := range AllAuthZENObligationTypes() {
		known[t] = true
	}
	seen := make(map[PEPCapability]bool, len(h.Capabilities))
	for _, c := range h.Capabilities {
		if !known[c.Type] {
			return refusePEPHandshake("/capabilities", "names obligation type %q, which is not one of %v", c.Type, AllAuthZENObligationTypes())
		}
		// A version of 0 would match only an obligation whose version was
		// never set.
		if c.Version <= 0 {
			return refusePEPHandshake("/capabilities", "declares %q at version %d; a version is a positive integer", c.Type, c.Version)
		}
		if seen[c] {
			return refusePEPHandshake("/capabilities", "declares %q at version %d more than once; the platform refuses a repeated capability", c.Type, c.Version)
		}
		seen[c] = true
	}
	return nil
}

func validatePEPIdentifier(value string, pattern *regexp.Regexp, pointer string) *PEPHandshakeError {
	if value == "" || len(value) > maxPEPHandshakeIdentifier || !pattern.MatchString(value) {
		return refusePEPHandshake(pointer, "%q is not of the form %s with at most %d bytes", value, pattern, maxPEPHandshakeIdentifier)
	}
	return nil
}

// canonicalPEPCapabilities returns a sorted copy: by type, then by version,
// the platform's canonical order.
func canonicalPEPCapabilities(in []PEPCapability) []PEPCapability {
	out := append(make([]PEPCapability, 0, len(in)), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Version < out[j].Version
	})
	return out
}

type pepHandshakeCtxKey struct{}

// ContextWithPEPHandshake returns ctx carrying h as this call's PEP capability
// declaration, in place of AxonFlowConfig.PEPHandshake, on the methods whose
// route reads the header: Decide, DecideAndFulfill and FulfillRequest,
// Evaluate and EvaluateAll, MCPCheckInput and MCPCheckOutput and their
// CheckTool aliases, and PreCheckWithContext. Every other method ignores it, so
// a context carrying a declaration can be passed anywhere without sending it
// to a route that does not read it. A nil h leaves the client's declaration in
// effect.
//
// One process can be two enforcement points (a request path and a response
// path discharging different obligations), and this is how each presents its
// own.
func ContextWithPEPHandshake(ctx context.Context, h *PEPHandshake) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, pepHandshakeCtxKey{}, h)
}

// pepPlaneCtxKey marks a request context as belonging to one of the four
// planes that read the declaration, carrying the header value to send. It is
// unexported, so no caller can make another route send the header.
type pepPlaneCtxKey struct{}

// onPEPPlane resolves the declaration for one call to a plane that reads it
// (the per-call one, else the client's) and marks ctx with its header value.
// A declaration the platform would refuse fails the call here, before anything
// is sent.
func (c *AxonFlowClient) onPEPPlane(ctx context.Context) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	declared := c.config.PEPHandshake
	if h, ok := ctx.Value(pepHandshakeCtxKey{}).(*PEPHandshake); ok && h != nil {
		declared = h
	}
	if declared == nil {
		return ctx, nil
	}
	value, err := declared.HeaderValue()
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, pepPlaneCtxKey{}, value), nil
}

// applyPEPHandshake sets the declaration on req when onPEPPlane marked its
// context. Called from addAuthHeaders, which every request builder uses, so
// the four planes need only mark their context.
func applyPEPHandshake(req *http.Request) {
	if v, ok := req.Context().Value(pepPlaneCtxKey{}).(string); ok && v != "" {
		req.Header.Set(PEPHandshakeHeader, v)
	}
}
