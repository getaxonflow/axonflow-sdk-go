package axonflow

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// This file carries what the SDK reads from a v11.0.0 platform beyond a
// verdict: which engine and policy set decided (the provenance fields on each
// response type), the refusal a legacy policy write now gets, and the
// deprecation the platform stamps on its legacy routes. Every provenance field
// is empty on an older platform, so an empty value means "not reported", never
// "no engine decided".

// LegacyValidatorAction names a checksum validator that acted before the
// policy engine decided (#4122). Under an organization's recorded pii=block or
// pii=redact detection override, the Indonesian or Indian identifier validator
// blocks or masks on its own, and a response's LegacyValidators names each one
// that did, so the verdict's provenance is complete.
type LegacyValidatorAction struct {
	Validator string `json:"validator"` // "indonesia_pii" or "india_pii"
	Action    string `json:"action"`    // "blocked" or "masked"
}

// PolicyIdentity names one policy a decision matched (PRD v11 §1.14).
// DecideResponse.PolicyIdentities follows EvaluatedPolicies one for one, in
// order. Name is the policy's own display name, empty when it declares none:
// the platform never presents an identifier as a name. Source says whose the
// policy is ("shipped", "organization" or "pack"). Version is the published
// version of an organization's or an installed pack's policy, 0 when the
// platform reports none.
type PolicyIdentity struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Source  string `json:"source,omitempty"`
	Version int    `json:"version,omitempty"`
}

// LegacyPolicyWriteFrozenCode is the error code a v11.0.0 platform answers a
// legacy policy write with.
const LegacyPolicyWriteFrozenCode = "LEGACY_POLICY_WRITE_FROZEN"

// LegacyPolicyWriteFrozenError is returned when the platform refuses a write to
// its static- or dynamic-policy routes. From v11.0.0 those writes answer
// 409 LEGACY_POLICY_WRITE_FROZEN, on the agent and the orchestrator alike:
// policy is authored through the typed route (/api/v1/typed-policies), which
// Message names. Reads on the legacy routes still work and are deprecated; see
// AxonFlowConfig.OnRouteDeprecation.
type LegacyPolicyWriteFrozenError struct {
	Message string
}

func (e *LegacyPolicyWriteFrozenError) Error() string {
	return LegacyPolicyWriteFrozenCode + ": " + e.Message
}

// responseError builds the error for a response whose status is 400 or more:
// the typed refusal for a frozen legacy policy write, else the generic HTTP
// error. Any other 409 keeps the generic error.
func responseError(statusCode int, body []byte) error {
	if statusCode == http.StatusConflict {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &payload) == nil && payload.Error.Code == LegacyPolicyWriteFrozenCode {
			message := payload.Error.Message
			if message == "" {
				message = "legacy policy write frozen"
			}
			return &LegacyPolicyWriteFrozenError{Message: message}
		}
	}
	return &httpError{statusCode: statusCode, message: string(body)}
}

// PlatformRouteDeprecation is what the platform declared about a route a call
// used. A v11.0.0 platform stamps its legacy policy routes with
// X-AxonFlow-Removed-In and Link: <successor>; rel="successor-version", and
// adds an RFC 9745 Deprecation header once the deprecating release is tagged.
// Either the first or the last marks the route deprecated, so the SDK reports
// it before the tag as well as after it.
type PlatformRouteDeprecation struct {
	Route       string // method and path, e.g. "GET /api/v1/static-policies"
	Successor   string // the route that replaces it, when the platform names one
	RemovedIn   string // the release that removes it, e.g. "v11.1"
	Deprecation string // the RFC 9745 Deprecation value, when the platform sends one
}

func (d PlatformRouteDeprecation) String() string {
	s := d.Route + " is deprecated by the AxonFlow platform"
	if d.Successor != "" {
		s += "; use " + d.Successor + " instead"
	}
	if d.RemovedIn != "" {
		s += "; it is removed in " + d.RemovedIn
	}
	return s + "."
}

var successorLinkRE = regexp.MustCompile(`(?i)<([^>]*)>\s*;\s*rel="?successor-version"?`)

// routeDeprecationFrom reads the deprecation a response's headers declare for
// its route, or nil when they declare none. Presence is what counts, as in the
// other SDKs: a Deprecation or X-AxonFlow-Removed-In header marks the route.
func routeDeprecationFrom(method, path string, header http.Header) *PlatformRouteDeprecation {
	deprecation, hasDeprecation := headerValue(header, "Deprecation")
	removedIn, hasRemovedIn := headerValue(header, "X-AxonFlow-Removed-In")
	if !hasDeprecation && !hasRemovedIn {
		return nil
	}
	d := &PlatformRouteDeprecation{Route: method + " " + path, RemovedIn: removedIn, Deprecation: deprecation}
	if m := successorLinkRE.FindStringSubmatch(strings.Join(header.Values("Link"), ", ")); m != nil {
		d.Successor = m[1]
	}
	return d
}

func headerValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// routeDeprecationNotes records which routes a client has reported, so each is
// reported once. A client AsUser derives shares its parent's record.
type routeDeprecationNotes struct {
	mu   sync.Mutex
	seen map[string]bool
}

// first reports whether route has not been reported yet, and records it. A nil
// record (a client not built by NewClient) reports every time.
func (n *routeDeprecationNotes) first(route string) bool {
	if n == nil {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen[route] {
		return false
	}
	if n.seen == nil {
		n.seen = map[string]bool{}
	}
	n.seen[route] = true
	return true
}

// noteRouteDeprecation reports the deprecation a response declares for its
// route, once per route: to AxonFlowConfig.OnRouteDeprecation when it is set,
// otherwise to the standard logger.
func (c *AxonFlowClient) noteRouteDeprecation(req *http.Request, resp *http.Response) {
	if req == nil || req.URL == nil || resp == nil {
		return
	}
	d := routeDeprecationFrom(req.Method, req.URL.Path, resp.Header)
	if d == nil || !c.routeDeprecations.first(d.Route) {
		return
	}
	if c.config.OnRouteDeprecation != nil {
		c.config.OnRouteDeprecation(*d)
		return
	}
	log.Printf("[AxonFlow] %s", d)
}
