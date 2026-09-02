// Read-path per-user identity and the platform's read-scope contract.
//
// Since platform #2922 the role-scoped read routes (audit / decisions /
// overrides) answer from the identity the CALLER presents, not from the tenant
// credential alone. The tenant credential in Authorization says which
// organization is asking; it does not say WHO. A caller that presents no
// per-user identity to an enterprise stack is not "a caller who sees
// everything" and is not "a caller who sees nothing by coincidence" — it is a
// caller the platform cannot scope, and every scoped read it makes returns
// zero rows by construction.
//
// This file carries the whole surface:
//
//   - the per-user identity itself (AxonFlowConfig.UserToken for a client-wide
//     identity, WithUserToken for a per-call one), stamped as the X-User-Token
//     header from exactly ONE site — addAuthHeaders in audit.go, which every
//     request-building method in this SDK already funnels through. There is no
//     per-method header plumbing, deliberately: the platform reads the header
//     once in its own proxy middleware (platform/agent/proxy.go
//     proxyAuthMiddleware), not per route, so a per-method sprinkle here would
//     be a second, drifting copy of a decision the platform makes in one place.
//
//   - the response side of the same contract: X-Axonflow-Read-Scope, which the
//     platform stamps on every scoped read (platform/orchestrator
//     read_scope.go applyReadScopeHeader) to say which of the three scopes the
//     answer was computed under. Without it a 404 from explain and an empty
//     list from ListDecisions are indistinguishable from "the row is not
//     there", which is how a governed read comes to report a confident,
//     vacuous nothing.
package axonflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// headerUserToken is the request header carrying the per-user identity.
//
// This constant is the SDK's only spelling of it. The header is set in exactly
// one place (applyReadIdentity, called from addAuthHeaders); if you find
// yourself setting it in a method, the method is the wrong altitude.
const headerUserToken = "X-User-Token"

// headerReadScope is the response header the platform stamps on scoped reads.
const headerReadScope = "X-Axonflow-Read-Scope"

// ReadScope is the scope the platform computed a role-scoped read under, taken
// from the X-Axonflow-Read-Scope response header.
//
// The three named values are the platform's closed set. Two states are NOT in
// that set and are deliberately distinct from each other and from the three:
//
//   - ReadScopeAbsent — the response carried no such header. That is what a
//     pre-#2922 platform, a non-scoped route, or a proxy that dropped the
//     header looks like. It means "not stated", never "none": treating an
//     absent header as a scope of none would turn every older stack's perfectly
//     good read into a refusal.
//
//   - any other non-empty string — a scope a newer platform names and this
//     build does not recognise. It is preserved verbatim rather than folded
//     into one of the three, so a caller can see what it was, and it never
//     triggers a refusal: this header is the platform's account of a decision
//     it has ALREADY made and applied, so an unrecognised value is a reporting
//     gap on our side, not a licence to invent an outcome.
type ReadScope string

const (
	// ReadScopeAbsent means the response carried no X-Axonflow-Read-Scope
	// header at all. Distinct from ReadScopeNone — see the type doc.
	ReadScopeAbsent ReadScope = ""

	// ReadScopeTenant means the read was tenant-wide: the caller held a
	// tenant-wide role (admin / owner / policy_admin), or the deployment is
	// Community / Community-SaaS, where the whole tenant is the one operator.
	ReadScopeTenant ReadScope = "tenant"

	// ReadScopeOwnRows means the read was narrowed to the rows attributed to
	// the identity the caller presented. A miss under this scope means "not
	// yours", which is not the same statement as "not there".
	ReadScopeOwnRows ReadScope = "own-rows"

	// ReadScopeNone means the platform RESOLVED no per-user identity for this
	// read and the caller holds no tenant-wide authority, so it returned zero
	// rows by construction. Under this scope a read CANNOT have returned data,
	// so its empty answer says nothing about what exists.
	//
	// "Resolved none" is wider than "presented none", and the difference is
	// worth knowing before you go looking in the wrong place. A token that
	// validates perfectly still resolves to no identity when its address is
	// one the platform reserves for SHARED, non-personal identities — the
	// whole of @axonflow.local and @axonflow.internal, plus the community and
	// evaluator addresses. Those name a pool of callers rather than a person,
	// and scoping a read to one would return the pool, so the platform
	// deliberately censuses them to nothing. A per-user token minted with an
	// address in one of those domains therefore reads exactly like no token at
	// all. (This is easy to hit: the platform's own generate-jwt.sh defaults
	// to demo-user@axonflow.local.)
	ReadScopeNone ReadScope = "none"
)

// readScopeOf extracts the scope the platform reported on a response.
// A nil response, or one without the header, is ReadScopeAbsent.
//
// Trimmed and lower-cased, for the same reason the platform's own header
// helpers are (sharedidentity.AdminAuthorityFromHeader uses EqualFold): a
// proxy that normalises header casing or appends whitespace must not silently
// change the answer. Here the cost of getting that wrong is one-sided and
// quiet — a scope spelled "None" would fall to the unrecognised branch, and
// the vacuous empty page it describes would come back as data again, which is
// the whole defect this file exists to remove. An unrecognised value is
// otherwise unchanged, so it still round-trips to the caller.
func readScopeOf(resp *http.Response) ReadScope {
	if resp == nil {
		return ReadScopeAbsent
	}
	return ReadScope(strings.ToLower(strings.TrimSpace(resp.Header.Get(headerReadScope))))
}

// ============================================================================
// Presenting an identity
// ============================================================================

// userTokenCtxKey is the private context key carrying a per-call identity.
// Private so no caller can plant one without going through WithUserToken.
type userTokenCtxKey struct{}

// ReadOption customises a single call. Options compose left to right; a later
// option of the same kind wins.
//
// Options carry the per-call identity on the request context rather than in
// each method's own parameter list. That is what lets one identity mechanism
// serve every method — including the ones that take a filter struct
// (ListDecisions) and the ones that take none (ExplainDecision) — without
// either signature growing a token field that a third method would then have
// to grow too.
type ReadOption func(context.Context) context.Context

// WithUserToken presents a per-user identity for this call only, overriding
// AxonFlowConfig.UserToken.
//
// Use it when one process acts on behalf of several people — a gateway, a
// bot handling many users' requests — so each read is scoped to the person it
// is for rather than to whichever identity the client was constructed with.
//
// An empty or whitespace-only token is not an identity: it clears the
// client-level one for this call rather than sending an empty header. That is
// deliberate, and it is how a caller says "make this read explicitly
// unidentified" (which, on an enterprise stack, is a read that returns
// nothing — see ReadScopeNone).
func WithUserToken(token string) ReadOption {
	return func(ctx context.Context) context.Context {
		return ContextWithUserToken(ctx, token)
	}
}

// ContextWithUserToken returns ctx carrying token as the per-user identity for
// requests made with it.
//
// This is the ambient form of WithUserToken, for the methods that take a
// context but no ReadOption. Use it when a per-request identity has to travel
// through code that does not know about this SDK — a middleware chain, a
// worker that is handed a context and a job.
//
// # What it reaches, exactly
//
// Only the methods that thread YOUR context into the outbound request. Roughly
// two thirds of this SDK's methods do; the rest build their request with
// http.NewRequest and no context (all of masfeat.go, execution_replay.go,
// policies.go, code_governance.go, and several in axonflow.go), and some take
// no context at all. On those, a token planted here is NOT seen and the client
// -level AxonFlowConfig.UserToken applies instead.
//
// That fallback is to a BROADER identity, which is the direction that matters:
// a gateway acting for Alice that plants her token on a context and then calls
// a non-context method gets the client's own identity, not hers. So for a
// process acting on behalf of several people, prefer AsUser, which binds the
// identity to the client and therefore reaches every method with no such
// carve-out. Reach for this only where a client per user is genuinely
// impractical, and only on the read methods, which do thread the context.
func ContextWithUserToken(ctx context.Context, token string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, userTokenCtxKey{}, strings.TrimSpace(token))
}

// AsUser returns a client identical to c but presenting token as its per-user
// identity, for a process acting on behalf of several people.
//
// This is the recommended shape for a gateway or a bot: unlike the
// context-carried identity, it reaches EVERY method, because it is resolved
// from the client rather than from a context the method may not thread. There
// is no carve-out to remember and no path on which the identity silently
// widens back to the process's own.
//
//	forAlice := client.AsUser(aliceToken)
//	rows, err := forAlice.ListDecisions(ctx, axonflow.ListDecisionsOptions{})
//
// The returned client SHARES the underlying HTTP clients and cache with c —
// it is a view, not a new connection pool — so deriving one per request is
// cheap. Only the identity differs.
//
// An empty token returns a client that presents no identity at all, which on
// an enterprise stack reads nothing (see ReadScopeNone).
//
// One value is copied rather than shared: the customer-portal session cookie.
// A LoginToPortal on either client after the derivation is invisible to the
// other, so derive AFTER logging in if the derived client needs the portal
// plane. That plane authenticates with the cookie rather than with this
// identity, so the two are independent by design.
func (c *AxonFlowClient) AsUser(token string) *AxonFlowClient {
	if c == nil {
		return nil
	}
	derived := *c
	derived.config.UserToken = strings.TrimSpace(token)
	return &derived
}

// applyReadOptions folds opts onto ctx. A nil ctx is treated as Background so
// an option can never panic on a caller's behalf.
func applyReadOptions(ctx context.Context, opts ...ReadOption) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		ctx = opt(ctx)
	}
	return ctx
}

// effectiveUserToken resolves the identity for a request: the per-call value
// if WithUserToken was used on this call (INCLUDING an explicit empty one,
// which is a deliberate "no identity" and must not fall back), otherwise the
// client-level AxonFlowConfig.UserToken.
func (c *AxonFlowClient) effectiveUserToken(ctx context.Context) string {
	if ctx != nil {
		if v, ok := ctx.Value(userTokenCtxKey{}).(string); ok {
			return v
		}
	}
	return strings.TrimSpace(c.config.UserToken)
}

// applyReadIdentity stamps the per-user identity on req, if there is one.
//
// Called from addAuthHeaders, which every request-building method in this SDK
// already uses, so the identity travels on every request without any method
// knowing about it. That is on purpose and mirrors the platform: the agent
// reads X-User-Token once, in the middleware in front of every proxied route
// (platform/agent/proxy.go), and the routes themselves never look at it.
//
// # The header is NOT inert on the routes that are not reads
//
// It is validated on every route the agent proxies, which is nearly all of
// them. platform/agent/proxy.go proxyAuthMiddleware resolves X-User-Token
// before dispatch and answers 401 "invalid user token" for a
// present-but-INVALID one — on /api/v1/plans, /api/v1/policies,
// /api/v1/connectors, /api/v1/process, /api/v1/budgets, /api/v1/cost,
// /api/v1/executions and the rest, not only on the scoped reads. A validated
// one also overrides the X-User-Email attribution those writes are recorded
// under.
//
// So a stale or rotated UserToken does not degrade to "unscoped reads"; it
// turns ListConnectors, InstallConnector, GetPlanStatus and policy CRUD into
// 401s. That is the correct direction — a credential the platform rejects must
// not be silently ignored — but it is a real operational consequence of
// setting this client-wide, and it is why the value belongs in the same
// rotation story as ClientSecret rather than being treated as a read-only
// convenience.
//
// # Where it IS inert
//
// Only two seams read X-User-Token at all — platform/agent/proxy.go
// (proxyAuthMiddleware, in front of the proxied routes) and
// mcp_identity.go (the MCP-server plane) — so it is inert on every route the
// AGENT SERVES ITSELF. Enumerated from the agent router rather than sampled,
// because replacing one wrong census with a shorter wrong census is not a fix:
//
//	/api/request                    ProxyLLMCall / ProxyLLMCallWithMedia
//	/api/v1/decide                  Decide / DecideAndFulfill — identity comes
//	                                from the request BODY's user_token here,
//	                                which is the whole reason the read path
//	                                needed a surface of its own
//	/api/v1/access/evaluation       Evaluate (AuthZEN)
//	/api/v1/static-policies/*       the system-policy family
//	/api/v1/circuit-breaker/*
//	/api/v1/hitl/*
//	/api/v1/mcp/check-input         PreCheck
//	/api/v1/mcp/check-output
//	/api/v1/register                RegisterTry (mints the credential)
//	/api/policy/pre-check
//	/api/audit/llm-call
//	/health                         HealthCheck / the telemetry probe
//
// Everything else this SDK calls is proxied, and therefore validates it.
//
// The token is a CREDENTIAL. It is written to the header and nowhere else: it
// is never logged (including under Debug), never carried in an error message,
// and never reaches telemetry — heartbeat.go builds its own request and does
// not call addAuthHeaders.
func (c *AxonFlowClient) applyReadIdentity(req *http.Request) {
	if req == nil {
		return
	}
	token := c.effectiveUserToken(req.Context())
	if token == "" {
		// Never send an empty header: to the platform a present-but-empty
		// X-User-Token is still an absent one (it TrimSpaces then tests for
		// empty), but sending it advertises an identity mechanism the caller
		// is not actually using, and it is one refactor away from a
		// present-but-invalid token, which is a hard 401.
		return
	}
	req.Header.Set(headerUserToken, token)
}

// ============================================================================
// Reading the platform's answer honestly
// ============================================================================

// ReadScopeError is the typed refusal for a role-scoped read whose answer was
// decided by the caller's identity scope rather than by the data.
//
// It exists because "no rows" and "no identity" are the same bytes on the
// wire. The platform distinguishes them in the X-Axonflow-Read-Scope header;
// this error is that distinction made visible to a Go caller, so a read that
// could not have succeeded reports a cause instead of a confident nothing.
//
// Two shapes, told apart by IdentityMissing:
//
//   - ReadScopeNone   — no identity was RESOLVED; the read returned zero rows
//     by construction and says nothing about what exists. Remedy: present an
//     identity (AxonFlowConfig.UserToken / WithUserToken) whose address is a
//     real person's — see ReadScopeNone for why a valid token can still
//     resolve to nothing.
//   - ReadScopeOwnRows — an identity WAS resolved, and the row is not among
//     the ones attributed to it. That does NOT mean the row exists and belongs
//     to somebody else: the platform answers "not attributed to you" and "not
//     there at all" with the identical 404, deliberately, so that a miss cannot
//     be used to probe for another user's rows. This error therefore reports
//     the scope, not a claim about what exists. Remedy: a tenant-wide role
//     (admin / owner / policy_admin) sees the whole tenant.
//
// The presented token is never included in Error(): the message is safe to
// log, which is the point of putting the diagnosis in a type rather than in a
// formatted string the caller assembles from the credential.
type ReadScopeError struct {
	// Resource names what was read, e.g. "decision".
	Resource string
	// ID is the identifier that was read, empty for a list read.
	ID string
	// Scope is the scope the platform reported.
	Scope ReadScope
	// StatusCode is the HTTP status the platform answered with (404 for a
	// scoped miss, 200 for a scoped-empty list).
	StatusCode int
}

// IdentityMissing reports whether the read failed because no per-user identity
// was presented (as opposed to one being presented and not matching).
func (e *ReadScopeError) IdentityMissing() bool { return e.Scope == ReadScopeNone }

func (e *ReadScopeError) Error() string {
	resource := e.Resource
	if resource == "" {
		resource = "read"
	}
	subject := resource
	if e.ID != "" {
		subject = fmt.Sprintf("%s %q", resource, e.ID)
	}
	if e.IdentityMissing() {
		return fmt.Sprintf(
			"HTTP %d: %s: the platform resolved no per-user identity for this read (%s: %s), so it "+
				"returned zero rows by construction and the empty answer says nothing about what exists. "+
				"Either no identity was presented — set AxonFlowConfig.UserToken or use "+
				"axonflow.WithUserToken — or the one presented carries an address the platform reserves "+
				"for shared identities (@axonflow.local, @axonflow.internal), which resolves to nobody. "+
				"(platform #2922)",
			e.StatusCode, subject, headerReadScope, e.Scope)
	}
	return fmt.Sprintf(
		"HTTP %d: %s was not found among the rows this identity can see: the platform reports "+
			"%s: %s, so the read was narrowed to the identity's own rows. It is either not "+
			"attributed to this identity or not there at all — the platform answers both the "+
			"same way ON PURPOSE, so that a miss cannot be used to probe for the existence of "+
			"another user's rows, and this SDK cannot tell them apart either. A tenant-wide role "+
			"(admin, owner or policy_admin) reads the whole tenant (platform #2922).",
		e.StatusCode, subject, headerReadScope, e.Scope)
}

// readScopeErrorFor returns the typed refusal for a scoped read that came back
// with nothing, or nil when the scope does not explain the result.
//
// nil is returned for ReadScopeTenant (the caller could see the whole tenant
// and it still was not there — a genuine miss), for ReadScopeAbsent (the
// platform did not state a scope; see the ReadScope doc for why absent is not
// none), and for any scope value this build does not recognise (a newer
// platform's; reporting a cause we cannot actually read would be a confident
// wrong diagnosis).
func readScopeErrorFor(resource, id string, scope ReadScope, status int) *ReadScopeError {
	switch scope {
	case ReadScopeNone, ReadScopeOwnRows:
		return &ReadScopeError{Resource: resource, ID: id, Scope: scope, StatusCode: status}
	default:
		return nil
	}
}

// refuseVacuousScopedPage returns the typed refusal when a scoped read came
// back EMPTY under a scope that could not have returned a row, and nil in
// every other case.
//
// One helper rather than a check at each read, because "the page is empty and
// the scope is none" is one rule and the reads that need it decode their body
// on more than one path each. A rule copied per return site is a rule that
// ends up applied on some of them.
//
// The emptiness guard is as load-bearing as the scope guard: a non-empty page
// is never turned into an error, whatever the header says. And only
// ReadScopeNone refuses — an own-rows or tenant-wide read that legitimately
// found nothing is a real answer, and replacing it with an error would swap
// one wrong report for another.
func refuseVacuousScopedPage(resp *http.Response, resource string, rows int) error {
	if rows > 0 {
		return nil
	}
	if readScopeOf(resp) != ReadScopeNone {
		return nil
	}
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return &ReadScopeError{Resource: resource, Scope: ReadScopeNone, StatusCode: status}
}

// stripIdentityOnCrossHostRedirect is the http.Client CheckRedirect policy for
// every client this SDK builds.
//
// net/http already strips Authorization, WWW-Authenticate, Cookie and Cookie2
// when a redirect changes host — sensitive headers must not follow a request
// somewhere the caller did not choose. That list is fixed and X-User-Token is
// not on it, so without this the SDK forwards a per-user credential to a host
// the caller never named, on a hop where the TENANT credential is dropped.
// Measured: an origin at localhost answering 302 to 127.0.0.1 saw
// Authorization="" and X-User-Token intact at the far end. Two lines from any
// endpoint that 301s http→https through a third party.
//
// The rule here is deliberately STRICTER than net/http's own. net/http
// compares Hostname() — port-insensitive — so it forwards Authorization
// across a port change on the same name; measured, a 127.0.0.1:A -> 127.0.0.1:B
// redirect kept Basic auth while this policy dropped the identity. Full host
// equality (name AND port) is the right rule for an identity assertion:
// a different port is a different service. Subdomains are not trusted either,
// for the same reason — this header is an identity assertion, not a session
// cookie, and "close enough" is not a property an identity should have.
//
// A same-name, different-port redirect therefore strips the identity and the
// scoped read that follows REFUSES visibly, which is the intended outcome:
// better a caller who is told their read was unscoped than one silently handed
// a credential to another service.
//
// The redirect itself is still followed — dropping the identity is enough,
// because a scoped read that arrives unscoped now REFUSES visibly
// (ReadScopeError) instead of quietly answering nothing.
func stripIdentityOnCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if len(via) > 0 && req.URL.Host != via[0].URL.Host {
		req.Header.Del(headerUserToken)
		// Not a secret — the tenant SECRET rides Authorization, which net/http
		// strips itself — but these two name the caller to whoever receives
		// them, and there is no reason for a host the caller never chose to
		// learn it. Dropped on the same hop, for the same reason.
		req.Header.Del("X-Client-ID")
		req.Header.Del("X-Axonflow-Client")
	}
	return nil
}

// AsReadScopeError unwraps err and returns the typed ReadScopeError if the
// chain carries one. Convenience for callers that do not want to import
// errors and declare the local pointer.
func AsReadScopeError(err error) (*ReadScopeError, bool) {
	var rse *ReadScopeError
	if errors.As(err, &rse) {
		return rse, true
	}
	return nil, false
}
