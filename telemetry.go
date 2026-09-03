package axonflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	defaultCheckpointURL = "https://checkpoint.getaxonflow.com/v1/ping"
	telemetryTimeout     = 3 * time.Second
)

// telemetryPayload is the JSON body sent to the checkpoint endpoint.
type telemetryPayload struct {
	// TelemetryType discriminates this ping for the v1 schema receiver
	// (axonflow-enterprise#2008). Always "sdk" for clients of this package.
	TelemetryType   string  `json:"telemetry_type"`
	SDK             string  `json:"sdk"`
	SDKVersion      string  `json:"sdk_version"`
	PlatformVersion *string `json:"platform_version"`
	OS              string  `json:"os"`
	Arch            string  `json:"arch"`
	RuntimeVersion  string  `json:"runtime_version"`
	// DeploymentMode is the v1 schema topology dimension:
	// "self_hosted" | "community_saas" | "unknown". Derived from the
	// configured endpoint host plus the explicit AXONFLOW_TRY=1
	// override; see ClassifyDeploymentMode.
	DeploymentMode string `json:"deployment_mode"`
	// EndpointType: SDK-derived classification of the configured endpoint.
	// One of: "localhost", "private_network", "remote", "unknown". See
	// ClassifyEndpoint. The raw URL is never sent. Issue #1525.
	EndpointType string   `json:"endpoint_type"`
	Features     []string `json:"features"`
	InstanceID   string   `json:"instance_id"`
	// Stream classifies the heartbeat sub-stream. Sandbox-mode clients emit
	// "sandbox" so analytics can distinguish dev/test pings from production
	// pings without conflating them; production-mode clients omit the field
	// and the server defaults to "heartbeat". The wire-allowlist is enforced
	// server-side — see checkpoint-service IsValidIncomingStream.
	Stream string `json:"stream,omitempty"`
	// OrgID identifies the deployment's organization (#2277). Two sources,
	// in precedence order: the ORG_ID env var when set (the operator's
	// explicit configuration on self-hosted deployments, or the cs_<uuid>
	// tenant identifier on Community SaaS); otherwise the "local-dev-org"
	// sentinel. Always emitted. See axonflow-landing/content/privacy.html
	// for the customer-facing commitment that covers this field.
	OrgID string `json:"org_id"`
	// LicenseTier is the licence tier the connected platform reported on
	// its own /health response ("community", "evaluation", "Enterprise",
	// the csaas "Plus" alias for EnterprisePlus, or the transient
	// "starting"). Coarse adoption signal only — no licence key, no
	// expiry, no seat count, no customer name. Issue #3619.
	//
	// THREE SIMILARLY-NAMED CONCEPTS LIVE NEARBY. Do not merge them:
	//
	//  1. DeploymentMode (this struct, `deployment_mode`) — SDK-derived
	//     TOPOLOGY: self_hosted | community_saas | unknown, classified
	//     from the endpoint URL. Says where the platform runs.
	//  2. The platform's own DEPLOYMENT_MODE env var — a server-side
	//     setting that decides which schema/tables the binary uses. Never
	//     read by this SDK and never sent on this field.
	//  3. LicenseTier (this field, `license_tier`) — what the platform
	//     REPORTED about its own licensing, for adoption analytics.
	//
	// ITEM 3 IS NOT AN ENTITLEMENT FACT. This SDK relays whatever /health
	// returned, and the receiver cannot verify the relay: whoever operates
	// the endpoint the client was pointed at controls the value completely.
	// It must never gate entitlement, unlock a feature, or enter any
	// authorization or billing decision. See axonflow-enterprise#3619.
	//
	// A community-mode binary can run on any topology and vice versa, so
	// neither field is derivable from the other.
	//
	// Sent verbatim: the value is reported exactly as /health returned it.
	// Casing and alias folding is the receiver's job (checkpoint-service
	// NormalizeLicenseTier), deliberately NOT duplicated here — a client
	// that folded locally would silently mask a platform emitting a tier
	// this SDK build predates.
	//
	// nil (omitted from the wire) means NOT LEARNED — /health unreachable,
	// non-2xx, unparseable, or carrying no "tier" key. Absent must never
	// become a known value: emitting "community" for a platform we could
	// not reach would be a false claim about a customer's deployment. The
	// receiver preserves omission for legacy pings, so an omitted field
	// reads as "unknown", not as any particular tier.
	LicenseTier *string `json:"license_tier,omitempty"`
	// Edition is the BUILD the connected platform reported on its own /health:
	// "community" or "enterprise". Relayed verbatim, and it rides the SAME
	// /health response the version and the tier already come from - no new
	// request. Issue axonflow-enterprise#3660.
	//
	// IT IS NOT AN ENTITLEMENT FACT, for the reason spelled out on LicenseTier
	// above: whoever operates the endpoint this client was pointed at controls
	// the value completely, and this SDK relays it unverified. Adoption
	// analytics only - never gate a feature, an authorization decision or a
	// billing decision on it.
	//
	// It is also NOT derivable from anything else here. The Community-SaaS
	// fleet runs the ENTERPRISE build against the community-saas schema, so
	// neither DeploymentMode nor LicenseTier implies it.
	//
	// nil (omitted) means NOT LEARNED - /health unreachable, non-2xx,
	// unparseable, or carrying no "edition" key. Absent must never become a
	// value: emitting "community" for a platform we could not reach would be a
	// false claim about a customer's deployment.
	Edition *string `json:"edition,omitempty"`
	// PlatformDeploymentMode is the connected platform's OWN DEPLOYMENT_MODE
	// setting, as it reported it on /health under the member name
	// `deployment_mode`.
	//
	// READ THE FIELD NAMES CAREFULLY - THIS IS THE TRAP THIS CONTRACT IS MOST
	// LIKELY TO BE GOT WRONG ON. The /health member is called
	// `deployment_mode` because there the platform is describing ITSELF. On
	// this ping, `deployment_mode` (the field above) already means something
	// else entirely: the TOPOLOGY bucket this SDK derives from the endpoint URL
	// it was configured with. They are different dimensions, and mapping
	// /health's member onto the topology field would overwrite a value every
	// existing dashboard reads.
	//
	// Same trust boundary and same nil semantics as Edition.
	PlatformDeploymentMode *string `json:"platform_deployment_mode,omitempty"`
}

// DeploymentMode classifications for telemetry (v1 schema, axonflow-enterprise#2008).
const (
	DeploymentModeSelfHosted    = "self_hosted"
	DeploymentModeCommunitySaaS = "community_saas"
	DeploymentModeUnknown       = "unknown"
)

// ClassifyDeploymentMode classifies the configured AxonFlow endpoint into
// the v1 deployment-mode allowlist (self_hosted | community_saas | unknown).
// Community-SaaS is detected from either an *.try.getaxonflow.com host or
// AXONFLOW_TRY=1 (the explicit override path for tenants behind a custom
// hostname proxying try.getaxonflow.com). Empty/unparseable endpoint
// resolves to "unknown" rather than defaulting to "self_hosted".
func ClassifyDeploymentMode(endpoint string) string {
	if os.Getenv("AXONFLOW_TRY") == "1" {
		return DeploymentModeCommunitySaaS
	}
	if endpoint == "" {
		return DeploymentModeUnknown
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return DeploymentModeUnknown
	}
	host := strings.ToLower(u.Hostname())
	if host == "try.getaxonflow.com" || strings.HasSuffix(host, ".try.getaxonflow.com") {
		return DeploymentModeCommunitySaaS
	}
	return DeploymentModeSelfHosted
}

// OrgIDLocalDevSentinel is emitted on the telemetry wire when ORG_ID is
// unset — the default-config Community-mode developer case. See #2277.
const OrgIDLocalDevSentinel = "local-dev-org"

// telemetryOrgID returns the org_id value to emit on the next telemetry
// ping. Reads ORG_ID from the environment (the operator's explicit
// configuration for self-hosted deployments, or the cs_<uuid> tenant
// identifier on Community SaaS) and falls back to OrgIDLocalDevSentinel
// when unset. Always returns a non-empty string. See #2277.
func telemetryOrgID() string {
	if v := os.Getenv("ORG_ID"); v != "" {
		return v
	}
	return OrgIDLocalDevSentinel
}

// EndpointType classifications for telemetry.
const (
	EndpointTypeLocalhost      = "localhost"
	EndpointTypePrivateNetwork = "private_network"
	EndpointTypeRemote         = "remote"
	EndpointTypeUnknown        = "unknown"
)

// ClassifyEndpoint classifies the configured AxonFlow endpoint URL into one
// of localhost | private_network | remote | unknown.
//
// The raw URL is never sent to the checkpoint service — only the classification.
// See issue #1525.
//
//   - "localhost": localhost, 127/8, ::1, 0.0.0.0, *.localhost
//   - "private_network": RFC1918 v4, link-local (169.254/16), ULA (fc00::/7),
//     and the suffixes .local, .internal, .lan, .intranet
//   - "remote": everything else
//   - "unknown": on parse failure
//
// As of v8.0 the legacy "community-saas" return value is removed —
// deployment topology lives on `deployment_mode` (see ClassifyDeploymentMode)
// per the v1 schema (axonflow-enterprise#2008).
func ClassifyEndpoint(endpoint string) string {
	if endpoint == "" {
		return EndpointTypeUnknown
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return EndpointTypeUnknown
	}
	host := strings.ToLower(u.Hostname())

	if host == "localhost" || host == "0.0.0.0" || strings.HasSuffix(host, ".localhost") {
		return EndpointTypeLocalhost
	}
	for _, suffix := range []string{".local", ".internal", ".lan", ".intranet"} {
		if strings.HasSuffix(host, suffix) {
			return EndpointTypePrivateNetwork
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return EndpointTypeRemote
	}
	if ip.IsLoopback() {
		return EndpointTypeLocalhost
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return EndpointTypePrivateNetwork
	}
	return EndpointTypeRemote
}

// telemetryResponse is the JSON response from the checkpoint endpoint.
type telemetryResponse struct {
	LatestVersion string `json:"latest_version"`
}

// healthProbe carries what a single /health fetch established. Each field is
// INDEPENDENT: a response that carries one but not the other yields a
// partially-populated result rather than discarding both. A nil field means
// "not learned" and is omitted from the wire — it never degrades to a
// default (see telemetryPayload.LicenseTier).
type healthProbe struct {
	PlatformVersion *string
	LicenseTier     *string
	// Edition / PlatformDeploymentMode - the platform-identity members added in
	// axonflow-enterprise#3660. Independent of the two above and of each other:
	// a platform that reports some of them and not others yields a partially
	// populated probe rather than nothing.
	Edition *string
	// PlatformDeploymentMode is read from the /health member named
	// `deployment_mode` and travels to the ping field named
	// `platform_deployment_mode`. The rename is the whole point - see the
	// telemetryPayload field doc.
	PlatformDeploymentMode *string
}

// maxHealthBodyBytes bounds the /health response the probe will parse.
// The real response is a few hundred bytes; 1 MiB is orders of magnitude
// above any legitimate body while capping how much a misbehaving or hostile
// endpoint can make the telemetry goroutine buffer. Exceeding it fails the
// decode, which fails open exactly like every other health-probe failure —
// both fields stay nil and the ping is still sent without them.
const maxHealthBodyBytes = 1 << 20

// probePlatformHealth calls the agent's /health endpoint ONCE and extracts
// every telemetry dimension it carries. Returns a zero healthProbe (both
// fields nil) on any failure — unreachable endpoint, non-2xx, unparseable
// body — so telemetry degrades to omitting the fields and never fails the
// ping or surfaces an error to the caller.
//
// The caller's context controls the deadline so the health probe and the
// checkpoint POST share one budget — preventing the two 3-second timeouts
// from stacking into ~6s of blocking on unreachable endpoints (issue #1693).
//
// This is the SDK's only /health fetch on the telemetry path; the licence
// tier rides along on the response already being fetched for the version.
// Adding a second request here would double the telemetry path's blocking
// budget and its failure surface — do not.
func probePlatformHealth(ctx context.Context, endpoint string) healthProbe {
	if endpoint == "" {
		return healthProbe{}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/health", nil)
	if err != nil {
		return healthProbe{}
	}

	// NO REDIRECTS ON THE TELEMETRY PATH. A 30x from /health would otherwise be
	// followed silently, and every value promoted below — the version, the tier,
	// the edition and the platform's deployment mode — would then describe the
	// REDIRECT TARGET rather than the endpoint the caller configured. A captive
	// portal, a misconfigured proxy or an http->https hop is enough to make the
	// heartbeat report a platform the user never pointed at.
	//
	// ErrUseLastResponse hands back the 30x itself, which fails the
	// StatusOK check below and yields an empty probe — "not learned", the
	// honest answer. Same precedent as the request client in axonflow.go.
	resp, err := (&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}).Do(req)
	if err != nil {
		return healthProbe{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return healthProbe{}
	}

	// Decoded into a generic map rather than a typed struct ON PURPOSE.
	//
	// With a struct carrying both `version` and `tier`, ONE badly-typed
	// member fails the WHOLE decode — so a platform answering
	// {"version":"10.3.0","tier":42} would have made this return nothing and
	// silently dropped platform_version, a field that worked before the tier
	// was added. A new dimension must not be able to regress an existing one.
	//
	// Decoding per-field also matches the Python, TypeScript and Java SDKs,
	// which all type-check each member individually. Bounded by
	// maxHealthBodyBytes above, so the map cannot grow unbounded.
	var health map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHealthBodyBytes)).Decode(&health); err != nil {
		return healthProbe{}
	}

	// maxRelayedValueBytes bounds every value promoted out of /health.
	//
	// WHY A DROP AND NOT A TRUNCATION. The checkpoint refuses a request body
	// over 64 KiB. A single 70 KB value from a hostile or broken /health
	// therefore produces a ~72 KB ping that is rejected WHOLE — the version,
	// the tier, the org id, every dimension lost, not just the oversized one —
	// and because the stamp is only written on a 2xx, the SDK retries that
	// same doomed request at every gate run for as long as /health keeps
	// answering that way.
	//
	// Dropping the offending value alone keeps the ping under the limit and
	// preserves every other dimension. It is dropped rather than truncated
	// because a truncated value is a value the platform never reported: 64
	// bytes of a 70 KB string is not a licence tier, and relaying it would put
	// a fabricated observation on the wire. Absent is the honest answer, and
	// this path already has a well-defined meaning for absent.
	//
	// 64 bytes is the same bound the receiver applies to these coarse enums,
	// and ~3.5x the longest legitimate value.
	const maxRelayedValueBytes = 64

	// Each field is promoted independently, and only when it is a non-empty
	// STRING. An absent key, a non-string value, and an explicit "" are all
	// "not learned" — the pointer stays nil rather than becoming a pointer to
	// "", which would put a meaningless empty value on the wire despite
	// omitempty, or a coerced value that misrepresents what the platform said.
	var probe healthProbe
	// learned promotes one member: a non-empty string, within the size bound.
	// One helper rather than four copies of the same two conditions — a bound
	// applied to three of four fields is the shape that gets found in
	// production by the field it was not applied to.
	learned := func(key string) *string {
		v, ok := health[key].(string)
		if !ok || v == "" || len(v) > maxRelayedValueBytes {
			return nil
		}
		return &v
	}

	if p := learned("version"); p != nil {
		probe.PlatformVersion = p
	}
	// Verbatim, including the transient "starting" the agent returns before its
	// licence is validated. "starting" is a real signal the receiver buckets
	// deliberately, not an error to filter client-side.
	if p := learned("tier"); p != nil {
		probe.LicenseTier = p
	}
	if p := learned("edition"); p != nil {
		probe.Edition = p
	}
	// NOTE THE NAME CHANGE, AND THAT IT IS DELIBERATE. The /health member is
	// `deployment_mode` (the platform describing itself); the wire field is
	// `platform_deployment_mode`. This SDK's OWN `deployment_mode` is a
	// different dimension - the topology it derives from its endpoint URL - and
	// promoting /health's member into it would overwrite a value every existing
	// dashboard reads.
	if p := learned("deployment_mode"); p != nil {
		probe.PlatformDeploymentMode = p
	}
	return probe
}

// generateInstanceID creates a random UUID v4 string without external dependencies.
func generateInstanceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version 4
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// isTelemetryEnabled determines whether telemetry should be sent for this client.
//
// `AXONFLOW_TELEMETRY=off` in the environment is the SOLE opt-out path.
// Telemetry is otherwise ON by default, regardless of mode (sandbox / production
// / anything else). Sandbox-mode pings are tagged Stream="sandbox" in the
// payload so analytics can still distinguish them — see telemetryPayload.Stream.
//
// Historical context: v7.x supported a `TelemetryEnabled *bool` config field
// and a `mode != "sandbox"` default-suppression rule. Both were removed in v8.0
// to leave a single, ops-controlled opt-out lever and avoid silent
// suppression that masks real adoption signal. See CHANGELOG v8.0.0.
//
// DO_NOT_TRACK is intentionally NOT honored. It is commonly inherited from
// host tools and developer environments (CLIs like Codex and Claude Code
// inject it unconditionally), which makes it an unreliable expression of
// user intent for AxonFlow telemetry.
func (c *AxonFlowClient) isTelemetryEnabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("AXONFLOW_TELEMETRY")), "off") {
		return false
	}
	return true
}

// sendTelemetryPing is a thin compatibility wrapper around the gated path
// used exclusively by older unit tests in this package. It checks
// isTelemetryEnabled and, if enabled, sends a single ping via
// sendTelemetryPingNow under a bounded context. It does NOT consult the
// 7-day stamp file — that's the heartbeat orchestrator's job
// (maybeSendHeartbeat). Production callers should always go through
// NewClient → maybeSendHeartbeat instead of calling this directly.
func (c *AxonFlowClient) sendTelemetryPing() {
	if !c.isTelemetryEnabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()
	_ = c.sendTelemetryPingNow(ctx)
}

// sendTelemetryPingNow sends a single telemetry ping to the checkpoint
// service under the caller-provided context deadline. Returns nil if the
// POST landed (HTTP 2xx) or a non-nil error otherwise. The caller is
// responsible for the gating decision (whether to send at all) — this
// function does NOT consult AXONFLOW_TELEMETRY, isTelemetryEnabled, the
// stamp file, or any rate-limit state. That separation lets the heartbeat
// orchestrator (maybeSendHeartbeat) make the gating decision once and
// only update the stamp when this returns nil — implementing the
// "stamp-on-delivery" contract.
//
// The /health probe and the checkpoint POST share the caller's context so
// the total blocking time is bounded by ctx — no stacked sub-timeouts.
// See issue #1693 for the original short-lived-process delivery fix.
func (c *AxonFlowClient) sendTelemetryPingNow(ctx context.Context) error {
	log.Printf("[AxonFlow] Telemetry enabled. Opt out: AXONFLOW_TELEMETRY=off | https://docs.getaxonflow.com/docs/telemetry")

	// Determine the checkpoint URL.
	checkpointURL := os.Getenv("AXONFLOW_CHECKPOINT_URL")
	if checkpointURL == "" {
		checkpointURL = defaultCheckpointURL
	}

	// v1 telemetry-schema (axonflow-enterprise#2008) deployment_mode classifier.
	// The prior config.Mode-based "production"/"development" split is removed —
	// the dimension now reflects deployment topology only: self_hosted |
	// community_saas | unknown.
	deploymentMode := ClassifyDeploymentMode(c.config.Endpoint)

	// One /health fetch supplies both platform_version and license_tier
	// (uses the shared deadline). Re-read on every heartbeat rather than
	// cached for the process lifetime: a licence can be applied to, or
	// expire on, a running platform, and a cached tier would keep
	// reporting the pre-change tier for as long as the client lives.
	probe := probePlatformHealth(ctx, c.config.Endpoint)

	// Stream classifier: sandbox-mode clients self-tag so analytics can
	// distinguish dev/test pings from production. Production-mode clients
	// omit the field and the server defaults to "heartbeat". The empty
	// default + omitempty preserves byte-identical wire shape for the
	// production-mode case relative to v7.x.
	stream := ""
	if c.config.Mode == "sandbox" {
		stream = "sandbox"
	}

	payload := telemetryPayload{
		TelemetryType:   "sdk",
		SDK:             "go",
		SDKVersion:      Version,
		PlatformVersion: probe.PlatformVersion,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		RuntimeVersion:  strings.TrimPrefix(runtime.Version(), "go"),
		DeploymentMode:  deploymentMode,
		EndpointType:    ClassifyEndpoint(c.config.Endpoint),
		Features:        []string{},
		InstanceID:      generateInstanceID(),
		Stream:          stream,
		OrgID:           telemetryOrgID(),
		LicenseTier:     probe.LicenseTier,
		// Forwarded verbatim, omitted when not learned. NOTE that /health's
		// `deployment_mode` member lands on `platform_deployment_mode` here,
		// NOT on DeploymentMode above, which is the topology this SDK derived
		// from its own endpoint URL. See the field docs.
		Edition:                probe.Edition,
		PlatformDeploymentMode: probe.PlatformDeploymentMode,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// POST uses whatever budget remains after the health probe.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, checkpointURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// NO REDIRECTS, AND HERE IT IS A CORRECTNESS BUG RATHER THAN A PRIVACY ONE.
	//
	// net/http does not re-POST across a 301/302/303: it converts the request
	// to a bodyless GET. So a redirect on the checkpoint POST produces a 200
	// for a request that carried NO PAYLOAD, the code below reads that 200 as a
	// successful delivery, and the caller writes the 7-day stamp — leaving the
	// installation silent for a week on a ping that was never actually sent.
	// A 200 that means "we delivered nothing" is the worst possible shape for
	// this path, because it is indistinguishable from success at every layer
	// above.
	//
	// ErrUseLastResponse surfaces the 30x itself, which fails the 2xx check and
	// leaves the stamp unwritten, so the next gate run retries.
	client := &http.Client{
		Timeout: telemetryTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("checkpoint returned HTTP %d", resp.StatusCode)
	}

	// Parse response for version check (debug mode only).
	if c.config.Debug {
		var telResp telemetryResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&telResp); decErr == nil {
			if telResp.LatestVersion != "" && telResp.LatestVersion != Version {
				log.Printf("[AxonFlow] A newer SDK version is available: %s (current: %s)", telResp.LatestVersion, Version)
			}
		}
	}
	return nil
}
