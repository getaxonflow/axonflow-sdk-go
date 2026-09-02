package axonflow

// The platform-identity relay (axonflow-enterprise#3660): `edition` and the
// platform's own `deployment_mode`, read from the SAME /health response the
// version and the tier already come from, and forwarded on the heartbeat.
//
// Every case here is driven through probePlatformHealth or through a real POST
// captured off the wire — never by setting a struct field and reading it back.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPlatformIdentityProbe covers what the probe learns, and — the half that
// matters more — what it refuses to learn.
func TestPlatformIdentityProbe(t *testing.T) {
	cases := []struct {
		name                            string
		body                            string
		wantVersion, wantTier           *string
		wantEdition, wantDeploymentMode *string
		why                             string
	}{
		{
			name:               "all four members",
			body:               `{"version":"10.4.0","tier":"Enterprise","edition":"enterprise","deployment_mode":"in-vpc-banking"}`,
			wantVersion:        strPtr("10.4.0"),
			wantTier:           strPtr("Enterprise"),
			wantEdition:        strPtr("enterprise"),
			wantDeploymentMode: strPtr("in-vpc-banking"),
			why:                "the happy path",
		},
		{
			name:        "a pre-10.4.0 platform carries neither new member",
			body:        `{"version":"10.3.0","tier":"Enterprise"}`,
			wantVersion: strPtr("10.3.0"),
			wantTier:    strPtr("Enterprise"),
			why: "ABSENT MUST STAY ABSENT. Most platforms in the field are pre-10.4.0; " +
				"inventing `community` for them would put a false claim about a customer's " +
				"deployment on the wire, at scale",
		},
		{
			name:               "deployment_mode without edition",
			body:               `{"version":"10.4.0","deployment_mode":"saas"}`,
			wantVersion:        strPtr("10.4.0"),
			wantDeploymentMode: strPtr("saas"),
			why:                "each member is promoted INDEPENDENTLY; one absent must not discard another",
		},
		{
			name:        "a numeric edition does not discard the version or the tier",
			body:        `{"version":"10.4.0","tier":"Enterprise","edition":42}`,
			wantVersion: strPtr("10.4.0"),
			wantTier:    strPtr("Enterprise"),
			why: "THE REGRESSION THIS DECODER EXISTS TO PREVENT. With a typed struct one " +
				"badly-typed member fails the WHOLE decode, so a new dimension would silently " +
				"take down fields that worked before it landed",
		},
		{
			name:               "an object deployment_mode does not discard edition",
			body:               `{"edition":"community","deployment_mode":{"name":"saas"}}`,
			wantEdition:        strPtr("community"),
			wantDeploymentMode: nil,
			why:                "same property, the other direction",
		},
		{
			name:        "null and empty are not learned",
			body:        `{"version":"10.4.0","edition":null,"deployment_mode":""}`,
			wantVersion: strPtr("10.4.0"),
			why: "an explicit null and an explicit empty string are both `the platform did " +
				"not say`, and must not become a pointer to \"\"",
		},
		{
			name:        "a boolean edition is not coerced",
			body:        `{"version":"10.4.0","edition":true}`,
			wantVersion: strPtr("10.4.0"),
			why:         "coercion would put \"true\" in the receiver's unknown bucket as though a platform said it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTierHealthServer(t, http.StatusOK, tc.body)
			ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
			defer cancel()

			probe := probePlatformHealth(ctx, endpoint)

			assertStrPtr(t, "PlatformVersion", probe.PlatformVersion, tc.wantVersion)
			assertStrPtr(t, "LicenseTier", probe.LicenseTier, tc.wantTier)
			assertStrPtr(t, "Edition", probe.Edition, tc.wantEdition)
			assertStrPtr(t, "PlatformDeploymentMode", probe.PlatformDeploymentMode, tc.wantDeploymentMode)
			if t.Failed() {
				t.Logf("why this case exists: %s", tc.why)
			}
		})
	}
}

// TestUnreachableOrBrokenHealthYieldsNothing is the unhappy path as a
// first-class case rather than an appendix. It is also the COMMON real-world
// state: a client pointed at an endpoint that is down, behind an auth proxy,
// or not AxonFlow at all.
func TestUnreachableOrBrokenHealthYieldsNothing(t *testing.T) {
	t.Run("non-2xx", func(t *testing.T) {
		endpoint := newTierHealthServer(t, http.StatusInternalServerError,
			`{"version":"10.4.0","edition":"enterprise","deployment_mode":"saas"}`)
		ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
		defer cancel()
		probe := probePlatformHealth(ctx, endpoint)
		if probe.Edition != nil || probe.PlatformDeploymentMode != nil {
			t.Errorf("a 500 yielded %+v; a body we were not served must not be trusted", probe)
		}
	})

	t.Run("non-JSON", func(t *testing.T) {
		endpoint := newTierHealthServer(t, http.StatusOK, `<html>503 from a proxy</html>`)
		ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
		defer cancel()
		probe := probePlatformHealth(ctx, endpoint)
		if probe.Edition != nil || probe.PlatformDeploymentMode != nil {
			t.Errorf("an HTML body yielded %+v", probe)
		}
	})

	t.Run("endpoint refuses the connection", func(t *testing.T) {
		// Bind, capture the URL, close: nothing is listening.
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
		defer cancel()
		probe := probePlatformHealth(ctx, url)
		if probe.Edition != nil || probe.PlatformDeploymentMode != nil {
			t.Errorf("an unreachable endpoint yielded %+v", probe)
		}
	})

	t.Run("empty endpoint", func(t *testing.T) {
		probe := probePlatformHealth(context.Background(), "")
		if probe.Edition != nil || probe.PlatformDeploymentMode != nil {
			t.Errorf("an unconfigured endpoint yielded %+v", probe)
		}
	})
}

// TestHostileHealthValuesAreRelayedSafely is the DoD's hostile-but-valid case.
//
// A quote, a backslash, a newline and 10 KB are all legal JSON strings, and a
// platform an SDK was pointed at can return any of them. The relay must produce
// a payload the receiver can still parse, with every OTHER field intact — the
// failure mode being guarded against is the one that silently killed an entire
// plugin heartbeat when a /health value contained a quote.
func TestHostileHealthValuesAreRelayedSafely(t *testing.T) {
	hostile := map[string]string{
		"double quote":  `a"b`,
		"backslash":     `a\b`,
		"newline":       "a\nb",
		"tab":           "a\tb",
		"json fragment": `","org_id":"pwned`,
		"unicode":       "🙂",
		"10KB":          strings.Repeat("x", 10*1024),
	}
	for name, v := range hostile {
		t.Run(name, func(t *testing.T) {
			// Built with encoding/json so the FIXTURE is a legal document: the
			// question is what the relay does with a legal document carrying a
			// hostile value, not whether one can be written.
			body, err := json.Marshal(map[string]string{
				"version": "10.4.0", "tier": "Enterprise",
				"edition": v, "deployment_mode": v,
			})
			if err != nil {
				t.Fatalf("marshal fixture: %v", err)
			}
			endpoint := newTierHealthServer(t, http.StatusOK, string(body))

			ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
			defer cancel()
			probe := probePlatformHealth(ctx, endpoint)

			// Relayed VERBATIM. Folding or sanitising here would mask what the
			// platform actually said; the receiver normalises to a closed enum
			// and bounds the length, which is where that belongs.
			if probe.Edition == nil || *probe.Edition != v {
				t.Errorf("edition = %v, want the value verbatim", probe.Edition)
			}

			// The payload must still serialise into something parseable, with
			// the structural fields untouched.
			out, err := json.Marshal(telemetryPayload{
				TelemetryType: "sdk", SDK: "go", SDKVersion: Version,
				Edition: probe.Edition, PlatformDeploymentMode: probe.PlatformDeploymentMode,
				OrgID: "acme-corp",
			})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			var round map[string]any
			if err := json.Unmarshal(out, &round); err != nil {
				t.Fatalf("the payload no longer parses — a value escaped the serializer: %v", err)
			}
			if round["sdk"] != "go" || round["org_id"] != "acme-corp" {
				t.Errorf("a hostile value broke out of its field: %s", out)
			}
		})
	}
}

// TestPingCarriesTheRelayedIdentity is the end-to-end assertion, taken off the
// WIRE: a real /health served, a real ping POSTed, the captured body decoded.
//
// It also pins the mapping that is easiest to get wrong: /health's
// `deployment_mode` member must land on `platform_deployment_mode`, while the
// ping's own `deployment_mode` keeps carrying the topology this SDK derived
// from its endpoint URL.
func TestPingCarriesTheRelayedIdentity(t *testing.T) {
	var captured []byte
	checkpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"latest_version":""}`))
	}))
	defer checkpoint.Close()

	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy","version":"10.4.0","tier":"Enterprise",` +
			`"edition":"enterprise","deployment_mode":"in-vpc-enterprise"}`))
	}))
	defer platform.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", checkpoint.URL)
	t.Setenv("AXONFLOW_TELEMETRY", "")

	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: platform.URL}}
	if err := c.sendTelemetryPingNow(context.Background()); err != nil {
		t.Fatalf("sendTelemetryPingNow: %v", err)
	}

	var p map[string]any
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("decode captured ping: %v\nbody=%s", err, captured)
	}

	if got, _ := p["edition"].(string); got != "enterprise" {
		t.Errorf("edition = %q, want enterprise\nbody=%s", got, captured)
	}
	if got, _ := p["platform_deployment_mode"].(string); got != "in-vpc-enterprise" {
		t.Errorf("platform_deployment_mode = %q, want in-vpc-enterprise\nbody=%s", got, captured)
	}
	// THE MAPPING PIN. `deployment_mode` is the SDK's own topology, derived from
	// the endpoint URL — an httptest server is 127.0.0.1, so self_hosted. If the
	// relay ever wrote /health's member here instead, this reads
	// "in-vpc-enterprise" and every existing deployment-mode dashboard is wrong.
	if got, _ := p["deployment_mode"].(string); got != DeploymentModeSelfHosted {
		t.Errorf("deployment_mode = %q, want %q — /health's member must map onto "+
			"platform_deployment_mode, NEVER onto this field\nbody=%s",
			got, DeploymentModeSelfHosted, captured)
	}
	// The pre-existing relays are undisturbed.
	if got, _ := p["license_tier"].(string); got != "Enterprise" {
		t.Errorf("license_tier = %q, want Enterprise", got)
	}
	if got, _ := p["platform_version"].(string); got != "10.4.0" {
		t.Errorf("platform_version = %q, want 10.4.0", got)
	}
}

// TestPingOmitsWhatItDidNotLearn: a platform that reports neither new member
// must produce a ping with neither KEY, not one with empty values. The receiver
// distinguishes "not reported" from every real value by the key's absence
// alone.
func TestPingOmitsWhatItDidNotLearn(t *testing.T) {
	var captured []byte
	checkpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer checkpoint.Close()

	// A pre-10.4.0 platform: version and tier, nothing else.
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"10.3.0","tier":"Community"}`))
	}))
	defer platform.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", checkpoint.URL)
	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: platform.URL}}
	if err := c.sendTelemetryPingNow(context.Background()); err != nil {
		t.Fatalf("sendTelemetryPingNow: %v", err)
	}

	var p map[string]any
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"edition", "platform_deployment_mode"} {
		if v, present := p[k]; present {
			t.Errorf("key %q is present as %#v; a platform that did not report it must leave "+
				"the key OFF the wire, so the receiver can tell \"not reported\" from a value\nbody=%s",
				k, v, captured)
		}
	}
	// The ping is still SENT, and still carries what it did learn.
	if got, _ := p["license_tier"].(string); got != "Community" {
		t.Errorf("license_tier = %q; the ping must still carry what it did learn", got)
	}
}

// TestHealthIsFetchedExactlyOncePerPing guards the design rule for the whole
// lane: the new dimensions ride the response ALREADY being fetched. A second
// request would double the telemetry path's blocking budget and its failure
// surface, for data that was in the first one.
func TestHealthIsFetchedExactlyOncePerPing(t *testing.T) {
	var healthHits int
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthHits++
		}
		_, _ = w.Write([]byte(`{"version":"10.4.0","tier":"Enterprise","edition":"enterprise","deployment_mode":"saas"}`))
	}))
	defer platform.Close()

	checkpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer checkpoint.Close()

	t.Setenv("AXONFLOW_CHECKPOINT_URL", checkpoint.URL)
	c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: platform.URL}}
	if err := c.sendTelemetryPingNow(context.Background()); err != nil {
		t.Fatalf("sendTelemetryPingNow: %v", err)
	}

	if healthHits != 1 {
		t.Errorf("/health was fetched %d times for ONE ping; the identity members must ride the "+
			"response already being fetched for the version and the tier", healthHits)
	}
}
