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

			// Relayed VERBATIM. Folding or sanitising a WITHIN-BOUNDS value here
			// would mask what the platform actually said; the receiver
			// normalises to a closed enum, which is where that belongs.
			//
			// The 10 KB case that used to live in this table moved to
			// TestOversizedHealthValueIsDroppedWholeNotTruncated when the size
			// bound landed: an oversized value is DROPPED, not relayed, because
			// one 70 KB member pushes the whole ping past the checkpoint's
			// 64 KiB limit and costs every other dimension with it. Hostile
			// CONTENT and hostile SIZE are different contracts, and keeping them
			// in one table would have hidden that.
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

// TestHealthRedirectIsNotFollowed — a 30x from /health must yield NOTHING.
//
// Following it would make every value the probe promotes describe the REDIRECT
// TARGET rather than the endpoint the caller configured: a captive portal, a
// misconfigured proxy or an http->https hop is enough to make the heartbeat
// report a platform the user never pointed at. The redirect target here serves
// a complete, plausible /health precisely so that a followed redirect would
// look like a successful probe rather than an error.
func TestHealthRedirectIsNotFollowed(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		_, _ = w.Write([]byte(`{"version":"99.99.99","tier":"EnterprisePlus",` +
			`"edition":"enterprise","deployment_mode":"saas"}`))
	}))
	defer target.Close()

	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound,
		http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			targetHits = 0
			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/health", code)
			}))
			defer redirector.Close()

			ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
			defer cancel()
			probe := probePlatformHealth(ctx, redirector.URL)

			if probe.PlatformVersion != nil || probe.LicenseTier != nil ||
				probe.Edition != nil || probe.PlatformDeploymentMode != nil {
				t.Errorf("a %d was followed and the probe relayed the redirect target's values: %+v",
					code, probe)
			}
			if targetHits != 0 {
				t.Errorf("the redirect target was fetched %d times; the telemetry path must not "+
					"follow a redirect off the configured endpoint", targetHits)
			}
		})
	}
}

// TestCheckpointRedirectDoesNotLookLikeDelivery is the more dangerous half.
//
// net/http does NOT re-POST across a 301/302/303 — it converts the request to a
// bodyless GET. So a redirect on the checkpoint POST yields a 200 for a request
// that carried NO PAYLOAD, and a caller that reads that 200 as success writes
// the 7-day stamp, leaving the installation silent for a week on a ping that
// was never sent. The redirect target here answers 200 with a normal checkpoint
// body, so a followed redirect is indistinguishable from success unless the
// client refuses to follow it.
func TestCheckpointRedirectDoesNotLookLikeDelivery(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound,
		http.StatusSeeOther, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var gotBodyless bool
			var targetHits int
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits++
				b, _ := io.ReadAll(r.Body)
				if r.Method == http.MethodGet || len(b) == 0 {
					gotBodyless = true
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"latest_version":""}`))
			}))
			defer target.Close()

			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/v1/ping", code)
			}))
			defer redirector.Close()

			platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"10.4.0","tier":"Enterprise"}`))
			}))
			defer platform.Close()

			t.Setenv("AXONFLOW_CHECKPOINT_URL", redirector.URL+"/v1/ping")
			c := &AxonFlowClient{config: AxonFlowConfig{Endpoint: platform.URL}}

			err := c.sendTelemetryPingNow(context.Background())

			// THE CONTRACT: a redirect must be an ERROR, so the caller does not
			// write the stamp. A nil error here is the silent-for-7-days bug.
			if err == nil {
				t.Errorf("a %d on the checkpoint POST returned success; the caller would write "+
					"the 7-day stamp for a ping that was never delivered", code)
			}
			if targetHits != 0 {
				t.Errorf("the redirect was followed (%d hits, bodyless=%v)", targetHits, gotBodyless)
			}
		})
	}
}

// TestOversizedHealthValueIsDroppedWholeNotTruncated pins the ingest-limit
// guard.
//
// The checkpoint refuses a body over 64 KiB, so ONE 70 KB value from a hostile
// or broken /health produces a ping rejected WHOLE — every dimension lost, not
// just the oversized one — and, because the stamp is written only on a 2xx, the
// SDK retries that same doomed request at every gate run.
//
// The offending value is DROPPED, not truncated: 64 bytes of a 70 KB string is
// not a licence tier, and relaying it would put a fabricated observation on the
// wire. Every OTHER value must survive, which is the half that makes the drop
// worth doing rather than failing the probe outright.
func TestOversizedHealthValueIsDroppedWholeNotTruncated(t *testing.T) {
	huge := strings.Repeat("z", 70*1024)

	for _, field := range []string{"version", "tier", "edition", "deployment_mode"} {
		t.Run(field, func(t *testing.T) {
			body := map[string]string{
				"version": "10.4.0", "tier": "Enterprise",
				"edition": "enterprise", "deployment_mode": "saas",
			}
			body[field] = huge
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			endpoint := newTierHealthServer(t, http.StatusOK, string(raw))
			ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
			defer cancel()
			probe := probePlatformHealth(ctx, endpoint)

			got := map[string]*string{
				"version": probe.PlatformVersion, "tier": probe.LicenseTier,
				"edition": probe.Edition, "deployment_mode": probe.PlatformDeploymentMode,
			}
			for name, p := range got {
				if name == field {
					if p != nil {
						t.Errorf("%s survived at %d bytes; an oversized value must be dropped, "+
							"and never truncated into a value the platform did not report", name, len(*p))
					}
					continue
				}
				// EVERY OTHER VALUE SURVIVES. Dropping the whole probe would be
				// the easy fix and the wrong one: one bad member must not cost
				// the dimensions beside it.
				if p == nil {
					t.Errorf("an oversized %s discarded %s as well; only the offending value is dropped", field, name)
				}
			}

			// And the resulting ping is small enough to be accepted.
			payload, _ := json.Marshal(telemetryPayload{
				TelemetryType: "sdk", SDK: "go", SDKVersion: Version,
				PlatformVersion: probe.PlatformVersion, LicenseTier: probe.LicenseTier,
				Edition: probe.Edition, PlatformDeploymentMode: probe.PlatformDeploymentMode,
			})
			if len(payload) > 64*1024 {
				t.Errorf("the ping is %d bytes, over the checkpoint's 64 KiB limit — it would be "+
					"rejected whole and retried forever", len(payload))
			}
		})
	}
}
