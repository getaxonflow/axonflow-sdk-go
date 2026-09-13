package axonflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// provenanceJSON is the v11.0.0 provenance a platform stamps on a response.
const provenanceJSON = `"engine":"anchored","subject_type":"Client","policy_bundle":"sha256:bundle",` +
	`"legacy_validators":[{"validator":"india_pii","action":"masked"}]`

var wantValidators = []LegacyValidatorAction{{Validator: "india_pii", Action: "masked"}}

type provenance struct {
	Engine, SubjectType, PolicyBundle string
	LegacyValidators                  []LegacyValidatorAction
}

var wantProvenance = provenance{"anchored", "Client", "sha256:bundle", wantValidators}

func newTestClient(t *testing.T, handler http.HandlerFunc, onDeprecation func(PlatformRouteDeprecation)) *AxonFlowClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewClient(AxonFlowConfig{
		Endpoint:           server.URL,
		ClientID:           "test-client",
		ClientSecret:       "test-secret",
		OnRouteDeprecation: onDeprecation,
	})
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// TestV11ProvenanceDecodesOnEveryResponseType proves each response type the
// platform stamps reads all four provenance fields off the wire.
func TestV11ProvenanceDecodesOnEveryResponseType(t *testing.T) {
	cases := []struct {
		name string
		body string
		read func([]byte) (provenance, error)
	}{
		{"ClientResponse", `{"success":true,` + provenanceJSON + `}`, func(b []byte) (provenance, error) {
			var r ClientResponse
			err := json.Unmarshal(b, &r)
			return provenance{r.Engine, r.SubjectType, r.PolicyBundle, r.LegacyValidators}, err
		}},
		{"ConnectorResponse", `{"success":true,` + provenanceJSON + `}`, func(b []byte) (provenance, error) {
			var r ConnectorResponse
			err := json.Unmarshal(b, &r)
			return provenance{r.Engine, r.SubjectType, r.PolicyBundle, r.LegacyValidators}, err
		}},
		{"MCPExecuteResponse", `{"success":true,` + provenanceJSON + `}`, func(b []byte) (provenance, error) {
			var r MCPExecuteResponse
			err := json.Unmarshal(b, &r)
			return provenance{r.Engine, r.SubjectType, r.PolicyBundle, r.LegacyValidators}, err
		}},
		{"MCPCheckOutputResponse", `{"allowed":true,` + provenanceJSON + `}`, func(b []byte) (provenance, error) {
			var r MCPCheckOutputResponse
			err := json.Unmarshal(b, &r)
			return provenance{r.Engine, r.SubjectType, r.PolicyBundle, r.LegacyValidators}, err
		}},
		{"DecideResponse", `{"verdict":"allow",` + provenanceJSON + `}`, func(b []byte) (provenance, error) {
			var r DecideResponse
			err := json.Unmarshal(b, &r)
			return provenance{r.Engine, r.SubjectType, r.PolicyBundle, r.LegacyValidators}, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.read([]byte(tc.body))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(got, wantProvenance) {
				t.Errorf("provenance = %+v, want %+v", got, wantProvenance)
			}
		})
	}
}

// TestDecideCarriesTheV11Provenance proves Decide returns the provenance and
// the three fields only /api/v1/decide carries: each evaluated policy named,
// the packs that composed, and the organization document's version.
func TestDecideCarriesTheV11Provenance(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"verdict":"allow","decision_id":"dec-1","obligations":[],`+
			`"evaluated_policies":["sys_a","org_b"],`+
			`"policy_identities":[{"id":"sys_a","name":"Block SQL injection","source":"shipped"},{"id":"org_b","source":"organization","version":3}],`+
			`"policy_packs":["rbi@sha256:pack"],"document_version":3,`+provenanceJSON+`}`)
	}, nil)
	resp, err := client.Decide(context.Background(), DecideRequest{})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got := (provenance{resp.Engine, resp.SubjectType, resp.PolicyBundle, resp.LegacyValidators}); !reflect.DeepEqual(got, wantProvenance) {
		t.Errorf("provenance = %+v, want %+v", got, wantProvenance)
	}
	wantIdentities := []PolicyIdentity{
		{ID: "sys_a", Name: "Block SQL injection", Source: "shipped"},
		{ID: "org_b", Source: "organization", Version: 3},
	}
	if !reflect.DeepEqual(resp.PolicyIdentities, wantIdentities) {
		t.Errorf("PolicyIdentities = %+v, want %+v", resp.PolicyIdentities, wantIdentities)
	}
	if !reflect.DeepEqual(resp.PolicyPacks, []string{"rbi@sha256:pack"}) || resp.DocumentVersion != 3 {
		t.Errorf("PolicyPacks = %v, DocumentVersion = %d", resp.PolicyPacks, resp.DocumentVersion)
	}
}

// TestPreCheckCarriesDecisionIDVerdictAndProvenance proves the gateway
// pre-check copies the v11 fields its raw response decodes onto the result.
func TestPreCheckCarriesDecisionIDVerdictAndProvenance(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/policy/pre-check" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeJSON(w, http.StatusOK, `{"context_id":"ctx-1","approved":true,"policies":[],`+
			`"expires_at":"2030-01-01T00:00:00Z","decision_id":"dec-2","verdict":"allow",`+provenanceJSON+`}`)
	}, nil)
	result, err := client.GetPolicyApprovedContext("user-token", "hello", nil, nil)
	if err != nil {
		t.Fatalf("GetPolicyApprovedContext: %v", err)
	}
	if result.DecisionID != "dec-2" || result.Verdict != "allow" {
		t.Errorf("DecisionID = %q, Verdict = %q", result.DecisionID, result.Verdict)
	}
	if got := (provenance{result.Engine, result.SubjectType, result.PolicyBundle, result.LegacyValidators}); !reflect.DeepEqual(got, wantProvenance) {
		t.Errorf("provenance = %+v, want %+v", got, wantProvenance)
	}
}

// TestMCPCheckOutputCarriesTheProvenance proves check-output returns it.
func TestMCPCheckOutputCarriesTheProvenance(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"allowed":true,"policies_evaluated":1,`+provenanceJSON+`}`)
	}, nil)
	resp, err := client.MCPCheckOutput(context.Background(), MCPCheckOutputRequest{ConnectorType: "postgres", Message: "hello"})
	if err != nil {
		t.Fatalf("MCPCheckOutput: %v", err)
	}
	if got := (provenance{resp.Engine, resp.SubjectType, resp.PolicyBundle, resp.LegacyValidators}); !reflect.DeepEqual(got, wantProvenance) {
		t.Errorf("provenance = %+v, want %+v", got, wantProvenance)
	}
}

// TestQueryConnectorCopiesTheProvenance proves the connector response built
// from an /api/request response keeps its provenance.
func TestQueryConnectorCopiesTheProvenance(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"success":true,"data":{"rows":[]},`+provenanceJSON+`}`)
	}, nil)
	resp, err := client.QueryConnector("user-token", "postgres", "select 1", nil)
	if err != nil {
		t.Fatalf("QueryConnector: %v", err)
	}
	if got := (provenance{resp.Engine, resp.SubjectType, resp.PolicyBundle, resp.LegacyValidators}); !reflect.DeepEqual(got, wantProvenance) {
		t.Errorf("provenance = %+v, want %+v", got, wantProvenance)
	}
}

const frozenBody = `{"error":{"code":"LEGACY_POLICY_WRITE_FROZEN","message":"legacy policy writes are frozen; author policy at /api/v1/typed-policies"}}`

// TestLegacyPolicyWritesReturnTheFrozenError proves a v11 refusal of a legacy
// write surfaces as the typed error on both planes: the agent's static-policy
// route and the orchestrator's dynamic-policy route.
func TestLegacyPolicyWritesReturnTheFrozenError(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, frozenBody)
	}, nil)
	_, staticErr := client.CreateStaticPolicy(&CreateStaticPolicyRequest{Name: "p", Category: CategorySecuritySQLI, Pattern: "x"})
	_, dynamicErr := client.CreateDynamicPolicy(&CreateDynamicPolicyRequest{Name: "p", Type: "risk"})
	for name, err := range map[string]error{"static policy (agent)": staticErr, "dynamic policy (orchestrator)": dynamicErr} {
		var frozen *LegacyPolicyWriteFrozenError
		if !errors.As(err, &frozen) {
			t.Fatalf("%s: want *LegacyPolicyWriteFrozenError, got %T: %v", name, err, err)
		}
		if !strings.Contains(frozen.Message, "/api/v1/typed-policies") {
			t.Errorf("%s: Message = %q, want it to name the typed route", name, frozen.Message)
		}
		if !strings.HasPrefix(err.Error(), LegacyPolicyWriteFrozenCode+": ") {
			t.Errorf("%s: Error() = %q, want it to lead with the code", name, err.Error())
		}
	}
}

// TestOtherErrorsAreNotTheFrozenError proves only a 409 carrying the frozen
// code becomes the typed error; every other refusal keeps the generic one.
func TestOtherErrorsAreNotTheFrozenError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"a 409 with another code", http.StatusConflict, `{"error":{"code":"VERSION_CONFLICT","message":"stale"}}`},
		{"a 409 whose error is a string", http.StatusConflict, `{"error":"conflict"}`},
		{"a 409 that is not JSON", http.StatusConflict, `conflict`},
		{"a 400 with the frozen code", http.StatusBadRequest, frozenBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, tc.body)
			}, nil)
			_, err := client.CreateStaticPolicy(&CreateStaticPolicyRequest{Name: "p", Category: CategorySecuritySQLI, Pattern: "x"})
			var frozen *LegacyPolicyWriteFrozenError
			if err == nil || errors.As(err, &frozen) {
				t.Fatalf("want the generic HTTP error, got %T: %v", err, err)
			}
			if want := fmt.Sprintf("HTTP %d: ", tc.status); !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), tc.body) {
				t.Errorf("Error() = %q, want the status and the body", err.Error())
			}
		})
	}
}

// deprecatedRoutes answers the two legacy list routes with the headers a v11
// platform stamps: removal release and successor on the static route (the
// successor in a SECOND Link value), an RFC 9745 Deprecation on the dynamic
// route, and nothing on any other path.
func deprecatedRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/static-policies":
		w.Header().Set("X-AxonFlow-Removed-In", "v11.1")
		w.Header().Add("Link", `</api/v1/audit>; rel="related"`)
		w.Header().Add("Link", `</api/v1/typed-policies>; rel="successor-version"`)
	case "/api/v1/dynamic-policies":
		w.Header().Set("Deprecation", "@1788220800")
	}
	writeJSON(w, http.StatusOK, `{"policies":[]}`)
}

// TestRouteDeprecationIsReportedOncePerRoute proves the SDK reports each
// deprecated route once per client, shares that record with AsUser clients,
// reads either marker, and reports nothing for an unmarked route.
func TestRouteDeprecationIsReportedOncePerRoute(t *testing.T) {
	var mu sync.Mutex
	var got []PlatformRouteDeprecation
	client := newTestClient(t, deprecatedRoutes, func(d PlatformRouteDeprecation) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, d)
	})
	for i := 0; i < 2; i++ {
		if _, err := client.ListStaticPolicies(nil); err != nil {
			t.Fatalf("ListStaticPolicies: %v", err)
		}
	}
	if _, err := client.AsUser("someone").ListStaticPolicies(nil); err != nil {
		t.Fatalf("AsUser ListStaticPolicies: %v", err)
	}
	if _, err := client.ListDynamicPolicies(nil); err != nil {
		t.Fatalf("ListDynamicPolicies: %v", err)
	}
	if _, err := client.GetStaticPolicy("pol_1"); err != nil {
		t.Fatalf("GetStaticPolicy: %v", err)
	}
	want := []PlatformRouteDeprecation{
		{Route: "GET /api/v1/static-policies", Successor: "/api/v1/typed-policies", RemovedIn: "v11.1"},
		{Route: "GET /api/v1/dynamic-policies", Deprecation: "@1788220800"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reported %+v, want %+v", got, want)
	}
}

// TestRouteDeprecationLogsWhenNoCallbackIsSet proves the fallback: without
// OnRouteDeprecation the SDK logs each deprecated route once.
func TestRouteDeprecationLogsWhenNoCallbackIsSet(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	client := newTestClient(t, deprecatedRoutes, nil)
	for i := 0; i < 2; i++ {
		if _, err := client.ListStaticPolicies(nil); err != nil {
			t.Fatalf("ListStaticPolicies: %v", err)
		}
	}
	want := "[AxonFlow] GET /api/v1/static-policies is deprecated by the AxonFlow platform; " +
		"use /api/v1/typed-policies instead; it is removed in v11.1."
	if n := strings.Count(buf.String(), want); n != 1 {
		t.Errorf("logged the deprecation %d times, want once; log:\n%s", n, buf.String())
	}
}

// TestRouteDeprecationWithoutARecordReportsEveryTime pins the one path with no
// record: a client not built by NewClient reports on every call rather than
// dropping the report.
func TestRouteDeprecationWithoutARecordReportsEveryTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deprecatedRoutes))
	defer server.Close()
	reports := 0
	client := &AxonFlowClient{
		config:     AxonFlowConfig{Endpoint: server.URL, OnRouteDeprecation: func(PlatformRouteDeprecation) { reports++ }},
		httpClient: server.Client(),
	}
	for i := 0; i < 2; i++ {
		if _, err := client.ListStaticPolicies(nil); err != nil {
			t.Fatalf("ListStaticPolicies: %v", err)
		}
	}
	if reports != 2 {
		t.Errorf("reports = %d, want 2", reports)
	}
}
