package axonflow

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
)

// The v11.0.0 deprecations: the three simulation methods keep answering until
// v11.1 and are reported once per route with the platform's own signal, and the
// retired per-policy override writes return the typed frozen error.

// stampedSimulationRoutes answers the three simulation routes with the headers
// a v11 platform stamps on the deprecated export surface today. The RFC 9745
// Deprecation header joins them once v11.0.0 is tagged; D1's tests read it.
func stampedSimulationRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-AxonFlow-Removed-In", "v11.1")
	w.Header().Add("Link", `</api/v1/typed-policies>; rel="successor-version"`)
	writeJSON(w, http.StatusOK, `{}`)
}

func TestTheSimulationMethodsWorkAndAreReportedDeprecatedOnce(t *testing.T) {
	var mu sync.Mutex
	var got []PlatformRouteDeprecation
	client := newTestClient(t, stampedSimulationRoutes, func(d PlatformRouteDeprecation) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, d)
	})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := client.SimulatePolicies(ctx, &SimulatePoliciesRequest{Query: "q"}); err != nil {
			t.Fatalf("SimulatePolicies: %v", err)
		}
		if _, err := client.GetPolicyImpactReport(ctx, &ImpactReportRequest{PolicyID: "p", Inputs: []ImpactReportInput{{Query: "q"}}}); err != nil {
			t.Fatalf("GetPolicyImpactReport: %v", err)
		}
		if _, err := client.DetectPolicyConflicts(ctx, ""); err != nil {
			t.Fatalf("DetectPolicyConflicts: %v", err)
		}
	}
	stamp := PlatformRouteDeprecation{Successor: "/api/v1/typed-policies", RemovedIn: "v11.1"}
	var want []PlatformRouteDeprecation
	for _, route := range []string{"simulate", "impact-report", "conflicts"} {
		d := stamp
		d.Route = "POST /api/v1/policies/" + route
		want = append(want, d)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reported\n %+v\nwant\n %+v", got, want)
	}
}

func TestRetiredOverrideWritesReturnTheFrozenError(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, frozenBody)
	}, nil)
	_, createErr := client.CreatePolicyOverride("sys_pii_email", &CreatePolicyOverrideRequest{})
	deleteErr := client.DeletePolicyOverride("sys_pii_email")
	for name, err := range map[string]error{"CreatePolicyOverride": createErr, "DeletePolicyOverride": deleteErr} {
		var frozen *LegacyPolicyWriteFrozenError
		if !errors.As(err, &frozen) {
			t.Errorf("%s: want *LegacyPolicyWriteFrozenError, got %T: %v", name, err, err)
		}
	}
}
