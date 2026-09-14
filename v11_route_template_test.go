package axonflow

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// stampEveryRoute answers every path with the removal stamp a v11 platform puts
// on its legacy policy routes, whatever the id, and a body every method reads.
func stampEveryRoute(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-AxonFlow-Removed-In", "v11.1")
	writeJSON(w, http.StatusOK, `{}`)
}

// reportedRoutes returns a client that records each reported deprecation, and
// a reader of the routes reported so far.
func reportedRoutes(t *testing.T) (*AxonFlowClient, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var routes []string
	client := newTestClient(t, stampEveryRoute, func(d PlatformRouteDeprecation) {
		mu.Lock()
		defer mu.Unlock()
		routes = append(routes, d.Route)
	})
	return client, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), routes...)
	}
}

// TestAStampedRouteWithAnIdIsReportedOnceNotOncePerId proves the record keys on
// the route's template: two policies read by id, and two overrides deleted,
// are one report each.
func TestAStampedRouteWithAnIdIsReportedOnceNotOncePerId(t *testing.T) {
	client, routes := reportedRoutes(t)
	for _, id := range []string{"pol_1", "pol_2"} {
		if _, err := client.GetStaticPolicy(id); err != nil {
			t.Fatalf("GetStaticPolicy(%s): %v", id, err)
		}
		if err := client.DeletePolicyOverride(id); err != nil {
			t.Fatalf("DeletePolicyOverride(%s): %v", id, err)
		}
	}
	want := []string{"GET /api/v1/static-policies/{id}", "DELETE /api/v1/static-policies/{id}/override"}
	if got := routes(); !reflect.DeepEqual(got, want) {
		t.Errorf("reported %v, want %v", got, want)
	}
}

// TestEveryIdBearingMethodReportsItsTemplateOnce calls each of the eleven
// methods that reach a deprecated route with an id, with two different ids,
// and expects exactly the ten template keys, each reported once.
func TestEveryIdBearingMethodReportsItsTemplateOnce(t *testing.T) {
	client, routes := reportedRoutes(t)
	for _, id := range []string{"x", "y"} {
		_, _ = client.GetStaticPolicy(id)
		_, _ = client.UpdateStaticPolicy(id, &UpdateStaticPolicyRequest{})
		_ = client.DeleteStaticPolicy(id)
		_, _ = client.ToggleStaticPolicy(id, true)
		_, _ = client.GetStaticPolicyVersions(id)
		_, _ = client.CreatePolicyOverride(id, &CreatePolicyOverrideRequest{})
		_ = client.DeletePolicyOverride(id)
		_, _ = client.GetDynamicPolicy(id)
		_, _ = client.UpdateDynamicPolicy(id, &UpdateDynamicPolicyRequest{})
		_ = client.DeleteDynamicPolicy(id)
		_, _ = client.ToggleDynamicPolicy(id, true)
	}
	got := routes()
	sort.Strings(got)
	want := []string{
		"DELETE /api/v1/dynamic-policies/{id}",
		"DELETE /api/v1/static-policies/{id}",
		"DELETE /api/v1/static-policies/{id}/override",
		"GET /api/v1/dynamic-policies/{id}",
		"GET /api/v1/static-policies/{id}",
		"GET /api/v1/static-policies/{id}/versions",
		"PATCH /api/v1/static-policies/{id}",
		"POST /api/v1/static-policies/{id}/override",
		"PUT /api/v1/dynamic-policies/{id}",
		"PUT /api/v1/static-policies/{id}",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reported %v, want exactly %v", got, want)
	}
}

// TestEveryConcatenatedStampedPathCarriesItsTemplate is a source census: every
// path this package builds on a deprecated family with an id goes through a
// ...RequestAt helper naming its {id} template, so a new call site that forgets
// the template fails here instead of reporting once per id. Its blind spot: a
// path built with fmt.Sprintf is refused below, but one assembled another way
// (strings.Builder, url.JoinPath) is not seen.
func TestEveryConcatenatedStampedPathCarriesItsTemplate(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	idPath := regexp.MustCompile(`"/api/v1/(static|dynamic)-policies/"`)
	tagged := regexp.MustCompile(`RequestAt\("(GET|PUT|DELETE|PATCH|POST)", "/api/v1/(static|dynamic)-policies/\{id\}(/versions|/override)?", "/api/v1/(static|dynamic)-policies/"\+`)
	formatted := regexp.MustCompile(`Sprintf\("[^"]*/api/v1/(static|dynamic)-policies/%`)
	var sites int
	var untagged []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if formatted.MatchString(line) {
				untagged = append(untagged, f+":"+strconv.Itoa(i+1)+" (fmt.Sprintf)")
			}
			if !idPath.MatchString(line) {
				continue
			}
			sites++
			if !tagged.MatchString(line) {
				untagged = append(untagged, f+":"+strconv.Itoa(i+1))
			}
		}
	}
	if len(untagged) > 0 {
		t.Errorf("a deprecated route built with an id but no route template: %v", untagged)
	}
	if sites != 11 {
		t.Errorf("found %d id-bearing call sites on the deprecated families, want 11: a new one needs its template and this count", sites)
	}
}
