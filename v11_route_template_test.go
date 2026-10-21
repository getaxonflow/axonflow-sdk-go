package axonflow

import (
	"fmt"
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
	w.Header().Set("X-AxonFlow-Removed-In", "v12.0")
	writeJSON(w, http.StatusOK, `{}`)
}

// reportedRoutes returns a client that records each reported deprecation, a
// reader of the routes reported so far, and a reader of the requests the
// server received, as "METHOD path".
func reportedRoutes(t *testing.T) (*AxonFlowClient, func() []string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var routes, served []string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = append(served, r.Method+" "+r.URL.Path)
		mu.Unlock()
		stampEveryRoute(w, r)
	}, func(d PlatformRouteDeprecation) {
		mu.Lock()
		defer mu.Unlock()
		routes = append(routes, d.Route)
	})
	read := func(list *[]string) func() []string {
		return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), (*list)...)
		}
	}
	return client, read(&routes), read(&served)
}

// TestAStampedRouteWithAnIdIsReportedOnceNotOncePerId proves the record keys on
// the route's template: two policies read by id, and two overrides deleted,
// are one report each.
func TestAStampedRouteWithAnIdIsReportedOnceNotOncePerId(t *testing.T) {
	client, routes, _ := reportedRoutes(t)
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
// and expects exactly the ten template keys, each reported once. The server
// must also receive each call's own request, with the id in its path, so a
// method that shares its template with another (ToggleDynamicPolicy and
// UpdateDynamicPolicy are both PUT /api/v1/dynamic-policies/{id}) is seen to
// send.
func TestEveryIdBearingMethodReportsItsTemplateOnce(t *testing.T) {
	client, routes, served := reportedRoutes(t)
	var wantServed []string
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
		for _, route := range []string{
			"GET /api/v1/static-policies/%s",
			"PUT /api/v1/static-policies/%s",
			"DELETE /api/v1/static-policies/%s",
			"PATCH /api/v1/static-policies/%s",
			"GET /api/v1/static-policies/%s/versions",
			"POST /api/v1/static-policies/%s/override",
			"DELETE /api/v1/static-policies/%s/override",
			"GET /api/v1/dynamic-policies/%s",
			"PUT /api/v1/dynamic-policies/%s",
			"DELETE /api/v1/dynamic-policies/%s",
			"PUT /api/v1/dynamic-policies/%s",
		} {
			wantServed = append(wantServed, fmt.Sprintf(route, id))
		}
	}
	if got := served(); !reflect.DeepEqual(got, wantServed) {
		t.Errorf("the server received %v, want exactly %v", got, wantServed)
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

// TestNoIdBearingPathIsBuiltOutsideItsTemplate is a source census over the
// seven deprecated families the platform lists (static-, system-, dynamic- and
// tenant-policies, policies, templates and policy-overrides): no path on them
// is concatenated or formatted with an id, so every id-bearing call goes
// through a ...RequestAt helper, which builds the path from its {id} template.
// A new call site therefore cannot report once per id, and a template cannot
// name a route other than the one sent. Its blind spot: a path assembled
// another way (strings.Builder, url.JoinPath) is not seen.
func TestNoIdBearingPathIsBuiltOutsideItsTemplate(t *testing.T) {
	families := `(static-policies|system-policies|dynamic-policies|tenant-policies|policies|templates|policy-overrides)`
	concatenated := regexp.MustCompile(`"/api/v1/` + families + `/[^"]*"\s*\+`)
	formatted := regexp.MustCompile(`Sprintf\("[^"]*/api/v1/` + families + `/[^"]*%`)
	templated := regexp.MustCompile(`RequestAt\("(GET|PUT|DELETE|PATCH|POST)", "/api/v1/` + families + `/\{id\}(/[a-z]+)?", \w+, `)
	// The census sees every family, and not a path without an id.
	for _, family := range []string{"static-policies", "system-policies", "dynamic-policies", "tenant-policies", "policies", "templates", "policy-overrides"} {
		if line := `c.policyRequest("GET", "/api/v1/` + family + `/"+id, nil, nil)`; !concatenated.MatchString(line) {
			t.Fatalf("the census does not see a concatenated %s path: %s", family, line)
		}
		if line := `fmt.Sprintf("/api/v1/` + family + `/%s", id)`; !formatted.MatchString(line) {
			t.Fatalf("the census does not see a formatted %s path: %s", family, line)
		}
	}
	if concatenated.MatchString(`c.policyRequest("GET", "/api/v1/static-policies", nil, nil)`) {
		t.Fatal("the census counts a path without an id")
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sites int
	var built []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if concatenated.MatchString(line) || formatted.MatchString(line) {
				built = append(built, f+":"+strconv.Itoa(i+1))
			}
			if templated.MatchString(line) {
				sites++
			}
		}
	}
	if len(built) > 0 {
		t.Errorf("a deprecated route's path built with an id outside its template: %v", built)
	}
	if sites != 11 {
		t.Errorf("found %d id-bearing call sites built from a template, want 11: a new one updates this count", sites)
	}
}
