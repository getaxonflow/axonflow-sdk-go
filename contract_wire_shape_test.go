// Wire-shape contract test: OpenAPI spec ↔ Go SDK struct tags.
//
// This test catches camelCase / snake_case drift and missing-field drift
// between the authoritative OpenAPI specs and the SDK's exported structs.
// It is the Go arm of QF-15 (see axonflow-enterprise#1699); the Python
// arm lives in axonflow-sdk-python's tests/test_wire_shape.py.
//
// Data flow:
//   - Load every *.yaml under AXONFLOW_OPENAPI_SPECS_DIR (set by CI
//     after cloning the community repo). Collect every schema that has
//     concrete `properties`.
//   - Walk this package's source files via go/parser, find every
//     exported struct, compute its wire-shape field names (the `json`
//     tag when set, otherwise the Go field name).
//   - For every struct whose type name matches a schema name, diff the
//     sorted property-name sets and fail on drift that is not covered
//     by the baseline in testdata/wire_shape_baseline.json.
//
// The test gate is opt-in via AXONFLOW_OPENAPI_SPECS_DIR: without the
// env var, all wire-shape tests skip cleanly, so `go test ./...` on a
// dev box with no specs checkout continues to work. The dedicated CI
// job sets the env var and runs only TestWireShape* via -run.
//
// All schema/struct/yaml logic lives in internal/wireshape so this test
// and scripts/refresh_wire_shape_baseline share a single source of
// truth. See internal/wireshape/wireshape.go.
//
// To regenerate the baseline (after a legitimate burn-down or platform
// spec change):
//
//	go run ./scripts/refresh_wire_shape_baseline \
//	    /path/to/axonflow/docs/api \
//	    --sha <community-repo-commit-sha>

package axonflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/getaxonflow/axonflow-sdk-go/v6/internal/wireshape"
)

// ExcludedTypes names struct types that legitimately do not participate
// in the wire contract even if their name collides with an OpenAPI
// schema. Each entry needs a one-line reason.
var ExcludedTypes = map[string]string{}

const baselinePath = "testdata/wire_shape_baseline.json"

// loadBaseline returns a zero baseline when the file is missing so that
// bootstrap runs (before the first refresh) produce actionable output
// instead of failing in fixture setup.
func loadBaseline(t *testing.T) wireshape.Baseline {
	t.Helper()
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wireshape.NewEmptyBaseline()
		}
		t.Fatalf("read baseline %s: %v", baselinePath, err)
	}
	var b wireshape.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("parse baseline %s: %v", baselinePath, err)
	}
	if b.CrossSpecDuplicates == nil {
		b.CrossSpecDuplicates = map[string]map[string][]string{}
	}
	if b.PerTypeDrift == nil {
		b.PerTypeDrift = map[string]wireshape.DriftEntry{}
	}
	return b
}

// specsDir returns the env-var path if it points at an existing
// directory, or "" if the gate should skip.
func specsDir() string {
	p := os.Getenv("AXONFLOW_OPENAPI_SPECS_DIR")
	if p == "" {
		return ""
	}
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		return ""
	}
	return p
}

func TestWireShapeSpecsDirIsPopulated(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	schemas, _, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	if len(schemas) == 0 {
		t.Fatalf("no schemas with properties loaded from %s", dir)
	}
}

func TestWireShapeNoNewCrossSpecDivergence(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	_, observed, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	baseline := loadBaseline(t)

	type problem struct {
		name string
		body string
	}
	var problems []problem

	for name, decls := range observed {
		expected, ok := baseline.CrossSpecDuplicates[name]
		if !ok {
			var b strings.Builder
			fmt.Fprintf(&b, "  %s: NEW cross-spec divergence (not in baseline).\n", name)
			for _, spec := range sortedKeys(decls) {
				fmt.Fprintf(&b, "    %s: %v\n", spec, decls[spec])
			}
			problems = append(problems, problem{name, b.String()})
			continue
		}
		if !equalPerSpecShapes(expected, decls) {
			var b strings.Builder
			fmt.Fprintf(&b, "  %s: divergence drifted from baseline.\n", name)
			allSpecs := map[string]struct{}{}
			for s := range expected {
				allSpecs[s] = struct{}{}
			}
			for s := range decls {
				allSpecs[s] = struct{}{}
			}
			specList := []string{}
			for s := range allSpecs {
				specList = append(specList, s)
			}
			sort.Strings(specList)
			for _, spec := range specList {
				exp := expected[spec]
				obs := decls[spec]
				if reflect.DeepEqual(exp, obs) {
					continue
				}
				fmt.Fprintf(&b, "    %s:\n      baseline: %v\n      observed: %v\n", spec, exp, obs)
			}
			problems = append(problems, problem{name, b.String()})
		}
	}

	if len(problems) == 0 {
		return
	}
	sort.Slice(problems, func(i, j int) bool { return problems[i].name < problems[j].name })
	var out strings.Builder
	out.WriteString("\nCross-spec schema divergence gate failed:\n\n")
	for _, p := range problems {
		out.WriteString(p.body)
	}
	out.WriteString("\nFix: reconcile in the axonflow-enterprise specs (rename one, " +
		"or merge into a shared supertype). If the divergence is intentional " +
		"and must stand, regenerate testdata/wire_shape_baseline.json via " +
		"`go run ./scripts/refresh_wire_shape_baseline ...`.\n")
	t.Fatal(out.String())
}

func TestWireShapeNoNewIntraFileDuplicates(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	_, _, observed, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	baseline := loadBaseline(t)
	allowed := baseline.IntraFileDuplicates

	type problem struct{ body string }
	var problems []problem

	// Every observed intra-file duplicate must match the baseline entry
	// exactly — both file AND count. A new duplicate OR a count change
	// (e.g. PolicyMatch going from 2 to 3 copies) fails the gate.
	for file, schemas := range observed {
		for schemaName, count := range schemas {
			allowedCount, ok := allowed[file][schemaName]
			if ok && allowedCount == count {
				continue
			}
			problems = append(problems, problem{fmt.Sprintf(
				"  %s: schema '%s' declared %d times (baseline says %d).",
				file, schemaName, count, allowedCount,
			)})
		}
	}
	// A baselined duplicate that no longer appears also fails — force
	// the baseline author to remove it deliberately, the same contract
	// as the cross-spec gate.
	for file, schemas := range allowed {
		for schemaName := range schemas {
			if _, ok := observed[file][schemaName]; !ok {
				problems = append(problems, problem{fmt.Sprintf(
					"  %s: baselined duplicate '%s' no longer observed — remove from baseline.intra_file_duplicates.",
					file, schemaName,
				)})
			}
		}
	}

	if len(problems) == 0 {
		return
	}
	sort.Slice(problems, func(i, j int) bool { return problems[i].body < problems[j].body })
	var b strings.Builder
	b.WriteString("\nIntra-file schema duplicate gate failed:\n\n")
	for _, p := range problems {
		b.WriteString(p.body)
		b.WriteString("\n")
	}
	b.WriteString("\nFix: remove the duplicate declaration in the OpenAPI spec. " +
		"A schema declared twice in one file leaves the contract ambiguous — " +
		"only the last declaration is authoritative at parse time, so readers " +
		"of the first disagree with readers of the second. If the duplicate " +
		"is intentional and must stand, regenerate " +
		"testdata/wire_shape_baseline.json to acknowledge it.\n")
	t.Fatal(b.String())
}

func TestWireShapeNoNewSDKVsSpecDrift(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	merged, _, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := wireshape.DiscoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	baseline := loadBaseline(t)

	matched := 0
	type drift struct {
		name         string
		newSDKOnly   []string
		newSpecOnly  []string
		baseSDKOnly  []string
		baseSpecOnly []string
	}
	var newDrift []drift

	for name, sdkFields := range sdk {
		if _, excluded := ExcludedTypes[name]; excluded {
			continue
		}
		specFields, ok := merged[name]
		if !ok {
			continue
		}
		matched++
		sdkOnly := wireshape.Difference(sdkFields, specFields)
		specOnly := wireshape.Difference(specFields, sdkFields)

		allowed, ok := baseline.PerTypeDrift[name]
		expectedSDK := map[string]struct{}{}
		expectedSpec := map[string]struct{}{}
		if ok {
			for _, f := range allowed.SDKOnly {
				expectedSDK[f] = struct{}{}
			}
			for _, f := range allowed.SpecOnly {
				expectedSpec[f] = struct{}{}
			}
		}
		newSDK := subtractSet(sdkOnly, expectedSDK)
		newSpec := subtractSet(specOnly, expectedSpec)
		if len(newSDK) == 0 && len(newSpec) == 0 {
			continue
		}
		newDrift = append(newDrift, drift{
			name:         name,
			newSDKOnly:   newSDK,
			newSpecOnly:  newSpec,
			baseSDKOnly:  subtractSet(sdkOnly, toSet(newSDK)),
			baseSpecOnly: subtractSet(specOnly, toSet(newSpec)),
		})
	}

	if matched == 0 {
		t.Fatal("No SDK struct matched any OpenAPI schema by name — check discovery.")
	}

	if len(newDrift) == 0 {
		return
	}
	sort.Slice(newDrift, func(i, j int) bool { return newDrift[i].name < newDrift[j].name })
	var b strings.Builder
	b.WriteString("\nNEW wire-shape drift detected (not covered by baseline):\n\n")
	for _, d := range newDrift {
		fmt.Fprintf(&b, "  %s:\n", d.name)
		if len(d.newSDKOnly) > 0 {
			fmt.Fprintf(&b, "    NEW, only in SDK struct:  %v\n", d.newSDKOnly)
		}
		if len(d.newSpecOnly) > 0 {
			fmt.Fprintf(&b, "    NEW, only in OpenAPI:     %v\n", d.newSpecOnly)
		}
		if len(d.baseSDKOnly) > 0 {
			fmt.Fprintf(&b, "    (baseline, only in SDK):  %v\n", d.baseSDKOnly)
		}
		if len(d.baseSpecOnly) > 0 {
			fmt.Fprintf(&b, "    (baseline, only in spec): %v\n", d.baseSpecOnly)
		}
	}
	b.WriteString("\nFix: align the json tag (or add one) to match the OpenAPI " +
		"property name, OR update the spec if the SDK is the source of truth. " +
		"Do not widen the baseline to hide drift without a tracking issue.\n")
	t.Fatal(b.String())
}

func TestWireShapeRegisteredTypesStillMap(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	merged, _, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := wireshape.DiscoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	baseline := loadBaseline(t)
	if len(baseline.RegisteredTypes) == 0 {
		t.Skip("baseline has no registered_types list; rename-escape guard disabled until baseline is regenerated.")
	}
	var missingSDK, missingSpec []string
	for _, name := range baseline.RegisteredTypes {
		if _, ok := sdk[name]; !ok {
			missingSDK = append(missingSDK, name)
		}
		if _, ok := merged[name]; !ok {
			missingSpec = append(missingSpec, name)
		}
	}
	if len(missingSDK) == 0 && len(missingSpec) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("\nRegistered-type mapping broken — rename-escape guard fired:\n\n")
	if len(missingSDK) > 0 {
		fmt.Fprintf(&b, "  No matching SDK struct for: %v\n", missingSDK)
	}
	if len(missingSpec) > 0 {
		fmt.Fprintf(&b, "  No matching OpenAPI schema for: %v\n", missingSpec)
	}
	b.WriteString("\nFix: either revert the rename, do it on both sides, or update " +
		"testdata/wire_shape_baseline.json::registered_types (and mirror the " +
		"rename in baseline.per_type_drift entries).\n")
	t.Fatal(b.String())
}

func TestWireShapeBaselineIsNotStale(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	merged, _, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := wireshape.DiscoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	baseline := loadBaseline(t)

	type stale struct {
		name     string
		sdkOnly  []string
		specOnly []string
		vanished bool
	}
	var staleEntries []stale
	for name, expected := range baseline.PerTypeDrift {
		sdkFields, hasSDK := sdk[name]
		specFields, hasSpec := merged[name]
		if !hasSDK || !hasSpec {
			staleEntries = append(staleEntries, stale{name: name, vanished: true})
			continue
		}
		sdkOnly := toSet(wireshape.Difference(sdkFields, specFields))
		specOnly := toSet(wireshape.Difference(specFields, sdkFields))
		staleSDK := subtractSet(expected.SDKOnly, sdkOnly)
		staleSpec := subtractSet(expected.SpecOnly, specOnly)
		if len(staleSDK) > 0 || len(staleSpec) > 0 {
			staleEntries = append(staleEntries, stale{name: name, sdkOnly: staleSDK, specOnly: staleSpec})
		}
	}
	if len(staleEntries) == 0 {
		return
	}
	sort.Slice(staleEntries, func(i, j int) bool { return staleEntries[i].name < staleEntries[j].name })
	t.Log("Baseline entries that no longer match observed drift (safe to shrink):")
	for _, e := range staleEntries {
		if e.vanished {
			t.Logf("  %s: <type or schema no longer exists>", e.name)
			continue
		}
		t.Logf("  %s:", e.name)
		if len(e.sdkOnly) > 0 {
			t.Logf("    sdk_only entries no longer drifting:  %v", e.sdkOnly)
		}
		if len(e.specOnly) > 0 {
			t.Logf("    spec_only entries no longer drifting: %v", e.specOnly)
		}
	}
}

func TestWireShapeUnmappedTypesAreTracked(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	merged, _, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := wireshape.DiscoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	unmapped := []string{}
	for name := range sdk {
		if _, ok := merged[name]; ok {
			continue
		}
		if _, ex := ExcludedTypes[name]; ex {
			continue
		}
		unmapped = append(unmapped, name)
	}
	sort.Strings(unmapped)
	t.Logf("%d SDK struct(s) have no matching OpenAPI schema (internal / client-side):", len(unmapped))
	for _, n := range unmapped {
		t.Logf("  - %s", n)
	}
}

func TestWireShapeUnmappedSchemasAreTracked(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	merged, _, _, err := wireshape.LoadSchemas(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := wireshape.DiscoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	unmapped := []string{}
	for name := range merged {
		if _, ok := sdk[name]; !ok {
			unmapped = append(unmapped, name)
		}
	}
	sort.Strings(unmapped)
	t.Logf("%d OpenAPI schema(s) have no matching Go SDK struct:", len(unmapped))
	for _, n := range unmapped {
		t.Logf("  - %s", n)
	}
}

// ---- small test-local helpers ----

func toSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

func subtractSet(a []string, b map[string]struct{}) []string {
	out := []string{}
	for _, v := range a {
		if _, ok := b[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func equalPerSpecShapes(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if !reflect.DeepEqual(av, bv) {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
