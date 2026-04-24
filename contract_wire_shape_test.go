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
//   - Walk the current package's source files via go/parser, find every
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
// To regenerate the baseline (after a legitimate burn-down or a
// platform spec change), run:
//
//	go run ./scripts/refresh_wire_shape_baseline \
//	    /path/to/axonflow/docs/api \
//	    --sha <community-repo-commit-sha>

package axonflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// ExcludedTypes names struct types that legitimately do not participate
// in the wire contract even if their name collides with an OpenAPI
// schema. Each entry needs a one-line reason.
var ExcludedTypes = map[string]string{}

const baselinePath = "testdata/wire_shape_baseline.json"

// wireShapeBaseline mirrors the structure of
// tests/fixtures/wire_shape_baseline.json in the Python SDK so the two
// gates stay conceptually aligned.
type wireShapeBaseline struct {
	Comment             string                         `json:"_comment,omitempty"`
	OpenAPISpecsSHA     string                         `json:"openapi_specs_sha"`
	CrossSpecDuplicates map[string]map[string][]string `json:"cross_spec_duplicates"`
	RegisteredTypes     []string                       `json:"registered_types"`
	PerTypeDrift        map[string]perTypeDrift        `json:"per_type_drift"`
}

type perTypeDrift struct {
	SDKOnly  []string `json:"sdk_only"`
	SpecOnly []string `json:"spec_only"`
}

// loadBaseline returns an empty baseline when the file is missing so
// that bootstrap runs (before the first refresh) can produce actionable
// output instead of failing in setup.
func loadBaseline(t *testing.T) wireShapeBaseline {
	t.Helper()
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wireShapeBaseline{
				CrossSpecDuplicates: map[string]map[string][]string{},
				PerTypeDrift:        map[string]perTypeDrift{},
			}
		}
		t.Fatalf("read baseline %s: %v", baselinePath, err)
	}
	var b wireShapeBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("parse baseline %s: %v", baselinePath, err)
	}
	if b.CrossSpecDuplicates == nil {
		b.CrossSpecDuplicates = map[string]map[string][]string{}
	}
	if b.PerTypeDrift == nil {
		b.PerTypeDrift = map[string]perTypeDrift{}
	}
	return b
}

// schemasFromSpecs loads every *.yaml in specDir and returns
// (mergedSchemas, duplicatesBySpec).
//
// - mergedSchemas maps schema name → sorted field names, last-loaded wins
//   on name collision; this is what SDK structs are diffed against.
//
// - duplicatesBySpec keeps only schemas whose declarations DIFFER across
//   specs (identical redundant declarations are benign). The baseline
//   fingerprint pins these per-spec so an already-acknowledged collision
//   can't quietly drift further.
func schemasFromSpecs(specDir string) (map[string][]string, map[string]map[string][]string, error) {
	merged := map[string][]string{}
	allDecls := map[string]map[string][]string{}

	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", specDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		full := filepath.Join(specDir, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", full, err)
		}
		// yaml.v3 is strict on duplicate mapping keys; Python's yaml.safe_load
		// is lenient (last-wins). To keep the Go and Python gates seeing the
		// same specs, decode into a tolerant Node tree and fold to a map
		// ourselves with last-wins semantics. A duplicate key here is
		// itself a platform spec bug worth tracking, but it must not
		// prevent the SDK gate from functioning against the other keys.
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", full, err)
		}
		doc, ok := yamlNodeToMap(&root)
		if !ok {
			continue
		}
		comps, _ := doc["components"].(map[string]any)
		if comps == nil {
			continue
		}
		schemas, _ := comps["schemas"].(map[string]any)
		for schemaName, raw := range schemas {
			schema, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			props, ok := schema["properties"].(map[string]any)
			if !ok || len(props) == 0 {
				continue
			}
			fields := make([]string, 0, len(props))
			for k := range props {
				fields = append(fields, k)
			}
			sort.Strings(fields)
			if _, seen := allDecls[schemaName]; !seen {
				allDecls[schemaName] = map[string][]string{}
			}
			allDecls[schemaName][name] = fields
			merged[schemaName] = fields
		}
	}

	duplicates := map[string]map[string][]string{}
	for schemaName, decls := range allDecls {
		if len(decls) < 2 {
			continue
		}
		shapes := map[string]struct{}{}
		for _, f := range decls {
			shapes[strings.Join(f, "|")] = struct{}{}
		}
		if len(shapes) > 1 {
			duplicates[schemaName] = decls
		}
	}
	return merged, duplicates, nil
}

// discoverSDKTypes walks the current package's non-test .go files and
// returns {StructName: sortedWireFieldNames} for every exported
// struct with at least one JSON-tagged field.
//
// Go doesn't offer a runtime "list all types in package" the way
// Python's pkgutil.walk_packages does, so we parse the AST directly.
// Embedded structs would need recursive resolution; the current Go SDK
// doesn't use embedding in public types (verified), so the simple
// first-level pass is sufficient. If that changes, the embedded field
// will appear as a fieldspec with empty Names and will need handling.
func discoverSDKTypes(pkgDir string) (map[string][]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgDir, func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", pkgDir, err)
	}

	result := map[string][]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				if !ts.Name.IsExported() {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				fields := extractWireFieldsFromAST(st)
				if len(fields) == 0 {
					return true
				}
				result[ts.Name.Name] = fields
				return true
			})
		}
	}
	return result, nil
}

func extractWireFieldsFromAST(st *ast.StructType) []string {
	if st.Fields == nil {
		return nil
	}
	out := []string{}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			// Anonymous / embedded — not used in current SDK, ignore.
			continue
		}
		tagStr := ""
		if field.Tag != nil {
			tagStr = reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
		}
		wireName := parseJSONTagName(tagStr)
		if wireName == "-" {
			continue
		}
		for _, name := range field.Names {
			if !name.IsExported() {
				continue
			}
			if wireName != "" {
				out = append(out, wireName)
			} else {
				// No json tag — Go uses the field name verbatim on the
				// wire. This won't match a snake_case spec property,
				// which is exactly what the gate should surface.
				out = append(out, name.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// parseJSONTagName returns the name portion of a json struct tag —
// everything before the first comma. "" means no tag / no name portion.
// "-" means omit-from-json; callers should skip the field.
func parseJSONTagName(tag string) string {
	if tag == "" {
		return ""
	}
	if i := strings.Index(tag, ","); i >= 0 {
		return tag[:i]
	}
	return tag
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
	schemas, _, err := schemasFromSpecs(dir)
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
	_, observed, err := schemasFromSpecs(dir)
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

func TestWireShapeNoNewSDKVsSpecDrift(t *testing.T) {
	dir := specsDir()
	if dir == "" {
		t.Skip("AXONFLOW_OPENAPI_SPECS_DIR not set; wire-shape tests skipped")
	}
	merged, _, err := schemasFromSpecs(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := discoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	baseline := loadBaseline(t)

	matched := 0
	type drift struct {
		name        string
		newSDKOnly  []string
		newSpecOnly []string
		baseSDKOnly []string
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
		sdkOnly := difference(sdkFields, specFields)
		specOnly := difference(specFields, sdkFields)

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
	merged, _, err := schemasFromSpecs(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := discoverSDKTypes(".")
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
	merged, _, err := schemasFromSpecs(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := discoverSDKTypes(".")
	if err != nil {
		t.Fatalf("discover SDK types: %v", err)
	}
	baseline := loadBaseline(t)

	type stale struct {
		name      string
		sdkOnly   []string
		specOnly  []string
		vanished  bool
	}
	var staleEntries []stale
	for name, expected := range baseline.PerTypeDrift {
		sdkFields, hasSDK := sdk[name]
		specFields, hasSpec := merged[name]
		if !hasSDK || !hasSpec {
			staleEntries = append(staleEntries, stale{name: name, vanished: true})
			continue
		}
		sdkOnly := toSet(difference(sdkFields, specFields))
		specOnly := toSet(difference(specFields, sdkFields))
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
	merged, _, err := schemasFromSpecs(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := discoverSDKTypes(".")
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
	merged, _, err := schemasFromSpecs(dir)
	if err != nil {
		t.Fatalf("load specs: %v", err)
	}
	sdk, err := discoverSDKTypes(".")
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

// yamlNodeToMap folds a YAML tree into a `map[string]any` with
// last-wins semantics on duplicate keys. Match's Python yaml.safe_load
// behavior so the gate tolerates platform-side spec duplicates
// (tracked separately as a spec bug) rather than refusing to parse.
func yamlNodeToMap(n *yaml.Node) (map[string]any, bool) {
	v := yamlNodeToValue(n)
	m, ok := v.(map[string]any)
	return m, ok
}

func yamlNodeToValue(n *yaml.Node) any {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return yamlNodeToValue(n.Content[0])
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			val := n.Content[i+1]
			if key.Kind != yaml.ScalarNode {
				continue
			}
			out[key.Value] = yamlNodeToValue(val) // last wins on duplicate
		}
		return out
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			out = append(out, yamlNodeToValue(c))
		}
		return out
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err == nil {
			return v
		}
		return n.Value
	case yaml.AliasNode:
		if n.Alias != nil {
			return yamlNodeToValue(n.Alias)
		}
	}
	return nil
}

// ---- small set/diff helpers ----

func difference(a, b []string) []string {
	bs := map[string]struct{}{}
	for _, s := range b {
		bs[s] = struct{}{}
	}
	out := []string{}
	for _, s := range a {
		if _, ok := bs[s]; !ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

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
