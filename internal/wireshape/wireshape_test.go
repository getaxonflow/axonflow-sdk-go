package wireshape

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestNodeToMapLastWinsOnDuplicateKey locks in the Python-parity claim
// made in LoadSchemas: yaml.v3 is strict on duplicate mapping keys, but
// we intentionally tolerate them with last-wins so the gate parses the
// same specs Python's yaml.safe_load does. If this behavior regresses
// (e.g. a refactor switches to yaml.Unmarshal into map[string]any which
// errors on duplicates), this test catches it.
func TestNodeToMapLastWinsOnDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	specFile := filepath.Join(dir, "dup.yaml")
	// PolicyMatch-style duplicate: same top-level mapping key declared
	// twice. The second declaration wins, matching Python behavior.
	if err := writeFile(specFile, `
components:
  schemas:
    Foo:
      type: object
      properties:
        first: {type: string}
    Foo:
      type: object
      properties:
        second: {type: string}
`); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	merged, crossSpec, intraFile, err := LoadSchemas(dir)
	if err != nil {
		t.Fatalf("LoadSchemas: %v", err)
	}
	got := merged["Foo"]
	want := []string{"second"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("last-wins broken: Foo fields = %v, want %v", got, want)
	}
	// Single file with self-duplicate: both declarations share the same
	// file name, so cross-spec duplicates should be empty.
	if len(crossSpec) != 0 {
		t.Fatalf("intra-file duplicates incorrectly reported cross-spec: %v", crossSpec)
	}
	// But intra-file duplicates MUST surface — this is exactly the
	// PolicyMatch-class bug the gate needs to catch.
	if got, want := intraFile["dup.yaml"]["Foo"], 2; got != want {
		t.Fatalf("intra-file duplicate count: got %d want %d (full map: %v)", got, want, intraFile)
	}
}

// TestLoadSchemasIntraFilePositiveNegative covers both sides of the
// intra-file duplicate detector: a schema declared twice in one file
// MUST surface; a schema declared once in each of two files (cross-
// spec, already covered by another gate) MUST NOT surface as intra-
// file.
func TestLoadSchemasIntraFilePositiveNegative(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "triple.yaml"), `
components:
  schemas:
    Foo:
      type: object
      properties: {a: {type: string}}
    Bar:
      type: object
      properties: {x: {type: string}}
    Foo:
      type: object
      properties: {b: {type: string}}
    Foo:
      type: object
      properties: {c: {type: string}}
`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "other.yaml"), `
components:
  schemas:
    Unique:
      type: object
      properties: {z: {type: string}}
`); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, intraFile, err := LoadSchemas(dir)
	if err != nil {
		t.Fatalf("LoadSchemas: %v", err)
	}
	// Positive: Foo in triple.yaml, counted 3 times
	if got, want := intraFile["triple.yaml"]["Foo"], 3; got != want {
		t.Errorf("triple.yaml.Foo count: got %d want %d", got, want)
	}
	// Negative: Bar in triple.yaml (declared once) should not be listed
	if _, ok := intraFile["triple.yaml"]["Bar"]; ok {
		t.Errorf("Bar was incorrectly flagged as intra-file duplicate")
	}
	// Negative: other.yaml has no duplicates
	if _, ok := intraFile["other.yaml"]; ok {
		t.Errorf("other.yaml was incorrectly flagged despite having no duplicates")
	}
}

// TestLoadSchemasCrossSpecDuplicate exercises the positive case for
// duplicatesBySpec: same schema name declared in two files with
// different shapes should surface as a cross-spec duplicate.
func TestLoadSchemasCrossSpecDuplicate(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "agent.yaml"), `
components:
  schemas:
    Shared:
      type: object
      properties:
        a: {type: string}
        b: {type: string}
`); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "orch.yaml"), `
components:
  schemas:
    Shared:
      type: object
      properties:
        a: {type: string}
        c: {type: string}
`); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, duplicates, _, err := LoadSchemas(dir)
	if err != nil {
		t.Fatalf("LoadSchemas: %v", err)
	}
	d, ok := duplicates["Shared"]
	if !ok {
		t.Fatalf("expected Shared to be flagged as cross-spec duplicate, got %v", duplicates)
	}
	if got := d["agent.yaml"]; !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("agent.yaml shape: got %v want [a b]", got)
	}
	if got := d["orch.yaml"]; !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("orch.yaml shape: got %v want [a c]", got)
	}
}

// TestLoadSchemasIdenticalDuplicateNotFlagged ensures that identical
// redundant declarations across specs (same name, same shape) are NOT
// flagged — they're benign and don't need a baseline entry.
func TestLoadSchemasIdenticalDuplicateNotFlagged(t *testing.T) {
	dir := t.TempDir()
	body := `
components:
  schemas:
    Shared:
      type: object
      properties:
        a: {type: string}
        b: {type: string}
`
	if err := writeFile(filepath.Join(dir, "agent.yaml"), body); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "orch.yaml"), body); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, duplicates, _, err := LoadSchemas(dir)
	if err != nil {
		t.Fatalf("LoadSchemas: %v", err)
	}
	if _, ok := duplicates["Shared"]; ok {
		t.Fatalf("identical duplicates incorrectly flagged: %v", duplicates)
	}
}

// TestParseJSONTagName covers the tag forms that actually appear in
// the SDK: bare name, name+options, just options, dash, and empty.
func TestParseJSONTagName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"name", "name"},
		{"name,omitempty", "name"},
		{",omitempty", ""},
		{"-", "-"},
		{"snake_case_field,omitempty,string", "snake_case_field"},
	}
	for _, c := range cases {
		if got := ParseJSONTagName(c.in); got != c.want {
			t.Errorf("ParseJSONTagName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDifference covers set subtraction, the set helper the gate uses
// to compute per-type drift.
func TestDifference(t *testing.T) {
	got := Difference([]string{"a", "b", "c"}, []string{"b", "d"})
	want := []string{"a", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Difference: got %v want %v", got, want)
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}

// TestDiscoverSDKTypesRejectsEmbeddedFields proves the embedded-field
// smuggling channel is CLOSED by capability removal: encoding/json
// promotes an embedded struct's fields onto the outer type's wire
// shape, so a skipped embed would let a field reach the wire while
// staying invisible to every TestWireShape* gate. Discovery must
// hard-fail on ANY embedded field in an exported struct, naming the
// struct and instructing the author to flatten.
func TestDiscoverSDKTypesRejectsEmbeddedFields(t *testing.T) {
	t.Run("embedded smuggle turns discovery red", func(t *testing.T) {
		dir := t.TempDir()
		src := `package p

type smuggleBase struct {
	Hidden string ` + "`json:\"hidden_on_the_wire\"`" + `
}

type Outer struct {
	smuggleBase
	Real string ` + "`json:\"real\"`" + `
}
`
		if err := writeFile(filepath.Join(dir, "x.go"), src); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		_, err := DiscoverSDKTypes(dir)
		if err == nil {
			t.Fatal("DiscoverSDKTypes accepted an exported struct with an embedded field - the smuggling channel is open")
		}
		msg := err.Error()
		if !strings.Contains(msg, "Outer") {
			t.Errorf("error must name the offending struct, got: %s", msg)
		}
		if !strings.Contains(msg, "smuggleBase") {
			t.Errorf("error must name the embedded type, got: %s", msg)
		}
		if !strings.Contains(msg, "Flatten") {
			t.Errorf("error must instruct the author to flatten, got: %s", msg)
		}
	})

	t.Run("pointer and cross-package embeds are also rejected", func(t *testing.T) {
		dir := t.TempDir()
		src := `package p

import "sync"

type Guarded struct {
	*sync.Mutex
	Value string ` + "`json:\"value\"`" + `
}
`
		if err := writeFile(filepath.Join(dir, "x.go"), src); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		_, err := DiscoverSDKTypes(dir)
		if err == nil {
			t.Fatal("DiscoverSDKTypes accepted a pointer embed")
		}
		if !strings.Contains(err.Error(), "*sync.Mutex") {
			t.Errorf("error must render the embedded type expression, got: %s", err.Error())
		}
	})

	t.Run("negative control: flattened struct passes with correct fields", func(t *testing.T) {
		dir := t.TempDir()
		src := `package p

type Outer struct {
	Hidden string ` + "`json:\"hidden_on_the_wire\"`" + `
	Real   string ` + "`json:\"real\"`" + `
}
`
		if err := writeFile(filepath.Join(dir, "x.go"), src); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		got, err := DiscoverSDKTypes(dir)
		if err != nil {
			t.Fatalf("negative control must pass, got: %v", err)
		}
		want := []string{"hidden_on_the_wire", "real"}
		if !reflect.DeepEqual(got["Outer"], want) {
			t.Errorf("Outer fields = %v, want %v", got["Outer"], want)
		}
	})
}

// TestStaleBaselineProblems is the burn-down ratchet's own table test
// (B2): the classification must fail each stale class and tolerate
// exactly the sanctioned shapes. Without this, mutating the gate's
// t.Fatal to t.Log would leave every suite green.
func TestStaleBaselineProblems(t *testing.T) {
	sdk := map[string][]string{
		"Both":    {"a", "shared"},
		"Drifter": {"a", "b"},
	}
	spec := map[string][]string{
		"Both":         {"a", "shared"},
		"Drifter":      {"a"},
		"SpecSideOnly": {"x"},
	}

	cases := []struct {
		name         string
		drift        map[string]DriftEntry
		wantProblem  string // substring that must appear; "" = no problems
		wantVanished []string
	}{
		{
			name:        "burned-down field goes red",
			drift:       map[string]DriftEntry{"Both": {SDKOnly: []string{"shared"}}},
			wantProblem: "burned down",
		},
		{
			name:        "dead or phantom allowance goes red",
			drift:       map[string]DriftEntry{"Both": {SDKOnly: []string{"ghost_field"}}},
			wantProblem: "dead allowance",
		},
		{
			name:         "vanished type with empty entry is tolerated and logged",
			drift:        map[string]DriftEntry{"VanishedAck": {Note: "ack"}},
			wantProblem:  "",
			wantVanished: []string{"VanishedAck"},
		},
		{
			name: "vanished type with content goes red (executed attack: plant an allowance on a vanished type, then restore the schema and add the field)",
			drift: map[string]DriftEntry{
				"VanishedAck": {Note: "ack", SDKOnly: []string{"planted_future_field"}},
			},
			wantProblem: "vanished-type acknowledgment must be an EMPTY entry",
		},
		{
			name:        "empty entry on a type that maps both sides goes red (dead entry)",
			drift:       map[string]DriftEntry{"Both": {Note: "carried but stale"}},
			wantProblem: "dead entry",
		},
		{
			name:        "genuine drift allowance stays green",
			drift:       map[string]DriftEntry{"Drifter": {SDKOnly: []string{"b"}}},
			wantProblem: "",
		},
		{
			name: "schema with no SDK struct is vanished for baseline purposes",
			drift: map[string]DriftEntry{
				"SpecSideOnly": {Note: "ack", SDKOnly: []string{"x_allow"}},
			},
			wantProblem: "vanished-type acknowledgment must be an EMPTY entry",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems, vanished := StaleBaselineProblems(tc.drift, sdk, spec)
			if tc.wantProblem == "" {
				if len(problems) != 0 {
					t.Fatalf("want no problems, got: %v", problems)
				}
			} else {
				if len(problems) == 0 {
					t.Fatalf("want a problem containing %q, got none", tc.wantProblem)
				}
				joined := strings.Join(problems, "\n")
				if !strings.Contains(joined, tc.wantProblem) {
					t.Fatalf("problems %v do not contain %q", problems, tc.wantProblem)
				}
			}
			if !reflect.DeepEqual(vanished, tc.wantVanished) && !(len(vanished) == 0 && len(tc.wantVanished) == 0) {
				t.Fatalf("vanishedAcks = %v, want %v", vanished, tc.wantVanished)
			}
		})
	}
}

// TestDiscoverSDKTypesEmbedEscapes covers the three executed escapes
// from the exported-declarations-only embed check (S1): the check must
// run on ALL struct declarations regardless of export, because an
// unexported embed-carrying struct reaches the wire via an exported
// alias, an exported defined type, or as a named field's type.
func TestDiscoverSDKTypesEmbedEscapes(t *testing.T) {
	write := func(t *testing.T, src string) string {
		dir := t.TempDir()
		if err := writeFile(filepath.Join(dir, "x.go"), src); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return dir
	}
	base := `package p

type smuggleBase struct {
	Hidden string ` + "`json:\"hidden_on_the_wire\"`" + `
}

type inner struct {
	smuggleBase
	Real string ` + "`json:\"real\"`" + `
}
`
	t.Run("exported alias of unexported embed-carrying struct is rejected", func(t *testing.T) {
		dir := write(t, base+"\ntype Pub = inner\n")
		if _, err := DiscoverSDKTypes(dir); err == nil || !strings.Contains(err.Error(), "inner") {
			t.Fatalf("want embed rejection naming inner, got: %v", err)
		}
	})
	t.Run("exported defined type over unexported embed-carrying struct is rejected", func(t *testing.T) {
		dir := write(t, base+"\ntype Pub inner\n")
		if _, err := DiscoverSDKTypes(dir); err == nil || !strings.Contains(err.Error(), "inner") {
			t.Fatalf("want embed rejection naming inner, got: %v", err)
		}
	})
	t.Run("exported struct with a field of unexported embed-carrying type is rejected", func(t *testing.T) {
		dir := write(t, base+"\ntype Pub struct {\n\tNested inner `json:\"nested\"`\n}\n")
		if _, err := DiscoverSDKTypes(dir); err == nil || !strings.Contains(err.Error(), "inner") {
			t.Fatalf("want embed rejection naming inner, got: %v", err)
		}
	})
}

// TestDiscoverSDKTypesResolvesAliases proves an exported alias or
// defined type over a same-package struct registers under the exported
// name with the target's wire fields - the CreateOverrideRequest class:
// a schema-named alias must not escape the contract by pointing at a
// differently named struct.
func TestDiscoverSDKTypesResolvesAliases(t *testing.T) {
	dir := t.TempDir()
	src := `package p

type target struct {
	A string ` + "`json:\"a\"`" + `
	B string ` + "`json:\"b\"`" + `
}

type AliasName = target

type DefinedName target

type ChainEnd = AliasName
`
	if err := writeFile(filepath.Join(dir, "x.go"), src); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := DiscoverSDKTypes(dir)
	if err != nil {
		t.Fatalf("DiscoverSDKTypes: %v", err)
	}
	want := []string{"a", "b"}
	for _, name := range []string{"AliasName", "DefinedName", "ChainEnd"} {
		if !reflect.DeepEqual(got[name], want) {
			t.Errorf("%s fields = %v, want %v (alias/typedef resolution broken)", name, got[name], want)
		}
	}
	if _, mapped := got["target"]; mapped {
		t.Error("unexported target must not be registered under its own name")
	}
}

// TestDiscoverSDKTypesExclusionEscapeHatch proves ExcludedTypes is
// applied BEFORE the embed check (S2): a genuinely non-wire type that
// embeds sync.Mutex would otherwise hard-fail the whole gate with
// flattening advice that makes no sense for a lock.
func TestDiscoverSDKTypesExclusionEscapeHatch(t *testing.T) {
	dir := t.TempDir()
	src := `package p

import "sync"

type Guarded struct {
	sync.Mutex
	N int ` + "`json:\"n\"`" + `
}

type Wire struct {
	A string ` + "`json:\"a\"`" + `
}
`
	if err := writeFile(filepath.Join(dir, "x.go"), src); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Without an exclusion: the whole discovery hard-fails, and the
	// message must offer the exclusion mechanism (not just flattening).
	_, err := DiscoverSDKTypes(dir)
	if err == nil {
		t.Fatal("embed-carrying Guarded must fail discovery when not excluded")
	}
	if !strings.Contains(err.Error(), "ExcludedTypes") {
		t.Errorf("error must offer the ExcludedTypes escape for non-wire types, got: %v", err)
	}

	// With the exclusion: discovery proceeds, Guarded is not mapped,
	// the genuine wire type still is.
	ExcludedTypes["Guarded"] = "test: internal lock holder, never serialized"
	t.Cleanup(func() { delete(ExcludedTypes, "Guarded") })
	got, err := DiscoverSDKTypes(dir)
	if err != nil {
		t.Fatalf("excluded Guarded must not fail discovery: %v", err)
	}
	if _, mapped := got["Guarded"]; mapped {
		t.Error("excluded type must not be wire-mapped")
	}
	if !reflect.DeepEqual(got["Wire"], []string{"a"}) {
		t.Errorf("Wire fields = %v, want [a]", got["Wire"])
	}
}
