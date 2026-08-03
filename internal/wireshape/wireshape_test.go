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
