package wireshape

import (
	"os"
	"path/filepath"
	"reflect"
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

	merged, duplicates, err := LoadSchemas(dir)
	if err != nil {
		t.Fatalf("LoadSchemas: %v", err)
	}
	got := merged["Foo"]
	want := []string{"second"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("last-wins broken: Foo fields = %v, want %v", got, want)
	}
	// Single file with self-duplicate: both declarations share the same
	// file name, so duplicatesBySpec (cross-spec) should be empty.
	if len(duplicates) != 0 {
		t.Fatalf("intra-file duplicates incorrectly reported cross-spec: %v", duplicates)
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
	_, duplicates, err := LoadSchemas(dir)
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
	_, duplicates, err := LoadSchemas(dir)
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
