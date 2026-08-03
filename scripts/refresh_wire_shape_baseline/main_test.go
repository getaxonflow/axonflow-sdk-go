package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/getaxonflow/axonflow-sdk-go/v9/internal/wireshape"
)

// TestRunPreservesCuratedNotes proves the refresher does not silently
// drop the curated _note keys that authorize baseline drift entries: a
// regen over an existing baseline must carry each entry's note forward
// as long as the entry still has drift, and must drop the note together
// with the entry once the drift fully burns down.
func TestRunPreservesCuratedNotes(t *testing.T) {
	dir := t.TempDir()

	// Scratch SDK package: Foo drifts (sdk_only "b"), Clean does not.
	sdkSrc := `package p

type Foo struct {
	A string ` + "`json:\"a\"`" + `
	B string ` + "`json:\"b\"`" + `
}

type Clean struct {
	C string ` + "`json:\"c\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(sdkSrc), 0o644); err != nil {
		t.Fatalf("write sdk fixture: %v", err)
	}

	specsDir := filepath.Join(dir, "specs")
	if err := os.MkdirAll(specsDir, 0o755); err != nil {
		t.Fatalf("mkdir specs: %v", err)
	}
	spec := `
components:
  schemas:
    Foo:
      type: object
      properties:
        a: {type: string}
    Clean:
      type: object
      properties:
        c: {type: string}
`
	if err := os.WriteFile(filepath.Join(specsDir, "spec.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatalf("write spec fixture: %v", err)
	}

	// Existing baseline: Foo's entry carries a curated note. Clean has a
	// note on an entry whose drift no longer exists; that note must die
	// with the entry (the burn-down lifecycle), not be resurrected.
	prev := wireshape.Baseline{
		OpenAPISpecsSHA: "oldsha",
		PerTypeDrift: map[string]wireshape.DriftEntry{
			"Foo": {
				Note:    "KEEP-ME: tracked by #3254, burns down at the next pin",
				SDKOnly: []string{"b"},
			},
			"Clean": {
				Note:    "DROP-ME: this entry's drift resolved",
				SDKOnly: []string{"c_old"},
			},
		},
	}
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	prevBytes, err := json.Marshal(prev)
	if err != nil {
		t.Fatalf("marshal prev baseline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "wire_shape_baseline.json"), prevBytes, 0o644); err != nil {
		t.Fatalf("write prev baseline: %v", err)
	}

	// run() resolves the SDK dir and baseline path relative to cwd.
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("chdir back: %v", err)
		}
	}()

	if err := run(specsDir, "newsha"); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "testdata", "wire_shape_baseline.json"))
	if err != nil {
		t.Fatalf("read regenerated baseline: %v", err)
	}
	var got wireshape.Baseline
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse regenerated baseline: %v", err)
	}

	if got.OpenAPISpecsSHA != "newsha" {
		t.Errorf("openapi_specs_sha = %q, want newsha", got.OpenAPISpecsSHA)
	}
	foo, ok := got.PerTypeDrift["Foo"]
	if !ok {
		t.Fatal("Foo drift entry missing from regenerated baseline")
	}
	if foo.Note != "KEEP-ME: tracked by #3254, burns down at the next pin" {
		t.Errorf("Foo._note = %q - the regen dropped or altered the curated note", foo.Note)
	}
	if len(foo.SDKOnly) != 1 || foo.SDKOnly[0] != "b" {
		t.Errorf("Foo.sdk_only = %v, want [b]", foo.SDKOnly)
	}
	if clean, exists := got.PerTypeDrift["Clean"]; exists {
		t.Errorf("Clean entry should have burned down entirely, got %+v", clean)
	}
}
