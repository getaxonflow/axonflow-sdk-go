package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getaxonflow/axonflow-sdk-go/v9/internal/wireshape"
)

// scratchTree builds a temp working tree for run(): a scratch SDK
// package (Foo drifts sdk_only ["b"], Clean matches its schema
// exactly), a scratch specs dir, and a previous baseline provided by
// the caller. It chdirs into the tree and restores the wd on cleanup.
func scratchTree(t *testing.T, prev *wireshape.Baseline) (dir, specsDir string) {
	t.Helper()
	dir = t.TempDir()

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

	specsDir = filepath.Join(dir, "specs")
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

	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if prev != nil {
		prevBytes, err := json.Marshal(prev)
		if err != nil {
			t.Fatalf("marshal prev baseline: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "testdata", "wire_shape_baseline.json"), prevBytes, 0o644); err != nil {
			t.Fatalf("write prev baseline: %v", err)
		}
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("chdir back: %v", err)
		}
	})
	return dir, specsDir
}

func readBaseline(t *testing.T, dir string) wireshape.Baseline {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "testdata", "wire_shape_baseline.json"))
	if err != nil {
		t.Fatalf("read regenerated baseline: %v", err)
	}
	var got wireshape.Baseline
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse regenerated baseline: %v", err)
	}
	return got
}

// TestRunPreservesCuratedNotes proves the refresher does not silently
// drop curated _note keys: a note on a still-drifting entry survives a
// regen, and a vanished-type acknowledgment entry (empty except for its
// _note, type unmapped at the pin) is preserved wholesale - the shape
// the #185 re-land relies on for types with no schema at the pin.
func TestRunPreservesCuratedNotes(t *testing.T) {
	prev := &wireshape.Baseline{
		OpenAPISpecsSHA: "oldsha",
		PerTypeDrift: map[string]wireshape.DriftEntry{
			"Foo": {
				Note:    "KEEP-ME: tracked by #3254, burns down at the next pin",
				SDKOnly: []string{"b"},
			},
			"VanishedTypeX": {
				Note: "ACK: no schema at this pin; type kept until the next major",
			},
		},
	}
	dir, specsDir := scratchTree(t, prev)

	if err := run(specsDir, "newsha", false); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := readBaseline(t, dir)

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
	vx, ok := got.PerTypeDrift["VanishedTypeX"]
	if !ok {
		t.Fatal("VanishedTypeX acknowledgment entry DELETED by the regen - the vanished-type paper trail must survive")
	}
	if vx.Note != "ACK: no schema at this pin; type kept until the next major" {
		t.Errorf("VanishedTypeX._note = %q, want the acknowledgment note", vx.Note)
	}
	if len(vx.SDKOnly) != 0 || len(vx.SpecOnly) != 0 {
		t.Errorf("VanishedTypeX entry must stay empty, got %+v", vx)
	}
}

// TestRunRefusesToDropNotesWithoutFlag proves a note that would not
// survive the regen (here: Clean's drift resolved, so its entry burns
// down) blocks the refresher with a diagnostic naming the note, and
// only --drop-notes confirms the discard.
func TestRunRefusesToDropNotesWithoutFlag(t *testing.T) {
	prev := &wireshape.Baseline{
		OpenAPISpecsSHA: "oldsha",
		PerTypeDrift: map[string]wireshape.DriftEntry{
			"Clean": {
				Note:    "DROP-ME: this entry's drift resolved",
				SDKOnly: []string{"c_old"},
			},
		},
	}
	dir, specsDir := scratchTree(t, prev)

	err := run(specsDir, "newsha", false)
	if err == nil {
		t.Fatal("run must refuse to silently drop a curated note without --drop-notes")
	}
	if !strings.Contains(err.Error(), "drop-notes") || !strings.Contains(err.Error(), "1 curated") {
		t.Errorf("refusal must name the flag and the drop count, got: %v", err)
	}

	if err := run(specsDir, "newsha", true); err != nil {
		t.Fatalf("run with --drop-notes must proceed: %v", err)
	}
	got := readBaseline(t, dir)
	if clean, exists := got.PerTypeDrift["Clean"]; exists {
		t.Errorf("Clean entry should have burned down entirely under --drop-notes, got %+v", clean)
	}
}

// TestRunFailsOnCorruptPreviousBaseline proves a corrupt (unreadable or
// unparsable) previous baseline fails the run instead of being treated
// as "no previous baseline" - that path would discard every curated
// note while exiting 0.
func TestRunFailsOnCorruptPreviousBaseline(t *testing.T) {
	dir, specsDir := scratchTree(t, nil)
	if err := os.WriteFile(filepath.Join(dir, "testdata", "wire_shape_baseline.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write corrupt baseline: %v", err)
	}
	err := run(specsDir, "newsha", false)
	if err == nil {
		t.Fatal("run must fail on a corrupt previous baseline, not silently drop all notes")
	}
	if !strings.Contains(err.Error(), "cannot be used") {
		t.Errorf("error should say the previous baseline cannot be used, got: %v", err)
	}
}

// TestRunBootstrapsWithoutPreviousBaseline proves the genuine bootstrap
// path (no baseline file at all) still works.
func TestRunBootstrapsWithoutPreviousBaseline(t *testing.T) {
	dir, specsDir := scratchTree(t, nil)
	if err := run(specsDir, "newsha", false); err != nil {
		t.Fatalf("bootstrap run: %v", err)
	}
	got := readBaseline(t, dir)
	if _, ok := got.PerTypeDrift["Foo"]; !ok {
		t.Error("bootstrap regen must record Foo's drift")
	}
}
