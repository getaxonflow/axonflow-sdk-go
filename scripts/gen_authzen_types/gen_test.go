package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The generator runs from the repository root, so these tests reach back up to
// read the same files the command does.
const (
	repoSurface = "../../testdata/authzen-surface.json"
	repoOutput  = "../../authzen_types_gen.go"
)

func loadSurface(t *testing.T) *Surface {
	t.Helper()
	raw, err := os.ReadFile(repoSurface)
	if err != nil {
		t.Fatalf("reading the surface artifact: %v", err)
	}
	s, err := ParseSurface(raw)
	if err != nil {
		t.Fatalf("parsing the surface artifact: %v", err)
	}
	return s
}

// TestCommittedTypesAreCurrent is the regeneration-is-clean gate.
//
// The generated file is committed so a consumer running `go get` receives
// working types without running a generator. That is only trustworthy if
// something proves the committed bytes are the output of the committed input --
// otherwise "generated" is a claim in a header comment rather than a fact.
//
// It fails on BOTH edits: changing the artifact without regenerating, and hand
// editing the generated file.
func TestCommittedTypesAreCurrent(t *testing.T) {
	want, err := Emit(loadSurface(t))
	if err != nil {
		t.Fatalf("emitting: %v", err)
	}
	have, err := os.ReadFile(repoOutput)
	if err != nil {
		t.Fatalf("reading %s: %v", repoOutput, err)
	}
	if !bytes.Equal(have, want) {
		t.Errorf("%s is not what %s generates.\nRegenerate it in the same change:\n"+
			"  go run ./scripts/gen_authzen_types",
			filepath.Base(repoOutput), filepath.Base(repoSurface))
	}
}

// TestGenerationIsDeterministic is why the check above can be trusted.
//
// Both the type list and each type's fields arrive from JSON. If any ordering
// leaked from a map, the committed-file check would fail on unrelated pull
// requests until somebody deleted it as flaky.
func TestGenerationIsDeterministic(t *testing.T) {
	s := loadSurface(t)
	first, err := Emit(s)
	if err != nil {
		t.Fatalf("emitting: %v", err)
	}
	for i := 0; i < 16; i++ {
		got, err := Emit(s)
		if err != nil {
			t.Fatalf("emitting: %v", err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("emission %d differs from the first; the generator is leaking an ordering", i+1)
		}
	}
}

// TestGeneratedFileCoversTheWholeArtifact is the anti-vacuity guard.
//
// The two tests above compare the generator against itself, so both stay green
// over a generator that emitted an empty file. This one asserts the output
// actually contains every type and every enum value the artifact declares.
func TestGeneratedFileCoversTheWholeArtifact(t *testing.T) {
	s := loadSurface(t)
	src, err := os.ReadFile(repoOutput)
	if err != nil {
		t.Fatalf("reading %s: %v", repoOutput, err)
	}
	got := string(src)

	if len(s.Types) == 0 || len(s.Enums) == 0 {
		t.Fatal("the artifact is empty; every assertion here would be vacuous")
	}
	for _, tp := range s.Types {
		decl := "type " + goTypeName(tp.Name) + " struct {"
		if !strings.Contains(got, decl) {
			t.Errorf("the generated file has no %q", decl)
			continue
		}
		// Scoped to THIS struct's block. A whole-file substring search reads
		// the envelope's optional `evaluations,omitempty` while checking the
		// bulk's REQUIRED `evaluations`, and reports a defect that is not
		// there - two types legitimately share a field name.
		block := got[strings.Index(got, decl)+len(decl):]
		block = block[:strings.Index(block, "\n}\n")]
		for _, f := range tp.Fields {
			// The json tag is the wire contract; the Go field name is not. A
			// renamed tag is a field the server cannot see.
			tag := "`json:\"" + f.Name
			if !strings.Contains(block, tag+"\"`") && !strings.Contains(block, tag+",omitempty\"`") {
				t.Errorf("%s.%s has no json tag in the generated file", tp.Name, f.Name)
			}
			// Optionality must survive into the tag, or a client omits a field
			// the server requires and gets a refusal it cannot explain.
			hasOmit := strings.Contains(block, tag+",omitempty\"`")
			if f.Required && hasOmit {
				t.Errorf("%s.%s is required but generated with omitempty", tp.Name, f.Name)
			}
			if !f.Required && !hasOmit {
				t.Errorf("%s.%s is optional but generated without omitempty", tp.Name, f.Name)
			}
		}
	}
	for _, e := range s.Enums {
		for _, v := range e.Values {
			if !strings.Contains(got, "= \""+v+"\"") {
				t.Errorf("enum %s is missing the value %q", e.Name, v)
			}
		}
	}
	// The envelope's exactly-one rule and the singular member's own required
	// set are the two constructs no struct tag can carry. If either stopped
	// being emitted the types would still compile and would build requests the
	// server refuses.
	if !strings.Contains(got, "exactly one of evaluation or evaluations") {
		t.Error("the envelope's exactly-one-of rule is not enforced in the generated file")
	}
	if !strings.Contains(got, "it has no shared base to inherit one from") {
		t.Error("the singular member's own required set is not enforced in the generated file")
	}
}

// TestPluralTypeNameFormsTheEnglishPlural pins the exported accessor names.
//
// The expectations are written by hand rather than derived from the emitter, so
// this is a statement about the names and not a restatement of the code that
// makes them. It matters because those names are exported: AllAuthZENCategorys
// would be a compatibility commitment for the life of the surface, and the same
// emitter shape ships in four sibling SDKs.
func TestPluralTypeNameFormsTheEnglishPlural(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The one the naive rule got wrong, and the five it happened to get right.
		{"AuthZENCategory", "AuthZENCategories"},
		{"AuthZENErrorCode", "AuthZENErrorCodes"},
		{"AuthZENIdentifierKind", "AuthZENIdentifierKinds"},
		{"AuthZENObligationType", "AuthZENObligationTypes"},
		{"AuthZENOperationalState", "AuthZENOperationalStates"},
		{"AuthZENReasonCode", "AuthZENReasonCodes"},
		// Shapes a later enum could arrive in.
		{"AuthZENPolicy", "AuthZENPolicies"},
		{"AuthZENKey", "AuthZENKeys"},
		{"AuthZENStatus", "AuthZENStatuses"},
		{"AuthZENBranch", "AuthZENBranches"},
		{"AuthZENIndex", "AuthZENIndices"},
	} {
		if got := pluralTypeName(tc.in); got != tc.want {
			t.Errorf("pluralTypeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestGeneratedAccessorsCarryThePluralName checks the committed file, because
// the rule above is only worth anything if the emission uses it in BOTH places
// it spells the accessor: the declaration and the Valid loop that calls it.
func TestGeneratedAccessorsCarryThePluralName(t *testing.T) {
	s := loadSurface(t)
	src, err := os.ReadFile(repoOutput)
	if err != nil {
		t.Fatalf("reading %s: %v", repoOutput, err)
	}
	got := string(src)
	if strings.Contains(got, "AllAuthZENCategorys") {
		t.Error("the generated file still carries the naive plural AllAuthZENCategorys")
	}
	for _, e := range s.Enums {
		name := goTypeName(e.Name)
		all := "All" + pluralTypeName(name)
		if !strings.Contains(got, "func "+all+"() []"+name+" {") {
			t.Errorf("the generated file declares no %s()", all)
		}
		if !strings.Contains(got, "range "+all+"()") {
			t.Errorf("%s.Valid does not call %s()", name, all)
		}
	}
}

// TestATypeReachingAValidatedMemberGetsAValidate pins the fixed point.
//
// A type with no required member of its own still needs a Validate when it
// carries a member whose type has one. Without it the local checks were
// asymmetric: the envelope nil-checked its singular's subject and nothing
// called the subject's own validator, so a subject left at the Go zero value
// went to the server as "type": "".
func TestATypeReachingAValidatedMemberGetsAValidate(t *testing.T) {
	s := loadSurface(t)
	validated := computeValidated(s)

	for _, tp := range s.Types {
		for _, f := range tp.Fields {
			ref, ok := validatableRef(f.Type)
			if ok && validated[ref] && !validated[tp.Name] {
				t.Errorf("%s.%s reaches %s, which validates, but %s has no Validate to call it from",
					tp.Name, f.Name, ref, tp.Name)
			}
		}
	}

	// The anti-vacuity leg: the loop above is satisfied by a surface where
	// every type qualifies on its own account, which is what it looked like
	// before. At least one type must qualify ONLY through composition, or the
	// fixed point is doing nothing and the assertion proves nothing.
	composed := 0
	for _, tp := range s.Types {
		if validated[tp.Name] && !typeHasOwnValidate(tp) {
			composed++
		}
	}
	if composed == 0 {
		t.Error("no type in the artifact qualifies for a Validate through a member's type; " +
			"the assertion above cannot fail and proves nothing")
	}
}

// TestParseSurfaceRefusesWhatItCannotGenerate pins the fail-loud rule.
//
// An artifact member this emitter does not understand is a construct the
// platform added and this SDK would silently omit -- the same
// declared-but-never-emitted class the contract guards exist for, arriving
// through the generator built to prevent it.
func TestParseSurfaceRefusesWhatItCannotGenerate(t *testing.T) {
	valid := `{"artifact":"axonflow-authzen-surface","artifact_version":1,"profile":"p",
	  "contract_schema_version":"v","source_schema_id":"i","source_schema_sha256":"s",
	  "enums":[{"name":"e","values":["a"]}],
	  "types":[{"name":"t","fields":[{"name":"f","required":true,"type":{"kind":"string"}}]}]}`

	for _, tc := range []struct{ name, doc string }{
		{"an unknown artifact member", strings.Replace(valid, `"enums":`, `"transport":"grpc","enums":`, 1)},
		{"an unknown type kind", strings.Replace(valid, `{"kind":"string"}`, `{"kind":"decimal"}`, 1)},
		{"a dangling type reference", strings.Replace(valid, `{"kind":"string"}`, `{"kind":"ref","ref":"nope"}`, 1)},
		{"a dangling enum reference", strings.Replace(valid, `{"kind":"string"}`, `{"kind":"enum","enum":"nope"}`, 1)},
		{"an array with no item type", strings.Replace(valid, `{"kind":"string"}`, `{"kind":"array"}`, 1)},
		{"a map with no value type", strings.Replace(valid, `{"kind":"string"}`, `{"kind":"map"}`, 1)},
		{"an enum with no values", strings.Replace(valid, `"values":["a"]`, `"values":[]`, 1)},
		{"a type with no fields", strings.Replace(valid, `"fields":[{"name":"f","required":true,"type":{"kind":"string"}}]`, `"fields":[]`, 1)},
		{"an exactly-one-of naming a field that does not exist", strings.Replace(valid,
			`"fields":[{"name":"f","required":true,"type":{"kind":"string"}}]`,
			`"exactly_one_of":[["f","g"]],"fields":[{"name":"f","required":true,"type":{"kind":"string"}}]`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSurface([]byte(tc.doc)); err == nil {
				t.Errorf("the emitter accepted %s; it would have been dropped from this SDK", tc.name)
			}
		})
	}

	// The control, so none of the above is passing because the fixture itself
	// is malformed.
	if _, err := ParseSurface([]byte(valid)); err != nil {
		t.Fatalf("the emitter refused a supported fixture: %v", err)
	}
}

// TestEmitRefusesAnUnsupportedArtifactVersion pins the format gate.
//
// A format change is a deliberate migration. Generating through one would
// produce types that look right and describe a different contract.
func TestEmitRefusesAnUnsupportedArtifactVersion(t *testing.T) {
	s := loadSurface(t)
	s.ArtifactVersion = 2
	if _, err := Emit(s); err == nil {
		t.Error("the emitter generated from an artifact format it does not support")
	}

	s = loadSurface(t)
	s.Artifact = "something-else"
	if _, err := Emit(s); err == nil {
		t.Error("the emitter generated from an artifact that is not an AuthZEN surface")
	}

	s = loadSurface(t)
	s.Types = nil
	if _, err := Emit(s); err == nil {
		t.Error("the emitter generated an empty SDK surface")
	}
}
