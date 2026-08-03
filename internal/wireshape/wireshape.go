// Package wireshape holds the shared building blocks for the QF-15 Go-arm
// wire-shape contract check: OpenAPI schema extraction, Go struct
// discovery via AST, and the baseline JSON type. It is imported by both
// contract_wire_shape_test.go (the gate) and
// scripts/refresh_wire_shape_baseline/main.go (the regenerator) so the
// two tools cannot drift apart.
//
// The package lives under internal/ so consumers of the SDK cannot
// import it; the yaml.v3 dep it pulls in is not linked into any
// consumer binary.
package wireshape

import (
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

	yaml "gopkg.in/yaml.v3"
)

// Baseline mirrors testdata/wire_shape_baseline.json so the test and
// the refresher can round-trip the same fixture without field-name skew.
type Baseline struct {
	Comment             string                         `json:"_comment,omitempty"`
	OpenAPISpecsSHA     string                         `json:"openapi_specs_sha"`
	CrossSpecDuplicates map[string]map[string][]string `json:"cross_spec_duplicates"`
	// IntraFileDuplicates records schemas declared more than once in the
	// same spec file. Key: spec filename → schema name → declaration count.
	// yaml.v3 would collapse these before the gate ever saw them; this
	// field exists so such collisions must be explicitly acknowledged.
	// Each entry should carry a tracking issue.
	IntraFileDuplicates map[string]map[string]int `json:"intra_file_duplicates"`
	RegisteredTypes     []string                  `json:"registered_types"`
	PerTypeDrift        map[string]DriftEntry     `json:"per_type_drift"`
}

// DriftEntry records the acknowledged drift between an SDK struct and
// its matching OpenAPI schema at baseline time.
//
// Note is the curated human rationale for the entry (tracking issue,
// burn-down condition). It is round-tripped by the baseline refresher
// (see CarryDriftNotes) so a regen does not silently drop the paper
// trail that authorizes the drift.
type DriftEntry struct {
	Note     string   `json:"_note,omitempty"`
	SDKOnly  []string `json:"sdk_only"`
	SpecOnly []string `json:"spec_only"`
}

// CarryDriftNotes reconciles the curated _note keys of a previous
// baseline's per_type_drift with a freshly computed drift map:
//
//   - a note is copied onto the freshly computed entry with the same
//     type name (never invented, never overwriting);
//   - a vanished-type ACKNOWLEDGMENT entry (empty sdk_only AND empty
//     spec_only, non-empty note, and the type still unmapped on at
//     least one side) is preserved wholesale - it is the sanctioned
//     shape for a type that must outlive its spec declaration, and a
//     regen must not delete the paper trail;
//   - every other previously noted entry that does not survive (entry
//     burned down, type renamed, or an acknowledgment whose type now
//     maps on both sides again) is reported in the returned dropped
//     list ("name: note") so the caller can refuse to discard curated
//     rationale silently.
func CarryDriftNotes(prev, next map[string]DriftEntry, sdk, spec map[string][]string) (dropped []string) {
	for name, entry := range next {
		if entry.Note != "" {
			continue
		}
		if old, ok := prev[name]; ok && old.Note != "" {
			entry.Note = old.Note
			next[name] = entry
		}
	}
	for name, old := range prev {
		if _, carried := next[name]; carried {
			continue
		}
		_, hasSDK := sdk[name]
		_, hasSpec := spec[name]
		if len(old.SDKOnly) == 0 && len(old.SpecOnly) == 0 && old.Note != "" && (!hasSDK || !hasSpec) {
			next[name] = old
		}
	}
	for name, old := range prev {
		if old.Note == "" {
			continue
		}
		if kept, ok := next[name]; !ok || kept.Note == "" {
			dropped = append(dropped, fmt.Sprintf("%s: %s", name, old.Note))
		}
	}
	sort.Strings(dropped)
	return dropped
}

// StaleBaselineProblems classifies every per_type_drift allowance
// against the observed SDK and spec shapes. It is the burn-down
// ratchet's logic, extracted so it can be table-tested independently of
// the gate that calls it (a ratchet with no test of its own fails open
// on its own mutations).
//
// Returned problems (each a human-readable line) fail the gate:
//   - a baselined field now declared on BOTH sides (drift burned down);
//   - a baselined field absent from the side that claimed it (dead
//     allowance, including phantom entries pre-authorizing future
//     drift);
//   - a VANISHED type whose entry carries ANY field allowance - the
//     only tolerated vanished-type shape is an empty entry with a
//     curated _note, otherwise a planted allowance would sit dormant
//     and pre-authorize drift the moment the type/schema returns;
//   - an empty entry whose type maps on BOTH sides - a dead entry that
//     is not a vanished-type acknowledgment (structurally covers a
//     carried-but-stale note).
//
// vanishedAcks lists the tolerated vanished-type acknowledgments for
// the caller to log.
func StaleBaselineProblems(perTypeDrift map[string]DriftEntry, sdk, spec map[string][]string) (problems, vanishedAcks []string) {
	addProblems := func(name, side string, stale []string, claimingSide, otherSide map[string]struct{}) {
		for _, f := range stale {
			_, onClaiming := claimingSide[f]
			_, onOther := otherSide[f]
			if onClaiming && onOther {
				problems = append(problems, fmt.Sprintf(
					"  %s: %s field %q is now declared on BOTH sides - the drift burned down. Remove it from the baseline entry.",
					name, side, f))
			} else {
				problems = append(problems, fmt.Sprintf(
					"  %s: %s field %q is not present on the side that claimed it - dead allowance (possibly a phantom entry pre-authorizing future drift). Remove it from the baseline entry.",
					name, side, f))
			}
		}
	}

	for name, expected := range perTypeDrift {
		sdkFields, hasSDK := sdk[name]
		specFields, hasSpec := spec[name]
		emptyEntry := len(expected.SDKOnly) == 0 && len(expected.SpecOnly) == 0

		if !hasSDK || !hasSpec {
			if emptyEntry {
				vanishedAcks = append(vanishedAcks, name)
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"  %s: type or schema does not exist at this pin, but the entry carries field allowances (sdk_only=%v spec_only=%v). A vanished-type acknowledgment must be an EMPTY entry with only a curated _note; field allowances on a vanished type would pre-authorize drift the moment the type or schema returns.",
				name, expected.SDKOnly, expected.SpecOnly))
			continue
		}
		if emptyEntry {
			problems = append(problems, fmt.Sprintf(
				"  %s: entry allows nothing and the type maps on BOTH sides - dead entry (a vanished-type acknowledgment is only valid while the type has no schema at the pin). Remove it.",
				name))
			continue
		}
		sdkSet := listToSet(sdkFields)
		specSet := listToSet(specFields)
		sdkOnly := listToSet(Difference(sdkFields, specFields))
		specOnly := listToSet(Difference(specFields, sdkFields))
		addProblems(name, "sdk_only", subtractList(expected.SDKOnly, sdkOnly), sdkSet, specSet)
		addProblems(name, "spec_only", subtractList(expected.SpecOnly, specOnly), specSet, sdkSet)
	}
	sort.Strings(problems)
	sort.Strings(vanishedAcks)
	return problems, vanishedAcks
}

func listToSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

func subtractList(a []string, b map[string]struct{}) []string {
	out := []string{}
	for _, v := range a {
		if _, ok := b[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// NewEmptyBaseline returns a zero-value Baseline with non-nil maps so
// callers can read from it without nil checks.
func NewEmptyBaseline() Baseline {
	return Baseline{
		CrossSpecDuplicates: map[string]map[string][]string{},
		IntraFileDuplicates: map[string]map[string]int{},
		PerTypeDrift:        map[string]DriftEntry{},
	}
}

// LoadSchemas parses every *.yaml in specDir and returns
// (mergedSchemas, crossSpecDuplicates, intraFileDuplicates, err).
//
//   - mergedSchemas maps each schema name to its sorted property names.
//     On any name collision (intra-file or cross-file) the last-seen
//     declaration wins; this is the set of shapes the gate diffs SDK
//     structs against.
//
//   - crossSpecDuplicates contains schemas whose declarations DIFFER
//     across spec files (identical redundant declarations are benign).
//     Keyed by {schemaName: {specFilename: sortedFields}}. The baseline
//     pins these so an already-acknowledged cross-spec collision can't
//     quietly widen later.
//
//   - intraFileDuplicates records schemas declared more than once in
//     the same file. Keyed by {specFilename: {schemaName: count}}.
//     yaml.v3 would collapse these at map-decode time, hiding the bug
//     (see the real PolicyMatch duplicate in orchestrator-api.yaml),
//     so we walk the Node tree manually at components.schemas level
//     and count pairs before any map dedup happens.
func LoadSchemas(specDir string) (
	merged map[string][]string,
	crossSpecDuplicates map[string]map[string][]string,
	intraFileDuplicates map[string]map[string]int,
	err error,
) {
	merged = map[string][]string{}
	allDecls := map[string]map[string][]string{}
	intraFileDuplicates = map[string]map[string]int{}

	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read %s: %w", specDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		full := filepath.Join(specDir, name)
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			return nil, nil, nil, fmt.Errorf("read %s: %w", full, readErr)
		}
		// yaml.v3 errors on duplicate mapping keys by default; Python's
		// yaml.safe_load is lenient (last-wins). To keep the Go and
		// Python gates seeing the same specs, decode into a tolerant
		// Node tree.
		var root yaml.Node
		if parseErr := yaml.Unmarshal(data, &root); parseErr != nil {
			return nil, nil, nil, fmt.Errorf("parse %s: %w", full, parseErr)
		}
		schemasNode := findSchemasNode(&root)
		if schemasNode == nil {
			continue
		}

		// Walk components.schemas pairwise so we can count intra-file
		// duplicates before any map collapses them.
		intraCounts := map[string]int{}
		for i := 0; i+1 < len(schemasNode.Content); i += 2 {
			keyNode := schemasNode.Content[i]
			valNode := schemasNode.Content[i+1]
			if keyNode.Kind != yaml.ScalarNode {
				continue
			}
			schemaName := keyNode.Value
			intraCounts[schemaName]++

			schemaMap, ok := nodeToValue(valNode).(map[string]any)
			if !ok {
				continue
			}
			props, ok := schemaMap["properties"].(map[string]any)
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
			// Last-wins inside a file: overwriting allDecls[name][file]
			// here matches the merged-schemas last-wins semantic and
			// keeps the cross-file comparison clean.
			allDecls[schemaName][name] = fields
			merged[schemaName] = fields
		}
		for schemaName, count := range intraCounts {
			if count > 1 {
				if intraFileDuplicates[name] == nil {
					intraFileDuplicates[name] = map[string]int{}
				}
				intraFileDuplicates[name][schemaName] = count
			}
		}
	}

	crossSpecDuplicates = map[string]map[string][]string{}
	for schemaName, decls := range allDecls {
		if len(decls) < 2 {
			continue
		}
		shapes := map[string]struct{}{}
		for _, f := range decls {
			shapes[strings.Join(f, "|")] = struct{}{}
		}
		if len(shapes) > 1 {
			crossSpecDuplicates[schemaName] = decls
		}
	}
	return merged, crossSpecDuplicates, intraFileDuplicates, nil
}

// findSchemasNode navigates the YAML tree to components.schemas and
// returns the MappingNode there (or nil if the path doesn't exist /
// isn't a map). Needed because yamlNodeToMap would collapse duplicate
// keys at every level, including the components.schemas level we
// specifically need to inspect for intra-file duplicates.
func findSchemasNode(root *yaml.Node) *yaml.Node {
	top := root
	if top != nil && top.Kind == yaml.DocumentNode && len(top.Content) > 0 {
		top = top.Content[0]
	}
	if top == nil || top.Kind != yaml.MappingNode {
		return nil
	}
	compsNode := findMapChild(top, "components")
	if compsNode == nil || compsNode.Kind != yaml.MappingNode {
		return nil
	}
	schemas := findMapChild(compsNode, "schemas")
	if schemas == nil || schemas.Kind != yaml.MappingNode {
		return nil
	}
	return schemas
}

func findMapChild(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		k := mapping.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// DiscoverSDKTypes walks the non-test .go files under pkgDir and
// returns {StructName: sortedWireFieldNames} for every exported struct
// with at least one JSON-tagged field.
//
// ExcludedTypes names Go types that legitimately do not participate in
// the wire contract. Each entry needs a one-line reason. It is the
// single source of truth for the gate (contract_wire_shape_test.go
// aliases it) AND the baseline refresher, and it is consulted BEFORE
// the embedded-field check so a genuinely non-wire type (e.g. one
// embedding sync.Mutex) can be excluded instead of flattened.
var ExcludedTypes = map[string]string{}

// Go doesn't offer a runtime "list all types in a package" the way
// Python's pkgutil.walk_packages does, so we parse the AST directly.
//
// Embedded fields are REJECTED with a hard error rather than skipped or
// resolved: encoding/json promotes an embedded struct's fields onto the
// outer type's wire shape, so a skipped embed is a smuggling channel -
// any field added through it would reach the wire while staying
// invisible to every TestWireShape* gate. Rather than blacklist that
// shape, the capability is removed: a struct declaration with ANY
// embedded field fails discovery (and with it the gate and the baseline
// refresher). The check runs on EVERY struct declaration in the
// package, exported or not, because an unexported embed-carrying struct
// reaches the wire through an exported alias, an exported defined type,
// or as the type of a named field on an exported struct. Types listed
// in ExcludedTypes are skipped (excluded from both the embed check and
// the wire mapping) - that is the sanctioned escape for genuinely
// non-wire types.
//
// Exported aliases (`type A = b`) and exported defined types
// (`type A b`) whose target resolves to a struct declared in this
// package are registered under the exported name with the target's
// fields, so a schema-named alias (e.g. CreateOverrideRequest) cannot
// escape the contract by pointing at a differently named struct.
func DiscoverSDKTypes(pkgDir string) (map[string][]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgDir, func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", pkgDir, err)
	}

	// Pass 1: collect every type declaration in the package - struct
	// declarations by name (any export status) and ident-target
	// declarations (aliases and defined types over a named type).
	structDecls := map[string]*ast.StructType{}
	identTargets := map[string]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				switch t := ts.Type.(type) {
				case *ast.StructType:
					structDecls[ts.Name.Name] = t
				case *ast.Ident:
					identTargets[ts.Name.Name] = t.Name
				}
				return true
			})
		}
	}

	// Pass 2: embed check over ALL struct declarations (minus explicit
	// exclusions), so an embed cannot hide behind an unexported name.
	var embeddedViolations []string
	for name, st := range structDecls {
		if _, excluded := ExcludedTypes[name]; excluded {
			continue
		}
		_, embedded := extractWireFieldsFromAST(st)
		if len(embedded) > 0 {
			embeddedViolations = append(embeddedViolations, fmt.Sprintf(
				"%s (embeds %s)", name, strings.Join(embedded, ", ")))
		}
	}
	if len(embeddedViolations) > 0 {
		sort.Strings(embeddedViolations)
		return nil, fmt.Errorf(
			"struct declaration(s) use embedded fields, which encoding/json promotes "+
				"onto the wire shape while the wire-shape gate cannot see them: %s. "+
				"Flatten the embedded struct into named, json-tagged fields so every "+
				"wire field is visible to the contract gate; if the type is genuinely "+
				"not a wire type (e.g. it embeds sync.Mutex for internal locking), add "+
				"it to internal/wireshape ExcludedTypes with a one-line reason instead",
			strings.Join(embeddedViolations, "; "))
	}

	// Pass 3: register every exported name that resolves to a struct -
	// directly, or through a bounded alias/defined-type ident chain.
	result := map[string][]string{}
	for name := range structDecls {
		registerResolved(result, name, structDecls, identTargets)
	}
	for name := range identTargets {
		registerResolved(result, name, structDecls, identTargets)
	}
	return result, nil
}

// registerResolved maps an exported, non-excluded type name to the wire
// fields of the struct it resolves to (itself, or through a chain of
// same-package aliases/defined types). Non-exported names, excluded
// names, and names that do not resolve to a struct in this package are
// skipped.
func registerResolved(result map[string][]string, name string, structDecls map[string]*ast.StructType, identTargets map[string]string) {
	if !ast.IsExported(name) {
		return
	}
	if _, excluded := ExcludedTypes[name]; excluded {
		return
	}
	target := name
	seen := map[string]bool{}
	for {
		if seen[target] {
			return // cyclic declaration; nothing to register
		}
		seen[target] = true
		if st, ok := structDecls[target]; ok {
			if _, excluded := ExcludedTypes[target]; excluded {
				return // alias of an excluded type is excluded too
			}
			fields, _ := extractWireFieldsFromAST(st)
			if len(fields) > 0 {
				result[name] = fields
			}
			return
		}
		next, ok := identTargets[target]
		if !ok {
			return // resolves outside the package (or to a non-struct)
		}
		target = next
	}
}

// extractWireFieldsFromAST returns the sorted wire-shape names for a
// struct's fields plus the rendered type names of any anonymous
// (embedded) fields. "Wire shape" means: json tag name if set, Go field
// name otherwise. Fields tagged `json:"-"` are skipped. Embedded fields
// are surfaced to the caller, which treats them as a hard error - see
// DiscoverSDKTypes.
func extractWireFieldsFromAST(st *ast.StructType) (fields []string, embedded []string) {
	if st.Fields == nil {
		return nil, nil
	}
	out := []string{}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			embedded = append(embedded, renderTypeExpr(field.Type))
			continue
		}
		tagStr := ""
		if field.Tag != nil {
			tagStr = reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
		}
		wireName := ParseJSONTagName(tagStr)
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
				// No json tag — encoding/json emits the Go field name
				// verbatim (CamelCase). This won't match a snake_case
				// spec property, which is exactly what the gate should
				// surface.
				out = append(out, name.Name)
			}
		}
	}
	sort.Strings(out)
	return out, embedded
}

// renderTypeExpr renders an embedded field's type expression for the
// embedded-field error message (Ident, pkg.Sel, or a pointer to either).
func renderTypeExpr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return renderTypeExpr(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + renderTypeExpr(t.X)
	default:
		return fmt.Sprintf("%T", e)
	}
}

// ParseJSONTagName returns the name portion of a json struct tag:
// everything before the first comma. Empty string means "no tag / no
// name portion"; "-" means "omit from json" and callers should skip the
// field.
func ParseJSONTagName(tag string) string {
	if tag == "" {
		return ""
	}
	if i := strings.Index(tag, ","); i >= 0 {
		return tag[:i]
	}
	return tag
}

// nodeToValue folds a YAML tree into Go types with last-wins semantics
// on duplicate mapping keys. It is intentionally unexported: callers
// that need to detect duplicates at a specific level (like LoadSchemas
// does at components.schemas) must walk the Node tree themselves.
func nodeToValue(n *yaml.Node) any {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return nodeToValue(n.Content[0])
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			val := n.Content[i+1]
			if key.Kind != yaml.ScalarNode {
				continue
			}
			out[key.Value] = nodeToValue(val) // last wins on duplicate
		}
		return out
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			out = append(out, nodeToValue(c))
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
			return nodeToValue(n.Alias)
		}
	}
	return nil
}

// Difference returns a sorted slice containing every element of a that
// is not in b.
func Difference(a, b []string) []string {
	bs := make(map[string]struct{}, len(b))
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

// ErrNoSchemas is returned when LoadSchemas finds no schemas with
// concrete properties in specDir. Useful for callers that want a
// typed sentinel rather than counting the returned map.
var ErrNoSchemas = errors.New("no OpenAPI schemas with properties found")
