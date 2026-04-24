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
	RegisteredTypes     []string                       `json:"registered_types"`
	PerTypeDrift        map[string]DriftEntry          `json:"per_type_drift"`
}

// DriftEntry records the acknowledged drift between an SDK struct and
// its matching OpenAPI schema at baseline time.
type DriftEntry struct {
	SDKOnly  []string `json:"sdk_only"`
	SpecOnly []string `json:"spec_only"`
}

// NewEmptyBaseline returns a zero-value Baseline with non-nil maps so
// callers can read from it without nil checks.
func NewEmptyBaseline() Baseline {
	return Baseline{
		CrossSpecDuplicates: map[string]map[string][]string{},
		PerTypeDrift:        map[string]DriftEntry{},
	}
}

// LoadSchemas parses every *.yaml in specDir and returns
// (mergedSchemas, duplicatesBySpec).
//
//   - mergedSchemas maps each schema name to its sorted property names.
//     On name collision the last-loaded declaration wins — this is the
//     set of shapes the gate diffs SDK structs against.
//
//   - duplicatesBySpec contains only schemas whose declarations DIFFER
//     across specs (identical redundant declarations are benign).
//     Keyed by {schemaName: {specFilename: sortedFields}}. The baseline
//     pins these so an already-acknowledged cross-spec collision cannot
//     quietly drift further.
func LoadSchemas(specDir string) (map[string][]string, map[string]map[string][]string, error) {
	merged := map[string][]string{}
	allDecls := map[string]map[string][]string{}

	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", specDir, err)
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
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", full, err)
		}
		// yaml.v3 is strict on duplicate mapping keys. Python's
		// yaml.safe_load is lenient (last-wins). To keep the Go and
		// Python gates seeing the same specs, decode into a tolerant
		// Node tree and fold it to a map ourselves with last-wins
		// semantics. A duplicate key here is itself a platform spec
		// bug worth tracking, but it must not block the SDK gate on
		// every other schema.
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", full, err)
		}
		doc, ok := NodeToMap(&root)
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

// DiscoverSDKTypes walks the non-test .go files under pkgDir and
// returns {StructName: sortedWireFieldNames} for every exported struct
// with at least one JSON-tagged field.
//
// Go doesn't offer a runtime "list all types in a package" the way
// Python's pkgutil.walk_packages does, so we parse the AST directly.
// Type aliases (TypeSpec.Assign != 0) are ignored because their Type
// is *ast.Ident, not *ast.StructType. Embedded fields appear as
// FieldList entries with empty Names — not handled today because the
// axonflow SDK's public types don't use embedding; if that changes,
// add recursive resolution here.
func DiscoverSDKTypes(pkgDir string) (map[string][]string, error) {
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

// extractWireFieldsFromAST returns the sorted wire-shape names for a
// struct's fields. "Wire shape" means: json tag name if set, Go field
// name otherwise. Fields tagged `json:"-"` are skipped. Anonymous
// (embedded) fields are skipped for now — see DiscoverSDKTypes.
func extractWireFieldsFromAST(st *ast.StructType) []string {
	if st.Fields == nil {
		return nil
	}
	out := []string{}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			continue // embedded; not handled, see note on DiscoverSDKTypes
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
	return out
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

// NodeToMap folds the top-level YAML document into a map[string]any
// with last-wins semantics on duplicate keys. See LoadSchemas for the
// rationale.
func NodeToMap(n *yaml.Node) (map[string]any, bool) {
	v := nodeToValue(n)
	m, ok := v.(map[string]any)
	return m, ok
}

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
