package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The language-neutral AuthZEN surface artifact, as this emitter reads it.
//
// These declarations mirror the platform's producer side. They are a SUBSET on
// purpose: an emitter should fail on an artifact field it does not understand
// rather than generate around it, which is why ParseSurface rejects unknown
// members instead of ignoring them.

// Surface is the whole artifact.
type Surface struct {
	Artifact        string `json:"artifact"`
	ArtifactVersion int    `json:"artifact_version"`
	Profile         string `json:"profile"`
	// ProfileHeader and Route are the request header the profile is negotiated
	// with and the one route the surface is served on. Both come from the
	// platform's contract constants through the artifact, so this SDK
	// generates the path and header it calls rather than transcribing them
	// (#3603: five hand-written copies, nothing checking them).
	ProfileHeader         string `json:"profile_header"`
	Route                 Route  `json:"route"`
	ContractSchemaVersion string `json:"contract_schema_version"`
	SourceSchemaID        string `json:"source_schema_id"`
	SourceSchemaSHA256    string `json:"source_schema_sha256"`
	Enums                 []Enum `json:"enums"`
	Types                 []Type `json:"types"`
}

// Enum is a closed set of string values.
// Route is the HTTP method and path of the surface's single route.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type Enum struct {
	Name   string   `json:"name"`
	Doc    string   `json:"doc,omitempty"`
	Values []string `json:"values"`
}

// Type is one object shape.
type Type struct {
	Name         string     `json:"name"`
	Doc          string     `json:"doc,omitempty"`
	Fields       []Field    `json:"fields"`
	ExactlyOneOf [][]string `json:"exactly_one_of,omitempty"`
}

// Field is one member of a type.
type Field struct {
	Name            string   `json:"name"`
	Doc             string   `json:"doc,omitempty"`
	Required        bool     `json:"required"`
	Type            TypeRef  `json:"type"`
	MinItems        int      `json:"min_items,omitempty"`
	MinLength       int      `json:"min_length,omitempty"`
	RequiresMembers []string `json:"requires_members,omitempty"`
	Const           string   `json:"const,omitempty"`
}

// TypeRef is a field's type.
type TypeRef struct {
	Kind  string   `json:"kind"`
	Ref   string   `json:"ref,omitempty"`
	Enum  string   `json:"enum,omitempty"`
	Items *TypeRef `json:"items,omitempty"`
	Value *TypeRef `json:"value,omitempty"`
}

// ParseSurface decodes the artifact STRICTLY and checks it hangs together.
//
// Strictness is the point. An artifact member this emitter does not know about
// is a construct the platform added and this SDK would silently omit - the
// declared-but-never-emitted class, arriving through the generator built to
// prevent it. Failing here costs one obvious CI error; ignoring it costs a
// field that four other SDKs have and this one does not.
func ParseSurface(raw []byte) (*Surface, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Surface
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing the surface artifact: %w", err)
	}

	// Every reference must resolve inside the document. A dangling ref would
	// otherwise become a Go type name that does not exist, and the failure
	// would surface as a compile error in generated code rather than as a
	// statement about the artifact.
	// The route and header are what the generated client CALLS. An artifact
	// without them would generate a client with nowhere to send a request, so
	// they are required, not defaulted.
	if s.Route.Method != "POST" || !strings.HasPrefix(s.Route.Path, "/") || strings.HasSuffix(s.Route.Path, "/") {
		return nil, fmt.Errorf("the artifact's route is %q %q; want POST and an absolute path with no trailing slash", s.Route.Method, s.Route.Path)
	}
	if s.ProfileHeader == "" || strings.ContainsAny(s.ProfileHeader, " :\n") {
		return nil, fmt.Errorf("the artifact's profile_header %q is not a header name", s.ProfileHeader)
	}
	types := map[string]bool{}
	for _, t := range s.Types {
		if types[t.Name] {
			return nil, fmt.Errorf("the artifact declares the type %q twice", t.Name)
		}
		types[t.Name] = true
	}
	enums := map[string]bool{}
	for _, e := range s.Enums {
		if enums[e.Name] {
			return nil, fmt.Errorf("the artifact declares the enum %q twice", e.Name)
		}
		if len(e.Values) == 0 {
			return nil, fmt.Errorf("enum %q has no values", e.Name)
		}
		enums[e.Name] = true
	}
	for _, t := range s.Types {
		if len(t.Fields) == 0 {
			return nil, fmt.Errorf("type %q has no fields", t.Name)
		}
		fields := map[string]bool{}
		for _, f := range t.Fields {
			if fields[f.Name] {
				return nil, fmt.Errorf("type %q declares the field %q twice", t.Name, f.Name)
			}
			fields[f.Name] = true
			if err := checkRef(t.Name+"."+f.Name, f.Type, types, enums); err != nil {
				return nil, err
			}
		}
		for _, group := range t.ExactlyOneOf {
			if len(group) < 2 {
				return nil, fmt.Errorf("type %q has an exactly-one-of group with %d members", t.Name, len(group))
			}
			for _, m := range group {
				if !fields[m] {
					return nil, fmt.Errorf("type %q names %q in an exactly-one-of group but has no such field", t.Name, m)
				}
			}
		}
	}
	return &s, nil
}

func checkRef(where string, tr TypeRef, types, enums map[string]bool) error {
	switch tr.Kind {
	case "ref":
		if !types[tr.Ref] {
			return fmt.Errorf("%s references the type %q, which the artifact does not define", where, tr.Ref)
		}
	case "enum":
		if !enums[tr.Enum] {
			return fmt.Errorf("%s references the enum %q, which the artifact does not define", where, tr.Enum)
		}
	case "array":
		if tr.Items == nil {
			return fmt.Errorf("%s is an array with no item type", where)
		}
		return checkRef(where+"[]", *tr.Items, types, enums)
	case "map":
		if tr.Value == nil {
			return fmt.Errorf("%s is a map with no value type", where)
		}
		return checkRef(where+"{}", *tr.Value, types, enums)
	case "string", "bool", "int", "object":
	default:
		return fmt.Errorf("%s has the unsupported type kind %q", where, tr.Kind)
	}
	return nil
}
