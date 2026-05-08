module github.com/getaxonflow/axonflow-sdk-go/v8

go 1.21

// Runtime implementation is pure standard library. The only non-stdlib
// dependency is gopkg.in/yaml.v3, used solely by the wire-shape contract
// test (contract_wire_shape_test.go) to load the OpenAPI specs that are
// the authoritative contract. It is not imported by any non-_test.go
// file, so consumers who build and run this SDK do not link yaml.v3
// into their binaries.
require gopkg.in/yaml.v3 v3.0.1
