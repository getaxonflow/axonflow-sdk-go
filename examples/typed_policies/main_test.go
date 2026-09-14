package main

import (
	"bytes"
	"os"
	"testing"
)

// The embedded default body is the vendored fixture, byte for byte: the example
// runs from any directory, and what it publishes is what the runtime proofs
// publish.
func TestTheEmbeddedBodyIsTheVendoredFixture(t *testing.T) {
	want, err := os.ReadFile("../../testdata/typed_policy_publish_body.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultBody) == 0 || !bytes.Equal(defaultBody, want) {
		t.Errorf("examples/typed_policies/typed_policy_publish_body.json (%d bytes) differs from testdata/typed_policy_publish_body.json (%d bytes): copy the fixture again", len(defaultBody), len(want))
	}
}
