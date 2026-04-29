package interceptors

import (
	"os"
	"testing"
)

// TestMain sets AXONFLOW_TELEMETRY=off for all tests in this package so
// that running `go test ./...` against the SDK never sends telemetry pings
// to the checkpoint endpoint. This package's tests construct AxonFlowClient
// instances which would otherwise fire a real ping on every NewClient call.
//
// The root package's main_test.go does the same thing, but `go test ./...`
// runs each package as a separate test binary, so each package needs its
// own TestMain.
func TestMain(m *testing.M) {
	os.Setenv("AXONFLOW_TELEMETRY", "off")
	os.Exit(m.Run())
}
