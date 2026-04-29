package axonflow

import (
	"os"
	"testing"
)

// TestMain sets AXONFLOW_TELEMETRY=off for all tests in this package so
// that running the SDK test suite never sends telemetry pings to the
// checkpoint endpoint. Individual telemetry tests override this via
// t.Setenv() when they need to verify enabled behavior.
func TestMain(m *testing.M) {
	os.Setenv("AXONFLOW_TELEMETRY", "off")
	os.Exit(m.Run())
}
