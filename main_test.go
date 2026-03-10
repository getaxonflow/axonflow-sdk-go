package axonflow

import (
	"os"
	"testing"
)

// TestMain sets DO_NOT_TRACK=1 for all tests in this package so that
// running the SDK test suite never sends telemetry pings to the
// checkpoint endpoint. Individual telemetry tests override this via
// t.Setenv() when they need to verify enabled behavior.
func TestMain(m *testing.M) {
	os.Setenv("DO_NOT_TRACK", "1")
	os.Exit(m.Run())
}
