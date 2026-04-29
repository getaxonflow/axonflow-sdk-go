// Cross-platform real-stack smoke for the Go SDK. See header in
// smoke_python.py for the contract this implements.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	agent := os.Getenv("AXONFLOW_AGENT_URL")
	if agent == "" {
		fmt.Fprintln(os.Stderr, "FAIL: AXONFLOW_AGENT_URL not set")
		os.Exit(1)
	}

	expected := stampPath()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agent,
		ClientID:     "smoke-test",
		ClientSecret: "smoke-secret",
	})
	_ = client.HealthCheck()
	// Constructor's heartbeat is synchronous in Go; small grace window
	// for the request-path async goroutine to settle.
	time.Sleep(500 * time.Millisecond)

	if _, err := os.Stat(expected); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: stamp not at %s: %v\n", expected, err)
		os.Exit(1)
	}
	fmt.Printf("OK: stamp at %s\n", expected)
}

// stampPath mirrors heartbeat.go's resolveStampPath() exactly. We can't
// call it directly because it's package-private to the SDK module.
func stampPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Caches", "axonflow", "go-telemetry-last-sent")
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "axonflow", "go-telemetry-last-sent")
	default:
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
			return filepath.Join(xdg, "axonflow", "go-telemetry-last-sent")
		}
		return filepath.Join(os.Getenv("HOME"), ".cache", "axonflow", "go-telemetry-last-sent")
	}
}
