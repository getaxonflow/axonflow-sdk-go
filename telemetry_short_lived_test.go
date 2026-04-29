// Regression test for issue #1693: telemetry must be delivered even when a
// Go binary exits immediately after client init.
//
// Root cause: `go client.sendTelemetryPing()` spawned a goroutine that was
// abandoned when main() returned, silently dropping the HTTP POST to
// checkpoint. The fix makes the call synchronous so the bounded-timeout
// context.WithTimeout guarantees the POST either lands or times out before
// main() returns.
//
// This test exercises a *compiled binary in a subprocess* — not in-process
// goroutines — so it hits the real "main() returns immediately" path that
// production users experience. In-process tests can't catch this regression
// because the test binary keeps running long enough for the goroutine to
// complete.

package axonflow

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTelemetryDeliveryOnShortLivedProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess telemetry test requires POSIX go build chain")
	}

	// Mock checkpoint server captures any POST it receives.
	var received atomic.Int32
	var mu sync.Mutex
	var payloads []map[string]any

	handler := http.NewServeMux()
	handler.HandleFunc("/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		mu.Lock()
		payloads = append(payloads, payload)
		mu.Unlock()
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"latest_version":"99.99.99","source":"external"}`))
	})
	handler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"mock-1.0"}`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Locate the module root so we can build from an external cmd dir.
	// The module under test is the current one (this _test.go lives at its root).
	modRoot, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	// Build a tiny binary that imports this module (via local replace) and
	// exits immediately after NewClient — no sleep, no goroutine wait. This
	// is the exact shape of a real short-lived caller.
	binDir := t.TempDir()
	srcDir := filepath.Join(binDir, "src")
	if err := writeShortLivedBinary(srcDir, modRoot); err != nil {
		t.Fatalf("writeShortLivedBinary: %v", err)
	}
	binPath := filepath.Join(binDir, "shortlived")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = srcDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	// Run the binary, no wait, no sleep. Point telemetry at the mock server.
	// Inherit parent env so the test works on any CI runner / shell, but
	// scrub the two opt-out vars that might otherwise disable telemetry
	// (e.g. a developer shell with DO_NOT_TRACK=1 exported globally).
	runCmd := exec.Command(binPath)
	runCmd.Env = append(filterOptOutEnv(os.Environ()),
		"AXONFLOW_CHECKPOINT_URL="+server.URL+"/v1/ping",
	)
	if out, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("binary run failed: %v\n%s", err, out)
	}

	if got := received.Load(); got != 1 {
		t.Fatalf("expected 1 telemetry ping after immediate-exit binary, got %d", got)
	}
	mu.Lock()
	payload := payloads[0]
	mu.Unlock()
	if sdk, _ := payload["sdk"].(string); sdk != "go" {
		t.Errorf("ping sdk field: got %q, want %q", sdk, "go")
	}
	if _, ok := payload["instance_id"].(string); !ok {
		t.Errorf("ping missing instance_id: %+v", payload)
	}
}

// filterOptOutEnv returns the parent environment with DO_NOT_TRACK and
// AXONFLOW_TELEMETRY removed. Used so the regression test exercises the
// telemetry-enabled code path even when the developer's shell has one of
// those set globally.
func filterOptOutEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "DO_NOT_TRACK=") || strings.HasPrefix(e, "AXONFLOW_TELEMETRY=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func writeShortLivedBinary(dir, modRoot string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// go.mod that replaces the upstream module with the local checkout.
	goMod := `module shortlived

go 1.21

require github.com/getaxonflow/axonflow-sdk-go/v7 v7.0.0-00010101000000-000000000000

replace github.com/getaxonflow/axonflow-sdk-go/v7 => ` + modRoot + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		return err
	}
	main := `package main

import (
	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	_ = axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: "http://127.0.0.1:1",
	})
	// no sleep, no goroutine wait — this is the regression case
}
`
	return os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o644)
}
