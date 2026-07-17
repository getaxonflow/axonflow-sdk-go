//go:build ignore

// runtime-e2e/v91_org_id_telemetry/main.go
//
// Real-wire test of the SDK's v9.1 org_id telemetry field (#2277). The
// SDK does not expose its internal http.Client, so we run a tiny
// in-process HTTP server that pretends to be the checkpoint receiver,
// inspects the raw JSON body for the org_id field, and exits with the
// verdict. Bytes flow real → real through net/http on both sides.
//
// Run via:
//
//	# ORG_ID set — operator-supplied or cs_<uuid>:
//	ORG_ID=acme-corp go run runtime-e2e/v91_org_id_telemetry/main.go
//
//	# ORG_ID unset — sentinel:
//	unset ORG_ID && go run runtime-e2e/v91_org_id_telemetry/main.go
//
// This proof goes alongside the unit-test wire assertions in
// telemetry_test.go. Both paths run against the same SDK build; this
// one additionally exercises the real net.Listen / http.Serve stack
// rather than httptest.Server (which is functionally equivalent but
// less faithful to a production-shaped wire path).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	expectedOrgID := os.Getenv("ORG_ID")
	if expectedOrgID == "" {
		expectedOrgID = "local-dev-org"
	}

	// The SDK gates pings to once per 7 days via a stamp file at
	// os.UserCacheDir + axonflow/go-telemetry-last-sent. Nuke that
	// stamp file at the same path the SDK resolves — env var injection
	// here is too late (sharedHeartbeat is a package var initialized
	// before main() runs). This makes the proof self-contained on
	// any host without manual cleanup between runs.
	if cacheDir, cdErr := os.UserCacheDir(); cdErr == nil {
		stampPath := filepath.Join(cacheDir, "axonflow", "go-telemetry-last-sent")
		_ = os.Remove(stampPath) // ignore: stamp may not exist on first run
	}

	var capturedBody atomic.Value
	capturedBody.Store([]byte{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody.Store(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"latest_version": "8.1.0"})
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()

	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Shutdown(context.Background())

	checkpointURL := "http://" + listener.Addr().String() + "/v1/ping"
	_ = os.Setenv("AXONFLOW_CHECKPOINT_URL", checkpointURL)
	_ = os.Setenv("AXONFLOW_TELEMETRY", "")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     "https://example.invalid",
		ClientID:     "rt-e2e",
		ClientSecret: "rt-e2e",
		Mode:         "production",
	})
	_ = client

	// SDK fires telemetry on startup goroutine — give it a beat to land.
	time.Sleep(2 * time.Second)

	got := capturedBody.Load().([]byte)
	if len(got) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: no telemetry body captured (did SDK try to ping?)")
		os.Exit(1)
	}

	var payload map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: telemetry body not valid JSON: %v\n%s\n", err, string(got))
		os.Exit(1)
	}

	orgID, ok := payload["org_id"].(string)
	if !ok {
		fmt.Fprintf(os.Stderr, "FAIL: telemetry body missing org_id field; body: %s\n", string(got))
		os.Exit(1)
	}
	if orgID != expectedOrgID {
		fmt.Fprintf(os.Stderr, "FAIL: telemetry org_id = %q, want %q\n", orgID, expectedOrgID)
		os.Exit(1)
	}

	fmt.Printf("PASS: telemetry wire payload carries org_id=%q (expected=%q)\n", orgID, expectedOrgID)
	fmt.Printf("Wire body: %s\n", string(got))
}
