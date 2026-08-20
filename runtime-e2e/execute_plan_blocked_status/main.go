//go:build ignore

// runtime-e2e/execute_plan_blocked_status/main.go
//
// Real-wire test of the #184 fix: ExecutePlan must never report Status
// "completed" for a policy-blocked execution. Spins up a tiny in-process
// HTTP server speaking the agent's /api/request envelope (real net.Listen +
// http.Serve, no httptest), drives client.ExecutePlan through the real
// net/http transport, and asserts three envelope verdicts:
//
//  1. success:true,  blocked:false -> Status "completed", nil error
//  2. success:true,  blocked:true  -> Status "failed", block reason on
//     the error and on Error (the #184 surviving gap)
//  3. success:false               -> Status "failed", error carried
//
// Run via:
//
//	go run runtime-e2e/execute_plan_blocked_status/main.go

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	var mode atomic.Value
	mode.Store("ok")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/request" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch mode.Load().(string) {
		case "ok":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  "plan ran",
			})
		case "blocked":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":      true,
				"blocked":      true,
				"block_reason": "policy sys_e2e_gate denied the plan",
			})
		case "failed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   "step 2 exploded",
			})
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: "http://" + ln.Addr().String(),
		ClientID: "runtime-e2e",
		Cache:    axonflow.CacheConfig{Enabled: false},
	})

	pass := 0

	// 1. clean success stays "completed"
	res, err := client.ExecutePlan("plan-ok")
	assertf(err == nil, "clean run: unexpected error %v", err)
	assertf(res != nil && res.Status == "completed", "clean run: want Status completed, got %+v", res)
	pass++

	// 2. the #184 gap: blocked must not read "completed"
	mode.Store("blocked")
	res, err = client.ExecutePlan("plan-blocked")
	assertf(err != nil, "blocked run: want error, got nil")
	assertf(res != nil && res.Status == "failed", "blocked run: want Status failed, got %+v", res)
	assertf(res != nil && strings.Contains(res.Error, "sys_e2e_gate"), "blocked run: block reason not carried on Error: %+v", res)
	assertf(strings.Contains(err.Error(), "sys_e2e_gate"), "blocked run: block reason not in error: %v", err)
	pass++

	// 3. envelope failure stays "failed"
	mode.Store("failed")
	res, err = client.ExecutePlan("plan-failed")
	assertf(err != nil, "failed run: want error, got nil")
	assertf(res != nil && res.Status == "failed", "failed run: want Status failed, got %+v", res)
	pass++

	fmt.Printf("execute_plan_blocked_status: %d/3 verdicts asserted\n", pass)
}

func assertf(ok bool, format string, args ...any) {
	if !ok {
		fatal(format, args...)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
