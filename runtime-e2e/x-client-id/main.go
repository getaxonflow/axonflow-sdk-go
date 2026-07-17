//go:build ignore

// runtime-e2e/x-client-id/main.go
//
// Per CLAUDE.md HARD RULE #0: real-wire test of the SDK's v9 X-Client-ID
// header emission against a real running AxonFlow agent.
//
// The SDK does not expose its internal http.Client, so to capture the
// outbound headers we run a tiny in-process reverse proxy that
// inspects every request, asserts the X-Client-ID header, and then
// forwards to the real agent. Bytes flow real → real.
//
// Run via:
//   go run runtime-e2e/x-client-id/main.go
//
// Prereqs: AXONFLOW_AGENT_URL, AXONFLOW_TENANT_ID, AXONFLOW_TENANT_SECRET.

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync/atomic"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_AGENT_URL")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	tenant := os.Getenv("AXONFLOW_TENANT_ID")
	secret := os.Getenv("AXONFLOW_TENANT_SECRET")
	if tenant == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "AXONFLOW_TENANT_ID + AXONFLOW_TENANT_SECRET must be set; see ../README.md")
		os.Exit(2)
	}

	target, err := url.Parse(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid AXONFLOW_AGENT_URL: %v\n", err)
		os.Exit(2)
	}

	var sawClientID atomic.Value
	sawClientID.Store("")

	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		sawClientID.Store(req.Header.Get("X-Client-ID"))
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()
	go func() {
		_ = http.Serve(listener, proxy)
	}()
	proxyURL := "http://" + listener.Addr().String()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     proxyURL,
		ClientID:     tenant,
		ClientSecret: secret,
	})

	fmt.Printf("Asserting wire X-Client-ID = %q\n", tenant)

	_, _ = client.MCPCheckInput(context.Background(), axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
	})

	got := sawClientID.Load().(string)
	if got != tenant {
		fmt.Fprintf(os.Stderr, "FAIL: wire X-Client-ID = %q, want %q\n", got, tenant)
		os.Exit(1)
	}
	fmt.Printf("PASS: wire X-Client-ID = %q\n", got)
}
