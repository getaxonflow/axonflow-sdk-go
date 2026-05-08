//go:build ignore

// runtime-e2e/x-axonflow-client/main.go
//
// Per CLAUDE.md HARD RULE #0: real-wire test of the SDK's
// userAgentRoundTripper emitting X-Axonflow-Client: sdk-go/<Version>
// against a real running AxonFlow agent.
//
// The SDK does not expose its internal http.Client, so to inject a
// known X-License-Token (so the agent can answer with a deterministic
// scope_mismatch echo) we run a tiny in-process reverse proxy that
// forwards every request to the real agent endpoint and prepends
// X-License-Token. This is real-wire forwarding, not a stub: the
// proxy adds a header and copies bytes; the agent's response is what
// drives the assertion.
//
// Run via:
//   go run runtime-e2e/x-axonflow-client/main.go
//
// Prereqs: AXONFLOW_AGENT_URL, AXONFLOW_TENANT_ID, AXONFLOW_TENANT_SECRET,
// AXONFLOW_E2E_PLUGIN_TOKEN — see ../README.md.

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_AGENT_URL")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	tenant := os.Getenv("AXONFLOW_TENANT_ID")
	secret := os.Getenv("AXONFLOW_TENANT_SECRET")
	token := os.Getenv("AXONFLOW_E2E_PLUGIN_TOKEN")
	if tenant == "" || secret == "" || token == "" {
		fmt.Fprintln(os.Stderr, "AXONFLOW_TENANT_ID + AXONFLOW_TENANT_SECRET + AXONFLOW_E2E_PLUGIN_TOKEN must be set; see ../README.md")
		os.Exit(2)
	}

	// Spin up an in-process reverse proxy that forwards every request to
	// the real agent at AXONFLOW_AGENT_URL and prepends X-License-Token.
	// The SDK is pointed at this proxy. Bytes flow real → real.
	target, err := url.Parse(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid AXONFLOW_AGENT_URL: %v\n", err)
		os.Exit(2)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		req.Header.Set("X-License-Token", token)
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

	expected := "sdk-go/" + axonflow.Version
	fmt.Printf("Asserting wire X-Axonflow-Client = %s\n", expected)

	_, err = client.MCPCheckInput(context.Background(), axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
	})
	if err != nil && strings.Contains(err.Error(), fmt.Sprintf("client \"%s\"", expected)) {
		fmt.Printf("PASS: agent reflected %s in scope_mismatch response\n", expected)
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: error did not echo expected client header; got: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "UNEXPECTED 200 — agent should have rejected scope_mismatch")
	os.Exit(1)
}
