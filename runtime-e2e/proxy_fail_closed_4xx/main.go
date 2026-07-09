//go:build ignore

// runtime-e2e/proxy_fail_closed_4xx/main.go
//
// Real-stack assertion: production-mode fail-open must NOT swallow definitive
// 4xx responses from the agent (getaxonflow/axonflow-enterprise#2861).
//
// Per CLAUDE.md HARD RULE #0 this driver MUST hit a real running AxonFlow
// agent — no httptest, no fixture servers.
//
// Regression background: ProxyLLMCall in Mode="production" used to convert an
// HTTP 401 (invalid credentials / invalid user token) into a synthetic
// success=true "fail-open" response, because the retry wrapper's
// "request failed after N attempts" prefix matched the string-based
// isAxonFlowError check. An auth failure silently became an ungoverned
// success. Fail-open is for AVAILABILITY failures (agent down, 5xx), never
// for definitive client errors.
//
// Assertions against a live agent:
//
//  1. ProxyLLMCall with syntactically valid Basic credentials but a garbage
//     user token returns an ERROR in production mode (HTTP 401 surfaces; no
//     fail-open success).
//  2. ProxyLLMCall with wrong Basic credentials returns an ERROR in
//     production mode (HTTP 401 surfaces; no fail-open success).
//  3. With valid credentials + valid JWT the same call succeeds, proving the
//     failure in (1)/(2) is the auth path, not the stack.
//
// Run locally (after `source /tmp/axonflow-e2e-env.sh` from the enterprise
// setup script):
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 \
//	AXONFLOW_CLIENT_ID="$AXONFLOW_CLIENT_ID" \
//	AXONFLOW_CLIENT_SECRET="$AXONFLOW_CLIENT_SECRET" \
//	AXONFLOW_USER_TOKEN="$AXONFLOW_USER_TOKEN" \
//	go run runtime-e2e/proxy_fail_closed_4xx/main.go
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func newClient(agentURL, clientID, clientSecret string) *axonflow.AxonFlowClient {
	return axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Mode:         "production", // fail-open enabled — the surface under test
		Retry: axonflow.RetryConfig{
			Enabled:      true, // retry wrapper prefix is what used to trip fail-open
			MaxAttempts:  2,
			InitialDelay: 50 * time.Millisecond,
		},
		Timeout: 30 * time.Second,
		Cache:   axonflow.CacheConfig{Enabled: false},
	})
}

func main() {
	agentURL := env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	userToken := os.Getenv("AXONFLOW_USER_TOKEN")
	if clientID == "" || clientSecret == "" || userToken == "" {
		fmt.Println("FAIL: AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN must be set (source /tmp/axonflow-e2e-env.sh)")
		os.Exit(1)
	}

	failures := 0

	// 1. Valid Basic auth, garbage user token → 401 must surface as error.
	{
		client := newClient(agentURL, clientID, clientSecret)
		resp, err := client.ProxyLLMCall("not-a-jwt", "What is 2+2?", "chat", nil)
		if err == nil {
			failures++
			fmt.Printf("FAIL [1] garbage user token: expected error, got success resp (fail-open leak): %+v\n", resp)
		} else if !strings.Contains(err.Error(), "401") {
			failures++
			fmt.Printf("FAIL [1] garbage user token: expected HTTP 401 in error, got: %v\n", err)
		} else {
			fmt.Println("PASS [1] garbage user token surfaces HTTP 401 error in production mode (no fail-open)")
		}
	}

	// 2. Wrong Basic credentials → 401 must surface as error.
	{
		client := newClient(agentURL, "demo-org", "demo-license-not-real")
		resp, err := client.ProxyLLMCall(userToken, "What is 2+2?", "chat", nil)
		if err == nil {
			failures++
			fmt.Printf("FAIL [2] wrong Basic creds: expected error, got success resp (fail-open leak): %+v\n", resp)
		} else if !strings.Contains(err.Error(), "401") {
			failures++
			fmt.Printf("FAIL [2] wrong Basic creds: expected HTTP 401 in error, got: %v\n", err)
		} else {
			fmt.Println("PASS [2] wrong Basic credentials surface HTTP 401 error in production mode (no fail-open)")
		}
	}

	// 3. Control: valid creds + valid JWT succeeds on the same stack.
	{
		client := newClient(agentURL, clientID, clientSecret)
		resp, err := client.ProxyLLMCall(userToken, "What is 2+2?", "chat", nil)
		if err != nil {
			failures++
			fmt.Printf("FAIL [3] control call with valid creds errored: %v\n", err)
		} else if !resp.Success {
			failures++
			fmt.Printf("FAIL [3] control call returned success=false: %s\n", resp.Error)
		} else {
			fmt.Println("PASS [3] control call with valid credentials + JWT succeeds")
		}
	}

	if failures > 0 {
		fmt.Printf("RESULT: FAIL (%d)\n", failures)
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS (3/3)")
}
