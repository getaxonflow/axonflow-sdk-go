//go:build ignore

// Run against a real disposable Hosted staging Agent with a prepared 402 or
// monthly-cap 429 fixture. This driver never accepts a production origin and
// prints no credential. A local unit-test listener is not a substitute.
package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	endpoint := strings.TrimRight(os.Getenv("AXONFLOW_HOSTED_STAGING_AGENT_URL"), "/")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "try-staging.getaxonflow.com" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		fmt.Fprintln(os.Stderr, "only the HTTPS Hosted staging Agent origin is allowed")
		os.Exit(2)
	}
	clientID := os.Getenv("AXONFLOW_HOSTED_STAGING_CLIENT_ID")
	secret := os.Getenv("AXONFLOW_HOSTED_STAGING_CLIENT_SECRET")
	if clientID == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "staging fixture credential is required")
		os.Exit(2)
	}
	expected := os.Getenv("AXONFLOW_HOSTED_EXPECTED_STATUS")
	if expected != "402" && expected != "429" {
		fmt.Fprintln(os.Stderr, "AXONFLOW_HOSTED_EXPECTED_STATUS must be 402 or 429")
		os.Exit(2)
	}
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: endpoint, ClientID: clientID, ClientSecret: secret,
		Mode: "production", Retry: axonflow.RetryConfig{
			Enabled: true, MaxAttempts: 3, InitialDelay: 50 * time.Millisecond,
		}, Cache: axonflow.CacheConfig{Enabled: false},
	})
	response, err := client.ProxyLLMCall("hosted-sdk-runtime-e2e", "synthetic Hosted refusal probe", "chat", nil)
	code := "hosted_payment_required"
	if expected == "429" {
		code = "hosted_monthly_limit_reached"
	}
	if response != nil || err == nil || !strings.Contains(err.Error(), "HTTP "+expected) ||
		!strings.Contains(err.Error(), code) {
		fmt.Fprintln(os.Stderr, "Hosted refusal did not surface as a terminal HTTP error")
		os.Exit(1)
	}
	fmt.Printf("PASS: real Hosted staging %s is a terminal Go error\n", expected)
}
