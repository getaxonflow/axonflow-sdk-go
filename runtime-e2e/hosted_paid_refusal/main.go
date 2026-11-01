//go:build ignore

// Run against a real disposable Hosted staging Agent with an unpaid Basic
// credential. This driver never accepts a production origin and prints no
// credential. A local unit-test listener is not a substitute for this run.
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
	clientID := os.Getenv("AXONFLOW_HOSTED_UNPAID_CLIENT_ID")
	secret := os.Getenv("AXONFLOW_HOSTED_UNPAID_CLIENT_SECRET")
	if clientID == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "staging unpaid Basic credential is required")
		os.Exit(2)
	}
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: endpoint, ClientID: clientID, ClientSecret: secret,
		Mode: "production", Retry: axonflow.RetryConfig{
			Enabled: true, MaxAttempts: 3, InitialDelay: 50 * time.Millisecond,
		}, Cache: axonflow.CacheConfig{Enabled: false},
	})
	response, err := client.ProxyLLMCall("hosted-sdk-runtime-e2e", "synthetic Hosted refusal probe", "chat", nil)
	if response != nil || err == nil || !strings.Contains(err.Error(), "HTTP 402") ||
		!strings.Contains(err.Error(), "hosted_payment_required") {
		fmt.Fprintln(os.Stderr, "Hosted 402 did not surface as a terminal payment error")
		os.Exit(1)
	}
	fmt.Println("PASS: real Hosted staging 402 is a terminal Go error")
}
