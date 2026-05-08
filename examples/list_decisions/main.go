// Example: list recent AxonFlow policy decisions for the caller's tenant.
//
// Implements the GET /api/v1/decisions contract — companion to the
// explain_decision flow. Returns the slim DecisionSummary page with
// optional filters; tier-cap 429s surface as *RateLimitError carrying
// the V1 upgrade envelope.
//
// Required env vars:
//
//	AXONFLOW_AGENT_URL          (default: http://localhost:8080)
//	AXONFLOW_CLIENT_ID
//	AXONFLOW_CLIENT_SECRET
//
// Optional filters:
//
//	AXONFLOW_LIST_DECISION       allow|deny|require_approval
//	AXONFLOW_LIST_POLICY_ID      e.g. sys_sqli_stacked_drop
//	AXONFLOW_LIST_LIMIT          integer (server-capped per tier)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_AGENT_URL")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	clientID := mustGetenv("AXONFLOW_CLIENT_ID")
	clientSecret := mustGetenv("AXONFLOW_CLIENT_SECRET")

	client := axonflow.NewClientSimple(endpoint, clientID, clientSecret)

	opts := axonflow.ListDecisionsOptions{
		Decision: os.Getenv("AXONFLOW_LIST_DECISION"),
		PolicyID: os.Getenv("AXONFLOW_LIST_POLICY_ID"),
	}
	if s := os.Getenv("AXONFLOW_LIST_LIMIT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			opts.Limit = n
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	decisions, err := client.ListDecisions(ctx, opts)
	if err != nil {
		if rle, ok := axonflow.AsRateLimitError(err); ok {
			fmt.Fprintf(os.Stderr, "=== Tier limit reached (%s) ===\n", rle.Envelope.LimitType)
			fmt.Fprintf(os.Stderr, "  current tier: %s\n", rle.Envelope.Tier)
			fmt.Fprintf(os.Stderr, "  limit:        %d\n", rle.Envelope.Limit)
			fmt.Fprintf(os.Stderr, "  reason:       %s\n", rle.Envelope.Error)
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "  upgrade to %s: %s\n", rle.Envelope.Upgrade.Tier, rle.Envelope.Upgrade.Wording)
			fmt.Fprintf(os.Stderr, "    compare:    %s\n", rle.Envelope.Upgrade.CompareURL)
			fmt.Fprintf(os.Stderr, "    buy:        %s\n", rle.Envelope.Upgrade.BuyURL)
			os.Exit(2)
		}
		log.Fatalf("list_decisions: %v", err)
	}

	fmt.Printf("=== Recent decisions (%d) ===\n", len(decisions))
	for _, d := range decisions {
		policy := d.PolicyID
		if policy == "" {
			policy = "-"
		}
		tool := d.ToolSignature
		if tool == "" {
			tool = "-"
		}
		fmt.Printf("  %s %-18s %s policy=%s tool=%s\n",
			d.Timestamp.Format(time.RFC3339), d.Decision, d.DecisionID, policy, tool)
	}
}

func mustGetenv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s must be set", k)
	}
	return v
}
