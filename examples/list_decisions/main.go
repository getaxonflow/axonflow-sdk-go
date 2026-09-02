// Example: list the recent AxonFlow policy decisions VISIBLE TO THE CALLER.
//
// Implements the GET /api/v1/decisions contract — companion to the
// explain_decision flow. Returns the slim DecisionSummary page with
// optional filters; tier-cap 429s surface as *RateLimitError carrying
// the V1 upgrade envelope.
//
// # Whose decisions come back (platform #2922)
//
// Not the tenant's — the caller's. On an enterprise stack a tenant-wide role
// (admin/owner/policy_admin) lists the whole tenant, any other identity lists
// only its own rows, and a caller presenting NO identity lists nothing at all.
// That last case used to look exactly like a quiet tenant; the SDK now refuses
// it as a *ReadScopeError instead of reporting an empty page as data.
//
// Mint an identity the way the E2E workflow does:
//
//	export AXONFLOW_USER_TOKEN=$(./scripts/generate-jwt.sh --kind user \
//	    --email dev@acme.com --org-id "$AXONFLOW_CLIENT_ID" --role developer --quiet)
//
// (./scripts/setup-e2e-testing.sh already exports exactly this variable.)
// Community deployments are single-operator and need none of it.
//
// Required env vars:
//
//	AXONFLOW_AGENT_URL          (default: http://localhost:8080)
//	AXONFLOW_CLIENT_ID
//	AXONFLOW_CLIENT_SECRET
//	AXONFLOW_USER_TOKEN         the per-user identity to scope the read to
//	                            (required on an enterprise stack)
//
// Optional filters:
//
//	AXONFLOW_LIST_DECISION       allowed|blocked|redacted|needs_approval|error
//	                             (canonical audit verdicts, platform 9.0.0+;
//	                             pre-9.0.0 allow|deny|require_approval now 400)
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

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_AGENT_URL")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	clientID := mustGetenv("AXONFLOW_CLIENT_ID")
	clientSecret := mustGetenv("AXONFLOW_CLIENT_SECRET")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		// The read-path identity this listing is scoped to. See the package
		// comment: leaving it empty against an enterprise stack is what made
		// this example report a confident, empty page.
		UserToken: os.Getenv("AXONFLOW_USER_TOKEN"),
	})

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
		if rse, ok := axonflow.AsReadScopeError(err); ok && rse.IdentityMissing() {
			fmt.Fprintln(os.Stderr, "=== This read was unscoped ===")
			fmt.Fprintf(os.Stderr, "  %v\n\n", err)
			fmt.Fprintln(os.Stderr, "  The platform returned zero rows because it had no identity to scope on,")
			fmt.Fprintln(os.Stderr, "  not because your tenant has no decisions. Set AXONFLOW_USER_TOKEN:")
			fmt.Fprintln(os.Stderr, "    export AXONFLOW_USER_TOKEN=$(./scripts/generate-jwt.sh --kind user \\")
			fmt.Fprintln(os.Stderr, "        --email dev@acme.com --org-id \"$AXONFLOW_CLIENT_ID\" --role developer --quiet)")
			os.Exit(3)
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
