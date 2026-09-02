// Example: explain a previously-made AxonFlow policy decision.
//
// Implements the ADR-043 explainability flow. Given a decision_id (typically
// surfaced on the response of a blocked governed call, an audit_logs row, or
// the `explain_decision` MCP tool), this example fetches the structured
// explanation and renders the matched policies, risk level, and override
// availability.
//
// Required env vars:
//
//	AXONFLOW_AGENT_URL          (default: http://localhost:8080)
//	AXONFLOW_CLIENT_ID
//	AXONFLOW_CLIENT_SECRET
//	AXONFLOW_USER_TOKEN         the PER-USER identity this read is scoped to
//	                            (see below — required on an enterprise stack)
//
// Optional:
//
//	AXONFLOW_DECISION_ID        the decision to explain. When unset the example
//	                            asks the platform for the most recent decision
//	                            THIS identity can see and explains that one.
//
// # Why AXONFLOW_USER_TOKEN is not optional here (platform #2922)
//
// ClientID/ClientSecret say which ORGANIZATION is asking. Explain answers from
// who is asking. On an enterprise stack a developer or viewer explains only
// their own decisions, a tenant-wide role (admin/owner/policy_admin) explains
// the whole tenant, and a caller presenting NO identity explains NOTHING — the
// endpoint answers not-found for every id, including ids that plainly exist.
// That is why this example failed on every enterprise stack until the SDK grew
// a read-path identity: it was asking anonymously.
//
// Mint one the way the E2E workflow does:
//
//	export AXONFLOW_USER_TOKEN=$(./scripts/generate-jwt.sh --kind user \
//	    --email dev@acme.com --org-id "$AXONFLOW_CLIENT_ID" --role developer --quiet)
//
// (./scripts/setup-e2e-testing.sh already exports exactly this variable.)
// Community deployments are single-operator and need none of it.
//
// Get a decision_id quickly by hitting a known-blocked policy:
//
//	curl -u "$AXONFLOW_CLIENT_ID:$AXONFLOW_CLIENT_SECRET" \
//	     -X POST $AXONFLOW_AGENT_URL/api/v1/mcp/check-input \
//	     -H 'Content-Type: application/json' \
//	     -d '{"connector_type":"postgres","operation":"execute","statement":"SELECT 1; DROP TABLE users;--","user_token":"u1"}'
//
// then read decision_id from the block response or the most recent audit row.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "community")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	decisionID := getEnv("AXONFLOW_DECISION_ID", "")

	fmt.Printf("Initializing AxonFlow client at %s...\n", agentURL)
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		// The read-path identity. Empty is legal and means "ask
		// anonymously", which on an enterprise stack explains nothing.
		UserToken: os.Getenv("AXONFLOW_USER_TOKEN"),
	})
	if os.Getenv("AXONFLOW_USER_TOKEN") == "" {
		fmt.Println("note: AXONFLOW_USER_TOKEN is unset — this read is unscoped. " +
			"On an enterprise stack it will explain nothing; see the package comment.")
	}

	ctx := context.Background()

	// No id given: ask for one this identity can actually see, so the example
	// explains a real decision rather than failing on a placeholder.
	if decisionID == "" {
		fmt.Println("AXONFLOW_DECISION_ID is unset — looking up the most recent visible decision...")
		recent, err := client.ListDecisions(ctx, axonflow.ListDecisionsOptions{Limit: 1})
		if err != nil {
			log.Fatalf("could not find a decision to explain: %v", explainScopeHint(err))
		}
		if len(recent) == 0 {
			log.Fatal("no decisions are visible to this identity yet — make a governed call first " +
				"(see the curl in the package comment), then re-run")
		}
		decisionID = recent[0].DecisionID
		fmt.Printf("  using decision_id=%s\n", decisionID)
	}

	fmt.Printf("Explaining decision %s...\n\n", decisionID)
	exp, err := client.ExplainDecision(ctx, decisionID)
	if err != nil {
		log.Fatalf("ExplainDecision failed: %v", explainScopeHint(err))
	}

	// An explanation that came back without the id it was asked about is not
	// an explanation — fail loudly rather than print an empty report.
	if exp.DecisionID == "" {
		log.Fatalf("the platform returned an explanation with no decision_id for %s", decisionID)
	}

	fmt.Println("=== Decision Explanation ===")
	fmt.Printf("  decision_id: %s\n", exp.DecisionID)
	fmt.Printf("  timestamp:   %s\n", exp.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  decision:    %s\n", exp.Decision)
	fmt.Printf("  reason:      %s\n", exp.Reason)
	if exp.RiskLevel != "" {
		fmt.Printf("  risk_level:  %s\n", exp.RiskLevel)
	}
	if exp.ToolSignature != "" {
		fmt.Printf("  tool:        %s\n", exp.ToolSignature)
	}

	fmt.Printf("\n  policy_matches (%d):\n", len(exp.PolicyMatches))
	for i, m := range exp.PolicyMatches {
		name := m.PolicyName
		if name == "" {
			name = "(unnamed)"
		}
		action := m.Action
		if action == "" {
			action = "-"
		}
		risk := m.RiskLevel
		if risk == "" {
			risk = "-"
		}
		fmt.Printf("    [%d] %s (%s) — action=%s risk=%s allow_override=%t\n",
			i, m.PolicyID, name, action, risk, m.AllowOverride)
	}

	if len(exp.MatchedRules) > 0 {
		fmt.Printf("\n  matched_rules (%d):\n", len(exp.MatchedRules))
		for _, r := range exp.MatchedRules {
			ruleID := r.RuleID
			if ruleID == "" {
				ruleID = "(no rule id)"
			}
			matchedOn := r.MatchedOn
			if matchedOn == "" {
				matchedOn = "-"
			}
			fmt.Printf("    %s on %s: matched=%s\n", r.PolicyID, ruleID, matchedOn)
		}
	}

	fmt.Printf("\n  override_available:           %t\n", exp.OverrideAvailable)
	if exp.OverrideExistingID != "" {
		fmt.Printf("  override_existing_id:         %s\n", exp.OverrideExistingID)
	}
	fmt.Printf("  historical_hit_count_session: %d\n", exp.HistoricalHitCountSession)
	if exp.PolicySourceLink != "" {
		fmt.Printf("  policy_source_link:           %s\n", exp.PolicySourceLink)
	}
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// explainScopeHint turns the SDK's typed scope refusal into the sentence a
// reader of this example actually needs, and passes everything else through
// unchanged. Without it the three distinct causes behind "not found" arrive
// looking identical.
func explainScopeHint(err error) error {
	rse, ok := axonflow.AsReadScopeError(err)
	if !ok {
		return err
	}
	if rse.IdentityMissing() {
		return fmt.Errorf("%w\n\n  → This read presented no per-user identity, so the platform "+
			"returned nothing by construction. Set AXONFLOW_USER_TOKEN (see the package comment).", err)
	}
	return fmt.Errorf("%w\n\n  → The identity in AXONFLOW_USER_TOKEN is scoped to its own rows and "+
		"this decision is not one of them. Use an admin, owner or policy_admin token to read the whole tenant.", err)
}
