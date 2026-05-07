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
//	AXONFLOW_DECISION_ID        the decision to explain
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

	"github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "community")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	decisionID := getEnv("AXONFLOW_DECISION_ID", "")

	if decisionID == "" {
		log.Fatal("AXONFLOW_DECISION_ID must be set (a decision_id from a recent blocked call)")
	}

	fmt.Printf("Initializing AxonFlow client at %s...\n", agentURL)
	client := axonflow.NewClientSimple(agentURL, clientID, clientSecret)

	fmt.Printf("Explaining decision %s...\n\n", decisionID)
	exp, err := client.ExplainDecision(context.Background(), decisionID)
	if err != nil {
		log.Fatalf("ExplainDecision failed: %v", err)
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
