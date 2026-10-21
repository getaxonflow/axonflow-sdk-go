//go:build ignore

// runtime-e2e/v11_decision_provenance/main.go
//
// Real-stack proof that the SDK surfaces the v11.0.0 platform wire, through its
// public surface against a real v11 agent and orchestrator. Nothing is mocked.
//
//  1. Decide carries Engine "anchored", a PolicyBundle digest and a
//     SubjectType, and its PolicyIdentities name EvaluatedPolicies one for
//     one, in order, at least one of them a shipped control.
//  2. The gateway pre-check carries a DecisionID, a Verdict of allow or deny,
//     and the same provenance.
//  3. MCP check-output carries the provenance.
//  4. A legacy static-policy read is reported once through
//     AxonFlowConfig.OnRouteDeprecation, naming /api/v1/typed-policies as the
//     successor and v12.0 as the removal release.
//  5. A valid legacy static-policy write and a valid dynamic-policy write each
//     return *axonflow.LegacyPolicyWriteFrozenError.
//
// Leg 5 needs the agent and the orchestrator on the application database role,
// as a deployment runs them: the freeze is a revoke on that role, and a stack
// connected as the database owner is not bound by it. See README.md.
//
// Run:
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 \
//	AXONFLOW_CLIENT_ID=runtime-e2e AXONFLOW_CLIENT_SECRET=runtime-e2e-secret \
//	AXONFLOW_USER_TOKEN=<a per-user JWT> \
//	go run runtime-e2e/v11_decision_provenance/main.go
//
// It prints each observed value and exits non-zero on any failed assertion.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures []string

func check(ok bool, description string) {
	if ok {
		fmt.Printf("PASS: %s\n", description)
		return
	}
	fmt.Printf("FAIL: %s\n", description)
	failures = append(failures, description)
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	endpoint := env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	fmt.Printf("agent: %s\n", endpoint)

	var mu sync.Mutex
	var deprecations []axonflow.PlatformRouteDeprecation
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     env("AXONFLOW_CLIENT_ID", "runtime-e2e"),
		ClientSecret: env("AXONFLOW_CLIENT_SECRET", "runtime-e2e-secret"),
		OnRouteDeprecation: func(d axonflow.PlatformRouteDeprecation) {
			mu.Lock()
			defer mu.Unlock()
			deprecations = append(deprecations, d)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Println("== decide")
	decideLeg(ctx, client)
	fmt.Println("== pre-check")
	preCheckLeg(client)
	fmt.Println("== MCP check-output")
	checkOutputLeg(ctx, client)
	fmt.Println("== deprecated read")
	mu.Lock()
	before := len(deprecations)
	mu.Unlock()
	if _, err := client.ListStaticPolicies(nil); err != nil {
		check(false, fmt.Sprintf("a legacy static-policy read succeeds (got %v)", err))
	}
	mu.Lock()
	reported := append([]axonflow.PlatformRouteDeprecation(nil), deprecations[before:]...)
	mu.Unlock()
	deprecatedReadLeg(reported)
	fmt.Println("== frozen writes")
	frozenWriteLeg(client)

	if len(failures) > 0 {
		fmt.Printf("\nFAIL: v11_decision_provenance (%d assertion(s))\n", len(failures))
		os.Exit(1)
	}
	fmt.Println("\nPASS: v11_decision_provenance")
}

func decideLeg(ctx context.Context, c *axonflow.AxonFlowClient) {
	resp, err := c.Decide(ctx, axonflow.DecideRequest{
		Stage:  "tool",
		Query:  "look up the weather",
		Target: axonflow.DecisionTarget{Type: "tool", Tool: "search"},
	})
	if err != nil {
		check(false, fmt.Sprintf("decide returns a verdict (got %v)", err))
		return
	}
	fmt.Printf("  decide: verdict=%s engine=%s subject_type=%s policy_bundle=%s evaluated=%v\n",
		resp.Verdict, resp.Engine, resp.SubjectType, resp.PolicyBundle, resp.EvaluatedPolicies)
	fmt.Printf("  decide: identities=%+v packs=%v document_version=%d\n",
		resp.PolicyIdentities, resp.PolicyPacks, resp.DocumentVersion)
	check(resp.Engine == "anchored", "decide names the anchored engine")
	check(resp.PolicyBundle != "", "decide carries the policy bundle digest")
	check(resp.SubjectType != "", "decide carries the subject type")
	ids := make([]string, 0, len(resp.PolicyIdentities))
	shipped := false
	for _, p := range resp.PolicyIdentities {
		ids = append(ids, p.ID)
		if p.Source == "shipped" {
			shipped = true
		}
	}
	check(len(ids) > 0 && strings.Join(ids, "\x00") == strings.Join(resp.EvaluatedPolicies, "\x00"),
		"decide's PolicyIdentities name EvaluatedPolicies one for one, in order")
	check(shipped, "decide's PolicyIdentities name at least one shipped control")
}

func preCheckLeg(c *axonflow.AxonFlowClient) {
	// An enterprise agent validates the user token as a JWT and refuses a malformed one
	// with 401; the setup script writes a real one as AXONFLOW_USER_TOKEN.
	result, err := c.GetPolicyApprovedContext(env("AXONFLOW_USER_TOKEN", "tok"), "hello", nil, nil)
	if err != nil {
		check(false, fmt.Sprintf("pre-check returns a result (got %v)", err))
		return
	}
	fmt.Printf("  pre-check: approved=%v decision_id=%s verdict=%s engine=%s subject_type=%s policy_bundle=%s\n",
		result.Approved, result.DecisionID, result.Verdict, result.Engine, result.SubjectType, result.PolicyBundle)
	check(result.DecisionID != "", "pre-check carries the decision id")
	check(result.Verdict == "allow" || result.Verdict == "deny", "pre-check carries the canonical verdict")
	check(result.Engine == "anchored", "pre-check names the anchored engine")
	check(result.PolicyBundle != "", "pre-check carries the policy bundle digest")
}

func checkOutputLeg(ctx context.Context, c *axonflow.AxonFlowClient) {
	resp, err := c.MCPCheckOutput(ctx, axonflow.MCPCheckOutputRequest{ConnectorType: "postgres", Message: "hello"})
	if err != nil {
		check(false, fmt.Sprintf("MCP check-output returns a result (got %v)", err))
		return
	}
	fmt.Printf("  mcp check-output: allowed=%v engine=%s subject_type=%s policy_bundle=%s\n",
		resp.Allowed, resp.Engine, resp.SubjectType, resp.PolicyBundle)
	check(resp.Engine == "anchored", "MCP check-output names the anchored engine")
	check(resp.PolicyBundle != "", "MCP check-output carries the policy bundle digest")
}

func deprecatedReadLeg(reported []axonflow.PlatformRouteDeprecation) {
	var static []axonflow.PlatformRouteDeprecation
	for _, d := range reported {
		fmt.Printf("  reported: %s\n", d)
		if d.Route == "GET /api/v1/static-policies" {
			static = append(static, d)
		}
	}
	check(len(static) == 1, "a legacy static-policy read is reported once through OnRouteDeprecation")
	if len(static) == 1 {
		check(static[0].Successor == "/api/v1/typed-policies", "the report names the typed route as the successor")
		check(static[0].RemovedIn == "v12.0", "the report names v12.0 as the removal release")
	}
}

func frozenWriteLeg(c *axonflow.AxonFlowClient) {
	probe := fmt.Sprintf("w3p-runtime-probe-%08x", uint32(time.Now().UnixNano()))
	created, err := c.CreateStaticPolicy(&axonflow.CreateStaticPolicyRequest{
		Name:     probe,
		Category: axonflow.CategorySecuritySQLI,
		Pattern:  "(?i)" + strings.ReplaceAll(probe, "-", "_"),
		Severity: axonflow.SeverityLow,
		Action:   axonflow.ActionWarn,
		Enabled:  true,
	})
	reportFrozen("a legacy static-policy write", err)
	if err == nil && created != nil {
		// The freeze did not bind: remove the probe rather than leave it behind.
		if delErr := c.DeleteStaticPolicy(created.ID); delErr != nil {
			fmt.Printf("  could not remove the probe static policy %s: %v\n", created.ID, delErr)
		}
	}
	createdDynamic, err := c.CreateDynamicPolicy(&axonflow.CreateDynamicPolicyRequest{
		Name:       probe,
		Type:       "risk",
		Category:   "dynamic-risk",
		Conditions: []axonflow.DynamicPolicyCondition{{Field: "risk_score", Operator: "greater_than", Value: 0.99}},
		Actions:    []axonflow.DynamicPolicyAction{{Type: "log", Config: map[string]interface{}{}}},
		Enabled:    true,
	})
	reportFrozen("a legacy dynamic-policy write", err)
	if err == nil && createdDynamic != nil {
		if delErr := c.DeleteDynamicPolicy(createdDynamic.ID); delErr != nil {
			fmt.Printf("  could not remove the probe dynamic policy %s: %v\n", createdDynamic.ID, delErr)
		}
	}
}

func reportFrozen(write string, err error) {
	var frozen *axonflow.LegacyPolicyWriteFrozenError
	switch {
	case err == nil:
		check(false, write+" returns LegacyPolicyWriteFrozenError (it succeeded)")
	case errors.As(err, &frozen):
		fmt.Printf("  %s refused: %v\n", write, err)
		check(true, write+" returns LegacyPolicyWriteFrozenError")
	default:
		check(false, fmt.Sprintf("%s returns LegacyPolicyWriteFrozenError (got %T: %v)", write, err, err))
	}
}
