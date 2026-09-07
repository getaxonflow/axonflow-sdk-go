package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	// Load configuration from environment variables
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	// Enterprise stacks (DEPLOYMENT_MODE=enterprise) validate user tokens as
	// JWTs. Export AXONFLOW_USER_TOKEN (see scripts/generate-jwt.sh in the
	// platform repo). Community stacks skip JWT validation, so leaving it
	// empty ("anonymous") is fine there.
	userToken := getEnv("AXONFLOW_USER_TOKEN", "")

	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

	// Create client with simple initialization
	fmt.Println("Initializing AxonFlow client...")
	client := axonflow.NewClientSimple(agentURL, clientID, clientSecret)

	// Perform health check
	fmt.Println("\nChecking AxonFlow Agent health...")
	if err := client.HealthCheck(); err != nil {
		log.Printf("Warning: Health check failed: %v", err)
	} else {
		fmt.Println("✓ AxonFlow Agent is healthy")
	}

	// Execute a simple query
	fmt.Println("\nExecuting governed query...")
	resp, err := client.ProxyLLMCall(
		userToken,
		"What is the capital of France?",
		"chat",
		map[string]interface{}{
			"temperature": 0.7,
			"max_tokens":  100,
		},
	)

	if err != nil {
		log.Fatalf("Query execution failed: %v", err)
	}

	// Check if request was blocked
	if resp.Blocked {
		fmt.Printf("❌ Request blocked by governance policy\n")
		fmt.Printf("   Reason: %s\n", resp.BlockReason)
		fmt.Printf("   Policies evaluated: %v\n", resp.PolicyInfo.PoliciesEvaluated)
		return
	}

	// A stack with no LLM provider credential still governs the request: the
	// policy engine runs, the verdict comes back, and only the provider round
	// trip is missing. Assert the half that is actually observable here rather
	// than failing on the half that structurally cannot happen. Mirrors the
	// skip predicate in sdk_integration_test.go.
	if !resp.Success {
		if !isProviderUnavailable(resp.Error) {
			log.Fatalf("❌ Query failed: %s", resp.Error)
		}
		fmt.Printf("⏭  LLM round trip skipped: no provider configured on this stack (%s)\n", resp.Error)
		mustHaveGovernanceVerdict("simple query", resp.PolicyInfo)
	} else {
		// Display result
		fmt.Println("✓ Query executed successfully")
		fmt.Printf("Result: %v\n", resp.Data)
	}

	// Display governance metadata
	fmt.Println("\nGovernance Metadata:")
	fmt.Printf("  Request ID: %s\n", resp.RequestID)
	if resp.PolicyInfo != nil {
		fmt.Printf("  Policies Evaluated: %v\n", resp.PolicyInfo.PoliciesEvaluated)
		fmt.Printf("  Processing Time: %s\n", resp.PolicyInfo.ProcessingTime)
	}

	// Test with sensitive data (should be redacted)
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Testing PII detection and redaction...")
	fmt.Println(strings.Repeat("=", 60))

	resp2, err := client.ProxyLLMCall(
		userToken,
		"My email is john.doe@example.com and my SSN is 123-45-6789",
		"chat",
		map[string]interface{}{},
	)

	if err != nil {
		log.Fatalf("PII test query failed: %v", err)
	}

	if resp2.Blocked {
		fmt.Printf("✓ PII detected and request blocked\n")
		fmt.Printf("  Reason: %s\n", resp2.BlockReason)
	} else if !resp2.Success {
		if !isProviderUnavailable(resp2.Error) {
			log.Fatalf("❌ PII test query failed: %s", resp2.Error)
		}
		fmt.Printf("⏭  LLM round trip skipped: no provider configured on this stack (%s)\n", resp2.Error)
		// PII detection happens BEFORE the provider is dialled, so this half is
		// fully observable without a credential and is the assertion worth
		// keeping: the benign query above evaluates no named policy, this one
		// must evaluate at least one. Deliberately not pinned to a policy id —
		// the claim is that detection ran, not what the stack calls its rule.
		info := mustHaveGovernanceVerdict("PII query", resp2.PolicyInfo)
		if len(info.PoliciesEvaluated) == 0 {
			log.Fatalf("❌ PII detection regression: statement carrying an email and an SSN "+
				"evaluated no policy at all (static_checks=%v, tenant=%s)",
				info.StaticChecks, info.TenantID)
		}
		fmt.Printf("✓ PII detection ran without a provider: policies evaluated %v\n", info.PoliciesEvaluated)
	} else {
		fmt.Printf("✓ PII handled: %v\n", resp2.Data)
	}
}

// isProviderUnavailable reports whether an unsuccessful response failed because
// the stack has no LLM provider credential, rather than because governance or
// the SDK misbehaved. Kept in sync with the skip predicate in
// sdk_integration_test.go.
func isProviderUnavailable(errMsg string) bool {
	return strings.Contains(errMsg, "LLM") ||
		strings.Contains(errMsg, "provider") ||
		strings.Contains(errMsg, "no healthy")
}

// mustHaveGovernanceVerdict asserts the platform returned a governance verdict.
// Reaching the agent and getting a policy envelope back is what this smoke can
// still prove with no provider wired up; an empty envelope means the SDK never
// got past the transport, which is a real regression and must stay fatal.
func mustHaveGovernanceVerdict(label string, info *axonflow.PolicyEvaluationInfo) *axonflow.PolicyEvaluationInfo {
	if info == nil {
		log.Fatalf("❌ %s: no governance verdict returned — the SDK did not reach the policy engine", label)
	}
	if len(info.StaticChecks) == 0 {
		log.Fatalf("❌ %s: governance verdict carries no static checks (tenant=%q) — policy engine did not run",
			label, info.TenantID)
	}
	fmt.Printf("✓ Governance verdict returned for %s: static_checks=%v tenant=%s processing_time=%s\n",
		label, info.StaticChecks, info.TenantID, info.ProcessingTime)
	return info
}

// getEnv retrieves environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
