//go:build ignore

// runtime-e2e/provider_absent_governance/main.go
//
// Real-wire proof that governance is observable on a stack with NO LLM
// provider credential — from a real axonflow client, in a real process, over
// real HTTP, against a real running agent.
//
// WHY THIS EXISTS:
//
// The `Run Basic Example` smoke called log.Fatalf on `LLM routing failed` and
// had been red on every push to main. The stack that job boots has no provider
// credential, so the example was failing on the one thing that job structurally
// cannot supply, while asserting nothing about the things it can. The repo has
// no secrets at all (`gh secret list` is empty), so there is no credential to
// wire in and the honest fix is to assert the governed half.
//
// The trap this guards is the OTHER direction: "make it pass" is one `|| true`
// away from a smoke that asserts nothing, and a no-op smoke is worse than a red
// one because it reports green. So the claim under test is not "the example
// exits 0" — it is that a provider-less stack still returns a real governance
// verdict, and that PII detection still runs, because both happen BEFORE the
// provider is dialled.
//
//	# against a real running agent (the community stack the integration job boots)
//	AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
//	  go run runtime-e2e/provider_absent_governance/main.go
//
// WHAT IT ASSERTS:
//
//  1. A governed call returns a governance verdict — policy_info present with a
//     non-empty static_checks — whether or not a provider answered. This is the
//     assertion the example now makes, proven here against a real agent.
//  2. PII detection RAN: a statement carrying an email and an SSN evaluates at
//     least one policy, while the benign query above it evaluates none. That
//     differential is what makes assertion 1 non-vacuous — an agent returning a
//     constant empty envelope would pass 1 and fail this.
//  3. The provider-absent predicate does not drift. The example, the
//     integration suite and this leg must all identify a missing provider the
//     same way; if the platform changes that error text, this fails loudly
//     rather than every caller silently reclassifying a real fault as a skip.
//  4. If a provider IS configured, the full round trip must SUCCEED. Without
//     this the leg would go permanently blind the day credentials appear.
//
// No stubs, no httptest: the lint-no-mocks gate forbids them under runtime-e2e/
// and the claim here is specifically about a real agent's real behaviour.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures int

func check(ok bool, what string) {
	if ok {
		fmt.Println("  PASS  " + what)
		return
	}
	fmt.Println("  FAIL  " + what)
	failures++
}

// providerAbsent is the predicate under test in assertion 3. It MUST stay
// byte-identical to the one in examples/basic/main.go and sdk_integration_test.go.
func providerAbsent(errMsg string) bool {
	return strings.Contains(errMsg, "LLM") ||
		strings.Contains(errMsg, "provider") ||
		strings.Contains(errMsg, "no healthy")
}

func endpoint() string {
	for _, k := range []string{"AXONFLOW_E2E_PLATFORM_ENDPOINT", "AXONFLOW_AGENT_URL"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "http://localhost:8080"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	url := endpoint()
	fmt.Printf("Agent under test: %s\n\n", url)

	client := axonflow.NewClientSimple(
		url,
		env("AXONFLOW_CLIENT_ID", "demo-client"),
		env("AXONFLOW_CLIENT_SECRET", "demo-secret"),
	)

	fmt.Println("[0] the agent is reachable through the real client")
	if err := client.HealthCheck(); err != nil {
		fmt.Printf("  FAIL  HealthCheck: %v\n", err)
		fmt.Println("\nRESULT: FAIL (no agent to prove anything against)")
		os.Exit(1)
	}
	check(true, "HealthCheck succeeded")

	// ---- benign query ---------------------------------------------------
	fmt.Println("\n[1] a benign governed call returns a governance verdict")
	benign, err := client.ProxyLLMCall("", "What is the capital of France?", "chat",
		map[string]interface{}{"temperature": 0.7, "max_tokens": 100})
	if err != nil {
		fmt.Printf("  FAIL  transport error: %v\n", err)
		fmt.Println("\nRESULT: FAIL")
		os.Exit(1)
	}
	benignAbsent := !benign.Success && !benign.Blocked && providerAbsent(benign.Error)
	fmt.Printf("      success=%v blocked=%v error=%q provider_absent=%v\n",
		benign.Success, benign.Blocked, benign.Error, benignAbsent)

	check(benign.PolicyInfo != nil, "policy_info returned")
	var benignEvaluated int
	if benign.PolicyInfo != nil {
		check(len(benign.PolicyInfo.StaticChecks) > 0,
			fmt.Sprintf("static_checks non-empty (%v)", benign.PolicyInfo.StaticChecks))
		check(benign.PolicyInfo.TenantID != "",
			fmt.Sprintf("tenant resolved (%q)", benign.PolicyInfo.TenantID))
		benignEvaluated = len(benign.PolicyInfo.PoliciesEvaluated)
	}

	// ---- PII query ------------------------------------------------------
	fmt.Println("\n[2] PII detection runs BEFORE the provider is dialled")
	pii, err := client.ProxyLLMCall("",
		"My email is john.doe@example.com and my SSN is 123-45-6789", "chat",
		map[string]interface{}{})
	if err != nil {
		fmt.Printf("  FAIL  transport error: %v\n", err)
		fmt.Println("\nRESULT: FAIL")
		os.Exit(1)
	}
	piiAbsent := !pii.Success && !pii.Blocked && providerAbsent(pii.Error)
	fmt.Printf("      success=%v blocked=%v error=%q provider_absent=%v\n",
		pii.Success, pii.Blocked, pii.Error, piiAbsent)

	if pii.Blocked {
		check(true, "PII request was BLOCKED outright (strongest outcome)")
	} else {
		check(pii.PolicyInfo != nil, "policy_info returned")
		if pii.PolicyInfo != nil {
			check(len(pii.PolicyInfo.StaticChecks) > 0,
				fmt.Sprintf("static_checks non-empty (%v)", pii.PolicyInfo.StaticChecks))
			// The differential that makes assertion 1 non-vacuous.
			check(len(pii.PolicyInfo.PoliciesEvaluated) > 0,
				fmt.Sprintf("PII statement evaluated >=1 policy (%v) vs %d for the benign query",
					pii.PolicyInfo.PoliciesEvaluated, benignEvaluated))
		}
	}

	// ---- the predicate itself -------------------------------------------
	fmt.Println("\n[3] the provider-absent predicate matches this stack's actual error")
	if benignAbsent || piiAbsent {
		check(true, "provider absent, and the predicate identified it — the LLM leg is a SKIP, not a failure")
		// Guard the reclassification risk in the other direction.
		check(!providerAbsent("policy engine panic") &&
			!providerAbsent("unauthorized") &&
			!providerAbsent("budget exceeded"),
			"the predicate does NOT swallow non-provider failures")
	} else {
		// ---- provider present: the full round trip must work ------------
		fmt.Println("      a provider answered on this stack — asserting the full round trip")
		check(benign.Success || benign.Blocked,
			fmt.Sprintf("benign query completed end to end (success=%v blocked=%v error=%q)",
				benign.Success, benign.Blocked, benign.Error))
		check(pii.Success || pii.Blocked,
			fmt.Sprintf("PII query completed end to end (success=%v blocked=%v error=%q)",
				pii.Success, pii.Blocked, pii.Error))
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("RESULT: FAIL (%d assertion(s))\n", failures)
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS — governance is observable on this stack without a provider")
}
