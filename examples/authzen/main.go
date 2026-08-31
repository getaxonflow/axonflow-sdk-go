// AuthZEN-native authorization against a running AxonFlow gateway.
//
// This example is the reference for the surface the ADR-065 compatibility plan
// ships in all five SDKs. It exercises the happy path AND the refusals, because
// the refusals are the half a new integration gets wrong: this surface answers
// "I cannot evaluate that" rather than evaluating around what it cannot read,
// and a caller that treats every error as a deny will block traffic it should
// have allowed.
//
// Run it against a local stack:
//
//	export AXONFLOW_ENDPOINT=http://localhost:8080
//	export AXONFLOW_CLIENT_ID=...        # required in enterprise mode
//	export AXONFLOW_CLIENT_SECRET=...
//	go run ./examples/authzen
//
// Exits non-zero if any step does not behave as documented, so it is usable as
// a smoke test rather than only as a demonstration.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	client := axonflow.NewClientSimple(
		endpoint,
		os.Getenv("AXONFLOW_CLIENT_ID"),
		os.Getenv("AXONFLOW_CLIENT_SECRET"),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	failures := 0
	step := func(name string, fn func() error) {
		fmt.Printf("\n=== %s ===\n", name)
		if err := fn(); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failures++
			return
		}
		fmt.Println("ok")
	}

	// -------------------------------------------------------------------
	// 1. The happy path: one subject, one action, one resource.
	// -------------------------------------------------------------------
	step("a single evaluation", func() error {
		dec, err := client.Evaluate(ctx, axonflow.AuthZENRequest{
			Subject:  &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
			Action:   &axonflow.AuthZENAction{Name: "llm.completion"},
			Resource: &axonflow.AuthZENResource{Type: "llm", ID: "openai/gpt-4o"},
			Context: map[string]any{
				"args": map[string]any{"query": "summarise yesterday's incident report"},
			},
		})
		if err != nil {
			return err
		}
		describe(dec)
		return nil
	})

	// -------------------------------------------------------------------
	// 2. Several preconditions of ONE operation.
	//
	// The reply is one decision, not one per entry: a denied entry denies the
	// operation. Anything an entry omits is inherited from the shared base.
	// -------------------------------------------------------------------
	step("several preconditions of one operation", func() error {
		dec, err := client.EvaluateAll(ctx, axonflow.AuthZENBulk{
			Subject: &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
			Action:  &axonflow.AuthZENAction{Name: "llm.completion"},
			Context: map[string]any{
				"args": map[string]any{"query": "summarise yesterday's incident report"},
			},
			Evaluations: []axonflow.AuthZENRequest{
				{Resource: &axonflow.AuthZENResource{Type: "llm", ID: "openai/gpt-4o"}},
				{Resource: &axonflow.AuthZENResource{Type: "llm", ID: "anthropic/claude-sonnet-4"}},
			},
		})
		if err != nil {
			return err
		}
		describe(dec)
		return nil
	})

	// -------------------------------------------------------------------
	// 3. The refusals. Each of these is a request the server will NOT answer
	//    with a decision, and each names the member to fix.
	// -------------------------------------------------------------------
	refusal := func(name string, req axonflow.AuthZENRequest, want axonflow.AuthZENErrorCode) {
		step("refused: "+name, func() error {
			dec, err := client.Evaluate(ctx, req)
			if err == nil {
				return fmt.Errorf("expected a refusal, got a decision: allowed=%v", dec.Allowed())
			}
			azErr, ok := axonflow.AsAuthZENError(err)
			if !ok {
				return fmt.Errorf("expected a typed refusal, got %T: %v", err, err)
			}
			if azErr.Code != want {
				return fmt.Errorf("code %q, want %q", azErr.Code, want)
			}
			fmt.Printf("  code:      %s\n", azErr.Code)
			fmt.Printf("  pointer:   %s\n", azErr.Pointer)
			fmt.Printf("  message:   %s\n", azErr.Message)
			if len(azErr.Supported) > 0 {
				fmt.Printf("  supported: %v\n", azErr.Supported)
			}
			fmt.Printf("  retryable: %v\n", azErr.Code.Retryable())
			return nil
		})
	}

	// An attribute the evaluator cannot read is REFUSED, not ignored. This is
	// the whole point of the surface: a decision computed without `clearance`
	// would report that clearance was considered.
	refusal("an attribute the evaluator cannot read",
		axonflow.AuthZENRequest{
			Subject: &axonflow.AuthZENSubject{
				Type: "gateway", ID: "llm-gateway-01",
				Properties: map[string]any{"clearance": "secret"},
			},
			Action:   &axonflow.AuthZENAction{Name: "llm.completion"},
			Resource: &axonflow.AuthZENResource{Type: "llm", ID: "openai/gpt-4o"},
			Context:  map[string]any{"args": map[string]any{"query": "q"}},
		},
		axonflow.AuthZENErrorCodeUnevaluableAttribute)

	refusal("an action outside the evaluable set",
		axonflow.AuthZENRequest{
			Subject:  &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
			Action:   &axonflow.AuthZENAction{Name: "jira.transition_issue"},
			Resource: &axonflow.AuthZENResource{Type: "llm", ID: "openai/gpt-4o"},
			Context:  map[string]any{"args": map[string]any{"query": "q"}},
		},
		axonflow.AuthZENErrorCodeUnsupportedAction)

	// An action and a resource that describe two different operations is
	// refused rather than resolved in one direction.
	refusal("an action and a resource that disagree",
		axonflow.AuthZENRequest{
			Subject:  &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
			Action:   &axonflow.AuthZENAction{Name: "llm.completion"},
			Resource: &axonflow.AuthZENResource{Type: "tool", ID: "jira/create_issue"},
			Context:  map[string]any{"args": map[string]any{"query": "q"}},
		},
		axonflow.AuthZENErrorCodeUnsupportedResource)

	refusal("nothing to evaluate",
		axonflow.AuthZENRequest{
			Subject:  &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
			Action:   &axonflow.AuthZENAction{Name: "llm.completion"},
			Resource: &axonflow.AuthZENResource{Type: "llm", ID: "openai/gpt-4o"},
			Context:  map[string]any{"args": map[string]any{}},
		},
		axonflow.AuthZENErrorCodeMissingEvaluableContent)

	// -------------------------------------------------------------------
	// 4. A malformed envelope never reaches the network: the generated types
	//    carry the rules the type system cannot.
	// -------------------------------------------------------------------
	step("an incomplete evaluation fails before the round trip", func() error {
		_, err := client.Evaluate(ctx, axonflow.AuthZENRequest{
			Subject: &axonflow.AuthZENSubject{Type: "gateway", ID: "llm-gateway-01"},
			// no action, no resource
		})
		if err == nil {
			return fmt.Errorf("an incomplete evaluation was accepted")
		}
		if _, isRefusal := axonflow.AsAuthZENError(err); isRefusal {
			return fmt.Errorf("the server answered; this should have failed locally: %v", err)
		}
		fmt.Printf("  caught locally: %v\n", err)
		return nil
	})

	fmt.Println()
	if failures > 0 {
		log.Fatalf("%d step(s) failed", failures)
	}
	fmt.Println("All AuthZEN steps behaved as documented.")
}

// describe prints what a Policy Enforcement Point would act on.
func describe(dec *axonflow.AuthZENResponse) {
	fmt.Printf("  allowed: %v\n", dec.Allowed())
	fmt.Printf("  state:   %s\n", dec.State())
	if dec.Context == nil {
		// Only when the server did not send a profile this build can read. The
		// boolean is still authoritative.
		fmt.Println("  (no profile context: acting on the boolean alone)")
		return
	}
	fmt.Printf("  reason:  %s (%s)\n", dec.Context.Reason, dec.Context.Category)
	fmt.Printf("  id:      %s\n", dec.Context.DecisionID)
	for _, o := range dec.Obligations() {
		// A MANDATORY obligation that cannot be discharged means the operation
		// must not proceed, even though allowed is true.
		fmt.Printf("  obligation: %s (mandatory=%v, from %s)\n", o.Type, o.Mandatory, o.SourcePolicy)
	}
	if dec.Context.Approval != nil {
		fmt.Printf("  approval required by %s\n", dec.Context.Approval.ExpiresAt)
	}
}
