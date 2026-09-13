// Declaring an enforcement point's capabilities with the PEP capability
// handshake, which the platform reads from v10.4.0.
//
// An enforcement point (a PEP) declares, on each governed call, the exact
// obligation types and schema versions it can discharge. On an Enterprise
// deployment an allow verdict carrying a mandatory obligation the declared set
// cannot discharge becomes a deny, so the enforcement point is never handed an
// instruction it would drop; a Community deployment records the declaration.
// From v11.0.0, on both editions, Decide under an organization's redact
// override refuses a caller that does not declare redaction.
//
// This example builds a declaration once for the client, overrides it for one
// call (one process can be two enforcement points), and shows that a
// declaration the platform would refuse fails here, before anything is sent.
//
// Run it against a local stack:
//
//	export AXONFLOW_ENDPOINT=http://localhost:8080
//	export AXONFLOW_CLIENT_ID=...
//	export AXONFLOW_CLIENT_SECRET=...
//	go run ./examples/pep_handshake
//
// Decide names the client id as the caller's organization, and the platform
// denies a caller naming an organization other than its own. On Enterprise the
// client id is the organization id and the secret its license key; on
// Community leave both unset.
//
// Exits non-zero if a step fails, so it is usable as a smoke test.
package main

import (
	"context"
	"errors"
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

	// The request path redacts fields; it declares exactly that.
	requestPath, err := axonflow.NewPEPHandshake("checkout-gateway", "https://pep.example.com",
		[]axonflow.PEPCapability{{Type: axonflow.AuthZENObligationTypeFieldRedact, Version: 1}})
	if err != nil {
		log.Fatalf("build the declaration: %v", err)
	}
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		PEPHandshake: requestPath,
	})
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
	decide := axonflow.DecideRequest{Stage: "tool", Query: "look up the weather",
		Target: axonflow.DecisionTarget{Type: "tool", Tool: "search"}}

	step("decide with the client's declaration", func() error {
		decision, err := client.Decide(ctx, decide)
		if err != nil {
			return err
		}
		fmt.Printf("verdict=%s obligations=%d\n", decision.Verdict, len(decision.Obligations))
		return nil
	})

	// The response path masks fields instead. It declares its own set for the
	// calls made with this context, in place of the client's.
	step("decide with a per-call declaration", func() error {
		responsePath, err := axonflow.NewPEPHandshake("checkout-gateway-response", "https://pep.example.com",
			[]axonflow.PEPCapability{{Type: axonflow.AuthZENObligationTypeFieldMask, Version: 1}})
		if err != nil {
			return err
		}
		decision, err := client.Decide(axonflow.ContextWithPEPHandshake(ctx, responsePath), decide)
		if err != nil {
			return err
		}
		fmt.Printf("verdict=%s obligations=%d\n", decision.Verdict, len(decision.Obligations))
		return nil
	})

	// A declaration the platform would refuse fails at construction, naming
	// the member at fault, instead of the first governed call answering 400.
	step("a declaration the platform would refuse", func() error {
		_, err := axonflow.NewPEPHandshake("Checkout:Gateway", "https://pep.example.com", []axonflow.PEPCapability{})
		var refusal *axonflow.PEPHandshakeError
		if !errors.As(err, &refusal) {
			return fmt.Errorf("want a *PEPHandshakeError, got %v", err)
		}
		fmt.Printf("refused at %s: %v\n", refusal.Pointer, err)
		return nil
	})

	if failures > 0 {
		fmt.Printf("\n%d step(s) failed\n", failures)
		os.Exit(1)
	}
}
