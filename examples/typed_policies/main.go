// Typed policy authoring against a running AxonFlow v11 platform.
//
// A v11 platform authors policy as a typed document: validated, published as a
// signed artifact pinned by its digest, and promoted to active. This example
// reads what the deployment may author, validates a document and prints every
// finding, and shows the document in force. It publishes and activates only
// when AXONFLOW_TYPED_POLICY_PUBLISH=1, because that changes the organization's
// active policy.
//
// Run it against a local stack from the repository root:
//
//	export AXONFLOW_ENDPOINT=http://localhost:8080
//	export AXONFLOW_CLIENT_ID=...
//	export AXONFLOW_CLIENT_SECRET=...
//	go run ./examples/typed_policies
//
// AXONFLOW_TYPED_POLICY_BODY names a JSON file holding {"document": ...,
// "fixtures": [...]}; the default is testdata/typed_policy_publish_body.json.
// Exits non-zero if a step fails, so it is usable as a smoke test.
package main

import (
	"context"
	"encoding/json"
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
	bodyPath := os.Getenv("AXONFLOW_TYPED_POLICY_BODY")
	if bodyPath == "" {
		bodyPath = "testdata/typed_policy_publish_body.json"
	}
	raw, err := os.ReadFile(bodyPath)
	if err != nil {
		log.Fatalf("read %s: %v", bodyPath, err)
	}
	var body struct {
		Document map[string]any   `json:"document"`
		Fixtures []map[string]any `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		log.Fatalf("decode %s: %v", bodyPath, err)
	}

	client := axonflow.NewClientSimple(endpoint, os.Getenv("AXONFLOW_CLIENT_ID"), os.Getenv("AXONFLOW_CLIENT_SECRET"))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	// What this deployment may author: consult it before publishing rather
	// than learning the edition's boundary from a refusal.
	step("what this deployment may author", func() error {
		edition, err := client.TypedPolicyEdition(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("root=%s max_documents=%d persistence=%s\n", edition.Root, edition.MaxDocuments, edition.Persistence)
		if edition.Constructs != nil {
			fmt.Printf("edition=%s obligation families=%v\n", edition.Constructs.Edition, edition.Constructs.ObligationFamilies)
		}
		return nil
	})

	// Validation reports every finding. A refused document is still a
	// successful validation: read Success and Findings, do not expect an error.
	step("validate the document", func() error {
		validation, err := client.ValidateTypedPolicy(ctx, body.Document, body.Fixtures)
		if err != nil {
			return err
		}
		fmt.Printf("success=%v\n", validation.Success)
		for _, f := range validation.Findings {
			fmt.Printf("  %s %s %s: %s\n", f.Severity, f.Code, f.PolicyID, f.Detail)
		}
		return nil
	})

	if os.Getenv("AXONFLOW_TYPED_POLICY_PUBLISH") == "1" {
		step("publish and activate", func() error {
			published, err := client.PublishTypedPolicy(ctx, body.Document, body.Fixtures)
			var refusal *axonflow.TypedPolicyRefusal
			if errors.As(err, &refusal) {
				// A refusal carries the platform's reason and, for a refused
				// document, the findings that refused it.
				fmt.Printf("refused: HTTP %d %s: %s\n", refusal.Status, refusal.Reason, refusal.Message)
				for _, f := range refusal.Findings {
					fmt.Printf("  %s %s %s\n", f.Severity, f.Code, f.PolicyID)
				}
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Printf("published %s (version %d)\n", published.Digest, published.Version)
			if _, err := client.ActivateTypedPolicy(ctx, published.Digest, "examples/typed_policies"); err != nil {
				return err
			}
			fmt.Println("activated")
			return nil
		})
	}

	// The document in force is returned as the exact bytes that were signed.
	step("the document in force", func() error {
		active, err := client.ActiveTypedPolicy(ctx)
		if err != nil {
			return err
		}
		if active == nil {
			fmt.Println("nothing is active")
			return nil
		}
		fmt.Printf("%d signed bytes; document_id=%v\n", len(active.Source), active.Document["metadata"].(map[string]any)["document_id"])
		return nil
	})

	if failures > 0 {
		fmt.Printf("\n%d step(s) failed\n", failures)
		os.Exit(1)
	}
}
