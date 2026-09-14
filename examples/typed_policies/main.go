// Typed policy authoring against a running AxonFlow v11 platform.
//
// A v11 platform authors policy as a typed document: validated, published as a
// signed artifact pinned by its digest, and promoted to active. This example
// reads what the deployment may author, validates a document and prints every
// finding, and shows the document in force. It publishes and activates only
// when AXONFLOW_TYPED_POLICY_PUBLISH=1, because that changes the organization's
// active policy. Before it activates, it prints the publication's report of the
// organization template's controls the document omits: activating a document
// that omits them removes them for the organization. A publication or
// activation it was asked for and refused fails the run.
//
// Run examples/pep_handshake first. Note: after a document with an
// organization-scope constraint is activated, a decide that does not supply
// the attribute the constraint conditions on is denied fail-closed with
// reasons ["unknown_constraint"]; supply the attribute or run this example on
// a fresh stack. From v11.0.0 the deny's first reason is that code, followed
// by one naming each constraint it could not evaluate and the attribute it
// needed (getaxonflow/axonflow-enterprise#4247). The default document is such
// a document.
//
// Run it against a local stack from the module root. Its default document is
// embedded, so the built program runs from any directory:
//
//	export AXONFLOW_ENDPOINT=http://localhost:8080
//	export AXONFLOW_CLIENT_ID=...
//	export AXONFLOW_CLIENT_SECRET=...
//	go run ./examples/typed_policies
//
// AXONFLOW_TYPED_POLICY_BODY names a JSON file holding {"document": ...,
// "fixtures": [...]}; the default is embedded in the example, a byte-for-byte
// copy of testdata/typed_policy_publish_body.json.
// Exits non-zero if a step fails, so it is usable as a smoke test.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

// defaultBody is the document and fixtures the example uses when
// AXONFLOW_TYPED_POLICY_BODY is unset, embedded so the example runs from any
// directory. A test holds it byte-equal to testdata/typed_policy_publish_body.json.
//
//go:embed typed_policy_publish_body.json
var defaultBody []byte

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	raw, source := defaultBody, "the embedded default body"
	if bodyPath := os.Getenv("AXONFLOW_TYPED_POLICY_BODY"); bodyPath != "" {
		var err error
		if raw, err = os.ReadFile(bodyPath); err != nil {
			log.Fatalf("read %s: %v", bodyPath, err)
		}
		source = bodyPath
	}
	var body struct {
		Document map[string]any   `json:"document"`
		Fixtures []map[string]any `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		log.Fatalf("decode %s: %v", source, err)
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
				// Publishing was asked for, so a refusal fails the run.
				return errors.New("the publication was refused")
			}
			if err != nil {
				return err
			}
			fmt.Printf("published %s (version %d)\n", published.Digest, published.Version)
			// Activating a document that omits the organization template's controls
			// removes them for the organization, so the report comes first.
			switch report := published.TemplateOmissions; {
			case report != nil:
				fmt.Printf("template omissions: %d of %d template controls: %s\n", len(report.Omitted), report.Of, strings.Join(report.Omitted, ", "))
			case published.TemplateOmissionsUnavailable != "":
				fmt.Printf("template omissions: unavailable: %s\n", published.TemplateOmissionsUnavailable)
			default:
				fmt.Println("template omissions: none")
			}
			if _, err := client.ActivateTypedPolicy(ctx, published.Digest, "examples/typed_policies"); err != nil {
				if errors.As(err, &refusal) {
					// Activation promotes: a digest whose version does not
					// advance past the active one is refused.
					fmt.Printf("activation refused: HTTP %d %s: %s\n", refusal.Status, refusal.Reason, refusal.Message)
					// Activating was asked for, so a refusal fails the run.
					return errors.New("the activation was refused")
				}
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
