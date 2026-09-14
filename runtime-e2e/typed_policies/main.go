//go:build ignore

// runtime-e2e/typed_policies/main.go
//
// Real-stack proof of typed policy authoring through the SDK. It drives the six
// typed policy methods against a real agent and orchestrator and asserts, on a
// fresh stack:
//
//  1. Nothing is active yet: ActiveTypedPolicy answers (nil, nil) from the
//     platform's 404 whose reason is nothing_active, the reason it keys on.
//  2. TypedPolicyEdition reports the deployment's boundary and names its
//     vocabulary by digest (not a test-world fixture), and TypedPolicySystem
//     the shipped controls with their digest.
//  3. The document the platform's own route test proves publishable validates
//     clean, publishes to a digest, and activates.
//     The publication reports the organization template's 22 controls the
//     document omits, and the activation reports the same.
//  4. ActiveTypedPolicy returns that document, carrying the policies that were
//     published, with the AUTHOR overwritten by the platform: the document
//     deliberately names someone-else, and on Community the platform signs the
//     Client principal of the presented credentials.
//  5. Activating the same digest again is refused as a typed 409
//     (activation_refused): activation promotes, and the version does not
//     advance.
//  6. Publishing with no fixtures is refused as a typed 422
//     (publication_refused) whose message names the missing fixtures.
//  7. A document naming an action the registry does not hold validates with
//     the platform's rejecting finding (ACTION_NOT_REGISTERED), and publishing
//     it is refused as a typed 422 (document_refused) carrying that finding.
//
// The document is testdata/typed_policy_publish_body.json, marshalled by the
// platform's own types, with its document_id made unique per run. Run it from
// the repository root against a FRESH community stack (nothing active on the
// organization); see README.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures []string

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func check(ok bool, description string) {
	if ok {
		fmt.Printf("PASS: %s\n", description)
		return
	}
	fmt.Printf("FAIL: %s\n", description)
	failures = append(failures, description)
}

func fatal(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

// deepCopy returns an independent copy of a decoded JSON object.
func deepCopy(v map[string]any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		fatal("copy: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		fatal("copy: %v", err)
	}
	return out
}

// refusal returns err as a *TypedPolicyRefusal, or nil.
func refusal(err error) *axonflow.TypedPolicyRefusal {
	var r *axonflow.TypedPolicyRefusal
	if errors.As(err, &r) {
		return r
	}
	return nil
}

func hasFinding(findings []axonflow.AuthoringFinding, code, severity, policyID string) bool {
	for _, f := range findings {
		if f.Code == code && f.Severity == severity && f.PolicyID == policyID {
			return true
		}
	}
	return false
}

func main() {
	endpoint := env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	fmt.Printf("agent: %s\n", endpoint)
	raw, err := os.ReadFile("testdata/typed_policy_publish_body.json")
	if err != nil {
		fatal("read the publish body: %v", err)
	}
	var body struct {
		Document map[string]any   `json:"document"`
		Fixtures []map[string]any `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		fatal("decode the publish body: %v", err)
	}
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     env("AXONFLOW_CLIENT_ID", "runtime-e2e"),
		ClientSecret: env("AXONFLOW_CLIENT_SECRET", "runtime-e2e-secret"),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		fatal("random: %v", err)
	}
	document := deepCopy(body.Document)
	documentID := "sdk-go-e2e-" + hex.EncodeToString(suffix)
	document["metadata"].(map[string]any)["document_id"] = documentID
	fixtures := body.Fixtures

	fmt.Println("== nothing active yet")
	active, err := client.ActiveTypedPolicy(ctx)
	check(active == nil && err == nil, fmt.Sprintf("ActiveTypedPolicy is (nil, nil) before any activation (err %v)", err))

	fmt.Println("== edition and system")
	edition, err := client.TypedPolicyEdition(ctx)
	if err != nil {
		fatal("TypedPolicyEdition: %v", err)
	}
	constructsEdition := ""
	if edition.Constructs != nil {
		constructsEdition = edition.Constructs.Edition
	}
	fmt.Printf("  edition: catalog=%s root=%s max_documents=%d persistence=%s constructs.edition=%s\n",
		edition.Catalog, edition.Root, edition.MaxDocuments, edition.Persistence, constructsEdition)
	check(edition.Success && edition.Root == "organization", "TypedPolicyEdition reports the root")
	check(edition.Constructs != nil, "TypedPolicyEdition reports the construct boundary")
	fmt.Printf("  vocabulary: catalog_digest=%s registry_version=%d catalog_fixture=%v\n",
		edition.CatalogDigest, edition.RegistryVersion, edition.CatalogFixture)
	check(edition.CatalogDigest != "", "TypedPolicyEdition names its vocabulary by digest")
	check(!edition.CatalogFixture, "the deployment's vocabulary is not a test-world fixture, so a document can activate against it")
	system, err := client.TypedPolicySystem(ctx)
	if err != nil {
		fatal("TypedPolicySystem: %v", err)
	}
	fmt.Printf("  system: root=%s version=%d digest=%s controls=%d assurance_counts=%v\n",
		system.Root, system.Version, system.Digest, len(system.Controls), system.AssuranceCounts)
	check(system.Digest != "" && len(system.Controls) > 0, "TypedPolicySystem returns the shipped corpus")
	named, mandatory := 0, 0
	for _, control := range system.Controls {
		if control.Name != "" {
			named++
		}
		if control.Mandatory {
			mandatory++
		}
	}
	fmt.Printf("  system controls: %d named, %d mandatory, of %d\n", named, mandatory, len(system.Controls))
	check(named > 0, "TypedPolicySystem reads each control's name")
	check(mandatory > 0, "TypedPolicySystem reads which controls are mandatory")

	fmt.Println("== validate, publish, activate")
	validation, err := client.ValidateTypedPolicy(ctx, document, fixtures)
	if err != nil {
		fatal("ValidateTypedPolicy: %v", err)
	}
	fmt.Printf("  validate: success=%v findings=%v\n", validation.Success, validation.Findings)
	check(validation.Success, "the document validates clean")
	published, err := client.PublishTypedPolicy(ctx, document, fixtures)
	if err != nil {
		fatal("PublishTypedPolicy: %v", err)
	}
	fmt.Printf("  publish: digest=%s version=%d\n", published.Digest, published.Version)
	check(published.Digest != "", "PublishTypedPolicy returns the artifact digest")
	if report := published.TemplateOmissions; report != nil {
		fmt.Printf("  template omissions: %d of %d: %s\n", len(report.Omitted), report.Of, strings.Join(report.Omitted, ", "))
	} else {
		fmt.Printf("  template omissions: none (unavailable=%q)\n", published.TemplateOmissionsUnavailable)
	}
	// The document names none of the template's controls, so it omits every one.
	check(published.TemplateOmissions != nil && published.TemplateOmissions.Of > 0 && len(published.TemplateOmissions.Omitted) == published.TemplateOmissions.Of,
		"the publication reports every organization template control the document omits")
	activation, err := client.ActivateTypedPolicy(ctx, published.Digest, "sdk-go runtime proof")
	if err != nil {
		fatal("ActivateTypedPolicy: %v", err)
	}
	fmt.Printf("  activate: success=%v activation=%v\n", activation.Success, activation.Activation)
	check(activation.Success, "ActivateTypedPolicy promotes the digest")
	check(reflect.DeepEqual(activation.TemplateOmissions, published.TemplateOmissions),
		"the activation reports the same omissions as the publication")

	fmt.Println("== the document in force")
	active, err = client.ActiveTypedPolicy(ctx)
	check(err == nil && active != nil, "ActiveTypedPolicy returns the document in force")
	if active != nil {
		metadata, _ := active.Document["metadata"].(map[string]any)
		author, _ := metadata["author"].(map[string]any)
		fmt.Printf("  active: document_id=%v author=%v\n", metadata["document_id"], author)
		check(metadata["document_id"] == documentID, "ActiveTypedPolicy is the document just activated")
		// The signed source carries the policies that were published: compared by
		// id against the request, not against a parse of the same bytes.
		ids := func(doc map[string]any) []string {
			var out []string
			policy, _ := doc["policy"].(map[string]any)
			policies, _ := policy["policies"].([]any)
			for _, p := range policies {
				if m, ok := p.(map[string]any); ok {
					if id, ok := m["id"].(string); ok {
						out = append(out, id)
					}
				}
			}
			return out
		}
		publishedIDs := ids(document)
		fmt.Printf("  active policy ids: %v\n", ids(active.Document))
		check(len(publishedIDs) > 0 && reflect.DeepEqual(ids(active.Document), publishedIDs),
			"the document in force carries the policies that were published")
		// The author is the caller the agent stamped, never the name the request
		// carried. On Community that caller is the API client: a Client principal
		// in the api-credential realm, named by the client id this proof presents.
		stamped := author["type"] != nil && author["local"] != nil && author["local"] != ""
		if constructsEdition == "community" {
			stamped = author["type"] == "Client" && author["qualifier"] == "axonflow-api-credential" &&
				author["local"] == env("AXONFLOW_CLIENT_ID", "runtime-e2e")
		}
		check(stamped && author["local"] != "someone-else", "the platform signed the caller as author, not the name in the request")
	}

	fmt.Println("== typed refusals")
	_, err = client.ActivateTypedPolicy(ctx, published.Digest, "")
	if r := refusal(err); r != nil {
		fmt.Printf("  re-activate: status=%d reason=%s error=%s\n", r.Status, r.Reason, r.Message)
		check(r.Status == 409 && r.Reason == "activation_refused", "re-activating the active digest is a typed 409 activation_refused")
	} else {
		check(false, fmt.Sprintf("re-activating the active digest is refused (got %v)", err))
	}
	_, err = client.PublishTypedPolicy(ctx, document, []map[string]any{})
	if r := refusal(err); r != nil {
		fmt.Printf("  publish without fixtures: status=%d reason=%s error=%s\n", r.Status, r.Reason, r.Message)
		check(r.Status == 422 && r.Reason == "publication_refused" && strings.Contains(r.Message, "declares no fixtures"),
			"publishing with no fixtures is a typed 422 publication_refused naming the cause")
	} else {
		check(false, fmt.Sprintf("publishing with no fixtures is refused (got %v)", err))
	}

	fmt.Println("== a document the save-time checks reject")
	unregistered := deepCopy(document)
	unregistered["metadata"].(map[string]any)["document_id"] = documentID + "-unregistered"
	policy := unregistered["policy"].(map[string]any)["policies"].([]any)[0].(map[string]any)
	policy["actions"].(map[string]any)["actions"].([]any)[0].(map[string]any)["local"] = "tool.not_registered"
	rejected, err := client.ValidateTypedPolicy(ctx, unregistered, fixtures)
	if err != nil {
		fatal("ValidateTypedPolicy (unregistered): %v", err)
	}
	fmt.Printf("  validate: success=%v findings=%v\n", rejected.Success, rejected.Findings)
	check(!rejected.Success && hasFinding(rejected.Findings, "ACTION_NOT_REGISTERED", "reject", "grant.refund"),
		"ValidateTypedPolicy answers an unregistered action with the platform's rejecting finding")
	_, err = client.PublishTypedPolicy(ctx, unregistered, fixtures)
	if r := refusal(err); r != nil {
		fmt.Printf("  publish: status=%d reason=%s findings=%v\n", r.Status, r.Reason, r.Findings)
		check(r.Status == 422 && r.Reason == "document_refused" && hasFinding(r.Findings, "ACTION_NOT_REGISTERED", "reject", "grant.refund"),
			"publishing it is a typed 422 document_refused carrying that finding")
	} else {
		check(false, fmt.Sprintf("publishing a document the save-time checks reject is refused (got %v)", err))
	}

	if len(failures) > 0 {
		fmt.Printf("\nFAIL: typed_policies (%d assertion(s))\n", len(failures))
		os.Exit(1)
	}
	fmt.Println("\nPASS: typed_policies")
}
