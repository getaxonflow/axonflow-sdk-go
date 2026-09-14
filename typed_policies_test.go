package axonflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Typed policy authoring: each operation on the wire (method, route and exact
// body) and on its answer, every documented refusal, and the null shapes a
// real platform sends.

// typedPolicyExchange is the one request a typedPolicyServer received.
type typedPolicyExchange struct {
	method, path string
	header       http.Header
	body         map[string]any // nil when the request had no body
}

// typedPolicyServer answers every request with status, headers and body, and
// records the request.
func typedPolicyServer(t *testing.T, status int, headers map[string]string, body string) (*AxonFlowClient, *typedPolicyExchange) {
	t.Helper()
	got := &typedPolicyExchange{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.header = r.Method, r.URL.Path, r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			got.body = map[string]any{}
			if err := json.Unmarshal(raw, &got.body); err != nil {
				t.Errorf("request body is not a JSON object: %s", raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return NewClient(AxonFlowConfig{
		Endpoint:     srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Retry:        RetryConfig{Enabled: false, MaxAttempts: 1},
	}), got
}

var (
	typedPolicyDocument = map[string]any{"api_version": "v1", "metadata": map[string]any{"document_id": "doc-1"}}
	typedPolicyFixtures = []map[string]any{{"name": "a refund is denied", "expect": "deny"}}
)

const typedPolicyDigest = "sha256:abc"

// asJSON normalises a value to what it looks like after a JSON round-trip, so
// it compares with a decoded request body.
func asJSON(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertTypedPolicyRoute(t *testing.T, got *typedPolicyExchange, method, route string) {
	t.Helper()
	if got.method != method || got.path != TypedPoliciesPath+route {
		t.Errorf("sent %s %s, want %s %s", got.method, got.path, method, TypedPoliciesPath+route)
	}
}

func TestTypedPolicyEdition(t *testing.T) {
	c, got := typedPolicyServer(t, 200, nil, `{"success":true,"catalog":"default","catalog_digest":"sha256:cat",
		"registry_version":3,"catalog_fixture":true,"root":"organization",
		"max_documents":20,"constructs":{"edition":"community","obligation_families":["field_redact"],
		"attribute_namespaces":["subject"],"group_scope":false,"separation_of_duties":false,
		"tier_established":true,"reserved":["group_scope"]},"persistence":"database","signing_key_custody":"local"}`)
	edition, err := c.TypedPolicyEdition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertTypedPolicyRoute(t, got, http.MethodGet, "/edition")
	if got.body != nil {
		t.Errorf("GET sent a body: %v", got.body)
	}
	want := &TypedAuthoringEdition{
		Success: true, Catalog: "default", CatalogDigest: "sha256:cat", RegistryVersion: 3, CatalogFixture: true,
		Root: "organization", MaxDocuments: 20,
		Constructs: &EditionConstructReport{
			Edition: "community", ObligationFamilies: []string{"field_redact"},
			AttributeNamespaces: []string{"subject"}, TierEstablished: true, Reserved: []string{"group_scope"},
		},
		Persistence: "database", SigningKeyCustody: "local",
	}
	if !reflect.DeepEqual(edition, want) {
		t.Errorf("edition\n got %+v\nwant %+v", edition, want)
	}
}

func TestValidateTypedPolicySendsTheDocumentAndFixturesAndReturnsEveryFinding(t *testing.T) {
	c, got := typedPolicyServer(t, 200, nil, `{"success":false,"findings":[{"code":"ACTION_NOT_REGISTERED",
		"severity":"reject","policy_id":"grant.refund","summary":"an action is not registered","detail":"tool.x"}]}`)
	validation, err := c.ValidateTypedPolicy(context.Background(), typedPolicyDocument, typedPolicyFixtures)
	if err != nil {
		t.Fatal(err)
	}
	assertTypedPolicyRoute(t, got, http.MethodPost, "/validate")
	wantBody := asJSON(t, map[string]any{"document": typedPolicyDocument, "fixtures": typedPolicyFixtures})
	if !reflect.DeepEqual(any(got.body), wantBody) {
		t.Errorf("body\n got %v\nwant %v", got.body, wantBody)
	}
	want := &TypedPolicyValidation{Findings: []AuthoringFinding{{
		Code: "ACTION_NOT_REGISTERED", Severity: "reject", PolicyID: "grant.refund",
		Summary: "an action is not registered", Detail: "tool.x",
	}}}
	if !reflect.DeepEqual(validation, want) {
		t.Errorf("validation\n got %+v\nwant %+v", validation, want)
	}
}

func TestNilFixturesSendNoneAndAnEmptyListSendsAnEmptyArray(t *testing.T) {
	c, got := typedPolicyServer(t, 200, nil, `{"success":true,"findings":[]}`)
	if _, err := c.ValidateTypedPolicy(context.Background(), typedPolicyDocument, nil); err != nil {
		t.Fatal(err)
	}
	if _, present := got.body["fixtures"]; present {
		t.Errorf("nil fixtures sent a fixtures member: %v", got.body)
	}
	if _, err := c.ValidateTypedPolicy(context.Background(), typedPolicyDocument, []map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if fixtures, ok := got.body["fixtures"].([]any); !ok || len(fixtures) != 0 {
		t.Errorf("an empty fixture list sent %v, want []", got.body["fixtures"])
	}
}

func TestPublishTypedPolicy(t *testing.T) {
	c, got := typedPolicyServer(t, 200, nil, `{"success":true,"digest":"sha256:abc","version":2,
		"findings":[{"code":"UNUSED_ATTRIBUTE","severity":"warn"}],
		"template_omissions":{"omitted":["sys_a","sys_b"],"of":22,"message":"omits 2 of 22"}}`)
	published, err := c.PublishTypedPolicy(context.Background(), typedPolicyDocument, typedPolicyFixtures)
	if err != nil {
		t.Fatal(err)
	}
	assertTypedPolicyRoute(t, got, http.MethodPost, "/publish")
	if !reflect.DeepEqual(any(got.body), asJSON(t, map[string]any{"document": typedPolicyDocument, "fixtures": typedPolicyFixtures})) {
		t.Errorf("body %v", got.body)
	}
	want := &TypedPolicyPublication{Success: true, Digest: typedPolicyDigest, Version: 2,
		Findings:          []AuthoringFinding{{Code: "UNUSED_ATTRIBUTE", Severity: "warn"}},
		TemplateOmissions: &TemplateOmissionReport{Omitted: []string{"sys_a", "sys_b"}, Of: 22, Message: "omits 2 of 22"}}
	if !reflect.DeepEqual(published, want) {
		t.Errorf("publication\n got %+v\nwant %+v", published, want)
	}
}

func TestActivateTypedPolicy(t *testing.T) {
	for _, tc := range []struct {
		reason string
		sent   map[string]any
	}{
		{"", map[string]any{"digest": typedPolicyDigest}},
		{"rollout", map[string]any{"digest": typedPolicyDigest, "reason": "rollout"}},
	} {
		c, got := typedPolicyServer(t, 200, nil, `{"success":true,"activation":{"digest":"sha256:abc","actor":"client:test-client"}}`)
		activation, err := c.ActivateTypedPolicy(context.Background(), typedPolicyDigest, tc.reason)
		if err != nil {
			t.Fatal(err)
		}
		assertTypedPolicyRoute(t, got, http.MethodPost, "/activate")
		if !reflect.DeepEqual(got.body, tc.sent) {
			t.Errorf("reason %q: body %v, want %v", tc.reason, got.body, tc.sent)
		}
		if !activation.Success || activation.Activation["actor"] != "client:test-client" {
			t.Errorf("activation %+v", activation)
		}
	}
}

func TestActiveTypedPolicyKeepsTheExactBytesThatWereSigned(t *testing.T) {
	signed := `{"api_version": "v1",   "metadata": {"document_id": "doc-1"}}`
	c, got := typedPolicyServer(t, 200, nil, signed)
	active, err := c.ActiveTypedPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertTypedPolicyRoute(t, got, http.MethodGet, "/active")
	if active == nil || string(active.Source) != signed {
		t.Fatalf("source %q, want the exact signed bytes %q", active.Source, signed)
	}
	if !reflect.DeepEqual(active.Document, asJSON(t, typedPolicyDocument)) {
		t.Errorf("document %v", active.Document)
	}
}

func TestNothingActiveIsNil(t *testing.T) {
	c, _ := typedPolicyServer(t, 404, nil, `{"success":false,"reason":"nothing_active","error":"nothing is active"}`)
	active, err := c.ActiveTypedPolicy(context.Background())
	if active != nil || err != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", active, err)
	}
}

func TestTypedPolicySystem(t *testing.T) {
	c, got := typedPolicyServer(t, 200, nil, `{"success":true,"system":{"root":"system","version":3,
		"digest":"sha256:system","authority":"shipped_corpus","controls":[{"id":"sys.pii.ssn",
		"name":"SSN redaction","authority":"constraint","assurance":"enforcement","mandatory":true,"description":"SSN",
		"obligations":[{"type":"field_redact"}]},{"id":"sys.log","assurance":"advisory"}],
		"assurance_counts":{"enforcement":1,"advisory":1},"document":{"api_version":"v1"}}}`)
	system, err := c.TypedPolicySystem(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertTypedPolicyRoute(t, got, http.MethodGet, "/system")
	want := &TypedPolicySystemCorpus{
		Root: "system", Version: 3, Digest: "sha256:system", Authority: "shipped_corpus",
		Controls: []TypedPolicySystemControl{{
			ID: "sys.pii.ssn", Name: "SSN redaction", Authority: "constraint", Assurance: "enforcement", Mandatory: true,
			Description: "SSN", Obligations: []map[string]any{{"type": "field_redact"}},
		}, {ID: "sys.log", Assurance: "advisory"}},
		AssuranceCounts: map[string]int{"enforcement": 1, "advisory": 1},
		Document:        map[string]any{"api_version": "v1"},
	}
	if !reflect.DeepEqual(system, want) {
		t.Errorf("system\n got %+v\nwant %+v", system, want)
	}
}

// Only the platform's own nothing_active is (nil, nil): any other 404, from a
// platform without the typed routes or an endpoint that is not an agent, is a
// refusal naming its status.
func TestA404ThatIsNotNothingActiveIsATypedRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body, reason string
	}{
		{"plain text", "text/plain", "404 page not found", ""},
		{"no such endpoint", "application/json", `{"success":false,"reason":"no_such_endpoint","error":"no such typed-policies endpoint"}`, "no_such_endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := typedPolicyServer(t, 404, map[string]string{"Content-Type": tc.contentType}, tc.body)
			active, err := c.ActiveTypedPolicy(context.Background())
			var refusal *TypedPolicyRefusal
			if active != nil || !errors.As(err, &refusal) || refusal.Status != 404 || refusal.Reason != tc.reason {
				t.Errorf("got (%v, %T %v), want a *TypedPolicyRefusal with status 404 and reason %q", active, err, err, tc.reason)
			}
		})
	}
}

// A publication whose omission report could not be produced says why, and
// carries no report.
func TestAPublicationWhoseOmissionReportIsUnavailableSaysWhy(t *testing.T) {
	c, _ := typedPolicyServer(t, 200, nil, `{"success":true,"digest":"sha256:abc","version":1,"findings":[],
		"template_omissions_unavailable":"the organization template could not be read"}`)
	published, err := c.PublishTypedPolicy(context.Background(), typedPolicyDocument, typedPolicyFixtures)
	if err != nil {
		t.Fatal(err)
	}
	if published.TemplateOmissions != nil || published.TemplateOmissionsUnavailable != "the organization template could not be read" {
		t.Errorf("publication %+v", published)
	}
}

// The activation carries the omission report beside the activation record, not
// inside it.
func TestTheActivationCarriesTheOmissionReport(t *testing.T) {
	c, _ := typedPolicyServer(t, 200, nil, `{"success":true,"activation":{"digest":"sha256:abc"},
		"template_omissions":{"omitted":["sys_a"],"of":22,"message":"omits 1 of 22"}}`)
	activation, err := c.ActivateTypedPolicy(context.Background(), typedPolicyDigest, "")
	if err != nil {
		t.Fatal(err)
	}
	want := &TemplateOmissionReport{Omitted: []string{"sys_a"}, Of: 22, Message: "omits 1 of 22"}
	if !reflect.DeepEqual(activation.TemplateOmissions, want) || activation.TemplateOmissionsUnavailable != "" {
		t.Errorf("activation report %+v, want %+v", activation.TemplateOmissions, want)
	}
	if _, inside := activation.Activation["template_omissions"]; inside {
		t.Errorf("the report was read into the activation record: %v", activation.Activation)
	}
}

// A tier refusal names the policy that crossed the ceiling; an outage refusal
// (with Retry-After) names none.
func TestATierRefusalNamesThePolicyThatCrossedIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
		body    string
		policy  string
	}{
		{"the ceiling", nil, `{"success":false,"reason":"tier_limit","code":"ERR_TIER_LIMIT_ORG_ROOT_POLICY","error":"ceiling","policy":"grant.refund"}`, "grant.refund"},
		{"an outage", map[string]string{"Retry-After": "30"}, `{"success":false,"reason":"tier_limit","code":"ERR_TIER_LIMIT_ORG_ROOT_POLICY","error":"admission could not be checked"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := typedPolicyServer(t, 402, tc.headers, tc.body)
			_, err := c.PublishTypedPolicy(context.Background(), typedPolicyDocument, typedPolicyFixtures)
			var refusal *TypedPolicyRefusal
			if !errors.As(err, &refusal) || refusal.Policy != tc.policy {
				t.Errorf("got %T %+v, want a refusal naming policy %q", err, err, tc.policy)
			}
		})
	}
}

// callTypedPolicy calls one operation by name, for the refusal table.
func callTypedPolicy(c *AxonFlowClient, operation string) error {
	ctx := context.Background()
	var err error
	switch operation {
	case "edition":
		_, err = c.TypedPolicyEdition(ctx)
	case "validate":
		_, err = c.ValidateTypedPolicy(ctx, typedPolicyDocument, typedPolicyFixtures)
	case "publish":
		_, err = c.PublishTypedPolicy(ctx, typedPolicyDocument, typedPolicyFixtures)
	case "activate":
		_, err = c.ActivateTypedPolicy(ctx, typedPolicyDigest, "")
	case "active":
		_, err = c.ActiveTypedPolicy(ctx)
	case "system":
		_, err = c.TypedPolicySystem(ctx)
	}
	return err
}

func TestEveryDocumentedTypedPolicyRefusalIsTyped(t *testing.T) {
	approver := `{"code":"APPROVER_IS_AUTHOR","severity":"reject","summary":"the author may not approve their own publication"}`
	for _, tc := range []struct {
		name, operation string
		status          int
		headers         map[string]string
		body            string
		reason, code    string
		findings        []string
		retryAfter      int
	}{
		{"publish 422 separation of duties", "publish", 422, nil,
			`{"success":false,"reason":"publication_refused","error":"refused: publication_refused","findings":[` + approver + `]}`,
			"publication_refused", "", []string{"APPROVER_IS_AUTHOR"}, 0},
		{"publish 422 document", "publish", 422, nil,
			`{"success":false,"reason":"document_refused","error":"refused: document_refused","findings":[]}`,
			"document_refused", "", nil, 0},
		{"publish 402 tier limit", "publish", 402, nil,
			`{"success":false,"reason":"tier_limit","error":"refused: tier_limit","code":"ERR_TIER_LIMIT_ORG_ROOT_POLICY"}`,
			"tier_limit", "ERR_TIER_LIMIT_ORG_ROOT_POLICY", nil, 0},
		{"publish 402 ledger outage", "publish", 402, map[string]string{"Retry-After": "30"},
			`{"success":false,"reason":"tier_limit","error":"refused: tier_limit","code":"ERR_TIER_LIMIT_ORG_ROOT_POLICY"}`,
			"tier_limit", "ERR_TIER_LIMIT_ORG_ROOT_POLICY", nil, 30},
		{"publish 429 artifact cap", "publish", 429, nil,
			`{"success":false,"reason":"artifact_cap","error":"refused: artifact_cap"}`, "artifact_cap", "", nil, 0},
		{"publish 400", "publish", 400, nil,
			`{"success":false,"reason":"document_id_required","error":"refused: document_id_required"}`,
			"document_id_required", "", nil, 0},
		{"activate 409", "activate", 409, nil,
			`{"success":false,"reason":"activation_refused","error":"refused: activation_refused"}`,
			"activation_refused", "", nil, 0},
		{"validate 503", "validate", 503, nil,
			`{"success":false,"reason":"catalog_not_configured","error":"refused: catalog_not_configured"}`,
			"catalog_not_configured", "", nil, 0},
		{"edition 404", "edition", 404, nil,
			`{"success":false,"reason":"no_such_endpoint","error":"refused: no_such_endpoint"}`,
			"no_such_endpoint", "", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := typedPolicyServer(t, tc.status, tc.headers, tc.body)
			err := callTypedPolicy(c, tc.operation)
			var refusal *TypedPolicyRefusal
			if !errors.As(err, &refusal) {
				t.Fatalf("want a *TypedPolicyRefusal, got %T %v", err, err)
			}
			var codes []string
			for _, f := range refusal.Findings {
				codes = append(codes, f.Code)
			}
			if refusal.Status != tc.status || refusal.Reason != tc.reason || refusal.Code != tc.code ||
				refusal.Message != "refused: "+tc.reason || !reflect.DeepEqual(codes, tc.findings) ||
				refusal.RetryAfter != tc.retryAfter {
				t.Errorf("refusal %+v", refusal)
			}
			if want := fmt.Sprintf("typed policy request refused (HTTP %d, %s): refused: %s", tc.status, tc.reason, tc.reason); err.Error() != want {
				t.Errorf("message %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestATypedPolicy401IsTheClientsUsualError(t *testing.T) {
	c, _ := typedPolicyServer(t, 401, nil, `{"success":false,"reason":"org_not_stamped","error":"refused: org_not_stamped"}`)
	_, err := c.TypedPolicySystem(context.Background())
	var refusal *TypedPolicyRefusal
	if errors.As(err, &refusal) {
		t.Fatalf("a 401 became a typed refusal: %v", err)
	}
	var httpErr *httpError
	if !errors.As(err, &httpErr) || httpErr.statusCode != 401 || !strings.Contains(httpErr.message, "refused: org_not_stamped") {
		t.Errorf("want the client's 401 error carrying the platform's text, got %T %v", err, err)
	}
}

func TestATypedPolicyRefusalWithoutAJSONBodyStillNamesItsStatus(t *testing.T) {
	c, _ := typedPolicyServer(t, 502, map[string]string{"Content-Type": "text/plain"}, "bad gateway")
	_, err := c.TypedPolicyEdition(context.Background())
	var refusal *TypedPolicyRefusal
	if !errors.As(err, &refusal) || refusal.Status != 502 || refusal.Reason != "" || refusal.Message != "HTTP 502 from /edition" {
		t.Errorf("got %T %+v", err, err)
	}
	if want := "typed policy request refused (HTTP 502): HTTP 502 from /edition"; err.Error() != want {
		t.Errorf("message %q, want %q", err.Error(), want)
	}
}

func TestATypedPolicySuccessWhoseBodyIsNotAnObjectIsAnError(t *testing.T) {
	c, _ := typedPolicyServer(t, 200, nil, `["not","an","object"]`)
	if _, err := c.TypedPolicyEdition(context.Background()); err == nil || !strings.Contains(err.Error(), "not an object") {
		t.Errorf("edition: got %v", err)
	}
	if _, err := c.ActiveTypedPolicy(context.Background()); err == nil || !strings.Contains(err.Error(), "not an object") {
		t.Errorf("active: got %v", err)
	}
}

// What the platform sends for a collection it holds as a nil Go slice or map:
// JSON null, not [] or {}. A real stack's clean validation answered
// "findings": null; these are every such field it declares without omitempty.
func TestANilGoCollectionReadsAsEmpty(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, body string
		read       func(c *AxonFlowClient) (int, error)
	}{
		{"validate findings", `{"success":true,"findings":null}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.ValidateTypedPolicy(ctx, typedPolicyDocument, nil)
			if err != nil {
				return 0, err
			}
			return len(r.Findings), nil
		}},
		{"publish findings", `{"success":true,"digest":"sha256:abc","version":1,"findings":null}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.PublishTypedPolicy(ctx, typedPolicyDocument, typedPolicyFixtures)
			if err != nil {
				return 0, err
			}
			return len(r.Findings), nil
		}},
		{"edition constructs", `{"success":true,"constructs":{"edition":"community","obligation_families":null,"attribute_namespaces":null}}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.TypedPolicyEdition(ctx)
			if err != nil {
				return 0, err
			}
			return len(r.Constructs.ObligationFamilies) + len(r.Constructs.AttributeNamespaces), nil
		}},
		{"system collections", `{"success":true,"system":{"root":"system","controls":null,"assurance_counts":null,"document":null}}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.TypedPolicySystem(ctx)
			if err != nil {
				return 0, err
			}
			return len(r.Controls) + len(r.AssuranceCounts) + len(r.Document), nil
		}},
		{"publish omissions null", `{"success":true,"digest":"sha256:abc","version":1,"findings":[],"template_omissions":null}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.PublishTypedPolicy(ctx, typedPolicyDocument, typedPolicyFixtures)
			if err != nil {
				return 0, err
			}
			if r.TemplateOmissions != nil {
				return 1, nil
			}
			return 0, nil
		}},
		{"publish omitted null", `{"success":true,"digest":"sha256:abc","version":1,"findings":[],"template_omissions":{"omitted":null,"of":22,"message":"m"}}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.PublishTypedPolicy(ctx, typedPolicyDocument, typedPolicyFixtures)
			if err != nil || r.TemplateOmissions == nil {
				return -1, err
			}
			return len(r.TemplateOmissions.Omitted), nil
		}},
		{"no system", `{"success":true,"system":null}`, func(c *AxonFlowClient) (int, error) {
			r, err := c.TypedPolicySystem(ctx)
			if err != nil {
				return 0, err
			}
			return len(r.Controls), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := typedPolicyServer(t, 200, nil, tc.body)
			n, err := tc.read(c)
			if err != nil || n != 0 {
				t.Errorf("got %d elements, err %v; want an empty read", n, err)
			}
		})
	}
}

func TestTheContextsUserTokenReachesTheTypedPolicyRoutes(t *testing.T) {
	c, got := typedPolicyServer(t, 200, nil, `{"success":true,"findings":[]}`)
	ctx := ContextWithUserToken(context.Background(), "user-jwt")
	if _, err := c.ValidateTypedPolicy(ctx, typedPolicyDocument, nil); err != nil {
		t.Fatal(err)
	}
	if v := got.header.Get(headerUserToken); v != "user-jwt" {
		t.Errorf("user token header %q, want the context's", v)
	}
}

func TestTheTypedPolicyRoutesCarryNoPEPHandshake(t *testing.T) {
	declared := mustPEPHandshake(t, "request-path", "https://pep.example.test", pepDeclared)
	c, got := typedPolicyServer(t, 200, nil, `{"success":true,"findings":[]}`)
	c.config.PEPHandshake = declared
	ctx := ContextWithPEPHandshake(context.Background(), declared)
	if _, err := c.ValidateTypedPolicy(ctx, typedPolicyDocument, nil); err != nil {
		t.Fatal(err)
	}
	if v := got.header.Get(PEPHandshakeHeader); v != "" {
		t.Errorf("the validate route received the handshake %q; only the four planes may", v)
	}
}
