package axonflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

// This file is typed policy authoring (platform v11.0.0), the successor to the
// legacy static- and dynamic-policy routes. A v11 platform authors policy as a
// typed document: validated, published as a signed artifact pinned by its
// digest, and promoted to active. Six routes under /api/v1/typed-policies do
// that, and the agent proxies all six with this client's credentials:
//
//   - TypedPolicyEdition: what this deployment may author, consulted BEFORE a
//     publication rather than learned from a refusal.
//   - ValidateTypedPolicy: every finding for a candidate document. It answers
//     identically on every edition; the edition's boundary applies at
//     publication.
//   - PublishTypedPolicy: validates, compiles, runs the declared fixtures,
//     signs, and pins the artifact by its digest.
//   - ActivateTypedPolicy: promotes a published digest to active.
//   - ActiveTypedPolicy: the document in force, as the exact bytes that were
//     signed.
//   - TypedPolicySystem: the platform's own controls, read-only.
//
// The organization and the author are the ones this client's credentials (and
// a user token on the context) resolve to. The agent stamps both, and neither
// can be named in a request.
//
// Activation PROMOTES: a digest whose version does not advance past the active
// one is refused. Rolling back to an earlier document and withdrawing the
// active one are operations of the customer portal, behind its session; the
// agent does not proxy them, so this client has no method for either.
//
// On an edition with separation of duties, PublishTypedPolicy refuses every
// publication with the finding code APPROVER_IS_AUTHOR: publishing through this
// route names no approver, and such a deployment approves in the customer
// portal.
//
// Every refusal is a *TypedPolicyRefusal carrying the HTTP status, the
// platform's reason and, where there are any, the findings. A 401 is the
// client's usual error, as on every other route.
//
// The platform marshals a collection it holds as a nil Go slice or map as JSON
// null (a clean validation answers "findings": null). It decodes here to a nil
// slice or map, which reads as empty.

// TypedPoliciesPath is the prefix of the six typed policy routes.
const TypedPoliciesPath = "/api/v1/typed-policies"

// EditionConstructReport is what this edition may spend (the spec's
// EditionConstructReport).
type EditionConstructReport struct {
	// Edition is community, evaluation or enterprise.
	Edition             string   `json:"edition,omitempty"`
	ObligationFamilies  []string `json:"obligation_families"`
	AttributeNamespaces []string `json:"attribute_namespaces"`
	GroupScope          bool     `json:"group_scope"`
	SeparationOfDuties  bool     `json:"separation_of_duties"`
	TierEstablished     bool     `json:"tier_established"`
	// Reserved names the constructs withheld for want of an edition ruling,
	// not by one.
	Reserved []string `json:"reserved,omitempty"`
}

// AuthoringFinding is one declared save-time or publication result (the
// spec's AuthoringFinding).
type AuthoringFinding struct {
	Code string `json:"code"`
	// Severity is reject or warn.
	Severity string `json:"severity"`
	PolicyID string `json:"policy_id,omitempty"`
	// Summary is the declared, code-level sentence.
	Summary string `json:"summary,omitempty"`
	// Detail says what was wrong, naming the offending value.
	Detail string `json:"detail,omitempty"`
}

// TypedAuthoringDocumentRequest is a candidate document and its fixtures (the
// spec's TypedAuthoringDocumentRequest).
type TypedAuthoringDocumentRequest struct {
	// Document is the authoring model itself, kept as a JSON object rather than
	// mirrored in Go types, so a field the policy vocabulary gains is
	// authorable without this SDK changing.
	Document map[string]any `json:"document"`
	// Fixtures are the author-declared cases the publication gauntlet runs. A
	// nil slice sends no fixtures member; an empty one sends [].
	Fixtures []map[string]any `json:"fixtures"`
}

// MarshalJSON omits the fixtures member only for a nil slice: an empty one is
// a declaration of no fixtures, which the platform answers differently.
func (r TypedAuthoringDocumentRequest) MarshalJSON() ([]byte, error) {
	if r.Fixtures == nil {
		return json.Marshal(struct {
			Document map[string]any `json:"document"`
		}{r.Document})
	}
	type plain TypedAuthoringDocumentRequest
	return json.Marshal(plain(r))
}

// TypedAuthoringEdition is what this deployment may author.
type TypedAuthoringEdition struct {
	Success bool `json:"success"`
	// Catalog is the configured authoring vocabulary.
	Catalog string `json:"catalog,omitempty"`
	// CatalogDigest is the vocabulary snapshot's content digest: its identity,
	// which a refusal, a decision and a proof carry too.
	CatalogDigest string `json:"catalog_digest,omitempty"`
	// RegistryVersion is the integer the wire carries for this vocabulary.
	RegistryVersion int64 `json:"registry_version"`
	// CatalogFixture is true for a test-world vocabulary, which the platform
	// refuses to activate a document against.
	CatalogFixture bool `json:"catalog_fixture"`
	// Root is the one authority root this surface publishes under.
	Root string `json:"root,omitempty"`
	// MaxDocuments is the customer-authored POLICIES (rules) admitted per
	// organization; -1 is unlimited. The member's name is historical: an
	// organization has one active document, and the ceiling counts the
	// policies inside it.
	MaxDocuments int                     `json:"max_documents"`
	Constructs   *EditionConstructReport `json:"constructs,omitempty"`
	// Persistence is process, database or unavailable.
	Persistence       string `json:"persistence,omitempty"`
	SigningKeyCustody string `json:"signing_key_custody,omitempty"`
}

// TypedPolicyValidation is every finding for a candidate document. Success is
// false when any finding is a rejection.
type TypedPolicyValidation struct {
	Success  bool               `json:"success"`
	Findings []AuthoringFinding `json:"findings"`
}

// TypedPolicyPublication is a published artifact. Activation names Digest,
// never the version.
type TypedPolicyPublication struct {
	Success  bool               `json:"success"`
	Digest   string             `json:"digest"`
	Version  int                `json:"version"`
	Findings []AuthoringFinding `json:"findings"`
	// TemplateOmissions is the platform's report of the organization template's
	// controls this document omits, nil when it omits none. Activating such a
	// document removes those controls for the organization.
	TemplateOmissions *TemplateOmissionReport `json:"template_omissions,omitempty"`
	// TemplateOmissionsUnavailable says why that report could not be produced,
	// when it could not.
	TemplateOmissionsUnavailable string `json:"template_omissions_unavailable,omitempty"`
}

// TemplateOmissionReport says which of the organization template's controls a
// document does not carry. Omitted is sorted, and Of is how many controls the
// template has.
type TemplateOmissionReport struct {
	Omitted []string `json:"omitted"`
	Of      int      `json:"of"`
	Message string   `json:"message,omitempty"`
}

// TypedPolicyActivation is the audited activation record.
type TypedPolicyActivation struct {
	Success    bool           `json:"success"`
	Activation map[string]any `json:"activation"`
	// TemplateOmissions is the report for the activated document, as on
	// TypedPolicyPublication; nil when it omits none.
	TemplateOmissions *TemplateOmissionReport `json:"template_omissions,omitempty"`
	// TemplateOmissionsUnavailable says why that report could not be produced,
	// when it could not.
	TemplateOmissionsUnavailable string `json:"template_omissions_unavailable,omitempty"`
}

// ActiveTypedPolicy is the document in force. Source is the exact byte
// sequence that was signed, so a caller can verify it; Document is the same
// bytes parsed.
type ActiveTypedPolicy struct {
	Source   []byte
	Document map[string]any
}

// TypedPolicySystemControl is one shipped control, with what happens when it
// cannot be evaluated.
type TypedPolicySystemControl struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Authority string `json:"authority,omitempty"`
	// Assurance is enforcement, gating_risk or advisory.
	Assurance string `json:"assurance,omitempty"`
	// Mandatory is whether an organization may not override it. The platform
	// omits the member when it is false, which reads as false.
	Mandatory   bool             `json:"mandatory"`
	Description string           `json:"description,omitempty"`
	Obligations []map[string]any `json:"obligations,omitempty"`
}

// TypedPolicySystemCorpus is the platform's own controls: the system root
// activated beneath every organization.
type TypedPolicySystemCorpus struct {
	Root    string `json:"root,omitempty"`
	Version int    `json:"version"`
	// Digest is the digest an enforcing engine anchors to.
	Digest          string                     `json:"digest,omitempty"`
	Authority       string                     `json:"authority,omitempty"`
	Controls        []TypedPolicySystemControl `json:"controls"`
	AssuranceCounts map[string]int             `json:"assurance_counts"`
	Document        map[string]any             `json:"document"`
}

// TypedPolicyRefusal is a typed policy authoring request the platform refused.
// Status is the HTTP status and Reason the platform's reason, for example
// publication_refused (422), activation_refused (409), tier_limit (402, with
// Code naming the limit and Policy the policy that crossed it) or artifact_cap
// (429). Findings holds the declared
// findings a refused publication or document carries, and RetryAfter the
// seconds from Retry-After when the refusal is retryable (0 when there is
// none). Message is the platform's own explanation.
type TypedPolicyRefusal struct {
	Status     int
	Reason     string
	Code       string
	Policy     string
	Message    string
	Findings   []AuthoringFinding
	RetryAfter int
}

func (e *TypedPolicyRefusal) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("typed policy request refused (HTTP %d): %s", e.Status, e.Message)
	}
	return fmt.Sprintf("typed policy request refused (HTTP %d, %s): %s", e.Status, e.Reason, e.Message)
}

// sendTypedPolicy sends one typed policy request and returns the answer with
// its body read. It maps no status: each caller does, through
// typedPolicyError.
func (c *AxonFlowClient) sendTypedPolicy(ctx context.Context, method, route string, payload any) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.config.Endpoint+TypedPoliciesPath+route, body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(req)
	if c.config.Debug {
		log.Printf("[AxonFlow] typed policies: %s %s", method, route)
	}
	resp, err := c.doHttpRequest(c.httpClient, req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}
	return resp, respBody, nil
}

// typedPolicyError is nil for a 2xx answer, the client's usual error for a 401,
// and a *TypedPolicyRefusal for every other refusal.
func typedPolicyError(resp *http.Response, body []byte, route string) error {
	if resp.StatusCode < 400 {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return responseError(resp.StatusCode, body)
	}
	var payload struct {
		Reason   string             `json:"reason"`
		Code     string             `json:"code"`
		Policy   string             `json:"policy"`
		Error    json.RawMessage    `json:"error"`
		Findings []AuthoringFinding `json:"findings"`
	}
	// A refusal without a JSON body still names its status; a member of an
	// unexpected type leaves the others decoded.
	_ = json.Unmarshal(body, &payload)
	var message string
	if json.Unmarshal(payload.Error, &message) != nil || message == "" {
		message = fmt.Sprintf("HTTP %d from %s", resp.StatusCode, route)
	}
	retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retryAfter < 0 {
		retryAfter = 0
	}
	return &TypedPolicyRefusal{
		Status:     resp.StatusCode,
		Reason:     payload.Reason,
		Code:       payload.Code,
		Policy:     payload.Policy,
		Message:    message,
		Findings:   payload.Findings,
		RetryAfter: retryAfter,
	}
}

// typedPolicyJSON sends one typed policy request and decodes a 2xx answer,
// which must be a JSON object, into out.
func (c *AxonFlowClient) typedPolicyJSON(ctx context.Context, method, route string, payload, out any) error {
	resp, body, err := c.sendTypedPolicy(ctx, method, route, payload)
	if err != nil {
		return err
	}
	if err := typedPolicyError(resp, body, route); err != nil {
		return err
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("%s%s answered %d with a body that is not an object", TypedPoliciesPath, route, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("failed to decode the %s%s answer: %w", TypedPoliciesPath, route, err)
	}
	return nil
}

// TypedPolicyEdition reports what this deployment may author: its construct
// boundary and its document ceiling.
func (c *AxonFlowClient) TypedPolicyEdition(ctx context.Context) (*TypedAuthoringEdition, error) {
	var out TypedAuthoringEdition
	if err := c.typedPolicyJSON(ctx, http.MethodGet, "/edition", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidateTypedPolicy returns every finding for a candidate document, ordered
// and complete. A refused document is still a successful validation: read
// Success and Findings rather than expecting an error. Pass nil fixtures to
// send none.
func (c *AxonFlowClient) ValidateTypedPolicy(ctx context.Context, document map[string]any, fixtures []map[string]any) (*TypedPolicyValidation, error) {
	var out TypedPolicyValidation
	request := TypedAuthoringDocumentRequest{Document: document, Fixtures: fixtures}
	if err := c.typedPolicyJSON(ctx, http.MethodPost, "/validate", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PublishTypedPolicy publishes a document as a signed artifact, pinned by its
// digest. fixtures are the author-declared cases the publication gauntlet runs;
// a publication without any is refused, since no policy in the document has
// then been shown to do anything.
//
// A refusal is a *TypedPolicyRefusal: 422 with the findings
// (publication_refused or document_refused; an edition boundary or
// APPROVER_IS_AUTHOR appears as a finding code), 402 tier_limit, 429
// artifact_cap, or 400 for a malformed request.
func (c *AxonFlowClient) PublishTypedPolicy(ctx context.Context, document map[string]any, fixtures []map[string]any) (*TypedPolicyPublication, error) {
	var out TypedPolicyPublication
	request := TypedAuthoringDocumentRequest{Document: document, Fixtures: fixtures}
	if err := c.typedPolicyJSON(ctx, http.MethodPost, "/publish", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActivateTypedPolicy promotes a published digest to active. The activation is
// audited and names the caller; reason is recorded with it, and an empty reason
// sends none.
//
// A refusal is a *TypedPolicyRefusal with status 409 and reason
// activation_refused when the digest is not admitted, its version does not
// advance, its parent is not the active digest, or the caller may not activate
// it: reload the active version and rebase.
func (c *AxonFlowClient) ActivateTypedPolicy(ctx context.Context, digest, reason string) (*TypedPolicyActivation, error) {
	payload := map[string]string{"digest": digest}
	if reason != "" {
		payload["reason"] = reason
	}
	var out TypedPolicyActivation
	if err := c.typedPolicyJSON(ctx, http.MethodPost, "/activate", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActiveTypedPolicy returns the document in force, or (nil, nil) when nothing
// is active.
//
// (nil, nil) is the platform's own answer: a 404 whose reason is
// nothing_active. Any other 404 is a *TypedPolicyRefusal with Status 404: a
// platform without the typed routes (before v11.0.0), or an endpoint that is
// not an AxonFlow agent, is reported as such rather than as nothing active.
//
// (nil, nil) is only as reliable as that reason: the platform currently also
// answers nothing_active when its document store cannot be read
// (getaxonflow/axonflow-enterprise#4255).
func (c *AxonFlowClient) ActiveTypedPolicy(ctx context.Context) (*ActiveTypedPolicy, error) {
	resp, body, err := c.sendTypedPolicy(ctx, http.MethodGet, "/active", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		var answer struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(body, &answer) == nil && answer.Reason == "nothing_active" {
			return nil, nil
		}
	}
	if err := typedPolicyError(resp, body, "/active"); err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil || document == nil {
		return nil, fmt.Errorf("%s/active answered %d with a body that is not an object", TypedPoliciesPath, resp.StatusCode)
	}
	return &ActiveTypedPolicy{Source: body, Document: document}, nil
}

// TypedPolicySystem returns the platform's own controls, read-only: the shipped
// system corpus.
func (c *AxonFlowClient) TypedPolicySystem(ctx context.Context) (*TypedPolicySystemCorpus, error) {
	var out struct {
		System *TypedPolicySystemCorpus `json:"system"`
	}
	if err := c.typedPolicyJSON(ctx, http.MethodGet, "/system", nil, &out); err != nil {
		return nil, err
	}
	if out.System == nil {
		return &TypedPolicySystemCorpus{}, nil
	}
	return out.System, nil
}
