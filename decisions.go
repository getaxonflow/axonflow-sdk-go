// Decision explainability methods for AxonFlow SDK.
// Implements the contract locked in ADR-043 (Explainability Data Contract).
package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ============================================================================
// Types (ADR-043 — frozen shape)
// ============================================================================

// DecisionExplanation is the canonical payload returned by Decisions.Explain.
// Shape is frozen per ADR-043; additive fields may be added with omitempty,
// renames/removals require a major version bump.
type DecisionExplanation struct {
	DecisionID                string          `json:"decision_id"`
	Timestamp                 time.Time       `json:"timestamp"`
	PolicyMatches             []ExplainPolicy `json:"policy_matches"`
	MatchedRules              []ExplainRule   `json:"matched_rules,omitempty"`
	Decision                  string          `json:"decision"` // "allow"|"deny"|"require_approval"
	Reason                    string          `json:"reason"`
	RiskLevel                 string          `json:"risk_level,omitempty"`
	OverrideAvailable         bool            `json:"override_available"`
	OverrideExistingID        string          `json:"override_existing_id,omitempty"`
	HistoricalHitCountSession int             `json:"historical_hit_count_session"`
	PolicySourceLink          string          `json:"policy_source_link,omitempty"`
	ToolSignature             string          `json:"tool_signature,omitempty"`
}

// ExplainPolicy is a policy reference inside an explanation.
type ExplainPolicy struct {
	PolicyID          string `json:"policy_id"`
	PolicyName        string `json:"policy_name,omitempty"`
	Action            string `json:"action,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`
	AllowOverride     bool   `json:"allow_override,omitempty"`
	PolicyDescription string `json:"policy_description,omitempty"`
}

// ExplainRule is rule-level detail inside an explanation.
type ExplainRule struct {
	PolicyID  string `json:"policy_id"`
	RuleID    string `json:"rule_id,omitempty"`
	RuleText  string `json:"rule_text,omitempty"`
	MatchedOn string `json:"matched_on,omitempty"`
}

// ============================================================================
// Methods
// ============================================================================

// ExplainDecision fetches the full explanation for a previously-made
// policy decision. The caller must either own the decision (user_email
// match) or belong to the same tenant. Returns a 404-equivalent error
// when the decision is past retention.
//
// Context cancellation is honored; the underlying HTTP request is bound
// to the given ctx.
//
// Example:
//
//	exp, err := client.ExplainDecision(ctx, "dec_wf123_step4")
//	if err != nil { return err }
//	if exp.OverrideAvailable {
//	    // offer the user a "override this for 10 minutes" action
//	}
func (c *AxonFlowClient) ExplainDecision(ctx context.Context, decisionID string) (*DecisionExplanation, error) {
	if decisionID == "" {
		return nil, fmt.Errorf("decisionID is required")
	}

	// Path-escape the decision ID — platform-generated IDs are usually
	// filesystem-safe, but nothing in ADR-043 guarantees it, and IDs that
	// contain "/" or "?" would break the URL otherwise.
	fullURL := c.config.Endpoint + "/api/v1/decisions/" + url.PathEscape(decisionID) + "/explain"

	httpReq, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build explain request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/json")
	c.addAuthHeaders(httpReq)

	resp, err := c.doHttpRequest(c.httpClient, httpReq)
	if err != nil {
		return nil, fmt.Errorf("explain request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read explain response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var out DecisionExplanation
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to decode explain response: %w", err)
	}
	return &out, nil
}
