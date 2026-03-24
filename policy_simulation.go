// Policy simulation methods for AxonFlow SDK.
// These methods allow dry-run policy evaluation, impact analysis, and conflict detection.
// Requires Evaluation tier or above.
package axonflow

import (
	"context"
	"log"
	"time"
)

// ============================================================================
// Policy Simulation Types
// ============================================================================

// SimulatePoliciesRequest is the request for POST /api/v1/policies/simulate.
type SimulatePoliciesRequest struct {
	// Query is the input text to simulate policy evaluation against.
	Query string `json:"query"`
	// RequestType optionally specifies the type of request (e.g., "llm_chat", "sql").
	RequestType string `json:"request_type,omitempty"`
	// User provides user attributes for policy evaluation context.
	User map[string]interface{} `json:"user,omitempty"`
	// Client provides client/application attributes for policy evaluation context.
	Client map[string]interface{} `json:"client,omitempty"`
	// Context provides additional context for policy evaluation.
	Context map[string]interface{} `json:"context,omitempty"`
}

// SimulationDailyUsage tracks simulation rate limit usage.
type SimulationDailyUsage struct {
	Used  int `json:"used"`
	Limit int `json:"limit"`
}

// SimulatePoliciesResponse is the response from POST /api/v1/policies/simulate.
type SimulatePoliciesResponse struct {
	Allowed          bool                  `json:"allowed"`
	AppliedPolicies  []string              `json:"applied_policies"`
	RiskScore        float64               `json:"risk_score"`
	RequiredActions  []string              `json:"required_actions"`
	ProcessingTimeMs int64                 `json:"processing_time_ms"`
	TotalPolicies    int                   `json:"total_policies"`
	DryRun           bool                  `json:"dry_run"`
	SimulatedAt      time.Time             `json:"simulated_at"`
	Tier             string                `json:"tier"`
	DailyUsage       *SimulationDailyUsage `json:"daily_usage,omitempty"`
}

// ImpactReportInput is a single test input for policy impact analysis.
type ImpactReportInput struct {
	// Query is the input text to evaluate against the target policy.
	Query string `json:"query"`
	// RequestType optionally specifies the type of request.
	RequestType string `json:"request_type,omitempty"`
	// User provides user attributes for evaluation context.
	User map[string]interface{} `json:"user,omitempty"`
	// Context provides additional context for evaluation.
	Context map[string]interface{} `json:"context,omitempty"`
}

// ImpactReportRequest is the request for POST /api/v1/policies/impact-report.
type ImpactReportRequest struct {
	// PolicyID is the ID of the policy to test.
	PolicyID string `json:"policy_id"`
	// Inputs is the list of test inputs to evaluate against the policy.
	Inputs []ImpactReportInput `json:"inputs"`
}

// ImpactReportResult is the evaluation result for a single input.
type ImpactReportResult struct {
	InputIndex int      `json:"input_index"`
	Matched    bool     `json:"matched"`
	Blocked    bool     `json:"blocked"`
	Actions    []string `json:"actions,omitempty"`
}

// ImpactReportResponse is the response from POST /api/v1/policies/impact-report.
type ImpactReportResponse struct {
	PolicyID         string               `json:"policy_id"`
	PolicyName       string               `json:"policy_name,omitempty"`
	TotalInputs      int                  `json:"total_inputs"`
	Matched          int                  `json:"matched"`
	Blocked          int                  `json:"blocked"`
	MatchRate        float64              `json:"match_rate"`
	BlockRate        float64              `json:"block_rate"`
	Results          []ImpactReportResult `json:"results"`
	ProcessingTimeMs int64                `json:"processing_time_ms"`
	GeneratedAt      time.Time            `json:"generated_at"`
	Tier             string               `json:"tier"`
}

// PolicyConflictRef identifies a policy involved in a conflict.
type PolicyConflictRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// PolicyConflict describes a conflict between two policies.
type PolicyConflict struct {
	PolicyA          PolicyConflictRef `json:"policy_a"`
	PolicyB          PolicyConflictRef `json:"policy_b"`
	ConflictType     string            `json:"conflict_type"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	OverlappingField string            `json:"overlapping_field"`
}

// policyConflictRequestBody is the internal request body for POST /api/v1/policies/conflicts.
type policyConflictRequestBody struct {
	PolicyID string `json:"policy_id,omitempty"`
}

// PolicyConflictResponse is the response from POST /api/v1/policies/conflicts.
type PolicyConflictResponse struct {
	Conflicts     []PolicyConflict `json:"conflicts"`
	TotalPolicies int              `json:"total_policies"`
	ConflictCount int              `json:"conflict_count"`
	CheckedAt     time.Time        `json:"checked_at"`
	Tier          string           `json:"tier"`
}

// ============================================================================
// Policy Simulation Methods
// ============================================================================

// SimulatePolicies runs all active policies against the provided input as a dry run.
// No actual enforcement occurs. Requires Evaluation tier or above.
//
// Example:
//
//	result, err := client.SimulatePolicies(ctx, &axonflow.SimulatePoliciesRequest{
//	    Query:       "SELECT * FROM users WHERE ssn = '123-45-6789'",
//	    RequestType: "sql",
//	    User: map[string]interface{}{"role": "analyst"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Allowed: %v, Risk: %.2f, Policies: %d\n",
//	    result.Allowed, result.RiskScore, result.TotalPolicies)
func (c *AxonFlowClient) SimulatePolicies(ctx context.Context, req *SimulatePoliciesRequest) (*SimulatePoliciesResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/policies/simulate"

	var resp SimulatePoliciesResponse
	if err := c.makeJSONRequest(ctx, "POST", fullURL, req, &resp); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Policy simulation: allowed=%v, risk=%.2f, policies=%d",
			resp.Allowed, resp.RiskScore, resp.TotalPolicies)
	}

	return &resp, nil
}

// GetPolicyImpactReport tests a single policy against multiple inputs to assess
// its match and block rates. Requires Evaluation tier or above.
//
// Example:
//
//	report, err := client.GetPolicyImpactReport(ctx, &axonflow.ImpactReportRequest{
//	    PolicyID: "policy-123",
//	    Inputs: []axonflow.ImpactReportInput{
//	        {Query: "harmless query"},
//	        {Query: "DROP TABLE users;", RequestType: "sql"},
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Match rate: %.1f%%, Block rate: %.1f%%\n",
//	    report.MatchRate*100, report.BlockRate*100)
func (c *AxonFlowClient) GetPolicyImpactReport(ctx context.Context, req *ImpactReportRequest) (*ImpactReportResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/policies/impact-report"

	var resp ImpactReportResponse
	if err := c.makeJSONRequest(ctx, "POST", fullURL, req, &resp); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Policy impact report: policy=%s, match_rate=%.2f, block_rate=%.2f",
			resp.PolicyID, resp.MatchRate, resp.BlockRate)
	}

	return &resp, nil
}

// DetectPolicyConflicts finds conflicts between active policies. Pass an empty
// policyID to check all policies against each other. Pass a specific policyID
// to check only conflicts involving that policy. Requires Evaluation tier or above.
//
// Example:
//
//	// Check all policies
//	conflicts, err := client.DetectPolicyConflicts(ctx, "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d conflicts among %d policies\n",
//	    conflicts.ConflictCount, conflicts.TotalPolicies)
//
//	// Check specific policy
//	conflicts, err = client.DetectPolicyConflicts(ctx, "policy-123")
func (c *AxonFlowClient) DetectPolicyConflicts(ctx context.Context, policyID string) (*PolicyConflictResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/policies/conflicts"

	body := &policyConflictRequestBody{}
	if policyID != "" {
		body.PolicyID = policyID
	}

	var resp PolicyConflictResponse
	if err := c.makeJSONRequest(ctx, "POST", fullURL, body, &resp); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Policy conflict detection: %d conflicts among %d policies",
			resp.ConflictCount, resp.TotalPolicies)
	}

	return &resp, nil
}
