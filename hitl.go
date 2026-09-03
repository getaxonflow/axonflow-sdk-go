// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package axonflow

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// ============================================================================
// HITL (Human-in-the-Loop) Queue Types
// ============================================================================

// HITLApprovalRequest represents a human approval request in the HITL queue.
type HITLApprovalRequest struct {
	// RequestID is the unique identifier for the approval request
	RequestID string `json:"request_id"`

	// OrgID is the organization ID
	OrgID string `json:"org_id"`

	// TenantID is the tenant ID
	TenantID string `json:"tenant_id"`

	// ClientID is the client ID that triggered the request
	ClientID string `json:"client_id"`

	// UserID is the user who triggered the request (optional)
	UserID string `json:"user_id,omitempty"`

	// OriginalQuery is the original query that triggered the approval request
	OriginalQuery string `json:"original_query"`

	// RequestType is the type of the original request
	RequestType string `json:"request_type"`

	// RequestContext contains additional context for the request (optional)
	RequestContext map[string]interface{} `json:"request_context,omitempty"`

	// TriggeredPolicyID is the ID of the policy that triggered the approval
	TriggeredPolicyID string `json:"triggered_policy_id"`

	// TriggeredPolicyName is the name of the policy that triggered the approval
	TriggeredPolicyName string `json:"triggered_policy_name"`

	// TriggerReason explains why the approval was triggered
	TriggerReason string `json:"trigger_reason"`

	// Severity is the severity level of the request
	Severity string `json:"severity"`

	// EUAIActArticle is the relevant EU AI Act article (optional)
	EUAIActArticle string `json:"eu_ai_act_article,omitempty"`

	// ComplianceFramework is the compliance framework that applies (optional)
	ComplianceFramework string `json:"compliance_framework,omitempty"`

	// RiskClassification is the risk classification level (optional)
	RiskClassification string `json:"risk_classification,omitempty"`

	// Status is the current status of the approval request
	Status string `json:"status"`

	// ReviewerID is the ID of the reviewer (optional, set after review)
	ReviewerID string `json:"reviewer_id,omitempty"`

	// ReviewerEmail is the email of the reviewer (optional, set after review)
	ReviewerEmail string `json:"reviewer_email,omitempty"`

	// ReviewComment is the reviewer's comment (optional, set after review)
	ReviewComment string `json:"review_comment,omitempty"`

	// ReviewedAt is when the request was reviewed (optional, set after review)
	ReviewedAt *string `json:"reviewed_at,omitempty"`

	// NotifyURL is the optional outbound webhook URL associated with the
	// request. Mirrors the value supplied on creation. Platforms that
	// implement the outbound-webhook dispatcher (introduced in
	// getaxonflow/axonflow-enterprise#2419) fire a signed POST to this URL
	// after the request reaches a terminal state
	// (approved/rejected/expired/overridden). Platforms that don't, simply
	// round-trip the field. Enables webhook-driven resume (n8n Wait-node,
	// ADK plugin polling-free mode).
	NotifyURL string `json:"notify_url,omitempty"`

	// ExpiresAt is when the approval request expires
	ExpiresAt string `json:"expires_at"`

	// CreatedAt is when the approval request was created
	CreatedAt string `json:"created_at"`

	// UpdatedAt is when the approval request was last updated
	UpdatedAt string `json:"updated_at"`
}

// HITLQueueListOptions configures the list query for the HITL queue.
type HITLQueueListOptions struct {
	// Status filters by status (comma-separated, e.g., "pending,approved")
	Status string `json:"status,omitempty"`

	// Severity filters by severity (comma-separated, e.g., "high,critical")
	Severity string `json:"severity,omitempty"`

	// Limit is the maximum number of results to return
	Limit int `json:"limit,omitempty"`

	// Offset is the offset for pagination
	Offset int `json:"offset,omitempty"`
}

// HITLQueueListResponse is the response from listing the HITL queue.
type HITLQueueListResponse struct {
	// Items is the list of approval requests
	Items []HITLApprovalRequest `json:"items"`

	// Total is the total count of matching requests
	Total int64 `json:"total"`

	// HasMore indicates whether there are more results beyond this page
	HasMore bool `json:"has_more"`
}

// HITLCreateInput is the input for creating a HITL approval request.
//
// Mirrors platform/agent/hitl/handler.go:86 CreateRequestInput. The
// platform's POST /api/v1/hitl/queue handler reads X-Org-ID and
// X-Tenant-ID from request headers (set by the auth middleware from
// the SDK client's credentials), and the JSON body must carry the
// fields below.
//
// Used by agent-framework callers that detect require_approval from
// pre_check / check_tool_input and want to enqueue the corresponding
// HITL row before polling the reviewer's decision (or pivoting to
// webhook-driven resume via NotifyURL).
type HITLCreateInput struct {
	// ClientID is the client identifier that triggered the request. Required.
	ClientID string `json:"client_id"`

	// UserID is the end-user identifier. Optional.
	UserID string `json:"user_id,omitempty"`

	// OriginalQuery is the original query that triggered the gate. Required.
	OriginalQuery string `json:"original_query"`

	// RequestType is the request type ("chat", "tool", "mcp", ...). Required.
	RequestType string `json:"request_type"`

	// RequestContext is additional context propagated from the gated call.
	RequestContext map[string]interface{} `json:"request_context,omitempty"`

	// TriggeredPolicyID is the ID of the policy that fired require_approval.
	TriggeredPolicyID string `json:"triggered_policy_id,omitempty"`

	// TriggeredPolicyName is the display name of the firing policy.
	TriggeredPolicyName string `json:"triggered_policy_name,omitempty"`

	// TriggerReason is a human-readable explanation of why approval is needed.
	TriggerReason string `json:"trigger_reason,omitempty"`

	// Severity is the severity level ("critical" | "high" | "medium" | "low").
	// Defaults to "high" server-side when empty.
	Severity string `json:"severity,omitempty"`

	// NotifyURL is the optional outbound webhook URL fired async after
	// terminal state transition (approved/rejected/expired/overridden).
	// Must be https:// (or http:// for self-hosted local-dev).
	// Server-side validation rejects bad schemes with HTTP 400. Pair
	// with the HMAC-SHA256 X-AxonFlow-Signature header on the receiver
	// side; signing key is the deployment-configured
	// AXONFLOW_HITL_WEBHOOK_SIGNING_KEY. Introduced in
	// getaxonflow/axonflow-enterprise#2419.
	NotifyURL string `json:"notify_url,omitempty"`

	// EUAIActArticle is the EU AI Act article reference (e.g. "Article 14").
	EUAIActArticle string `json:"eu_ai_act_article,omitempty"`

	// ComplianceFramework is the compliance framework label
	// (GDPR / HIPAA / RBI / ...).
	ComplianceFramework string `json:"compliance_framework,omitempty"`

	// RiskClassification is the risk classification level.
	RiskClassification string `json:"risk_classification,omitempty"`

	// ExpiresInSeconds optionally overrides the approval expiry window.
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
}

// HITLReviewInput is the input for approving or rejecting an HITL request.
type HITLReviewInput struct {
	// ReviewerID is the ID of the reviewer (required)
	ReviewerID string `json:"reviewer_id"`

	// ReviewerEmail is the email of the reviewer (required)
	ReviewerEmail string `json:"reviewer_email"`

	// ReviewerRole is the role of the reviewer (optional)
	ReviewerRole string `json:"reviewer_role,omitempty"`

	// Comment is the reviewer's comment (optional)
	Comment string `json:"comment,omitempty"`
}

// HITLStats contains dashboard statistics for the HITL queue.
type HITLStats struct {
	// TotalPending is the total number of pending approval requests
	TotalPending int64 `json:"total_pending"`

	// HighPriority is the number of high-priority pending requests
	HighPriority int64 `json:"high_priority"`

	// CriticalPriority is the number of critical-priority pending requests
	CriticalPriority int64 `json:"critical_priority"`

	// OldestPendingHours is the age in hours of the oldest pending request (optional)
	OldestPendingHours *float64 `json:"oldest_pending_hours,omitempty"`
}

// ============================================================================
// Enterprise response envelope types (internal)
// ============================================================================

// hitlListEnvelope is the enterprise API response envelope for list endpoints.
type hitlListEnvelope struct {
	Success bool                  `json:"success"`
	Data    []HITLApprovalRequest `json:"data"`
	Meta    struct {
		Total  int64 `json:"total"`
		Limit  int   `json:"limit"`
		Offset int   `json:"offset"`
	} `json:"meta"`
}

// hitlItemEnvelope is the enterprise API response envelope for single-item endpoints.
type hitlItemEnvelope struct {
	Success bool                `json:"success"`
	Data    HITLApprovalRequest `json:"data"`
}

// hitlStatsEnvelope is the enterprise API response envelope for stats endpoints.
type hitlStatsEnvelope struct {
	Success bool      `json:"success"`
	Data    HITLStats `json:"data"`
}

// hitlActionEnvelope is the enterprise API response envelope for action endpoints.
type hitlActionEnvelope struct {
	Success bool `json:"success"`
}

// ============================================================================
// HITL Queue Methods
// ============================================================================

// ListHITLQueue lists approval requests in the HITL queue.
//
// Use this to retrieve pending (or filtered) approval requests for the
// human-in-the-loop review dashboard.
//
// Example:
//
//	result, err := client.ListHITLQueue(axonflow.HITLQueueListOptions{
//	    Status:   "pending",
//	    Severity: "high,critical",
//	    Limit:    20,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d items (total: %d)\n", len(result.Items), result.Total)
func (c *AxonFlowClient) ListHITLQueue(opts HITLQueueListOptions) (*HITLQueueListResponse, error) {
	params := url.Values{}

	if opts.Status != "" {
		params.Set("status", opts.Status)
	}
	if opts.Severity != "" {
		params.Set("severity", opts.Severity)
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		params.Set("offset", strconv.Itoa(opts.Offset))
	}

	fullURL := c.config.Endpoint + "/api/v1/hitl/queue"
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var envelope hitlListEnvelope
	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &envelope); err != nil {
		return nil, fmt.Errorf("failed to list HITL queue: %w", err)
	}

	items := envelope.Data
	if items == nil {
		items = []HITLApprovalRequest{}
	}

	result := &HITLQueueListResponse{
		Items:   items,
		Total:   envelope.Meta.Total,
		HasMore: (int64(envelope.Meta.Offset) + int64(len(items))) < envelope.Meta.Total,
	}

	return result, nil
}

// GetHITLRequest retrieves a specific HITL approval request by ID.
//
// Example:
//
//	request, err := client.GetHITLRequest("req_abc123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Request %s: %s (severity: %s)\n",
//	    request.RequestID, request.Status, request.Severity)
func (c *AxonFlowClient) GetHITLRequest(requestID string) (*HITLApprovalRequest, error) {
	if requestID == "" {
		return nil, fmt.Errorf("request ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/hitl/queue/%s", c.config.Endpoint, requestID)

	var envelope hitlItemEnvelope
	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &envelope); err != nil {
		return nil, fmt.Errorf("failed to get HITL request: %w", err)
	}

	return &envelope.Data, nil
}

// CreateHITLRequest creates a new HITL approval request via
// POST /api/v1/hitl/queue.
//
// Enterprise Feature: Requires AxonFlow Enterprise license. The platform
// returns 403 with ErrHITLApprovalDisabledByTier when called against a
// community tier that hasn't enabled HITL, and 401 when credentials are
// invalid.
//
// This is the explicit row-creation step for callers that detect
// require_approval from a separate gate (pre_check, check_tool_input,
// MAP plan approvals) and want the row enqueued so a reviewer can act
// on it. After creating, either poll GetHITLRequest(returned.RequestID)
// until terminal state, or pass NotifyURL so the platform fires a
// signed webhook on the transition (n8n Wait-node "On Webhook Call"
// pattern, ADK plugin polling-free mode).
//
// ClientID, OriginalQuery, and RequestType are required; all other
// fields are optional. Bad NotifyURL schemes are rejected by the
// platform with HTTP 400 (surfaced here as a wrapped error); only
// https:// (and http:// for self-hosted local-dev) are accepted.
//
// Example:
//
//	req, err := client.CreateHITLRequest(axonflow.HITLCreateInput{
//	    ClientID:            "loan-desk",
//	    OriginalQuery:       "disburse $50000 to cust-001",
//	    RequestType:         "adk-tool",
//	    TriggeredPolicyID:   "loan-amount-cap",
//	    TriggeredPolicyName: "Loan amount cap",
//	    TriggerReason:       "Disbursement above $10k requires manager approval",
//	    Severity:            "high",
//	    NotifyURL:           "https://workflows.example.com/hooks/loan-approve",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Created HITL approval %s\n", req.RequestID)
func (c *AxonFlowClient) CreateHITLRequest(input HITLCreateInput) (*HITLApprovalRequest, error) {
	if input.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if input.OriginalQuery == "" {
		return nil, fmt.Errorf("original_query is required")
	}
	if input.RequestType == "" {
		return nil, fmt.Errorf("request_type is required")
	}

	fullURL := c.config.Endpoint + "/api/v1/hitl/queue"

	var envelope hitlItemEnvelope
	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, input, &envelope); err != nil {
		return nil, fmt.Errorf("failed to create HITL request: %w", err)
	}

	return &envelope.Data, nil
}

// ApproveHITLRequest approves a pending HITL approval request.
//
// The review input must include the reviewer's ID and email for audit tracking.
//
// Example:
//
//	err := client.ApproveHITLRequest("req_abc123", axonflow.HITLReviewInput{
//	    ReviewerID:    "user_reviewer1",
//	    ReviewerEmail: "reviewer@example.com",
//	    Comment:       "Approved after manual review",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) ApproveHITLRequest(requestID string, review HITLReviewInput) error {
	if requestID == "" {
		return fmt.Errorf("request ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/hitl/queue/%s/approve", c.config.Endpoint, requestID)

	var envelope hitlActionEnvelope
	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, review, &envelope); err != nil {
		return fmt.Errorf("failed to approve HITL request: %w", err)
	}

	return nil
}

// RejectHITLRequest rejects a pending HITL approval request.
//
// The review input must include the reviewer's ID and email for audit tracking.
//
// Example:
//
//	err := client.RejectHITLRequest("req_abc123", axonflow.HITLReviewInput{
//	    ReviewerID:    "user_reviewer1",
//	    ReviewerEmail: "reviewer@example.com",
//	    Comment:       "Rejected: query violates compliance policy",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) RejectHITLRequest(requestID string, review HITLReviewInput) error {
	if requestID == "" {
		return fmt.Errorf("request ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/hitl/queue/%s/reject", c.config.Endpoint, requestID)

	var envelope hitlActionEnvelope
	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, review, &envelope); err != nil {
		return fmt.Errorf("failed to reject HITL request: %w", err)
	}

	return nil
}

// GetHITLStats retrieves dashboard statistics for the HITL queue.
//
// Example:
//
//	stats, err := client.GetHITLStats()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Pending: %d, High: %d, Critical: %d\n",
//	    stats.TotalPending, stats.HighPriority, stats.CriticalPriority)
func (c *AxonFlowClient) GetHITLStats() (*HITLStats, error) {
	fullURL := c.config.Endpoint + "/api/v1/hitl/stats"

	var envelope hitlStatsEnvelope
	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &envelope); err != nil {
		return nil, fmt.Errorf("failed to get HITL stats: %w", err)
	}

	return &envelope.Data, nil
}
