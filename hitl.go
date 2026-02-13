// Copyright 2026 AxonFlow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
