// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package axonflow

import (
	"context"
	"fmt"
)

// ============================================================================
// Webhook CRUD Types (Feature 7)
// ============================================================================

// CreateWebhookRequest is the request to create a new webhook subscription.
type CreateWebhookRequest struct {
	// URL is the endpoint to deliver webhook events to (required)
	URL string `json:"url"`

	// Events is the list of event types to subscribe to (required)
	Events []string `json:"events"`

	// Secret is an optional shared secret for HMAC signature verification
	Secret string `json:"secret,omitempty"`

	// Active indicates whether the webhook is active
	Active bool `json:"active"`
}

// WebhookSubscription represents a webhook subscription.
type WebhookSubscription struct {
	// ID is the unique identifier for the webhook
	ID string `json:"id"`

	// URL is the endpoint receiving webhook events
	URL string `json:"url"`

	// Events is the list of subscribed event types
	Events []string `json:"events"`

	// Active indicates whether the webhook is active
	Active bool `json:"active"`

	// TenantID is the tenant that owns this subscription.
	TenantID string `json:"tenant_id,omitempty"`

	// OrgID is the organization that owns this subscription.
	OrgID string `json:"org_id,omitempty"`

	// Secret is the HMAC-SHA256 signing key for verifying inbound
	// webhook payload signatures (X-AxonFlow-Signature header).
	// Returned by CreateWebhook on initial creation; required for
	// callers to validate payload authenticity.
	Secret string `json:"secret,omitempty"`

	// CreatedAt is when the webhook was created
	CreatedAt string `json:"created_at"`

	// UpdatedAt is when the webhook was last updated
	UpdatedAt string `json:"updated_at"`
}

// UpdateWebhookRequest is the request to update an existing webhook subscription.
type UpdateWebhookRequest struct {
	// URL is the new endpoint URL (optional)
	URL string `json:"url,omitempty"`

	// Events is the new list of event types (optional)
	Events []string `json:"events,omitempty"`

	// Active is the new active status (optional, use pointer to distinguish from zero value)
	Active *bool `json:"active,omitempty"`
}

// ListWebhooksResponse is the response from listing webhook subscriptions.
type ListWebhooksResponse struct {
	// Webhooks is the list of webhook subscriptions
	Webhooks []WebhookSubscription `json:"webhooks"`

	// Total is the total count of webhooks
	Total int `json:"total"`
}

// ============================================================================
// Webhook CRUD Methods (Feature 7)
// ============================================================================

// CreateWebhook creates a new webhook subscription.
//
// Example:
//
//	webhook, err := client.CreateWebhook(CreateWebhookRequest{
//	    URL:    "https://example.com/webhooks",
//	    Events: []string{"workflow.completed", "step.approval_required"},
//	    Active: true,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Webhook created: %s\n", webhook.ID)
func (c *AxonFlowClient) CreateWebhook(req CreateWebhookRequest) (*WebhookSubscription, error) {
	fullURL := c.config.Endpoint + "/api/v1/webhooks"
	var result WebhookSubscription

	if err := c.makeJSONRequest(context.Background(), "POST", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to create webhook: %w", err)
	}

	return &result, nil
}

// GetWebhook retrieves a webhook subscription by ID.
//
// Example:
//
//	webhook, err := client.GetWebhook("wh_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Webhook %s: %s (active: %v)\n", webhook.ID, webhook.URL, webhook.Active)
func (c *AxonFlowClient) GetWebhook(webhookID string) (*WebhookSubscription, error) {
	if webhookID == "" {
		return nil, fmt.Errorf("webhook ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/webhooks/%s", c.config.Endpoint, webhookID)
	var result WebhookSubscription

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get webhook: %w", err)
	}

	return &result, nil
}

// UpdateWebhook updates an existing webhook subscription.
//
// Example:
//
//	active := false
//	webhook, err := client.UpdateWebhook("wh_123", UpdateWebhookRequest{
//	    Active: &active,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Webhook updated: %s (active: %v)\n", webhook.ID, webhook.Active)
func (c *AxonFlowClient) UpdateWebhook(webhookID string, req UpdateWebhookRequest) (*WebhookSubscription, error) {
	if webhookID == "" {
		return nil, fmt.Errorf("webhook ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/webhooks/%s", c.config.Endpoint, webhookID)
	var result WebhookSubscription

	if err := c.makeJSONRequest(context.Background(), "PUT", fullURL, req, &result); err != nil {
		return nil, fmt.Errorf("failed to update webhook: %w", err)
	}

	return &result, nil
}

// DeleteWebhook deletes a webhook subscription.
//
// Example:
//
//	err := client.DeleteWebhook("wh_123")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *AxonFlowClient) DeleteWebhook(webhookID string) error {
	if webhookID == "" {
		return fmt.Errorf("webhook ID is required")
	}

	fullURL := fmt.Sprintf("%s/api/v1/webhooks/%s", c.config.Endpoint, webhookID)

	if err := c.makeJSONRequest(context.Background(), "DELETE", fullURL, nil, nil); err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}

	return nil
}

// ListWebhooks lists all webhook subscriptions.
//
// Example:
//
//	result, err := client.ListWebhooks()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d webhooks\n", result.Total)
//	for _, wh := range result.Webhooks {
//	    fmt.Printf("  %s: %s (active: %v)\n", wh.ID, wh.URL, wh.Active)
//	}
func (c *AxonFlowClient) ListWebhooks() (*ListWebhooksResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/webhooks"
	var result ListWebhooksResponse

	if err := c.makeJSONRequest(context.Background(), "GET", fullURL, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to list webhooks: %w", err)
	}

	return &result, nil
}
