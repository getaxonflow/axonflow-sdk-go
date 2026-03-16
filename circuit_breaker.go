// Circuit breaker observability methods for AxonFlow SDK.
// These methods allow querying circuit breaker status, history, and configuration.
package axonflow

import (
	"context"
	"fmt"
	"log"
	"net/url"
)

// ============================================================================
// Circuit Breaker Types
// ============================================================================

// CircuitBreakerCircuit represents an active circuit.
type CircuitBreakerCircuit struct {
	ID             string `json:"id"`
	Scope          string `json:"scope"`
	ScopeID        string `json:"scope_id"`
	OrgID          string `json:"org_id"`
	State          string `json:"state"`
	TripReason     string `json:"trip_reason,omitempty"`
	TrippedBy      string `json:"tripped_by,omitempty"`
	TrippedAt      string `json:"tripped_at,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	ErrorCount     int    `json:"error_count"`
	ViolationCount int    `json:"violation_count"`
}

// CircuitBreakerStatusResponse is the response from GET /api/v1/circuit-breaker/status.
type CircuitBreakerStatusResponse struct {
	ActiveCircuits      []CircuitBreakerCircuit `json:"active_circuits"`
	Count               int                     `json:"count"`
	EmergencyStopActive bool                    `json:"emergency_stop_active"`
}

// CircuitBreakerHistoryEntry is a single entry in circuit breaker history.
type CircuitBreakerHistoryEntry struct {
	ID             string `json:"id"`
	OrgID          string `json:"org_id"`
	Scope          string `json:"scope"`
	ScopeID        string `json:"scope_id"`
	State          string `json:"state"`
	TripReason     string `json:"trip_reason,omitempty"`
	TrippedBy      string `json:"tripped_by,omitempty"`
	TrippedByEmail string `json:"tripped_by_email,omitempty"`
	TripComment    string `json:"trip_comment,omitempty"`
	TrippedAt      string `json:"tripped_at,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	ResetBy        string `json:"reset_by,omitempty"`
	ResetAt        string `json:"reset_at,omitempty"`
	ErrorCount     int    `json:"error_count"`
	ViolationCount int    `json:"violation_count"`
}

// CircuitBreakerHistoryResponse is the response from GET /api/v1/circuit-breaker/history.
type CircuitBreakerHistoryResponse struct {
	History []CircuitBreakerHistoryEntry `json:"history"`
	Count   int                          `json:"count"`
}

// CircuitBreakerConfig represents effective circuit breaker configuration.
type CircuitBreakerConfig struct {
	Source                string                 `json:"source"`
	ErrorThreshold        int                    `json:"error_threshold"`
	ViolationThreshold    int                    `json:"violation_threshold"`
	WindowSeconds         int                    `json:"window_seconds"`
	DefaultTimeoutSeconds int                    `json:"default_timeout_seconds"`
	MaxTimeoutSeconds     int                    `json:"max_timeout_seconds"`
	EnableAutoRecovery    bool                   `json:"enable_auto_recovery"`
	TenantID              string                 `json:"tenant_id,omitempty"`
	Overrides             map[string]interface{} `json:"overrides,omitempty"`
}

// CircuitBreakerConfigUpdate is the request to update per-tenant config.
type CircuitBreakerConfigUpdate struct {
	TenantID              string `json:"tenant_id"`
	ErrorThreshold        *int   `json:"error_threshold,omitempty"`
	ViolationThreshold    *int   `json:"violation_threshold,omitempty"`
	WindowSeconds         *int   `json:"window_seconds,omitempty"`
	DefaultTimeoutSeconds *int   `json:"default_timeout_seconds,omitempty"`
	MaxTimeoutSeconds     *int   `json:"max_timeout_seconds,omitempty"`
	EnableAutoRecovery    *bool  `json:"enable_auto_recovery,omitempty"`
}

// circuitBreakerDataWrapper wraps the API response which nests data under "data" key.
type circuitBreakerDataWrapper[T any] struct {
	Success bool `json:"success"`
	Data    T    `json:"data"`
}

// ============================================================================
// Circuit Breaker Methods
// ============================================================================

// GetCircuitBreakerStatus returns all active circuit breaker circuits.
//
// This method queries the AxonFlow orchestrator for the current state of all
// circuit breakers, including whether any emergency stop is active.
//
// Example:
//
//	status, err := client.GetCircuitBreakerStatus(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Active circuits: %d, Emergency stop: %v\n",
//	    status.Count, status.EmergencyStopActive)
//	for _, circuit := range status.ActiveCircuits {
//	    fmt.Printf("  [%s] %s/%s - %s\n",
//	        circuit.State, circuit.Scope, circuit.ScopeID, circuit.TripReason)
//	}
func (c *AxonFlowClient) GetCircuitBreakerStatus(ctx context.Context) (*CircuitBreakerStatusResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/circuit-breaker/status"

	var wrapper circuitBreakerDataWrapper[CircuitBreakerStatusResponse]
	if err := c.makeJSONRequest(ctx, "GET", fullURL, nil, &wrapper); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Circuit breaker status: %d active circuits", wrapper.Data.Count)
	}

	return &wrapper.Data, nil
}

// GetCircuitBreakerHistory returns circuit breaker history for audit trail.
//
// Use limit to control how many entries to return. Pass 0 or a negative value
// to use the server default.
//
// Example:
//
//	history, err := client.GetCircuitBreakerHistory(ctx, 50)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, entry := range history.History {
//	    fmt.Printf("[%s] %s/%s tripped by %s: %s\n",
//	        entry.TrippedAt, entry.Scope, entry.ScopeID,
//	        entry.TrippedBy, entry.TripReason)
//	}
func (c *AxonFlowClient) GetCircuitBreakerHistory(ctx context.Context, limit int) (*CircuitBreakerHistoryResponse, error) {
	fullURL := c.config.Endpoint + "/api/v1/circuit-breaker/history"
	if limit > 0 {
		fullURL = fmt.Sprintf("%s?limit=%d", fullURL, limit)
	}

	var wrapper circuitBreakerDataWrapper[CircuitBreakerHistoryResponse]
	if err := c.makeJSONRequest(ctx, "GET", fullURL, nil, &wrapper); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Circuit breaker history: %d entries", wrapper.Data.Count)
	}

	return &wrapper.Data, nil
}

// GetCircuitBreakerConfig returns circuit breaker config (global or tenant-specific).
//
// Pass an empty tenantID to get the global configuration. Pass a specific
// tenantID to get tenant-level overrides.
//
// Example:
//
//	// Global config
//	config, err := client.GetCircuitBreakerConfig(ctx, "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Error threshold: %d, Window: %ds\n",
//	    config.ErrorThreshold, config.WindowSeconds)
//
//	// Tenant-specific config
//	config, err = client.GetCircuitBreakerConfig(ctx, "tenant-abc")
func (c *AxonFlowClient) GetCircuitBreakerConfig(ctx context.Context, tenantID string) (*CircuitBreakerConfig, error) {
	fullURL := c.config.Endpoint + "/api/v1/circuit-breaker/config"
	if tenantID != "" {
		fullURL = fmt.Sprintf("%s?tenant_id=%s", fullURL, url.QueryEscape(tenantID))
	}

	var wrapper circuitBreakerDataWrapper[CircuitBreakerConfig]
	if err := c.makeJSONRequest(ctx, "GET", fullURL, nil, &wrapper); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Circuit breaker config (source: %s)", wrapper.Data.Source)
	}

	return &wrapper.Data, nil
}

// UpdateCircuitBreakerConfig updates per-tenant circuit breaker config.
//
// TenantID is required. Only the fields that are non-nil will be updated;
// omitted fields retain their current values.
//
// Example:
//
//	threshold := 10
//	window := 300
//	updated, err := client.UpdateCircuitBreakerConfig(ctx, axonflow.CircuitBreakerConfigUpdate{
//	    TenantID:       "tenant-abc",
//	    ErrorThreshold: &threshold,
//	    WindowSeconds:  &window,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Updated config (source: %s)\n", updated.Source)
func (c *AxonFlowClient) UpdateCircuitBreakerConfig(ctx context.Context, config CircuitBreakerConfigUpdate) (*CircuitBreakerConfig, error) {
	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	fullURL := c.config.Endpoint + "/api/v1/circuit-breaker/config"

	var wrapper circuitBreakerDataWrapper[CircuitBreakerConfig]
	if err := c.makeJSONRequest(ctx, "PUT", fullURL, config, &wrapper); err != nil {
		return nil, err
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Updated circuit breaker config for tenant %s", config.TenantID)
	}

	return &wrapper.Data, nil
}
