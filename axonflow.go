// Package axonflow provides an enterprise-grade Go SDK for the AxonFlow AI governance platform.
// It enables invisible AI governance with production-ready features including retry logic,
// caching, fail-open strategy, and debug mode.
package axonflow

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AxonFlowConfig represents configuration for the AxonFlow client
type AxonFlowConfig struct {
	Endpoint              string        // Required: AxonFlow endpoint URL (Agent proxies all routes since ADR-026)
	ClientID              string        // Required for enterprise features: OAuth2 client ID
	ClientSecret          string        // Required for enterprise features: OAuth2 client secret
	Mode                  string        // "production" | "sandbox" (default: "production")
	Debug                 bool          // Enable debug logging (default: false)
	Timeout               time.Duration // Request timeout (default: 60s)
	MapTimeout            time.Duration // Timeout for MAP operations (default: 120s) - MAP involves multiple LLM calls
	Retry                 RetryConfig   // Retry configuration
	Cache                 CacheConfig   // Cache configuration
	TelemetryEnabled      *bool         // Override telemetry default: nil=auto, true=on, false=off
	InsecureSkipTLSVerify bool          // Disable TLS cert verification (dev/testing only). Also settable via NODE_TLS_REJECT_UNAUTHORIZED=0.
}

// RetryConfig configures retry behavior
type RetryConfig struct {
	Enabled      bool          // Enable retry logic (default: true)
	MaxAttempts  int           // Maximum retry attempts (default: 3)
	InitialDelay time.Duration // Initial delay between retries (default: 1s)
}

// CacheConfig configures caching behavior
type CacheConfig struct {
	Enabled bool          // Enable caching (default: true)
	TTL     time.Duration // Cache TTL (default: 60s)
}

// AxonFlowClient represents the SDK for connecting to AxonFlow platform
type AxonFlowClient struct {
	config        AxonFlowConfig
	httpClient    *http.Client
	mapHttpClient *http.Client // Separate client with longer timeout for MAP operations
	cache         *cache
	sessionCookie string // Session cookie for Customer Portal authentication
}

// ============================================================================
// Portal Authentication Types
// ============================================================================

// PortalLoginRequest represents a login request to the Customer Portal
type PortalLoginRequest struct {
	OrgID    string `json:"org_id"`
	Password string `json:"password"`
}

// PortalLoginResponse represents a login response from the Customer Portal
type PortalLoginResponse struct {
	SessionID string `json:"session_id"`
	OrgID     string `json:"org_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
}

// ClientRequest represents a request to AxonFlow Agent
type ClientRequest struct {
	Query       string                 `json:"query"`
	UserToken   string                 `json:"user_token"`
	ClientID    string                 `json:"client_id"`
	RequestType string                 `json:"request_type"` // "multi-agent-plan", "sql", "chat", "mcp-query"
	Context     map[string]interface{} `json:"context"`
	Media       []MediaContent         `json:"media,omitempty"` // Optional media (images) for multimodal requests
}

// ClientResponse represents response from AxonFlow Agent
type ClientResponse struct {
	Success       bool                   `json:"success"`
	Data          interface{}            `json:"data,omitempty"`
	Result        string                 `json:"result,omitempty"`     // For multi-agent planning
	PlanID        string                 `json:"plan_id,omitempty"`    // For multi-agent planning
	RequestID     string                 `json:"request_id,omitempty"` // Unique request identifier
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Blocked       bool                   `json:"blocked"`
	BlockReason   string                 `json:"block_reason,omitempty"`
	PolicyInfo    *PolicyEvaluationInfo  `json:"policy_info,omitempty"`
	BudgetInfo    *BudgetInfo            `json:"budget_info,omitempty"`    // Budget enforcement status (Issue #1082)
	MediaAnalysis *MediaAnalysisResponse `json:"media_analysis,omitempty"` // Media governance results
}

// BudgetInfo provides budget status information (Issue #1082)
type BudgetInfo struct {
	BudgetID   string  `json:"budget_id,omitempty"`
	BudgetName string  `json:"budget_name,omitempty"`
	UsedUSD    float64 `json:"used_usd"`
	LimitUSD   float64 `json:"limit_usd"`
	Percentage float64 `json:"percentage"`
	Exceeded   bool    `json:"exceeded"`
	Action     string  `json:"action,omitempty"` // "warn", "block", "downgrade"
}

// PolicyEvaluationInfo contains policy evaluation metadata
type PolicyEvaluationInfo struct {
	PoliciesEvaluated []string      `json:"policies_evaluated"`
	StaticChecks      []string      `json:"static_checks"`
	ProcessingTime    string        `json:"processing_time"` // Processing time as duration string (e.g., "17.48s")
	TenantID          string        `json:"tenant_id"`
	CodeArtifact      *CodeArtifact `json:"code_artifact,omitempty"` // Code artifact metadata if code detected
}

// CodeArtifact represents metadata for LLM-generated code detection
type CodeArtifact struct {
	IsCodeOutput    bool     `json:"is_code_output"`   // Whether response contains code
	Language        string   `json:"language"`         // Detected programming language
	CodeType        string   `json:"code_type"`        // Code category (function, class, script, etc.)
	SizeBytes       int      `json:"size_bytes"`       // Size of detected code in bytes
	LineCount       int      `json:"line_count"`       // Number of lines of code
	SecretsDetected int      `json:"secrets_detected"` // Count of potential secrets found
	UnsafePatterns  int      `json:"unsafe_patterns"`  // Count of unsafe code patterns
	PoliciesChecked []string `json:"policies_checked"` // Code governance policies evaluated
}

// ConnectorMetadata represents information about an MCP connector
type ConnectorMetadata struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Category     string                 `json:"category"`
	Icon         string                 `json:"icon"`
	Tags         []string               `json:"tags"`
	Capabilities []string               `json:"capabilities"`
	ConfigSchema map[string]interface{} `json:"config_schema"`
	Installed    bool                   `json:"installed"`
	InstanceName string                 `json:"instance_name,omitempty"` // Name of installed instance
	Healthy      bool                   `json:"healthy,omitempty"`
	LastCheck    string                 `json:"last_check,omitempty"` // When last health check was performed
}

// ConnectorHealthStatus represents the health status of an installed connector
type ConnectorHealthStatus struct {
	Healthy   bool              `json:"healthy"`   // Overall health status
	Latency   int64             `json:"latency"`   // Connection latency in nanoseconds
	Details   map[string]string `json:"details"`   // Additional diagnostic info
	Timestamp string            `json:"timestamp"` // When health check was performed
	Error     string            `json:"error"`     // Error message if unhealthy
}

// ConnectorInstallRequest represents a request to install an MCP connector
type ConnectorInstallRequest struct {
	ConnectorID string                 `json:"connector_id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Options     map[string]interface{} `json:"options"`
	Credentials map[string]string      `json:"credentials"`
}

// ConnectorResponse represents response from an MCP connector query
type ConnectorResponse struct {
	Success bool                   `json:"success"`
	Data    interface{}            `json:"data"`
	Error   string                 `json:"error,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
	// PolicyInfo fields for MCP tiered policy enforcement (Issues #963, #975)
	Redacted       bool        `json:"redacted,omitempty"`
	RedactedFields []string    `json:"redacted_fields,omitempty"`
	PolicyInfo     *PolicyInfo `json:"policy_info,omitempty"`
}

// WasRedacted returns true if any fields were redacted by policy evaluation.
func (r *ConnectorResponse) WasRedacted() bool {
	return r.Redacted
}

// PolicyInfo contains information about policy evaluation results.
// This is returned with MCP connector responses when policies are evaluated.
type PolicyInfo struct {
	PoliciesEvaluated int               `json:"policies_evaluated"`
	Blocked           bool              `json:"blocked"`
	BlockReason       string            `json:"block_reason,omitempty"`
	RedactionsApplied int               `json:"redactions_applied"`
	ProcessingTimeMs  int64             `json:"processing_time_ms"`
	MatchedPolicies   []PolicyMatchInfo `json:"matched_policies,omitempty"`
	// ExfiltrationCheck contains row/volume limit information (Issue #966)
	ExfiltrationCheck *ExfiltrationCheckInfo `json:"exfiltration_check,omitempty"`
	// DynamicPolicyInfo contains Orchestrator dynamic policy evaluation results (Issue #968)
	DynamicPolicyInfo *DynamicPolicyInfo `json:"dynamic_policy_info,omitempty"`
}

// PolicyMatchInfo contains details about a matched policy.
type PolicyMatchInfo struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Action     string `json:"action"`
}

// ExfiltrationCheckInfo contains information about exfiltration limit checks (Issue #966).
// This helps prevent large-scale data extraction via MCP queries.
type ExfiltrationCheckInfo struct {
	// RowsReturned is the number of rows in the response
	RowsReturned int64 `json:"rows_returned"`
	// RowLimit is the configured maximum rows per query
	RowLimit int `json:"row_limit"`
	// BytesReturned is the size of the response data in bytes
	BytesReturned int64 `json:"bytes_returned"`
	// ByteLimit is the configured maximum bytes per response
	ByteLimit int64 `json:"byte_limit"`
	// WithinLimits indicates whether the response is within configured limits
	WithinLimits bool `json:"within_limits"`
}

// DynamicPolicyInfo contains information about dynamic policy evaluation (Issue #968).
// Dynamic policies are evaluated by the Orchestrator and can include rate limiting,
// budget controls, time-based access, and role-based access policies.
type DynamicPolicyInfo struct {
	// PoliciesEvaluated is the number of dynamic policies checked
	PoliciesEvaluated int `json:"policies_evaluated"`
	// MatchedPolicies contains details about policies that matched
	MatchedPolicies []DynamicPolicyMatch `json:"matched_policies,omitempty"`
	// OrchestratorReachable indicates if the Orchestrator was reachable
	OrchestratorReachable bool `json:"orchestrator_reachable"`
	// ProcessingTimeMs is the time taken for dynamic policy evaluation
	ProcessingTimeMs int64 `json:"processing_time_ms"`
}

// DynamicPolicyMatch contains details about a matched dynamic policy.
type DynamicPolicyMatch struct {
	// PolicyID is the unique identifier of the policy
	PolicyID string `json:"policy_id"`
	// PolicyName is the human-readable name of the policy
	PolicyName string `json:"policy_name"`
	// PolicyType is the type of policy (rate-limit, budget, time-access, role-access, mcp, connector)
	PolicyType string `json:"policy_type"`
	// Action is the action taken (allow, block, log, etc.)
	Action string `json:"action"`
	// Reason provides context for the policy match
	Reason string `json:"reason,omitempty"`
}

// ============================================================================
// Workflow Policy Enforcement Types (Issues #1019, #1020, #1021)
// ============================================================================

// PolicyEvaluationResult contains comprehensive policy evaluation results.
// This is used for MAP and WCP (Workflow Control Point) policy enforcement.
type PolicyEvaluationResult struct {
	// Allowed indicates whether the action was permitted by policies
	Allowed bool `json:"allowed"`
	// AppliedPolicies contains the IDs of policies that were applied
	AppliedPolicies []string `json:"applied_policies"`
	// RiskScore is the calculated risk score (0.0-1.0) based on policy evaluation
	RiskScore float64 `json:"risk_score"`
	// RequiredActions contains actions required before proceeding (e.g., "mfa_verification", "manager_approval")
	RequiredActions []string `json:"required_actions"`
	// ProcessingTimeMs is the time taken for policy evaluation in milliseconds
	ProcessingTimeMs int64 `json:"processing_time_ms"`
	// DatabaseAccessed indicates whether a database was accessed during policy evaluation
	DatabaseAccessed bool `json:"database_accessed"`
}

// PolicyMatch contains details about a policy that matched during evaluation.
// Used in workflow step gate responses to provide detailed policy match information.
type PolicyMatch struct {
	// PolicyID is the unique identifier of the matched policy
	PolicyID string `json:"policy_id"`
	// PolicyName is the human-readable name of the policy
	PolicyName string `json:"policy_name"`
	// Action is the action prescribed by the policy (allow, block, require_approval, log)
	Action string `json:"action"`
	// Reason explains why this policy matched
	Reason string `json:"reason,omitempty"`
}

// PlanResponse represents a multi-agent plan generation response
type PlanResponse struct {
	PlanID            string                 `json:"plan_id"`
	Status            string                 `json:"status"` // Plan status (pending, executing, completed, failed, cancelled)
	Steps             []PlanStep             `json:"steps"`
	Domain            string                 `json:"domain"`
	Complexity        int                    `json:"complexity"`         // Complexity score (1-10)
	Parallel          bool                   `json:"parallel"`           // Whether steps can run in parallel
	EstimatedDuration string                 `json:"estimated_duration"` // Estimated execution time
	Metadata          map[string]interface{} `json:"metadata"`
}

// PlanStep represents a single step in a multi-agent plan
type PlanStep struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Description   string                 `json:"description"`
	Dependencies  []string               `json:"dependencies"` // IDs of steps this depends on
	Agent         string                 `json:"agent"`        // Agent responsible for execution
	Parameters    map[string]interface{} `json:"parameters"`
	EstimatedTime string                 `json:"estimated_time"` // Estimated execution time for this step
}

// ============================================================================
// Gateway Mode Types
// ============================================================================

// TokenUsage represents token usage information for audit logging
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// RateLimitInfo represents rate limit information returned from pre-check
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

// PolicyApprovalResult represents the result from policy pre-check in Gateway Mode
type PolicyApprovalResult struct {
	// ContextID is a unique ID for correlating pre-check with audit
	ContextID string `json:"context_id"`
	// Approved indicates whether the request was approved
	Approved bool `json:"approved"`
	// RequiresRedaction indicates whether response requires redaction (PII detected with redact action)
	RequiresRedaction bool `json:"requires_redaction,omitempty"`
	// ApprovedData contains filtered/approved data to send to LLM
	ApprovedData map[string]interface{} `json:"approved_data"`
	// Policies lists the policies that were evaluated
	Policies []string `json:"policies"`
	// RateLimitInfo contains rate limit information (if applicable)
	RateLimitInfo *RateLimitInfo `json:"rate_limit_info,omitempty"`
	// ExpiresAt indicates when this approval expires
	ExpiresAt time.Time `json:"expires_at"`
	// BlockReason contains the reason for blocking (if not approved)
	BlockReason string `json:"block_reason,omitempty"`
}

// AuditResult represents the result from audit logging in Gateway Mode
type AuditResult struct {
	// Success indicates whether the audit was logged successfully
	Success bool `json:"success"`
	// AuditID is a unique ID for reference
	AuditID string `json:"audit_id"`
}

// ExecutionMode represents plan execution strategies
type ExecutionMode string

const (
	ExecutionModeAuto       ExecutionMode = "auto"
	ExecutionModeSequential ExecutionMode = "sequential"
	ExecutionModeParallel   ExecutionMode = "parallel"
	ExecutionModeBalanced   ExecutionMode = "balanced"
	ExecutionModeConfirm    ExecutionMode = "confirm"
	ExecutionModeStep       ExecutionMode = "step"
)

// GeneratePlanOptions provides additional options for plan generation.
type GeneratePlanOptions struct {
	ExecutionMode ExecutionMode `json:"execution_mode,omitempty"`
}

// CancelPlanResponse represents the response from cancelling a plan.
type CancelPlanResponse struct {
	PlanID  string `json:"plan_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// UpdatePlanRequest represents a request to update a plan's configuration.
type UpdatePlanRequest struct {
	ExpectedVersion int           `json:"version"`
	ExecutionMode   ExecutionMode `json:"execution_mode,omitempty"`
	Domain          string        `json:"domain,omitempty"`
}

// UpdatePlanResponse represents the response from updating a plan.
type UpdatePlanResponse struct {
	PlanID  string `json:"plan_id"`
	Version int    `json:"version"`
	Status  string `json:"status"`
	Success bool   `json:"success"`
}

// PlanVersionEntry represents a single version in a plan's version history.
type PlanVersionEntry struct {
	Version       int    `json:"version"`
	ChangedAt     string `json:"changed_at"`
	ChangedBy     string `json:"changed_by,omitempty"`
	ChangeType    string `json:"change_type"`
	ChangeSummary string `json:"change_summary,omitempty"`
}

// PlanVersionsResponse represents the response from querying plan version history.
type PlanVersionsResponse struct {
	PlanID   string             `json:"plan_id"`
	Versions []PlanVersionEntry `json:"versions"`
}

// ResumePlanResponse represents the response from resuming a paused plan.
type ResumePlanResponse struct {
	PlanID       string      `json:"plan_id"`
	WorkflowID   string      `json:"workflow_id,omitempty"`
	Status       string      `json:"status"`
	Approved     bool        `json:"approved,omitempty"`
	Message      string      `json:"message,omitempty"`
	StepResult   interface{} `json:"step_result,omitempty"`
	NextStep     int         `json:"next_step,omitempty"`
	NextStepName string      `json:"next_step_name,omitempty"`
	TotalSteps   int         `json:"total_steps,omitempty"`
}

// RollbackPlanRequest represents a request to rollback a plan to a previous version.
type RollbackPlanRequest struct {
	TargetVersion int `json:"target_version"`
}

// RollbackPlanResponse represents the response from rolling back a plan.
type RollbackPlanResponse struct {
	PlanID          string `json:"plan_id"`
	Version         int    `json:"version"`
	PreviousVersion int    `json:"previous_version"`
	Status          string `json:"status"`
}

// ErrVersionConflict indicates the plan was modified by another request
var ErrVersionConflict = fmt.Errorf("version conflict: plan was modified by another request")

// PlanExecutionResponse represents the result of plan execution
type PlanExecutionResponse struct {
	PlanID                 string       `json:"plan_id"`
	Status                 string       `json:"status"`                // "running", "completed", "failed", "partial", "awaiting_approval"
	WorkflowID             string       `json:"workflow_id,omitempty"` // WCP workflow ID for confirm/step mode
	Result                 string       `json:"result,omitempty"`
	StepResults            []StepResult `json:"step_results,omitempty"`
	Error                  string       `json:"error,omitempty"`
	Duration               string       `json:"duration,omitempty"`
	CompletedSteps         int          `json:"completed_steps"`                    // Number of completed steps
	TotalSteps             int          `json:"total_steps"`                        // Total number of steps
	CurrentStep            string       `json:"current_step,omitempty"`             // Currently executing step
	EstimatedTimeRemaining string       `json:"estimated_time_remaining,omitempty"` // For in-progress plans
	// PolicyInfo contains policy evaluation results for MAP execution (Issue #1020)
	PolicyInfo *PolicyEvaluationResult `json:"policy_info,omitempty"`
}

// StepResult represents the result of a single plan step execution
type StepResult struct {
	StepID   string      `json:"step_id"`
	StepName string      `json:"step_name"`
	Status   string      `json:"status"` // "pending", "running", "completed", "failed"
	Result   interface{} `json:"result,omitempty"`
	Error    string      `json:"error,omitempty"`
	Duration string      `json:"duration,omitempty"`
}

// Cache entry
type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

// Simple in-memory cache
type cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

func newCache(ttl time.Duration) *cache {
	c := &cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
	// Start cleanup goroutine
	go c.cleanup()
	return c
}

func (c *cache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiration) {
		return nil, false
	}

	return entry.value, true
}

func (c *cache) set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		value:      value,
		expiration: time.Now().Add(c.ttl),
	}
}

func (c *cache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiration) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// NewClient creates a new AxonFlow client with the given configuration
func NewClient(config AxonFlowConfig) *AxonFlowClient {
	// Try mode: override endpoint to try.getaxonflow.com for evaluation.
	// ClientID is mandatory — the server needs it for tenant isolation.
	if os.Getenv("AXONFLOW_TRY") == "1" {
		config.Endpoint = "https://try.getaxonflow.com"
		if config.ClientID == "" {
			panic("ClientID is required in try mode (AXONFLOW_TRY=1). Register at https://try.getaxonflow.com/api/v1/register")
		}
	}

	// Reject ClientSecret without ClientID — licensed mode must specify tenant.
	// Log loudly but don't crash the process — the server will reject requests
	// and the error will surface at first API call.
	if config.ClientSecret != "" && config.ClientID == "" {
		log.Println("ERROR: axonflow: ClientID is required when ClientSecret is set. " +
			"Set ClientID to your tenant identity to avoid data being stored under the wrong tenant. " +
			"Requests will fail until ClientID is configured.")
	}

	// Set defaults
	if config.Mode == "" {
		config.Mode = "production"
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.MapTimeout == 0 {
		config.MapTimeout = 120 * time.Second // 2 minutes for MAP operations
	}
	if config.Retry.InitialDelay == 0 {
		config.Retry.InitialDelay = 1 * time.Second
	}
	if config.Retry.MaxAttempts == 0 {
		config.Retry.MaxAttempts = 3
		config.Retry.Enabled = true
	}
	// Set default cache TTL if not specified
	// Issue #1082: Only enable cache by default if TTL is 0 (unset)
	// To disable caching, set TTL to a non-zero value (e.g., 1ns) with Enabled=false
	if config.Cache.TTL == 0 {
		config.Cache.TTL = 60 * time.Second
		config.Cache.Enabled = true
	}
	// If TTL is explicitly set, respect the Enabled flag as-is

	// Configure TLS — opt-in insecure mode for development/testing only.
	// Can be enabled via AxonFlowConfig.InsecureSkipTLSVerify or NODE_TLS_REJECT_UNAUTHORIZED=0.
	skipTLS := config.InsecureSkipTLSVerify || os.Getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0"
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipTLS, // #nosec G402 -- user opt-in via config flag or env var for development/testing only; codeql[go/disabled-certificate-check]
	}
	if skipTLS {
		log.Printf("[AxonFlow] WARNING: TLS certificate verification is disabled. This should ONLY be used in development/testing environments. Do not use in production.")
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	uaTransport := &userAgentRoundTripper{
		inner:     transport,
		userAgent: "axonflow-sdk-go/" + Version,
	}

	client := &AxonFlowClient{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: uaTransport,
		},
		mapHttpClient: &http.Client{
			Timeout:   config.MapTimeout,
			Transport: uaTransport,
		},
	}

	if config.Cache.Enabled {
		client.cache = newCache(config.Cache.TTL)
	}

	if config.Debug {
		log.Printf("[AxonFlow] Client initialized - Mode: %s, Endpoint: %s, MapTimeout: %v", config.Mode, config.Endpoint, config.MapTimeout)
	}

	// Send telemetry ping synchronously with a bounded timeout.
	//
	// A goroutine here would be fire-and-forget in theory, but in practice any
	// short-lived process (CLI binary, serverless handler, quickstart snippet,
	// cold-start function) returns from main() before the goroutine's HTTP
	// POST completes, silently dropping the ping. See issue #1693.
	//
	// sendTelemetryPing runs the health probe and the checkpoint POST under a
	// single shared context.WithTimeout(telemetryTimeout) so the total
	// blocking time on NewClient is bounded at ~telemetryTimeout (3s),
	// regardless of whether endpoints are reachable. Typical is ~350ms warm
	// / ~1.3s cold.
	client.sendTelemetryPing()

	return client
}

// NewClientSimple creates a client with simple parameters (backward compatible)
func NewClientSimple(endpoint, clientID, clientSecret string) *AxonFlowClient {
	return NewClient(AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
}

// Sandbox creates a client in sandbox mode for testing
func Sandbox(apiKey string) *AxonFlowClient {
	if apiKey == "" {
		apiKey = "demo-key"
	}

	return NewClient(AxonFlowConfig{
		Endpoint:     "https://staging-eu.getaxonflow.com",
		ClientID:     apiKey,
		ClientSecret: apiKey,
		Mode:         "sandbox",
		Debug:        true,
	})
}

// ProxyLLMCall sends a query through AxonFlow platform with full policy enforcement.
// This is Proxy Mode - AxonFlow acts as an intermediary, making the LLM call on your behalf.
//
// Use this when you want AxonFlow to:
//   - Evaluate policies before the LLM call
//   - Make the LLM call to the configured provider
//   - Filter/redact sensitive data from responses
//   - Automatically track costs and audit the interaction
//
// For Gateway Mode (lower latency, you make the LLM call), use:
//   - GetPolicyApprovedContext() before your LLM call
//   - AuditLLMCall() after your LLM call
//
// If userToken is empty, it defaults to "anonymous" for audit purposes.
func (c *AxonFlowClient) ProxyLLMCall(userToken, query, requestType string, context map[string]interface{}) (*ClientResponse, error) {
	// Default to "anonymous" if userToken is empty (community mode)
	if userToken == "" {
		userToken = "anonymous"
	}

	// Generate cache key
	cacheKey := fmt.Sprintf("%s:%s:%s", requestType, query, userToken)

	// Plan operations are mutations and must not be cached
	isMutation := requestType == "execute-plan" || requestType == "generate-plan" ||
		requestType == "cancel-plan" || requestType == "update-plan"

	// Check cache if enabled (skip for mutations)
	if c.cache != nil && !isMutation {
		if cached, found := c.cache.get(cacheKey); found {
			if c.config.Debug {
				log.Printf("[AxonFlow] Cache hit for query: %s", query[:min(50, len(query))])
			}
			return cached.(*ClientResponse), nil
		}
	}

	req := ClientRequest{
		Query:       query,
		UserToken:   userToken,
		ClientID:    c.config.ClientID,
		RequestType: requestType,
		Context:     context,
	}

	var resp *ClientResponse
	var err error

	// Execute with retry if enabled (skip retry for mutations — they are not idempotent)
	if c.config.Retry.Enabled && !isMutation {
		resp, err = c.executeWithRetry(req)
	} else {
		resp, err = c.executeRequest(req)
	}

	// Handle fail-open in production mode
	if err != nil && c.config.Mode == "production" && c.isAxonFlowError(err) {
		if c.config.Debug {
			log.Printf("[AxonFlow] AxonFlow unavailable, failing open: %v", err)
		}
		// Return a success response indicating the request was allowed through
		return &ClientResponse{
			Success: true,
			Data:    nil,
			Error:   fmt.Sprintf("AxonFlow unavailable (fail-open): %v", err),
		}, nil
	}

	if err != nil {
		return nil, err
	}

	// Cache successful responses (skip mutations — plan operations)
	if c.cache != nil && resp.Success && !isMutation {
		c.cache.set(cacheKey, resp)
	}

	return resp, nil
}

// ProxyLLMCallWithMedia sends a request with media content (images) to AxonFlow for governance + routing.
// Media items are analyzed for PII, content safety, biometric data, and document classification
// before being forwarded to the LLM provider.
func (c *AxonFlowClient) ProxyLLMCallWithMedia(userToken, query, requestType string, media []MediaContent, context map[string]interface{}) (*ClientResponse, error) {
	// Default to "anonymous" if userToken is empty (community mode)
	if userToken == "" {
		userToken = "anonymous"
	}

	// Generate cache key
	cacheKey := fmt.Sprintf("%s:%s:%s", requestType, query, userToken)

	// Plan operations are mutations and must not be cached
	isMutation := requestType == "execute-plan" || requestType == "generate-plan" ||
		requestType == "cancel-plan" || requestType == "update-plan"

	// Media requests must not be cached — binary content makes cache keys unreliable
	hasMedia := len(media) > 0

	// Check cache if enabled (skip for mutations and media requests)
	if c.cache != nil && !isMutation && !hasMedia {
		if cached, found := c.cache.get(cacheKey); found {
			if c.config.Debug {
				log.Printf("[AxonFlow] Cache hit for query: %s", query[:min(50, len(query))])
			}
			return cached.(*ClientResponse), nil
		}
	}

	req := ClientRequest{
		Query:       query,
		UserToken:   userToken,
		ClientID:    c.config.ClientID,
		RequestType: requestType,
		Context:     context,
		Media:       media,
	}

	var resp *ClientResponse
	var err error

	// Execute with retry if enabled (skip retry for mutations — they are not idempotent)
	if c.config.Retry.Enabled && !isMutation {
		resp, err = c.executeWithRetry(req)
	} else {
		resp, err = c.executeRequest(req)
	}

	// Handle fail-open in production mode
	if err != nil && c.config.Mode == "production" && c.isAxonFlowError(err) {
		if c.config.Debug {
			log.Printf("[AxonFlow] AxonFlow unavailable, failing open: %v", err)
		}
		// Return a success response indicating the request was allowed through
		return &ClientResponse{
			Success: true,
			Data:    nil,
			Error:   fmt.Sprintf("AxonFlow unavailable (fail-open): %v", err),
		}, nil
	}

	if err != nil {
		return nil, err
	}

	// Cache successful responses (skip mutations and media requests)
	if c.cache != nil && resp.Success && !isMutation && !hasMedia {
		c.cache.set(cacheKey, resp)
	}

	return resp, nil
}

// executeWithRetry executes a request with exponential backoff retry
func (c *AxonFlowClient) executeWithRetry(req ClientRequest) (*ClientResponse, error) {
	var lastErr error

	for attempt := 0; attempt < c.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: delay * 2^(attempt-1)
			delay := time.Duration(float64(c.config.Retry.InitialDelay) * math.Pow(2, float64(attempt-1)))
			if c.config.Debug {
				log.Printf("[AxonFlow] Retry attempt %d/%d after %v", attempt+1, c.config.Retry.MaxAttempts, delay)
			}
			time.Sleep(delay)
		}

		resp, err := c.executeRequest(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Don't retry on client errors (4xx)
		if httpErr, ok := err.(*httpError); ok && httpErr.statusCode >= 400 && httpErr.statusCode < 500 {
			if c.config.Debug {
				log.Printf("[AxonFlow] Client error (4xx), not retrying: %v", err)
			}
			break
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.Retry.MaxAttempts, lastErr)
}

// httpError represents an HTTP error with status code
type httpError struct {
	statusCode int
	message    string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.statusCode, e.message)
}

// executeRequest executes a single request without retry
func (c *AxonFlowClient) executeRequest(req ClientRequest) (*ClientResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/request", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Sending request - Type: %s, Query: %s", req.RequestType, req.Query[:min(50, len(req.Query))])
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// [DEBUG] Log raw response body before unmarshaling
	log.Printf("[SDK-DEBUG] Raw response body size: %d bytes", len(body))
	if len(body) > 0 && len(body) <= 500 {
		log.Printf("[SDK-DEBUG] Raw response body (full): %s", string(body))
	} else if len(body) > 500 {
		log.Printf("[SDK-DEBUG] Raw response body (first 500 chars): %s...", string(body[:500]))
	}

	// For 402 (Payment Required) or 403 (Forbidden), the request was blocked - parse the response body
	// 402: Budget exceeded (Issue #1082)
	// 403: Policy violation
	if resp.StatusCode == http.StatusPaymentRequired || resp.StatusCode == http.StatusForbidden {
		var clientResp ClientResponse
		if err := json.Unmarshal(body, &clientResp); err != nil {
			return nil, fmt.Errorf("failed to parse blocked response: %w", err)
		}
		// The response contains blocked=true and block_reason from the agent
		return &clientResp, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var clientResp ClientResponse
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for nested errors in the Data field
	// When orchestrator fails, agent wraps error as: {"success":true, "data":{"success":false, "error":"..."}}
	if clientResp.Data != nil {
		if dataMap, ok := clientResp.Data.(map[string]interface{}); ok {
			// Check if data contains nested success field
			if dataSuccess, hasSuccess := dataMap["success"].(bool); hasSuccess && !dataSuccess {
				// Orchestrator execution failed - extract error message
				if errorMsg, hasError := dataMap["error"].(string); hasError {
					log.Printf("[SDK-DEBUG] Detected orchestrator failure in data.error: %s", errorMsg)
					// Surface the error by setting the Error field and marking success as false
					clientResp.Error = errorMsg
					clientResp.Success = false
				}
			}
			// Also check if data.result or data.data exists and use it if Result is empty
			if clientResp.Result == "" {
				if dataResult, hasResult := dataMap["result"].(string); hasResult && dataResult != "" {
					log.Printf("[SDK-DEBUG] Using data.result field (length: %d)", len(dataResult))
					clientResp.Result = dataResult
				} else if dataData, hasData := dataMap["data"].(string); hasData && dataData != "" {
					log.Printf("[SDK-DEBUG] Using data.data field (length: %d)", len(dataData))
					clientResp.Result = dataData
				}
			}
			// Check if data.plan_id exists and use it if PlanID is empty
			if clientResp.PlanID == "" {
				if dataPlanID, hasPlanID := dataMap["plan_id"].(string); hasPlanID && dataPlanID != "" {
					log.Printf("[SDK-DEBUG] Using data.plan_id field: %s", dataPlanID)
					clientResp.PlanID = dataPlanID
				}
			}
			// Check if data.metadata exists and use it if Metadata is empty
			if clientResp.Metadata == nil {
				if dataMetadata, hasMetadata := dataMap["metadata"].(map[string]interface{}); hasMetadata {
					log.Printf("[SDK-DEBUG] Using data.metadata field")
					clientResp.Metadata = dataMetadata
				}
			}
		}
	}

	// [DEBUG] Log unmarshaled response details
	log.Printf("[SDK-DEBUG] Unmarshaled - Success: %v, Blocked: %v, BlockReason: %s, Result length: %d, PlanID: %s",
		clientResp.Success, clientResp.Blocked, clientResp.BlockReason, len(clientResp.Result), clientResp.PlanID)
	if len(clientResp.Result) > 0 {
		if len(clientResp.Result) <= 100 {
			log.Printf("[SDK-DEBUG] Result (full): %s", clientResp.Result)
		} else {
			log.Printf("[SDK-DEBUG] Result (first 100 chars): %s...", clientResp.Result[:100])
		}
	} else {
		log.Printf("[SDK-DEBUG] Result is empty!")
	}
	log.Printf("[SDK-DEBUG] Metadata keys: %v", getMetadataKeys(clientResp.Metadata))

	// If we detected an error in the data field, log it prominently
	if clientResp.Error != "" {
		log.Printf("[SDK-DEBUG] Error field set: %s", clientResp.Error)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Response received - Success: %v, Duration: %v", clientResp.Success, duration)
	}

	return &clientResp, nil
}

// isAxonFlowError checks if an error is from AxonFlow (vs the AI provider)
func (c *AxonFlowClient) isAxonFlowError(err error) bool {
	errMsg := err.Error()
	return strings.Contains(errMsg, "AxonFlow") ||
		strings.Contains(errMsg, "governance") ||
		strings.Contains(errMsg, "request failed") ||
		strings.Contains(errMsg, "connection refused")
}

// HealthCheck checks if AxonFlow Agent is healthy
func (c *AxonFlowClient) HealthCheck() error {
	resp, err := c.httpClient.Get(c.config.Endpoint + "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent not healthy: status %d", resp.StatusCode)
	}

	if c.config.Debug {
		log.Println("[AxonFlow] Health check passed")
	}

	return nil
}

// OrchestratorHealthCheck checks orchestrator health via Agent proxy.
// Deprecated: Use HealthCheck() instead - Agent proxies all routes since ADR-026.
func (c *AxonFlowClient) OrchestratorHealthCheck() error {
	// Since ADR-026, Agent proxies to Orchestrator, so we just call Agent health
	return c.HealthCheck()
}

// HealthResponse contains detailed health information from the platform.
type HealthResponse struct {
	Status       string               `json:"status"`
	Service      string               `json:"service"`
	Version      string               `json:"version"`
	Timestamp    string               `json:"timestamp"`
	Capabilities []PlatformCapability `json:"capabilities,omitempty"`
	SDKCompat    *SDKCompatibility    `json:"sdk_compatibility,omitempty"`
}

// PlatformCapability describes a feature supported by the platform.
type PlatformCapability struct {
	Name        string `json:"name"`
	Since       string `json:"since"`
	Description string `json:"description"`
}

// SDKCompatibility describes SDK version compatibility.
type SDKCompatibility struct {
	MinSDKVersion         string `json:"min_sdk_version"`
	RecommendedSDKVersion string `json:"recommended_sdk_version"`
}

// HasCapability checks if the platform supports a named capability.
func (h *HealthResponse) HasCapability(name string) bool {
	if h == nil {
		return false
	}
	for _, cap := range h.Capabilities {
		if cap.Name == name {
			return true
		}
	}
	return false
}

// HealthCheckDetailed returns detailed health info including capabilities.
func (c *AxonFlowClient) HealthCheckDetailed() (*HealthResponse, error) {
	url := fmt.Sprintf("%s/health", c.config.Endpoint)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating health request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("decoding health response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Platform version: %s, SDK version: %s", health.Version, Version)
	}

	if health.SDKCompat != nil && health.SDKCompat.MinSDKVersion != "" {
		if compareSemver(Version, health.SDKCompat.MinSDKVersion) < 0 {
			log.Printf("[AxonFlow] WARNING: SDK version %s is below minimum supported version %s. Please upgrade.", Version, health.SDKCompat.MinSDKVersion)
		}
	}

	return &health, nil
}

// compareSemver compares two semantic version strings (e.g., "3.8.0" vs "3.10.0").
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Each segment is parsed as an integer; unparseable segments default to 0.
// Only supports MAJOR.MINOR.PATCH numeric versions. Pre-release suffixes
// (e.g., "3.8.0-beta.1") are stripped before comparison.
func compareSemver(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		aVal := 0
		bVal := 0
		if i < len(aParts) {
			seg := strings.SplitN(aParts[i], "-", 2)[0]
			aVal, _ = strconv.Atoi(seg)
		}
		if i < len(bParts) {
			seg := strings.SplitN(bParts[i], "-", 2)[0]
			bVal, _ = strconv.Atoi(seg)
		}
		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
	}
	return 0
}

// getMetadataKeys returns the keys from a metadata map for debugging
func getMetadataKeys(metadata map[string]interface{}) []string {
	if metadata == nil {
		return []string{}
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	return keys
}

// ListConnectors returns all available MCP connectors from the marketplace
func (c *AxonFlowClient) ListConnectors() ([]ConnectorMetadata, error) {
	req, err := http.NewRequest("GET", c.config.Endpoint+"/api/v1/connectors", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.addAuthHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list connectors failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Response is wrapped: {"connectors": [...], "total": N}
	var response struct {
		Connectors []ConnectorMetadata `json:"connectors"`
		Total      int                 `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode connectors: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listed %d connectors", len(response.Connectors))
	}

	return response.Connectors, nil
}

// GetConnector returns details for a specific connector by ID
func (c *AxonFlowClient) GetConnector(connectorID string) (*ConnectorMetadata, error) {
	reqURL := fmt.Sprintf("%s/api/v1/connectors/%s", c.config.Endpoint, connectorID)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.addAuthHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("connector not found: %s", connectorID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get connector failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var connector ConnectorMetadata
	if err := json.NewDecoder(resp.Body).Decode(&connector); err != nil {
		return nil, fmt.Errorf("failed to decode connector: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Got connector: %s (installed: %v)", connector.ID, connector.Installed)
	}

	return &connector, nil
}

// GetConnectorHealth returns the health status of an installed connector
func (c *AxonFlowClient) GetConnectorHealth(connectorID string) (*ConnectorHealthStatus, error) {
	reqURL := fmt.Sprintf("%s/api/v1/connectors/%s/health", c.config.Endpoint, connectorID)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.addAuthHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("connector not found: %s", connectorID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("connector health check failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var status ConnectorHealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode health status: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector %s health: %v", connectorID, status.Healthy)
	}

	return &status, nil
}

// InstallConnector installs an MCP connector from the marketplace
func (c *AxonFlowClient) InstallConnector(req ConnectorInstallRequest) error {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal install request: %w", err)
	}

	// Connector install via Agent proxy: POST /api/v1/connectors/{id}/install
	url := fmt.Sprintf("%s/api/v1/connectors/%s/install", c.config.Endpoint, req.ConnectorID)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create install request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("install request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("install failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector installed: %s", req.Name)
	}

	return nil
}

// UninstallConnector removes an installed MCP connector
func (c *AxonFlowClient) UninstallConnector(connectorName string) error {
	url := fmt.Sprintf("%s/api/v1/connectors/%s", c.config.Endpoint, connectorName)
	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create uninstall request: %w", err)
	}

	c.addAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("uninstall request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uninstall failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector uninstalled: %s", connectorName)
	}

	return nil
}

// QueryConnector executes a query against an installed MCP connector
func (c *AxonFlowClient) QueryConnector(userToken, connectorName, query string, params map[string]interface{}) (*ConnectorResponse, error) {
	context := map[string]interface{}{
		"connector": connectorName,
		"params":    params,
	}

	resp, err := c.ProxyLLMCall(userToken, query, "mcp-query", context)
	if err != nil {
		return nil, err
	}

	connResp := &ConnectorResponse{
		Success: resp.Success,
		Data:    resp.Data,
		Error:   resp.Error,
		Meta:    resp.Metadata,
	}

	return connResp, nil
}

// MCPQueryRequest represents a request to query an MCP connector directly.
type MCPQueryRequest struct {
	Connector string                 `json:"connector"`
	Statement string                 `json:"statement"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// MCPQuery executes a query directly against the MCP connector endpoint.
// This method calls the agent's /mcp/resources/query endpoint which provides:
// - Request-phase policy evaluation (SQLi blocking, PII blocking)
// - Response-phase policy evaluation (PII redaction)
// - PolicyInfo metadata in responses
//
// Returns ConnectorResponse with PolicyInfo, Redacted, and RedactedFields populated.
func (c *AxonFlowClient) MCPQuery(ctx context.Context, req MCPQueryRequest) (*ConnectorResponse, error) {
	if req.Connector == "" {
		return nil, fmt.Errorf("connector name is required")
	}
	if req.Statement == "" {
		return nil, fmt.Errorf("statement is required")
	}

	url := c.config.Endpoint + "/mcp/resources/query"

	var result ConnectorResponse
	if err := c.makeJSONRequest(ctx, "POST", url, req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// MCPExecuteRequest represents a request to execute a command via an MCP connector.
type MCPExecuteRequest struct {
	Connector string                 `json:"connector"`
	Action    string                 `json:"action"`
	Params    map[string]interface{} `json:"params,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// MCPExecuteResponse represents the response from an MCP execute command.
type MCPExecuteResponse struct {
	Success      bool                   `json:"success"`
	Result       interface{}            `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	RowsAffected int                    `json:"rows_affected,omitempty"`
	Meta         map[string]interface{} `json:"meta,omitempty"`
	PolicyInfo   *PolicyInfo            `json:"policy_info,omitempty"`
}

// MCPExecute executes a command (write operation) via an MCP connector.
// This method calls the agent's /mcp/tools/execute endpoint.
func (c *AxonFlowClient) MCPExecute(ctx context.Context, req MCPExecuteRequest) (*MCPExecuteResponse, error) {
	if req.Connector == "" {
		return nil, fmt.Errorf("connector name is required")
	}
	if req.Action == "" {
		return nil, fmt.Errorf("action is required")
	}

	url := c.config.Endpoint + "/mcp/tools/execute"

	var result MCPExecuteResponse
	if err := c.makeJSONRequest(ctx, "POST", url, req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// MCPCheckInputRequest represents a request to validate input against MCP policies.
type MCPCheckInputRequest struct {
	ConnectorType string                 `json:"connector_type"`
	Statement     string                 `json:"statement"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`
	Operation     string                 `json:"operation,omitempty"`
}

// MCPCheckInputResponse represents the result of input policy evaluation.
type MCPCheckInputResponse struct {
	Allowed           bool        `json:"allowed"`
	BlockReason       string      `json:"block_reason,omitempty"`
	PoliciesEvaluated int         `json:"policies_evaluated"`
	PolicyInfo        *PolicyInfo `json:"policy_info,omitempty"`
}

// MCPCheckOutputRequest represents a request to validate output against MCP policies.
type MCPCheckOutputRequest struct {
	ConnectorType string                   `json:"connector_type"`
	ResponseData  []map[string]interface{} `json:"response_data,omitempty"`
	Message       string                   `json:"message,omitempty"`
	Metadata      map[string]interface{}   `json:"metadata,omitempty"`
	RowCount      int                      `json:"row_count,omitempty"`
}

// MCPCheckOutputResponse represents the result of output policy evaluation.
type MCPCheckOutputResponse struct {
	Allowed           bool                   `json:"allowed"`
	BlockReason       string                 `json:"block_reason,omitempty"`
	RedactedData      interface{}            `json:"redacted_data,omitempty"`
	PoliciesEvaluated int                    `json:"policies_evaluated"`
	ExfiltrationInfo  *ExfiltrationCheckInfo `json:"exfiltration_info,omitempty"`
	PolicyInfo        *PolicyInfo            `json:"policy_info,omitempty"`
}

// MCPCheckInput validates an MCP request against configured policies without executing it.
// Use this when an external orchestrator (e.g., LangGraph, CrewAI) manages MCP execution
// but needs AxonFlow policy enforcement as a pre-execution gate.
// Note: HTTP 403 is a valid policy-blocked response, not an error.
func (c *AxonFlowClient) MCPCheckInput(ctx context.Context, req MCPCheckInputRequest) (*MCPCheckInputResponse, error) {
	if req.Operation == "" {
		req.Operation = "execute"
	}
	url := c.config.Endpoint + "/api/v1/mcp/check-input"
	var result MCPCheckInputResponse
	if err := c.makePolicyCheckRequest(ctx, url, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// MCPCheckOutput validates MCP response data against configured policies without executing a query.
// Use this when an external orchestrator manages MCP execution but needs AxonFlow policy
// enforcement as a post-execution gate (PII redaction, exfiltration limits).
// Note: HTTP 403 is a valid policy-blocked response, not an error.
func (c *AxonFlowClient) MCPCheckOutput(ctx context.Context, req MCPCheckOutputRequest) (*MCPCheckOutputResponse, error) {
	url := c.config.Endpoint + "/api/v1/mcp/check-output"
	var result MCPCheckOutputResponse
	if err := c.makePolicyCheckRequest(ctx, url, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckToolInput is an alias for MCPCheckInput. It validates tool input against configured policies.
func (c *AxonFlowClient) CheckToolInput(ctx context.Context, req MCPCheckInputRequest) (*MCPCheckInputResponse, error) {
	return c.MCPCheckInput(ctx, req)
}

// CheckToolOutput is an alias for MCPCheckOutput. It validates tool output against configured policies.
func (c *AxonFlowClient) CheckToolOutput(ctx context.Context, req MCPCheckOutputRequest) (*MCPCheckOutputResponse, error) {
	return c.MCPCheckOutput(ctx, req)
}

// GeneratePlan creates a multi-agent execution plan from a natural language query.
// The userToken parameter is optional; if not provided, it defaults to the client ID.
// Usage: GeneratePlan(query, domain) or GeneratePlan(query, domain, userToken)
// Note: This uses MapTimeout (default 120s) as MAP operations involve multiple LLM calls.
func (c *AxonFlowClient) GeneratePlan(query string, domain string, userToken ...string) (*PlanResponse, error) {
	context := map[string]interface{}{}
	if domain != "" {
		context["domain"] = domain
	}

	// Use client ID as fallback if no user token provided
	token := c.config.ClientID
	if len(userToken) > 0 && userToken[0] != "" {
		token = userToken[0]
	}

	// Use executeMapRequest with longer timeout for MAP operations
	req := ClientRequest{
		Query:       query,
		UserToken:   token,
		ClientID:    c.config.ClientID,
		RequestType: "multi-agent-plan",
		Context:     context,
	}

	resp, err := c.executeMapRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("plan generation failed: %s", resp.Error)
	}

	// Parse plan from response
	planData, ok := resp.Data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected plan response format")
	}

	// Convert to PlanResponse
	planBytes, _ := json.Marshal(planData)
	var plan PlanResponse
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse plan: %w", err)
	}

	plan.PlanID = resp.PlanID

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan generated: %s (%d steps)", plan.PlanID, len(plan.Steps))
	}

	return &plan, nil
}

// executeMapRequest executes a MAP request using the mapHttpClient with longer timeout
func (c *AxonFlowClient) executeMapRequest(req ClientRequest) (*ClientResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/request", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] MAP request - Query: %s (timeout: %v)", req.Query[:min(50, len(req.Query))], c.config.MapTimeout)
	}

	startTime := time.Now()
	resp, err := c.mapHttpClient.Do(httpReq) // Use mapHttpClient with longer timeout
	if err != nil {
		return nil, fmt.Errorf("MAP request failed: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] MAP response received in %v", duration)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var clientResp ClientResponse
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for nested errors/data in the Data field (same logic as executeRequest)
	if clientResp.Data != nil {
		if dataMap, ok := clientResp.Data.(map[string]interface{}); ok {
			if dataSuccess, hasSuccess := dataMap["success"].(bool); hasSuccess && !dataSuccess {
				if errorMsg, hasError := dataMap["error"].(string); hasError {
					clientResp.Error = errorMsg
					clientResp.Success = false
				}
			}
			if clientResp.Result == "" {
				if dataResult, hasResult := dataMap["result"].(string); hasResult && dataResult != "" {
					clientResp.Result = dataResult
				}
			}
			if clientResp.PlanID == "" {
				if dataPlanID, hasPlanID := dataMap["plan_id"].(string); hasPlanID && dataPlanID != "" {
					clientResp.PlanID = dataPlanID
				}
			}
			if clientResp.Metadata == nil {
				if dataMetadata, hasMetadata := dataMap["metadata"].(map[string]interface{}); hasMetadata {
					clientResp.Metadata = dataMetadata
				}
			}
		}
	}

	return &clientResp, nil
}

// ExecutePlan executes a previously generated multi-agent plan.
// The userToken parameter is optional; if not provided, it defaults to the client ID.
// Usage: ExecutePlan(planID) or ExecutePlan(planID, userToken)
func (c *AxonFlowClient) ExecutePlan(planID string, userToken ...string) (*PlanExecutionResponse, error) {
	context := map[string]interface{}{
		"plan_id": planID,
	}

	// Use client ID as fallback if no user token provided
	token := c.config.ClientID
	if len(userToken) > 0 && userToken[0] != "" {
		token = userToken[0]
	}

	resp, err := c.ProxyLLMCall(token, "", "execute-plan", context)
	if err != nil {
		return nil, err
	}

	execResp := &PlanExecutionResponse{
		PlanID: planID,
		Status: "completed",
		Result: resp.Result,
		Error:  resp.Error,
	}

	// Read status from response data if available (e.g., "awaiting_approval" for confirm mode)
	if resp.Data != nil {
		if dataMap, ok := resp.Data.(map[string]interface{}); ok {
			if status, ok := dataMap["status"].(string); ok && status != "" {
				execResp.Status = status
			}
			if wfID, ok := dataMap["workflow_id"].(string); ok {
				execResp.WorkflowID = wfID
			}
			if cs, ok := dataMap["current_step"].(float64); ok {
				execResp.CurrentStep = fmt.Sprintf("%.0f", cs)
			}
			if ts, ok := dataMap["total_steps"].(float64); ok {
				execResp.TotalSteps = int(ts)
			}
		}
	}
	// Also check metadata for status
	if execResp.Status == "completed" && resp.Metadata != nil {
		if status, ok := resp.Metadata["status"].(string); ok && status != "" {
			execResp.Status = status
		}
	}

	if resp.Metadata != nil {
		if duration, ok := resp.Metadata["duration"].(string); ok {
			execResp.Duration = duration
		}
		if stepResults, ok := resp.Metadata["step_results"].([]interface{}); ok {
			// Convert to StepResult slice
			for _, sr := range stepResults {
				if srMap, ok := sr.(map[string]interface{}); ok {
					stepResult := StepResult{}
					if id, ok := srMap["step_id"].(string); ok {
						stepResult.StepID = id
					}
					if name, ok := srMap["step_name"].(string); ok {
						stepResult.StepName = name
					}
					if status, ok := srMap["status"].(string); ok {
						stepResult.Status = status
					}
					if result, ok := srMap["result"]; ok {
						stepResult.Result = result
					}
					if errStr, ok := srMap["error"].(string); ok {
						stepResult.Error = errStr
					}
					if dur, ok := srMap["duration"].(string); ok {
						stepResult.Duration = dur
					}
					execResp.StepResults = append(execResp.StepResults, stepResult)
				}
			}
		}
		if completed, ok := resp.Metadata["completed_steps"].(float64); ok {
			execResp.CompletedSteps = int(completed)
		}
		if total, ok := resp.Metadata["total_steps"].(float64); ok {
			execResp.TotalSteps = int(total)
		}
	}

	if !resp.Success {
		execResp.Status = "failed"
		if c.config.Debug {
			log.Printf("[AxonFlow] Plan executed: %s - Status: %s", planID, execResp.Status)
		}
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = "plan execution failed"
		}
		return execResp, fmt.Errorf("%s", errMsg)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan executed: %s - Status: %s", planID, execResp.Status)
	}

	return execResp, nil
}

// GetPlanStatus retrieves the status of a running or completed plan
func (c *AxonFlowClient) GetPlanStatus(planID string) (*PlanExecutionResponse, error) {
	req, err := http.NewRequest("GET", c.config.Endpoint+"/api/v1/plan/"+planID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.addAuthHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get plan status failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var status PlanExecutionResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode plan status: %w", err)
	}

	return &status, nil
}

// CancelPlan cancels a running or pending plan.
// An optional reason can be provided to explain why the plan was cancelled.
// Usage: CancelPlan(planID) or CancelPlan(planID, "reason for cancellation")
func (c *AxonFlowClient) CancelPlan(planID string, reason ...string) (*CancelPlanResponse, error) {
	cancelReason := ""
	if len(reason) > 0 {
		cancelReason = reason[0]
	}

	reqBody := map[string]interface{}{}
	if cancelReason != "" {
		reqBody["reason"] = cancelReason
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cancel request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/plan/%s/cancel", c.config.Endpoint, planID)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create cancel request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Cancelling plan: %s", planID)
	}

	resp, err := c.mapHttpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cancel plan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read cancel response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cancel plan failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var cancelResp CancelPlanResponse
	if err := json.Unmarshal(body, &cancelResp); err != nil {
		return nil, fmt.Errorf("failed to decode cancel response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan cancelled: %s - Status: %s", planID, cancelResp.Status)
	}

	return &cancelResp, nil
}

// UpdatePlan updates a plan's configuration (execution mode, domain).
// Uses optimistic concurrency control via ExpectedVersion in the request.
// Returns ErrVersionConflict if the plan was modified by another request (HTTP 409).
func (c *AxonFlowClient) UpdatePlan(planID string, req UpdatePlanRequest) (*UpdatePlanResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/plan/%s", c.config.Endpoint, planID)
	httpReq, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create update request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Updating plan: %s (expected version: %d)", planID, req.ExpectedVersion)
	}

	resp, err := c.mapHttpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("update plan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read update response: %w", err)
	}

	// Handle version conflict (409 Conflict)
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrVersionConflict
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update plan failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var updateResp UpdatePlanResponse
	if err := json.Unmarshal(body, &updateResp); err != nil {
		return nil, fmt.Errorf("failed to decode update response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan updated: %s - Version: %d, Status: %s", planID, updateResp.Version, updateResp.Status)
	}

	return &updateResp, nil
}

// GetPlanVersions retrieves the version history of a plan.
func (c *AxonFlowClient) GetPlanVersions(planID string) (*PlanVersionsResponse, error) {
	url := fmt.Sprintf("%s/api/v1/plan/%s/versions", c.config.Endpoint, planID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create versions request: %w", err)
	}

	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting plan versions: %s", planID)
	}

	resp, err := c.mapHttpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get plan versions request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read versions response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get plan versions failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var versionsResp PlanVersionsResponse
	if err := json.Unmarshal(body, &versionsResp); err != nil {
		return nil, fmt.Errorf("failed to decode versions response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan %s has %d versions", planID, len(versionsResp.Versions))
	}

	return &versionsResp, nil
}

// ResumePlan resumes a paused plan (e.g., one waiting for approval in "confirm" or "step" mode).
// The approved parameter is optional; if not provided, it defaults to true.
// Usage: ResumePlan(planID) or ResumePlan(planID, false)
func (c *AxonFlowClient) ResumePlan(planID string, approved ...bool) (*ResumePlanResponse, error) {
	isApproved := true
	if len(approved) > 0 {
		isApproved = approved[0]
	}

	reqBody := map[string]interface{}{
		"approved": isApproved,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resume request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/plan/%s/resume", c.config.Endpoint, planID)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create resume request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Resuming plan: %s (approved: %v)", planID, isApproved)
	}

	resp, err := c.mapHttpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("resume plan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read resume response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resume plan failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var resumeResp ResumePlanResponse
	if err := json.Unmarshal(body, &resumeResp); err != nil {
		return nil, fmt.Errorf("failed to decode resume response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan resumed: %s - Status: %s, Approved: %v", planID, resumeResp.Status, resumeResp.Approved)
	}

	return &resumeResp, nil
}

// RollbackPlan rolls back a plan to a previous version.
// The targetVersion specifies which version to revert to.
func (c *AxonFlowClient) RollbackPlan(planID string, targetVersion int) (*RollbackPlanResponse, error) {
	url := fmt.Sprintf("%s/api/v1/plan/%s/rollback/%d", c.config.Endpoint, planID, targetVersion)
	httpReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create rollback request: %w", err)
	}

	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Rolling back plan: %s to version %d", planID, targetVersion)
	}

	resp, err := c.mapHttpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rollback plan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read rollback response: %w", err)
	}

	// Handle version conflict (409 Conflict)
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrVersionConflict
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rollback plan failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var rollbackResp RollbackPlanResponse
	if err := json.Unmarshal(body, &rollbackResp); err != nil {
		return nil, fmt.Errorf("failed to decode rollback response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan rolled back: %s - Version: %d, Previous: %d, Status: %s",
			planID, rollbackResp.Version, rollbackResp.PreviousVersion, rollbackResp.Status)
	}

	return &rollbackResp, nil
}

// GeneratePlanWithOptions creates a multi-agent execution plan with additional options.
// This extends GeneratePlan with support for execution mode selection.
// The userToken parameter is optional; if not provided, it defaults to the client ID.
// Usage: GeneratePlanWithOptions(query, domain, opts) or GeneratePlanWithOptions(query, domain, opts, userToken)
// Note: This uses MapTimeout (default 120s) as MAP operations involve multiple LLM calls.
func (c *AxonFlowClient) GeneratePlanWithOptions(query string, domain string, opts GeneratePlanOptions, userToken ...string) (*PlanResponse, error) {
	context := map[string]interface{}{}
	if domain != "" {
		context["domain"] = domain
	}
	if opts.ExecutionMode != "" {
		context["execution_mode"] = opts.ExecutionMode
	}

	// Use client ID as fallback if no user token provided
	token := c.config.ClientID
	if len(userToken) > 0 && userToken[0] != "" {
		token = userToken[0]
	}

	// Use executeMapRequest with longer timeout for MAP operations
	req := ClientRequest{
		Query:       query,
		UserToken:   token,
		ClientID:    c.config.ClientID,
		RequestType: "multi-agent-plan",
		Context:     context,
	}

	resp, err := c.executeMapRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("plan generation failed: %s", resp.Error)
	}

	// Parse plan from response
	planData, ok := resp.Data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected plan response format")
	}

	// Convert to PlanResponse
	planBytes, _ := json.Marshal(planData)
	var plan PlanResponse
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse plan: %w", err)
	}

	plan.PlanID = resp.PlanID

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan generated with options: %s (%d steps, mode: %s)", plan.PlanID, len(plan.Steps), opts.ExecutionMode)
	}

	return &plan, nil
}

// ============================================================================
// Gateway Mode Methods
// ============================================================================

// PreCheck is an alias for GetPolicyApprovedContext for simpler API.
func (c *AxonFlowClient) PreCheck(
	userToken string,
	query string,
	dataSources []string,
	context map[string]interface{},
) (*PolicyApprovalResult, error) {
	return c.GetPolicyApprovedContext(userToken, query, dataSources, context)
}

// GetPolicyApprovedContext performs a policy pre-check before making a direct LLM call.
//
// Use Gateway Mode when you want to:
//   - Make direct LLM calls (not through AxonFlow proxy)
//   - Have full control over your LLM provider/model selection
//   - Minimize latency by calling LLM directly
//
// Example:
//
//	ctx, err := client.GetPolicyApprovedContext(userToken, query, []string{"postgres"}, nil)
//	if err != nil {
//	    return err
//	}
//	if !ctx.Approved {
//	    return fmt.Errorf("blocked: %s", ctx.BlockReason)
//	}
//
//	// Make direct LLM call with ctx.ApprovedData
//	resp, err := openai.CreateCompletion(...)
//
//	// Audit the call
//	client.AuditLLMCall(ctx.ContextID, "summary", "openai", "gpt-4", tokenUsage, latencyMs, nil)

// getEffectiveClientID returns the configured ClientID or a default value for community mode.
// This enables zero-config usage for community/self-hosted deployments while still
// supporting enterprise deployments with explicit credentials.
func (c *AxonFlowClient) getEffectiveClientID() string {
	if c.config.ClientID != "" {
		return c.config.ClientID
	}
	return "community" // Smart default for community mode
}

func (c *AxonFlowClient) GetPolicyApprovedContext(
	userToken string,
	query string,
	dataSources []string,
	context map[string]interface{},
) (*PolicyApprovalResult, error) {
	if dataSources == nil {
		dataSources = []string{}
	}
	if context == nil {
		context = map[string]interface{}{}
	}

	// Use smart default for clientId - enables zero-config community mode
	clientID := c.getEffectiveClientID()

	reqBody := map[string]interface{}{
		"user_token":   userToken,
		"client_id":    clientID,
		"query":        query,
		"data_sources": dataSources,
		"context":      context,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pre-check request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/policy/pre-check", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-check request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Pre-check for query: %s", query[:min(50, len(query))])
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("pre-check request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read pre-check response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	// Parse response
	var rawResp struct {
		ContextID         string                 `json:"context_id"`
		Approved          bool                   `json:"approved"`
		RequiresRedaction bool                   `json:"requires_redaction"`
		ApprovedData      map[string]interface{} `json:"approved_data"`
		Policies          []string               `json:"policies"`
		RateLimit         *struct {
			Limit     int    `json:"limit"`
			Remaining int    `json:"remaining"`
			ResetAt   string `json:"reset_at"`
		} `json:"rate_limit,omitempty"`
		ExpiresAt   string `json:"expires_at"`
		BlockReason string `json:"block_reason,omitempty"`
	}

	if err := json.Unmarshal(body, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pre-check response: %w", err)
	}

	// Parse expiration time (supports both RFC3339 and RFC3339Nano formats)
	expiresAt, err := parseTimeWithFallback(rawResp.ExpiresAt)
	if err != nil {
		// Use a default expiration if parsing fails
		expiresAt = time.Now().Add(5 * time.Minute)
		if c.config.Debug {
			log.Printf("[AxonFlow] Warning: Failed to parse expires_at '%s', using default 5 minute expiration", rawResp.ExpiresAt)
		}
	}

	result := &PolicyApprovalResult{
		ContextID:         rawResp.ContextID,
		Approved:          rawResp.Approved,
		RequiresRedaction: rawResp.RequiresRedaction,
		ApprovedData:      rawResp.ApprovedData,
		Policies:          rawResp.Policies,
		ExpiresAt:         expiresAt,
		BlockReason:       rawResp.BlockReason,
	}

	// Parse rate limit info if present
	if rawResp.RateLimit != nil {
		resetAt, err := parseTimeWithFallback(rawResp.RateLimit.ResetAt)
		if err != nil && c.config.Debug {
			log.Printf("[AxonFlow] Warning: Failed to parse rate_limit.reset_at '%s'", rawResp.RateLimit.ResetAt)
		}
		result.RateLimitInfo = &RateLimitInfo{
			Limit:     rawResp.RateLimit.Limit,
			Remaining: rawResp.RateLimit.Remaining,
			ResetAt:   resetAt,
		}
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Pre-check result - Approved: %v, ContextID: %s, Policies: %d",
			result.Approved, result.ContextID, len(result.Policies))
	}

	return result, nil
}

// AuditLLMCall logs an audit trail after making a direct LLM call.
//
// This is required for compliance and monitoring when using Gateway Mode.
// Call this after making your direct LLM call to ensure the audit trail is complete.
//
// Example:
//
//	result, err := client.AuditLLMCall(
//	    ctx.ContextID,
//	    "Generated report with 5 items",
//	    "openai",
//	    "gpt-4",
//	    TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
//	    250, // latency in ms
//	    nil, // optional metadata
//	)
func (c *AxonFlowClient) AuditLLMCall(
	contextID string,
	responseSummary string,
	provider string,
	model string,
	tokenUsage TokenUsage,
	latencyMs int64,
	metadata map[string]interface{},
) (*AuditResult, error) {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}

	// Use smart default for clientId - enables zero-config community mode
	clientID := c.getEffectiveClientID()

	reqBody := map[string]interface{}{
		"context_id":       contextID,
		"client_id":        clientID,
		"response_summary": responseSummary,
		"provider":         provider,
		"model":            model,
		"token_usage": map[string]int{
			"prompt_tokens":     tokenUsage.PromptTokens,
			"completion_tokens": tokenUsage.CompletionTokens,
			"total_tokens":      tokenUsage.TotalTokens,
		},
		"latency_ms": latencyMs,
		"metadata":   metadata,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/audit/llm-call", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Audit - ContextID: %s, Provider: %s, Model: %s",
			contextID, provider, model)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("audit request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var rawResp struct {
		Success bool   `json:"success"`
		AuditID string `json:"audit_id"`
	}

	if err := json.Unmarshal(body, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit response: %w", err)
	}

	result := &AuditResult{
		Success: rawResp.Success,
		AuditID: rawResp.AuditID,
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Audit logged - AuditID: %s", result.AuditID)
	}

	return result, nil
}

// Helper functions

// parseTimeWithFallback tries to parse a time string using RFC3339Nano first (with fractional seconds),
// then falls back to RFC3339 (without fractional seconds). This handles timestamps from the server
// that may or may not include nanosecond precision.
func parseTimeWithFallback(value string) (time.Time, error) {
	// Try RFC3339Nano first (supports fractional seconds up to nanosecond precision)
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t, nil
	}
	// Fall back to RFC3339 (no fractional seconds)
	return time.Parse(time.RFC3339, value)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Media Governance Methods
// ============================================================================

// GetMediaGovernanceConfig retrieves the current tenant's media governance configuration.
func (c *AxonFlowClient) GetMediaGovernanceConfig() (*MediaGovernanceConfig, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting media governance config")
	}

	var config MediaGovernanceConfig
	if err := c.policyRequest("GET", "/api/v1/media-governance/config", nil, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// UpdateMediaGovernanceConfig updates the current tenant's media governance configuration.
func (c *AxonFlowClient) UpdateMediaGovernanceConfig(req UpdateMediaGovernanceConfigRequest) (*MediaGovernanceConfig, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Updating media governance config")
	}

	var config MediaGovernanceConfig
	if err := c.policyRequest("PUT", "/api/v1/media-governance/config", req, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// GetMediaGovernanceStatus retrieves the media governance feature availability status.
func (c *AxonFlowClient) GetMediaGovernanceStatus() (*MediaGovernanceStatus, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting media governance status")
	}

	var status MediaGovernanceStatus
	if err := c.policyRequest("GET", "/api/v1/media-governance/status", nil, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// ============================================================================
// Portal Authentication Methods
// ============================================================================

// LoginToPortal authenticates with the Customer Portal and stores the session cookie.
// This is required for enterprise features like Code Governance PR workflow.
//
// Example:
//
//	resp, err := client.LoginToPortal("test-org-001", "test123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Logged in as %s\n", resp.Name)
//
//	// Now you can use Code Governance methods
//	providers, err := client.ListGitProviders()
func (c *AxonFlowClient) LoginToPortal(orgID, password string) (*PortalLoginResponse, error) {
	reqBody := PortalLoginRequest{
		OrgID:    orgID,
		Password: password,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login request: %w", err)
	}

	fullURL := c.config.Endpoint + "/api/v1/auth/login"

	req, err := http.NewRequest("POST", fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.config.Debug {
		log.Printf("[AxonFlow] Portal login for org: %s", orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read login response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	var loginResp PortalLoginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login response: %w", err)
	}

	// Extract session cookie from response and store it
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "axonflow_session" {
			c.sessionCookie = cookie.Value
			if c.config.Debug {
				log.Printf("[AxonFlow] Portal session established for %s", orgID)
			}
			break
		}
	}

	// If no cookie in response, use session_id from JSON response
	if c.sessionCookie == "" && loginResp.SessionID != "" {
		c.sessionCookie = loginResp.SessionID
		if c.config.Debug {
			log.Printf("[AxonFlow] Portal session established from response body for %s", orgID)
		}
	}

	return &loginResp, nil
}

// LogoutFromPortal logs out from the Customer Portal and clears the session cookie.
func (c *AxonFlowClient) LogoutFromPortal() error {
	if c.sessionCookie == "" {
		return nil // Already logged out
	}

	fullURL := c.config.Endpoint + "/api/v1/auth/logout"

	req, err := http.NewRequest("POST", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "axonflow_session",
		Value: c.sessionCookie,
	})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", err)
	}
	defer resp.Body.Close()

	c.sessionCookie = ""

	if c.config.Debug {
		log.Printf("[AxonFlow] Portal session ended")
	}

	return nil
}

// IsLoggedIn returns true if the client has an active portal session.
func (c *AxonFlowClient) IsLoggedIn() bool {
	return c.sessionCookie != ""
}

// makePolicyCheckRequest performs a POST request where HTTP 403 is a valid policy-blocked
// response (not an error). The response body is deserialized into result for both 2xx and 403.
func (c *AxonFlowClient) makePolicyCheckRequest(ctx context.Context, fullURL string, body interface{}, result interface{}) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(req)

	if c.config.Debug {
		log.Printf("[AxonFlow] Policy check request: POST %s", fullURL)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// 403 is a valid policy-blocked response — deserialize normally
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusForbidden {
		return &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}

// makeJSONRequest is a generic helper for making JSON HTTP requests
func (c *AxonFlowClient) makeJSONRequest(ctx context.Context, method, fullURL string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(req)

	if c.config.Debug {
		log.Printf("[AxonFlow] JSON request: %s %s", method, fullURL)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	// Handle no-content responses
	if resp.StatusCode == 204 || len(respBody) == 0 {
		return nil
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}
