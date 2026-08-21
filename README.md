# AxonFlow SDK for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/getaxonflow/axonflow-sdk-go/v9.svg)](https://pkg.go.dev/github.com/getaxonflow/axonflow-sdk-go/v9)
[![Go Report Card](https://goreportcard.com/badge/github.com/getaxonflow/axonflow-sdk-go)](https://goreportcard.com/report/github.com/getaxonflow/axonflow-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Upgrade strongly recommended.** AxonFlow ships substantial monthly security and quality hardening; staying on the latest major is the security-supported release line. [Latest release](https://github.com/getaxonflow/axonflow-sdk-go/releases/latest) · [Security advisories](https://github.com/getaxonflow/axonflow-sdk-go/security/advisories)

> ## ⚠️ Use the `/v9` import path
>
> Go's semantic import versioning requires the module path to include the major version suffix for v2+. The current release line is **v9.x**, imported as:
>
> ```go
> import "github.com/getaxonflow/axonflow-sdk-go/v9"
> ```
>
> ```bash
> go get github.com/getaxonflow/axonflow-sdk-go/v9
> ```
>
> `go get github.com/getaxonflow/axonflow-sdk-go@latest` (without `/v9`) resolves to **v1.17.0** (a 2026-01 relic from before the v2 split) and is eight major release lines behind current. See the [Migration Guide](#migration-guide) below.

> **Taking a sponsored workflow to production?**
>
> Choose the path that fits:
> - **Self-serve:** free 90-day [Evaluation License](https://getaxonflow.com/evaluation-license?utm_source=readme_sdk_go_eval)
> - **Paid production program:** [Design Partner or Confidential Pilot](https://getaxonflow.com/design-partner?utm_source=readme_sdk_go)  -  one scoped workflow over 60 or 75 days, founder-led rollout support, upfront conversion pricing, and a fixed decision date; public track from $2,000 or confidential track from $4,000
>
> The paid program requires a dated forcing event, written controls, an executive sponsor, and a technical owner. Prices are subject to eligibility and a signed agreement.

> **Questions or feedback?**
>
> Comment in [GitHub Discussions](https://github.com/getaxonflow/axonflow/discussions/239) or email [hello@getaxonflow.com](mailto:hello@getaxonflow.com) for private feedback.

Enterprise-grade Go SDK for AxonFlow AI governance platform. Add invisible AI governance to your applications with production-ready features including retry logic, caching, fail-open strategy, and debug mode.

## How This SDK Fits with AxonFlow

This SDK is a client library for interacting with a running AxonFlow control plane. It is used from application or agent code to send execution context, policies, and requests at runtime.

A deployed AxonFlow platform (self-hosted or cloud) is required for end-to-end AI governance. SDKs alone are not sufficient—the platform and SDKs are designed to be used together.

### See AxonFlow in Action

Three short videos covering different angles of the platform:

- **[Community Quickstart Demo (Code + Terminal, 2.5 min)](https://youtu.be/BSqU1z0xxCo)** — governed calls, PII block, Gateway Mode with LangChain/CrewAI, and MAP from YAML
- **[Runtime Control Demo (Portal + Workflow, 2.5 min)](https://youtu.be/sRTv2uF0sxY)** — approvals, retry safety, execution state, and the audit viewer
- **[Architecture Deep Dive (12 min)](https://youtu.be/Q2CZ1qnquhg)** — how the control plane works, policy enforcement flow, and multi-agent planning

## Installation

```bash
go get github.com/getaxonflow/axonflow-sdk-go/v9
```

## Evaluation Tier (Free License)

Need more capacity than Community without moving to Enterprise? Evaluation uses the same core features with higher limits:

| Limit | Community | Evaluation (Free) | Enterprise |
|-------|-----------|-------------------|------------|
| Tenant policies | 20 | 50 | Unlimited |
| Org-wide policies | 0 | 5 | Unlimited |
| Audit retention | 3 days | 14 days | 3650 days |
| Concurrent executions | 5 | 25 | Unlimited |
| Pending execution approvals | 5 | 25 | Unlimited |
| Evidence export (CSV / JSON) | — | 5,000 records · 14d window · 3/day | Unlimited |
| Policy simulation | — | 300 / day | Unlimited |

Concurrent executions applies to MAP and WCP executions per tenant. Pending execution approvals applies to MAP confirm/step mode and WCP approval queues.

> **Note:** Evidence export and policy simulation are licensed AxonFlow platform capabilities available alongside the SDK on your deployed platform — not language-specific SDK helpers. Access them via the platform API or customer portal. The SDK row is included to show what your licensed deployment unlocks at each tier.

[Get a free Evaluation license](https://getaxonflow.com/evaluation-license?utm_source=readme_sdk_go_eval) · [Run a paid production program](https://getaxonflow.com/design-partner?utm_source=readme_sdk_go_eval) · [Full feature matrix](https://docs.getaxonflow.com/docs/features/community-vs-enterprise?utm_source=readme_sdk_go_eval)

## Try Without Installing

Skip local setup entirely — try AxonFlow instantly at [**try.getaxonflow.com**](https://docs.getaxonflow.com/docs/deployment/community-saas):

```bash
# 1. Register (30 seconds)
curl -X POST https://try.getaxonflow.com/api/v1/register \
  -H "Content-Type: application/json" -d '{"label":"my-trial"}'

# 2. Set credentials and auto-connect
export AXONFLOW_TRY=1
export AXONFLOW_CLIENT_ID=cs_your-tenant-id
export AXONFLOW_CLIENT_SECRET=your-secret
```

No Docker, no license, no installation. Rate-limited to 20 req/min. [Learn more](https://docs.getaxonflow.com/docs/deployment/community-saas).

## Quick Start

### Basic Usage (OAuth2 Client Credentials)

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
    // Simple initialization with OAuth2 credentials
    client := axonflow.NewClient(axonflow.AxonFlowConfig{
        Endpoint:     "http://localhost:8080",
        ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
        ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
    })

    // Execute a governed query
    resp, err := client.ProxyLLMCall(
        "user-token",
        "What is the capital of France?",
        "chat",
        map[string]interface{}{},
    )

    if err != nil {
        log.Fatalf("Query failed: %v", err)
    }

    if resp.Blocked {
        log.Printf("Request blocked: %s", resp.BlockReason)
        return
    }

    fmt.Printf("Result: %s\n", resp.Data)
}
```

### Advanced Configuration

```go
import (
    "time"
    "os"
    "github.com/getaxonflow/axonflow-sdk-go/v9"
)

// Full configuration with all features
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
    ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
    Mode:         "production",  // or "sandbox"
    Debug:        true,          // Enable debug logging
    Timeout:      60 * time.Second,

    // Retry configuration (exponential backoff)
    Retry: axonflow.RetryConfig{
        Enabled:      true,
        MaxAttempts:  3,
        InitialDelay: 1 * time.Second,
    },

    // Cache configuration (in-memory with TTL)
    Cache: axonflow.CacheConfig{
        Enabled: true,
        TTL:     60 * time.Second,
    },
})
```

### Self-Hosted Mode (No License Required)

Connect to a self-hosted AxonFlow instance running via docker-compose:

```go
package main

import (
    "fmt"
    "log"

    "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
    // Self-hosted (localhost) - no license key needed!
    client := axonflow.NewClient(axonflow.AxonFlowConfig{
        Endpoint: "http://localhost:8081",
        // That's it - no authentication required for localhost
    })

    // Use normally - same features as production
    resp, err := client.ProxyLLMCall(
        "user-token",
        "Test with self-hosted AxonFlow",
        "chat",
        map[string]interface{}{},
    )

    if err != nil {
        log.Fatalf("Query failed: %v", err)
    }

    fmt.Printf("Result: %s\n", resp.Data)
}
```

**Self-hosted deployment:**
```bash
# Clone and start AxonFlow
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow
export OPENAI_API_KEY=sk-your-key-here
docker-compose up

# Go SDK connects to http://localhost:8081 - no license needed!
```

**Features:**
- ✅ Full AxonFlow features without license
- ✅ Perfect for local development and testing
- ✅ Same API as production
- ✅ Automatically detects localhost and skips authentication

### Sandbox Mode (Local Testing)

```go
// Quick sandbox client for local testing — defaults to http://localhost:8080.
client := axonflow.Sandbox("demo-client", "demo-secret")

resp, err := client.ProxyLLMCall(
    "",
    "Test query with sensitive data: SSN 123-45-6789",
    "chat",
    map[string]interface{}{},
)

if resp.Blocked {
    fmt.Printf("Blocked: %s\n", resp.BlockReason)
}
```

> Sandbox-mode clients fire telemetry like every other client — anonymous SDK
> heartbeat, classification-only payload, opt-out via `AXONFLOW_TELEMETRY=off`.
> Pings are tagged `stream="sandbox"` server-side so dev/test usage is
> distinguishable from production heartbeat.

## Features

### ✅ Retry Logic with Exponential Backoff

Automatic retry on transient failures with exponential backoff:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Retry: axonflow.RetryConfig{
        Enabled:      true,
        MaxAttempts:  3,           // Retry up to 3 times
        InitialDelay: 1 * time.Second,  // 1s, 2s, 4s backoff
    },
})

// Automatically retries on 5xx errors or network failures
resp, err := client.ProxyLLMCall(...)
```

### ✅ In-Memory Caching with TTL

Reduce latency and load with intelligent caching:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Cache: axonflow.CacheConfig{
        Enabled: true,
        TTL:     60 * time.Second,  // Cache for 60 seconds
    },
})

// First call: hits AxonFlow
resp1, _ := client.ProxyLLMCall("token", "query", "chat", nil)

// Second call (within 60s): served from cache
resp2, _ := client.ProxyLLMCall("token", "query", "chat", nil)
```

### ✅ Fail-Open Strategy (Production Mode)

Never block your users if AxonFlow is unavailable:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Mode:     "production",  // Fail-open in production
    Debug:    true,
})

// If AxonFlow is unavailable, request proceeds with warning
resp, err := client.ProxyLLMCall(...)
// err == nil, resp.Success == true, resp.Error contains warning
```

## LLM Interceptors (OpenAI & Anthropic)

Wrap your LLM clients with automatic AxonFlow governance using the interceptors package:

### OpenAI Interceptor

```go
import (
    "context"
    "github.com/sashabaranov/go-openai"
    "github.com/getaxonflow/axonflow-sdk-go/v9"
    "github.com/getaxonflow/axonflow-sdk-go/v9/interceptors"
)

// Initialize AxonFlow client
axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
    ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
})

// Create an adapter for the OpenAI client
openaiClient := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

// Use the function wrapper for direct usage
wrappedFn := interceptors.WrapOpenAIFunc(
    func(ctx context.Context, req interceptors.ChatCompletionRequest) (interceptors.ChatCompletionResponse, error) {
        // Convert to go-openai types and call
        goReq := openai.ChatCompletionRequest{
            Model: req.Model,
            Messages: convertMessages(req.Messages),
        }
        resp, err := openaiClient.CreateChatCompletion(ctx, goReq)
        if err != nil {
            return interceptors.ChatCompletionResponse{}, err
        }
        return convertResponse(resp), nil
    },
    axonflowClient,
    "user-token",
)

// Use wrapped function - governance happens automatically
resp, err := wrappedFn(ctx, interceptors.ChatCompletionRequest{
    Model: "gpt-4",
    Messages: []interceptors.ChatMessage{
        {Role: "user", Content: "Hello, world!"},
    },
})

if err != nil {
    if interceptors.IsPolicyViolationError(err) {
        pve, _ := interceptors.GetPolicyViolation(err)
        log.Printf("Blocked: %s (policies: %v)", pve.BlockReason, pve.Policies)
    }
}
```

### Anthropic Interceptor

```go
import (
    "context"
    "github.com/getaxonflow/axonflow-sdk-go/v9"
    "github.com/getaxonflow/axonflow-sdk-go/v9/interceptors"
)

// Create Anthropic interceptor
wrappedFn := interceptors.WrapAnthropicFunc(
    yourAnthropicCreateFn,
    axonflowClient,
    "user-token",
)

// Use wrapped function
resp, err := wrappedFn(ctx, interceptors.AnthropicMessageRequest{
    Model:     "claude-3-sonnet-20240229",
    MaxTokens: 1024,
    Messages: []interceptors.AnthropicMessage{
        interceptors.CreateUserMessage("Hello, Claude!"),
    },
})
```

### Interface-Based Wrapping

For more flexibility, implement the `OpenAIChatCompleter` or `AnthropicMessageCreator` interfaces:

```go
// Implement the interface
type MyOpenAIClient struct {
    // your fields
}

func (c *MyOpenAIClient) CreateChatCompletion(ctx context.Context, req interceptors.ChatCompletionRequest) (interceptors.ChatCompletionResponse, error) {
    // your implementation
}

// Wrap the client
wrapped := interceptors.WrapOpenAIClient(&MyOpenAIClient{}, axonflowClient, "user-token")

// Use wrapped client
resp, err := wrapped.CreateChatCompletion(ctx, req)
```

## MCP Connector Marketplace

Integrate with external data sources using AxonFlow's MCP (Model Context Protocol) connectors:

### List Available Connectors

```go
connectors, err := client.ListConnectors()
if err != nil {
    log.Fatalf("Failed to list connectors: %v", err)
}

for _, conn := range connectors {
    fmt.Printf("Connector: %s (%s)\n", conn.Name, conn.Type)
    fmt.Printf("  Description: %s\n", conn.Description)
    fmt.Printf("  Installed: %v\n", conn.Installed)
}
```

### Install a Connector

```go
err := client.InstallConnector(axonflow.ConnectorInstallRequest{
    ConnectorID: "amadeus-travel",
    Name:        "amadeus-prod",
    TenantID:    "your-tenant-id",
    Options: map[string]interface{}{
        "environment": "production",
    },
    Credentials: map[string]string{
        "api_key":    "your-amadeus-key",
        "api_secret": "your-amadeus-secret",
    },
})

if err != nil {
    log.Fatalf("Failed to install connector: %v", err)
}

fmt.Println("Connector installed successfully!")
```

### Query a Connector

```go
// Query the Amadeus connector for flight information
resp, err := client.QueryConnector(
    "user-session-token",  // User token for authentication and audit trail
    "amadeus-prod",
    "Find flights from Paris to Amsterdam on Dec 15",
    map[string]interface{}{
        "origin":      "CDG",
        "destination": "AMS",
        "date":        "2025-12-15",
    },
)

if err != nil {
    log.Fatalf("Connector query failed: %v", err)
}

if resp.Success {
    fmt.Printf("Flight data: %v\n", resp.Data)
} else {
    fmt.Printf("Query failed: %s\n", resp.Error)
}
```

### Production Connectors (November 2025)

AxonFlow now supports **7 production-ready connectors**:

#### Salesforce CRM Connector

Query Salesforce data using SOQL:

```go
// Query Salesforce contacts
resp, err := client.QueryConnector(
    "user-session-token",  // User token for authentication and audit trail
    "salesforce-crm",
    "Find all contacts for account Acme Corp",
    map[string]interface{}{
        "soql": "SELECT Id, Name, Email, Phone FROM Contact WHERE AccountId = '001xx000003DHP0'",
    },
)

if err != nil {
    log.Fatalf("Salesforce query failed: %v", err)
}

fmt.Printf("Found %d contacts\n", len(resp.Data.([]interface{})))
```

**Authentication:** OAuth 2.0 password grant (configured in AxonFlow dashboard)

#### Snowflake Data Warehouse Connector

Execute analytics queries on Snowflake:

```go
// Query Snowflake for sales analytics
resp, err := client.QueryConnector(
    "user-session-token",  // User token for authentication and audit trail
    "snowflake-warehouse",
    "Get monthly revenue for last 12 months",
    map[string]interface{}{
        "sql": `SELECT DATE_TRUNC('month', order_date) as month,
                COUNT(*) as orders,
                SUM(amount) as revenue
                FROM orders
                WHERE order_date >= DATEADD(month, -12, CURRENT_DATE())
                GROUP BY month
                ORDER BY month`,
    },
)

if err != nil {
    log.Fatalf("Snowflake query failed: %v", err)
}

fmt.Printf("Revenue data: %v\n", resp.Data)
```

**Authentication:** Key-pair JWT authentication (configured in AxonFlow dashboard)

#### Slack Connector

Send notifications and alerts to Slack channels:

```go
// Send Slack notification
resp, err := client.QueryConnector(
    "user-session-token",  // User token for authentication and audit trail
    "slack-workspace",
    "Send deployment notification to #engineering channel",
    map[string]interface{}{
        "channel": "#engineering",
        "text":    "🚀 Deployment complete! All systems operational.",
        "blocks": []map[string]interface{}{
            {
                "type": "section",
                "text": map[string]string{
                    "type": "mrkdwn",
                    "text": "*Deployment Status*\n✅ All systems operational",
                },
            },
        },
    },
)

if err != nil {
    log.Fatalf("Slack notification failed: %v", err)
}

fmt.Printf("Message sent: %v\n", resp.Success)
```

**Authentication:** OAuth 2.0 bot token (configured in AxonFlow dashboard)

#### Available Connectors

| Connector | Type | Use Case |
|-----------|------|----------|
| PostgreSQL | Database | Relational data access |
| Redis | Cache | Distributed rate limiting |
| Slack | Communication | Team notifications |
| Salesforce | CRM | Customer data, SOQL queries |
| Snowflake | Data Warehouse | Analytics, reporting |
| Amadeus GDS | Travel | Flight/hotel booking |
| Cassandra | NoSQL | Distributed database |

For complete connector documentation, see [https://docs.getaxonflow.com/docs/mcp/overview](https://docs.getaxonflow.com/docs/mcp/overview)

## MCP Policy Features (v3.2.0)

### Exfiltration Detection

Prevent large-scale data extraction with automatic row and byte limits:

```go
// Query with exfiltration limits (default: 10K rows, 10MB)
response, err := client.QueryConnector("postgres", "SELECT * FROM customers", nil)
if err != nil {
    log.Fatal(err)
}

// Check exfiltration info
if response.PolicyInfo.ExfiltrationCheck.Exceeded {
    log.Printf("Data limit exceeded: %s", response.PolicyInfo.ExfiltrationCheck.LimitType)
    // LimitType: "rows" or "bytes"
}

// Configure limits via environment:
// MCP_MAX_ROWS_PER_QUERY=1000
// MCP_MAX_BYTES_PER_QUERY=5242880
```

### Dynamic Policy Evaluation

Enable Orchestrator-based policy evaluation for rate limiting, budget controls, and more:

```go
// Response includes dynamic policy info when enabled
response, err := client.QueryConnector("postgres", "SELECT id FROM users", nil)
if err != nil {
    log.Fatal(err)
}

// Check dynamic policy evaluation results
dynamicInfo := response.PolicyInfo.DynamicPolicyInfo
if dynamicInfo.OrchestratorReachable {
    log.Printf("Policies evaluated: %d", dynamicInfo.PoliciesEvaluated)
    for _, policy := range dynamicInfo.MatchedPolicies {
        log.Printf("  %s: %s", policy.PolicyName, policy.Action)
    }
}

// Enable via environment:
// MCP_DYNAMIC_POLICIES_ENABLED=true
```

## Multi-Agent Planning (MAP)

Generate and execute complex multi-step plans using AI agent orchestration:

### Generate a Plan

```go
// Generate a travel planning workflow
plan, err := client.GeneratePlan(
    "Plan a 3-day trip to Paris with moderate budget",
    "travel",  // Domain hint (optional)
)

if err != nil {
    log.Fatalf("Plan generation failed: %v", err)
}

fmt.Printf("Generated plan %s with %d steps\n", plan.PlanID, len(plan.Steps))
fmt.Printf("Complexity: %d, Parallel: %v\n", plan.Complexity, plan.Parallel)

for i, step := range plan.Steps {
    fmt.Printf("  Step %d: %s (%s)\n", i+1, step.Name, step.Type)
    fmt.Printf("    Description: %s\n", step.Description)
    fmt.Printf("    Agent: %s\n", step.Agent)
}
```

### Execute a Plan

```go
// Execute the generated plan
execResp, err := client.ExecutePlan(plan.PlanID)
if err != nil {
    log.Fatalf("Plan execution failed: %v", err)
}

fmt.Printf("Plan Status: %s\n", execResp.Status)
fmt.Printf("Duration: %s\n", execResp.Duration)

if execResp.Status == "completed" {
    fmt.Printf("Result:\n%s\n", execResp.Result)
} else if execResp.Status == "failed" {
    fmt.Printf("Error: %s\n", execResp.Error)
}
```

### Check Plan Status

```go
// For long-running plans, check status periodically
status, err := client.GetPlanStatus(plan.PlanID)
if err != nil {
    log.Fatalf("Failed to get plan status: %v", err)
}

fmt.Printf("Plan Status: %s\n", status.Status)
```

## Health Check

Check if AxonFlow Agent is available:

```go
err := client.HealthCheck()
if err != nil {
    log.Printf("AxonFlow Agent is unhealthy: %v", err)
} else {
    log.Println("AxonFlow Agent is healthy")
}
```

## VPC Private Endpoint (Low-Latency)

For applications running in AWS VPC, use the private endpoint for lower latency:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "https://<your-vpc-endpoint>.example.com:8443",  // VPC private endpoint (replace with your deployment URL)
    ClientID:     "your-client-id",
    ClientSecret: "your-secret",
    Mode:         "production",
})
```

**Network Latency Characteristics:**
- Public endpoint: Higher latency (internet routing overhead)
- VPC private endpoint: Lower latency (intra-VPC routing)

## Error Handling

```go
resp, err := client.ProxyLLMCall(...)
if err != nil {
    // Network errors, timeouts, or AxonFlow unavailability
    log.Printf("Request failed: %v", err)
    return
}

if resp.Blocked {
    // Policy violation - request blocked by governance rules
    log.Printf("Request blocked: %s", resp.BlockReason)
    log.Printf("Policies evaluated: %v", resp.PolicyInfo.PoliciesEvaluated)
    return
}

if !resp.Success {
    // Request succeeded but returned error from downstream
    log.Printf("Query failed: %s", resp.Error)
    return
}

// Success - use resp.Data or resp.Result
fmt.Printf("Result: %v\n", resp.Data)
```

## Production Best Practices

1. **Environment Variables**: Never hardcode credentials
   ```go
   import "os"

   client := axonflow.NewClient(axonflow.AxonFlowConfig{
       Endpoint:     os.Getenv("AXONFLOW_AGENT_URL"),
       ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
       ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
   })
   ```

2. **Fail-Open in Production**: Use `Mode: "production"` to fail-open if AxonFlow is unavailable

3. **Enable Caching**: Reduce latency for repeated queries

4. **Enable Retry**: Handle transient failures automatically

5. **Debug in Development**: Use `Debug: true` during development, disable in production

6. **Health Checks**: Monitor AxonFlow availability with periodic health checks

7. **Secure Storage**: Store credentials in environment variables or secrets management systems (AWS Secrets Manager, HashiCorp Vault, etc.)

## Configuration Reference

### AxonFlowConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Endpoint` | `string` | Required | AxonFlow Agent endpoint URL |
| `ClientID` | `string` | **Required** | OAuth2 client ID for authentication |
| `ClientSecret` | `string` | **Required** | OAuth2 client secret for authentication |
| `Mode` | `string` | `"production"` | `"production"` or `"sandbox"` |
| `Debug` | `bool` | `false` | Enable debug logging |
| `Timeout` | `time.Duration` | `60s` | Request timeout |
| `Retry.Enabled` | `bool` | `true` | Enable retry logic |
| `Retry.MaxAttempts` | `int` | `3` | Maximum retry attempts |
| `Retry.InitialDelay` | `time.Duration` | `1s` | Initial retry delay (exponential backoff) |
| `Cache.Enabled` | `bool` | `true` | Enable caching |
| `Cache.TTL` | `time.Duration` | `60s` | Cache time-to-live |

**Note:** For self-hosted (localhost) deployments, `ClientID` and `ClientSecret` are optional.

## Migration Guide

### Migrating from v1.x (bare import path) to v5

If `go get github.com/getaxonflow/axonflow-sdk-go@latest` resolved to **v1.17.0**, you are on a 2026-01 relic because you used the bare module path. Go's semantic import versioning requires the `/v5` suffix for v2+ releases.

```bash
# In go.mod, remove the old entry and replace with the v5 path:
#   github.com/getaxonflow/axonflow-sdk-go → github.com/getaxonflow/axonflow-sdk-go/v9
go get github.com/getaxonflow/axonflow-sdk-go/v9
```

Update all imports in your `.go` files to include `/v5`:

```go
// Before:
import "github.com/getaxonflow/axonflow-sdk-go"

// After:
import "github.com/getaxonflow/axonflow-sdk-go/v9"
```

The API surface between v1 and v5 is substantially different. Check the release notes for v2, v3, v4, and v5 for the breaking changes you'll need to adopt. If you're coming from v1.x directly, the fastest path is usually to re-read the [Quick Start](#quick-start) section rather than trying to incrementally migrate.

### Migrating from v4 to v5

**1. Update module path:**

```bash
# In go.mod, change:
#   github.com/getaxonflow/axonflow-sdk-go/v4 → github.com/getaxonflow/axonflow-sdk-go/v9
go get github.com/getaxonflow/axonflow-sdk-go/v9
```

Update all imports in your `.go` files from `/v4` to `/v5`. No API-surface changes are required for the v4 → v5 bump itself — the major version increment reflects a policy break in how plan-scoped HITL responses are returned. See the [v5.0.0 release notes](https://github.com/getaxonflow/axonflow-sdk-go/releases/tag/v5.0.0) for the specifics.

### Migrating from v3 to v4

**1. Update module path:**
```bash
# In go.mod, change:
#   github.com/getaxonflow/axonflow-sdk-go/v3 → github.com/getaxonflow/axonflow-sdk-go/v4
go get github.com/getaxonflow/axonflow-sdk-go/v4@v4.0.0
```

Update all imports in your `.go` files from `v3` to `v4`.

**2. Remove `TotalSteps` from `CreateWorkflowRequest`:**
```go
// Before (v3):
req := axonflow.CreateWorkflowRequest{
    WorkflowName: "my-workflow",
    TotalSteps:   5,  // Remove this
}

// After (v4):
req := axonflow.CreateWorkflowRequest{
    WorkflowName: "my-workflow",
}
// Total steps are auto-computed at terminal state (Platform v4.5.0+)
```

**3. Specify `Operation` for `MCPCheckInput` if you relied on the `"query"` default:**
```go
// Before (v3): defaulted to "query"
resp, _ := client.MCPCheckInput(ctx, req)

// After (v4): defaults to "execute" — pass explicitly if needed
req.Operation = "query"
resp, _ := client.MCPCheckInput(ctx, req)
```

### Migrating to OAuth2 Client Credentials

If you're using older authentication methods (`LicenseKey` or API keys), migrate to OAuth2 client credentials:

**Before (v2.x):**
```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:   "http://localhost:8080",
    LicenseKey: os.Getenv("AXONFLOW_LICENSE_KEY"),
})
```

**After (v3.x):**
```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
    ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
})
```

**How to get credentials:**
1. Contact AxonFlow support at [hello@getaxonflow.com](mailto:hello@getaxonflow.com)
2. Credentials are provided as part of your AxonFlow subscription
3. Store credentials securely in environment variables or secrets management systems

**Self-hosted users:** No credentials required for localhost endpoints.

## Examples

Complete working examples for all features are available in the [examples folder](https://github.com/getaxonflow/axonflow/tree/main/examples).

### Community Features

```go
// PII Detection - Automatically detect sensitive data
result, _ := client.GetPolicyApprovedContext("user", "SSN: 123-45-6789", nil, nil)
// result.RequiresRedaction = true (SSN detected)

// SQL Injection Detection - Block malicious queries
result, _ := client.GetPolicyApprovedContext("user", "SELECT * FROM users; DROP TABLE users;", nil, nil)
// result.Approved = false, result.BlockReason = "SQL injection detected"

// Static Policies - List and manage built-in policies
policies, _ := client.ListPolicies()
// Returns: [{Name: "pii-detection", Enabled: true}, {Name: "sql-injection", Enabled: true}, ...]

// Dynamic Policies - Create runtime policies
err := client.CreateDynamicPolicy(axonflow.DynamicPolicyRequest{
    Name:       "block-competitor-queries",
    Conditions: `{"contains": ["competitor", "pricing"]}`,
    Action:     "block",
})

// MCP Connectors - Query external data sources
resp, _ := client.QueryConnector("user-token", "postgres-db", "SELECT name, email FROM customers", nil)
// resp.Data contains query results with PII automatically redacted

// Multi-Agent Planning - Orchestrate complex workflows
plan, _ := client.GeneratePlan("Research AI governance regulations and summarize", "legal")
result, _ := client.ExecutePlan(plan.PlanID)

// Audit Logging - Track all LLM interactions
logs, _ := client.ListAuditLogs(axonflow.AuditLogFilter{UserID: "user-123", Limit: 100})

// Execution Replay - Debug past executions
executions, _ := client.ListExecutions(axonflow.ExecutionFilter{Status: "failed"})
```

### Enterprise Features

These features require an AxonFlow Enterprise license:

```go
// Code Governance - Automated PR reviews with AI
prResult, _ := client.ReviewPullRequest(axonflow.PRReviewRequest{
    RepoOwner:  "your-org",
    RepoName:   "your-repo",
    PRNumber:   123,
    CheckTypes: []string{"security", "style", "performance"},
})

// Cost Controls - Budget management for LLM usage
budget, _ := client.GetBudget("team-engineering")
// Returns: {Limit: 1000.00, Used: 234.56, Remaining: 765.44}

// MCP Policy Enforcement - Automatic PII redaction in connector responses
resp, _ := client.QueryConnector("user", "postgres", "SELECT * FROM customers", nil)
// resp.PolicyInfo.Redacted = true
// resp.PolicyInfo.RedactedFields = ["ssn", "credit_card"]
```

For enterprise features, contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com).

## Support

- **Documentation**: https://docs.getaxonflow.com
- **Issues**: https://github.com/getaxonflow/axonflow-sdk-go/issues
- **Email**: hello@getaxonflow.com

If you are evaluating AxonFlow in a company setting and cannot open a public issue, you can share feedback or blockers confidentially here:
[Anonymous evaluation feedback form](https://getaxonflow.com/feedback)

No email required. Optional contact if you want a response.

## Telemetry

This SDK sends anonymous usage telemetry (SDK version, OS, enabled features) to help improve AxonFlow.
No prompts, payloads, or PII are ever collected. Opt out: `AXONFLOW_TELEMETRY=off`.

`AXONFLOW_TELEMETRY=off` is the **sole opt-out lever** as of v8.0. The
v7.x `TelemetryEnabled` config field has been removed; the previous
silent suppression of sandbox-mode pings has also been removed
(sandbox-mode pings now fire and are tagged `stream="sandbox"` so
they're distinguishable from production heartbeat).

### Scope of `AXONFLOW_TELEMETRY=off`

`AXONFLOW_TELEMETRY=off` disables the anonymous SDK heartbeat (version, OS, architecture). On **self-hosted** and **in-VPC** deployments, that heartbeat is the only data the SDK sends to AxonFlow, so setting `=off` means we receive nothing. On **Community SaaS** (`try.getaxonflow.com`) the hosted service also processes operational data — registrations, audit logs, policy enforcement records, workflow state, plan data, and request-header metadata aggregated for usage analytics — as part of running the platform; that operational data flow is governed by the [Privacy Policy](https://getaxonflow.com/privacy/), not by `AXONFLOW_TELEMETRY`.

`DO_NOT_TRACK` is **not** honored as an opt-out for AxonFlow telemetry. It is commonly inherited from host tools and developer environments, which makes it an unreliable expression of user intent.

See [Telemetry Documentation](https://docs.getaxonflow.com/docs/telemetry) for full details.

## License

MIT
