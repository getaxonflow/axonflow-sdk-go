# AxonFlow Go SDK Examples

This directory contains working examples demonstrating how to use the AxonFlow Go SDK.

## Prerequisites

```bash
go get github.com/getaxonflow/axonflow-sdk-go/v9
```

Set environment variables:

```bash
export AXONFLOW_AGENT_URL="http://localhost:8080"  # Default for local docker-compose
export AXONFLOW_CLIENT_ID="your-client-id"
export AXONFLOW_CLIENT_SECRET="AXON-PLUS-yourorg-20351025-signature"  # Your license key
```

**Note**: `AXONFLOW_CLIENT_SECRET` should be your AxonFlow license key in the format `AXON-{TIER}-{ORG}-{EXPIRY}-{SIGNATURE}`

## Examples

### 1. Basic Usage (`examples/basic/`)

Simple SDK initialization and protected AI calls.

```bash
cd examples/basic
go run main.go
```

Demonstrates:
- Client initialization
- Executing protected queries
- Handling blocked requests
- PII detection
- Governance metadata

### 2. MCP Connectors (`examples/connectors/`)

Working with the MCP connector marketplace.

```bash
cd examples/connectors
go run main.go
```

Demonstrates:
- Listing available connectors
- Installing connectors
- Querying connector data

### 3. Multi-Agent Planning (`examples/planning/`)

Complex workflow orchestration with MAP.

```bash
cd examples/planning
go run main.go
```

Demonstrates:
- Generating multi-step plans
- Executing plans
- Checking plan status
- Handling plan results

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AXONFLOW_AGENT_URL` | Yes | AxonFlow Agent endpoint URL |
| `AXONFLOW_CLIENT_ID` | Yes | Your client identifier |
| `AXONFLOW_CLIENT_SECRET` | Yes | Your AxonFlow license key (format: AXON-{TIER}-{ORG}-{EXPIRY}-{SIG}) |
| `AXONFLOW_REDIS_HOST` | No | Redis host as seen from the platform (default: `redis`, the docker-compose service) |
| `AXONFLOW_REDIS_PORT` | No | Redis port (default: `6379`) |

## Authentication

The AxonFlow Go SDK uses license-based authentication:

1. **License Key**: Your `AXONFLOW_CLIENT_SECRET` is your license key
2. **Format**: `AXON-{TIER}-{ORG}-{EXPIRY}-{SIGNATURE}`
3. **Validation**: HMAC-SHA256 signature verification
4. **Rate Limiting**: Enforced based on your license tier

Example license keys by tier:
- **Professional (PRO)**: `AXON-PRO-acme-20351025-8f3a2b9c` (500 req/min)
- **Enterprise (ENT)**: `AXON-ENT-acme-20351025-a1b2c3d4` (1000 req/min)
- **Enterprise Plus (PLUS)**: `AXON-PLUS-acme-20351025-e5f6a7b8` (Unlimited)

## Learn More

- [Main Documentation](../README.md)
- [API Reference](https://pkg.go.dev/github.com/getaxonflow/axonflow-sdk-go/v9)
- [AxonFlow Docs](https://docs.getaxonflow.com)
