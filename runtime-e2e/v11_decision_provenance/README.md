# v11_decision_provenance

Real-stack proof that the SDK surfaces the v11.0.0 platform wire:

Requires a v11.1.0 or later platform: a v11.0.0 platform stamps `X-AxonFlow-Removed-In: v11.1`, and this leg reds against it.

- decision provenance on `Decide`, the gateway pre-check and MCP check-output;
- a deprecated route reported through `AxonFlowConfig.OnRouteDeprecation` on a legacy policy read;
- `LegacyPolicyWriteFrozenError` on a legacy policy write.

Nothing is mocked: the program calls a running agent and orchestrator through the SDK's public surface.

## The stack it needs

A v11 agent and orchestrator. For the frozen-write leg, both must connect as the application database role (`AXONFLOW_DB_USE_APP_ROLE=true` with `AXONFLOW_DB_APP_ROLE_URL` set), the way a deployment runs them. The v11 freeze is a revoke on that role. A local stack that connects as the database owner is not bound by it, and on such a stack the write would succeed; the program then removes the probe policy it created and fails.

The platform's `scripts/setup-e2e-testing.sh production-posture` boots an enterprise stack that way, and `scripts/e2e/probe-boot-log.sh` confirms every main pool is on the app role.

## Run

```
AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_CLIENT_ID=runtime-e2e AXONFLOW_CLIENT_SECRET=runtime-e2e-secret \
AXONFLOW_USER_TOKEN=<a per-user JWT> \
go run runtime-e2e/v11_decision_provenance/main.go
```

The pre-check leg sends `AXONFLOW_USER_TOKEN`: an enterprise agent validates the pre-check's user token as a JWT and refuses a malformed one with 401. The setup script writes one to its env file.

It prints each observed value and exits non-zero on any failed assertion.
