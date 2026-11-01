# Hosted 402 runtime proof

Run this against a disposable Hosted staging Agent with a newly registered unpaid Basic credential. The driver accepts only `https://try-staging.getaxonflow.com`; it makes one harmless synthetic governed request and prints no credential.

```bash
AXONFLOW_HOSTED_STAGING_AGENT_URL=https://try-staging.getaxonflow.com \
AXONFLOW_HOSTED_UNPAID_CLIENT_ID='<staging-tenant>' \
AXONFLOW_HOSTED_UNPAID_CLIENT_SECRET='<staging-secret>' \
AXONFLOW_TELEMETRY=off \
go run runtime-e2e/hosted_paid_refusal/main.go
```

A real Agent run is a release gate. The local HTTP contract test proves parsing, fail-closed behavior, and the one-request retry boundary; it does not replace this live check.
