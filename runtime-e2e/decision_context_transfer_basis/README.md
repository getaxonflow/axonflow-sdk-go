# decision_context_transfer_basis (v8.4.0)

Real-wire test for the v8.4.0 SDK surface (platform epic #2508):

- **`DecisionSummary.Context` / `DecisionExplanation.Context`** — the sanitized
  request context a PEP attaches to a Decision Mode call is surfaced back
  through `ListDecisions` and `ExplainDecision`.
- **`AuditLogEntry.TransferBasis = "pasal_56b_dpa"`** — the Pasal 56(b) explicit
  DPA tag round-trips verbatim.

The driver acts as the PEP (raw `POST /api/v1/decide` — that endpoint is
intentionally not SDK-wrapped per ADR-056), then reads the decision back through
the SDK and asserts `Context` is populated with the PEP-forwarded keys.

## Run

```
# Requires a running agent at AXONFLOW_AGENT_URL (default http://localhost:8080).
# In community mode any client id/secret is accepted and maps to a tenant.
export AXONFLOW_AGENT_URL=http://localhost:8080
export AXONFLOW_TENANT_ID=buku-e-go-e2e
export AXONFLOW_TENANT_SECRET=buku-e-secret

go run runtime-e2e/decision_context_transfer_basis/main.go
```

Exits non-zero if the SDK does not surface the new fields.
