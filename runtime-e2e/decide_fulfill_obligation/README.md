# runtime-e2e: Decision Mode PEP — decide → fulfill → forward

Real-stack assertion for the Decision Mode PEP contract
(getaxonflow/axonflow-enterprise#2571 / epic #2563).

Proves end-to-end, against a **real** running AxonFlow agent (no mocks):

1. `client.Decide(...)` on a PII-bearing request returns `verdict=allow` with a
   self-describing `redact_pii` obligation whose fulfillment names the
   `check-input` engine endpoint (request phase, `text/plain`).
2. `client.FulfillRequest(...)` discharges it by round-tripping the statement
   through that engine endpoint and returns ENGINE-redacted content — the
   original email (`john.doe@example.com`) and card (`4111111111111111`) no
   longer appear. The SDK contains no local redaction path.
3. `client.DecideAndFulfill(...)` does both in one call.
4. Demo / wrong credentials are refused (HTTP 401).

## Run

```sh
source /tmp/axonflow-e2e-env.sh   # provides AXONFLOW_CLIENT_ID + AXONFLOW_CLIENT_SECRET

AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_CLIENT_ID="$AXONFLOW_CLIENT_ID" \
AXONFLOW_CLIENT_SECRET="$AXONFLOW_CLIENT_SECRET" \
go run runtime-e2e/decide_fulfill_obligation/main.go
```

Exit 0 + `PASS:` line = success. Any `FAIL:` line on stderr = failure (exit 1).
