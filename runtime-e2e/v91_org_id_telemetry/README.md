# Runtime proof — `org_id` in SDK telemetry payload (v9.1)

Verifies the v9.1 contract: every SDK telemetry ping body carries an
`org_id` field, populated from the `ORG_ID` env var with a
`local-dev-org` sentinel fallback. Issue #2277.

## When to run

- **Local development** — single-binary `go run`, no infrastructure
  prerequisites. The proof spins up its own in-process HTTP listener
  to receive the SDK's outgoing telemetry POST and inspects the wire
  body.

- **CI** — covered by the unit/functional tests in
  `telemetry_test.go::TestSendTelemetryPing_OrgIDOnWire` and
  `TestSendTelemetryPing_OrgIDAlwaysPresent`. This runtime proof is a
  redundant real-stack confirmation, not a CI gate.

## Usage

```sh
# ORG_ID set — operator-supplied (self-hosted) or cs_<uuid> (Community SaaS):
ORG_ID=acme-corp go run runtime-e2e/v91_org_id_telemetry/main.go

# ORG_ID unset — local-dev-org sentinel:
unset ORG_ID && go run runtime-e2e/v91_org_id_telemetry/main.go
```

Expected output:

```
PASS: telemetry wire payload carries org_id="acme-corp" (expected="acme-corp")
Wire body: {"telemetry_type":"sdk", ... ,"org_id":"acme-corp"}
```

## What it asserts

1. The SDK constructed under any config emits a telemetry POST within
   2 seconds of `NewClient`.
2. The POST body is valid JSON.
3. The body has an `org_id` key.
4. The value matches `$ORG_ID` (when set) or `local-dev-org` (when
   unset).

## Mutation proof

Remove the `OrgID: telemetryOrgID(),` line from `telemetry.go`'s
`payload := telemetryPayload{...}` block and rerun. The proof exits 1
with `FAIL: telemetry org_id = "", want "local-dev-org"`.

## Cross-SDK parity

Companion runtime-e2e tests will land in the other 4 SDKs under the
same `runtime-e2e/v91_org_id_telemetry/` subdirectory as part of the
#2277 cross-repo rollout:

- `axonflow-sdk-python/runtime-e2e/v91_org_id_telemetry/`
- `axonflow-sdk-typescript/runtime-e2e/v91_org_id_telemetry/`
- `axonflow-sdk-java/runtime-e2e/v91_org_id_telemetry/`
- `axonflow-sdk-rust/runtime-e2e/v91_org_id_telemetry/`

All five SDKs send the field with the same wire name (`org_id`),
same sentinel value (`local-dev-org`), and the same precedence
(env > sentinel). The captured-payload transcript across the five
will be posted as the delivery comment on Epic #2230.
