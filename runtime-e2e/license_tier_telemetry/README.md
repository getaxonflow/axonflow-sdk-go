# Runtime proof — `license_tier` in SDK telemetry (#3619)

Verifies that the SDK reports the connected platform's licence tier on its telemetry heartbeat, reads it from the `/health` response it **already** fetches for `platform_version`, and **omits** the field on every path where the tier could not be learned.

Closes the gap where telemetry could not distinguish an enterprise-licensed deployment from an unlicensed community one.

## Usage

```sh
# 1. MATRIX — every tier value and every fail-open path, against a local stand-in platform.
go run runtime-e2e/license_tier_telemetry/main.go

# 2. REAL PLATFORM — drive the SDK at a live agent and cross-check the wire
#    value against that agent's own /health.
AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
  go run runtime-e2e/license_tier_telemetry/main.go
```

Mode 2 is the one that proves the contract end to end: it reads the tier from the live platform independently, then asserts the SDK put *that* value on the wire verbatim. If the endpoint is unreachable it asserts the **platform-down** contract instead — ping still delivered, field omitted.

## What it asserts

1. `community`, `evaluation`, `Enterprise`, the csaas `Plus` alias and the transient `starting` each reach the wire byte-for-byte. No client-side case folding or alias mapping — normalization is the receiver's job (checkpoint-service `NormalizeLicenseTier`), and folding here would mask a tier this SDK build predates.
2. On every not-learned path — platform down, HTTP 500, malformed body, no `tier` key, empty `tier` — the ping is **still delivered** and `license_tier` is **absent** from the JSON. Never `""`, never a substituted default.
3. `deployment_mode` is unchanged by the tier. The two dimensions stay separate.

## Why each case runs in a fresh child process

`sharedHeartbeat` is a process-global singleton (see `heartbeat.go`), so one process emits at most one ping no matter how many clients it builds. A matrix driven in-process would silently assert against the first case's body every time. The proof re-execs itself per case; the parent hosts both listeners.

## Mutation proof

| Mutation | Failing assertion |
|---|---|
| Delete `LicenseTier: probe.LicenseTier,` from the payload literal in `telemetry.go` | case 1 — `license_tier absent from wire` |
| Drop the `health.Tier != ""` guard in `probePlatformHealth` | case 2 — `license_tier present as ""` |
| Restore the pre-#3619 early return when `version` is empty | unit test `TestHealthProbeLearnsVersionAndTierIndependently` — a platform reporting a tier but no version loses the tier |

## CI coverage

The equivalent assertions run in CI as unit tests in `telemetry_test.go`: `TestTelemetryWireCarriesTierVerbatimForEveryPlatformEmittedValue`, `TestTelemetryWireOmitsTierWheneverHealthDidNotYieldOne`, `TestHealthProbeLearnsVersionAndTierIndependently`, `TestTierProbeDoesNotStackASecondTimeoutOntoTheTelemetryBudget`, and `TestLicenseTierDoesNotAlterDeploymentMode`. This runtime proof is a real-stack confirmation, not a CI gate.
