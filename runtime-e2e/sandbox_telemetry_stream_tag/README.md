# Runtime proof — Sandbox-mode telemetry fires with stream=sandbox (v8)

Verifies the v8 contract: a `Sandbox()`-constructed client produces a
heartbeat ping that lands in checkpoint DynamoDB with the row tagged
`stream="sandbox"`.

## When to run

**Post-deploy verification.** Two infrastructure prerequisites:

1. **`axonflow-enterprise` PR #2005 deployed** — without the server-side
   wire-allowlist, the Lambda hardcodes `stream=heartbeat` regardless of
   payload, and this test will fail at the assertion step. Confirm with:
   ```sh
   curl -sS -X POST -H 'Content-Type: application/json' \
     -d '{"sdk":"go","sdk_version":"8.0.0","stream":"community_saas_operational","instance_id":"x"}' \
     https://checkpoint.getaxonflow.com/v1/ping
   # Expect HTTP 400 "invalid stream value"
   ```
2. **AWS credentials** with read on `/aws/lambda/prod-axonflow-checkpoint`.

## Usage

```sh
AWS_REGION=us-east-1 ./test.sh
```

## What it asserts

1. Builds a tiny Go program against the local SDK via `go.mod replace`.
2. The program calls `axonflow.Sandbox(...)` which historically would have
   produced no telemetry.
3. The Lambda's CloudWatch audit log records an `event_stored` row with
   `sdk=go/8` AND `stream=sandbox`.

## Pre-v8 behavior (regression-guard context)

In v7.x, `Sandbox()` set `Mode: "sandbox"` and the SDK gate
short-circuited at `mode != "sandbox"`. This silent suppression is the
specific hole this test guards against re-introducing. If a future
refactor restores any mode-based gate, this test fires loudly.
