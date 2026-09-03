# adapter_telemetry - real-wire proof of the adapter registry

Covers axonflow-enterprise#3682 items 1-3 for the Go SDK: `RegisterAdapter`
puts `adapter:<name>` on the `features` array of the heartbeat that already
fires, an over-cap name is dropped whole, the adapter survives every `/health`
failure mode, and a redirect is refused on **both** telemetry legs.

## Run it

```
# Matrix mode - the registry, the cap, and both redirect legs.
go run runtime-e2e/adapter_telemetry/main.go

# Real-platform mode - drive the SDK at a live agent and assert the adapter
# rides the SAME ping that carries that agent's own version and tier.
AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
  go run runtime-e2e/adapter_telemetry/main.go
```

Bring the agent up with the standard setup described in
`axonflow-internal-docs/engineering/E2E_EXAMPLES_TESTING_WORKFLOW.md`.

## Why there are listeners here

The SDK does not expose its internal telemetry `http.Client`, and the real
checkpoint service is **production** - a runtime proof must not deliver test
pings to it. So the driver runs real listeners on both sides and the bytes
flow real → real through `net/http`: a real client, its real startup
goroutine, its real `/health` probe, its real POST. Nothing about the SDK is
mocked, injected or stubbed; the stand-ins are the two *peers*, exactly as in
the neighbouring `license_tier_telemetry` driver. Raw `net.Listen` is used
rather than `httptest`, which is what the no-mocks lint forbids. In
real-platform mode the platform side stops being a stand-in.

Each case runs in a **fresh child process**. The heartbeat gate is a
process-global singleton and the adapter registry is a package-global set, so
one process would emit a single ping carrying the union of every case's
registrations - every assertion after the first would be reading the first
case's body.

## What it asserts, and what it cannot

| # | Assertion |
|---|---|
| 1 | A registered adapter reaches the wire in `features`. |
| 2 | An unregistered one does not - paired with (1) as its positive control, because "absent" is also true of a ping that never fired. |
| 3 | A 65-byte name is dropped **whole**: neither sent in full nor truncated to 64, and it does not take the valid name with it. |
| 4 | The adapter still ships when `/health` is unconfigured, unreachable, 500, malformed, or carries none of the relayed fields. The adapter is the SDK's own knowledge and must not depend on the platform. |
| 5 | A 302 on `/health` and a 302 on the checkpoint POST are both refused, each proven with **two** listeners where the second one records. |

**Cannot vary:** the receiver's own behaviour. The checkpoint's
`NormalizeAdapterFeature` folds an unrecognised name into `adapter:unknown` at
*read* time, in another repo, and is asserted there. That separation is the
point of item 1 - this SDK sends the caller's name and takes no view on the
vocabulary.

The redirect cases use **two** listeners because a single-listener fixture
cannot express the defect: if the redirector and the target are the same
process, a followed redirect and a refused one are indistinguishable. Each
asserts on what the *second* listener saw, and each carries a positive control
that the *first* one was actually contacted - otherwise "the target saw
nothing" is equally true of a run that never happened.

## Mutation proof

| Mutation | Expected failure |
|---|---|
| `Features: registeredFeatures()` → `[]string{}` in `telemetry.go` | case 1: `features = [], want it to contain adapter:langchain` |
| Drop the length guard in `RegisterAdapter` (truncate instead) | case 3: `the 65-byte name was TRUNCATED to 64 and sent` |
| Remove `CheckRedirect` from the `/health` probe client | case 5: `the redirect TARGET was fetched 1 times` |
| Remove `CheckRedirect` from the checkpoint POST client | case 5: `the redirect TARGET received 1 request(s) (0 carrying a body)` |

All four were run and observed; the last one is also the empirical
demonstration that `net/http` converts a redirected POST into a **bodyless
GET** - the target recorded the request with zero bytes of body, which is the
200-that-delivered-nothing this refusal exists to prevent.
