# PEP capability handshake: the platform reads the SDK's declaration

`main.go` drives the SDK's public surface against a real AxonFlow agent. It asserts, from the agent's own metrics, that the `X-Axonflow-PEP-Handshake` declaration the SDK sends is decoded and admitted on every plane that reads it.

## What it proves

After each call the driver reads `axonflow_pep_handshake_total{outcome, plane}` from the agent's `/prometheus` endpoint. The agent moves that counter once per inbound request on the four planes that resolve the declaration, so each assertion is a fact the agent recorded.

| Call | Expected movement |
|---|---|
| `Decide` | `accepted` on `decision` |
| `Evaluate`, `EvaluateAll` | `accepted` on `access_evaluation` |
| `MCPCheckInput`, `MCPCheckOutput`, `FulfillRequest`'s engine round-trip | `accepted` on `mcp` |
| `PreCheckWithContext` | `accepted` on `gateway` |
| `Decide` with a per-call declaration naming `approval_challenge` | `over_advertised` on `decision` on a Community agent, which drops that family; `accepted` on any other edition |
| `Decide` from a client with no declaration | `absent` on `decision` |

Each call must move exactly the one series listed, by exactly one. `accepted` means the agent decoded the SDK's bytes, validated the document and admitted the enforcement point. A malformed or repeated header would have been refused with a 400 and counted as `malformed`.

## What it does not prove

The consequence of a declaration differs by edition. On Enterprise, an allow verdict carrying a mandatory obligation the declared set cannot discharge becomes a deny. On Community, the declaration is recorded and does not deny. That rule is the platform's own, and the platform's suites prove it. This driver proves the declaration arrives and is admitted, which is the SDK's part.

`ProxyLLMCall` (`/api/request`) and the OpenAI-compatible route do not read the header, and the SDK does not send it there. The unit tests in `pep_handshake_test.go` assert that absence on the wire.

## Running it

Boot an agent from the platform's main (any edition), then:

```
AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_CLIENT_ID=runtime-e2e AXONFLOW_CLIENT_SECRET=runtime-e2e-secret \
AXONFLOW_USER_TOKEN=<a per-user JWT> \
go run runtime-e2e/pep_handshake_planes/main.go
```

On an enterprise agent the pre-check validates its user token as a JWT, so pass the per-user token `scripts/setup-e2e-testing.sh` writes as `AXONFLOW_USER_TOKEN`. The driver reads the agent's edition from `/health` to choose the per-call leg's expected outcome. It needs no other state: nothing is written, and the counter deltas are read around each call. Run it against an agent no other client is using, since a concurrent request on one of the four planes would move the counter too.
