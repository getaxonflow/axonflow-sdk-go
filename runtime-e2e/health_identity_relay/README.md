# health_identity_relay

**Proves** the SDK relays the platform's `edition` and its own `deployment_mode`
from `/health` onto the heartbeat as `edition` and `platform_deployment_mode`
(axonflow-enterprise#3660), over real HTTP, from a real
`axonflow.NewClient` in a real process.

**Prereqs**: none for the matrix mode. `AXONFLOW_E2E_PLATFORM_ENDPOINT` for the
real-platform mode.

**Run**

```bash
# matrix: every relay path and every not-learned path, local stand-ins
go run runtime-e2e/health_identity_relay/main.go

# real platform: cross-check the wire against a live agent's own /health
AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
  go run runtime-e2e/health_identity_relay/main.go
```

**Asserts**

1. Both members reach the wire **verbatim**, on the **right fields**.
2. **The mapping trap**: the ping's own `deployment_mode` still carries the
   SDK-derived topology, never the platform's own mode. The two dimensions share
   a name across the two documents, so a relay that promotes `/health`'s member
   into the field of the same name looks correct and silently overwrites a value
   every existing deployment-mode dashboard reads.
3. Both keys are **absent** — not empty, not defaulted — on every not-learned
   path (pre-10.4.0 platform, platform down, 500, non-JSON, empty, null,
   badly-typed), and the ping is still **delivered** on each.
4. A badly-typed new member does not regress its neighbours: `"edition": 42`
   must leave `platform_version`, `license_tier` and the sibling member intact.

A pre-10.4.0 platform is an **assertion**, not a skip: most agents in the field
serve neither member, and the contract for that case is that the ping carries
neither key.

**Each case runs in a fresh child process.** The shared heartbeat is a
process-global singleton, so one process emits at most one ping however many
clients it builds — driving the matrix in-process would silently assert against
the first case's body every time.

**Mutation proofs** are listed at the top of `main.go`; each was run.
