# read_path_identity - per-user identity on the READ path (platform #2922)

Real-wire proof, through the Go SDK's own runtime against a **live enterprise
stack**, that `ExplainDecision` and `ListDecisions` are scoped to the identity
the caller presents - and that the SDK reports the three outcomes honestly
instead of collapsing them into "nothing there".

## The defect this pins

All five SDKs carried `user_token` as a **write-path body field only**, so both
read methods asked the platform anonymously. On an enterprise stack that is not
"a caller who sees everything" - it is a caller the platform cannot scope. The
consequence, measured live on this stack before the fix:

```
$ curl -H "Authorization: Basic $AUTH" .../api/v1/decisions?limit=5
HTTP/1.1 200 OK
X-Axonflow-Read-Scope: none
{"decisions":[]}
```

A `200` with an empty page. Indistinguishable, to the caller, from a tenant that
has made no decisions - and `explain` answered `404` for ids that plainly
existed. The same requests with `X-User-Token` return `own-rows` or `tenant`
and the data.

## What the driver asserts

| # | Step | Why it cannot pass vacuously |
|---|---|---|
| 1 | Write 3 decisions as dev-a through the real `/decide` plane | - |
| 2 | List as dev-a, then **dev-b writes one** | Floor is **the number this run wrote**, and each id is checked **by id** - a stale row or a lucky non-empty page cannot satisfy it. The floor alone still cannot tell own-rows from tenant-wide, so dev-b then writes a row of its own and dev-a's page must **not grow** |
| 3 | Explain as dev-a | Asserts a context value **this run chose**, not merely "non-empty" |
| 4 | List with **no identity** | Must be a typed `ReadScopeError` with `IdentityMissing`, never `[]` + `nil`. A stack that returns rows here fails loudly - every other scoping assertion would be vacuous |
| 5 | Explain dev-a's decision **as dev-b** | Must refuse, and must **not** report a missing identity - dev-b presented one. Reporting the wrong cause fails the step |
| 6 | **Malformed / expired / another-org** tokens | Each must fail **closed** with 401 and must not echo the credential. A rejected identity degrading to "no identity" would hand back the tenant credential's visibility |
| 7 | Explain as **admin** | Without it, step 5 is unfalsifiable: a read broken for everyone also "refuses dev-b" |
| 8 | No leak | The token must appear in **no** log byte and in **no** request reaching the telemetry collector this driver hosts. `Debug` is **on** and a **positive control** asserts SDK output is present *before* the grep — otherwise "absent" is a claim about an empty haystack, true of every string. Fails if the collector received nothing |
| 9 | Observable | The orchestrator must have **recorded** the unscoped read. Failing closed with no platform-side record is only half the property |

## Two traps this driver exists to not fall into

**Identities are minted at `@example.com`, never `@axonflow.local`.** The
platform reserves that whole domain (and `@axonflow.internal`) for *shared,
non-personal* identities and censuses them to nothing before scoping
(`IsSharedSyntheticIdentity`). A perfectly valid developer token minted at
`@axonflow.local` reads **zero rows** and reports scope `none` - identical to
presenting no token at all. Verified on this stack: the same token differing
only in domain yields `none` vs `own-rows`. `generate-jwt.sh`'s own default
(`demo-user@axonflow.local`) lands in the reserved domain, so a driver built on
it would prove nothing about own-rows scoping while appearing to pass.

**The write leg goes through `client.Decide`, not a hand-rolled POST.** A driver
that hand-posts the write leg is testing curl on that leg — the SDK's own
request shape, headers and encoding go unexercised. It is also the evidence for
the corrected "inert on the write path" claim: `/api/v1/decide` is not proxied,
so the `X-User-Token` a client stamps is genuinely ignored there and attribution
comes from the body's `user_token`. On every route the agent *does* proxy, the
header is validated and a bad one is a 401 — which is why the write leg uses a
client with **no** client-level identity.

**Tokens are minted in-process, not taken from `AXONFLOW_USER_TOKEN`.** The
scoping assertions need *several distinct* identities - two developers, an
admin, an expired one, one from another org. A single shared env token cannot
express them, and the setup script's token is `role=admin`, which short-circuits
to tenant-wide and would make steps 4-7 untestable.

## Run

```bash
# 1. Bring up the enterprise stack FROM THE axonflow-enterprise CHECKOUT, per
#    axonflow-internal-docs/engineering/E2E_EXAMPLES_TESTING_WORKFLOW.md
(cd /path/to/axonflow-enterprise && ./scripts/setup-e2e-testing.sh enterprise)

# 2. Then run the driver FROM THIS REPO's root.
set -a; source /tmp/axonflow-e2e-env.sh; set +a
export AXONFLOW_AGENT_URL=http://localhost:8080
go run runtime-e2e/read_path_identity/main.go
```

Env: `AXONFLOW_AGENT_URL`, `AXONFLOW_CLIENT_ID`, `AXONFLOW_CLIENT_SECRET`,
`JWT_SECRET` (or `AXONFLOW_JWT_SECRET`). Optional `AXONFLOW_ORCH_CONTAINER`
(default `axonflow-orchestrator`) for step 9.

Exits non-zero on the first failed assertion.
