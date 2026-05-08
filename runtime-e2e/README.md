# SDK runtime tests — axonflow-sdk-go

Per CLAUDE.md HARD RULE #0: a user-facing feature is not done until you
have demonstrated it working through the SDK's actual runtime — a real
`import "github.com/getaxonflow/axonflow-sdk-go/v8"` from a real Go
program with real `net/http` against a real running AxonFlow agent.

**Tests in this directory MUST hit a real endpoint.** No
`httptest.NewServer`, no fixture servers, no capture-stub harnesses.
The `scripts/lint-no-mocks-in-runtime-e2e.sh` lint enforces this; a
forbidden mock pattern fails CI. (If a specific driver legitimately
needs an in-process listener — e.g. to inject a license token the SDK
itself does not surface — mark it inline with `// allow-mocks-here:
<reason>` and justify in PR review.)

## Convention

Each test lives in its own subdirectory like `runtime-e2e/<feature>/`.
Each subdirectory has a `main.go` invokable via `go run`. The driver
file uses `//go:build ignore` so it is excluded from the SDK package's
normal build/`go vet`/`go test` pass — these are runners, not unit
tests.

```
runtime-e2e/
  README.md                      # this file
  <feature>/
    main.go                      # //go:build ignore — invoked via `go run`
```

## How to run locally

Set `AXONFLOW_AGENT_URL` (default `http://localhost:8080`). Bring up a
local agent via the standard E2E setup script (see
`axonflow-internal-docs/engineering/E2E_EXAMPLES_TESTING_WORKFLOW.md`).
Then:

```
export AXONFLOW_AGENT_URL=http://localhost:8080

# Register a community-saas tenant
RESP=$(curl -s -X POST $AXONFLOW_AGENT_URL/api/v1/register \
  -H "Content-Type: application/json" -d '{"label":"sdk-runtime-e2e"}')
export AXONFLOW_TENANT_ID=$(echo "$RESP" | jq -r .tenant_id)
export AXONFLOW_TENANT_SECRET=$(echo "$RESP" | jq -r .secret)

# Mint a plugin-aud token (see x-axonflow-client/ for use)
export AXONFLOW_E2E_PLUGIN_TOKEN=<jwt with aud=axonflow.saas.plugin>

go run runtime-e2e/x-axonflow-client/main.go
```

## What counts as a test

Each `main.go` exits non-zero if the SDK's real wire output to a real
agent isn't what you expect. The strongest evidence pattern is to
capture an agent response that echoes a value the SDK should have sent
(e.g. `X-Axonflow-Client: sdk-go/<version>` reflected back from the
agent's scope-mismatch handler).
