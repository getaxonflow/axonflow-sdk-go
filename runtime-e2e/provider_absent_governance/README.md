# provider_absent_governance

**Proves** that a community stack with **no LLM provider credential** still
returns a real governance verdict, and that PII detection still runs - from a
real `axonflow.NewClientSimple` in a real process, over real HTTP, against a
real running agent.

**Prereqs**: a running AxonFlow agent. `AXONFLOW_E2E_PLATFORM_ENDPOINT` (or
`AXONFLOW_AGENT_URL`) points at it; defaults to `http://localhost:8080`.
`AXONFLOW_CLIENT_ID` / `AXONFLOW_CLIENT_SECRET` default to the demo pair.

**Run**

```bash
AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 \
  go run runtime-e2e/provider_absent_governance/main.go
```

Executed in CI by the `Integration Tests` job in
`.github/workflows/integration.yml`, against the community stack that job
already boots.

**Asserts**

1. A governed call returns a governance verdict - `policy_info` present with a
   non-empty `static_checks` and a resolved tenant - whether or not a provider
   answered.
2. **The differential**: the PII statement evaluates at least one policy while
   the benign query evaluates none. This is what makes assertion 1
   non-vacuous - an agent returning a constant empty envelope would satisfy 1
   and fail this.
3. The provider-absent predicate does not drift. `examples/basic/main.go`,
   `sdk_integration_test.go` and this leg must identify a missing provider the
   same way, and the predicate must **not** swallow a non-provider failure
   (`policy engine panic`, `unauthorized`, `budget exceeded` are asserted to
   fall through to a real failure).
4. If a provider **is** configured, the full round trip must succeed - so the
   leg does not go permanently blind the day a credential appears.

**Why it exists**

`Run Basic Example` had been red on every push to main: the example called
`log.Fatalf` on `LLM routing failed` from a stack that has no credential to
give it. The repo has no secrets at all, so there is nothing to wire in.

The risk in fixing that is the opposite failure - "make it pass" is one
`|| true` away from a smoke that asserts nothing and reports green. This leg
pins the half that **is** observable without a provider, so the smoke can never
be quietly weakened to a no-op without this going red.
