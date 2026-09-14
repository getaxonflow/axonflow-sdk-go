# Typed policy authoring through the SDK

`main.go` drives the six typed policy methods (`TypedPolicyEdition`, `ValidateTypedPolicy`, `PublishTypedPolicy`, `ActivateTypedPolicy`, `ActiveTypedPolicy` and `TypedPolicySystem`) against a real agent and orchestrator. Nothing is mocked.

## What it proves

On a fresh stack, in order:

1. Nothing is active yet: `ActiveTypedPolicy` answers `(nil, nil)` from the platform's 404.
2. `TypedPolicyEdition` reports the deployment's boundary, and `TypedPolicySystem` the shipped controls with their digest.
3. The document the platform's own route test proves publishable validates clean, publishes to a digest, and activates.
4. `ActiveTypedPolicy` returns that document as the exact signed source. The platform overwrites the author: the document deliberately names `someone-else`, and the platform signs the caller the agent resolved.
5. Activating the same digest again is a typed 409 `activation_refused`: activation promotes, and the version does not advance.
6. Publishing with no fixtures is a typed 422 `publication_refused` whose message names the missing fixtures.
7. A document naming an action the registry does not hold validates with the platform's rejecting finding (`ACTION_NOT_REGISTERED` on `grant.refund`), and publishing it is a typed 422 `document_refused` carrying that finding.

The document is `testdata/typed_policy_publish_body.json`, byte-identical to axonflow-sdk-python's `tests/fixtures/typed_policy_publish_body.json`: the body the platform's own route test proves publishable, marshalled by the platform's own types. Its `document_id` is made unique per run.

## What it does not prove

Rolling back and withdrawing are customer portal operations the agent does not proxy, so the SDK has no method for either. An edition with separation of duties refuses every publication through this route with `APPROVER_IS_AUTHOR`; the unit tests cover that refusal's shape, and this driver runs on Community, which has no separation of duties.

Two members are covered by unit tests only. `TypedPolicyRefusal.Policy`, the policy a tier refusal names, needs a deployment at its tier ceiling. `TemplateOmissionsUnavailable`, the reason the platform could not produce the omission report, needs a document store that cannot be read. This driver sets up neither.

## Running it

Boot a community stack from the platform's main with the agent and orchestrator on the application database role, so it behaves as a deployment does. Then, from the repository root:

```
AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_CLIENT_ID=runtime-e2e AXONFLOW_CLIENT_SECRET=runtime-e2e-secret \
go run runtime-e2e/typed_policies/main.go
```

Run it against a fresh stack: the first assertion needs nothing active on the organization, and each run activates a document.
