# v11.0.0 deprecations through the SDK

`main.go` calls the three policy simulation methods the SDK marks deprecated (`SimulatePolicies`, `DetectPolicyConflicts` and `GetPolicyImpactReport`) against a real v11 agent and orchestrator, and reads what `AxonFlowConfig.OnRouteDeprecation` reports. Nothing is mocked.

## What it proves

1. `SimulatePolicies` and `DetectPolicyConflicts` still work. Each route is reported exactly once, with the platform's own signal: `X-AxonFlow-Removed-In: v12.0` and the successor `/api/v1/typed-policies` from the `Link`. The platform adds an RFC 9745 `Deprecation` date (`@<unix seconds>`) once v11.0.0 is tagged and omits it until then, so the leg accepts it absent or well-formed.
2. `GetPolicyImpactReport` is reported the same way.
3. A second call of each reports nothing new: once per route per client.

## Why the impact report is proved on its signal, not on a result

The platform evaluates the named policy from the organization's tenant policies. A fresh organization has none, and a v11 platform refuses to create one (the legacy write freeze). The lookup is the tenant policy store (`PolicyService.TestPolicy`, orchestrator `policy_api_service.go:391`). So on a fresh v11 stack the call names a policy that cannot exist, and the leg asserts only that the platform refuses it with a non-2xx (today a `500 INTERNAL_ERROR`, tracked in getaxonflow/axonflow-enterprise#4223), so a fix to that status leaves this leg green. The deprecation is stamped whatever the handler answers, and that is what this leg proves for the route. On an organization that still holds legacy tenant policies, the call returns its report until v12.0.

## Running it

The simulation routes are registered from the Evaluation licence up, so boot an enterprise stack from the platform's main (`scripts/setup-e2e-testing.sh production-posture`). Then, from the repository root, with the credentials that script writes:

```
AXONFLOW_AGENT_URL=http://localhost:8080 \
AXONFLOW_CLIENT_ID=<org id> AXONFLOW_CLIENT_SECRET=<licence> \
go run runtime-e2e/v11_deprecations/main.go
```
