# AuthZEN migration notes - DRAFT, not yet in effect

**Status: DRAFT. Nothing here is deprecated today.**

This file is written now and published later on purpose. The deprecation it
describes is a **v11.0.0** event; the surface it describes shipped in v10.3.0 so
that customers have a migration target *during* the shadow window rather than
being handed one at the moment the default flips. Publishing the notice early
would tell people to move off something that is not going anywhere for two
releases.

Keep it in the repository, out of the README, until the v11 release train picks
it up. The reviewer's question for any edit here is "is this true on the day
v11 ships", not "is this true today".

## Timeline

| Release | The legacy decision surface | The AuthZEN surface |
|---|---|---|
| v10.3.0 (now) | Fully supported. Not deprecated. No warnings. | New. Available. Recommended for new integrations. |
| v10.3.x | Unchanged. | Unchanged. |
| **v11.0.0** | **Deprecated.** Still works; wire-stable. Doc + release-note notice. | The engine behind it becomes the ADR-065 Policy Decision Point. **No wire change.** |
| v12.0.0 | **Removed.** | The only decision surface. |

The legacy surface is **wire-stable through all of v11**. A v10.x integration
keeps working on v11 without edits; deprecation is a signal to plan, not a
breakage.

## Why migrate at all

Not because the old surface stops working - it does not, until v12. Because of
what happens *underneath* each of them at v11.

At v11 the engine behind `Evaluate` becomes the new Policy Decision Point. An
integration already speaking AuthZEN gets that with **no code change**. An
integration still on the legacy surface will eventually make the same move, but
at v12, under time pressure, and with the wire shape changing at the same time.

So the choice is one migration or two. That is the whole argument.

## What changes at the call site

The legacy surface asks "here is a stage, a target and a query - what is the
verdict?". The AuthZEN surface asks "may this subject perform this action on
this resource?". The mapping is mechanical:

| Legacy | AuthZEN |
|---|---|
| `stage: "llm"` | `Action.Name: "llm.completion"` + `Resource.Type: "llm"` |
| `stage: "tool"` | `Action.Name: "tool.call"` + `Resource.Type: "tool"` |
| `stage: "agent"` | `Action.Name: "agent.invoke"` + `Resource.Type: "agent"` |
| `caller_identity.gateway_id` | `Subject{Type: "gateway", ID: ...}` |
| `target.provider` + `target.model` | `Resource.ID: "provider/model"` |
| `target.server` + `target.tool` | `Resource.ID: "server/tool"` |
| `query` | `Context["args"]["query"]` |
| `verdict: "allow"` | `Decision: true` / `State: ALLOW` |
| `verdict: "deny"` | `Decision: false` / `State: DENY` |
| `verdict: "needs_approval"` | `Decision: false` / `State: CHALLENGE` |
| `obligations[]` | `Context.Obligations[]` |

## The one behavioural difference to plan for

**The AuthZEN surface refuses what it cannot evaluate. The legacy surface
ignored it.**

A legacy caller could attach any `context` map; unrecognised keys were dropped
and the evaluation proceeded. The AuthZEN surface returns a typed refusal naming
the member instead.

This is a deliberate improvement and it is the only thing likely to surprise a
migrating integration. Code that was quietly sending fields nothing read will
start getting `422`s that name those fields. That is the surface telling you
something true which was previously hidden: those attributes were never
considered.

Handle it by branching on the refusal rather than treating every error as a
deny:

```go
dec, err := client.Evaluate(ctx, req)
if azErr, ok := axonflow.AsAuthZENError(err); ok {
    // A refusal is NOT a denial. The request was never evaluated.
    // azErr.Pointer names the member to remove or move.
    // Only azErr.Code.Retryable() is worth a retry.
}
```

Treating a refusal as a deny is safe (it fails closed) but will block traffic
that should have been allowed once the request is corrected.

## Not yet expressible

An **end-user subject**. `Subject.Type` must be `gateway` today, because an
end-user subject would have to be trusted from caller-supplied JSON - an
impersonation surface - or silently dropped, which is the fail-open this surface
exists to prevent. It arrives with the identity plane at v11. Integrations that
authorize per end user should stay on the legacy `user_token` path until then.

## Checklist for the v11 release train

- [ ] Move this file's content into the README and the public docs site.
- [ ] Add the deprecation notice to the legacy methods' doc comments.
- [ ] Confirm the removal release named here is still v12.0.0.
- [ ] Confirm the end-user subject is supported, and delete the section above if so.
- [ ] Cross-check the mapping table against the adapter, which is the
      authoritative source: `platform/agent/authzen_adapter.go`.
