# `CreateHITLRequest` — runtime-e2e

Real-stack assertion for the cross-SDK
[`CreateHITLRequest`](https://github.com/getaxonflow/axonflow-enterprise/issues/2421)
surface added in Go SDK v8.2.0. Sister proof to the equivalent Python /
TypeScript / Java runtime-e2e tests shipping in the same parity sweep.

## What this proves

Drives `client.CreateHITLRequest(...)` through the real `net/http`
transport against a `net.Listen` server that mimics the platform
handler at `platform/agent/hitl/handler.go:177`. Captures the raw
HTTP body, decodes it, and asserts every required field from
`HITLCreateInput` lands on the wire — including the new `notify_url`
field added in
[#2419](https://github.com/getaxonflow/axonflow-enterprise/issues/2419)
— then asserts the SDK parses the platform's `APIResponse{success,
data}` envelope back into a populated `HITLApprovalRequest`.

No `httptest`, no doubles, no `_test.go` — runs the production
transport against an in-process HTTP server, which is what the
`runtime-e2e/` DoD gate is asking for. Built with `//go:build ignore`
so the file is excluded from the standard `go test ./...` matrix.

## Usage

```bash
go run runtime-e2e/create_hitl_request/main.go
```

Exits `0` on PASS, non-zero on FAIL. Prints captured wire body +
parsed response fields on success for human-readable confirmation.

## Companion unit coverage

`hitl_test.go::TestCreateHITLRequest*` exercises the same surface
through `httptest.NewServer` for six scenarios (happy path
full-fields, minimal required-fields, bad-`NotifyURL`-scheme 400
propagation, 401 propagation, connect-failure propagation, and the
three required-field validation guards). The runtime proof here is
the redundant real-stack confirmation.
