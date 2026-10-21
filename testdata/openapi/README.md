# OpenAPI schema snapshot for the wire-shape contract

The wire-shape contract (`contract_wire_shape_test.go`, run by `.github/workflows/wire-shape-contract.yml`) diffs the Go SDK's exported structs against the platform's OpenAPI specs. It reads the schema declarations under `components.schemas` and the names of each one's `properties`.

The four files here hold exactly that, and nothing else. `scripts/snapshot_openapi_schemas.py` derives them from the platform's `docs/api/*.yaml` at platform commit `ba5201a52edd2bfbe9f1dadd736f19cae03d9cc4`, the merged platform source for the v11.2.0 train. The script is vendored byte-identical from axonflow-sdk-python (`756f06136`), and the four files are byte-identical to that repository's `tests/fixtures/openapi/`, so both SDKs pin the same contract.

The script works on the YAML node graph, so every declaration survives in source order, including a schema declared twice in one file and a declaration with no properties. It drops descriptions, types, paths and the `info` block: the full specs carry the platform's own licence statement there, and this repository is MIT. It refuses a YAML merge key under `schemas` or `properties`, since loaders disagree on expanding one.

Each file's generated header names the platform commit it was derived from. The refresh records that commit as the baseline's `openapi_specs_sha`, and `TestWireShapeSnapshotMatchesThePin` fails when the two disagree, so the baseline cannot name a revision the snapshot does not hold.

Regenerating `testdata/wire_shape_baseline.json` from these files gives a byte-identical baseline to regenerating it from the full specs, so nothing the contract checks is lost.

## Checking

    python scripts/snapshot_openapi_schemas.py --self-test
    python scripts/snapshot_openapi_schemas.py --check-snapshot testdata/openapi
    AXONFLOW_OPENAPI_SPECS_DIR=$PWD/testdata/openapi go test -run TestWireShape .

## Moving the pin

A change to the pinned SHA or to any file here needs the `spec-pin-bump` label on its pull request.

    python scripts/snapshot_openapi_schemas.py <platform-checkout>/docs/api testdata/openapi --source-commit <SHA>
    go run ./scripts/refresh_wire_shape_baseline testdata/openapi

| File | sha256 of the source spec |
|---|---|
| `agent-api.yaml` | `617e6236f91dd7716baaab8e2f22ef24f1713ebfd4938cc52a60a3368e3acb1a` |
| `masfeat-api.yaml` | `eb224773c2a14fc6a84a630b652b17e010a4776da28529b13e173b002d2d4756` |
| `orchestrator-api.yaml` | `a1f96d929ff35acb1204ce5ba3c6e605b8f91d93e7fa62a2fa8a760ea8486860` |
| `policy-api.yaml` | `a1a7aff59d759033f99721a40d942e8750c6026d69f9efb0edf66016f0069ae9` |

