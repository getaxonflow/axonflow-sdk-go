# OpenAPI schema snapshot for the wire-shape contract

The wire-shape contract (`contract_wire_shape_test.go`, run by `.github/workflows/wire-shape-contract.yml`) diffs the Go SDK's exported structs against the platform's OpenAPI specs. It reads the schema declarations under `components.schemas` and the names of each one's `properties`.

The four files here hold exactly that, and nothing else. `scripts/snapshot_openapi_schemas.py` derives them from the platform's `docs/api/*.yaml` at platform commit `36e0e96b7e5c16626d394272b727b533f2b94a04`, the v11.0.0 candidate. The script is vendored byte-identical from axonflow-sdk-python (`756f06136`), and the four files are byte-identical to that repository's `tests/fixtures/openapi/`, so both SDKs pin the same contract.

The script works on the YAML node graph, so every declaration survives in source order, including a schema declared twice in one file and a declaration with no properties. It drops descriptions, types, paths and the `info` block: the full specs carry the platform's own licence statement there, and this repository is MIT. It refuses a YAML merge key under `schemas` or `properties`, since loaders disagree on expanding one.

Regenerating `testdata/wire_shape_baseline.json` from these files gives a byte-identical baseline to regenerating it from the full specs, so nothing the contract checks is lost.

## Checking

    python scripts/snapshot_openapi_schemas.py --self-test
    python scripts/snapshot_openapi_schemas.py --check-snapshot testdata/openapi
    AXONFLOW_OPENAPI_SPECS_DIR=$PWD/testdata/openapi go test -run TestWireShape .

## Moving the pin

A change to the pinned SHA or to any file here needs the `spec-pin-bump` label on its pull request.

    python scripts/snapshot_openapi_schemas.py <platform-checkout>/docs/api testdata/openapi --source-commit <SHA>
    go run ./scripts/refresh_wire_shape_baseline --sha <SHA> testdata/openapi

| File | sha256 of the source spec |
|---|---|
| `agent-api.yaml` | `49bd1b145cd3b2d29e8cc8de240cc184d4f5d24f83b6c546894d1f0a682a032a` |
| `masfeat-api.yaml` | `2d49d6af2d5b1510b373c01fce1df2b712b32766b14d477652797746c52147e7` |
| `orchestrator-api.yaml` | `b173c9bec456e4af3aa09c63306e503caa73ca0cf61da3dfaa7b21453dcd1188` |
| `policy-api.yaml` | `090730a359bf242b6ed5c1a0d63a2831c749583bd957cc3ecc64c99ead5514b7` |

