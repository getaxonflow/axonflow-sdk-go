# Contributing to AxonFlow Go SDK

Thank you for your interest in contributing to the AxonFlow Go SDK! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/axonflow-go.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test ./...`
6. Commit your changes: `git commit -m "Add your feature"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

```bash
git clone https://github.com/getaxonflow/axonflow-go.git
cd axonflow-go
go mod download
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...
```

### Wire-shape contract tests

When you add or rename an exported struct whose type name matches an
OpenAPI schema in the platform specs, a CI job diffs the JSON tags
against the spec and fails the PR on drift. This is enforced by
`contract_wire_shape_test.go` (opt-in via the `AXONFLOW_OPENAPI_SPECS_DIR`
env var).

Run locally:

```bash
# Clone the community mirror — the specs live in docs/api/
git clone https://github.com/getaxonflow/axonflow.git ../axonflow

# Point the test at the specs dir and run only wire-shape tests
AXONFLOW_OPENAPI_SPECS_DIR=../axonflow/docs/api \
  go test -v -run "TestWireShape" .
```

Without the env var, the tests skip cleanly — a plain `go test ./...`
doesn't need the specs.

If you legitimately need to update the acknowledged baseline (e.g. a
drift entry was burned down, or a new acknowledged divergence was
added), regenerate it with:

```bash
# Pinning the SHA picks up the current HEAD of the community mirror.
# Alternately pass --sha <commit-sha> to pin explicitly.
go run ./scripts/refresh_wire_shape_baseline ../axonflow/docs/api
```

Never regenerate to silence a failure without understanding what drifted;
that defeats the gate.

#### Bumping `openapi_specs_sha`

The wire-shape gate pins the OpenAPI spec revision via
`openapi_specs_sha` in the baseline so a given SDK commit always diffs
against the same spec. Changing that SHA in the same PR that changes
SDK structs can silently retarget the gate past drift it should have
caught, so the CI job enforces an extra guardrail: any PR that moves
`openapi_specs_sha` must also carry the `spec-pin-bump` label, which
surfaces the bump for explicit review.

Recommended flow:

1. Open a dedicated PR that updates only `openapi_specs_sha` (and the
   parts of the baseline that change as a consequence: drift entries,
   cross-spec shapes).
2. Apply the `spec-pin-bump` label.
3. Merge.
4. Follow up with the SDK-side changes that the new spec enables.

If it's genuinely one change (platform + SDK shipping together), apply
the label to the single PR — the label just signals the reviewer to
scrutinise the SHA move.

### Running Examples

Set up your environment variables:

```bash
export AXONFLOW_AGENT_URL="http://localhost:8080"  # Local docker-compose default
export AXONFLOW_CLIENT_ID="your-client-id"
export AXONFLOW_CLIENT_SECRET="your-client-secret"
```

Run examples:

```bash
# Basic example
go run examples/basic/main.go

# Connectors example
go run examples/connectors/main.go

# Planning example
go run examples/planning/main.go
```

## Code Style

- Follow standard Go formatting: `go fmt ./...`
- Run linting: `go vet ./...`
- Keep functions focused and well-documented
- Use meaningful variable and function names
- Add comments for exported functions and types

## Pull Request Guidelines

1. **Keep PRs focused**: One feature or fix per PR
2. **Update documentation**: If you change the API, update README.md
3. **Add tests**: All new features should include tests
4. **Pass CI checks**: Ensure all tests pass before submitting
5. **Write clear commit messages**: Describe what and why, not how

### Commit Message Format

```
Add feature: brief description

Detailed explanation of the changes and why they were made.
Any breaking changes should be clearly noted.
```

## Feature Requests

Have an idea for a new feature? We'd love to hear it!

1. Check existing issues to avoid duplicates
2. Open a new issue with the "Feature Request" label
3. Describe the feature and its use case
4. Discuss implementation approach

## Bug Reports

Found a bug? Help us fix it!

1. Check existing issues to avoid duplicates
2. Open a new issue with the "Bug" label
3. Include:
   - Go version
   - Operating system
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Error messages or logs

## Testing

We use Go's built-in testing framework. When adding new features:

1. Add unit tests for new functions
2. Add integration tests for API interactions
3. Ensure test coverage remains high
4. Mock external dependencies when appropriate

Example test structure:

```go
func TestClientProxyLLMCall(t *testing.T) {
    client := NewClientSimple("https://example.com", "id", "secret")

    resp, err := client.ProxyLLMCall("token", "query", "chat", nil)

    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }

    if resp == nil {
        t.Error("Expected response, got nil")
    }
}
```

## Documentation

- Update README.md for user-facing changes
- Add GoDoc comments for all exported functions and types
- Include usage examples in comments when helpful
- Keep documentation clear and concise

## Code Review Process

1. All PRs require at least one approval
2. Maintainers will review your PR within 3-5 business days
3. Address feedback and update your PR
4. Once approved, a maintainer will merge your PR

## Baseline burndown policy

The wire-shape contract gate uses a baseline file (`testdata/wire_shape_baseline.json`) to grandfather pre-existing drift findings — the gate fails on any *new* drift but tolerates the listed entries. The baseline exists to land the gate without a giant cleanup PR; it is not intended to be permanent.

When your PR touches a type listed in the baseline, do one of:

- **Burn it down.** Realign the struct with the OpenAPI spec in this PR, regenerate the baseline (`go run ./scripts/refresh_wire_shape_baseline ../axonflow/docs/api`), and note "burndown: `<entry>`" in the PR description.
- **Justify it.** If the drift can't be resolved in this PR (different scope, blocked on a platform spec change, etc.), say so in the PR description in one line.

CI does not block PRs that touch a baselined type without addressing it, but reviewers will ask the burndown-or-justify question.

## License

By contributing to AxonFlow Go SDK, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have questions about contributing, feel free to:

- Open a discussion on GitHub
- Email us at hello@getaxonflow.com
- Check our documentation at https://docs.getaxonflow.com

Thank you for contributing to AxonFlow!
