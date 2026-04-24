#!/usr/bin/env bash
# Validates that the Go SDK version constant(s) match the latest
# released version in CHANGELOG.md. Patterned on the AxonFlow
# platform's script of the same name.
#
# Purpose: keep the repo's manifest (version.go) in lock-step with the
# CHANGELOG so the state on `main` always matches the most recent
# published tag. Prevents the v5.6.0-shipped-but-repo-says-5.6.0-too
# sync, AND the worse v5.6.1-shipped-but-repo-still-says-5.6.0 drift.
#
# Run locally:
#   ./.github/scripts/validate-version-alignment.sh
#
# CI: runs on every PR and push to main that touches CHANGELOG.md or
# any file carrying the version constant.

set -euo pipefail

ERRORS=0

# Latest RELEASED version = first `## [x.y.z]` line that isn't the
# Keep-a-Changelog "[Unreleased]" placeholder. The Unreleased section
# accumulates in-flight changes between tags and must not be used as
# the expected-version target — the manifest only gets bumped when we
# actually cut a tag.
LATEST_VERSION=$(grep -m1 -E '^## \[[0-9]' CHANGELOG.md | sed 's/## \[\(.*\)\].*/\1/' | sed 's/^v//')

if [ -z "${LATEST_VERSION:-}" ]; then
    echo "❌ Could not extract a released version (## [X.Y.Z]) from CHANGELOG.md"
    exit 1
fi

echo "📋 Latest CHANGELOG version: $LATEST_VERSION"
echo ""

# Check version.go::Version.
echo "🔧 Checking version.go..."
VER_GO=$(grep -E '^const Version = "[0-9]' version.go | sed 's/.*"\(.*\)".*/\1/' || true)
if [ -z "${VER_GO:-}" ]; then
    echo "  ❌ version.go — could not read const Version"
    ERRORS=$((ERRORS + 1))
elif [ "$VER_GO" != "$LATEST_VERSION" ]; then
    echo "  ❌ version.go — const Version is \"$VER_GO\", expected \"$LATEST_VERSION\""
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ version.go — $VER_GO"
fi

echo ""

if [ "$ERRORS" -gt 0 ]; then
    echo "❌ Found $ERRORS version misalignment(s)."
    echo ""
    echo "Fix: bump the stale file(s) to match CHANGELOG v$LATEST_VERSION."
    echo "Or, if CHANGELOG is behind a tag you already pushed, add the"
    echo "missing '## [${VER_GO:-X.Y.Z}] - YYYY-MM-DD' section."
    exit 1
fi

echo "✅ All version constants match CHANGELOG v$LATEST_VERSION."
