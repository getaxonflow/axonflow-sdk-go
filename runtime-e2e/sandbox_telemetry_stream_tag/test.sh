#!/usr/bin/env bash
# Runtime proof — Go SDK v8 sandbox-mode telemetry fires with stream=sandbox.
#
# Builds a tiny Go program that uses the LOCAL SDK (via go.mod replace)
# in sandbox mode against an unreachable agent endpoint. The SDK fires
# its anonymous telemetry ping during NewClient. We then query the
# deployed checkpoint Lambda's CloudWatch logs for the audit line that
# should record stream=sandbox in DynamoDB.
#
# Pre-v8 this test would have produced ZERO pings (sandbox-mode silent
# suppression). Post-v8 we expect exactly one ping with stream=sandbox.
#
# Stack-state assumptions:
#   - axonflow-enterprise PR #2005 is deployed (server-side stream allowlist
#     accepts and persists "sandbox" — without that, this row is stored
#     as stream=heartbeat, defeating the test's purpose).
#   - AWS credentials with read access on /aws/lambda/prod-axonflow-checkpoint.
#
# Usage:
#   AWS_REGION=us-east-1 ./test.sh

set -uo pipefail

REGION=${AWS_REGION:-us-east-1}
LOG_GROUP=${LOG_GROUP:-/aws/lambda/prod-axonflow-checkpoint}
RUN_TAG=$(date -u +%s)
SDK_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

# Build a transient Go program that imports the local SDK + creates a
# Sandbox client. The unreachable :65530 endpoint is intentional — we
# only want the anonymous heartbeat to fire, not any platform call.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/go.mod" <<EOF
module sandbox-rt-${RUN_TAG}

go 1.21

require github.com/getaxonflow/axonflow-sdk-go/v9 v9.0.0-00010101000000-000000000000

replace github.com/getaxonflow/axonflow-sdk-go/v9 => ${SDK_ROOT}
EOF

cat > "$WORK/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	_ = os.Unsetenv("AXONFLOW_TELEMETRY")
	fmt.Printf("[%s] Constructing Sandbox client (unreachable agent)...\n", time.Now().Format(time.RFC3339))
	c := axonflow.Sandbox("rt-test")
	_ = c
	fmt.Printf("[%s] NewClient returned. Sleeping 2s for inflight HTTP...\n", time.Now().Format(time.RFC3339))
	time.Sleep(2 * time.Second)
	fmt.Printf("[%s] Done.\n", time.Now().Format(time.RFC3339))
}
EOF

T0_MS=$(($(date -u +%s)*1000))
echo "Run tag: $RUN_TAG"
echo "T0 (ms): $T0_MS"
echo

(
	cd "$WORK"
	go mod tidy 2>&1 | tail -3
	go run main.go 2>&1
)

echo
echo "Waiting 10s for CloudWatch log delivery..."
sleep 10

# Look for the audit row our run produced — match by sdk=go and a fresh
# correlation_id stamped within the last ~1 minute window.
echo "Querying CloudWatch logs since T0 for sdk=go event_stored entries..."
HITS=$(aws --region "$REGION" logs filter-log-events \
	--log-group-name "$LOG_GROUP" \
	--start-time "$T0_MS" \
	--filter-pattern '"event_stored" "sdk=go/8"' \
	--query 'events[*].message' \
	--output text 2>&1)

if [ -z "$HITS" ]; then
	red "FAIL: no event_stored sdk=go/8 row landed in checkpoint logs since T0"
	red "  Expected: one audit row tagged stream=sandbox"
	red "  CloudWatch query window: $T0_MS → now"
	exit 1
fi

echo "Audit rows found:"
echo "$HITS"
echo

if echo "$HITS" | grep -q 'stream=sandbox'; then
	green "PASS: Go SDK sandbox-mode ping landed with stream=sandbox"
else
	red "FAIL: audit row did not include stream=sandbox"
	red "  This usually means PR #2005 (server-side allowlist) is not yet deployed —"
	red "  the server still hardcodes stream=heartbeat regardless of payload."
	exit 1
fi
