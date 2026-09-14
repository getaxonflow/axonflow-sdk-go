#!/usr/bin/env bash
# Runtime proof: examples/pep_handshake and examples/typed_policies, built from
# this tree, against a LIVE Community agent, in the order the README gives:
# the handshake example first. NO mocks. The examples run from a temporary
# directory outside the tree with no body file: typed_policies embeds its
# default document.
#
# Precondition, checked with curl rather than the SDK: no typed document is
# active (GET /api/v1/typed-policies/active answers 404 nothing_active).
# Otherwise the leg stops with exit 2: it changes the organization's active
# policy, so it needs a fresh stack.
#
#   1. pep_handshake: exits 0, the first decide is allowed, and the declaration
#      the platform would refuse fails in the client at /pep_id, before
#      anything is sent.
#   2. typed_policies without publishing (the README's default): exits 0, and
#      ActiveTypedPolicy reads the platform's nothing_active as nothing active.
#   3. typed_policies with AXONFLOW_TYPED_POLICY_PUBLISH=1: exits 0, prints the
#      publication's template-omission report BEFORE it activates, and the
#      document is published and activated.
#   4. typed_policies asked to publish a document the save-time checks reject:
#      exits 1, printing the platform's typed 422 document_refused.
#   5. typed_policies publishing the same document again: the publication is a
#      new artifact of the same document version, so the activation is refused
#      (a typed 409 activation_refused, since activation promotes), and the
#      example exits 1.
#   6. pep_handshake again: printed as an OBSERVATION, not asserted. After run
#      3 activates a document with an organization-scope constraint, a decide
#      that does not supply the attribute the constraint conditions on is
#      denied fail-closed with reasons ["unknown_constraint"]. From v11.0.0 the
#      deny's first reason is that code, followed by one naming each constraint
#      it could not evaluate and the attribute it needed
#      (getaxonflow/axonflow-enterprise#4247).
#
# Credentials are left unset: Decide names the client id as the caller's
# organization, and on Community the organization is the deployment's.
#
#   AXONFLOW_ENDPOINT=http://localhost:8080 ./runtime-e2e/v11_examples/run.sh
#
# Exit codes: 0 all proofs passed; 1 a proof failed; 2 the agent is not
# reachable, or a typed document is already active.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
unset AXONFLOW_CLIENT_ID AXONFLOW_CLIENT_SECRET
export AXONFLOW_ENDPOINT="$ENDPOINT" AXONFLOW_TELEMETRY=off

if ! timeout 60 bash -c "until curl -sf --max-time 5 ${ENDPOINT}/health > /dev/null; do sleep 2; done"; then
  echo "FAIL: agent at ${ENDPOINT} did not become healthy within 60s"
  exit 2
fi

OUT="$(mktemp -d "${TMPDIR:-/tmp}/v11-examples.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
# Built first and outside the timeouts, so a cold build does not count against
# a run.
(cd "$ROOT" && go build -o "$OUT/pep_handshake" ./examples/pep_handshake && go build -o "$OUT/typed_policies" ./examples/typed_policies) || {
  echo "FAIL: the examples did not build"
  exit 1
}

echo "=== precondition: no typed document is active"
code=$(curl -s --max-time 10 -o "$OUT/active.json" -w '%{http_code}' "${ENDPOINT}/api/v1/typed-policies/active")
reason=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("reason",""))' "$OUT/active.json" 2>/dev/null || true)
if [ "$code" != 404 ] || [ "$reason" != nothing_active ]; then
  echo "FAIL: a typed document is already active, or the route did not answer nothing_active (HTTP $code, reason '$reason'): run this leg on a fresh stack"
  exit 2
fi
echo "ok: HTTP 404 nothing_active"

FAILURES=0
check() {
  if [ "$1" = ok ]; then echo "PASS: $2"; else echo "FAIL: $2"; FAILURES=$((FAILURES + 1)); fi
}
# Runs one built example from $OUT, outside the tree, with extra environment,
# prints its output, and returns its exit code.
run_example() {
  local example=$1 log=$2
  shift 2
  (cd "$OUT" && env "$@" timeout 120 "./$example") > "$log" 2>&1
  local rc=$?
  sed 's/^/  | /' "$log"
  return "$rc"
}

echo "=== 1. pep_handshake on a fresh stack"
rc=0; run_example pep_handshake "$OUT/1.log" || rc=$?
check "$([ "$rc" = 0 ] && echo ok)" "pep_handshake exits 0 (exit $rc)"
# The verdict of the first decide, the one under the client's declaration.
first=$(awk '/^=== decide with the client.s declaration ===/ {f = 1; next}
  f && /^verdict=/ {sub(/ .*/, ""); print; exit}
  f && /^===/ {exit}' "$OUT/1.log")
check "$([ "$first" = verdict=allow ] && echo ok)" "the first decide is allowed on a fresh stack ($first)"
check "$(grep -q '^refused at /pep_id: ' "$OUT/1.log" && echo ok)" \
  "the declaration the platform would refuse fails in the client, at /pep_id, before anything is sent"

echo "=== 2. typed_policies without publishing, as the README runs it"
rc=0; run_example typed_policies "$OUT/2.log" || rc=$?
check "$([ "$rc" = 0 ] && echo ok)" "typed_policies exits 0 without publishing (exit $rc)"
check "$(grep -qx 'nothing is active' "$OUT/2.log" && echo ok)" \
  "ActiveTypedPolicy reads the platform's nothing_active as nothing active"

echo "=== 3. typed_policies with AXONFLOW_TYPED_POLICY_PUBLISH=1, as the README runs it"
rc=0; run_example typed_policies "$OUT/3.log" AXONFLOW_TYPED_POLICY_PUBLISH=1 || rc=$?
check "$([ "$rc" = 0 ] && echo ok)" "typed_policies exits 0 (exit $rc)"
omissions=$(grep -n -m1 '^template omissions: ' "$OUT/3.log" | cut -d: -f1)
activated=$(grep -n -m1 -x 'activated' "$OUT/3.log" | cut -d: -f1)
check "$([ -n "$omissions" ] && [ -n "$activated" ] && [ "$omissions" -lt "$activated" ] && echo ok)" \
  "it prints the publication's template-omission report before it activates"
check "$([ -n "$activated" ] && echo ok)" "the document is published and activated"

echo "=== 4. typed_policies asked to publish a document the save-time checks reject"
# The vendored body with one action the registry does not contain: the same
# edit runtime-e2e/typed_policies makes to it.
python3 - "$ROOT/testdata/typed_policy_publish_body.json" "$OUT/refused_body.json" <<'PY' || { echo "FAIL: could not write the refused body"; exit 1; }
import json, sys
body = json.load(open(sys.argv[1]))
body["document"]["metadata"]["document_id"] = "v11-examples-refused"
body["document"]["policy"]["policies"][0]["actions"]["actions"][0]["local"] = "tool.not_registered"
json.dump(body, open(sys.argv[2], "w"))
PY
rc=0; run_example typed_policies "$OUT/4.log" \
  AXONFLOW_TYPED_POLICY_PUBLISH=1 AXONFLOW_TYPED_POLICY_BODY="$OUT/refused_body.json" || rc=$?
check "$([ "$rc" = 1 ] && echo ok)" "typed_policies exits 1 when the publication it asked for is refused (exit $rc)"
check "$(grep -q '^refused: HTTP 422 document_refused: ' "$OUT/4.log" && echo ok)" \
  "it prints the platform's typed 422 document_refused"

echo "=== 5. typed_policies publishing the same document again"
rc=0; run_example typed_policies "$OUT/5.log" AXONFLOW_TYPED_POLICY_PUBLISH=1 || rc=$?
check "$([ "$rc" = 1 ] && echo ok)" "typed_policies exits 1 when the activation it asked for is refused (exit $rc)"
check "$(grep -q '^published ' "$OUT/5.log" && echo ok)" \
  "the second publication is accepted: a new artifact of the same document version"
check "$(grep -q '^activation refused: HTTP 409 activation_refused: ' "$OUT/5.log" && echo ok)" \
  "it prints the platform's typed 409 activation_refused"

echo "=== 6. OBSERVATION, not asserted: pep_handshake after the activation"
run_example pep_handshake "$OUT/6.log" || true
echo "  observed: $(grep -m1 -oE '^verdict=.*' "$OUT/6.log" || echo 'no verdict printed')"

if [ "$FAILURES" -gt 0 ]; then
  echo
  echo "FAIL: v11_examples ($FAILURES assertion(s))"
  exit 1
fi
echo
echo "PASS: v11_examples"
