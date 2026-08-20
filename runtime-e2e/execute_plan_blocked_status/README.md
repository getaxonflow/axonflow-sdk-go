# execute_plan_blocked_status

Real-wire driver for the #184 fix: a policy-blocked plan execution
(envelope success:true, blocked:true) must report Status "failed" with the
block reason carried, never "completed". Also pins the clean-success and
envelope-failure verdicts so all three arms of the status derivation are
exercised over the real net/http transport.

Run: `go run runtime-e2e/execute_plan_blocked_status/main.go`
