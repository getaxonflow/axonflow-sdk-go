//go:build ignore

// runtime-e2e/decide_fulfill_obligation/main.go
//
// Real-stack assertion: Decision Mode PEP decide -> fulfill -> forward
// (getaxonflow/axonflow-enterprise#2571 / epic #2563).
//
// Per CLAUDE.md HARD RULE #0 this driver MUST hit a real running AxonFlow agent
// — no httptest, no fixture servers. It proves the engine-fulfillable obligation
// contract end to end through a real net/http round-trip:
//
//  1. client.Decide(...) on a PII-bearing request returns verdict=allow with a
//     self-describing redact_pii obligation whose fulfillment names the
//     check-input engine endpoint (request phase, text/plain).
//  2. client.FulfillRequest(...) discharges it by round-tripping the statement
//     through that engine endpoint and returns ENGINE-redacted content — the
//     original email + card no longer appear, and the masking is the engine's
//     (the SDK contains no local redaction path).
//  3. client.DecideAndFulfill(...) does both in one call.
//  4. Demo / wrong credentials are refused (HTTP 401); the PEP cannot decide with
//     credentials the enterprise PDP does not accept.
//
// Enterprise auth is HTTP Basic (org:license) — the SDK builds it from
// ClientID + ClientSecret.
//
// Run locally (after `source /tmp/axonflow-e2e-env.sh` from the enterprise
// setup script):
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 \
//	AXONFLOW_CLIENT_ID="$AXONFLOW_CLIENT_ID" \
//	AXONFLOW_CLIENT_SECRET="$AXONFLOW_CLIENT_SECRET" \
//	go run runtime-e2e/decide_fulfill_obligation/main.go

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

// The PII the request carries. The engine's redactor must mask the email + card;
// neither raw value may survive into the fulfilled content.
const (
	rawEmail = "john.doe@example.com"
	rawCard  = "4111111111111111"
)

var query = fmt.Sprintf("Send the receipt to %s and charge card %s", rawEmail, rawCard)

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "FAIL: %s\n", msg)
	os.Exit(1)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	endpoint := envOr("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "required env not set: AXONFLOW_CLIENT_ID + AXONFLOW_CLIENT_SECRET; see file header")
		os.Exit(2)
	}

	ctx := context.Background()
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Mode:         "production",
	})

	// 1. Decide() surfaces the engine-fulfillable redact_pii obligation.
	decision, err := client.Decide(ctx, axonflow.DecideRequest{
		Stage:          "tool",
		Query:          query,
		Target:         axonflow.DecisionTarget{Type: "tool", Tool: "send_receipt"},
		CallerIdentity: axonflow.DecisionCallerIdentity{GatewayID: "sdk-runtime-e2e"},
	})
	if err != nil {
		fail(fmt.Sprintf("Decide returned error: %v", err))
	}
	fmt.Printf("decide -> verdict=%s obligations=%d trace_id=%s\n", decision.Verdict, len(decision.Obligations), decision.TraceID)
	if decision.Verdict != axonflow.VerdictAllow {
		fail(fmt.Sprintf("expected allow, got %s (%s)", decision.Verdict, decision.Error))
	}
	if decision.TraceID == "" {
		fail("decide response did not surface a trace_id")
	}
	if !axonflow.HasRequestRedaction(decision.Obligations) {
		fail(fmt.Sprintf("no request-phase redact_pii obligation on a PII request; got %+v", decision.Obligations))
	}
	var ful *axonflow.ObligationFulfillment
	for _, o := range decision.Obligations {
		if o.Type == axonflow.ObligationRedactPII {
			ful = o.Fulfillment
			break
		}
	}
	if ful == nil || ful.Phase != axonflow.PhaseRequest {
		fail(fmt.Sprintf("obligation not request-phase engine-fulfillable: %+v", ful))
	}
	if !strings.Contains(ful.Endpoint, "check-input") {
		fail(fmt.Sprintf("fulfillment endpoint is not the request-redaction endpoint: %s", ful.Endpoint))
	}
	fmt.Printf("  obligation fulfillment -> %s phase=%s types=%v\n", ful.Endpoint, ful.Phase, ful.ContentTypes)

	// 2. FulfillRequest() returns ENGINE-redacted content; raw PII is gone.
	content, didRedact, err := client.FulfillRequest(ctx, decision, query)
	if err != nil {
		if errors.Is(err, axonflow.ErrObligationNotFulfillable) {
			fail(fmt.Sprintf("obligation unexpectedly not fulfillable against real agent: %v", err))
		}
		fail(fmt.Sprintf("FulfillRequest returned error: %v", err))
	}
	fmt.Printf("fulfill_request -> did_redact=%v content=%q\n", didRedact, content)
	if !didRedact {
		fail("engine reported no redaction on a request that carries PII")
	}
	if strings.Contains(content, rawEmail) {
		fail(fmt.Sprintf("raw email survived fulfillment — PII leak: %q", content))
	}
	if strings.Contains(content, rawCard) {
		fail(fmt.Sprintf("raw card survived fulfillment — PII leak: %q", content))
	}
	if content == query {
		fail("fulfilled content is byte-identical to the unredacted query")
	}

	// 3. DecideAndFulfill() one-call path yields the same masked content.
	verdict, oneCall, _, err := client.DecideAndFulfill(ctx, axonflow.DecideRequest{
		Stage:  "tool",
		Query:  query,
		Target: axonflow.DecisionTarget{Type: "tool", Tool: "send_receipt"},
	})
	if err != nil {
		fail(fmt.Sprintf("DecideAndFulfill returned error: %v", err))
	}
	fmt.Printf("decide_and_fulfill -> verdict=%s content=%q\n", verdict, oneCall)
	if verdict != axonflow.VerdictAllow {
		fail(fmt.Sprintf("decide_and_fulfill verdict %s, expected allow", verdict))
	}
	if strings.Contains(oneCall, rawEmail) || strings.Contains(oneCall, rawCard) {
		fail(fmt.Sprintf("decide_and_fulfill leaked PII: %q", oneCall))
	}
	if oneCall == query {
		fail("decide_and_fulfill content is byte-identical to the unredacted query")
	}

	// 4. Demo / wrong credentials are refused by the enterprise PDP.
	badClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     "demo-org",
		ClientSecret: "demo-license-not-real",
		Mode:         "production",
	})
	_, err = badClient.Decide(ctx, axonflow.DecideRequest{Stage: "tool", Query: "hi"})
	if err == nil {
		fail("demo credentials were NOT refused by the PDP")
	}
	if !strings.Contains(err.Error(), "401") {
		fail(fmt.Sprintf("demo creds error did not surface a 401: %v", err))
	}
	fmt.Println("demo creds -> 401 (refused) OK")

	fmt.Println("PASS: decide -> fulfill -> forward verified against real agent")
}
