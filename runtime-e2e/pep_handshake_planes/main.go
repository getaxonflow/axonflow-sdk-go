//go:build ignore

// runtime-e2e/pep_handshake_planes/main.go
//
// Real-stack proof that the platform READS the SDK's PEP capability
// declaration on every plane that resolves it. After each governed call the
// driver reads the agent's own counter, axonflow_pep_handshake_total{outcome,
// plane} on /prometheus, which the agent moves once per inbound request on the
// four planes that resolve the declaration. Nothing is mocked.
//
//	Decide                                  accepted on decision
//	Evaluate, EvaluateAll                   accepted on access_evaluation
//	MCPCheckInput, MCPCheckOutput,
//	FulfillRequest's engine round-trip      accepted on mcp
//	PreCheckWithContext                     accepted on gateway
//	Decide with a per-call declaration      over_advertised on decision on a
//	  naming approval_challenge             Community agent (which drops that
//	                                        family), accepted on any other
//	Decide from a client with no declaration absent on decision
//
// Each call must move exactly the one series listed, by exactly one.
// "accepted" means the agent decoded the SDK's bytes, validated the document
// and admitted the enforcement point; a malformed or repeated header would have
// been refused with a 400 and counted as "malformed".
//
// Run against an agent no other client is using, since a concurrent request on
// one of the four planes would move the counter too:
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 \
//	AXONFLOW_CLIENT_ID=runtime-e2e AXONFLOW_CLIENT_SECRET=runtime-e2e-secret \
//	AXONFLOW_USER_TOKEN=<a per-user JWT> \
//	go run runtime-e2e/pep_handshake_planes/main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var (
	endpoint = env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	failures []string
	series   = regexp.MustCompile(`^axonflow_pep_handshake_total\{([^}]*)\}\s+(\S+)$`)
	label    = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

type key struct{ outcome, plane string }

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func check(ok bool, description string) {
	if ok {
		fmt.Printf("PASS: %s\n", description)
		return
	}
	fmt.Printf("FAIL: %s\n", description)
	failures = append(failures, description)
}

// scrape reads the agent's handshake counter, keyed by (outcome, plane).
func scrape() (map[key]float64, error) {
	resp, err := http.Get(endpoint + "/prometheus")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /prometheus: HTTP %d", resp.StatusCode)
	}
	counts := map[key]float64{}
	lines := bufio.NewScanner(resp.Body)
	lines.Buffer(make([]byte, 1<<20), 1<<20)
	for lines.Scan() {
		m := series.FindStringSubmatch(lines.Text())
		if m == nil {
			continue
		}
		labels := map[string]string{}
		for _, l := range label.FindAllStringSubmatch(m[1], -1) {
			labels[l[1]] = l[2]
		}
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			return nil, err
		}
		counts[key{labels["outcome"], labels["plane"]}] = v
	}
	return counts, lines.Err()
}

func moved(before, after map[key]float64) map[key]float64 {
	out := map[key]float64{}
	for k, v := range after {
		if v != before[k] {
			out[k] = v - before[k]
		}
	}
	for k, v := range before {
		if _, ok := after[k]; !ok {
			out[k] = -v
		}
	}
	return out
}

func render(counts map[key]float64) string {
	parts := make([]string, 0, len(counts))
	for k, n := range counts {
		parts = append(parts, fmt.Sprintf("%s@%s +%g", k.outcome, k.plane, n))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// counted runs call and requires it to move exactly the one series in want.
func counted(description string, call func() error, want key) {
	fmt.Printf("== %s\n", description)
	before, err := scrape()
	if err != nil {
		check(false, fmt.Sprintf("%s: scrape before: %v", description, err))
		return
	}
	if err := call(); err != nil {
		check(false, fmt.Sprintf("%s returned %v", description, err))
		return
	}
	after, err := scrape()
	if err != nil {
		check(false, fmt.Sprintf("%s: scrape after: %v", description, err))
		return
	}
	got := moved(before, after)
	fmt.Printf("  the agent counted %s\n", render(got))
	check(len(got) == 1 && got[want] == 1, fmt.Sprintf("%s: %s@%s +1", description, want.outcome, want.plane))
}

func mustHandshake(pepID string, capabilities []axonflow.PEPCapability) *axonflow.PEPHandshake {
	h, err := axonflow.NewPEPHandshake(pepID, "https://pep.example.test", capabilities)
	if err != nil {
		fmt.Printf("FAIL: build the declaration %s: %v\n", pepID, err)
		os.Exit(1)
	}
	return h
}

func main() {
	var health struct {
		Edition string `json:"edition"`
	}
	if resp, err := http.Get(endpoint + "/health"); err == nil {
		_ = json.NewDecoder(resp.Body).Decode(&health)
		resp.Body.Close()
	}
	fmt.Printf("agent: %s (edition %q)\n", endpoint, health.Edition)
	// The platform drops approval-family capabilities only for a Community
	// enforcement point; any other edition admits the per-call document whole.
	overrideOutcome := "accepted"
	if health.Edition == "community" {
		overrideOutcome = "over_advertised"
	}

	declared := mustHandshake("sdk-go-e2e", []axonflow.PEPCapability{{Type: axonflow.AuthZENObligationTypeFieldRedact, Version: 1}})
	override := mustHandshake("sdk-go-e2e-override", []axonflow.PEPCapability{
		{Type: axonflow.AuthZENObligationTypeApprovalChallenge, Version: 1},
		{Type: axonflow.AuthZENObligationTypeFieldRedact, Version: 1},
	})
	config := axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     env("AXONFLOW_CLIENT_ID", "runtime-e2e"),
		ClientSecret: env("AXONFLOW_CLIENT_SECRET", "runtime-e2e-secret"),
	}
	bare := axonflow.NewClient(config)
	config.PEPHandshake = declared
	client := axonflow.NewClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	query := "look up the weather"
	decide := axonflow.DecideRequest{Stage: "tool", Query: query, Target: axonflow.DecisionTarget{Type: "tool", Tool: "search"}}
	subject := &axonflow.AuthZENSubject{Type: "gateway", ID: "sdk-go-e2e"}
	action := &axonflow.AuthZENAction{Name: "llm.completion"}
	args := map[string]any{"args": map[string]any{"query": query}}
	// A decision carrying the request-phase redaction obligation, so
	// FulfillRequest makes its engine round-trip to the real agent.
	redacting := &axonflow.DecideResponse{
		Verdict: axonflow.VerdictAllow, DecisionID: "sdk-go-e2e", Stage: "tool",
		Obligations: []axonflow.Obligation{{
			Type: axonflow.ObligationRedactPII,
			Fulfillment: &axonflow.ObligationFulfillment{
				Endpoint: "/api/v1/mcp/check-input", Method: "POST",
				Phase: axonflow.PhaseRequest, ContentTypes: []string{axonflow.ContentTypeText},
			},
		}},
	}

	counted("Decide", func() error { _, err := client.Decide(ctx, decide); return err }, key{"accepted", "decision"})
	counted("Evaluate", func() error {
		_, err := client.Evaluate(ctx, axonflow.AuthZENRequest{
			Subject: subject, Action: action, Resource: &axonflow.AuthZENResource{Type: "llm", ID: "llm"}, Context: args,
		})
		return err
	}, key{"accepted", "access_evaluation"})
	counted("EvaluateAll", func() error {
		_, err := client.EvaluateAll(ctx, axonflow.AuthZENBulk{
			Subject: subject, Action: action, Context: args,
			Evaluations: []axonflow.AuthZENRequest{{Resource: &axonflow.AuthZENResource{Type: "llm", ID: "llm"}}},
		})
		return err
	}, key{"accepted", "access_evaluation"})
	counted("MCPCheckInput", func() error {
		_, err := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{ConnectorType: "postgres", Statement: "SELECT 1"})
		return err
	}, key{"accepted", "mcp"})
	counted("MCPCheckOutput", func() error {
		_, err := client.MCPCheckOutput(ctx, axonflow.MCPCheckOutputRequest{ConnectorType: "postgres", Message: "hello"})
		return err
	}, key{"accepted", "mcp"})
	counted("PreCheckWithContext", func() error {
		// An enterprise agent validates the pre-check's user token as a JWT.
		_, err := client.PreCheckWithContext(ctx, env("AXONFLOW_USER_TOKEN", "tok"), "hello", nil, nil)
		return err
	}, key{"accepted", "gateway"})
	counted("FulfillRequest", func() error {
		_, _, err := client.FulfillRequest(ctx, redacting, "email the receipt to jane.doe@example.com")
		return err
	}, key{"accepted", "mcp"})
	counted("Decide with a per-call declaration", func() error {
		_, err := client.Decide(axonflow.ContextWithPEPHandshake(ctx, override), decide)
		return err
	}, key{overrideOutcome, "decision"})
	counted("Decide with no declaration", func() error { _, err := bare.Decide(ctx, decide); return err }, key{"absent", "decision"})

	if len(failures) > 0 {
		fmt.Printf("\nFAIL: pep_handshake_planes (%d assertion(s))\n", len(failures))
		os.Exit(1)
	}
	fmt.Println("\nPASS: pep_handshake_planes")
}
