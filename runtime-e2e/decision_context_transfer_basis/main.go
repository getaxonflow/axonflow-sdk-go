//go:build ignore

// runtime-e2e/decision_context_transfer_basis/main.go
//
// Real-wire test of the v8.4.0 SDK surface against a running AxonFlow agent
// (platform v8.5.0, epic #2508):
//
//  1. DecisionSummary.Context — the sanitized request context a PEP attaches
//     to a Decision Mode call (POST /api/v1/decide), surfaced back through
//     ListDecisions + ExplainDecision. We act as the PEP via raw HTTP (the
//     decide endpoint is intentionally NOT SDK-wrapped — ADR-056), then read
//     the decision back through the SDK and assert Context round-trips.
//  2. AuditLogEntry.TransferBasis = "pasal_56b_dpa" — Pasal 56(b) explicit DPA
//     tag round-trips through serialize → deserialize without information loss.
//
// Run via:
//   go run runtime-e2e/decision_context_transfer_basis/main.go
//
// Prereqs: a running agent (AXONFLOW_AGENT_URL, default http://localhost:8080).
// AXONFLOW_TENANT_ID / AXONFLOW_TENANT_SECRET default to a community client.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
	endpoint := getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getenv("AXONFLOW_TENANT_ID", "buku-e-go-e2e")
	secret := getenv("AXONFLOW_TENANT_SECRET", "buku-e-secret")

	// ---- Step 1: act as the PEP — create a decision carrying request context.
	wantCtx := map[string]string{
		"x_ai_agent":        "refund-bot",
		"x_session_id":      "sess-buku-42",
		"x_leader_identity": "ops-lead",
	}
	decisionID, raw, err := createDecisionWithContext(endpoint, clientID, secret)
	if err != nil {
		fail("create decision (PEP/raw HTTP): %v", err)
	}
	fmt.Printf("PEP decide → decision_id=%s\n", decisionID)
	fmt.Printf("server /decide response: %s\n", raw)

	// ---- Step 2: read it back through the SDK's ListDecisions.
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: secret,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rows, err := client.ListDecisions(ctx, axonflow.ListDecisionsOptions{Limit: 5})
	if err != nil {
		fail("SDK ListDecisions: %v", err)
	}
	var found *axonflow.DecisionSummary
	for i := range rows {
		if rows[i].DecisionID == decisionID {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		fail("SDK ListDecisions did not return decision %s (got %d rows)", decisionID, len(rows))
	}
	dump, _ := json.Marshal(found)
	fmt.Printf("SDK ListDecisions → %s\n", dump)
	for k, v := range wantCtx {
		if found.Context[k] != v {
			fail("ListDecisions context[%q] = %q, want %q (full: %v)", k, found.Context[k], v, found.Context)
		}
	}
	fmt.Printf("PASS: ListDecisions DecisionSummary.Context populated with %d PEP-forwarded keys\n", len(found.Context))

	// ---- Step 3: full context via ExplainDecision.
	exp, err := client.ExplainDecision(ctx, decisionID)
	if err != nil {
		fail("SDK ExplainDecision: %v", err)
	}
	expDump, _ := json.Marshal(map[string]any{"context": exp.Context, "context_truncated": exp.ContextTruncated})
	fmt.Printf("SDK ExplainDecision → %s\n", expDump)
	for k, v := range wantCtx {
		if exp.Context[k] != v {
			fail("ExplainDecision context[%q] = %q, want %q", k, exp.Context[k], v)
		}
	}
	fmt.Printf("PASS: ExplainDecision returned full Context (context_truncated=%v)\n", exp.ContextTruncated)

	// ---- Step 4: transfer_basis = pasal_56b_dpa round-trip (Pasal 56(b)).
	entry := axonflow.AuditLogEntry{
		ID:            "e2e-audit",
		Timestamp:     time.Now().UTC(),
		DataResidency: "ID",
		TransferBasis: axonflow.TransferBasisPasal56bDPA,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		fail("marshal AuditLogEntry: %v", err)
	}
	var back axonflow.AuditLogEntry
	if err := json.Unmarshal(b, &back); err != nil {
		fail("unmarshal AuditLogEntry: %v", err)
	}
	if back.TransferBasis != "pasal_56b_dpa" {
		fail("transfer_basis round-trip = %q, want pasal_56b_dpa (verbatim, never auto-translated)", back.TransferBasis)
	}
	fmt.Printf("SDK AuditLogEntry round-trip → %s\n", b)
	fmt.Printf("PASS: AuditLogEntry.TransferBasis = %q round-trips verbatim\n", back.TransferBasis)

	fmt.Println("ALL PASS: v8.4.0 Context + pasal_56b_dpa verified through SDK runtime")
}

// createDecisionWithContext calls POST /api/v1/decide as the PEP would —
// the request context lives in the body's `context` map; the platform
// canonicalizes the keys (x-ai-agent → x_ai_agent) and persists them.
func createDecisionWithContext(endpoint, clientID, secret string) (string, string, error) {
	body := map[string]any{
		"stage":  "llm",
		"query":  "summarize this support ticket",
		"target": map[string]any{"type": "llm", "model": "gpt-4", "provider": "openai"},
		"context": map[string]any{
			"x-ai-agent":        "refund-bot",
			"x-session-id":      "sess-buku-42",
			"x-leader-identity": "ops-lead",
		},
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", endpoint+"/api/v1/decide", bytes.NewReader(buf))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-ID", clientID)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("decide HTTP %d: %s", resp.StatusCode, rb)
	}
	var out struct {
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", "", err
	}
	if out.DecisionID == "" {
		return "", "", fmt.Errorf("no decision_id in response: %s", rb)
	}
	return out.DecisionID, string(rb), nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
