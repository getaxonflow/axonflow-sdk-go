//go:build ignore

// runtime-e2e/mark_step_completed_metadata/main.go
//
// Real-wire test of MarkStepCompletedRequest.Metadata against a live
// AxonFlow enterprise stack (community v9.6.1 spec, orchestrator-api.yaml
// MarkStepCompletedRequest schema: metadata is a free-form object captured
// at step-completion time, opaque to the client).
//
// Drives the full WCP lifecycle through the SDK's real net/http transport:
//
//  1. CreateWorkflow registers a workflow.
//  2. StepGate gates a step (first-call retry_context invariants).
//  3. MarkStepCompleted sends a body carrying the new metadata field and
//     must get a 2xx back — proving the live orchestrator accepts the
//     spec-declared field rather than rejecting the body.
//  4. Re-gate on the same step must report completion_count=1 /
//     prior_completion_status=completed — proving the /complete call that
//     carried metadata was fully processed, not silently dropped.
//  5. GetWorkflow must show the step recorded.
//
// Note: no read endpoint currently echoes step-completion metadata back
// (the platform treats it as opaque audit context), so presence-on-read
// cannot be asserted; acceptance + processed-completion is the strongest
// live evidence available.
//
// Run via:
//
//	go run runtime-e2e/mark_step_completed_metadata/main.go
//
// Prereqs: a running orchestrator (AXONFLOW_ORCHESTRATOR_URL, default
// http://localhost:8081 — WCP endpoints live on the orchestrator) and
// enterprise credentials in AXONFLOW_CLIENT_ID / AXONFLOW_CLIENT_SECRET.

package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
	endpoint := getenv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081")
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		fail("AXONFLOW_CLIENT_ID / AXONFLOW_CLIENT_SECRET are required (source /tmp/axonflow-e2e-env.sh)")
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	// ---- Step 1: register a workflow.
	wf, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "go-sdk-step-metadata-e2e",
	})
	if err != nil {
		fail("CreateWorkflow: %v", err)
	}
	fmt.Printf("workflow created: %s\n", wf.WorkflowID)

	// ---- Step 2: gate the step.
	gate, err := client.StepGate(wf.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepName: "metadata-step",
		StepType: axonflow.StepTypeToolCall,
	})
	if err != nil {
		fail("StepGate: %v", err)
	}
	if gate.Decision != axonflow.GateDecisionAllow {
		fail("StepGate decision = %q, want allow (reason: %s)", gate.Decision, gate.Reason)
	}
	if gate.RetryContext.CompletionCount != 0 {
		fail("first gate completion_count = %d, want 0", gate.RetryContext.CompletionCount)
	}
	fmt.Printf("gate: decision=%s gate_count=%d completion_count=%d\n",
		gate.Decision, gate.RetryContext.GateCount, gate.RetryContext.CompletionCount)

	// ---- Step 3: complete WITH metadata. A non-2xx surfaces as err here.
	metadata := map[string]interface{}{
		"ticket":              "JIRA-42",
		"approved_by":         "ops-lead",
		"downstream_latency":  183,
		"retry_attempt_count": 1,
	}
	if err := client.MarkStepCompleted(wf.WorkflowID, "step-1", &axonflow.MarkStepCompletedRequest{
		Output:   map[string]interface{}{"result": "success"},
		Metadata: metadata,
	}); err != nil {
		fail("MarkStepCompleted with metadata: %v", err)
	}
	fmt.Printf("PASS: MarkStepCompleted with metadata=%v accepted (2xx)\n", metadata)

	// ---- Step 4: re-gate — the completion carrying metadata must have landed.
	regate, err := client.StepGate(wf.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepType: axonflow.StepTypeToolCall,
	})
	if err != nil {
		fail("re-gate after complete: %v", err)
	}
	if regate.RetryContext.CompletionCount != 1 {
		fail("re-gate completion_count = %d, want 1", regate.RetryContext.CompletionCount)
	}
	if regate.RetryContext.PriorCompletionStatus != axonflow.PriorCompletionStatusCompleted {
		fail("re-gate prior_completion_status = %q, want completed", regate.RetryContext.PriorCompletionStatus)
	}
	fmt.Printf("PASS: re-gate confirms completion processed (completion_count=%d, prior_completion_status=%s)\n",
		regate.RetryContext.CompletionCount, regate.RetryContext.PriorCompletionStatus)

	// ---- Step 5: workflow status read-back shows the step recorded.
	status, err := client.GetWorkflow(wf.WorkflowID)
	if err != nil {
		fail("GetWorkflow: %v", err)
	}
	var found bool
	for _, s := range status.Steps {
		if s.StepID == "step-1" {
			found = true
			break
		}
	}
	if !found {
		fail("GetWorkflow did not list step-1 (steps=%v)", status.Steps)
	}
	fmt.Printf("PASS: GetWorkflow lists step-1 (workflow status=%s)\n", status.Status)

	fmt.Println("PASS: MarkStepCompletedRequest.Metadata live round-trip OK")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
