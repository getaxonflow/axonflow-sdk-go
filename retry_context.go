package axonflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PriorCompletionStatus reports the state of the prior gate+complete cycle for a step.
type PriorCompletionStatus string

const (
	// PriorCompletionStatusNone is returned on the first gate call for a step.
	PriorCompletionStatusNone PriorCompletionStatus = "none"

	// PriorCompletionStatusCompleted is returned when a prior gate call and a prior /complete
	// both landed for this (workflow_id, step_id).
	PriorCompletionStatusCompleted PriorCompletionStatus = "completed"

	// PriorCompletionStatusGatedNotCompleted is returned when a prior gate call landed
	// but no /complete has followed yet for this (workflow_id, step_id).
	PriorCompletionStatusGatedNotCompleted PriorCompletionStatus = "gated_not_completed"
)

// RetryContext is the first-class state signal returned on every StepGateResponse.
// It replaces the ambiguous `cached: bool` flag; callers should migrate off `Cached`
// and `DecisionSource` to RetryContext fields.
type RetryContext struct {
	// GateCount is the number of times /gate has been called for this (workflow_id, step_id),
	// including the current call. First call returns 1. Always >= 1.
	GateCount int `json:"gate_count"`

	// CompletionCount is the number of times /complete has been successfully called
	// for this (workflow_id, step_id). Typically 0 on first gate call, 1 after the step completes.
	CompletionCount int `json:"completion_count"`

	// PriorCompletionStatus reports whether a prior gate+complete cycle has landed.
	PriorCompletionStatus PriorCompletionStatus `json:"prior_completion_status"`

	// PriorOutputAvailable is true iff PriorCompletionStatus == PriorCompletionStatusCompleted.
	// Mirrors whether PriorOutput *could* be returned if the caller opts in with
	// StepGateOptions.IncludePriorOutput.
	PriorOutputAvailable bool `json:"prior_output_available"`

	// PriorOutput is the output from the prior /complete, or nil. Non-nil only when the gate
	// call set StepGateOptions.IncludePriorOutput == true AND PriorCompletionStatus == PriorCompletionStatusCompleted.
	PriorOutput map[string]interface{} `json:"prior_output"`

	// PriorCompletionAt is the timestamp of the prior /complete, if any.
	PriorCompletionAt *time.Time `json:"prior_completion_at"`

	// FirstAttemptAt is the timestamp of the first gate call for this (workflow_id, step_id).
	// On the first call, equals LastAttemptAt.
	FirstAttemptAt time.Time `json:"first_attempt_at"`

	// LastAttemptAt is the timestamp of the current gate call (the one that produced this response).
	LastAttemptAt time.Time `json:"last_attempt_at"`

	// LastDecision is the decision of the immediately prior gate call. On the first call
	// (GateCount == 1), equals the current call's Decision field.
	LastDecision GateDecision `json:"last_decision"`

	// IdempotencyKey is the key the caller set on this step (from the first gate call that
	// supplied one), or empty string if the caller never supplied one. Once set, it is immutable.
	IdempotencyKey string `json:"idempotency_key"`
}

// IdempotencyKeyMismatchError is returned when a /gate or /complete request supplies an
// idempotency_key that conflicts with the key recorded on an earlier gate call for the same
// (workflow_id, step_id). Maps to HTTP 409 with error.code == "IDEMPOTENCY_KEY_MISMATCH".
type IdempotencyKeyMismatchError struct {
	// Message is the human-readable error message from the platform.
	Message string

	// WorkflowID is the workflow ID on which the mismatch occurred.
	WorkflowID string

	// StepID is the step ID on which the mismatch occurred.
	StepID string

	// ExpectedIdempotencyKey is the key recorded on the first gate call. Empty string
	// if the gate call had no key but /complete did.
	ExpectedIdempotencyKey string

	// ReceivedIdempotencyKey is the key supplied on the current request. Empty string
	// if /complete omitted a key that gate had set.
	ReceivedIdempotencyKey string
}

func (e *IdempotencyKeyMismatchError) Error() string {
	return fmt.Sprintf("idempotency_key mismatch on workflow=%s step=%s: expected=%q received=%q: %s",
		e.WorkflowID, e.StepID, e.ExpectedIdempotencyKey, e.ReceivedIdempotencyKey, e.Message)
}

// parseIdempotencyKeyMismatch returns a typed *IdempotencyKeyMismatchError if err wraps
// a 409 response with error.code == "IDEMPOTENCY_KEY_MISMATCH", otherwise nil.
func parseIdempotencyKeyMismatch(err error) *IdempotencyKeyMismatchError {
	if err == nil {
		return nil
	}
	var httpErr *httpError
	if !errors.As(err, &httpErr) {
		return nil
	}
	if httpErr.statusCode != 409 {
		return nil
	}

	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details struct {
				WorkflowID             string `json:"workflow_id"`
				StepID                 string `json:"step_id"`
				ExpectedIdempotencyKey string `json:"expected_idempotency_key"`
				ReceivedIdempotencyKey string `json:"received_idempotency_key"`
			} `json:"details"`
		} `json:"error"`
	}
	if jerr := json.Unmarshal([]byte(httpErr.message), &envelope); jerr != nil {
		return nil
	}
	if envelope.Error.Code != "IDEMPOTENCY_KEY_MISMATCH" {
		return nil
	}

	return &IdempotencyKeyMismatchError{
		Message:                envelope.Error.Message,
		WorkflowID:             envelope.Error.Details.WorkflowID,
		StepID:                 envelope.Error.Details.StepID,
		ExpectedIdempotencyKey: envelope.Error.Details.ExpectedIdempotencyKey,
		ReceivedIdempotencyKey: envelope.Error.Details.ReceivedIdempotencyKey,
	}
}
