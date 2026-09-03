// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ============================================================================
// StreamExecutionStatus SSE Tests
// ============================================================================

func TestStreamExecutionStatus(t *testing.T) {
	now := time.Now()
	events := []ExecutionStatus{
		{
			ExecutionID:     "exec_stream_1",
			ExecutionType:   ExecutionTypeMAP,
			Name:            "test-plan",
			Status:          ExecutionStatusRunning,
			ProgressPercent: 33.3,
			TotalSteps:      3,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		{
			ExecutionID:     "exec_stream_1",
			ExecutionType:   ExecutionTypeMAP,
			Name:            "test-plan",
			Status:          ExecutionStatusRunning,
			ProgressPercent: 66.7,
			TotalSteps:      3,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		{
			ExecutionID:     "exec_stream_1",
			ExecutionType:   ExecutionTypeMAP,
			Name:            "test-plan",
			Status:          ExecutionStatusCompleted,
			ProgressPercent: 100.0,
			TotalSteps:      3,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		expectedPath := "/api/v1/unified/executions/exec_stream_1/stream"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("Expected Accept: text/event-stream, got %s", r.Header.Get("Accept"))
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support Flusher")
		}

		for _, event := range events {
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	ctx := context.Background()
	statusCh, errCh, err := client.StreamExecutionStatus(ctx, "exec_stream_1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var received []ExecutionStatus
	for status := range statusCh {
		received = append(received, status)
	}

	// Check for errors
	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("Unexpected stream error: %v", streamErr)
	}

	if len(received) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(received))
	}
	if received[0].ProgressPercent != 33.3 {
		t.Errorf("Event 0 progress = %v, want 33.3", received[0].ProgressPercent)
	}
	if received[1].ProgressPercent != 66.7 {
		t.Errorf("Event 1 progress = %v, want 66.7", received[1].ProgressPercent)
	}
	if received[2].Status != ExecutionStatusCompleted {
		t.Errorf("Event 2 status = %v, want completed", received[2].Status)
	}
}

func TestStreamExecutionStatusEmptyID(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		Endpoint: "http://localhost",
		ClientID: "test",
	})

	_, _, err := client.StreamExecutionStatus(context.Background(), "")
	if err == nil {
		t.Error("Expected error for empty execution ID")
	}
}

func TestStreamExecutionStatusServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	_, _, err := client.StreamExecutionStatus(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error for server error response")
	}
	if httpErr, ok := err.(*httpError); ok {
		if httpErr.statusCode != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", httpErr.statusCode)
		}
	}
}

func TestStreamExecutionStatusContextCancellation(t *testing.T) {
	now := time.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support Flusher")
		}

		// Send one event, then keep connection open
		event := ExecutionStatus{
			ExecutionID:     "exec_cancel_test",
			ExecutionType:   ExecutionTypeWCP,
			Name:            "long-workflow",
			Status:          ExecutionStatusRunning,
			ProgressPercent: 10.0,
			TotalSteps:      10,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()

		// Keep the connection open until the client disconnects
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	statusCh, errCh, err := client.StreamExecutionStatus(ctx, "exec_cancel_test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Read first event
	status, ok := <-statusCh
	if !ok {
		t.Fatal("Expected to receive at least one event")
	}
	if status.Status != ExecutionStatusRunning {
		t.Errorf("Expected running status, got %s", status.Status)
	}

	// Cancel the context
	cancel()

	// Drain remaining events
	for range statusCh {
	}

	// Error channel should have context error
	streamErr := <-errCh
	if streamErr != nil && streamErr != context.Canceled {
		// It's okay if the error is nil (server closed cleanly)
		// or context.Canceled. Anything else is unexpected.
		t.Logf("Stream error (acceptable): %v", streamErr)
	}
}

func TestStreamExecutionStatusSSEComments(t *testing.T) {
	now := time.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support Flusher")
		}

		// Send SSE comments (keep-alive) and empty lines before data
		fmt.Fprintf(w, ": keep-alive\n\n")
		flusher.Flush()

		fmt.Fprintf(w, "\n")
		flusher.Flush()

		event := ExecutionStatus{
			ExecutionID:     "exec_comment_test",
			ExecutionType:   ExecutionTypeMAP,
			Name:            "comment-test",
			Status:          ExecutionStatusCompleted,
			ProgressPercent: 100.0,
			TotalSteps:      1,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	statusCh, errCh, err := client.StreamExecutionStatus(context.Background(), "exec_comment_test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var received []ExecutionStatus
	for status := range statusCh {
		received = append(received, status)
	}

	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("Unexpected stream error: %v", streamErr)
	}

	// Should only receive the actual data event, not comments or empty lines
	if len(received) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(received))
	}
	if received[0].Status != ExecutionStatusCompleted {
		t.Errorf("Expected completed status, got %s", received[0].Status)
	}
}

func TestStreamExecutionStatusInvalidJSON(t *testing.T) {
	now := time.Now()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support Flusher")
		}

		// Send invalid JSON (should be skipped)
		fmt.Fprintf(w, "data: {invalid json}\n\n")
		flusher.Flush()

		// Then send a valid event
		event := ExecutionStatus{
			ExecutionID:     "exec_json_test",
			ExecutionType:   ExecutionTypeWCP,
			Name:            "json-test",
			Status:          ExecutionStatusCompleted,
			ProgressPercent: 100.0,
			TotalSteps:      1,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	statusCh, errCh, err := client.StreamExecutionStatus(context.Background(), "exec_json_test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var received []ExecutionStatus
	for status := range statusCh {
		received = append(received, status)
	}

	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("Unexpected stream error: %v", streamErr)
	}

	// Invalid JSON should be skipped; only the valid event received
	if len(received) != 1 {
		t.Fatalf("Expected 1 event (invalid skipped), got %d", len(received))
	}
	if received[0].ExecutionID != "exec_json_test" {
		t.Errorf("Expected exec_json_test, got %s", received[0].ExecutionID)
	}
}

func TestStreamExecutionStatusWithSteps(t *testing.T) {
	now := time.Now()
	cost := 0.05

	event := ExecutionStatus{
		ExecutionID:      "exec_steps_test",
		ExecutionType:    ExecutionTypeWCP,
		Name:             "workflow-with-steps",
		Status:           ExecutionStatusCompleted,
		CurrentStepIndex: 1,
		TotalSteps:       2,
		ProgressPercent:  100.0,
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
		Steps: []UnifiedStepStatus{
			{
				StepID:    "step-1",
				StepIndex: 0,
				StepName:  "LLM Call",
				StepType:  UnifiedStepTypeLLMCall,
				Status:    StepStatusCompleted,
				Model:     "gpt-4",
				Provider:  "openai",
				CostUSD:   &cost,
			},
			{
				StepID:    "step-2",
				StepIndex: 1,
				StepName:  "Gate Check",
				StepType:  UnifiedStepTypeGate,
				Status:    StepStatusCompleted,
				Decision:  UnifiedGateDecisionAllow,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support Flusher")
		}

		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	statusCh, errCh, err := client.StreamExecutionStatus(context.Background(), "exec_steps_test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var received []ExecutionStatus
	for status := range statusCh {
		received = append(received, status)
	}

	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("Unexpected stream error: %v", streamErr)
	}

	if len(received) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(received))
	}

	status := received[0]
	if len(status.Steps) != 2 {
		t.Fatalf("Expected 2 steps, got %d", len(status.Steps))
	}
	if status.Steps[0].StepName != "LLM Call" {
		t.Errorf("Step 0 name = %s, want LLM Call", status.Steps[0].StepName)
	}
	if status.Steps[0].Model != "gpt-4" {
		t.Errorf("Step 0 model = %s, want gpt-4", status.Steps[0].Model)
	}
	if status.Steps[1].Decision != UnifiedGateDecisionAllow {
		t.Errorf("Step 1 decision = %s, want allow", status.Steps[1].Decision)
	}
	if status.TotalCost() != 0.05 {
		t.Errorf("TotalCost = %v, want 0.05", status.TotalCost())
	}
}

func TestStreamExecutionStatusFailedTerminal(t *testing.T) {
	now := time.Now()
	events := []ExecutionStatus{
		{
			ExecutionID:     "exec_fail_test",
			ExecutionType:   ExecutionTypeMAP,
			Name:            "failing-plan",
			Status:          ExecutionStatusRunning,
			ProgressPercent: 50.0,
			TotalSteps:      2,
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		{
			ExecutionID:     "exec_fail_test",
			ExecutionType:   ExecutionTypeMAP,
			Name:            "failing-plan",
			Status:          ExecutionStatusFailed,
			ProgressPercent: 50.0,
			TotalSteps:      2,
			Error:           "Step 2 failed: LLM timeout",
			StartedAt:       now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support Flusher")
		}

		for _, event := range events {
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "test",
	})

	statusCh, errCh, err := client.StreamExecutionStatus(context.Background(), "exec_fail_test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var received []ExecutionStatus
	for status := range statusCh {
		received = append(received, status)
	}

	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("Unexpected stream error: %v", streamErr)
	}

	if len(received) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(received))
	}
	if received[1].Status != ExecutionStatusFailed {
		t.Errorf("Final status = %s, want failed", received[1].Status)
	}
	if received[1].Error != "Step 2 failed: LLM timeout" {
		t.Errorf("Error = %s, want 'Step 2 failed: LLM timeout'", received[1].Error)
	}
}
