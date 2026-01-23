package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestMASFEATRegisterSystem tests the MASFEATRegisterSystem method
func TestMASFEATRegisterSystem(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry" {
				t.Errorf("expected path /api/v1/masfeat/registry, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			var reqBody RegisterSystemRequest
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}

			if reqBody.SystemID != "test-system" {
				t.Errorf("expected system_id test-system, got %s", reqBody.SystemID)
			}
			if reqBody.CustomerImpact != 4 {
				t.Errorf("expected risk_rating_impact 4, got %d", reqBody.CustomerImpact)
			}

			response := AISystemRegistry{
				ID:              "uuid-123",
				SystemID:        "test-system",
				SystemName:      "Test System",
				Materiality:     MaterialityHigh,
				Status:          SystemStatusDraft,
				CustomerImpact:  4,
				ModelComplexity: 3,
				HumanReliance:   5,
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		system, err := client.MASFEATRegisterSystem(&RegisterSystemRequest{
			SystemID:        "test-system",
			SystemName:      "Test System",
			UseCase:         UseCaseCreditScoring,
			OwnerTeam:       "Test Team",
			CustomerImpact:  4,
			ModelComplexity: 3,
			HumanReliance:   5,
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if system.ID != "uuid-123" {
			t.Errorf("expected ID uuid-123, got %s", system.ID)
		}
		if system.Materiality != MaterialityHigh {
			t.Errorf("expected materiality high, got %s", system.Materiality)
		}
	})

	t.Run("error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid request"}`))
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		_, err := client.MASFEATRegisterSystem(&RegisterSystemRequest{
			SystemID: "test-system",
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

// TestMASFEATActivateSystem tests the MASFEATActivateSystem method
func TestMASFEATActivateSystem(t *testing.T) {
	t.Run("successful activation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry/uuid-123" {
				t.Errorf("expected path /api/v1/masfeat/registry/uuid-123, got %s", r.URL.Path)
			}
			if r.Method != "PUT" {
				t.Errorf("expected method PUT, got %s", r.Method)
			}

			var reqBody map[string]string
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}

			if reqBody["status"] != "active" {
				t.Errorf("expected status active, got %s", reqBody["status"])
			}

			response := AISystemRegistry{
				ID:         "uuid-123",
				SystemID:   "test-system",
				SystemName: "Test System",
				Status:     SystemStatusActive,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		system, err := client.MASFEATActivateSystem("uuid-123")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if system.Status != SystemStatusActive {
			t.Errorf("expected status active, got %s", system.Status)
		}
	})
}

// TestMASFEATCreateAssessment tests the MASFEATCreateAssessment method
func TestMASFEATCreateAssessment(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments" {
				t.Errorf("expected path /api/v1/masfeat/assessments, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := FEATAssessment{
				ID:             "assessment-123",
				SystemID:       "test-system",
				AssessmentType: "initial",
				Status:         FEATStatusPending,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		assessment, err := client.MASFEATCreateAssessment(&CreateAssessmentRequest{
			SystemID:       "test-system",
			AssessmentType: "initial",
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if assessment.ID != "assessment-123" {
			t.Errorf("expected ID assessment-123, got %s", assessment.ID)
		}
		if assessment.Status != FEATStatusPending {
			t.Errorf("expected status pending, got %s", assessment.Status)
		}
	})
}

// TestMASFEATConfigureKillSwitch tests the MASFEATConfigureKillSwitch method
func TestMASFEATConfigureKillSwitch(t *testing.T) {
	t.Run("successful configuration", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system/configure" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system/configure, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			accuracy := 0.85
			bias := 0.15
			response := KillSwitch{
				SystemID:           "test-system",
				Status:             KillSwitchEnabled,
				AccuracyThreshold:  &accuracy,
				BiasThreshold:      &bias,
				AutoTriggerEnabled: true,
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		accuracy := 0.85
		bias := 0.15
		autoTrigger := true

		killSwitch, err := client.MASFEATConfigureKillSwitch("test-system", &ConfigureKillSwitchRequest{
			AccuracyThreshold:  &accuracy,
			BiasThreshold:      &bias,
			AutoTriggerEnabled: &autoTrigger,
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if killSwitch.Status != KillSwitchEnabled {
			t.Errorf("expected status enabled, got %s", killSwitch.Status)
		}
		if !killSwitch.AutoTriggerEnabled {
			t.Error("expected auto_trigger_enabled to be true")
		}
	})
}

// TestMASFEATTriggerKillSwitch tests the MASFEATTriggerKillSwitch method
func TestMASFEATTriggerKillSwitch(t *testing.T) {
	t.Run("successful trigger", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system/trigger" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system/trigger, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := KillSwitch{
				SystemID:        "test-system",
				Status:          KillSwitchTriggered,
				TriggeredReason: "Accuracy below threshold",
				TriggeredBy:     "monitoring-system",
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		killSwitch, err := client.MASFEATTriggerKillSwitch("test-system", &TriggerKillSwitchRequest{
			Reason:      "Accuracy below threshold",
			TriggeredBy: "monitoring-system",
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if killSwitch.Status != KillSwitchTriggered {
			t.Errorf("expected status triggered, got %s", killSwitch.Status)
		}
		if killSwitch.TriggeredReason != "Accuracy below threshold" {
			t.Errorf("expected reason 'Accuracy below threshold', got %s", killSwitch.TriggeredReason)
		}
	})

}

// TestMASFEATRestoreKillSwitch tests the MASFEATRestoreKillSwitch method
func TestMASFEATRestoreKillSwitch(t *testing.T) {
	t.Run("successful restore", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system/restore" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system/restore, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := KillSwitch{
				SystemID:   "test-system",
				Status:     KillSwitchEnabled,
				RestoredBy: "ops-team@example.com",
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		killSwitch, err := client.MASFEATRestoreKillSwitch("test-system", &RestoreKillSwitchRequest{
			Reason:     "Issues resolved",
			RestoredBy: "ops-team@example.com",
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if killSwitch.Status != KillSwitchEnabled {
			t.Errorf("expected status enabled, got %s", killSwitch.Status)
		}
		if killSwitch.RestoredBy != "ops-team@example.com" {
			t.Errorf("expected restored_by 'ops-team@example.com', got %s", killSwitch.RestoredBy)
		}
	})
}

// TestMASFEATGetKillSwitch tests the MASFEATGetKillSwitch method
func TestMASFEATGetKillSwitch(t *testing.T) {
	t.Run("successful get", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			accuracy := 0.85
			bias := 0.15
			response := KillSwitch{
				SystemID:           "test-system",
				Status:             KillSwitchEnabled,
				AccuracyThreshold:  &accuracy,
				BiasThreshold:      &bias,
				AutoTriggerEnabled: true,
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		killSwitch, err := client.MASFEATGetKillSwitch("test-system")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if killSwitch.Status != KillSwitchEnabled {
			t.Errorf("expected status enabled, got %s", killSwitch.Status)
		}
	})
}

// TestMASFEATGetKillSwitchHistory tests the MASFEATGetKillSwitchHistory method
func TestMASFEATGetKillSwitchHistory(t *testing.T) {
	t.Run("successful get history", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system/history" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system/history, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			response := []KillSwitchEvent{
				{
					ID:           "event-1",
					KillSwitchID: "ks-123",
					EventType:    "triggered",
					EventData:    map[string]interface{}{"reason": "Accuracy below threshold"},
					CreatedBy:    "monitoring-system",
					CreatedAt:    time.Now(),
				},
				{
					ID:           "event-2",
					KillSwitchID: "ks-123",
					EventType:    "restored",
					EventData:    map[string]interface{}{"reason": "Issues resolved"},
					CreatedBy:    "ops-team@example.com",
					CreatedAt:    time.Now(),
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		history, err := client.MASFEATGetKillSwitchHistory("test-system", 10)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(history) != 2 {
			t.Errorf("expected 2 events, got %d", len(history))
		}
		if history[0].EventType != "triggered" {
			t.Errorf("expected first event type 'triggered', got %s", history[0].EventType)
		}
	})

}

// TestMASFEATGetRegistrySummary tests the MASFEATGetRegistrySummary method
func TestMASFEATGetRegistrySummary(t *testing.T) {
	t.Run("successful get summary", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry/summary" {
				t.Errorf("expected path /api/v1/masfeat/registry/summary, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			response := RegistrySummary{
				TotalSystems:           10,
				ActiveSystems:          7,
				HighMaterialityCount:   3,
				MediumMaterialityCount: 4,
				LowMaterialityCount:    3,
				ByUseCase: map[string]int{
					"credit_scoring":   5,
					"fraud_detection":  3,
					"customer_service": 2,
				},
				ByStatus: map[string]int{
					"active":    7,
					"draft":     2,
					"suspended": 1,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		summary, err := client.MASFEATGetRegistrySummary()

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if summary.TotalSystems != 10 {
			t.Errorf("expected total_systems 10, got %d", summary.TotalSystems)
		}
		if summary.ActiveSystems != 7 {
			t.Errorf("expected active_systems 7, got %d", summary.ActiveSystems)
		}
		if summary.HighMaterialityCount != 3 {
			t.Errorf("expected high_materiality_count 3, got %d", summary.HighMaterialityCount)
		}
	})

}

// TestMASFEATGetSystem tests the MASFEATGetSystem method
func TestMASFEATGetSystem(t *testing.T) {
	t.Run("successful get", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry/uuid-123" {
				t.Errorf("expected path /api/v1/masfeat/registry/uuid-123, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			response := AISystemRegistry{
				ID:          "uuid-123",
				SystemID:    "test-system",
				SystemName:  "Test System",
				Status:      SystemStatusActive,
				Materiality: MaterialityHigh,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		system, err := client.MASFEATGetSystem("uuid-123")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if system.ID != "uuid-123" {
			t.Errorf("expected ID uuid-123, got %s", system.ID)
		}
		if system.Status != SystemStatusActive {
			t.Errorf("expected status active, got %s", system.Status)
		}
	})
}

// TestMASFEATUpdateAssessment tests the MASFEATUpdateAssessment method
func TestMASFEATUpdateAssessment(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments/assessment-123" {
				t.Errorf("expected path /api/v1/masfeat/assessments/assessment-123, got %s", r.URL.Path)
			}
			if r.Method != "PUT" {
				t.Errorf("expected method PUT, got %s", r.Method)
			}

			overallScore := 82
			response := FEATAssessment{
				ID:           "assessment-123",
				SystemID:     "test-system",
				Status:       FEATStatusInProgress,
				OverallScore: &overallScore,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		fairnessScore := 85
		ethicsScore := 90
		assessment, err := client.MASFEATUpdateAssessment("assessment-123", &UpdateAssessmentRequest{
			FairnessScore: &fairnessScore,
			EthicsScore:   &ethicsScore,
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if assessment.Status != FEATStatusInProgress {
			t.Errorf("expected status in_progress, got %s", assessment.Status)
		}
	})
}

// TestMASFEATSubmitAssessment tests the MASFEATSubmitAssessment method
func TestMASFEATSubmitAssessment(t *testing.T) {
	t.Run("successful submit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments/assessment-123/submit" {
				t.Errorf("expected path /api/v1/masfeat/assessments/assessment-123/submit, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := FEATAssessment{
				ID:       "assessment-123",
				SystemID: "test-system",
				Status:   FEATStatusCompleted,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		assessment, err := client.MASFEATSubmitAssessment("assessment-123")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if assessment.Status != FEATStatusCompleted {
			t.Errorf("expected status completed, got %s", assessment.Status)
		}
	})
}

// TestMASFEATApproveAssessment tests the MASFEATApproveAssessment method
func TestMASFEATApproveAssessment(t *testing.T) {
	t.Run("successful approve", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments/assessment-123/approve" {
				t.Errorf("expected path /api/v1/masfeat/assessments/assessment-123/approve, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			approvedAt := time.Now()
			response := FEATAssessment{
				ID:         "assessment-123",
				SystemID:   "test-system",
				Status:     FEATStatusApproved,
				ApprovedBy: "compliance@example.com",
				ApprovedAt: &approvedAt,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		assessment, err := client.MASFEATApproveAssessment("assessment-123", &ApproveAssessmentRequest{
			ApprovedBy: "compliance@example.com",
			Comments:   "Approved",
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if assessment.Status != FEATStatusApproved {
			t.Errorf("expected status approved, got %s", assessment.Status)
		}
		if assessment.ApprovedBy != "compliance@example.com" {
			t.Errorf("expected approved_by 'compliance@example.com', got %s", assessment.ApprovedBy)
		}
	})
}

// TestMASFEATUpdateSystem tests the MASFEATUpdateSystem method
func TestMASFEATUpdateSystem(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry/uuid-123" {
				t.Errorf("expected path /api/v1/masfeat/registry/uuid-123, got %s", r.URL.Path)
			}
			if r.Method != "PUT" {
				t.Errorf("expected method PUT, got %s", r.Method)
			}

			response := AISystemRegistry{
				ID:         "uuid-123",
				SystemID:   "test-system",
				SystemName: "Updated System",
				Status:     SystemStatusActive,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		name := "Updated System"
		system, err := client.MASFEATUpdateSystem("uuid-123", &UpdateSystemRequest{
			SystemName: &name,
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if system.SystemName != "Updated System" {
			t.Errorf("expected name 'Updated System', got %s", system.SystemName)
		}
	})
}

// TestMASFEATListSystems tests the MASFEATListSystems method
func TestMASFEATListSystems(t *testing.T) {
	t.Run("successful list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry" {
				t.Errorf("expected path /api/v1/masfeat/registry, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			response := []AISystemRegistry{
				{
					ID:         "uuid-1",
					SystemID:   "system-1",
					SystemName: "System 1",
					Status:     SystemStatusActive,
				},
				{
					ID:         "uuid-2",
					SystemID:   "system-2",
					SystemName: "System 2",
					Status:     SystemStatusDraft,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		systems, err := client.MASFEATListSystems(nil)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(systems) != 2 {
			t.Errorf("expected 2 systems, got %d", len(systems))
		}
	})
}

// TestMASFEATRetireSystem tests the MASFEATRetireSystem method
func TestMASFEATRetireSystem(t *testing.T) {
	t.Run("successful retire", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/registry/uuid-123" {
				t.Errorf("expected path /api/v1/masfeat/registry/uuid-123, got %s", r.URL.Path)
			}
			if r.Method != "DELETE" {
				t.Errorf("expected method DELETE, got %s", r.Method)
			}

			response := AISystemRegistry{
				ID:         "uuid-123",
				SystemID:   "test-system",
				SystemName: "Test System",
				Status:     SystemStatusRetired,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		system, err := client.MASFEATRetireSystem("uuid-123")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if system.Status != SystemStatusRetired {
			t.Errorf("expected status retired, got %s", system.Status)
		}
	})
}

// TestMASFEATGetAssessment tests the MASFEATGetAssessment method
func TestMASFEATGetAssessment(t *testing.T) {
	t.Run("successful get", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments/assessment-123" {
				t.Errorf("expected path /api/v1/masfeat/assessments/assessment-123, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			response := FEATAssessment{
				ID:       "assessment-123",
				SystemID: "test-system",
				Status:   FEATStatusApproved,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		assessment, err := client.MASFEATGetAssessment("assessment-123")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if assessment.ID != "assessment-123" {
			t.Errorf("expected ID assessment-123, got %s", assessment.ID)
		}
	})
}

// TestMASFEATListAssessments tests the MASFEATListAssessments method
func TestMASFEATListAssessments(t *testing.T) {
	t.Run("successful list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments" {
				t.Errorf("expected path /api/v1/masfeat/assessments, got %s", r.URL.Path)
			}
			if r.Method != "GET" {
				t.Errorf("expected method GET, got %s", r.Method)
			}

			response := []FEATAssessment{
				{
					ID:       "assessment-1",
					SystemID: "system-1",
					Status:   FEATStatusApproved,
				},
				{
					ID:       "assessment-2",
					SystemID: "system-2",
					Status:   FEATStatusPending,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		assessments, err := client.MASFEATListAssessments(nil)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(assessments) != 2 {
			t.Errorf("expected 2 assessments, got %d", len(assessments))
		}
	})
}

// TestMASFEATRejectAssessment tests the MASFEATRejectAssessment method
func TestMASFEATRejectAssessment(t *testing.T) {
	t.Run("successful reject", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/assessments/assessment-123/reject" {
				t.Errorf("expected path /api/v1/masfeat/assessments/assessment-123/reject, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := FEATAssessment{
				ID:       "assessment-123",
				SystemID: "test-system",
				Status:   FEATStatusRejected,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		assessment, err := client.MASFEATRejectAssessment("assessment-123", &RejectAssessmentRequest{
			RejectedBy: "compliance@example.com",
			Reason:     "Not complete",
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if assessment.Status != FEATStatusRejected {
			t.Errorf("expected status rejected, got %s", assessment.Status)
		}
	})
}

// TestMASFEATEnableKillSwitch tests the MASFEATEnableKillSwitch method
func TestMASFEATEnableKillSwitch(t *testing.T) {
	t.Run("successful enable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system/enable" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system/enable, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := KillSwitch{
				SystemID: "test-system",
				Status:   KillSwitchEnabled,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		killSwitch, err := client.MASFEATEnableKillSwitch("test-system")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if killSwitch.Status != KillSwitchEnabled {
			t.Errorf("expected status enabled, got %s", killSwitch.Status)
		}
	})
}

// TestMASFEATDisableKillSwitch tests the MASFEATDisableKillSwitch method
func TestMASFEATDisableKillSwitch(t *testing.T) {
	t.Run("successful disable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/masfeat/killswitch/test-system/disable" {
				t.Errorf("expected path /api/v1/masfeat/killswitch/test-system/disable, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			response := KillSwitch{
				SystemID: "test-system",
				Status:   KillSwitchDisabled,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(AxonFlowConfig{
			Endpoint:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		})

		killSwitch, err := client.MASFEATDisableKillSwitch("test-system", "Maintenance")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if killSwitch.Status != KillSwitchDisabled {
			t.Errorf("expected status disabled, got %s", killSwitch.Status)
		}
	})
}
