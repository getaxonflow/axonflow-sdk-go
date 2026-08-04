//go:build ignore

// runtime-e2e/masfeat_wire_fields/main.go
//
// Real-wire test of the #3254 pin-advance batch on the masfeat models
// against a real running stack with the MAS FEAT module mounted.
//
// The 9.x server serves trigger_reason (not the SDK's old fiction
// triggered_reason) on the kill switch, and high_materiality /
// medium_materiality / low_materiality / assessments_due /
// kill_switches_triggered / org_id (not *_count / by_use_case /
// by_status) on the registry summary - see
// platform/orchestrator/masfeat/types.go at v9.13.0 (df027c788). This
// suite proves both through the actual user-facing surface:
//
//  1. Register a probe AI system, then read the registry summary: the
//     real count fields populate (total_systems >= 1) and the five
//     deprecated fiction fields are zero-valued on the live wire.
//  2. Trigger the probe system's kill switch WITH a distinctive reason
//     and read it back: KillSwitch.TriggerReason round-trips the exact
//     reason (a server that did not serve trigger_reason fails this),
//     while the deprecated TriggeredReason stays empty.
//
// Run via:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	export AXONFLOW_TENANT_ID=<registered tenant/client id>
//	export AXONFLOW_TENANT_SECRET=<its secret>
//	go run runtime-e2e/masfeat_wire_fields/main.go
//
// Deployment-mode caveat: MAS FEAT is an ENTERPRISE compliance module.
// A community stack does not mount /api/v1/masfeat/* and every call
// below answers 404 (verified against the session-3254 community
// v9.13.0 stack on 2026-08-04); run this against an enterprise stack
// with the masfeat module enabled.
package main

import (
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	endpoint := getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getenv("AXONFLOW_TENANT_ID", "buku-e-go-e2e")
	secret := getenv("AXONFLOW_TENANT_SECRET", "buku-e-secret")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: secret,
	})

	systemID := fmt.Sprintf("e2e-3254-wire-%d", time.Now().UnixNano())
	if _, err := client.MASFEATRegisterSystem(&axonflow.RegisterSystemRequest{
		SystemID:        systemID,
		SystemName:      "e2e 3254 wire-fields probe",
		UseCase:         axonflow.UseCaseOther,
		OwnerTeam:       "e2e-harness",
		CustomerImpact:  1,
		ModelComplexity: 1,
		HumanReliance:   1,
	}); err != nil {
		fail("MASFEATRegisterSystem failed (is the masfeat module mounted? community stacks answer 404 here): %v", err)
	}
	fmt.Printf("registered probe system %s\n", systemID)

	// 1) Registry summary: real fields populate, fiction stays zero.
	sum, err := client.MASFEATGetRegistrySummary()
	if err != nil {
		fail("MASFEATGetRegistrySummary failed: %v", err)
	}
	if sum.TotalSystems < 1 {
		fail("RegistrySummary.TotalSystems = %d after registering a system - the real total_systems field did not populate", sum.TotalSystems)
	}
	if sum.HighMaterialityCount != 0 || sum.MediumMaterialityCount != 0 || sum.LowMaterialityCount != 0 ||
		sum.ByUseCase != nil || sum.ByStatus != nil {
		fail("a deprecated RegistrySummary fiction field is non-zero on the live wire: %+v", sum)
	}
	fmt.Printf("registry summary: total=%d high=%d med=%d low=%d due=%d triggered=%d (fiction fields all zero)\n",
		sum.TotalSystems, sum.HighMateriality, sum.MediumMateriality, sum.LowMateriality,
		sum.AssessmentsDue, sum.KillSwitchesTriggered)

	// 2) Kill switch: trigger with a distinctive reason, read it back
	// through the REAL field. A server not serving trigger_reason
	// cannot pass this round-trip.
	reason := fmt.Sprintf("e2e-3254 reason %d", time.Now().UnixNano())
	if _, err := client.MASFEATTriggerKillSwitch(systemID, &axonflow.TriggerKillSwitchRequest{
		Reason:      reason,
		TriggeredBy: "e2e-harness",
	}); err != nil {
		fail("MASFEATTriggerKillSwitch failed: %v", err)
	}
	ks, err := client.MASFEATGetKillSwitch(systemID)
	if err != nil {
		fail("MASFEATGetKillSwitch failed: %v", err)
	}
	if ks.TriggerReason != reason {
		fail("KillSwitch.TriggerReason = %q, want the triggered reason %q - the real trigger_reason field did not round-trip", ks.TriggerReason, reason)
	}
	if ks.TriggeredReason != "" {
		fail("deprecated KillSwitch.TriggeredReason = %q, must stay empty on the live wire", ks.TriggeredReason)
	}
	fmt.Printf("kill switch trigger_reason round-tripped: %q (deprecated triggered_reason empty)\n", ks.TriggerReason)

	fmt.Println("PASS: masfeat_wire_fields")
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
