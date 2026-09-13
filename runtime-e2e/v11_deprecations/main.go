//go:build ignore

// runtime-e2e/v11_deprecations/main.go
//
// Real-stack proof of the v11.0.0 deprecations the SDK marks, through its public
// surface against a real v11 agent and orchestrator. Nothing is mocked.
//
//  1. SimulatePolicies and DetectPolicyConflicts still work, and each route is
//     reported exactly once through AxonFlowConfig.OnRouteDeprecation with the
//     platform's own signal: X-AxonFlow-Removed-In v11.1 and the successor
//     /api/v1/typed-policies from the Link. The platform adds an RFC 9745
//     Deprecation date ("@<unix seconds>") once v11.0.0 is tagged and omits
//     it until then, so the leg accepts it absent or well-formed.
//  2. GetPolicyImpactReport is reported the same way. It cannot return a
//     result on a fresh v11 stack: the platform evaluates the named policy from
//     the organization's TENANT policies, a fresh organization has none, and a
//     v11 platform refuses to create one. So the call names a policy that
//     cannot exist and asserts only that the platform refuses it (any
//     non-2xx); the deprecation is stamped whatever the handler answers.
//  3. A second call of each reports nothing new: once per route per client.
//
// The simulation routes are registered from the Evaluation licence up, so run
// it against an enterprise (production-posture) stack. See README.md.
//
// Run:
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 \
//	AXONFLOW_CLIENT_ID=<org id> AXONFLOW_CLIENT_SECRET=<licence> \
//	go run runtime-e2e/v11_deprecations/main.go
package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures []string

// deprecationDate is the RFC 9745 form the platform writes: "@<unix seconds>".
var deprecationDate = regexp.MustCompile(`^@[0-9]+$`)

func check(ok bool, description string) {
	if ok {
		fmt.Printf("PASS: %s\n", description)
		return
	}
	fmt.Printf("FAIL: %s\n", description)
	failures = append(failures, description)
}

// refusedStatus is the HTTP status of the SDK's error for a non-2xx answer
// ("HTTP <status>: <body>"), or 0 when err is nil or not such an error.
func refusedStatus(err error) int {
	if err == nil || !strings.HasPrefix(err.Error(), "HTTP ") {
		return 0
	}
	var status int
	if _, scanErr := fmt.Sscanf(err.Error(), "HTTP %d:", &status); scanErr != nil {
		return 0
	}
	return status
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	endpoint := env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	fmt.Printf("agent: %s\n", endpoint)

	var mu sync.Mutex
	var reports []axonflow.PlatformRouteDeprecation
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     env("AXONFLOW_CLIENT_ID", "runtime-e2e"),
		ClientSecret: env("AXONFLOW_CLIENT_SECRET", "runtime-e2e-secret"),
		OnRouteDeprecation: func(d axonflow.PlatformRouteDeprecation) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, d)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// reportedBy runs call and returns the deprecations it reported.
	reportedBy := func(call func() error) ([]axonflow.PlatformRouteDeprecation, error) {
		mu.Lock()
		before := len(reports)
		mu.Unlock()
		err := call()
		mu.Lock()
		defer mu.Unlock()
		return append([]axonflow.PlatformRouteDeprecation(nil), reports[before:]...), err
	}
	simulate := func() error {
		_, err := client.SimulatePolicies(ctx, &axonflow.SimulatePoliciesRequest{Query: "SELECT * FROM users", RequestType: "sql"})
		return err
	}
	conflicts := func() error {
		_, err := client.DetectPolicyConflicts(ctx, "")
		return err
	}
	impact := func() error {
		_, err := client.GetPolicyImpactReport(ctx, &axonflow.ImpactReportRequest{
			PolicyID: "sdk-go-e2e-no-such-policy",
			Inputs:   []axonflow.ImpactReportInput{{Query: "hello"}},
		})
		return err
	}
	signalled := func(got []axonflow.PlatformRouteDeprecation, route string) bool {
		if len(got) != 1 {
			return false
		}
		d := got[0]
		return d.Route == route && d.RemovedIn == "v11.1" && d.Successor == "/api/v1/typed-policies" &&
			(d.Deprecation == "" || deprecationDate.MatchString(d.Deprecation))
	}

	for _, leg := range []struct {
		name, route string
		call        func() error
		refused     bool
	}{
		{"SimulatePolicies", "POST /api/v1/policies/simulate", simulate, false},
		{"DetectPolicyConflicts", "POST /api/v1/policies/conflicts", conflicts, false},
		{"GetPolicyImpactReport", "POST /api/v1/policies/impact-report", impact, true},
	} {
		fmt.Printf("== %s\n", leg.name)
		got, err := reportedBy(leg.call)
		fmt.Printf("  err=%v\n  reported=%+v\n", err, got)
		if leg.refused {
			check(refusedStatus(err) >= 400,
				leg.name+" is refused (non-2xx) for a policy that cannot exist on a fresh v11 organization")
		} else {
			check(err == nil, leg.name+" still works")
		}
		check(signalled(got, leg.route), leg.name+" is reported deprecated once, with v11.1 and the typed successor")
		again, _ := reportedBy(leg.call)
		check(len(again) == 0, leg.name+" is not reported a second time")
	}

	if len(failures) > 0 {
		fmt.Printf("\nFAIL: v11_deprecations (%d assertion(s))\n", len(failures))
		os.Exit(1)
	}
	fmt.Println("\nPASS: v11_deprecations")
}
