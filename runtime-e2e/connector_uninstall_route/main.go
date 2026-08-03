//go:build ignore

// runtime-e2e/connector_uninstall_route/main.go
//
// Real-stack assertion: UninstallConnector must hit the platform's actual
// uninstall route (DELETE /api/v1/connectors/{id}/uninstall).
//
// Per CLAUDE.md HARD RULE #0 this driver MUST hit a real running AxonFlow
// agent — no httptest, no fixture servers.
//
// Regression background: UninstallConnector used to issue
// DELETE /api/v1/connectors/{id}, a route the platform does not serve for
// DELETE — every uninstall through the SDK failed with HTTP 405
// Method Not Allowed. This driver proves the full marketplace lifecycle
// against a live stack:
//
//  1. Install the redis-cache connector for the caller's tenant (an
//     "already registered" from a previous run is tolerated — the surface
//     under test is uninstall).
//  2. Query it through the governed mcp-query path (proves it is really
//     installed and serving).
//  3. Uninstall it — MUST succeed. A 405 here is the exact regression this
//     leg guards against.
//  4. Re-install it — MUST succeed cleanly. This only works if step 3
//     genuinely removed the registration (install fails with
//     "already registered" otherwise), and it restores the stack state.
//  5. Query again — proves the reinstalled connector serves.
//
// Run locally (after `source /tmp/axonflow-e2e-env.sh` from the enterprise
// setup script; AXONFLOW_USER_TOKEN must be a JWT whose tenant_id matches
// the license org):
//
//	AXONFLOW_AGENT_URL=http://localhost:8080 \
//	AXONFLOW_CLIENT_ID="$AXONFLOW_CLIENT_ID" \
//	AXONFLOW_CLIENT_SECRET="$AXONFLOW_CLIENT_SECRET" \
//	AXONFLOW_TENANT_ID="$AXONFLOW_TENANT_ID" \
//	AXONFLOW_USER_TOKEN="$AXONFLOW_USER_TOKEN" \
//	go run runtime-e2e/connector_uninstall_route/main.go
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

const connectorID = "redis-cache"

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func install(client *axonflow.AxonFlowClient, tenantID string) error {
	return client.InstallConnector(axonflow.ConnectorInstallRequest{
		ConnectorID: connectorID,
		Name:        connectorID,
		TenantID:    tenantID,
		Options: map[string]interface{}{
			// The docker-compose stack's redis service.
			"host": env("AXONFLOW_E2E_REDIS_HOST", "redis"),
			"port": 6379,
			"db":   0,
		},
	})
}

// query polls the governed mcp-query path until the connector serves. The
// agent caches per-tenant connector configs for 30s (RuntimeConfigService
// default CacheTTL), so a query issued right after install can be answered
// from a pre-install snapshot; poll past that window before failing.
func query(client *axonflow.AxonFlowClient, userToken, label string) bool {
	deadline := time.Now().Add(45 * time.Second)
	for {
		resp, err := client.QueryConnector(userToken, connectorID, "GET",
			map[string]interface{}{"key": "user:123:preferences"})
		switch {
		case err == nil && resp.Success && resp.Error == "" && resp.Data != nil:
			fmt.Printf("PASS [%s] governed query served by %s\n", label, connectorID)
			return true
		case time.Now().After(deadline):
			if err != nil {
				fmt.Printf("FAIL [%s] governed query errored: %v\n", label, err)
			} else {
				fmt.Printf("FAIL [%s] governed query did not reach the connector: success=%v error=%q data=%v\n",
					label, resp.Success, resp.Error, resp.Data)
			}
			return false
		}
		time.Sleep(3 * time.Second)
	}
}

func main() {
	agentURL := env("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	userToken := os.Getenv("AXONFLOW_USER_TOKEN")
	tenantID := env("AXONFLOW_TENANT_ID", clientID)
	if clientID == "" || clientSecret == "" || userToken == "" {
		fmt.Println("FAIL: AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN must be set (source /tmp/axonflow-e2e-env.sh)")
		os.Exit(1)
	}

	client := axonflow.NewClientSimple(agentURL, clientID, clientSecret)
	failures := 0

	// 1. Install. A leftover registration from a previous run reports
	//    "already registered" — converge by uninstalling (the surface under
	//    test) and installing fresh, so the DB row is known-good for THIS
	//    tenant regardless of prior state.
	if err := install(client, tenantID); err != nil {
		if strings.Contains(err.Error(), "already registered") {
			fmt.Println("INFO [1] leftover registration from a previous run — uninstalling and installing fresh")
			if err := client.UninstallConnector(connectorID); err != nil {
				fmt.Printf("FAIL [1] uninstall of leftover registration: %v\n", err)
				os.Exit(1)
			}
			if err := install(client, tenantID); err != nil {
				fmt.Printf("FAIL [1] fresh install after uninstall: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("FAIL [1] install: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println("PASS [1] connector installed")

	// 2. Prove it serves.
	if !query(client, userToken, "2") {
		failures++
	}

	// 3. Uninstall — the surface under test. The old SDK route
	//    (DELETE /api/v1/connectors/{id}) 405s here.
	if err := client.UninstallConnector(connectorID); err != nil {
		fmt.Printf("FAIL [3] UninstallConnector: %v\n", err)
		if strings.Contains(err.Error(), "405") {
			fmt.Println("      (HTTP 405 = the exact wrong-route regression this leg guards against)")
		}
		os.Exit(1)
	}
	fmt.Println("PASS [3] UninstallConnector succeeded (real /uninstall route)")

	// 4. Re-install MUST be clean: only possible if step 3 genuinely
	//    unregistered the connector. Also restores the stack state.
	if err := install(client, tenantID); err != nil {
		failures++
		fmt.Printf("FAIL [4] re-install after uninstall (uninstall did not unregister?): %v\n", err)
	} else {
		fmt.Println("PASS [4] re-install clean — uninstall genuinely removed the registration")
	}

	// 5. Reinstalled connector serves again.
	if !query(client, userToken, "5") {
		failures++
	}

	if failures > 0 {
		fmt.Printf("connector_uninstall_route: %d failure(s)\n", failures)
		os.Exit(1)
	}
	fmt.Println("connector_uninstall_route: all assertions passed")
}
