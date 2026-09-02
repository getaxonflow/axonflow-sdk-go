package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	// Load configuration from environment variables
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	// Enterprise stacks (DEPLOYMENT_MODE=enterprise) validate user tokens as
	// JWTs — export AXONFLOW_USER_TOKEN. Community stacks skip JWT validation.
	userToken := getEnv("AXONFLOW_USER_TOKEN", "")
	// Connector installs are tenant-scoped: the tenant must exist on the
	// platform (tenants.tenant_id). On local/dev stacks the tenant id matches
	// the client id (org), so default to that.
	tenantID := getEnv("AXONFLOW_TENANT_ID", clientID)
	// The Redis connector connects FROM the platform (orchestrator), not from
	// this process. On the docker-compose stack the Redis service is reachable
	// as "redis"; override for other topologies.
	redisHost := getEnv("AXONFLOW_REDIS_HOST", "redis")
	redisPort, err := strconv.Atoi(getEnv("AXONFLOW_REDIS_PORT", "6379"))
	if err != nil {
		log.Fatalf("AXONFLOW_REDIS_PORT must be a number: %v", err)
	}

	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

	failed := false
	// Community-edition stacks run connectors from config files and have no
	// DB persistence for marketplace installs (migration 021 is
	// enterprise-conditional), so the install→query arc is skipped there
	// rather than failed.
	installArc := true

	// Initialize client
	fmt.Println("Initializing AxonFlow client...")
	client := axonflow.NewClientSimple(agentURL, clientID, clientSecret)

	// List available connectors in the marketplace
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 1: List Available Connectors")
	fmt.Println(strings.Repeat("=", 60))

	connectors, err := client.ListConnectors()
	if err != nil {
		log.Fatalf("Failed to list connectors: %v", err)
	}

	fmt.Printf("Found %d connectors:\n\n", len(connectors))
	redisInstalled := false
	for i, conn := range connectors {
		fmt.Printf("%d. %s (%s)\n", i+1, conn.Name, conn.Type)
		fmt.Printf("   Description: %s\n", conn.Description)
		fmt.Printf("   Version: %s\n", conn.Version)
		fmt.Printf("   Installed: %v\n", conn.Installed)
		if conn.Installed {
			fmt.Printf("   Instance Name: %s\n", conn.InstanceName)
		}
		if conn.Type == "redis" && conn.Installed {
			redisInstalled = true
		}
		fmt.Println()
	}

	// Install a connector. Redis ships with the docker-compose stack, so the
	// install→query arc runs end-to-end with no external service or paid
	// credentials. (Earlier revisions installed the Amadeus travel connector
	// here; Amadeus decommissioned its self-service APIs on 2026-07-17, so an
	// example pinned to it can never succeed again.)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Step 2: Install Redis Connector")
	fmt.Println(strings.Repeat("=", 60))

	if redisInstalled {
		// Keep the example re-runnable: the platform rejects duplicate
		// registrations, so don't re-install an already-installed connector.
		fmt.Println("✓ Redis connector already installed — skipping install")
	} else {
		fmt.Printf("Installing Redis connector (host=%s port=%d)...\n", redisHost, redisPort)

		err = client.InstallConnector(axonflow.ConnectorInstallRequest{
			ConnectorID: "redis-cache",
			Name:        "redis-cache",
			TenantID:    tenantID,
			Options: map[string]interface{}{
				"host": redisHost,
				"port": redisPort,
			},
		})

		if err != nil {
			switch {
			case strings.Contains(err.Error(), "already registered"):
				fmt.Println("✓ Connector already installed, continuing")
			case strings.Contains(err.Error(), "Failed to persist connector config"):
				// Community-edition stack: no connector_configs table by
				// design. Not a failure — the arc just isn't available here.
				fmt.Println("⚠ This stack cannot persist connector installs (community edition")
				fmt.Println("  runs connectors from config files) — skipping the install/query arc")
				installArc = false
			default:
				fmt.Printf("⚠ Failed to install connector: %v\n", err)
				failed = true
			}
		} else {
			fmt.Println("✓ Connector installed successfully!")
		}
	}

	// Query the installed connector through the governed gateway path.
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 3: Query Connector")
	fmt.Println(strings.Repeat("=", 60))

	if !installArc {
		fmt.Println("Skipped (connector install is not available on this stack).")
		fmt.Println("\n✅ Connector examples completed (listing only on this edition)")
		return
	}

	fmt.Println("Querying Redis connector...")

	redisResp, err := client.QueryConnector(
		userToken, // AXONFLOW_USER_TOKEN (JWT) on enterprise stacks; empty ("anonymous") is fine on community stacks.
		"redis-cache",
		// Redis connector queries are command statements: GET, EXISTS, TTL, KEYS
		// (the key goes in params).
		"GET",
		map[string]interface{}{
			"key": "user:123:preferences",
		},
	)

	if err != nil {
		fmt.Printf("⚠ Redis query failed: %v\n", err)
		failed = true
	} else if !redisResp.Success {
		fmt.Printf("⚠ Redis query failed: %s\n", redisResp.Error)
		failed = true
	} else if redisResp.Error != "" || redisResp.Data == nil {
		// Success=true with an Error set means the SDK failed open
		// (production mode, AxonFlow unavailable) — don't report data.
		fmt.Printf("⚠ No Redis data (governed call did not reach the connector): %s\n", redisResp.Error)
		failed = true
	} else {
		fmt.Println("✓ Redis data retrieved:")
		fmt.Printf("%v\n", redisResp.Data)
	}

	// List connectors again to see installed status
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 4: Verify Installed Connectors")
	fmt.Println(strings.Repeat("=", 60))

	connectors, err = client.ListConnectors()
	if err != nil {
		log.Fatalf("Failed to list connectors: %v", err)
	}

	installedCount := 0
	for _, conn := range connectors {
		if conn.Installed {
			installedCount++
			if conn.InstanceName != "" {
				fmt.Printf("✓ %s (installed as '%s')\n", conn.Name, conn.InstanceName)
			} else {
				fmt.Printf("✓ %s\n", conn.Name)
			}
		}
	}

	fmt.Printf("\nTotal installed connectors: %d\n", installedCount)
	if installedCount == 0 {
		fmt.Println("⚠ Expected at least the Redis connector to be installed")
		failed = true
	}

	if failed {
		fmt.Println("\n⚠ Connector examples completed with failures")
		os.Exit(1)
	}
	fmt.Println("\n✅ Connector examples completed")
}

// getEnv retrieves environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
