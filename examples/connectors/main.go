package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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

	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

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
	for i, conn := range connectors {
		fmt.Printf("%d. %s (%s)\n", i+1, conn.Name, conn.Type)
		fmt.Printf("   Description: %s\n", conn.Description)
		fmt.Printf("   Version: %s\n", conn.Version)
		fmt.Printf("   Installed: %v\n", conn.Installed)
		if conn.Installed {
			fmt.Printf("   Instance Name: %s\n", conn.InstanceName)
		}
		fmt.Println()
	}

	// Install a connector (example: Amadeus Travel API)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Step 2: Install Amadeus Travel Connector")
	fmt.Println(strings.Repeat("=", 60))

	// Check if Amadeus credentials are available
	amadeusKey := os.Getenv("AMADEUS_API_KEY")
	amadeusSecret := os.Getenv("AMADEUS_API_SECRET")

	if amadeusKey == "" || amadeusSecret == "" {
		fmt.Println("⚠ Skipping connector installation (AMADEUS_API_KEY and AMADEUS_API_SECRET not set)")
		fmt.Println("To install a connector, set the required credentials:")
		fmt.Println("  export AMADEUS_API_KEY=your-key")
		fmt.Println("  export AMADEUS_API_SECRET=your-secret")
	} else {
		fmt.Println("Installing Amadeus connector...")

		err = client.InstallConnector(axonflow.ConnectorInstallRequest{
			ConnectorID: "amadeus-travel",
			Name:        "amadeus-travel",
			TenantID:    tenantID,
			Options: map[string]interface{}{
				// Amadeus issues self-service keys for the "test" environment;
				// switch to "production" only with production Amadeus keys.
				"environment": "test",
				"region":      "europe",
			},
			Credentials: map[string]string{
				"api_key":    amadeusKey,
				"api_secret": amadeusSecret,
			},
		})

		if err != nil {
			if strings.Contains(err.Error(), "already registered") {
				fmt.Println("✓ Connector already installed, continuing")
			} else {
				log.Printf("Failed to install connector: %v", err)
			}
		} else {
			fmt.Println("✓ Connector installed successfully!")
		}
	}

	// Query an installed connector
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 3: Query Connector")
	fmt.Println(strings.Repeat("=", 60))

	// Example 1: Query Amadeus for flight data
	if amadeusKey != "" {
		fmt.Println("Querying Amadeus connector for flights...")

		// Amadeus connector operations: search_flights, search_hotels,
		// lookup_airport (parameters carry the search criteria).
		departureDate := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
		resp, err := client.QueryConnector(
			userToken,        // AXONFLOW_USER_TOKEN (JWT) on enterprise stacks; empty ("anonymous") is fine on community stacks.
			"amadeus-travel", // query by connector ID (the marketplace ID used at install time)
			"search_flights",
			map[string]interface{}{
				"origin":         "CDG",
				"destination":    "AMS",
				"departure_date": departureDate,
				"adults":         1,
				"max":            2,
			},
		)

		if err != nil {
			log.Printf("Connector query failed: %v", err)
		} else if !resp.Success {
			fmt.Printf("Query failed: %s\n", resp.Error)
		} else if resp.Error != "" || resp.Data == nil {
			// Success=true with an Error set means the SDK failed open
			// (production mode, AxonFlow unavailable) — don't report data.
			fmt.Printf("⚠ No flight data (governed call did not reach the connector): %s\n", resp.Error)
		} else {
			fmt.Println("✓ Flight data retrieved:")
			fmt.Printf("%v\n", resp.Data)
		}
	}

	// Example 2: Query Redis connector (if available)
	fmt.Println("\nQuerying Redis connector...")

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
		fmt.Printf("⚠ Redis query failed (expected if not installed): %v\n", err)
	} else if !redisResp.Success {
		fmt.Printf("⚠ Redis query failed: %s\n", redisResp.Error)
	} else if redisResp.Error != "" || redisResp.Data == nil {
		fmt.Printf("⚠ No Redis data (governed call did not reach the connector): %s\n", redisResp.Error)
	} else {
		fmt.Println("✓ Redis data retrieved:")
		fmt.Printf("%v\n", redisResp.Data)
	}

	// Example 3: List connectors again to see installed status
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
}

// getEnv retrieves environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
