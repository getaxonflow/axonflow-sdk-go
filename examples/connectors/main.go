package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v5"
)

func main() {
	// Load configuration from environment variables
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")

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
			Name:        "amadeus-prod",
			TenantID:    "demo-tenant",
			Options: map[string]interface{}{
				"environment": "production",
				"region":      "europe",
			},
			Credentials: map[string]string{
				"api_key":    amadeusKey,
				"api_secret": amadeusSecret,
			},
		})

		if err != nil {
			log.Printf("Failed to install connector: %v", err)
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

		resp, err := client.QueryConnector(
			"", // SDK auto-populates user_token (defaults to "anonymous"). Don't hardcode a non-JWT literal — JWT-validating stacks reject it.
			"amadeus-prod",
			"Find flights from Paris to Amsterdam on 2025-12-15",
			map[string]interface{}{
				"origin":      "CDG",
				"destination": "AMS",
				"date":        "2025-12-15",
				"adults":      1,
			},
		)

		if err != nil {
			log.Printf("Connector query failed: %v", err)
		} else if !resp.Success {
			fmt.Printf("Query failed: %s\n", resp.Error)
		} else {
			fmt.Println("✓ Flight data retrieved:")
			fmt.Printf("%v\n", resp.Data)
		}
	}

	// Example 2: Query Redis connector (if available)
	fmt.Println("\nQuerying Redis connector...")

	redisResp, err := client.QueryConnector(
		"", // SDK auto-populates user_token (defaults to "anonymous"). Don't hardcode a non-JWT literal — JWT-validating stacks reject it.
		"redis-cache",
		"Get cached user preferences for user-123",
		map[string]interface{}{
			"key": "user:123:preferences",
		},
	)

	if err != nil {
		fmt.Printf("⚠ Redis query failed (expected if not installed): %v\n", err)
	} else if !redisResp.Success {
		fmt.Printf("⚠ Redis query failed: %s\n", redisResp.Error)
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
			fmt.Printf("✓ %s (installed as '%s')\n", conn.Name, conn.InstanceName)
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
