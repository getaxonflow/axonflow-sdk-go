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

	// Create client with simple initialization
	fmt.Println("Initializing AxonFlow client...")
	client := axonflow.NewClientSimple(agentURL, clientID, clientSecret)

	// Perform health check
	fmt.Println("\nChecking AxonFlow Agent health...")
	if err := client.HealthCheck(); err != nil {
		log.Printf("Warning: Health check failed: %v", err)
	} else {
		fmt.Println("✓ AxonFlow Agent is healthy")
	}

	// Execute a simple query
	fmt.Println("\nExecuting governed query...")
	resp, err := client.ProxyLLMCall(
		"", // SDK auto-populates user_token (defaults to "anonymous" if no JWT). Don't pass a literal — JWT-validating stacks reject it.
		"What is the capital of France?",
		"chat",
		map[string]interface{}{
			"temperature": 0.7,
			"max_tokens":  100,
		},
	)

	if err != nil {
		log.Fatalf("Query execution failed: %v", err)
	}

	// Check if request was blocked
	if resp.Blocked {
		fmt.Printf("❌ Request blocked by governance policy\n")
		fmt.Printf("   Reason: %s\n", resp.BlockReason)
		fmt.Printf("   Policies evaluated: %v\n", resp.PolicyInfo.PoliciesEvaluated)
		return
	}

	// Check if request succeeded
	if !resp.Success {
		fmt.Printf("❌ Query failed: %s\n", resp.Error)
		return
	}

	// Display result
	fmt.Println("✓ Query executed successfully")
	fmt.Printf("Result: %s\n", resp.Data)

	// Display governance metadata
	fmt.Println("\nGovernance Metadata:")
	fmt.Printf("  Request ID: %s\n", resp.RequestID)
	if resp.PolicyInfo != nil {
		fmt.Printf("  Policies Evaluated: %v\n", resp.PolicyInfo.PoliciesEvaluated)
		fmt.Printf("  Processing Time: %s\n", resp.PolicyInfo.ProcessingTime)
	}

	// Test with sensitive data (should be redacted)
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Testing PII detection and redaction...")
	fmt.Println(strings.Repeat("=", 60))

	resp2, err := client.ProxyLLMCall(
		"", // SDK auto-populates user_token (defaults to "anonymous" if no JWT). Don't pass a literal — JWT-validating stacks reject it.
		"My email is john.doe@example.com and my SSN is 123-45-6789",
		"chat",
		map[string]interface{}{},
	)

	if err != nil {
		log.Printf("Warning: PII test query failed: %v", err)
		return
	}

	if resp2.Blocked {
		fmt.Printf("✓ PII detected and request blocked\n")
		fmt.Printf("  Reason: %s\n", resp2.BlockReason)
	} else {
		fmt.Printf("✓ PII handled: %s\n", resp2.Data)
	}
}

// getEnv retrieves environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
