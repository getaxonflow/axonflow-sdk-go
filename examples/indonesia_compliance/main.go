package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	// Enterprise stacks (DEPLOYMENT_MODE=enterprise) validate user tokens as
	// JWTs — export AXONFLOW_USER_TOKEN. Community stacks skip JWT validation.
	userToken := getEnv("AXONFLOW_USER_TOKEN", "")

	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

	client := axonflow.NewClientSimple(agentURL, clientID, clientSecret)

	fmt.Println("=== Indonesia Compliance Example ===")
	fmt.Println()

	// 1. Verify PII Indonesia category constant
	fmt.Printf("PII Indonesia category: %s\n", axonflow.CategoryPIIIndonesia)

	// 2. Send a request containing an Indonesian NIK (national ID number)
	fmt.Println("\nSending governed request with NIK...")
	resp, err := client.ProxyLLMCall(
		userToken,
		"Customer NIK is 3204110507900003 and their name is Budi Santoso",
		"chat",
		map[string]interface{}{
			"purpose": "identity_verification",
		},
	)
	if err != nil {
		log.Printf("Request error (expected if no LLM configured): %v", err)
	} else {
		fmt.Printf("Response blocked: %v\n", resp.Blocked)
		if resp.PolicyInfo != nil {
			fmt.Printf("Policies evaluated: %v\n", resp.PolicyInfo.PoliciesEvaluated)
		}
	}

	// 3. Query audit logs to demonstrate cross-border fields
	fmt.Println("\nQuerying audit logs...")
	ctx := context.Background()
	yesterday := time.Now().Add(-24 * time.Hour)
	now := time.Now()
	auditResp, err := client.SearchAuditLogs(ctx, &axonflow.AuditSearchRequest{
		StartTime: &yesterday,
		EndTime:   &now,
		Limit:     5,
	})
	if err != nil {
		log.Printf("Audit search error: %v", err)
	} else {
		fmt.Printf("Found %d audit entries\n", len(auditResp.Entries))
		for _, entry := range auditResp.Entries {
			fmt.Printf("  [%s] type=%s blocked=%v",
				entry.Timestamp.Format(time.RFC3339),
				entry.RequestType,
				entry.Blocked)
			if entry.DataResidency != "" {
				fmt.Printf(" residency=%s", entry.DataResidency)
			}
			if entry.TransferBasis != "" {
				fmt.Printf(" basis=%s", entry.TransferBasis)
			}
			fmt.Println()
		}
	}

	// 4. List policies filtered by Indonesia PII category
	fmt.Println("\nListing Indonesia PII policies...")
	policies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Category: axonflow.CategoryPIIIndonesia,
	})
	if err != nil {
		log.Printf("Policy list error: %v", err)
	} else {
		fmt.Printf("Found %d Indonesia PII policies\n", len(policies))
		for _, p := range policies {
			fmt.Printf("  %s: %s (severity=%s, action=%s)\n",
				p.Name, p.Description, p.Severity, p.Action)
		}
	}

	fmt.Println("\n=== Done ===")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
