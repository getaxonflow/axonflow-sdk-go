package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v4"
)

func main() {
	// Load configuration from environment variables
	agentURL := getEnv("AXONFLOW_AGENT_URL", "https://staging-eu.getaxonflow.com")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")

	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

	// Initialize client with advanced configuration
	fmt.Println("Initializing AxonFlow client with advanced features...")
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Mode:         "production",
		Debug:        true,
		Timeout:      90 * time.Second, // Longer timeout for planning

		// Enable retry for robustness
		Retry: axonflow.RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: 1 * time.Second,
		},

		// Enable caching for plan retrieval
		Cache: axonflow.CacheConfig{
			Enabled: true,
			TTL:     120 * time.Second,
		},
	})

	// Generate a multi-step plan
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 1: Generate Multi-Agent Plan")
	fmt.Println(strings.Repeat("=", 60))

	planGoal := "Plan a 3-day business trip to Paris with meetings at La Défense, " +
		"moderate budget for accommodation, and include dinner recommendations"

	fmt.Printf("Goal: %s\n\n", planGoal)
	fmt.Println("Generating plan...")

	plan, err := client.GeneratePlan(planGoal, "travel")
	if err != nil {
		log.Fatalf("Plan generation failed: %v", err)
	}

	fmt.Println("✓ Plan generated successfully!")
	fmt.Printf("  Plan ID: %s\n", plan.PlanID)
	fmt.Printf("  Steps: %d\n", len(plan.Steps))
	fmt.Printf("  Complexity: %d/10\n", plan.Complexity)
	fmt.Printf("  Parallel execution: %v\n", plan.Parallel)
	fmt.Printf("  Estimated duration: %s\n\n", plan.EstimatedDuration)

	// Display plan steps
	fmt.Println("Plan Steps:")
	fmt.Println(strings.Repeat("-", 60))
	for i, step := range plan.Steps {
		fmt.Printf("\n%d. %s\n", i+1, step.Name)
		fmt.Printf("   Type: %s\n", step.Type)
		fmt.Printf("   Agent: %s\n", step.Agent)
		fmt.Printf("   Description: %s\n", step.Description)

		if len(step.Dependencies) > 0 {
			fmt.Printf("   Dependencies: %v\n", step.Dependencies)
		}

		if len(step.Parameters) > 0 {
			fmt.Printf("   Parameters: %v\n", step.Parameters)
		}

		fmt.Printf("   Estimated time: %s\n", step.EstimatedTime)
	}

	// Execute the plan
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 2: Execute Plan")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("Executing plan...")
	startTime := time.Now()

	execResp, err := client.ExecutePlan(plan.PlanID)
	if err != nil {
		log.Fatalf("Plan execution failed: %v", err)
	}

	executionTime := time.Since(startTime)

	// Display execution results
	fmt.Printf("\n✓ Plan execution completed in %v\n", executionTime)
	fmt.Printf("  Status: %s\n", execResp.Status)
	fmt.Printf("  Duration: %s\n", execResp.Duration)

	if execResp.Status == "completed" {
		fmt.Println("\nPlan Result:")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println(execResp.Result)
		fmt.Println(strings.Repeat("=", 60))

		// Display step results
		if len(execResp.StepResults) > 0 {
			fmt.Println("\nStep-by-Step Results:")
			for i, stepResult := range execResp.StepResults {
				fmt.Printf("\nStep %d: %s\n", i+1, stepResult.StepName)
				fmt.Printf("  Status: %s\n", stepResult.Status)
				fmt.Printf("  Duration: %s\n", stepResult.Duration)

				if stepResult.Status == "completed" {
					fmt.Printf("  Result: %v\n", stepResult.Result)
				} else if stepResult.Status == "failed" {
					fmt.Printf("  Error: %s\n", stepResult.Error)
				}
			}
		}
	} else if execResp.Status == "failed" {
		fmt.Printf("❌ Plan execution failed: %s\n", execResp.Error)
	} else if execResp.Status == "partial" {
		fmt.Printf("⚠ Plan execution partially completed\n")
		fmt.Printf("  Successful steps: %d/%d\n", execResp.CompletedSteps, len(plan.Steps))
	}

	// Check plan status (demonstrates status polling for long-running plans)
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Step 3: Verify Plan Status")
	fmt.Println(strings.Repeat("=", 60))

	status, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		log.Fatalf("Failed to get plan status: %v", err)
	}

	fmt.Printf("Plan Status: %s\n", status.Status)
	fmt.Printf("Progress: %d/%d steps completed\n", status.CompletedSteps, status.TotalSteps)

	if status.Status == "in_progress" {
		fmt.Printf("Current step: %s\n", status.CurrentStep)
		fmt.Printf("Estimated time remaining: %s\n", status.EstimatedTimeRemaining)
	}

	// Example 2: Complex parallel plan
	fmt.Println("\n\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: Complex Parallel Plan")
	fmt.Println(strings.Repeat("=", 60))

	complexGoal := "Research and compare cloud providers (AWS, Azure, GCP) for " +
		"a new microservices architecture, including pricing, compliance, and performance data"

	fmt.Printf("Goal: %s\n\n", complexGoal)
	fmt.Println("Generating complex plan...")

	complexPlan, err := client.GeneratePlan(complexGoal, "research")
	if err != nil {
		log.Printf("Complex plan generation failed: %v", err)
		return
	}

	fmt.Println("✓ Complex plan generated!")
	fmt.Printf("  Plan ID: %s\n", complexPlan.PlanID)
	fmt.Printf("  Steps: %d\n", len(complexPlan.Steps))
	fmt.Printf("  Complexity: %d/10\n", complexPlan.Complexity)
	fmt.Printf("  Parallel execution: %v (can run %d steps in parallel)\n",
		complexPlan.Parallel, countParallelSteps(complexPlan.Steps))
	fmt.Printf("  Estimated duration: %s\n", complexPlan.EstimatedDuration)

	fmt.Println("\nNote: This complex plan demonstrates AxonFlow's ability to:")
	fmt.Println("  • Break down complex goals into manageable steps")
	fmt.Println("  • Identify dependencies between steps")
	fmt.Println("  • Execute independent steps in parallel for efficiency")
	fmt.Println("  • Orchestrate multiple specialized agents")
}

// getEnv retrieves environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// countParallelSteps counts how many steps can run in parallel
func countParallelSteps(steps []axonflow.PlanStep) int {
	noDeps := 0
	for _, step := range steps {
		if len(step.Dependencies) == 0 {
			noDeps++
		}
	}
	return noDeps
}
