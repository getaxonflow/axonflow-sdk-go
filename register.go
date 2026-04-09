package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const TryEndpoint = "https://try.getaxonflow.com"

type TryRegistration struct {
	TenantID     string `json:"tenant_id"`
	Secret       string `json:"secret"`
	SecretPrefix string `json:"secret_prefix"`
	ExpiresAt    string `json:"expires_at"`
	Endpoint     string `json:"endpoint"`
	Note         string `json:"note"`
}

// RegisterTry registers a new tenant on try.getaxonflow.com.
// Store the secret securely — it is shown only once.
func RegisterTry(ctx context.Context, label string) (*TryRegistration, error) {
	return RegisterTryWithEndpoint(ctx, label, TryEndpoint)
}

// RegisterTryWithEndpoint registers a new tenant on the specified endpoint.
// Use this for local testing with a different endpoint URL.
func RegisterTryWithEndpoint(ctx context.Context, label, endpoint string) (*TryRegistration, error) {
	body := "{}"
	if label != "" {
		body = fmt.Sprintf(`{"label":%q}`, label)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		endpoint+"/api/v1/register",
		strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var reg TryRegistration
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}
	return &reg, nil
}
