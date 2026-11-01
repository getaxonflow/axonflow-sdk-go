package axonflow

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Hosted Agent's exact 402 body has no success or blocked fields. A
// decoded zero-value ClientResponse with a nil error would let a caller miss
// the payment refusal; production fail-open must not turn it into success.
func TestHostedPaymentRequiredIsTerminalError(t *testing.T) {
	const hostedBody = `{"checkout_method":"POST","checkout_url":"https://try-staging.getaxonflow.com/api/v1/billing/checkout","error":"hosted_payment_required","message":"Hosted governance requires an active paid plan.","tenant_id":"cs_test_unpaid"}`
	for _, tc := range []struct {
		name string
		body string
	}{
		{"hosted envelope", hostedBody},
		{"malformed refusal", `{"error":"hosted_payment_required"`},
		{"contradictory success", `{"success":true,"blocked":true,"error":"hosted_payment_required"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/request" {
					t.Errorf("path = %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := NewClient(AxonFlowConfig{
				Endpoint: server.URL,
				ClientID: "cs_test_unpaid",
				Mode:     "production",
				Retry:    RetryConfig{Enabled: true, MaxAttempts: 3, InitialDelay: time.Millisecond},
				Cache:    CacheConfig{Enabled: false},
			})
			response, err := client.ProxyLLMCall("user", "synthetic refusal probe", "chat", nil)
			if response != nil || err == nil {
				t.Fatalf("402 response = %#v, err = %v; want nil response and error", response, err)
			}
			var httpErr *httpError
			if !errors.As(err, &httpErr) || httpErr.statusCode != http.StatusPaymentRequired {
				t.Fatalf("error = %T %v; want HTTP 402", err, err)
			}
			if !strings.Contains(err.Error(), "hosted_payment_required") {
				t.Fatalf("error lost Hosted refusal code: %v", err)
			}
			if calls != 1 {
				t.Fatalf("402 calls = %d, want 1", calls)
			}
		})
	}
}

// Existing self-hosted policy/budget replies with an explicit blocked verdict
// continue to use ClientResponse rather than the Hosted HTTP error path.
func TestLegacyBlocked402StillReturnsVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"success":false,"blocked":true,"block_reason":"budget exceeded"}`))
	}))
	defer server.Close()
	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL,
		ClientID: "self-hosted",
		Mode:     "production",
		Retry:    RetryConfig{Enabled: true, MaxAttempts: 3, InitialDelay: time.Millisecond},
		Cache:    CacheConfig{Enabled: false},
	})
	response, err := client.ProxyLLMCall("user", "legacy budget probe", "chat", nil)
	if err != nil || response == nil || response.Success || !response.Blocked || response.BlockReason != "budget exceeded" {
		t.Fatalf("legacy blocked 402 response = %#v, err = %v", response, err)
	}
}

func TestHostedMonthlyLimit429IsTerminalError(t *testing.T) {
	const hostedBody = `{"error":"hosted_monthly_limit_reached","message":"Monthly hosted governance allowance reached.","limit_type":"monthly_governed_events","higher_usage_path":"paid_enterprise_poc"}`
	for _, tc := range []struct {
		name, body, tierLimit string
	}{
		{"exact Agent response", hostedBody, "monthly_governed_events"},
		{"body code only", hostedBody, ""},
		{"header with malformed body", `{"error":`, "monthly_governed_events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("X-Axonflow-Tier-Limit", tc.tierLimit)
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := NewClient(AxonFlowConfig{
				Endpoint: server.URL, ClientID: "hosted-capped", Mode: "production",
				Retry: RetryConfig{Enabled: true, MaxAttempts: 3, InitialDelay: time.Millisecond},
				Cache: CacheConfig{Enabled: false},
			})
			response, err := client.ProxyLLMCall("user", "monthly cap probe", "chat", nil)
			var httpErr *httpError
			if response != nil || !errors.As(err, &httpErr) || httpErr.statusCode != http.StatusTooManyRequests || !httpErr.hostedMonthlyLimit {
				t.Fatalf("Hosted cap response = %#v, err = %v; want terminal HTTP 429", response, err)
			}
			if calls != 1 {
				t.Fatalf("Hosted cap calls = %d, want 1", calls)
			}
		})
	}
}

func TestOrdinary429KeepsProductionFailOpen(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
	}))
	defer server.Close()
	client := NewClient(AxonFlowConfig{
		Endpoint: server.URL, ClientID: "self-hosted", Mode: "production",
		Retry: RetryConfig{Enabled: true, MaxAttempts: 3, InitialDelay: time.Millisecond},
		Cache: CacheConfig{Enabled: false},
	})
	response, err := client.ProxyLLMCall("user", "ordinary 429 probe", "chat", nil)
	if err != nil || response == nil || !response.Success || calls != 1 {
		t.Fatalf("ordinary 429 response = %#v, err = %v, calls = %d; want fail-open success after one call", response, err, calls)
	}
}

func TestOrdinary200StillReturnsVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"request_id":"governed-200"}`))
	}))
	defer server.Close()
	client := NewClient(AxonFlowConfig{Endpoint: server.URL, ClientID: "self-hosted", Mode: "production", Cache: CacheConfig{Enabled: false}})
	response, err := client.ProxyLLMCall("user", "ordinary 200 probe", "chat", nil)
	if err != nil || response == nil || !response.Success || response.RequestID != "governed-200" {
		t.Fatalf("ordinary 200 response = %#v, err = %v", response, err)
	}
}
