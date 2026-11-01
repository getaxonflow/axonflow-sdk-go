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
