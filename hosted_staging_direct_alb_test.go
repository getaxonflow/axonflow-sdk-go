package axonflow

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Run this only with a disposable Hosted staging fixture. The request URL stays
// on the staging hostname, so net/http retains its Host header and TLS SNI;
// only the TCP destination is redirected to the temporary ALB. Certificate
// verification remains enabled. Production SDK transport behavior is unchanged.
func TestHostedStagingPaidRefusalDirectALB(t *testing.T) {
	if os.Getenv("AXONFLOW_HOSTED_LIVE_TEST") != "1" {
		t.Skip("set AXONFLOW_HOSTED_LIVE_TEST=1 for the disposable staging run")
	}
	if os.Getenv("AXONFLOW_TRY") == "1" || os.Getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" {
		t.Fatal("live staging probe requires an explicit endpoint and TLS verification")
	}
	const stagingHost = "try-staging.getaxonflow.com"
	alb := os.Getenv("STAGING_ALB_DNS")
	if alb == "" || !strings.HasSuffix(alb, ".elb.amazonaws.com") || strings.ContainsAny(alb, "/:@ 	\r\n") {
		t.Fatal("STAGING_ALB_DNS must be a bare AWS ALB DNS name")
	}
	clientID, secret := os.Getenv("AXONFLOW_HOSTED_STAGING_CLIENT_ID"), os.Getenv("AXONFLOW_HOSTED_STAGING_CLIENT_SECRET")
	if clientID == "" || secret == "" {
		t.Fatal("disposable staging client ID and secret are required")
	}
	expected := os.Getenv("AXONFLOW_HOSTED_EXPECTED_STATUS")
	if expected != "402" && expected != "429" {
		t.Fatal("AXONFLOW_HOSTED_EXPECTED_STATUS must be 402 or 429")
	}

	client := NewClient(AxonFlowConfig{
		Endpoint: "https://" + stagingHost, ClientID: clientID, ClientSecret: secret,
		Mode: "production", Retry: RetryConfig{
			Enabled: true, MaxAttempts: 3, InitialDelay: 50 * time.Millisecond,
		}, Cache: CacheConfig{Enabled: false},
	})
	ua, ok := client.httpClient.Transport.(*userAgentRoundTripper)
	if !ok {
		t.Fatal("unexpected SDK HTTP transport wrapper")
	}
	transport, ok := ua.inner.(*http.Transport)
	if !ok {
		t.Fatal("unexpected SDK HTTP transport")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("staging TLS verification is not enabled")
	}
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig.ServerName = stagingHost
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != stagingHost+":443" {
			return nil, errors.New("unexpected staging dial target")
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(alb, "443"))
	}

	response, err := client.ProxyLLMCall("hosted-sdk-runtime-e2e", "synthetic Hosted refusal probe", "chat", nil)
	code := "hosted_payment_required"
	if expected == "429" {
		code = "hosted_monthly_limit_reached"
	}
	if response != nil || err == nil || !strings.Contains(err.Error(), "HTTP "+expected) || !strings.Contains(err.Error(), code) {
		t.Fatalf("Hosted %s refusal did not surface as a terminal HTTP error: response=%#v error=%v", expected, response, err)
	}
	t.Logf("PASS: real Hosted staging %s is a terminal Go error", expected)
}
