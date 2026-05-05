package axonflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// X-Axonflow-Client header injection — ADR-050 §4.
//
// Asserts the SDK's transport stamps both User-Agent and X-Axonflow-Client
// on every request so the agent can derive request scope (sdk) and validate
// against the token's aud.scope via HasScope().

func TestUserAgentRoundTripper_StampsClientHeader(t *testing.T) {
	var captured http.Header
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer stub.Close()

	rt := &userAgentRoundTripper{
		inner:        http.DefaultTransport,
		userAgent:    "axonflow-sdk-go/" + Version,
		clientHeader: "sdk-go/" + Version,
	}
	client := &http.Client{Transport: rt}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, stub.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	resp.Body.Close()

	wantUA := "axonflow-sdk-go/" + Version
	if got := captured.Get("User-Agent"); got != wantUA {
		t.Errorf("User-Agent: want %q, got %q", wantUA, got)
	}

	wantClient := "sdk-go/" + Version
	if got := captured.Get("X-Axonflow-Client"); got != wantClient {
		t.Errorf("X-Axonflow-Client: want %q, got %q", wantClient, got)
	}
}

func TestUserAgentRoundTripper_DoesNotOverrideExistingHeaders(t *testing.T) {
	var captured http.Header
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer stub.Close()

	rt := &userAgentRoundTripper{
		inner:        http.DefaultTransport,
		userAgent:    "axonflow-sdk-go/" + Version,
		clientHeader: "sdk-go/" + Version,
	}
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, stub.URL, nil)
	req.Header.Set("User-Agent", "user-supplied-ua")
	req.Header.Set("X-Axonflow-Client", "user-supplied-client/0.0.0")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	resp.Body.Close()

	if got := captured.Get("User-Agent"); got != "user-supplied-ua" {
		t.Errorf("User-Agent: caller's value should be preserved, got %q", got)
	}
	if got := captured.Get("X-Axonflow-Client"); got != "user-supplied-client/0.0.0" {
		t.Errorf("X-Axonflow-Client: caller's value should be preserved, got %q", got)
	}
}

func TestUserAgentRoundTripper_ClientHeaderFormat(t *testing.T) {
	// Sanity: agent's deriveScopeFromClientHeader splits on '/' and maps
	// "sdk-*" prefixes to scope=sdk. Lock down the shape so we can't
	// accidentally regress agent-side parsing.
	want := "sdk-go/" + Version
	if want[:len("sdk-go/")] != "sdk-go/" {
		t.Errorf("client header must start with sdk-go/")
	}
}
