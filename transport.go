package axonflow

import "net/http"

// userAgentRoundTripper stamps a User-Agent identifying this SDK build and an
// X-Axonflow-Client header carrying the agent-parseable "<client-id>/<version>"
// per ADR-050 §4. Both headers are set only if absent so callers can override
// either.
type userAgentRoundTripper struct {
	inner        http.RoundTripper
	userAgent    string
	clientHeader string
}

func (t *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	needsUA := req.Header.Get("User-Agent") == ""
	needsClient := req.Header.Get("X-Axonflow-Client") == ""
	if !needsUA && !needsClient {
		return t.inner.RoundTrip(req)
	}
	r2 := req.Clone(req.Context())
	if needsUA {
		r2.Header.Set("User-Agent", t.userAgent)
	}
	if needsClient {
		// ADR-050 §4: every governed request to the agent carries
		// X-Axonflow-Client so the agent can derive request scope (sdk)
		// and validate against the token's aud.scope via HasScope().
		r2.Header.Set("X-Axonflow-Client", t.clientHeader)
	}
	return t.inner.RoundTrip(r2)
}
