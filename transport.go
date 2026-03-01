package axonflow

import "net/http"

type userAgentRoundTripper struct {
	inner     http.RoundTripper
	userAgent string
}

func (t *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	return t.inner.RoundTrip(req)
}
