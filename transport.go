package axonflow

import "net/http"

type userAgentRoundTripper struct {
	inner     http.RoundTripper
	userAgent string
}

func (t *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		r2 := req.Clone(req.Context())
		r2.Header.Set("User-Agent", t.userAgent)
		return t.inner.RoundTrip(r2)
	}
	return t.inner.RoundTrip(req)
}
