package axonflow

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClassifyEndpoint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// localhost
		{"localhost hostname", "http://localhost:8080", EndpointTypeLocalhost},
		{"localhost https", "https://localhost", EndpointTypeLocalhost},
		{"127.0.0.1", "http://127.0.0.1", EndpointTypeLocalhost},
		{"127.0.0.1:8080", "http://127.0.0.1:8080", EndpointTypeLocalhost},
		{"127/8 loopback", "http://127.1.2.3", EndpointTypeLocalhost},
		{"IPv6 ::1", "http://[::1]", EndpointTypeLocalhost},
		{"IPv6 ::1:8080", "http://[::1]:8080", EndpointTypeLocalhost},
		{"0.0.0.0", "http://0.0.0.0:8080", EndpointTypeLocalhost},
		{"*.localhost", "http://agent.localhost", EndpointTypeLocalhost},
		{"case insensitive localhost", "http://LOCALHOST", EndpointTypeLocalhost},

		// private_network — RFC1918
		{"10.x", "http://10.0.0.1", EndpointTypePrivateNetwork},
		{"10.1.2.3", "http://10.1.2.3", EndpointTypePrivateNetwork},
		{"192.168.1.1", "http://192.168.1.1", EndpointTypePrivateNetwork},
		{"172.16.0.1", "http://172.16.0.1", EndpointTypePrivateNetwork},
		{"172.31.255.254", "http://172.31.255.254", EndpointTypePrivateNetwork},
		{"link-local 169.254", "http://169.254.169.254", EndpointTypePrivateNetwork},
		{".internal", "http://agent.internal", EndpointTypePrivateNetwork},
		{".local", "http://agent.local", EndpointTypePrivateNetwork},
		{".lan", "http://agent.lan", EndpointTypePrivateNetwork},
		{".intranet", "http://agent.intranet", EndpointTypePrivateNetwork},
		{"case insensitive .internal", "http://AGENT.INTERNAL", EndpointTypePrivateNetwork},

		// not in RFC1918 — boundary checks
		{"172.15.0.1 not private", "http://172.15.0.1", EndpointTypeRemote},
		{"172.32.0.1 not private", "http://172.32.0.1", EndpointTypeRemote},

		// remote
		{"public hostname", "https://production-us.getaxonflow.com", EndpointTypeRemote},
		{"another public hostname", "https://api.example.com", EndpointTypeRemote},
		{"public IPv4 8.8.8.8", "http://8.8.8.8", EndpointTypeRemote},
		{"public IPv4 1.1.1.1", "http://1.1.1.1", EndpointTypeRemote},

		// unknown
		{"empty", "", EndpointTypeUnknown},
		{"no scheme no host", "://nohost", EndpointTypeUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyEndpoint(tc.in)
			if got != tc.want {
				t.Errorf("ClassifyEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestPayloadContainsNoURL asserts that the telemetry JSON payload built
// from a client configured with a real URL never contains the URL itself.
func TestPayloadContainsNoURL(t *testing.T) {
	secretURL := "https://my-private-cluster.banking-internal.example.com:8443"
	endpointType := ClassifyEndpoint(secretURL)
	if endpointType != EndpointTypeRemote {
		t.Fatalf("expected remote, got %q", endpointType)
	}

	payload := telemetryPayload{
		SDK:          "go",
		SDKVersion:   "5.2.0",
		OS:           "linux",
		Arch:         "amd64",
		EndpointType: endpointType,
	}

	// Serialize and check no URL-shaped strings leak in.
	body, _ := json.Marshal(payload)
	for _, needle := range []string{
		"my-private-cluster",
		"banking-internal",
		"example.com",
		"8443",
		"https://",
	} {
		if strings.Contains(string(body), needle) {
			t.Errorf("payload contains forbidden URL fragment %q: %s", needle, string(body))
		}
	}
}
