//go:build ignore

// runtime-e2e/x_axonflow_client/main.go
//
// Real-wire proof that THIS build's version is the one the live platform
// expects, and that it is what the SDK puts on the wire.
//
// A release bump changes exactly one product fact: the version string in
// version.go, which every governed request carries as
// `X-Axonflow-Client: sdk-go/<version>` (ADR-050 §4) and which the platform's
// /health names per SDK under `sdk_compatibility.recommended_sdk_version`. A
// bump PR that forgot version.go, or a tag cut against the wrong constant,
// ships an SDK that the platform immediately reports as behind. That is the
// defect a runtime leg on a release PR can catch, and nothing else in this
// repository's CI can: the version-alignment check compares version.go with
// CHANGELOG.md, two files in the same tree, and cannot see the platform.
//
// TWO REAL ENDPOINTS, nothing mocked:
//
//  1. THE LIVE PLATFORM. GET /health on the real agent (default
//     https://try.getaxonflow.com, the hosted sandbox; read-only) and read
//     `sdk_compatibility.recommended_sdk_version.go` and `min_sdk_version.go`.
//     The built axonflow.Version must EQUAL the recommended version - this is
//     a release leg, and the release is what the platform recommends - and
//     must not be below the minimum.
//
//  2. THE WIRE. A real net.Listener on 127.0.0.1 receives ONE governed request
//     from a real axonflow.NewClientSimple in this process and records the
//     X-Axonflow-Client and User-Agent headers exactly as sent. The header
//     must be `sdk-go/<axonflow.Version>`. The receiver answers a minimal
//     body; whatever the SDK then makes of that body is not the subject - the
//     header on the request is.
//
// Run:
//
//	go run runtime-e2e/x_axonflow_client/main.go
//	AXONFLOW_E2E_PLATFORM_ENDPOINT=http://localhost:8080 go run runtime-e2e/x_axonflow_client/main.go
//
// Exits 0 only when both assertions hold; every finding is printed.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures int

func check(name string, err error) {
	if err != nil {
		fmt.Printf("FAIL  %s: %v\n", name, err)
		failures++
		return
	}
	fmt.Printf("ok    %s\n", name)
}

type health struct {
	Version          string `json:"version"`
	SDKCompatibility struct {
		Min         map[string]string `json:"min_sdk_version"`
		Recommended map[string]string `json:"recommended_sdk_version"`
	} `json:"sdk_compatibility"`
}

// semverLess reports a < b for dotted numeric versions; anything unparsable
// compares as a string so a malformed value cannot read as "new enough".
func semverLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		if aerr != nil || berr != nil {
			return a < b
		}
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}

func main() {
	platform := os.Getenv("AXONFLOW_E2E_PLATFORM_ENDPOINT")
	if platform == "" {
		platform = "https://try.getaxonflow.com"
	}
	fmt.Printf("built axonflow.Version = %s\n", axonflow.Version)
	fmt.Printf("live platform          = %s\n", platform)

	// -- 1. the live platform's expectation of this SDK ----------------------
	httpc := &http.Client{Timeout: 20 * time.Second}
	resp, err := httpc.Get(strings.TrimRight(platform, "/") + "/health")
	if err != nil {
		check("the live platform answers /health", err)
		os.Exit(1)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var h health
	if err := json.Unmarshal(raw, &h); err != nil || resp.StatusCode != http.StatusOK {
		check("the live platform answers /health", fmt.Errorf("HTTP %d, parse error %v: %s", resp.StatusCode, err, string(raw)))
		os.Exit(1)
	}
	check("the live platform answers /health", nil)
	fmt.Printf("platform version %s; recommended sdk-go %q; minimum sdk-go %q\n",
		h.Version, h.SDKCompatibility.Recommended["go"], h.SDKCompatibility.Min["go"])

	recommended := h.SDKCompatibility.Recommended["go"]
	minimum := h.SDKCompatibility.Min["go"]
	switch {
	case recommended == "":
		check("the platform publishes a recommended sdk-go version", fmt.Errorf("sdk_compatibility.recommended_sdk_version has no \"go\" entry: %s", string(raw)))
	case axonflow.Version != recommended:
		check("the built version equals the version the live platform recommends",
			fmt.Errorf("version.go says %s, the platform recommends %s - the bump and the platform disagree", axonflow.Version, recommended))
	default:
		check("the built version equals the version the live platform recommends", nil)
	}
	if minimum != "" && semverLess(axonflow.Version, minimum) {
		check("the built version is not below the platform's minimum", fmt.Errorf("%s < %s", axonflow.Version, minimum))
	} else {
		check("the built version is not below the platform's minimum", nil)
	}

	// -- 2. the header this build puts on the wire ---------------------------
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		check("a real receiver listens", err)
		os.Exit(1)
	}
	var (
		mu       sync.Mutex
		captured http.Header
		path     string
	)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if captured == nil {
			captured = r.Header.Clone()
			path = r.URL.Path
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	})}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	client := axonflow.NewClientSimple("http://"+listener.Addr().String(), "e2e-x-axonflow-client", "e2e-secret")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A governed request; the receiver records the request, and what the SDK
	// makes of the minimal reply is not the subject.
	_, _ = client.Evaluate(ctx, axonflow.AuthZENRequest{
		Subject:  &axonflow.AuthZENSubject{Type: "gateway", ID: "runtime-e2e-gateway"},
		Action:   &axonflow.AuthZENAction{Name: "llm.completion"},
		Resource: &axonflow.AuthZENResource{Type: "llm", ID: "llm"},
		Context:  map[string]any{"args": map[string]any{"query": "version probe"}},
	})

	mu.Lock()
	got := captured
	mu.Unlock()
	if got == nil {
		check("the SDK sent a governed request to the receiver", fmt.Errorf("no request arrived"))
		os.Exit(1)
	}
	check("the SDK sent a governed request to the receiver", nil)
	fmt.Printf("wire: %s %s  X-Axonflow-Client=%q  User-Agent=%q\n", "POST", path, got.Get("X-Axonflow-Client"), got.Get("User-Agent"))
	want := "sdk-go/" + axonflow.Version
	if got.Get("X-Axonflow-Client") != want {
		check("X-Axonflow-Client carries this build's version", fmt.Errorf("got %q, want %q", got.Get("X-Axonflow-Client"), want))
	} else {
		check("X-Axonflow-Client carries this build's version", nil)
	}
	if !strings.Contains(got.Get("User-Agent"), axonflow.Version) {
		check("User-Agent names this build's version", fmt.Errorf("got %q", got.Get("User-Agent")))
	} else {
		check("User-Agent names this build's version", nil)
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("%d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Printf("PASS: sdk-go/%s is what the live platform recommends and what this build sends.\n", axonflow.Version)
}
