package axonflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The heartbeat fires on the client's FIRST OUTBOUND REQUEST (#3682). That
// makes "which code paths count as a request" a correctness question rather
// than a detail, and it is the question this file exists to keep answered.
//
// A gate placed at one caller is not a gate on the others. doHttpRequest wraps
// almost every request site and calls the trigger, and a comment there used to
// claim no path bypasses it — but StreamExecutionStatus builds its own
// http.Client (SSE needs one with no timeout) and called .Do directly, so a
// process whose only outbound call is a stream never pinged at all. Measured:
// zero pings. A monitor or dashboard backend that opens one long-lived stream
// and does nothing else is a real shape, and it was silently invisible.
//
// Rather than fix the one instance and leave the class open, this test is the
// census: every raw `.Do(` in the package must be a KNOWN site, and adding a
// new one fails here until its author says in writing which category it is in.
//
// This is a source-scanning guard, so it is only as wide as the syntax it
// matches. It catches `.Do(`, which is how every net/http request is issued in
// this package. It would NOT catch a request issued through some future helper
// that hides the call, and it is not a substitute for thinking about the
// trigger when adding one — said plainly rather than left for someone to
// discover.

// requestSiteExemptions maps "file:line-bearing snippet" to the reason that
// site does not need — or cannot have — the heartbeat trigger.
//
// Keyed by file rather than by line so ordinary edits above a call site do not
// churn this table; the COUNT per file is what is pinned.
var requestSiteExemptions = map[string]struct {
	count  int
	reason string
}{
	"heartbeat.go": {
		count: 1,
		reason: "doHttpRequest itself — THE wrapper. It calls the trigger " +
			"immediately before this .Do, which is what covers every site routed " +
			"through it.",
	},
	"execution.go": {
		count: 1,
		reason: "StreamExecutionStatus. SSE needs a client with no timeout, which " +
			"the shared wrapper cannot express, so this site builds its own and " +
			"calls maybeSendHeartbeatOnRequest itself. NOT exempt from the " +
			"trigger — exempt only from the wrapper.",
	},
	"register.go": {
		count: 1,
		reason: "A PACKAGE-LEVEL function, not a client method: registration is how " +
			"a tenant is created, so there is no client and no configured endpoint " +
			"to describe. A heartbeat here would report a deployment that does not " +
			"exist yet.",
	},
	"telemetry.go": {
		count: 2,
		reason: "The telemetry path itself — the /health probe and the checkpoint " +
			"POST. These MUST NOT call the trigger: doing so would make the " +
			"heartbeat trigger itself, recursively.",
	},
}

func TestEveryRequestSitePassesTheHeartbeatTrigger(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	found := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			// Skip comments so prose mentioning .Do( does not count as a site —
			// a marker string that collides with the prose beside it is its own
			// failure mode.
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, ".Do(") {
				found[name]++
			}
		}
	}

	// POSITIVE CONTROL. If the scan finds nothing at all it has stopped
	// working — a renamed method, a moved package, a changed extension — and
	// an empty result would otherwise read as "no bypasses", which is the
	// most dangerous way for this guard to fail.
	total := 0
	for _, n := range found {
		total += n
	}
	if total == 0 {
		t.Fatal("the scan found ZERO request sites, which cannot be true for this package. " +
			"The guard has stopped matching and would report any bypass as clean")
	}
	const knownTotal = 5
	if total != knownTotal {
		t.Logf("request-site census: %d sites across %d files (was %d)", total, len(found), knownTotal)
	}

	for file, count := range found {
		exemption, ok := requestSiteExemptions[file]
		if !ok {
			t.Errorf("%s issues %d raw HTTP request(s) and is not in requestSiteExemptions.\n\n"+
				"The telemetry heartbeat fires on the client's FIRST OUTBOUND REQUEST, so a "+
				"request path that bypasses doHttpRequest is a path on which the SDK never "+
				"pings. StreamExecutionStatus was exactly that and it was invisible.\n\n"+
				"Either route this through doHttpRequest, or call "+
				"c.maybeSendHeartbeatOnRequest() before the .Do and add an entry here saying "+
				"why the wrapper could not be used.", file, count)
			continue
		}
		if count != exemption.count {
			t.Errorf("%s now issues %d raw HTTP request(s), the census recorded %d.\n"+
				"Recorded reason: %s\n\n"+
				"If the new site is legitimate, give it the heartbeat trigger and update the "+
				"count. If it is a bypass, route it through doHttpRequest.",
				file, count, exemption.count, exemption.reason)
		}
	}
}
