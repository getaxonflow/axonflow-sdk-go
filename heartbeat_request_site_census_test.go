package axonflow

import (
	"os"
	"path/filepath"
	"regexp"
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
// matches, and R3 was right that the first version's needle was narrower than
// this paragraph claimed. It now matches every request-issuing method
// net/http's Client exposes — Do, Get, Post, Head, PostForm — and the
// package-level http.Get / http.Post / http.Head / http.PostForm helpers.
//
// THREE FORMS IT STILL DOES NOT SEE, declared rather than discovered:
//
//   1. A call split across lines, e.g. `c.httpClient.\n\tDo(req)`. The scan
//      is line-based; gofmt does not produce this shape, but a hand-edit
//      could.
//   2. A method VALUE: `do := c.httpClient.Do; do(req)`. The call site then
//      carries no receiver at all.
//   3. A request issued through some future helper that hides the call behind
//      another name.
//
// It is not a substitute for thinking about the trigger when adding a request
// path. What it does guarantee is that the ordinary spellings cannot be added
// silently.

// requestSiteCategory is a CLOSED set. Free text let a new site claim any
// category it liked, which made "naming its category" true only by courtesy —
// R3's L3. An unknown value fails the test.
type requestSiteCategory string

const (
	// categoryWrapper: doHttpRequest itself, which calls the trigger.
	categoryWrapper requestSiteCategory = "wrapper"
	// categoryTriggersItself: builds its own client for a reason the wrapper
	// cannot express, and calls the trigger directly.
	categoryTriggersItself requestSiteCategory = "triggers-itself"
	// categoryNoClient: a package-level function with no client and no
	// configured endpoint, so there is nothing for a heartbeat to describe.
	categoryNoClient requestSiteCategory = "no-client"
	// categoryTelemetryPath: the telemetry path itself, which MUST NOT
	// trigger or the heartbeat triggers recursively.
	categoryTelemetryPath requestSiteCategory = "telemetry-path"
)

var validCategories = map[requestSiteCategory]bool{
	categoryWrapper:        true,
	categoryTriggersItself: true,
	categoryNoClient:       true,
	categoryTelemetryPath:  true,
}

// requestSiteExemptions records, per file, how many raw request sites it has
// and which category they are in.
//
// Keyed by file rather than by line so ordinary edits above a call site do not
// churn this table; the COUNT per file is what is pinned.
var requestSiteExemptions = map[string]struct {
	count    int
	category requestSiteCategory
	reason   string
}{
	"heartbeat.go": {
		category: categoryWrapper,
		count:    1,
		reason: "doHttpRequest itself — THE wrapper. It calls the trigger " +
			"immediately before this .Do, which is what covers every site routed " +
			"through it.",
	},
	"execution.go": {
		category: categoryTriggersItself,
		count:    1,
		reason: "StreamExecutionStatus. SSE needs a client with no timeout, which " +
			"the shared wrapper cannot express, so this site builds its own and " +
			"calls maybeSendHeartbeatOnRequest itself. NOT exempt from the " +
			"trigger — exempt only from the wrapper.",
	},
	"register.go": {
		category: categoryNoClient,
		count:    1,
		reason: "A PACKAGE-LEVEL function, not a client method: registration is how " +
			"a tenant is created, so there is no client and no configured endpoint " +
			"to describe. A heartbeat here would report a deployment that does not " +
			"exist yet.",
	},
	"telemetry.go": {
		category: categoryTelemetryPath,
		count:    2,
		reason: "The telemetry path itself — the /health probe and the checkpoint " +
			"POST. These MUST NOT call the trigger: doing so would make the " +
			"heartbeat trigger itself, recursively.",
	},
}

// requestCall matches the ordinary spellings of "issue an HTTP request".
//
// THE RECEIVER IS PART OF THE PATTERN, and that is a correction rather than a
// nicety. Widening the needle to a bare `.Get(` on any receiver immediately
// flagged three sites that are not requests at all — `resp.Header.Get(...)` in
// read_identity.go and two in transport.go — because `Header` ends in a word
// character followed by `.Get(`. A guard that cries wolf is not a stricter
// guard: it trains the next reader to add a bogus exemption to make the test
// pass, which is how a census stops meaning anything.
//
// So: `.Do(` on any receiver, since http.Client is essentially its only user;
// the other verbs only on a receiver whose name ends in Client/client; and the
// package-level http.* helpers.
//
// DECLARED LIMIT: a client held in a variable NOT named *client (say
// `hc.Get(u)`) is not matched. That is the price of not producing false
// positives, and it is stated rather than left to be discovered.
var requestCall = regexp.MustCompile(
	`\.Do\(|[Cc]lient\.(?:Get|Post|Head|PostForm)\(|\bhttp\.(?:Get|Post|Head|PostForm)\(`)

func TestEveryRequestSitePassesTheHeartbeatTrigger(t *testing.T) {
	// Every recorded exemption must name a category from the closed set.
	for file, ex := range requestSiteExemptions {
		if !validCategories[ex.category] {
			t.Errorf("%s claims category %q, which is not one of the four defined categories. "+
				"A free-text category is not a category", file, ex.category)
		}
	}

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
			if requestCall.MatchString(line) {
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

	// FALSE-POSITIVE CONTROL, the mirror of the positive control above. A
	// needle broad enough to match `resp.Header.Get(` would make this census
	// noise, and noise gets silenced with bogus exemptions.
	for _, notARequest := range []string{
		"\tscope := resp.Header.Get(headerReadScope)",
		"\tneedsUA := req.Header.Get(\"User-Agent\") == \"\"",
		"\tv := u.Query().Get(\"id\")",
	} {
		if requestCall.MatchString(notARequest) {
			t.Errorf("the needle matches %q, which issues no request. False positives train "+
				"readers to add bogus exemptions, which is how a census stops meaning anything",
				strings.TrimSpace(notARequest))
		}
	}

	// And it must still match the real spellings.
	for _, isARequest := range []string{
		"\tresp, err := streamClient.Do(req)",
		"\tresp, err := c.httpClient.Get(url)",
		"\tresp, err := http.Post(url, ct, body)",
	} {
		if !requestCall.MatchString(isARequest) {
			t.Errorf("the needle MISSES %q, which is an ordinary request spelling",
				strings.TrimSpace(isARequest))
		}
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
