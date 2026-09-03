package axonflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tests for the adapter registry (axonflow-enterprise#3682, item 1) and the
// per-value / per-array bounds it shares with the /health relay (item 2).
//
// WHAT THESE TESTS CAN AND CANNOT VARY. Every case here drives the REAL
// payload builder (sendTelemetryPingNow) against a real httptest listener and
// reads the bytes that actually left the process, so the axis under test —
// what reaches `features` on the wire — is varied end to end. The axis they
// CANNOT vary is the receiver: the checkpoint's own normalisation
// (NormalizeAdapterFeature folding an unknown name into `adapter:unknown` at
// read time) happens in another repo and is asserted there, not here. That
// separation is the point of item 1: this SDK sends the caller's name and
// takes no view on the vocabulary.

// captureFeatures runs one real ping against a stand-in checkpoint and
// returns the `features` array exactly as it arrived on the wire, plus
// whether the key was present at all.
func captureFeatures(t *testing.T) ([]string, bool) {
	t.Helper()

	type result struct {
		features []string
		present  bool
	}
	got := make(chan result, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			got <- result{nil, false}
			w.WriteHeader(http.StatusOK)
			return
		}
		raw, ok := payload["features"]
		if !ok {
			got <- result{nil, false}
			w.WriteHeader(http.StatusOK)
			return
		}
		// A JSON array decodes to []any; render it back to []string so the
		// assertion reads on the values rather than on interface boxing.
		list, _ := raw.([]any)
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, _ := item.(string)
			out = append(out, s)
		}
		got <- result{out, true}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)
	t.Setenv("AXONFLOW_TELEMETRY", "")

	c := &AxonFlowClient{config: AxonFlowConfig{Mode: "production"}}
	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()
	if err := c.sendTelemetryPingNow(ctx); err != nil {
		t.Fatalf("the ping did not land, so this case asserts nothing: %v", err)
	}

	select {
	case r := <-got:
		return r.features, r.present
	case <-time.After(5 * time.Second):
		t.Fatal("no ping body captured")
		return nil, false
	}
}

// TestFeaturesIsAlwaysPresentAndEmptyByDefault is the POSITIVE CONTROL for
// every absence assertion below. "features did not contain adapter:x" is only
// evidence if the field arrived at all and the run actually happened — an
// absent key and an empty array are different facts, and a ping that never
// fired would satisfy a naive absence check trivially.
func TestFeaturesIsAlwaysPresentAndEmptyByDefault(t *testing.T) {
	defer resetAdapterRegistryForTest()()

	features, present := captureFeatures(t)
	if !present {
		t.Fatal("`features` key absent from the wire; it has always serialized as [] and that shape is load-bearing")
	}
	if len(features) != 0 {
		t.Errorf("features = %v on a client that registered nothing, want []", features)
	}
}

// TestRegisteredAdapterReachesTheWire is the core of item 1.
//
// MUTATION GATE: replace `Features: registeredFeatures()` in
// sendTelemetryPingNow with `Features: []string{}` and this test fails with
// "features = [] ... want [adapter:langchain]".
func TestRegisteredAdapterReachesTheWire(t *testing.T) {
	defer resetAdapterRegistryForTest()()

	RegisterAdapter("langchain")

	features, present := captureFeatures(t)
	if !present {
		t.Fatal("`features` key absent from the wire")
	}
	if len(features) != 1 || features[0] != "adapter:langchain" {
		t.Errorf("features = %v, want [adapter:langchain]", features)
	}
}

// TestUnregisteredAdapterDoesNotReachTheWire pairs with the test above: the
// array carries what was declared and nothing else. Without this, a
// registeredFeatures() that returned a hardcoded list would pass the positive
// case.
func TestUnregisteredAdapterDoesNotReachTheWire(t *testing.T) {
	defer resetAdapterRegistryForTest()()

	RegisterAdapter("langchain")

	features, _ := captureFeatures(t)
	for _, f := range features {
		if f == "adapter:langgraph" {
			t.Errorf("features = %v contains adapter:langgraph, which nothing registered", features)
		}
	}
	// Positive control: the run DID happen and DID carry the thing that was
	// registered, so the absence above is a real absence.
	if len(features) != 1 || features[0] != "adapter:langchain" {
		t.Fatalf("features = %v, want exactly [adapter:langchain] — without this the absence check above is vacuous", features)
	}
}

// TestRegisterAdapterNormalisesAndDeduplicates pins the only two
// transformations the SDK applies, and that it applies no others.
func TestRegisterAdapterNormalisesAndDeduplicates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inputs []string
		want   []string
		about  string
	}{
		{
			name:   "lowercased",
			inputs: []string{"LangChain"},
			want:   []string{"adapter:langchain"},
			about:  "the receiver folds case before matching; sending the fold too keeps one spelling on the row",
		},
		{
			name:   "trimmed",
			inputs: []string{"  langgraph\t\n"},
			want:   []string{"adapter:langgraph"},
			about:  "surrounding whitespace is not part of an identifier",
		},
		{
			name:   "deduplicated",
			inputs: []string{"litellm", "LITELLM", " litellm "},
			want:   []string{"adapter:litellm"},
			about:  "an adapter whose constructor runs per request must declare itself once",
		},
		{
			name:   "sorted, so the wire is deterministic",
			inputs: []string{"langgraph", "langchain"},
			want:   []string{"adapter:langchain", "adapter:langgraph"},
			about:  "registration order must not change the bytes",
		},
		{
			name:   "an unrecognised name is NOT filtered",
			inputs: []string{"some-framework-we-have-never-heard-of"},
			want:   []string{"adapter:some-framework-we-have-never-heard-of"},
			about:  "an SDK-side allowlist would be a second vocabulary that drifts from the receiver's",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer resetAdapterRegistryForTest()()
			for _, n := range tc.inputs {
				RegisterAdapter(n)
			}
			got := registeredFeatures()
			if len(got) != len(tc.want) {
				t.Fatalf("registeredFeatures() = %v, want %v (%s)", got, tc.want, tc.about)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("registeredFeatures()[%d] = %q, want %q (%s)", i, got[i], tc.want[i], tc.about)
				}
			}
		})
	}
}

// TestRegisterAdapterRefusesEmptyNames — `adapter:` alone is not an
// identifier, and a whitespace-only name is empty after the trim the
// receiver also applies.
func TestRegisterAdapterRefusesEmptyNames(t *testing.T) {
	for _, name := range []string{"", "   ", "\t\n"} {
		t.Run("name="+strings.ReplaceAll(name, "\t", "\\t"), func(t *testing.T) {
			defer resetAdapterRegistryForTest()()
			RegisterAdapter(name)
			if got := registeredFeatures(); len(got) != 0 {
				t.Errorf("registeredFeatures() = %v, want [] — a name that is empty after trimming declares nothing", got)
			}
		})
	}
}

// TestAdapterNameCapIsBytesAndDropsWhole is the item-2 boundary, asserted at
// exactly 64/65 rather than at a round number far from the edge.
//
// TWO MUTATION GATES, and they fail in opposite directions:
//
//  1. Set maxRelayedValueBytes to 65 → the 65-byte case is admitted and
//     "want the 65-byte name DROPPED" fails.
//  2. Replace the drop with a truncation (register normalized[:64] instead
//     of returning) → the 65-byte case yields a 64-byte name on the wire and
//     the same assertion fails, now with a value present.
//
// The multi-byte case is what makes this a BYTE cap rather than a character
// cap: 33 two-byte runes are 33 characters and 66 bytes. A cap written as
// utf8.RuneCountInString would admit it.
func TestAdapterNameCapIsBytesAndDropsWhole(t *testing.T) {
	sixtyFour := strings.Repeat("a", 64)
	sixtyFive := strings.Repeat("a", 65)
	// 33 x U+00E9 ("é") = 33 runes, 66 bytes.
	thirtyThreeAccents := strings.Repeat("é", 33)

	t.Run("64 bytes is kept", func(t *testing.T) {
		defer resetAdapterRegistryForTest()()
		RegisterAdapter(sixtyFour)
		got := registeredFeatures()
		if len(got) != 1 || got[0] != featureAdapterPrefix+sixtyFour {
			t.Errorf("a 64-byte name was refused; got %v", got)
		}
	})

	t.Run("65 bytes is dropped WHOLE", func(t *testing.T) {
		defer resetAdapterRegistryForTest()()
		RegisterAdapter(sixtyFive)
		got := registeredFeatures()
		if len(got) != 0 {
			t.Errorf("registeredFeatures() = %v, want the 65-byte name DROPPED. "+
				"A truncated adapter name is a name nothing is running, and the receiver "+
				"would bucket it as a real value", got)
		}
	})

	t.Run("the cap counts BYTES, not characters", func(t *testing.T) {
		defer resetAdapterRegistryForTest()()
		if len([]rune(thirtyThreeAccents)) > maxRelayedValueBytes {
			t.Fatalf("fixture is wrong: %d runes is already over the cap, so this "+
				"case could not distinguish a byte cap from a character cap",
				len([]rune(thirtyThreeAccents)))
		}
		if len(thirtyThreeAccents) <= maxRelayedValueBytes {
			t.Fatalf("fixture is wrong: %d bytes is under the cap", len(thirtyThreeAccents))
		}
		RegisterAdapter(thirtyThreeAccents)
		if got := registeredFeatures(); len(got) != 0 {
			t.Errorf("registeredFeatures() = %v; 33 two-byte runes are 33 CHARACTERS but 66 BYTES "+
				"and must be dropped — this is the case a character-counting cap admits", got)
		}
	})
}

// TestFeaturesArrayIsBoundedToThirtyTwoEntries — the entry cap, driven
// through the real registry because it IS reachable that way.
//
// MUTATION GATE: raise maxFeatures to 33 and the length assertion fails.
func TestFeaturesArrayIsBoundedToThirtyTwoEntries(t *testing.T) {
	defer resetAdapterRegistryForTest()()

	for i := 0; i < 40; i++ {
		// Zero-padded so the sort order is the numeric order, making "which
		// 32 survive" a stated answer rather than an accident.
		RegisterAdapter(fmt.Sprintf("%02d", i))
	}
	got := registeredFeatures()
	if len(got) != maxFeatures {
		t.Fatalf("registeredFeatures() returned %d entries, want the cap of %d", len(got), maxFeatures)
	}
	if got[0] != featureAdapterPrefix+"00" {
		t.Errorf("got[0] = %q, want the sorted-first entry — the cap must be deterministic, not map-iteration order", got[0])
	}
	if got[maxFeatures-1] != featureAdapterPrefix+"31" {
		t.Errorf("got[%d] = %q, want adapter:31", maxFeatures-1, got[maxFeatures-1])
	}
}

// TestBoundFeaturesDropsAnOverlongEntry tests the byte bound DIRECTLY on
// boundFeatures rather than through RegisterAdapter, and says why.
//
// RegisterAdapter cannot produce an entry over maxFeatureBytes: it already
// refuses a name over 64 bytes, so the longest entry it can emit is
// len("adapter:")+64 = 72. A test driven through the registry could not
// express this defect and would read as disproof of a bound that was never
// exercised. Driving boundFeatures directly is the only way to vary the axis.
//
// MUTATION GATE: replace the `continue` in boundFeatures with a truncation
// (`f = f[:maxFeatureBytes]`) and the "want it DROPPED" assertion fails.
func TestBoundFeaturesDropsAnOverlongEntry(t *testing.T) {
	// Positive control on the premise this test's framing rests on: the
	// registry genuinely cannot reach this bound.
	longestFromRegistry := len(featureAdapterPrefix) + maxRelayedValueBytes
	if longestFromRegistry > maxFeatureBytes {
		t.Fatalf("the premise changed: RegisterAdapter can now emit a %d-byte entry, which exceeds "+
			"maxFeatureBytes (%d). This bound is now reachable through the registry and MUST be "+
			"tested through it as well", longestFromRegistry, maxFeatureBytes)
	}

	within := "adapter:" + strings.Repeat("b", maxFeatureBytes-len("adapter:"))
	over := within + "b"
	if len(within) != maxFeatureBytes || len(over) != maxFeatureBytes+1 {
		t.Fatalf("fixture is wrong: within=%d over=%d", len(within), len(over))
	}

	got := boundFeatures([]string{within, over})
	if len(got) != 1 || got[0] != within {
		t.Errorf("boundFeatures kept %v; the %d-byte entry must be kept and the %d-byte entry DROPPED WHOLE, not truncated",
			got, len(within), len(over))
	}
}

// TestFeaturesNeverSerializesAsNull — the wire shape for "nothing declared"
// is `[]`, and a nil slice would make it `null`. The receiver treats an
// absent/null array differently from an empty one ("the emitter reported no
// features" vs "it does not report them"), so this is a contract, not
// cosmetics.
func TestFeaturesNeverSerializesAsNull(t *testing.T) {
	defer resetAdapterRegistryForTest()()

	body, err := json.Marshal(telemetryPayload{Features: registeredFeatures()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"features":[]`) {
		t.Errorf("payload serialized as %s, want features as [] not null", string(body))
	}
}
