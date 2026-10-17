package canonical_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"aegis.local/runtime/internal/canonical"
	"aegis.local/runtime/internal/event"
)

func ptr[T any](v T) *T { return &v }
func sample() event.Event {
	return event.Event{Fields: event.Fields{EventID: "e", Source: event.SourceAgent, Kind: event.KindRunStarted, Phase: event.PhaseStart,
		PolicyDecision: event.PolicyDecisionNone, SideEffectClass: event.SideEffectClassNone, ReplayBehavior: event.ReplayBehaviorUnspecified},
		SchemaVersion: 1, RunID: "r", Sequence: 1}
}
func encoded(t *testing.T, e event.Event) []byte {
	t.Helper()
	b, err := canonical.Encode(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestByteLayout(t *testing.T) {
	e := sample()
	e.ObservedAtUnixNano = -2
	b := encoded(t, e)
	if string(b[:14]) != "AEGIS-EVENT-V1" {
		t.Fatal("domain changed")
	}
	if binary.BigEndian.Uint16(b[14:16]) != 1 {
		t.Fatal("schema width")
	}
	// One-byte run/event IDs: each occupies four length bytes plus one content byte.
	if !bytes.Equal(b[16:26], []byte{0, 0, 0, 1, 'r', 0, 0, 0, 1, 'e'}) {
		t.Fatal("string lengths")
	}
	if b[26] != 0 || binary.BigEndian.Uint64(b[27:35]) != 1 {
		t.Fatal("parent marker or sequence offset")
	}
	if !bytes.Equal(b[35:43], []byte{255, 255, 255, 255, 255, 255, 255, 254}) {
		t.Fatal("signed time must be two's complement")
	}
	if len(b) != 74 {
		t.Fatalf("minimal one-character-ID event length changed: %d", len(b))
	}
}
func TestAttributeOrderAndNoMutation(t *testing.T) {
	e := sample()
	e.Attributes = map[string]string{"z": "last", "é": "unicode", "a": ""}
	before := map[string]string{"z": "last", "é": "unicode", "a": ""}
	want := encoded(t, e)
	for i := 0; i < 100; i++ {
		other := sample()
		other.Attributes = map[string]string{}
		other.Attributes["é"] = "unicode"
		other.Attributes["a"] = ""
		other.Attributes["z"] = "last"
		if !bytes.Equal(want, encoded(t, other)) {
			t.Fatal("insertion order changed bytes")
		}
	}
	if !reflect.DeepEqual(e.Attributes, before) {
		t.Fatal("encoder mutated attributes")
	}
	n := sample()
	empty := sample()
	empty.Attributes = map[string]string{}
	if !bytes.Equal(encoded(t, n), encoded(t, empty)) {
		t.Fatal("nil and empty map differ")
	}
	// Reading an immutable shared event is safe and yields independently owned output.
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := canonical.Encode(e)
			if err != nil || !bytes.Equal(b, want) {
				t.Error("concurrent encoding differs", err)
			}
			if len(b) > 0 {
				b[0] = 0
			}
		}()
	}
	wg.Wait()
	if !bytes.Equal(want, encoded(t, e)) {
		t.Fatal("returned buffer aliases shared state")
	}
}
func TestOptionalPresenceAndHashExclusion(t *testing.T) {
	e := sample()
	e.SourceInstanceID = ptr("p")
	absent := encoded(t, e)
	e.SourceMonotonicNano = ptr(int64(0))
	if bytes.Equal(absent, encoded(t, e)) {
		t.Fatal("absent and zero time collide")
	}
	e = sample()
	absent = encoded(t, e)
	e.InputHash = ptr(event.Digest{})
	if bytes.Equal(absent, encoded(t, e)) {
		t.Fatal("absent and zero digest collide")
	}
	e = sample()
	before := encoded(t, e)
	e.PreviousEventHash = event.Digest{1}
	e.EventHash = event.Digest{2}
	if !bytes.Equal(before, encoded(t, e)) {
		t.Fatal("chain fields leaked into canonical bytes")
	}
}
func TestRejectBeforeEncode(t *testing.T) {
	changes := []func(*event.Event){func(e *event.Event) { e.SchemaVersion = 2 }, func(e *event.Event) { e.Source = 0 },
		func(e *event.Event) { e.RunID = "../" }, func(e *event.Event) { e.Sequence = 0 },
		func(e *event.Event) { e.Attributes = map[string]string{"x": strings.Repeat("x", 4097)} },
		func(e *event.Event) { e.CapabilityID = ptr(string([]byte{255})) }}
	for _, change := range changes {
		e := sample()
		change(&e)
		b, err := canonical.Encode(e)
		if err == nil || b != nil {
			t.Fatal("invalid event produced bytes")
		}
	}
}
func TestNoNormalizationOrConcatenationAmbiguity(t *testing.T) {
	a := sample()
	b := sample()
	a.Attributes = map[string]string{"ab": "c"}
	b.Attributes = map[string]string{"a": "bc"}
	if bytes.Equal(encoded(t, a), encoded(t, b)) {
		t.Fatal("missing lengths allow collision")
	}
	a.Attributes = map[string]string{"é": ""}
	b.Attributes = map[string]string{"e\u0301": ""}
	if bytes.Equal(encoded(t, a), encoded(t, b)) {
		t.Fatal("unexpected Unicode normalization")
	}
}
func FuzzCanonicalJSONRoundTrip(f *testing.F) {
	b, _ := json.Marshal(sample())
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := event.DecodeEvent(b)
		if err != nil {
			return
		}
		a := encoded(t, e)
		out, err := json.MarshalIndent(e, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		again, err := event.DecodeEvent(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, encoded(t, again)) {
			t.Fatal("JSON formatting changed canonical bytes")
		}
	})
}
