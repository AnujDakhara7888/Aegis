package hashchain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aegis.local/runtime/internal/canonical"
	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/hashchain"
)

type vector struct {
	Name         string          `json:"name"`
	Event        json.RawMessage `json:"event"`
	CanonicalHex string          `json:"canonical_hex"`
	PreviousHash string          `json:"previous_hash"`
	EventHash    string          `json:"event_hash"`
}

func load(t *testing.T, name string) (vector, event.Event) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/canonical", name))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	e, err := event.DecodeEvent(v.Event)
	if err != nil {
		t.Fatal(err)
	}
	return v, e
}
func sum(t *testing.T, e event.Event) event.Digest {
	t.Helper()
	h, err := hashchain.Sum(e)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func ptr[T any](v T) *T { return &v }
func TestPermanentGoldenVectors(t *testing.T) {
	files, err := filepath.Glob("../../testdata/canonical/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("expected four permanent vectors, got %d", len(files))
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			v, e := load(t, filepath.Base(path))
			b, err := canonical.Encode(e)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(b) != v.CanonicalHex {
				t.Fatalf("canonical vector changed\nwant %s\n got %x", v.CanonicalHex, b)
			}
			if e.PreviousEventHash.String() != v.PreviousHash {
				t.Fatal("previous hash differs")
			}
			h := sum(t, e)
			if h.String() != v.EventHash || h != e.EventHash {
				t.Fatalf("hash differs: %s", h)
			}
		})
	}
}
func TestEveryLogicalFieldCovered(t *testing.T) {
	_, original := load(t, "02-linked-rich.json")
	want := sum(t, original)
	tests := []struct {
		name   string
		change func(*event.Event)
	}{
		{"run", func(e *event.Event) { e.RunID = "other" }}, {"event", func(e *event.Event) { e.EventID = "other" }},
		{"parent", func(e *event.Event) { e.ParentEventID = ptr("different") }}, {"parent absent", func(e *event.Event) { e.ParentEventID = nil }},
		{"sequence", func(e *event.Event) { e.Sequence++ }}, {"wall time", func(e *event.Event) { e.ObservedAtUnixNano-- }},
		{"instance", func(e *event.Event) { e.SourceInstanceID = ptr("different") }}, {"monotonic", func(e *event.Event) { e.SourceMonotonicNano = ptr(int64(1)) }},
		{"source", func(e *event.Event) { e.Source = event.SourceAgent }}, {"kind", func(e *event.Event) { e.Kind = event.KindToolFailed }},
		{"phase", func(e *event.Event) { e.Phase = event.PhaseEnd }},
		{"input", func(e *event.Event) { e.InputHash = ptr(event.Digest{1}) }}, {"input absent", func(e *event.Event) { e.InputHash = nil }},
		{"output", func(e *event.Event) { e.OutputHash = ptr(event.Digest{2}) }}, {"output absent", func(e *event.Event) { e.OutputHash = nil }},
		{"payload", func(e *event.Event) { e.PayloadHash = ptr(event.Digest{3}) }}, {"payload absent", func(e *event.Event) { e.PayloadHash = nil }},
		{"size", func(e *event.Event) { e.PayloadSize = 1 }}, {"capability", func(e *event.Event) { e.CapabilityID = ptr("other") }},
		{"capability absent", func(e *event.Event) { e.CapabilityID = nil }}, {"policy", func(e *event.Event) { e.PolicyDecision = event.PolicyDecisionDeny }},
		{"effect", func(e *event.Event) { e.SideEffectClass = event.SideEffectClassRead }}, {"replay", func(e *event.Event) { e.ReplayBehavior = event.ReplayBehaviorRecordedResult }},
		{"retry", func(e *event.Event) { e.IdempotencyKey = ptr("other") }}, {"retry absent", func(e *event.Event) { e.IdempotencyKey = nil }},
		{"attribute key", func(e *event.Event) { e.Attributes["b"] = e.Attributes["a"]; delete(e.Attributes, "a") }},
		{"attribute value", func(e *event.Event) { e.Attributes["a"] = "changed" }}, {"attribute count", func(e *event.Event) { delete(e.Attributes, "z") }},
		{"previous", func(e *event.Event) { e.PreviousEventHash[0] ^= 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, e := load(t, "02-linked-rich.json")
			tt.change(&e)
			if sum(t, e) == want {
				t.Fatal("field not covered by chain hash")
			}
		})
	}
	// Schema is covered by canonical bytes, but alternate versions must be rejected.
	e := original
	e.SchemaVersion++
	if _, err := hashchain.Sum(e); err == nil {
		t.Fatal("accepted unknown schema")
	}
	e = original
	e.EventHash = event.Digest{7}
	if sum(t, e) != want {
		t.Fatal("self hash must be excluded")
	}
}
func TestChainLinksAndDomainSeparation(t *testing.T) {
	_, first := load(t, "01-minimal.json")
	_, second := load(t, "02-linked-rich.json")
	if first.PreviousEventHash != (event.Digest{}) || second.PreviousEventHash != sum(t, first) {
		t.Fatal("fixture chain is not linked")
	}
	originalTerminal := sum(t, second)
	changed := first
	changed.Attributes = map[string]string{"tampered": "yes"}
	second.PreviousEventHash = sum(t, changed)
	if sum(t, second) == originalTerminal {
		t.Fatal("prefix modification did not propagate")
	}
	// Removal or a different predecessor changes the terminal link relative to its anchor.
	second.PreviousEventHash = event.Digest{}
	if sum(t, second) == originalTerminal {
		t.Fatal("predecessor removal invisible")
	}
	b, err := canonical.Encode(first)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain := sha256.Sum256(append(first.PreviousEventHash[:], b...))
	if event.Digest(wrongDomain) == sum(t, first) {
		t.Fatal("missing domain separation")
	}
	before, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	_ = sum(t, first)
	after, _ := json.Marshal(first)
	if !bytes.Equal(before, after) {
		t.Fatal("Sum mutated event")
	}
	first.Sequence = 0
	if h, err := hashchain.Sum(first); err == nil || h != (event.Digest{}) {
		t.Fatal("invalid event returned a usable hash")
	}
}
func TestJSONPresentationDoesNotAffectHash(t *testing.T) {
	_, e := load(t, "02-linked-rich.json")
	want := sum(t, e)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := event.DecodeEvent(pretty)
	if err != nil {
		t.Fatal(err)
	}
	if sum(t, decoded) != want {
		t.Fatal("JSON presentation affected logical hash")
	}
}
