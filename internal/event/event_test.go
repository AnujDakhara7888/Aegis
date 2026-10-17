package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }
func sample() Event {
	return Event{Fields: Fields{EventID: "event-1", Source: SourceAgent, Kind: KindRunStarted, Phase: PhaseStart,
		PolicyDecision: PolicyDecisionNone, SideEffectClass: SideEffectClassNone, ReplayBehavior: ReplayBehaviorUnspecified,
		Attributes: map[string]string{}}, SchemaVersion: 1, RunID: "run-1", Sequence: 1}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestEventJSONRoundTrip(t *testing.T) {
	e := sample()
	e.SourceInstanceID = ptr("process-1")
	e.SourceMonotonicNano = ptr(int64(0))
	e.ObservedAtUnixNano = math.MinInt64
	e.InputHash = ptr(Digest{1})
	e.OutputHash = ptr(Digest{2})
	e.PayloadHash = ptr(Digest{3})
	e.CapabilityID = ptr("cap:read")
	e.IdempotencyKey = ptr("retry-1")
	e.ParentEventID = ptr("other")
	e.Attributes["é"] = "世界\x00🙂"
	b := mustJSON(t, e)
	got, err := DecodeEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, e) {
		t.Fatalf("round trip differs: %+v", got)
	}
	if !bytes.Contains(b, []byte(`"source":"AGENT"`)) {
		t.Fatal("enum not readable")
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	got, err = DecodeEvent(formatted.Bytes())
	if err != nil || !reflect.DeepEqual(got, e) {
		t.Fatal("whitespace changed logical data", err)
	}
}
func TestValidationLimits(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Event)
	}{
		{"schema zero", func(e *Event) { e.SchemaVersion = 0 }}, {"schema future", func(e *Event) { e.SchemaVersion = 2 }},
		{"empty event", func(e *Event) { e.EventID = "" }}, {"long event", func(e *Event) { e.EventID = strings.Repeat("x", 129) }},
		{"run traversal", func(e *Event) { e.RunID = "../run" }}, {"run absolute", func(e *Event) { e.RunID = "/run" }},
		{"unicode ID", func(e *Event) { e.EventID = "é" }}, {"id prefix", func(e *Event) { e.EventID = "_x" }},
		{"parent invalid", func(e *Event) { e.ParentEventID = ptr("") }}, {"self parent", func(e *Event) { e.ParentEventID = ptr(e.EventID) }},
		{"sequence", func(e *Event) { e.Sequence = 0 }}, {"source", func(e *Event) { e.Source = 0 }},
		{"kind", func(e *Event) { e.Kind = 26 }}, {"phase", func(e *Event) { e.Phase = 65535 }},
		{"policy", func(e *Event) { e.PolicyDecision = 0 }}, {"effect", func(e *Event) { e.SideEffectClass = 8 }},
		{"replay", func(e *Event) { e.ReplayBehavior = 0 }},
		{"empty instance", func(e *Event) { e.SourceInstanceID = ptr("") }},
		{"long capability", func(e *Event) { e.CapabilityID = ptr(strings.Repeat("x", 257)) }},
		{"invalid UTF8 optional", func(e *Event) { e.IdempotencyKey = ptr(string([]byte{255})) }},
		{"negative monotonic", func(e *Event) { e.SourceInstanceID = ptr("p"); e.SourceMonotonicNano = ptr(int64(-1)) }},
		{"monotonic no instance", func(e *Event) { e.SourceMonotonicNano = ptr(int64(0)) }},
		{"key empty", func(e *Event) { e.Attributes[""] = "x" }},
		{"key long", func(e *Event) { e.Attributes[strings.Repeat("x", 65)] = "x" }},
		{"value long", func(e *Event) { e.Attributes["k"] = strings.Repeat("x", 4097) }},
		{"UTF8 key", func(e *Event) { e.Attributes[string([]byte{255})] = "" }},
		{"UTF8 value", func(e *Event) { e.Attributes["k"] = string([]byte{255}) }},
		{"attribute count", func(e *Event) {
			for i := 0; i < 33; i++ {
				e.Attributes[fmt.Sprint(i)] = ""
			}
		}},
		{"total bytes", func(e *Event) {
			for i := 0; i < 16; i++ {
				e.Attributes[fmt.Sprint(i)] = strings.Repeat("x", 4096)
			}
		}},
		{"size without hash", func(e *Event) { e.PayloadSize = 1 }},
		{"payload too big", func(e *Event) { e.PayloadHash = ptr(Digest{}); e.PayloadSize = MaxPayloadBytes + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := sample()
			tt.change(&e)
			if e.Validate() == nil {
				t.Fatal("accepted invalid event")
			}
		})
	}
}
func TestValidBoundaries(t *testing.T) {
	e := sample()
	e.EventID = strings.Repeat("a", 128)
	e.RunID = strings.Repeat("Z", 128)
	e.SourceInstanceID = ptr(strings.Repeat("é", 128))
	e.CapabilityID = ptr(strings.Repeat("x", 256))
	e.IdempotencyKey = ptr(strings.Repeat("x", 256))
	e.SourceMonotonicNano = ptr(int64(math.MaxInt64))
	e.Sequence = math.MaxUint64
	e.ObservedAtUnixNano = math.MaxInt64
	e.PayloadHash = ptr(Digest{})
	e.PayloadSize = MaxPayloadBytes
	for i := 0; i < 16; i++ {
		e.Attributes[fmt.Sprintf("%064d", i)] = strings.Repeat("x", 4032)
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	} // exactly 65536 total attribute bytes
	if _, err := DecodeEvent(mustJSON(t, e)); err != nil {
		t.Fatal(err)
	}
	e.Attributes = map[string]string{}
	for i := 0; i < 32; i++ {
		e.Attributes[fmt.Sprint(i)] = ""
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Attributes = nil
	e.PayloadSize = 0
	e.ObservedAtUnixNano = math.MinInt64
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEvent(mustJSON(t, e)); err != nil {
		t.Fatal("nil attributes must serialize as object", err)
	}
}
func TestStrictJSONRejection(t *testing.T) {
	base := string(mustJSON(t, sample()))
	tests := map[string]string{
		"unknown":              strings.Replace(base, `"event_id":`, `"extra":1,"event_id":`, 1),
		"duplicate":            strings.Replace(base, `"event_id":`, `"event_id":"other","event_id":`, 1),
		"escaped duplicate":    strings.Replace(base, `"event_id":`, `"event_\u0069d":"other","event_id":`, 1),
		"case alias":           strings.Replace(base, `"event_id":`, `"EVENT_ID":"other","event_id":`, 1),
		"duplicate attributes": strings.Replace(base, `"attributes":{}`, `"attributes":{"x":"1","\u0078":"2"}`, 1),
		"null attribute":       strings.Replace(base, `"attributes":{}`, `"attributes":{"x":null}`, 1),
		"null optional":        strings.Replace(base, `"attributes":{}`, `"parent_event_id":null,"attributes":{}`, 1),
		"float":                strings.Replace(base, `"sequence":1`, `"sequence":1.0`, 1),
		"negative unsigned":    strings.Replace(base, `"sequence":1`, `"sequence":-1`, 1),
		"overflow":             strings.Replace(base, `"sequence":1`, `"sequence":18446744073709551616`, 1),
		"time overflow":        strings.Replace(base, `"observed_at_unix_nano":0`, `"observed_at_unix_nano":9223372036854775808`, 1),
		"numeric enum":         strings.Replace(base, `"source":"AGENT"`, `"source":1`, 1),
		"unknown enum":         strings.Replace(base, `"source":"AGENT"`, `"source":"agent"`, 1),
		"high surrogate":       strings.Replace(base, `"attributes":{}`, `"attributes":{"x":"\ud800"}`, 1),
		"low surrogate":        strings.Replace(base, `"attributes":{}`, `"attributes":{"x":"\udc00"}`, 1),
		"bad pair":             strings.Replace(base, `"attributes":{}`, `"attributes":{"x":"\ud800\u0041"}`, 1),
		"invalid utf8":         strings.Replace(base, `"attributes":{}`, "\"attributes\":{\"x\":\"\xff\"}", 1),
		"trailing":             base + ` {}`, "array": "[]", "null": "null", "truncated": base[:len(base)-1],
		"oversize": strings.Repeat(" ", MaxEventJSONBytes) + base,
		"nested":   strings.Replace(base, `"attributes":{}`, `"attributes":{"x":[[[["x"]]]]}`, 1),
	}
	for name, s := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEvent([]byte(s)); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
	for _, group := range [][]string{commonRequired, eventRequired} {
		for _, key := range group {
			t.Run("missing "+key, func(t *testing.T) {
				var m map[string]any
				_ = json.Unmarshal([]byte(base), &m)
				delete(m, key)
				if _, err := DecodeEvent(mustJSON(t, m)); err == nil {
					t.Fatal("accepted missing field")
				}
			})
		}
	}
	valid := strings.Replace(base, `"attributes":{}`, `"attributes":{"a":"\ud83d\ude42","b":"\\ud800","c":"\"","d":"�"}`, 1)
	if _, err := DecodeEvent([]byte(valid)); err != nil {
		t.Fatal("rejected valid Unicode/escapes", err)
	}
}
func TestInputAuthorityAndPayload(t *testing.T) {
	input := EventInput{Fields: sample().Fields}
	for _, payload := range []*[]byte{nil, ptr([]byte(nil)), ptr([]byte{}), ptr([]byte{0, 255, 1}), ptr(make([]byte, MaxPayloadBytes))} {
		input.Payload = payload
		b := mustJSON(t, input)
		got, err := DecodeInput(b)
		if err != nil {
			t.Fatal(err)
		}
		if (got.Payload == nil) != (payload == nil) {
			t.Fatal("payload presence lost")
		}
		if payload != nil && !bytes.Equal(*got.Payload, *payload) {
			t.Fatal("payload changed")
		}
	}
	input.Payload = ptr(make([]byte, MaxPayloadBytes+1))
	if input.Validate() == nil {
		t.Fatal("accepted oversized payload")
	}
	if _, err := DecodeInput(mustJSON(t, input)); err == nil {
		t.Fatal("decoder accepted oversized payload")
	}
	input.Payload = nil
	b := mustJSON(t, input)
	for _, key := range append(append([]string{}, eventRequired...), "payload_hash") {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m[key] = "spoof"
		if _, err := DecodeInput(mustJSON(t, m)); err == nil {
			t.Fatalf("accepted recorder-owned field %s", key)
		}
	}
	for _, raw := range []string{`[1,2]`, `null`, `"!bad!"`} {
		bad := strings.Replace(string(b), `"attributes":{}`, `"payload":`+raw+`,"attributes":{}`, 1)
		if _, err := DecodeInput([]byte(bad)); err == nil {
			t.Fatal("accepted invalid payload", raw)
		}
	}
	if _, err := DecodeInput(append(bytes.Repeat([]byte(" "), MaxInputJSONBytes), b...)); err == nil {
		t.Fatal("accepted oversized input JSON")
	}
}
func TestDigest(t *testing.T) {
	d := Digest{0, 1, 255}
	got, err := ParseDigest(d.String())
	if err != nil || got != d {
		t.Fatal(err)
	}
	for _, s := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("G", 64), strings.Repeat("A", 64)} {
		if _, err := ParseDigest(s); err == nil {
			t.Fatal("accepted invalid digest")
		}
	}
	for _, b := range []string{`null`, `1`, `"bad"`} {
		var d Digest
		if json.Unmarshal([]byte(b), &d) == nil {
			t.Fatal("accepted invalid digest JSON")
		}
	}
}
func TestEnumWireValues(t *testing.T) {
	// Explicit names and numeric order are pinned independently of production tables.
	tables := []struct {
		value any
		names []string
	}{
		{Source(0), strings.Fields("AGENT RECORDER MODEL TOOL PROXY KERNEL AUDIT_READER")},
		{Kind(0), strings.Fields("RUN_STARTED RUN_COMPLETED RUN_FAILED DOCUMENT_RETRIEVED MODEL_REQUESTED MODEL_RESPONDED TOOL_REQUESTED TOOL_COMPLETED TOOL_FAILED NETWORK_REQUESTED NETWORK_COMPLETED APPROVAL_REQUESTED APPROVAL_GRANTED APPROVAL_REJECTED POLICY_ALLOWED POLICY_DENIED CAPABILITY_ALLOWED CAPABILITY_DENIED SIDE_EFFECT_PREPARED SIDE_EFFECT_COMMITTED CHECKPOINT_CREATED BUDGET_UPDATED BUDGET_EXCEEDED RUNTIME_FAILED KERNEL_EVENT_OBSERVED")},
		{Phase(0), strings.Fields("INSTANT REQUEST RESPONSE START END")},
		{PolicyDecision(0), strings.Fields("NONE ALLOW DENY REQUIRE_APPROVAL")},
		{SideEffectClass(0), strings.Fields("NONE PURE READ REVERSIBLE_WRITE IRREVERSIBLE_WRITE NONDETERMINISTIC HUMAN_APPROVAL")},
		{ReplayBehavior(0), strings.Fields("UNSPECIFIED REEXECUTE RECORDED_RESULT SIMULATE NEVER REQUIRE_APPROVAL")},
	}
	for _, tt := range tables {
		for i, name := range tt.names {
			v := reflect.New(reflect.TypeOf(tt.value))
			v.Elem().SetUint(uint64(i + 1))
			b, err := json.Marshal(v.Interface())
			if err != nil || string(b) != `"`+name+`"` {
				t.Fatalf("enum %T %d changed: %s %v", tt.value, i+1, b, err)
			}
			dst := reflect.New(v.Elem().Type())
			if err := json.Unmarshal(b, dst.Interface()); err != nil {
				t.Fatal(err)
			}
			if dst.Elem().Uint() != uint64(i+1) {
				t.Fatal("numeric assignment changed")
			}
		}
		for _, n := range []uint64{0, uint64(len(tt.names) + 1), 65535} {
			v := reflect.New(reflect.TypeOf(tt.value))
			v.Elem().SetUint(n)
			if _, err := json.Marshal(v.Interface()); err == nil {
				t.Fatal("invalid enum marshaled")
			}
		}
		for _, raw := range []string{`0`, `null`, `"UNKNOWN"`, `""`, `true`} {
			v := reflect.New(reflect.TypeOf(tt.value))
			if json.Unmarshal([]byte(raw), v.Interface()) == nil {
				t.Fatal("invalid enum decoded")
			}
		}
	}
}
func FuzzDecodeEvent(f *testing.F) {
	b, _ := json.Marshal(sample())
	f.Add(b)
	f.Add([]byte(`{"x":"\ud800"}`))
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEvent(b)
		if err != nil {
			return
		}
		if err := e.Validate(); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeEvent(out)
		if err != nil || !reflect.DeepEqual(e, again) {
			t.Fatal("unstable strict round trip", err)
		}
	})
}
