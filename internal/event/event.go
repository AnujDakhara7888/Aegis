package event

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion          uint16 = 1
	MaxIDBytes                    = 128
	MaxOptionalStringBytes        = 256
	MaxAttributes                 = 32
	MaxAttributeKeyBytes          = 64
	MaxAttributeValueBytes        = 4096
	MaxAttributeTotalBytes        = 65536
	MaxPayloadBytes               = 1 << 20
	MaxInputJSONBytes             = 2 << 20
	MaxEventJSONBytes             = 512 << 10
)

// Digest is a raw SHA-256 digest. JSON uses exactly 64 lowercase hex characters.
type Digest [32]byte

func (d Digest) String() string { return hex.EncodeToString(d[:]) }
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) != 64 || s != strings.ToLower(s) {
		return d, fmt.Errorf("digest must be 64 lowercase hex characters")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return d, fmt.Errorf("invalid digest: %w", err)
	}
	copy(d[:], b)
	return d, nil
}
func (d Digest) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }
func (d *Digest) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParseDigest(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// Fields is the client-controlled logical content common to inputs and events.
// Callers must not mutate fields, maps, or pointed-to values during validation or encoding.
type Fields struct {
	EventID             string            `json:"event_id"`
	ParentEventID       *string           `json:"parent_event_id,omitempty"`
	SourceInstanceID    *string           `json:"source_instance_id,omitempty"`
	SourceMonotonicNano *int64            `json:"source_monotonic_nano,omitempty"`
	Source              Source            `json:"source"`
	Kind                Kind              `json:"kind"`
	Phase               Phase             `json:"phase"`
	InputHash           *Digest           `json:"input_hash,omitempty"`
	OutputHash          *Digest           `json:"output_hash,omitempty"`
	CapabilityID        *string           `json:"capability_id,omitempty"`
	PolicyDecision      PolicyDecision    `json:"policy_decision"`
	SideEffectClass     SideEffectClass   `json:"side_effect_class"`
	ReplayBehavior      ReplayBehavior    `json:"replay_behavior"`
	IdempotencyKey      *string           `json:"idempotency_key,omitempty"`
	Attributes          map[string]string `json:"attributes"`
}

// EventInput never accepts recorder-owned sequence, time, run, or chain fields.
// A nil Payload is absent; a pointer to an empty slice is an empty payload.
type EventInput struct {
	Fields
	Payload *[]byte `json:"payload,omitempty"`
}

// Event is the logical accepted record. Hash fields are excluded from canonical bytes.
type Event struct {
	Fields
	SchemaVersion      uint16  `json:"schema_version"`
	RunID              string  `json:"run_id"`
	Sequence           uint64  `json:"sequence"`
	ObservedAtUnixNano int64   `json:"observed_at_unix_nano"`
	PayloadHash        *Digest `json:"payload_hash,omitempty"`
	PayloadSize        uint64  `json:"payload_size"`
	PreviousEventHash  Digest  `json:"previous_event_hash"`
	EventHash          Digest  `json:"event_hash"`
}

// MarshalJSON normalizes a programmatic nil attribute map to the empty object.
func (e Event) MarshalJSON() ([]byte, error) {
	type plain Event
	if e.Attributes == nil {
		e.Attributes = map[string]string{}
	}
	return json.Marshal(plain(e))
}
func (e EventInput) MarshalJSON() ([]byte, error) {
	type plain EventInput
	if e.Attributes == nil {
		e.Attributes = map[string]string{}
	}
	if e.Payload != nil && *e.Payload == nil {
		empty := []byte{}
		e.Payload = &empty
	}
	return json.Marshal(plain(e))
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > MaxIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}

// ValidateID reports whether s is a safe schema-v1 run or event identifier.
// IDs are deliberately path-separator-free because run IDs become directory names.
func ValidateID(s string) error {
	if !validID(s) {
		return fmt.Errorf("invalid identifier")
	}
	return nil
}
func validString(s string, min, max int) bool {
	return len(s) >= min && len(s) <= max && utf8.ValidString(s)
}
func (f Fields) Validate() error {
	if !validID(f.EventID) {
		return fmt.Errorf("invalid event_id")
	}
	if f.ParentEventID != nil && (!validID(*f.ParentEventID) || *f.ParentEventID == f.EventID) {
		return fmt.Errorf("invalid parent_event_id")
	}
	for _, v := range []struct {
		name  string
		value *string
	}{
		{"source_instance_id", f.SourceInstanceID}, {"capability_id", f.CapabilityID}, {"idempotency_key", f.IdempotencyKey},
	} {
		if v.value != nil && !validString(*v.value, 1, MaxOptionalStringBytes) {
			return fmt.Errorf("invalid %s", v.name)
		}
	}
	if f.SourceMonotonicNano != nil && (*f.SourceMonotonicNano < 0 || f.SourceInstanceID == nil) {
		return fmt.Errorf("source_monotonic_nano requires nonnegative time and source_instance_id")
	}
	if !f.Source.Valid() || !f.Kind.Valid() || !f.Phase.Valid() || !f.PolicyDecision.Valid() || !f.SideEffectClass.Valid() || !f.ReplayBehavior.Valid() {
		return fmt.Errorf("unknown required enum")
	}
	if len(f.Attributes) > MaxAttributes {
		return fmt.Errorf("too many attributes")
	}
	total := 0
	for k, v := range f.Attributes {
		if !validString(k, 1, MaxAttributeKeyBytes) || !validString(v, 0, MaxAttributeValueBytes) {
			return fmt.Errorf("invalid attribute length or UTF-8")
		}
		total += len(k) + len(v)
	}
	if total > MaxAttributeTotalBytes {
		return fmt.Errorf("attribute byte budget exceeded")
	}
	return nil
}
func (e EventInput) Validate() error {
	if err := e.Fields.Validate(); err != nil {
		return err
	}
	if e.Payload != nil && len(*e.Payload) > MaxPayloadBytes {
		return fmt.Errorf("payload exceeds limit")
	}
	return nil
}

// Validate checks structure, not hash correctness, parent existence, or log ordering.
func (e Event) Validate() error {
	if err := e.Fields.Validate(); err != nil {
		return err
	}
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", e.SchemaVersion)
	}
	if !validID(e.RunID) {
		return fmt.Errorf("invalid run_id")
	}
	if e.Sequence == 0 {
		return fmt.Errorf("sequence must be positive")
	}
	if e.PayloadSize > MaxPayloadBytes || e.PayloadHash == nil && e.PayloadSize != 0 {
		return fmt.Errorf("invalid payload reference size")
	}
	return nil
}
