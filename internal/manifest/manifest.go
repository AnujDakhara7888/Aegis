// Package manifest defines, signs, and verifies the sealed-run manifest format.
package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"aegis.local/runtime/internal/event"
)

const (
	SchemaVersion uint16 = 1
	MaxJSONBytes         = 16 << 10
)

type CompletionStatus uint16

const (
	CompletionCompleted CompletionStatus = 1
	CompletionFailed    CompletionStatus = 2
	CompletionAborted   CompletionStatus = 3
)

var completionNames = [...]string{"", "COMPLETED", "FAILED", "ABORTED"}

func (v CompletionStatus) Valid() bool { return v > 0 && int(v) < len(completionNames) }
func (v CompletionStatus) String() string {
	if !v.Valid() {
		return fmt.Sprintf("UNKNOWN(%d)", v)
	}
	return completionNames[v]
}
func (v CompletionStatus) MarshalJSON() ([]byte, error) {
	if !v.Valid() {
		return nil, fmt.Errorf("unknown completion status %d", v)
	}
	return json.Marshal(v.String())
}
func (v *CompletionStatus) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("completion status must be a string: %w", err)
	}
	for number := 1; number < len(completionNames); number++ {
		if completionNames[number] == name {
			*v = CompletionStatus(number)
			return nil
		}
	}
	return fmt.Errorf("unknown completion status %q", name)
}

type SignatureAlgorithm uint16

const SignatureEd25519 SignatureAlgorithm = 1

func (v SignatureAlgorithm) Valid() bool { return v == SignatureEd25519 }
func (v SignatureAlgorithm) String() string {
	if v == SignatureEd25519 {
		return "ED25519"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}
func (v SignatureAlgorithm) MarshalJSON() ([]byte, error) {
	if !v.Valid() {
		return nil, fmt.Errorf("unknown signature algorithm %d", v)
	}
	return json.Marshal(v.String())
}
func (v *SignatureAlgorithm) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("signature algorithm must be a string: %w", err)
	}
	if name != "ED25519" {
		return fmt.Errorf("unknown signature algorithm %q", name)
	}
	*v = SignatureEd25519
	return nil
}

// Manifest is the complete JSON representation of a sealed run. Signature is
// standard padded base64 in JSON through encoding/json's []byte representation.
type Manifest struct {
	ManifestSchemaVersion        uint16             `json:"manifest_schema_version"`
	RunID                        string             `json:"run_id"`
	EventSchemaVersion           uint16             `json:"event_schema_version"`
	EventCount                   uint64             `json:"event_count"`
	FirstEventHash               event.Digest       `json:"first_event_hash"`
	TerminalEventHash            event.Digest       `json:"terminal_event_hash"`
	ReferencedBlobSetDigest      event.Digest       `json:"referenced_blob_set_digest"`
	CompletionStatus             CompletionStatus   `json:"completion_status"`
	SealedAtUnixNano             int64              `json:"sealed_at_unix_nano"`
	RecorderPublicKeyFingerprint event.Digest       `json:"recorder_public_key_fingerprint"`
	SignatureAlgorithm           SignatureAlgorithm `json:"signature_algorithm"`
	Signature                    []byte             `json:"signature"`
}

// ValidateFields checks all signed fields. It deliberately ignores Signature so
// the same validation can run immediately before signing.
func (m Manifest) ValidateFields() error {
	if m.ManifestSchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported manifest_schema_version %d", m.ManifestSchemaVersion)
	}
	if err := event.ValidateID(m.RunID); err != nil {
		return fmt.Errorf("run_id: %w", err)
	}
	if m.EventSchemaVersion != event.SchemaVersion {
		return fmt.Errorf("unsupported event_schema_version %d", m.EventSchemaVersion)
	}
	if !m.CompletionStatus.Valid() {
		return fmt.Errorf("invalid completion_status")
	}
	if !m.SignatureAlgorithm.Valid() {
		return fmt.Errorf("invalid signature_algorithm")
	}
	if m.EventCount == 0 && (m.FirstEventHash != (event.Digest{}) || m.TerminalEventHash != (event.Digest{})) {
		return fmt.Errorf("empty run must use zero first and terminal hashes")
	}
	return nil
}

func (m Manifest) Validate() error {
	if err := m.ValidateFields(); err != nil {
		return err
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be exactly %d bytes", ed25519.SignatureSize)
	}
	return nil
}

// Fingerprint returns SHA-256 over the raw Ed25519 public key.
func Fingerprint(publicKey ed25519.PublicKey) (event.Digest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return event.Digest{}, fmt.Errorf("public key must be exactly %d bytes", ed25519.PublicKeySize)
	}
	return event.Digest(sha256.Sum256(publicKey)), nil
}
