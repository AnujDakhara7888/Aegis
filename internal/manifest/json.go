package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

var manifestFields = []string{
	"manifest_schema_version", "run_id", "event_schema_version", "event_count",
	"first_event_hash", "terminal_event_hash", "referenced_blob_set_digest",
	"completion_status", "sealed_at_unix_nano", "recorder_public_key_fingerprint",
	"signature_algorithm", "signature",
}

// Decode applies strict trust-boundary JSON rules before validating the manifest.
func Decode(data []byte) (Manifest, error) {
	if len(data) > MaxJSONBytes {
		return Manifest{}, fmt.Errorf("manifest JSON exceeds %d bytes", MaxJSONBytes)
	}
	if !utf8.Valid(data) || !json.Valid(data) {
		return Manifest{}, fmt.Errorf("invalid manifest JSON or UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return Manifest{}, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return Manifest{}, fmt.Errorf("manifest must be a JSON object")
	}
	seen := make(map[string]bool, len(manifestFields))
	allowed := make(map[string]bool, len(manifestFields))
	for _, field := range manifestFields {
		allowed[field] = true
	}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return Manifest{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return Manifest{}, fmt.Errorf("manifest key must be a string")
		}
		if !allowed[key] {
			return Manifest{}, fmt.Errorf("unknown manifest field %q", key)
		}
		if seen[key] {
			return Manifest{}, fmt.Errorf("duplicate manifest field %q", key)
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return Manifest{}, err
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return Manifest{}, fmt.Errorf("manifest field %q must not be null", key)
		}
	}
	if _, err := dec.Token(); err != nil {
		return Manifest{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Manifest{}, fmt.Errorf("trailing manifest JSON")
	}
	for _, field := range manifestFields {
		if !seen[field] {
			return Manifest{}, fmt.Errorf("missing manifest field %q", field)
		}
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var result Manifest
	if err := dec.Decode(&result); err != nil {
		return Manifest{}, err
	}
	if err := result.Validate(); err != nil {
		return Manifest{}, err
	}
	return result, nil
}
