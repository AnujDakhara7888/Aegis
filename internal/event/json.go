package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

var commonRequired = []string{"event_id", "source", "kind", "phase", "policy_decision", "side_effect_class", "replay_behavior", "attributes"}
var eventRequired = []string{"schema_version", "run_id", "sequence", "observed_at_unix_nano", "payload_size", "previous_event_hash", "event_hash"}

// DecodeEvent is the strict trust-boundary decoder. Bare json.Unmarshal is not a validator.
func DecodeEvent(data []byte) (Event, error) {
	var e Event
	if err := strictDecode(data, MaxEventJSONBytes, eventRequired, &e); err != nil {
		return Event{}, err
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}
func DecodeInput(data []byte) (EventInput, error) {
	var e EventInput
	if err := strictDecode(data, MaxInputJSONBytes, nil, &e); err != nil {
		return EventInput{}, err
	}
	if err := e.Validate(); err != nil {
		return EventInput{}, err
	}
	return e, nil
}
func strictDecode(data []byte, limit int, extraRequired []string, dst any) error {
	if len(data) > limit {
		return fmt.Errorf("JSON exceeds %d bytes", limit)
	}
	if !utf8.Valid(data) || !json.Valid(data) {
		return fmt.Errorf("invalid JSON or UTF-8")
	}
	if err := validSurrogates(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := checkValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return fmt.Errorf("expected JSON object")
	}
	for _, required := range [][]string{commonRequired, extraRequired} {
		for _, k := range required {
			if _, ok := fields[k]; !ok {
				return fmt.Errorf("missing required field %s", k)
			}
		}
	}
	// encoding/json matches struct names case-insensitively. Explicitly forbid that.
	allowed := map[string]bool{}
	for _, k := range commonRequired {
		allowed[k] = true
	}
	for _, k := range []string{"parent_event_id", "source_instance_id", "source_monotonic_nano", "input_hash", "output_hash", "capability_id", "idempotency_key"} {
		allowed[k] = true
	}
	if extraRequired == nil {
		allowed["payload"] = true
	} else {
		for _, k := range extraRequired {
			allowed[k] = true
		}
		allowed["payload_hash"] = true
	}
	for k := range fields {
		if !allowed[k] {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	if payload, ok := fields["payload"]; ok && bytes.TrimSpace(payload)[0] != '"' {
		return fmt.Errorf("payload must be a base64 JSON string")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

// checkValue rejects duplicate keys at every object level and null anywhere.
func checkValue(dec *json.Decoder, depth int) error {
	if depth > 4 {
		return fmt.Errorf("JSON nesting exceeds event schema")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return fmt.Errorf("null is not an event value; omit optional fields")
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok {
					return fmt.Errorf("object key must be a string")
				}
				if seen[s] {
					return fmt.Errorf("duplicate JSON key %q", s)
				}
				seen[s] = true
				if err := checkValue(dec, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := checkValue(dec, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter")
		}
	}
	return nil
}

// encoding/json replaces lone escaped surrogates with U+FFFD; reject them instead.
// json.Valid has already checked string syntax and escape lengths.
func validSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		n, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return fmt.Errorf("unpaired low surrogate")
		}
		if n < 0xD800 || n > 0xDBFF {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return fmt.Errorf("unpaired high surrogate")
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return fmt.Errorf("invalid surrogate pair")
		}
		i += 6
	}
	return nil
}
