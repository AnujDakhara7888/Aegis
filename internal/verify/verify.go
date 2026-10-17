// Package verify validates authoritative event logs and referenced payloads.
// Signature verification is performed by the manifest/store layer with a pinned key.
package verify

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/hashchain"
)

var (
	ErrCorrupt          = errors.New("run is corrupt")
	ErrRecoveryRequired = errors.New("run requires recovery")
	ErrRunNotFound      = errors.New("run not found")
	ErrSealedRun        = errors.New("run is sealed; use sealed-run verification")
)

// Record describes an authoritative event's position in events.jsonl.
type Record struct {
	Event  event.Event
	Offset int64
	Length int64
}

// Report is reconstructed entirely from authoritative log and blob state.
type Report struct {
	RunID        string
	Records      []Record
	TerminalHash event.Digest
}

// Verify checks an open run without modifying any file.
func Verify(root, runID string) (Report, error) {
	return scan(root, runID, false, false)
}

// Recover checks an open run and repairs only a parser-confirmed incomplete final
// fragment or a complete valid final event that lacks its newline delimiter.
func Recover(root, runID string) (Report, error) {
	return scan(root, runID, true, false)
}

// VerifySealedContent validates event and blob state while permitting the caller
// to verify the already-present manifest separately against an expected key.
func VerifySealedContent(root, runID string) (Report, error) {
	return scan(root, runID, false, true)
}

func scan(root, runID string, repair, allowManifest bool) (Report, error) {
	if err := event.ValidateID(runID); err != nil {
		return Report{}, fmt.Errorf("run ID: %w", err)
	}
	runDir := filepath.Join(root, "runs", runID)
	if !allowManifest {
		if _, err := os.Stat(filepath.Join(runDir, "manifest.json")); err == nil {
			return Report{}, ErrSealedRun
		} else if !errors.Is(err, os.ErrNotExist) {
			return Report{}, fmt.Errorf("inspect manifest: %w", err)
		}
	}

	flags := os.O_RDONLY
	if repair {
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(filepath.Join(runDir, "events.jsonl"), flags, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Report{}, ErrRunNotFound
	}
	if err != nil {
		return Report{}, fmt.Errorf("open event log: %w", err)
	}
	defer f.Close()

	report := Report{RunID: runID}
	// One bounded buffer prevents a corrupt log without delimiters from forcing
	// unbounded allocation before the event-size limit can be enforced.
	reader := bufio.NewReaderSize(f, event.MaxEventJSONBytes+2)
	seen := make(map[string]struct{})
	var offset int64
	var previous event.Digest

	for {
		line, readErr := reader.ReadSlice('\n')
		if len(line) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return Report{}, corrupt(offset, "event JSON exceeds %d bytes", event.MaxEventJSONBytes)
		}

		hasNewline := len(line) > 0 && line[len(line)-1] == '\n'
		body := line
		if hasNewline {
			body = body[:len(body)-1]
		}
		if len(body) > event.MaxEventJSONBytes {
			return Report{}, corrupt(offset, "event JSON exceeds %d bytes", event.MaxEventJSONBytes)
		}

		if !hasNewline {
			if !errors.Is(readErr, io.EOF) {
				return Report{}, fmt.Errorf("read event log at offset %d: %w", offset, readErr)
			}
			if !json.Valid(body) {
				if !isUnexpectedEnd(body) {
					return Report{}, corrupt(offset, "malformed final JSON fragment")
				}
				if !repair {
					return Report{}, fmt.Errorf("%w: incomplete final JSON fragment at offset %d", ErrRecoveryRequired, offset)
				}
				if err := f.Truncate(offset); err != nil {
					return Report{}, fmt.Errorf("truncate incomplete tail: %w", err)
				}
				if err := f.Sync(); err != nil {
					return Report{}, fmt.Errorf("sync recovered log: %w", err)
				}
				break
			}
		}

		e, err := event.DecodeEvent(body)
		if err != nil {
			return Report{}, corrupt(offset, "decode event: %v", err)
		}
		if err := validateRecord(root, runID, uint64(len(report.Records)+1), previous, seen, e); err != nil {
			return Report{}, corrupt(offset, "%v", err)
		}

		length := int64(len(line))
		if !hasNewline {
			if !repair {
				return Report{}, fmt.Errorf("%w: complete final event lacks newline at offset %d", ErrRecoveryRequired, offset)
			}
			if _, err := f.WriteAt([]byte{'\n'}, offset+int64(len(body))); err != nil {
				return Report{}, fmt.Errorf("restore final newline: %w", err)
			}
			if err := f.Sync(); err != nil {
				return Report{}, fmt.Errorf("sync restored newline: %w", err)
			}
			length++
		}

		report.Records = append(report.Records, Record{Event: e, Offset: offset, Length: length})
		seen[e.EventID] = struct{}{}
		previous = e.EventHash
		report.TerminalHash = e.EventHash
		offset += length

		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return Report{}, fmt.Errorf("read event log at offset %d: %w", offset, readErr)
		}
	}
	return report, nil
}

func validateRecord(root, runID string, wantSequence uint64, previous event.Digest, seen map[string]struct{}, e event.Event) error {
	if e.RunID != runID {
		return fmt.Errorf("event %q belongs to run %q", e.EventID, e.RunID)
	}
	if e.Sequence != wantSequence {
		return fmt.Errorf("event %q has sequence %d; expected %d", e.EventID, e.Sequence, wantSequence)
	}
	if _, exists := seen[e.EventID]; exists {
		return fmt.Errorf("duplicate event ID %q", e.EventID)
	}
	if e.ParentEventID != nil {
		if _, exists := seen[*e.ParentEventID]; !exists {
			return fmt.Errorf("event %q refers to missing or later parent %q", e.EventID, *e.ParentEventID)
		}
	}
	if e.PreviousEventHash != previous {
		return fmt.Errorf("event %q has the wrong predecessor hash", e.EventID)
	}
	wantHash, err := hashchain.Sum(e)
	if err != nil {
		return fmt.Errorf("hash event %q: %w", e.EventID, err)
	}
	if e.EventHash != wantHash {
		return fmt.Errorf("event %q hash does not match its logical content", e.EventID)
	}
	if e.PayloadHash != nil {
		if err := verifyBlob(filepath.Join(root, "blobs", "sha256", e.PayloadHash.String()), *e.PayloadHash, e.PayloadSize); err != nil {
			return fmt.Errorf("event %q payload: %w", e.EventID, err)
		}
	}
	return nil
}

func verifyBlob(path string, want event.Digest, wantSize uint64) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("missing blob %s", want)
	}
	if err != nil {
		return fmt.Errorf("open blob %s: %w", want, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat blob %s: %w", want, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("blob %s is not a regular file", want)
	}
	if info.Size() < 0 || uint64(info.Size()) != wantSize {
		return fmt.Errorf("blob %s size is %d; expected %d", want, info.Size(), wantSize)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read blob %s: %w", want, err)
	}
	if !bytes.Equal(h.Sum(nil), want[:]) {
		return fmt.Errorf("blob %s content hash mismatch", want)
	}
	return nil
}

func isUnexpectedEnd(data []byte) bool {
	var value any
	err := json.Unmarshal(data, &value)
	var syntax *json.SyntaxError
	return errors.As(err, &syntax) && strings.Contains(syntax.Error(), "unexpected end of JSON input")
}

func corrupt(offset int64, format string, args ...any) error {
	return fmt.Errorf("%w at byte %d: %s", ErrCorrupt, offset, fmt.Sprintf(format, args...))
}
