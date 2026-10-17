// Package store implements the single-process, file-backed Aegis recorder store.
package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/hashchain"
	"aegis.local/runtime/internal/verify"
)

var (
	ErrRunExists           = errors.New("run already exists")
	ErrRunNotFound         = errors.New("run not found")
	ErrRunSealed           = errors.New("run is sealed")
	ErrIdempotencyConflict = errors.New("event ID conflicts with an accepted event")
	ErrParentNotFound      = errors.New("parent event is not already accepted in this run")
	ErrRecoveryRequired    = errors.New("run requires explicit recovery")
)

// Store assumes it is the only Store process writing its root. It serializes
// writers inside the process, but does not claim cross-process writer safety.
type Store struct {
	root string
	now  func() time.Time

	mu   sync.Mutex
	runs map[string]*runState

	// hooks are nil in production and permit deterministic fault injection in tests.
	hooks testHooks
}

type runState struct {
	mu               sync.Mutex
	recoveryRequired bool
}

type testHooks struct {
	writeLog     func(*os.File, []byte) error
	syncLog      func(*os.File) error
	afterLogSync func(event.Event) error
	writeIndex   func(string, Index) error
}

// Open creates or opens a private Aegis data root and its shared directories.
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("data root must not be empty")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve data root: %w", err)
	}
	if err := ensurePrivateDir(absRoot); err != nil {
		return nil, err
	}
	for _, dir := range []string{filepath.Join(absRoot, "runs"), filepath.Join(absRoot, "blobs"), filepath.Join(absRoot, "blobs", "sha256")} {
		if err := ensurePrivateDir(dir); err != nil {
			return nil, err
		}
	}
	return &Store{root: absRoot, now: time.Now, runs: make(map[string]*runState)}, nil
}

// Root returns the absolute data-root path.
func (s *Store) Root() string { return s.root }

// CreateRun creates an empty authoritative log and a disposable empty index.
func (s *Store) CreateRun(runID string) error {
	if err := event.ValidateID(runID); err != nil {
		return fmt.Errorf("run ID: %w", err)
	}
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()

	runDir := s.runDir(runID)
	if _, err := os.Stat(runDir); err == nil {
		return ErrRunExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect run directory: %w", err)
	}
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return fmt.Errorf("create run directory: %w", err)
	}
	if err := syncDir(filepath.Dir(runDir)); err != nil {
		return fmt.Errorf("sync runs directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(runDir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create event log: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync empty event log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close empty event log: %w", err)
	}
	if err := syncDir(runDir); err != nil {
		return fmt.Errorf("sync run directory: %w", err)
	}
	// The index is derived; inability to create it cannot invalidate the run.
	_ = s.writeIndex(runID, Index{SchemaVersion: IndexSchemaVersion, RunID: runID, Entries: []IndexEntry{}})
	return nil
}

// Append validates and durably accepts one event, or returns the original event
// for an identical event-ID retry. A conflicting retry never changes the log.
func (s *Store) Append(runID string, supplied event.EventInput) (event.Event, error) {
	if err := event.ValidateID(runID); err != nil {
		return event.Event{}, fmt.Errorf("run ID: %w", err)
	}
	input := cloneInput(supplied)
	if err := input.Validate(); err != nil {
		return event.Event{}, fmt.Errorf("validate input: %w", err)
	}
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.recoveryRequired {
		return event.Event{}, ErrRecoveryRequired
	}

	report, err := verify.Verify(s.root, runID)
	if err != nil {
		return event.Event{}, s.translateVerifyError(err)
	}
	wantPayloadHash, wantPayloadSize := payloadIdentity(input.Payload)
	for _, record := range report.Records {
		if record.Event.EventID != input.EventID {
			continue
		}
		if sameInput(record.Event, input, wantPayloadHash, wantPayloadSize) {
			return record.Event, nil
		}
		return event.Event{}, ErrIdempotencyConflict
	}
	if input.ParentEventID != nil && !containsEvent(report, *input.ParentEventID) {
		return event.Event{}, ErrParentNotFound
	}

	if input.Payload != nil {
		if err := s.publishBlob(*input.Payload, *wantPayloadHash); err != nil {
			return event.Event{}, err
		}
	}
	accepted := event.Event{
		Fields:             input.Fields,
		SchemaVersion:      event.SchemaVersion,
		RunID:              runID,
		Sequence:           uint64(len(report.Records) + 1),
		ObservedAtUnixNano: s.now().UnixNano(),
		PayloadHash:        wantPayloadHash,
		PayloadSize:        wantPayloadSize,
		PreviousEventHash:  report.TerminalHash,
	}
	accepted.EventHash, err = hashchain.Sum(accepted)
	if err != nil {
		return event.Event{}, fmt.Errorf("hash accepted event: %w", err)
	}
	line, err := json.Marshal(accepted)
	if err != nil {
		return event.Event{}, fmt.Errorf("encode accepted event JSON: %w", err)
	}
	if len(line) > event.MaxEventJSONBytes {
		return event.Event{}, fmt.Errorf("accepted event JSON exceeds %d bytes", event.MaxEventJSONBytes)
	}
	line = append(line, '\n')

	log, err := os.OpenFile(filepath.Join(s.runDir(runID), "events.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return event.Event{}, fmt.Errorf("open event log for append: %w", err)
	}
	writeLog := writeAll
	if s.hooks.writeLog != nil {
		writeLog = s.hooks.writeLog
	}
	if err := writeLog(log, line); err != nil {
		state.recoveryRequired = true
		log.Close()
		return event.Event{}, fmt.Errorf("append event; disk outcome is uncertain: %w", err)
	}
	syncLog := func(f *os.File) error { return f.Sync() }
	if s.hooks.syncLog != nil {
		syncLog = s.hooks.syncLog
	}
	if err := syncLog(log); err != nil {
		state.recoveryRequired = true
		log.Close()
		return event.Event{}, fmt.Errorf("sync event log; disk outcome is uncertain: %w", err)
	}
	if err := log.Close(); err != nil {
		state.recoveryRequired = true
		return event.Event{}, fmt.Errorf("close event log; disk outcome is uncertain: %w", err)
	}

	report.Records = append(report.Records, verify.Record{Event: accepted, Offset: reportEnd(report), Length: int64(len(line))})
	report.TerminalHash = accepted.EventHash
	// The event is already durable. A derived-index failure must not turn it into
	// an acknowledged-but-hidden event or encourage a duplicate append.
	_ = s.writeIndex(runID, indexFromReport(report))
	if s.hooks.afterLogSync != nil {
		if err := s.hooks.afterLogSync(accepted); err != nil {
			return event.Event{}, fmt.Errorf("response lost after durable append: %w", err)
		}
	}
	return accepted, nil
}

// VerifyRun performs read-only full open-run and payload verification.
func (s *Store) VerifyRun(runID string) (verify.Report, error) {
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()
	report, err := verify.Verify(s.root, runID)
	if err != nil {
		return verify.Report{}, s.translateVerifyError(err)
	}
	return report, nil
}

// RecoverRun explicitly resolves an uncertain tail and then refreshes the index.
func (s *Store) RecoverRun(runID string) (verify.Report, error) {
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()
	report, err := verify.Recover(s.root, runID)
	if err != nil {
		state.recoveryRequired = true
		return verify.Report{}, s.translateVerifyError(err)
	}
	state.recoveryRequired = false
	_ = s.writeIndex(runID, indexFromReport(report))
	return report, nil
}

func (s *Store) state(runID string) *runState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.runs[runID]
	if state == nil {
		state = &runState{}
		s.runs[runID] = state
	}
	return state
}

func (s *Store) runDir(runID string) string { return filepath.Join(s.root, "runs", runID) }

func (s *Store) translateVerifyError(err error) error {
	switch {
	case errors.Is(err, verify.ErrRunNotFound):
		return ErrRunNotFound
	case errors.Is(err, verify.ErrSealedRun):
		return ErrRunSealed
	case errors.Is(err, verify.ErrRecoveryRequired):
		return fmt.Errorf("%w: %v", ErrRecoveryRequired, err)
	default:
		return err
	}
}

func cloneInput(input event.EventInput) event.EventInput {
	clone := input
	clone.Fields = input.Fields
	clone.ParentEventID = cloneString(input.ParentEventID)
	clone.SourceInstanceID = cloneString(input.SourceInstanceID)
	clone.SourceMonotonicNano = cloneInt64(input.SourceMonotonicNano)
	clone.InputHash = cloneDigest(input.InputHash)
	clone.OutputHash = cloneDigest(input.OutputHash)
	clone.CapabilityID = cloneString(input.CapabilityID)
	clone.IdempotencyKey = cloneString(input.IdempotencyKey)
	clone.Attributes = make(map[string]string, len(input.Attributes))
	for key, value := range input.Attributes {
		clone.Attributes[key] = value
	}
	if input.Payload != nil {
		payload := append([]byte(nil), (*input.Payload)...)
		clone.Payload = &payload
	}
	return clone
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneDigest(value *event.Digest) *event.Digest {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func payloadIdentity(payload *[]byte) (*event.Digest, uint64) {
	if payload == nil {
		return nil, 0
	}
	digest := event.Digest(sha256.Sum256(*payload))
	return &digest, uint64(len(*payload))
}

func sameInput(accepted event.Event, input event.EventInput, payloadHash *event.Digest, payloadSize uint64) bool {
	return reflect.DeepEqual(accepted.Fields, input.Fields) && reflect.DeepEqual(accepted.PayloadHash, payloadHash) && accepted.PayloadSize == payloadSize
}

func containsEvent(report verify.Report, eventID string) bool {
	for _, record := range report.Records {
		if record.Event.EventID == eventID {
			return true
		}
	}
	return false
}

func reportEnd(report verify.Report) int64 {
	if len(report.Records) == 0 {
		return 0
	}
	last := report.Records[len(report.Records)-1]
	return last.Offset + last.Length
}
