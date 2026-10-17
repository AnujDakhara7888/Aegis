package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/verify"
)

const IndexSchemaVersion uint16 = 1

// Index is a replaceable acceleration structure reconstructed from events.jsonl.
type Index struct {
	SchemaVersion uint16       `json:"schema_version"`
	RunID         string       `json:"run_id"`
	EventCount    uint64       `json:"event_count"`
	TerminalHash  event.Digest `json:"terminal_event_hash"`
	Entries       []IndexEntry `json:"entries"`
}

type IndexEntry struct {
	Sequence uint64 `json:"sequence"`
	EventID  string `json:"event_id"`
	Offset   int64  `json:"offset"`
	Length   int64  `json:"length"`
}

// RebuildIndex verifies authoritative state and atomically replaces index.json.
func (s *Store) RebuildIndex(runID string) (Index, error) {
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()
	report, err := verify.Verify(s.root, runID)
	if err != nil {
		return Index{}, s.translateVerifyError(err)
	}
	index := indexFromReport(report)
	if err := s.writeIndex(runID, index); err != nil {
		return Index{}, fmt.Errorf("write rebuilt index: %w", err)
	}
	return index, nil
}

// ReadIndex reads and validates derived state for inspection and tests. Recorder
// correctness never depends on this method succeeding.
func (s *Store) ReadIndex(runID string) (Index, error) {
	data, err := os.ReadFile(filepath.Join(s.runDir(runID), "index.json"))
	if err != nil {
		return Index{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var index Index
	if err := dec.Decode(&index); err != nil {
		return Index{}, fmt.Errorf("decode index: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return Index{}, fmt.Errorf("index has trailing content")
	}
	if index.SchemaVersion != IndexSchemaVersion || index.RunID != runID || index.EventCount != uint64(len(index.Entries)) {
		return Index{}, fmt.Errorf("invalid index metadata")
	}
	for i, entry := range index.Entries {
		if entry.Sequence != uint64(i+1) || event.ValidateID(entry.EventID) != nil || entry.Offset < 0 || entry.Length <= 0 {
			return Index{}, fmt.Errorf("invalid index entry %d", i)
		}
	}
	return index, nil
}

func indexFromReport(report verify.Report) Index {
	index := Index{
		SchemaVersion: IndexSchemaVersion,
		RunID:         report.RunID,
		EventCount:    uint64(len(report.Records)),
		TerminalHash:  report.TerminalHash,
		Entries:       make([]IndexEntry, 0, len(report.Records)),
	}
	for _, record := range report.Records {
		index.Entries = append(index.Entries, IndexEntry{
			Sequence: record.Event.Sequence,
			EventID:  record.Event.EventID,
			Offset:   record.Offset,
			Length:   record.Length,
		})
	}
	return index
}

func (s *Store) writeIndex(runID string, index Index) error {
	if s.hooks.writeIndex != nil {
		return s.hooks.writeIndex(runID, index)
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(filepath.Join(s.runDir(runID), "index.json"), data, 0o600)
}
