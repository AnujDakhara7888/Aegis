package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/verify"
)

const testRunID = "run-1"

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), ".aegis"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRun(testRunID); err != nil {
		t.Fatal(err)
	}
	return store
}

func testInput(id string) event.EventInput {
	return event.EventInput{Fields: event.Fields{
		EventID:         id,
		Source:          event.SourceAgent,
		Kind:            event.KindRunStarted,
		Phase:           event.PhaseInstant,
		PolicyDecision:  event.PolicyDecisionNone,
		SideEffectClass: event.SideEffectClassNone,
		ReplayBehavior:  event.ReplayBehaviorUnspecified,
		Attributes:      map[string]string{"name": id},
	}}
}

func appendEvent(t *testing.T, store *Store, input event.EventInput) event.Event {
	t.Helper()
	accepted, err := store.Append(testRunID, input)
	if err != nil {
		t.Fatal(err)
	}
	return accepted
}

func logPath(store *Store) string {
	return filepath.Join(store.Root(), "runs", testRunID, "events.jsonl")
}

func indexPath(store *Store) string {
	return filepath.Join(store.Root(), "runs", testRunID, "index.json")
}

func readLogLines(t *testing.T, store *Store) [][]byte {
	t.Helper()
	data, err := os.ReadFile(logPath(store))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		t.Fatal("test helper requires newline-terminated log")
	}
	return bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
}

func writeLogLines(t *testing.T, store *Store, lines [][]byte) {
	t.Helper()
	var data []byte
	for _, line := range lines {
		data = append(data, line...)
		data = append(data, '\n')
	}
	if err := os.WriteFile(logPath(store), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireCorrupt(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.VerifyRun(testRunID); !errors.Is(err, verify.ErrCorrupt) {
		t.Fatalf("expected corruption, got %v", err)
	}
}

func TestCreateAppendReopenAndPermissions(t *testing.T) {
	store := testStore(t)
	store.now = func() time.Time { return time.Unix(123, 456) }
	first := appendEvent(t, store, testInput("event-1"))
	parent := first.EventID
	payload := []byte("invoice payload")
	secondInput := testInput("event-2")
	secondInput.ParentEventID = &parent
	secondInput.Payload = &payload
	second := appendEvent(t, store, secondInput)

	if first.Sequence != 1 || second.Sequence != 2 || second.PreviousEventHash != first.EventHash {
		t.Fatal("store did not assign a contiguous hash-linked order")
	}
	if first.ObservedAtUnixNano != time.Unix(123, 456).UnixNano() {
		t.Fatal("store did not assign its observed time")
	}
	for _, path := range []string{store.Root(), filepath.Join(store.Root(), "runs"), filepath.Join(store.Root(), "runs", testRunID), filepath.Join(store.Root(), "blobs", "sha256")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s mode is %o", path, info.Mode().Perm())
		}
	}
	for _, path := range []string{logPath(store), indexPath(store), filepath.Join(store.Root(), "blobs", "sha256", second.PayloadHash.String())} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file %s mode is %o", path, info.Mode().Perm())
		}
	}

	reopened, err := Open(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	third := appendEvent(t, reopened, testInput("event-3"))
	if third.Sequence != 3 || third.PreviousEventHash != second.EventHash {
		t.Fatal("reopened store did not reconstruct authoritative state")
	}
	report, err := reopened.VerifyRun(testRunID)
	if err != nil || len(report.Records) != 3 || report.TerminalHash != third.EventHash {
		t.Fatalf("unexpected verification report: %+v, %v", report, err)
	}
	if err := reopened.CreateRun(testRunID); !errors.Is(err, ErrRunExists) {
		t.Fatalf("expected run-exists error, got %v", err)
	}
}

func TestOpenCreatesNestedPrivateDataRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nested", "runtime", ".aegis")
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if store.Root() != root {
		t.Fatalf("root = %s; want %s", store.Root(), root)
	}
	for _, path := range []string{filepath.Dir(filepath.Dir(root)), filepath.Dir(root), root} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("created directory %s mode is %o", path, info.Mode().Perm())
		}
	}
}

func TestConcurrentAppendsAreSerialized(t *testing.T) {
	store := testStore(t)
	const count = 64
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Append(testRunID, testInput(fmt.Sprintf("event-%03d", i)))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	report, err := store.VerifyRun(testRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Records) != count {
		t.Fatalf("got %d events; want %d", len(report.Records), count)
	}
	ids := make([]string, 0, count)
	for i, record := range report.Records {
		if record.Event.Sequence != uint64(i+1) {
			t.Fatalf("sequence %d at position %d", record.Event.Sequence, i)
		}
		ids = append(ids, record.Event.EventID)
	}
	sort.Strings(ids)
	for i, id := range ids {
		if id != fmt.Sprintf("event-%03d", i) {
			t.Fatalf("missing or duplicate ID at %d: %s", i, id)
		}
	}
}

func TestIdempotentRetryConflictAndParents(t *testing.T) {
	store := testStore(t)
	input := testInput("event-1")
	first := appendEvent(t, store, input)
	before, err := os.Stat(logPath(store))
	if err != nil {
		t.Fatal(err)
	}
	retried := appendEvent(t, store, input)
	after, err := os.Stat(logPath(store))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retried, first) || after.Size() != before.Size() {
		t.Fatal("identical retry did not return the original event without appending")
	}

	conflict := input
	conflict.Kind = event.KindRunFailed
	if _, err := store.Append(testRunID, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	empty := []byte{}
	conflict = input
	conflict.Payload = &empty
	if _, err := store.Append(testRunID, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("absent and empty payload must conflict, got %v", err)
	}

	missing := "not-yet-recorded"
	child := testInput("event-2")
	child.ParentEventID = &missing
	if _, err := store.Append(testRunID, child); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("expected missing-parent error, got %v", err)
	}
	parent := first.EventID
	child.ParentEventID = &parent
	accepted := appendEvent(t, store, child)
	if accepted.Sequence != 2 {
		t.Fatal("rejected parent attempt changed authoritative order")
	}
}

func TestPayloadPresenceAndContentAddressing(t *testing.T) {
	store := testStore(t)
	absent := appendEvent(t, store, testInput("absent"))
	if absent.PayloadHash != nil || absent.PayloadSize != 0 {
		t.Fatal("absent payload acquired a blob reference")
	}
	emptyPayload := []byte{}
	emptyInput := testInput("empty")
	emptyInput.Payload = &emptyPayload
	empty := appendEvent(t, store, emptyInput)
	if empty.PayloadHash == nil || empty.PayloadSize != 0 {
		t.Fatal("empty payload lost its presence")
	}
	secondInput := testInput("empty-again")
	secondInput.Payload = &emptyPayload
	second := appendEvent(t, store, secondInput)
	if *second.PayloadHash != *empty.PayloadHash {
		t.Fatal("equal payloads did not share a content address")
	}
	entries, err := os.ReadDir(filepath.Join(store.Root(), "blobs", "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one shared blob, got %d", len(entries))
	}
}

func TestIndexIsDisposableAndRebuildable(t *testing.T) {
	store := testStore(t)
	appendEvent(t, store, testInput("event-1"))
	if err := os.Remove(indexPath(store)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyRun(testRunID); err != nil {
		t.Fatal("missing index affected verification", err)
	}
	index, err := store.RebuildIndex(testRunID)
	if err != nil || index.EventCount != 1 {
		t.Fatalf("rebuild failed: %+v, %v", index, err)
	}

	if err := os.WriteFile(indexPath(store), []byte(`{"invented":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second := appendEvent(t, store, testInput("event-2"))
	index, err = store.ReadIndex(testRunID)
	if err != nil || index.EventCount != 2 || index.TerminalHash != second.EventHash {
		t.Fatalf("append trusted stale index: %+v, %v", index, err)
	}

	store.hooks.writeIndex = func(string, Index) error { return errors.New("injected index failure") }
	third := appendEvent(t, store, testInput("event-3"))
	if third.Sequence != 3 {
		t.Fatal("derived index failure prevented durable append")
	}
	stale, err := store.ReadIndex(testRunID)
	if err != nil || stale.EventCount != 2 {
		t.Fatalf("expected prior valid index to remain, got %+v, %v", stale, err)
	}
	store.hooks.writeIndex = nil
	index, err = store.RebuildIndex(testRunID)
	if err != nil || index.EventCount != 3 || index.TerminalHash != third.EventHash {
		t.Fatalf("index did not rebuild from log: %+v, %v", index, err)
	}
}

func TestVerificationDetectsEventModificationDeletionAndReordering(t *testing.T) {
	tests := map[string]func(*testing.T, *Store){
		"logical modification": func(t *testing.T, store *Store) {
			lines := readLogLines(t, store)
			var changed map[string]any
			if err := json.Unmarshal(lines[1], &changed); err != nil {
				t.Fatal(err)
			}
			changed["observed_at_unix_nano"] = float64(99)
			lines[1], _ = json.Marshal(changed)
			writeLogLines(t, store, lines)
		},
		"middle deletion": func(t *testing.T, store *Store) {
			lines := readLogLines(t, store)
			writeLogLines(t, store, [][]byte{lines[0], lines[2]})
		},
		"reordering": func(t *testing.T, store *Store) {
			lines := readLogLines(t, store)
			lines[0], lines[1] = lines[1], lines[0]
			writeLogLines(t, store, lines)
		},
		"duplicate": func(t *testing.T, store *Store) {
			lines := readLogLines(t, store)
			writeLogLines(t, store, [][]byte{lines[0], lines[0], lines[1], lines[2]})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := testStore(t)
			appendEvent(t, store, testInput("event-1"))
			appendEvent(t, store, testInput("event-2"))
			appendEvent(t, store, testInput("event-3"))
			mutate(t, store)
			requireCorrupt(t, store)
		})
	}
}

func TestOpenRunTerminalDeletionNeedsASealedAnchor(t *testing.T) {
	store := testStore(t)
	appendEvent(t, store, testInput("event-1"))
	appendEvent(t, store, testInput("event-2"))
	lines := readLogLines(t, store)
	writeLogLines(t, store, lines[:1])
	report, err := store.VerifyRun(testRunID)
	if err != nil || len(report.Records) != 1 {
		t.Fatalf("a remaining valid prefix should verify as an open run: %+v, %v", report, err)
	}
	// A signed manifest with an event count and terminal hash will make this
	// detectable. An open hash chain has no separately trusted terminal anchor.
}

func TestJSONWhitespaceDoesNotAffectVerification(t *testing.T) {
	store := testStore(t)
	accepted := appendEvent(t, store, testInput("event-1"))
	lines := readLogLines(t, store)
	// JSONL reserves physical newlines as record delimiters, but insignificant
	// horizontal whitespace within a record does not affect logical verification.
	spaced := append([]byte(" \t"), lines[0]...)
	spaced = append(spaced, ' ', '\r')
	writeLogLines(t, store, [][]byte{spaced})
	report, err := store.VerifyRun(testRunID)
	if err != nil || len(report.Records) != 1 || report.TerminalHash != accepted.EventHash {
		t.Fatalf("presentation-only change invalidated logical history: %+v, %v", report, err)
	}
}

func TestVerificationDetectsMissingAndReplacedBlobs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{"missing", os.Remove},
		{"same-size replacement", func(path string) error { return os.WriteFile(path, []byte("xxxxxx"), 0o600) }},
		{"wrong size", func(path string) error { return os.WriteFile(path, []byte("x"), 0o600) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testStore(t)
			payload := []byte("secret")
			input := testInput("event-1")
			input.Payload = &payload
			accepted := appendEvent(t, store, input)
			path := filepath.Join(store.Root(), "blobs", "sha256", accepted.PayloadHash.String())
			if err := test.mutate(path); err != nil {
				t.Fatal(err)
			}
			requireCorrupt(t, store)
		})
	}
}

func TestOrphanBlobDoesNotChangeAuthoritativeHistory(t *testing.T) {
	store := testStore(t)
	accepted := appendEvent(t, store, testInput("event-1"))
	orphan := filepath.Join(store.Root(), "blobs", "sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := store.VerifyRun(testRunID)
	if err != nil || len(report.Records) != 1 || report.TerminalHash != accepted.EventHash {
		t.Fatalf("orphan blob affected authoritative history: %+v, %v", report, err)
	}
}

func TestRecoveryRepairsOnlyAllowedTails(t *testing.T) {
	t.Run("incomplete fragment", func(t *testing.T) {
		store := testStore(t)
		appendEvent(t, store, testInput("event-1"))
		original, _ := os.ReadFile(logPath(store))
		fragment := bytes.TrimSuffix(original, []byte{'\n'})
		f, err := os.OpenFile(logPath(store), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(fragment[:len(fragment)/2])
		_ = f.Close()
		if _, err := store.VerifyRun(testRunID); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("expected recovery requirement, got %v", err)
		}
		if _, err := store.Append(testRunID, testInput("event-2")); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("append bypassed recovery: %v", err)
		}
		report, err := store.RecoverRun(testRunID)
		if err != nil || len(report.Records) != 1 {
			t.Fatalf("recovery failed: %+v, %v", report, err)
		}
		recovered, _ := os.ReadFile(logPath(store))
		if !bytes.Equal(recovered, original) {
			t.Fatal("recovery did not truncate exactly to the verified boundary")
		}
		if appendEvent(t, store, testInput("event-2")).Sequence != 2 {
			t.Fatal("append after recovery used wrong sequence")
		}
	})

	t.Run("complete valid event without newline", func(t *testing.T) {
		store := testStore(t)
		accepted := appendEvent(t, store, testInput("event-1"))
		info, _ := os.Stat(logPath(store))
		if err := os.Truncate(logPath(store), info.Size()-1); err != nil {
			t.Fatal(err)
		}
		if _, err := store.VerifyRun(testRunID); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("expected recovery requirement, got %v", err)
		}
		report, err := store.RecoverRun(testRunID)
		if err != nil || len(report.Records) != 1 || report.TerminalHash != accepted.EventHash {
			t.Fatalf("valid event was not retained: %+v, %v", report, err)
		}
		data, _ := os.ReadFile(logPath(store))
		if data[len(data)-1] != '\n' {
			t.Fatal("newline was not restored")
		}
	})

	for name, tail := range map[string][]byte{
		"malformed fragment":         []byte(`@`),
		"complete invalid JSON":      []byte(`{}`),
		"newline-terminated invalid": []byte("{\"bad\":}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			store := testStore(t)
			appendEvent(t, store, testInput("event-1"))
			f, err := os.OpenFile(logPath(store), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(tail)
			_ = f.Close()
			before, _ := os.ReadFile(logPath(store))
			if _, err := store.RecoverRun(testRunID); !errors.Is(err, verify.ErrCorrupt) {
				t.Fatalf("expected corruption, got %v", err)
			}
			after, _ := os.ReadFile(logPath(store))
			if !bytes.Equal(before, after) {
				t.Fatal("recovery discarded corrupt data")
			}
		})
	}

	t.Run("oversized unterminated record", func(t *testing.T) {
		store := testStore(t)
		f, err := os.OpenFile(logPath(store), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(bytes.Repeat([]byte{'x'}, event.MaxEventJSONBytes+3))
		_ = f.Close()
		if _, err := store.RecoverRun(testRunID); !errors.Is(err, verify.ErrCorrupt) {
			t.Fatalf("expected bounded oversized-record rejection, got %v", err)
		}
	})
}

func TestInjectedWriteSyncAndResponseFailures(t *testing.T) {
	t.Run("partial write", func(t *testing.T) {
		store := testStore(t)
		store.hooks.writeLog = func(file *os.File, line []byte) error {
			_, err := file.Write(line[:len(line)/2])
			if err != nil {
				return err
			}
			return io.ErrUnexpectedEOF
		}
		input := testInput("event-1")
		if _, err := store.Append(testRunID, input); err == nil {
			t.Fatal("injected partial write succeeded")
		}
		if _, err := store.Append(testRunID, input); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("uncertain run accepted another write: %v", err)
		}
		store.hooks.writeLog = nil
		report, err := store.RecoverRun(testRunID)
		if err != nil || len(report.Records) != 0 {
			t.Fatalf("partial write recovery failed: %+v, %v", report, err)
		}
		if appendEvent(t, store, input).Sequence != 1 {
			t.Fatal("retry after recovery did not become first event")
		}
	})

	t.Run("sync failure with complete line", func(t *testing.T) {
		store := testStore(t)
		store.hooks.syncLog = func(*os.File) error { return errors.New("injected sync failure") }
		input := testInput("event-1")
		if _, err := store.Append(testRunID, input); err == nil {
			t.Fatal("injected sync failure succeeded")
		}
		store.hooks.syncLog = nil
		report, err := store.RecoverRun(testRunID)
		if err != nil || len(report.Records) != 1 {
			t.Fatalf("complete uncertain event was not recovered: %+v, %v", report, err)
		}
		retried := appendEvent(t, store, input)
		if retried.Sequence != 1 || len(readLogLines(t, store)) != 1 {
			t.Fatal("retry duplicated a complete uncertain event")
		}
	})

	t.Run("lost response after durable append", func(t *testing.T) {
		store := testStore(t)
		store.hooks.afterLogSync = func(event.Event) error { return errors.New("injected lost response") }
		input := testInput("event-1")
		if _, err := store.Append(testRunID, input); err == nil {
			t.Fatal("lost response was not reported")
		}
		store.hooks.afterLogSync = nil
		retried := appendEvent(t, store, input)
		if retried.Sequence != 1 || len(readLogLines(t, store)) != 1 {
			t.Fatal("retry duplicated durable event after lost response")
		}
	})
}

func TestSealedMarkerPreventsOpenRunMutation(t *testing.T) {
	store := testStore(t)
	manifest := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
	if err := os.WriteFile(manifest, []byte("reserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(testRunID, testInput("event-1")); !errors.Is(err, ErrRunSealed) {
		t.Fatalf("expected sealed-run error, got %v", err)
	}
	if _, err := store.RecoverRun(testRunID); !errors.Is(err, ErrRunSealed) {
		t.Fatalf("recovery modified sealed marker run: %v", err)
	}
}

func TestReadIndexRejectsTrailingJSON(t *testing.T) {
	store := testStore(t)
	data, err := os.ReadFile(indexPath(store))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(`{}`)...)
	if err := os.WriteFile(indexPath(store), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadIndex(testRunID); err == nil {
		t.Fatal("accepted trailing index JSON")
	}
}

func TestLogContainsOneCompleteJSONEventPerLine(t *testing.T) {
	store := testStore(t)
	for i := 0; i < 10; i++ {
		appendEvent(t, store, testInput(fmt.Sprintf("event-%d", i)))
	}
	f, err := os.Open(logPath(store))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		if _, err := event.DecodeEvent(scanner.Bytes()); err != nil {
			t.Fatalf("line %d is not a complete strict event: %v", count+1, err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("got %d lines", count)
	}
}
