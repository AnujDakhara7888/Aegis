package verify_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/store"
	"aegis.local/runtime/internal/verify"
)

func TestVerifyAndRecoverPublicContract(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis")
	recorder, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.CreateRun("run-1"); err != nil {
		t.Fatal(err)
	}
	input := event.EventInput{Fields: event.Fields{
		EventID:         "event-1",
		Source:          event.SourceRecorder,
		Kind:            event.KindRunStarted,
		Phase:           event.PhaseStart,
		PolicyDecision:  event.PolicyDecisionNone,
		SideEffectClass: event.SideEffectClassNone,
		ReplayBehavior:  event.ReplayBehaviorUnspecified,
		Attributes:      map[string]string{},
	}}
	accepted, err := recorder.Append("run-1", input)
	if err != nil {
		t.Fatal(err)
	}
	report, err := verify.Verify(root, "run-1")
	if err != nil || len(report.Records) != 1 || report.TerminalHash != accepted.EventHash {
		t.Fatalf("unexpected report: %+v, %v", report, err)
	}

	logPath := filepath.Join(root, "runs", "run-1", "events.jsonl")
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(logPath, info.Size()-1); err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(root, "run-1"); !errors.Is(err, verify.ErrRecoveryRequired) {
		t.Fatalf("expected recovery requirement, got %v", err)
	}
	report, err = verify.Recover(root, "run-1")
	if err != nil || len(report.Records) != 1 || report.TerminalHash != accepted.EventHash {
		t.Fatalf("unexpected recovery report: %+v, %v", report, err)
	}
}

func TestVerifyMissingRun(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".aegis")
	if _, err := store.Open(root); err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(root, "missing"); !errors.Is(err, verify.ErrRunNotFound) {
		t.Fatalf("expected missing-run error, got %v", err)
	}
}
