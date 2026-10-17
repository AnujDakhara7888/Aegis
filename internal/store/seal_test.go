package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/manifest"
	"aegis.local/runtime/internal/verify"
)

func keyedStore(t *testing.T) (*Store, ed25519.PublicKey) {
	t.Helper()
	store := testStore(t)
	publicKey, err := store.GenerateRecorderKey()
	if err != nil {
		t.Fatal(err)
	}
	return store, publicKey
}

func TestRecorderKeyGenerationAndLoading(t *testing.T) {
	store := testStore(t)
	publicKey, err := store.GenerateRecorderKey()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadRecorderPublicKey()
	if err != nil || !bytes.Equal(loaded, publicKey) {
		t.Fatalf("public key did not load: %x, %v", loaded, err)
	}
	for _, name := range []string{privateKeyFile, publicKeyFile} {
		path := filepath.Join(store.Root(), "keys", name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("key %s has mode %v", name, info.Mode())
		}
	}
	if _, err := store.GenerateRecorderKey(); !errors.Is(err, ErrRecorderKeyExists) {
		t.Fatalf("expected existing-key error, got %v", err)
	}
	loadedPublic, loadedPrivate, err := store.loadRecorderKeyPair()
	if err != nil || !bytes.Equal(loadedPublic, publicKey) || !bytes.Equal(loadedPrivate.Public().(ed25519.PublicKey), publicKey) {
		t.Fatal("stored key pair does not match", err)
	}
}

func TestPartialOrOverexposedKeyStateFailsClosed(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		store := testStore(t)
		keysDir := filepath.Join(store.Root(), "keys")
		if err := os.Mkdir(keysDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keysDir, publicKeyFile), make([]byte, ed25519.PublicKeySize), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GenerateRecorderKey(); !errors.Is(err, ErrRecorderKeyExists) {
			t.Fatalf("partial state was replaced: %v", err)
		}
		if _, _, err := store.loadRecorderKeyPair(); !errors.Is(err, ErrRecorderKeyMissing) {
			t.Fatalf("partial state did not fail closed: %v", err)
		}
	})
	t.Run("private permissions", func(t *testing.T) {
		store, _ := keyedStore(t)
		privatePath := filepath.Join(store.Root(), "keys", privateKeyFile)
		if err := os.Chmod(privatePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.loadRecorderKeyPair(); !errors.Is(err, ErrRecorderKeyMissing) {
			t.Fatalf("broad private permissions were accepted: %v", err)
		}
	})
}

func TestSealEmptyRunAndFreezeMutation(t *testing.T) {
	store, publicKey := keyedStore(t)
	store.now = func() time.Time { return time.Unix(100, 200) }
	signed, err := store.SealRun(testRunID, manifest.CompletionCompleted)
	if err != nil {
		t.Fatal(err)
	}
	if signed.EventCount != 0 || signed.FirstEventHash != (event.Digest{}) || signed.TerminalEventHash != (event.Digest{}) {
		t.Fatal("empty-run anchors are incorrect")
	}
	if signed.SealedAtUnixNano != time.Unix(100, 200).UnixNano() {
		t.Fatal("recorder did not assign seal time")
	}
	verified, err := store.VerifySealedRun(testRunID, publicKey)
	if err != nil || !reflect.DeepEqual(verified, signed) {
		t.Fatalf("sealed run did not verify: %+v, %v", verified, err)
	}
	manifestPath := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
	info, err := os.Stat(manifestPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode is wrong: %v, %v", info, err)
	}
	if _, err := store.Append(testRunID, testInput("event-1")); !errors.Is(err, ErrRunSealed) {
		t.Fatalf("append modified a sealed run: %v", err)
	}
	if _, err := store.RecoverRun(testRunID); !errors.Is(err, ErrRunSealed) {
		t.Fatalf("recovery modified a sealed run: %v", err)
	}
}

func TestSealPopulatedRunCoversEventsAndUniqueBlobSet(t *testing.T) {
	store, publicKey := keyedStore(t)
	payload := []byte("shared payload")
	firstInput := testInput("event-1")
	firstInput.Payload = &payload
	first := appendEvent(t, store, firstInput)
	secondInput := testInput("event-2")
	secondInput.Payload = &payload
	second := appendEvent(t, store, secondInput)
	third := appendEvent(t, store, testInput("event-3"))
	signed, err := store.SealRun(testRunID, manifest.CompletionFailed)
	if err != nil {
		t.Fatal(err)
	}
	wantBlobSet, _ := manifest.BlobSetDigest([]event.Digest{*first.PayloadHash})
	if signed.EventCount != 3 || signed.FirstEventHash != first.EventHash || signed.TerminalEventHash != third.EventHash || signed.ReferencedBlobSetDigest != wantBlobSet {
		t.Fatal("manifest does not cover reconstructed run anchors")
	}
	if *first.PayloadHash != *second.PayloadHash {
		t.Fatal("test setup did not share payload digest")
	}
	if _, err := store.VerifySealedRun(testRunID, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestSealRetryAndCompletionConflict(t *testing.T) {
	store, publicKey := keyedStore(t)
	appendEvent(t, store, testInput("event-1"))
	first, err := store.SealRun(testRunID, manifest.CompletionCompleted)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
	before, _ := os.ReadFile(path)
	retried, err := store.SealRun(testRunID, manifest.CompletionCompleted)
	if err != nil || !reflect.DeepEqual(retried, first) {
		t.Fatalf("equal seal retry changed result: %+v, %v", retried, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("equal seal retry rewrote manifest")
	}
	if _, err := store.SealRun(testRunID, manifest.CompletionFailed); !errors.Is(err, ErrSealConflict) {
		t.Fatalf("expected completion conflict, got %v", err)
	}
	if _, err := store.VerifySealedRun(testRunID, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestSealedIndexRebuildRequiresExpectedKey(t *testing.T) {
	store, publicKey, signed := createSealedRun(t)
	if err := os.Remove(indexPath(store)); err != nil {
		t.Fatal(err)
	}
	index, err := store.RebuildSealedIndex(testRunID, publicKey)
	if err != nil || index.EventCount != signed.EventCount || index.TerminalHash != signed.TerminalEventHash {
		t.Fatalf("sealed index rebuild failed: %+v, %v", index, err)
	}
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RebuildSealedIndex(testRunID, otherPublic); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("sealed index rebuilt with wrong key: %v", err)
	}
}

func createSealedRun(t *testing.T) (*Store, ed25519.PublicKey, manifest.Manifest) {
	t.Helper()
	store, publicKey := keyedStore(t)
	payload := []byte("secret")
	first := testInput("event-1")
	first.Payload = &payload
	appendEvent(t, store, first)
	appendEvent(t, store, testInput("event-2"))
	appendEvent(t, store, testInput("event-3"))
	signed, err := store.SealRun(testRunID, manifest.CompletionCompleted)
	if err != nil {
		t.Fatal(err)
	}
	return store, publicKey, signed
}

func TestSealedVerificationDetectsTamperingAndWrongKey(t *testing.T) {
	t.Run("terminal suffix deletion", func(t *testing.T) {
		store, publicKey, _ := createSealedRun(t)
		lines := readLogLines(t, store)
		writeLogLines(t, store, lines[:2])
		if _, err := store.VerifySealedRun(testRunID, publicKey); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("terminal deletion was not detected: %v", err)
		}
	})
	t.Run("event modification", func(t *testing.T) {
		store, publicKey, _ := createSealedRun(t)
		lines := readLogLines(t, store)
		var values map[string]any
		_ = json.Unmarshal(lines[0], &values)
		values["observed_at_unix_nano"] = float64(9)
		lines[0], _ = json.Marshal(values)
		writeLogLines(t, store, lines)
		if _, err := store.VerifySealedRun(testRunID, publicKey); !errors.Is(err, verify.ErrCorrupt) {
			t.Fatalf("event modification was not detected: %v", err)
		}
	})
	t.Run("blob modification", func(t *testing.T) {
		store, publicKey, _ := createSealedRun(t)
		report, err := verify.VerifySealedContent(store.Root(), testRunID)
		if err != nil {
			t.Fatal(err)
		}
		digest := report.Records[0].Event.PayloadHash
		path := filepath.Join(store.Root(), "blobs", "sha256", digest.String())
		if err := os.WriteFile(path, []byte("xxxxxx"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.VerifySealedRun(testRunID, publicKey); !errors.Is(err, verify.ErrCorrupt) {
			t.Fatalf("blob modification was not detected: %v", err)
		}
	})
	t.Run("manifest field", func(t *testing.T) {
		store, publicKey, _ := createSealedRun(t)
		path := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
		data, _ := os.ReadFile(path)
		var values map[string]any
		_ = json.Unmarshal(data, &values)
		values["completion_status"] = "FAILED"
		changed, _ := json.Marshal(values)
		_ = os.WriteFile(path, changed, 0o600)
		if _, err := store.VerifySealedRun(testRunID, publicKey); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("manifest change was not detected: %v", err)
		}
	})
	t.Run("signature", func(t *testing.T) {
		store, publicKey, signed := createSealedRun(t)
		signed.Signature[0] ^= 1
		data, _ := json.Marshal(signed)
		path := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
		_ = os.WriteFile(path, data, 0o600)
		if _, err := store.VerifySealedRun(testRunID, publicKey); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("signature change was not detected: %v", err)
		}
	})
	t.Run("wrong expected key", func(t *testing.T) {
		store, _, _ := createSealedRun(t)
		otherPublic, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.VerifySealedRun(testRunID, otherPublic); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("wrong key verified: %v", err)
		}
	})
}

func TestManifestJSONPresentationDoesNotAffectSignature(t *testing.T) {
	store, publicKey, _ := createSealedRun(t)
	path := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
	data, _ := os.ReadFile(path)
	var values map[string]any
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	reformatted, _ := json.MarshalIndent(values, "", "    ")
	if err := os.WriteFile(path, append(reformatted, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifySealedRun(testRunID, publicKey); err != nil {
		t.Fatal("JSON presentation affected logical signature", err)
	}
}

func TestSealPublicationAndResponseFailuresAreRetryable(t *testing.T) {
	t.Run("publication outcome uncertain", func(t *testing.T) {
		store, publicKey := keyedStore(t)
		appendEvent(t, store, testInput("event-1"))
		store.hooks.writeManifest = func(path string, data []byte) error {
			if err := writeAtomic(path, data, 0o600); err != nil {
				return err
			}
			return errors.New("injected post-publication error")
		}
		if _, err := store.SealRun(testRunID, manifest.CompletionCompleted); err == nil {
			t.Fatal("injected publication error succeeded")
		}
		store.hooks.writeManifest = nil
		if _, err := store.SealRun(testRunID, manifest.CompletionCompleted); err != nil {
			t.Fatal("seal retry did not recover published manifest", err)
		}
		if _, err := store.VerifySealedRun(testRunID, publicKey); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("lost response", func(t *testing.T) {
		store, publicKey := keyedStore(t)
		store.hooks.afterManifestSync = func() error { return errors.New("injected lost response") }
		if _, err := store.SealRun(testRunID, manifest.CompletionAborted); err == nil {
			t.Fatal("lost response was not reported")
		}
		store.hooks.afterManifestSync = nil
		if _, err := store.SealRun(testRunID, manifest.CompletionAborted); err != nil {
			t.Fatal("retry after lost response failed", err)
		}
		if _, err := store.VerifySealedRun(testRunID, publicKey); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInvalidExistingManifestIsNeverOverwritten(t *testing.T) {
	store, _ := keyedStore(t)
	path := filepath.Join(store.Root(), "runs", testRunID, "manifest.json")
	original := []byte(`{"invalid":true}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SealRun(testRunID, manifest.CompletionCompleted); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("expected invalid-manifest error, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, original) {
		t.Fatal("invalid manifest was overwritten")
	}
}

func TestVerifySealedRequiresManifestAndSafeRunID(t *testing.T) {
	store, publicKey := keyedStore(t)
	if _, err := store.VerifySealedRun(testRunID, publicKey); !errors.Is(err, ErrRunNotSealed) {
		t.Fatalf("expected not-sealed error, got %v", err)
	}
	if _, err := store.VerifySealedRun("../escape", publicKey); err == nil {
		t.Fatal("accepted unsafe run ID")
	}
}
