package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"aegis.local/runtime/internal/event"
	"aegis.local/runtime/internal/manifest"
	"aegis.local/runtime/internal/verify"
)

// SealRun validates all authoritative state and atomically publishes a signed
// manifest. An existing valid manifest makes an equal-status retry idempotent.
func (s *Store) SealRun(runID string, status manifest.CompletionStatus) (manifest.Manifest, error) {
	if err := event.ValidateID(runID); err != nil {
		return manifest.Manifest{}, fmt.Errorf("run ID: %w", err)
	}
	if !status.Valid() {
		return manifest.Manifest{}, fmt.Errorf("invalid completion status")
	}
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.recoveryRequired {
		return manifest.Manifest{}, ErrRecoveryRequired
	}
	publicKey, err := s.LoadRecorderPublicKey()
	if err != nil {
		return manifest.Manifest{}, err
	}
	manifestPath := filepath.Join(s.runDir(runID), "manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		existing, _, err := s.verifySealedLocked(runID, publicKey)
		if err != nil {
			return manifest.Manifest{}, err
		}
		if existing.CompletionStatus != status {
			return manifest.Manifest{}, ErrSealConflict
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest.Manifest{}, fmt.Errorf("inspect manifest: %w", err)
	}
	loadedPublic, privateKey, err := s.loadRecorderKeyPair()
	if err != nil {
		return manifest.Manifest{}, err
	}
	if !bytes.Equal(loadedPublic, publicKey) {
		return manifest.Manifest{}, fmt.Errorf("%w: public key changed while sealing", ErrRecorderKeyMissing)
	}

	report, err := verify.Verify(s.root, runID)
	if err != nil {
		return manifest.Manifest{}, s.translateVerifyError(err)
	}
	references := referencedBlobs(report)
	blobSetDigest, err := manifest.BlobSetDigest(references)
	if err != nil {
		return manifest.Manifest{}, err
	}
	fingerprint, err := manifest.Fingerprint(publicKey)
	if err != nil {
		return manifest.Manifest{}, err
	}
	unsigned := manifest.Manifest{
		ManifestSchemaVersion:        manifest.SchemaVersion,
		RunID:                        runID,
		EventSchemaVersion:           event.SchemaVersion,
		EventCount:                   uint64(len(report.Records)),
		ReferencedBlobSetDigest:      blobSetDigest,
		CompletionStatus:             status,
		SealedAtUnixNano:             s.now().UnixNano(),
		RecorderPublicKeyFingerprint: fingerprint,
		SignatureAlgorithm:           manifest.SignatureEd25519,
	}
	if len(report.Records) > 0 {
		unsigned.FirstEventHash = report.Records[0].Event.EventHash
		unsigned.TerminalEventHash = report.TerminalHash
	}
	signed, err := manifest.Sign(unsigned, privateKey)
	if err != nil {
		return manifest.Manifest{}, err
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("encode manifest JSON: %w", err)
	}
	data = append(data, '\n')
	if len(data) > manifest.MaxJSONBytes {
		return manifest.Manifest{}, fmt.Errorf("manifest JSON exceeds %d bytes", manifest.MaxJSONBytes)
	}
	writeManifest := func(path string, data []byte) error { return writeAtomic(path, data, 0o600) }
	if s.hooks.writeManifest != nil {
		writeManifest = s.hooks.writeManifest
	}
	if err := writeManifest(manifestPath, data); err != nil {
		return manifest.Manifest{}, fmt.Errorf("publish manifest; disk outcome may be uncertain: %w", err)
	}
	if s.hooks.afterManifestSync != nil {
		if err := s.hooks.afterManifestSync(); err != nil {
			return manifest.Manifest{}, fmt.Errorf("response lost after durable seal: %w", err)
		}
	}
	return signed, nil
}

// VerifySealedRun authenticates the manifest with a caller-supplied expected key,
// then reconstructs and compares every covered event/blob property.
func (s *Store) VerifySealedRun(runID string, expectedPublicKey ed25519.PublicKey) (manifest.Manifest, error) {
	if err := event.ValidateID(runID); err != nil {
		return manifest.Manifest{}, fmt.Errorf("run ID: %w", err)
	}
	state := s.state(runID)
	state.mu.Lock()
	defer state.mu.Unlock()
	signed, _, err := s.verifySealedLocked(runID, expectedPublicKey)
	return signed, err
}

func (s *Store) verifySealedLocked(runID string, expectedPublicKey ed25519.PublicKey) (manifest.Manifest, verify.Report, error) {
	signed, err := s.readManifest(runID)
	if err != nil {
		return manifest.Manifest{}, verify.Report{}, err
	}
	if err := manifest.VerifySignature(signed, expectedPublicKey); err != nil {
		return manifest.Manifest{}, verify.Report{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	report, err := verify.VerifySealedContent(s.root, runID)
	if err != nil {
		return manifest.Manifest{}, verify.Report{}, err
	}
	if signed.RunID != runID || signed.EventCount != uint64(len(report.Records)) {
		return manifest.Manifest{}, verify.Report{}, fmt.Errorf("%w: run identity or event count mismatch", ErrInvalidManifest)
	}
	var first event.Digest
	if len(report.Records) > 0 {
		first = report.Records[0].Event.EventHash
	}
	if signed.FirstEventHash != first || signed.TerminalEventHash != report.TerminalHash {
		return manifest.Manifest{}, verify.Report{}, fmt.Errorf("%w: event anchors do not match", ErrInvalidManifest)
	}
	blobSetDigest, err := manifest.BlobSetDigest(referencedBlobs(report))
	if err != nil {
		return manifest.Manifest{}, verify.Report{}, err
	}
	if signed.ReferencedBlobSetDigest != blobSetDigest {
		return manifest.Manifest{}, verify.Report{}, fmt.Errorf("%w: referenced blob set does not match", ErrInvalidManifest)
	}
	return signed, report, nil
}

func (s *Store) readManifest(runID string) (manifest.Manifest, error) {
	path := filepath.Join(s.runDir(runID), "manifest.json")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return manifest.Manifest{}, ErrRunNotSealed
	}
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("inspect manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > manifest.MaxJSONBytes {
		return manifest.Manifest{}, fmt.Errorf("%w: invalid manifest file", ErrInvalidManifest)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	decoded, err := manifest.Decode(data)
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	return decoded, nil
}

func referencedBlobs(report verify.Report) []event.Digest {
	references := make([]event.Digest, 0, len(report.Records))
	for _, record := range report.Records {
		if record.Event.PayloadHash != nil {
			references = append(references, *record.Event.PayloadHash)
		}
	}
	return references
}
