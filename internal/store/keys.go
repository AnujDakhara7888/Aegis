package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"aegis.local/runtime/internal/manifest"
)

const (
	privateKeyFile = "recorder.key"
	publicKeyFile  = "recorder.pub"
)

// GenerateRecorderKey creates one durable key pair. Existing or partial key state
// is never replaced. The returned public key is safe to distribute as trust input.
func (s *Store) GenerateRecorderKey() (ed25519.PublicKey, error) {
	keysDir := filepath.Join(s.root, "keys")
	if _, err := os.Stat(keysDir); err == nil {
		return nil, ErrRecorderKeyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect recorder key directory: %w", err)
	}
	publicKey, privateKey, err := manifest.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp(s.root, ".keys-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary key directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tempDir)
		}
	}()
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return nil, fmt.Errorf("set temporary key directory mode: %w", err)
	}
	if err := writeNewSyncedFile(filepath.Join(tempDir, privateKeyFile), privateKey, 0o600); err != nil {
		return nil, fmt.Errorf("write private recorder key: %w", err)
	}
	if err := writeNewSyncedFile(filepath.Join(tempDir, publicKeyFile), publicKey, 0o600); err != nil {
		return nil, fmt.Errorf("write public recorder key: %w", err)
	}
	if err := syncDir(tempDir); err != nil {
		return nil, fmt.Errorf("sync temporary key directory: %w", err)
	}
	if err := os.Rename(tempDir, keysDir); err != nil {
		if _, statErr := os.Stat(keysDir); statErr == nil {
			return nil, ErrRecorderKeyExists
		}
		return nil, fmt.Errorf("publish recorder key directory: %w", err)
	}
	cleanup = false
	if err := syncDir(s.root); err != nil {
		return nil, fmt.Errorf("sync data root after key publication: %w", err)
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

// LoadRecorderPublicKey reads the independently trusted local public-key file.
func (s *Store) LoadRecorderPublicKey() (ed25519.PublicKey, error) {
	data, err := readFixedRegularFile(filepath.Join(s.root, "keys", publicKeyFile), ed25519.PublicKeySize, false)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(data), nil
}

func (s *Store) loadRecorderKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, err := s.LoadRecorderPublicKey()
	if err != nil {
		return nil, nil, err
	}
	privateBytes, err := readFixedRegularFile(filepath.Join(s.root, "keys", privateKeyFile), ed25519.PrivateKeySize, true)
	if err != nil {
		return nil, nil, err
	}
	privateKey := ed25519.PrivateKey(privateBytes)
	derived := privateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(publicKey, derived) {
		return nil, nil, fmt.Errorf("%w: public and private recorder keys do not match", ErrRecorderKeyMissing)
	}
	return publicKey, privateKey, nil
}

func writeNewSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := writeAll(file, data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func readFixedRegularFile(path string, size int, private bool) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrRecorderKeyMissing
	}
	if err != nil {
		return nil, fmt.Errorf("inspect recorder key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(size) {
		return nil, fmt.Errorf("%w: invalid recorder key file", ErrRecorderKeyMissing)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: private key permissions are too broad", ErrRecorderKeyMissing)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read recorder key: %w", err)
	}
	return data, nil
}
