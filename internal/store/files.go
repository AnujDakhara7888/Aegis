package store

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aegis.local/runtime/internal/event"
)

func ensurePrivateDir(path string) error {
	if err := createDirPath(path); err != nil {
		return fmt.Errorf("create private directory %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("set private directory mode %s: %w", path, err)
	}
	if err := syncDir(path); err != nil {
		return fmt.Errorf("sync private directory %s: %w", path, err)
	}
	return nil
}

// createDirPath creates each missing component separately and synchronizes its
// parent entry. Existing ancestor permissions are never changed.
func createDirPath(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path exists and is not a directory")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return fmt.Errorf("no existing ancestor for %s", path)
	}
	if err := createDirPath(parent); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	return syncDir(parent)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *Store) publishBlob(payload []byte, digest event.Digest) error {
	dir := filepath.Join(s.root, "blobs", "sha256")
	target := filepath.Join(dir, digest.String())
	if _, err := os.Stat(target); err == nil {
		return verifyBlobFile(target, payload, digest)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect blob %s: %w", digest, err)
	}

	temp, err := os.CreateTemp(dir, ".blob-*")
	if err != nil {
		return fmt.Errorf("create temporary blob: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("set temporary blob mode: %w", err)
	}
	if err := writeAll(temp, payload); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary blob: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync temporary blob: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary blob: %w", err)
	}
	if err := os.Rename(tempPath, target); err != nil {
		return fmt.Errorf("publish blob: %w", err)
	}
	removeTemp = false
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync blob directory: %w", err)
	}
	return nil
}

func verifyBlobFile(path string, payload []byte, digest event.Digest) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open existing blob %s: %w", digest, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat existing blob %s: %w", digest, err)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(payload)) {
		return fmt.Errorf("existing blob %s has invalid type or size", digest)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read existing blob %s: %w", digest, err)
	}
	if !bytes.Equal(h.Sum(nil), digest[:]) {
		return fmt.Errorf("existing blob %s content hash mismatch", digest)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if err := writeAll(temp, data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return syncDir(dir)
}
