package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

// GenerateKey creates a new Ed25519 key using the supplied cryptographic source.
// Callers normally pass crypto/rand.Reader; accepting a reader enables fixed tests.
func GenerateKey(random io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return publicKey, privateKey, nil
}

func Sign(unsigned Manifest, privateKey ed25519.PrivateKey) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, fmt.Errorf("private key must be exactly %d bytes", ed25519.PrivateKeySize)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return Manifest{}, fmt.Errorf("derive Ed25519 public key")
	}
	fingerprint, err := Fingerprint(publicKey)
	if err != nil {
		return Manifest{}, err
	}
	if unsigned.RecorderPublicKeyFingerprint != fingerprint {
		return Manifest{}, fmt.Errorf("manifest fingerprint does not match private key")
	}
	canonical, err := Canonical(unsigned)
	if err != nil {
		return Manifest{}, err
	}
	unsigned.Signature = ed25519.Sign(privateKey, canonical)
	return unsigned, nil
}

func VerifySignature(signed Manifest, expectedPublicKey ed25519.PublicKey) error {
	if err := signed.Validate(); err != nil {
		return err
	}
	fingerprint, err := Fingerprint(expectedPublicKey)
	if err != nil {
		return err
	}
	if signed.RecorderPublicKeyFingerprint != fingerprint {
		return fmt.Errorf("manifest fingerprint does not match expected public key")
	}
	canonical, err := Canonical(signed)
	if err != nil {
		return err
	}
	if !ed25519.Verify(expectedPublicKey, canonical, signed.Signature) {
		return fmt.Errorf("invalid Ed25519 manifest signature")
	}
	return nil
}
