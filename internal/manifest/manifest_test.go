package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aegis.local/runtime/internal/event"
)

func fixedKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return publicKey, privateKey
}

func sampleManifest(t *testing.T) Manifest {
	t.Helper()
	publicKey, _ := fixedKey(t)
	fingerprint, err := Fingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	blobSet, err := BlobSetDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Manifest{
		ManifestSchemaVersion:        SchemaVersion,
		RunID:                        "run-1",
		EventSchemaVersion:           event.SchemaVersion,
		ReferencedBlobSetDigest:      blobSet,
		CompletionStatus:             CompletionCompleted,
		RecorderPublicKeyFingerprint: fingerprint,
		SignatureAlgorithm:           SignatureEd25519,
	}
}

func signedSample(t *testing.T) Manifest {
	t.Helper()
	_, privateKey := fixedKey(t)
	signed, err := Sign(sampleManifest(t), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestCanonicalLayoutAndSignatureExclusion(t *testing.T) {
	m := sampleManifest(t)
	m.SealedAtUnixNano = -2
	encoded, err := Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded[:len(CanonicalDomain)]) != CanonicalDomain || len(CanonicalDomain) != 17 {
		t.Fatal("manifest domain changed")
	}
	m.Signature = bytes.Repeat([]byte{7}, ed25519.SignatureSize)
	again, err := Canonical(m)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatal("signature leaked into canonical manifest bytes")
	}
	if !bytes.Contains(encoded, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}) {
		t.Fatal("signed seal time was not encoded as big-endian two's complement")
	}
}

func TestBlobSetDigestIsSortedUniqueAndNonMutating(t *testing.T) {
	a := event.Digest{2}
	b := event.Digest{1}
	input := []event.Digest{a, b, a}
	before := append([]event.Digest(nil), input...)
	got, err := BlobSetDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	want, err := BlobSetDigest([]event.Digest{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if got != want || !reflect.DeepEqual(input, before) {
		t.Fatal("blob set was order-sensitive, duplicate-sensitive, or mutated input")
	}
	empty, err := BlobSetDigest(nil)
	if err != nil || empty == (event.Digest{}) {
		t.Fatal("empty blob set must have a deterministic nonzero digest")
	}
}

func TestSignVerifyAndTampering(t *testing.T) {
	publicKey, privateKey := fixedKey(t)
	signed, err := Sign(sampleManifest(t), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(signed, publicKey); err != nil {
		t.Fatal(err)
	}
	changed := signed
	changed.EventCount = 1
	changed.FirstEventHash = event.Digest{1}
	changed.TerminalEventHash = event.Digest{1}
	if err := VerifySignature(changed, publicKey); err == nil {
		t.Fatal("signed-field change preserved signature")
	}
	changed = signed
	changed.Signature = append([]byte(nil), signed.Signature...)
	changed.Signature[0] ^= 1
	if err := VerifySignature(changed, publicKey); err == nil {
		t.Fatal("signature modification verified")
	}
	otherPublic, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(signed, otherPublic); err == nil {
		t.Fatal("wrong public key verified")
	}
	bad := sampleManifest(t)
	bad.RecorderPublicKeyFingerprint[0] ^= 1
	if _, err := Sign(bad, privateKey); err == nil {
		t.Fatal("signed with mismatched fingerprint")
	}
}

func TestStrictJSONRoundTripAndRejections(t *testing.T) {
	signed := signedSample(t)
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil || !reflect.DeepEqual(decoded, signed) {
		t.Fatalf("round trip failed: %+v, %v", decoded, err)
	}
	tests := map[string][]byte{
		"unknown":      bytes.Replace(data, []byte(`"run_id":`), []byte(`"unknown":1,"run_id":`), 1),
		"duplicate":    bytes.Replace(data, []byte(`"run_id":`), []byte(`"run_id":"other","run_id":`), 1),
		"alias":        bytes.Replace(data, []byte(`"run_id":`), []byte(`"RUN_ID":"other","run_id":`), 1),
		"null":         bytes.Replace(data, []byte(`"run_id":"run-1"`), []byte(`"run_id":null`), 1),
		"numeric enum": bytes.Replace(data, []byte(`"completion_status":"COMPLETED"`), []byte(`"completion_status":1`), 1),
		"unknown enum": bytes.Replace(data, []byte(`"completion_status":"COMPLETED"`), []byte(`"completion_status":"complete"`), 1),
		"trailing":     append(append([]byte(nil), data...), []byte(` {}`)...),
		"array":        []byte(`[]`),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(candidate); err == nil {
				t.Fatal("accepted invalid manifest JSON")
			}
		})
	}
	for _, field := range manifestFields {
		t.Run("missing "+field, func(t *testing.T) {
			var values map[string]any
			if err := json.Unmarshal(data, &values); err != nil {
				t.Fatal(err)
			}
			delete(values, field)
			candidate, _ := json.Marshal(values)
			if _, err := Decode(candidate); err == nil {
				t.Fatal("accepted missing required field")
			}
		})
	}
}

func TestValidationBoundaries(t *testing.T) {
	tests := []func(*Manifest){
		func(m *Manifest) { m.ManifestSchemaVersion = 0 },
		func(m *Manifest) { m.ManifestSchemaVersion = 2 },
		func(m *Manifest) { m.RunID = "../run" },
		func(m *Manifest) { m.EventSchemaVersion = 2 },
		func(m *Manifest) { m.CompletionStatus = 0 },
		func(m *Manifest) { m.SignatureAlgorithm = 0 },
		func(m *Manifest) { m.FirstEventHash = event.Digest{1} },
		func(m *Manifest) { m.TerminalEventHash = event.Digest{1} },
	}
	for index, change := range tests {
		m := sampleManifest(t)
		change(&m)
		if err := m.ValidateFields(); err == nil {
			t.Fatalf("case %d accepted invalid manifest", index)
		}
	}
	m := sampleManifest(t)
	m.EventCount = math.MaxUint64
	m.FirstEventHash = event.Digest{1}
	m.TerminalEventHash = event.Digest{2}
	m.SealedAtUnixNano = math.MinInt64
	if _, err := Canonical(m); err != nil {
		t.Fatal(err)
	}
	m.Signature = bytes.Repeat([]byte{0}, ed25519.SignatureSize-1)
	if err := m.Validate(); err == nil {
		t.Fatal("accepted short signature")
	}
	for _, value := range []CompletionStatus{0, 4, math.MaxUint16} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatalf("marshaled invalid completion %d", value)
		}
	}
	if _, err := Fingerprint(ed25519.PublicKey(strings.Repeat("x", 31))); err == nil {
		t.Fatal("accepted short public key")
	}
}

func TestPermanentGoldenVectors(t *testing.T) {
	type fixture struct {
		Name                 string          `json:"name"`
		Manifest             json.RawMessage `json:"manifest"`
		ReferencedBlobHashes []string        `json:"referenced_blob_hashes"`
		BlobSetDigest        string          `json:"blob_set_digest"`
		CanonicalHex         string          `json:"canonical_hex"`
		PublicKeyHex         string          `json:"public_key_hex"`
	}
	paths, err := filepath.Glob("../../testdata/manifest/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected three permanent vectors, got %d", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var vector fixture
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			m, err := Decode(vector.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := Canonical(m)
			if err != nil || hex.EncodeToString(canonical) != vector.CanonicalHex {
				t.Fatalf("canonical bytes changed: %v", err)
			}
			references := make([]event.Digest, len(vector.ReferencedBlobHashes))
			for index, value := range vector.ReferencedBlobHashes {
				references[index], err = event.ParseDigest(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			digest, err := BlobSetDigest(references)
			if err != nil || digest.String() != vector.BlobSetDigest || digest != m.ReferencedBlobSetDigest {
				t.Fatalf("blob-set digest changed: %s, %v", digest, err)
			}
			publicBytes, err := hex.DecodeString(vector.PublicKeyHex)
			if err != nil {
				t.Fatal(err)
			}
			publicKey := ed25519.PublicKey(publicBytes)
			if err := VerifySignature(m, publicKey); err != nil {
				t.Fatal(err)
			}
			fixedPublic, _ := fixedKey(t)
			if !bytes.Equal(publicKey, fixedPublic) {
				t.Fatal("fixture public key changed independently of test key")
			}
		})
	}
}
