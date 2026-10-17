package manifest

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	"aegis.local/runtime/internal/event"
)

const (
	CanonicalDomain = "AEGIS-MANIFEST-V1"
	BlobSetDomain   = "AEGIS-BLOBS-V1"
)

// Canonical encodes every meaningful manifest field except Signature.
func Canonical(m Manifest) ([]byte, error) {
	if err := m.ValidateFields(); err != nil {
		return nil, err
	}
	result := make([]byte, 0, 192)
	result = append(result, CanonicalDomain...)
	result = binary.BigEndian.AppendUint16(result, m.ManifestSchemaVersion)
	result = binary.BigEndian.AppendUint32(result, uint32(len(m.RunID)))
	result = append(result, m.RunID...)
	result = binary.BigEndian.AppendUint16(result, m.EventSchemaVersion)
	result = binary.BigEndian.AppendUint64(result, m.EventCount)
	result = append(result, m.FirstEventHash[:]...)
	result = append(result, m.TerminalEventHash[:]...)
	result = append(result, m.ReferencedBlobSetDigest[:]...)
	result = binary.BigEndian.AppendUint16(result, uint16(m.CompletionStatus))
	result = binary.BigEndian.AppendUint64(result, uint64(m.SealedAtUnixNano))
	result = append(result, m.RecorderPublicKeyFingerprint[:]...)
	result = binary.BigEndian.AppendUint16(result, uint16(m.SignatureAlgorithm))
	return result, nil
}

// BlobSetDigest hashes the sorted unique set of referenced payload digests.
func BlobSetDigest(references []event.Digest) (event.Digest, error) {
	if uint64(len(references)) > math.MaxUint32 {
		return event.Digest{}, fmt.Errorf("too many referenced blob digests")
	}
	ordered := append([]event.Digest(nil), references...)
	sort.Slice(ordered, func(i, j int) bool {
		return string(ordered[i][:]) < string(ordered[j][:])
	})
	unique := ordered[:0]
	for _, digest := range ordered {
		if len(unique) == 0 || unique[len(unique)-1] != digest {
			unique = append(unique, digest)
		}
	}
	h := sha256.New()
	h.Write([]byte(BlobSetDomain))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(unique)))
	h.Write(count[:])
	for _, digest := range unique {
		h.Write(digest[:])
	}
	var result event.Digest
	copy(result[:], h.Sum(nil))
	return result, nil
}
