// Package hashchain computes individual event links; it is not a log verifier.
package hashchain

import (
	"crypto/sha256"

	"aegis.local/runtime/internal/canonical"
	"aegis.local/runtime/internal/event"
)

const Domain = "AEGIS-CHAIN-V1"

// Sum computes SHA256(domain || previous_event_hash || canonical_event_bytes).
// It ignores the supplied EventHash, returns a new digest, and never mutates e.
// The store/verifier must enforce sequence, run identity, and predecessor linkage.
func Sum(e event.Event) (event.Digest, error) {
	b, err := canonical.Encode(e)
	if err != nil {
		return event.Digest{}, err
	}
	h := sha256.New()
	h.Write([]byte(Domain))
	h.Write(e.PreviousEventHash[:])
	h.Write(b)
	var result event.Digest
	copy(result[:], h.Sum(nil))
	return result, nil
}
