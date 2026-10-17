// Package canonical implements the frozen, version-one logical event encoding.
package canonical

import (
	"encoding/binary"
	"sort"

	"aegis.local/runtime/internal/event"
)

const Domain = "AEGIS-EVENT-V1"

// Encode validates before allocating encoded output. It never hashes JSON or
// includes either chain hash. The caller must not mutate e while Encode runs.
func Encode(e event.Event) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	w := encoder{b: make([]byte, 0, 512)}
	w.b = append(w.b, Domain...)
	w.u16(e.SchemaVersion)
	w.str(e.RunID)
	w.str(e.EventID)
	w.optionalString(e.ParentEventID)
	w.u64(e.Sequence)
	w.u64(uint64(e.ObservedAtUnixNano)) // signed i64 as two's complement
	w.optionalString(e.SourceInstanceID)
	if e.SourceMonotonicNano == nil {
		w.b = append(w.b, 0)
	} else {
		w.b = append(w.b, 1)
		w.u64(uint64(*e.SourceMonotonicNano))
	}
	w.u16(uint16(e.Source))
	w.u16(uint16(e.Kind))
	w.u16(uint16(e.Phase))
	w.optionalDigest(e.InputHash)
	w.optionalDigest(e.OutputHash)
	w.optionalDigest(e.PayloadHash)
	w.u64(e.PayloadSize)
	w.optionalString(e.CapabilityID)
	w.u16(uint16(e.PolicyDecision))
	w.u16(uint16(e.SideEffectClass))
	w.u16(uint16(e.ReplayBehavior))
	w.optionalString(e.IdempotencyKey)
	keys := make([]string, 0, len(e.Attributes))
	for key := range e.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys) // Go string comparison is lexicographic unsigned byte order.
	w.u32(uint32(len(keys)))
	for _, key := range keys {
		w.str(key)
		w.str(e.Attributes[key])
	}
	return w.b, nil
}

type encoder struct{ b []byte }

func (w *encoder) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *encoder) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *encoder) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *encoder) str(v string) { w.u32(uint32(len(v))); w.b = append(w.b, v...) }
func (w *encoder) optionalString(v *string) {
	if v == nil {
		w.b = append(w.b, 0)
		return
	}
	w.b = append(w.b, 1)
	w.str(*v)
}
func (w *encoder) optionalDigest(v *event.Digest) {
	if v == nil {
		w.b = append(w.b, 0)
		return
	}
	w.b = append(w.b, 1)
	w.b = append(w.b, v[:]...)
}
