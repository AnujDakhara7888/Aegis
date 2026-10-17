# ADR 0002: Explicit event encoding and strict JSON

Status: accepted for schema v1, 2026-10-17.

Context: JSON byte representations vary across languages, and duplicate fields or
implicit defaults undermine stable validation. Wall clocks do not define order.

Decision: freeze fixed-order, big-endian, domain-separated canonical encoding with
u16 enums, bounded UTF-8 strings, explicit optional markers, raw SHA-256 digests,
and sorted string attributes. Use a structural EventInput distinct from accepted
Event; pointers preserve optional absence. Required enums use explicit NONE or
UNSPECIFIED values, never implicit zero. Strict decoding rejects ambiguous JSON,
unknown fields and malformed Unicode. Sequence is authoritative order.

Alternatives: raw JSON hashing (format-sensitive); protobuf determinism (not a
cross-language promise); string enums in canonical bytes (larger and rename-prone);
Unicode normalization (changes supplied content); client timestamps as order (unsafe).

Consequences: exact bytes and enum numbers are a compatibility contract. Golden
vectors cannot be updated without schema version change and an ADR. Limits and
JSON names are part of v1. Structural validation cannot check log context; the
store/verifier will enforce sequence, parent existence and hash-link consistency.
