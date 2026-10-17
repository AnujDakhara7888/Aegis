# Canonical event encoding v1 (frozen)

This document precedes the encoder implementation. Any change to the byte layout,
meaning of existing enum values, or permanent golden vectors requires a new event
schema version and an ADR. Domain strings are ASCII with no NUL or newline.

## Primitives

`u16`, `u32`, `u64`: unsigned integers of exactly 2, 4, 8 bytes, big endian.
`i64`: exactly 8 bytes, big-endian two’s-complement; conversion modulo 2^64.
`string`: u32 UTF-8 byte length then exactly those bytes. Valid Unicode scalar
values only. No normalization, case folding, terminator, or locale transformation.
`bytes`: u32 length then bytes, where a variable byte array is needed. Payload
bytes are not embedded in event encoding v1; only their digest and size are.
`digest`: fixed 32 raw SHA-256 bytes (not hex text and without a length prefix).
`optional(T)`: one byte 00 if absent, or 01 immediately followed by T if present.
Other presence bytes are invalid. Absent is distinct from a present zero value.

## Exact field order

| Order | Field | Encoding |
|---|---|---|
| 1 | domain | literal 14 bytes `AEGIS-EVENT-V1` |
| 2 | schema_version | u16, exactly 1 |
| 3 | run_id | string |
| 4 | event_id | string |
| 5 | parent_event_id | optional(string) |
| 6 | sequence | u64, >= 1 |
| 7 | observed_at_unix_nano | i64 |
| 8 | source_instance_id | optional(string) |
| 9 | source_monotonic_nano | optional(i64), nonnegative |
| 10 | source | u16 enum |
| 11 | kind | u16 enum |
| 12 | phase | u16 enum |
| 13 | input_hash | optional(digest) |
| 14 | output_hash | optional(digest) |
| 15 | payload_hash | optional(digest) |
| 16 | payload_size | u64 |
| 17 | capability_id | optional(string) |
| 18 | policy_decision | u16 enum |
| 19 | side_effect_class | u16 enum |
| 20 | replay_behavior | u16 enum |
| 21 | idempotency_key | optional(string) |
| 22 | attributes count | u32 |
| 23 | attributes | count pairs of string key then string value |

The literal prefix `AEGIS-EVENT-V1` is **14 bytes** (41 45 47 49 53 2d 45 56 45 4e 54 2d 56 31).

Attribute keys are unique and sorted lexicographically by unsigned UTF-8 bytes.
An empty/nil attribute map is encoded as count zero. Empty values are allowed.
No floats, nested attributes, implicit field defaults, or unknown required enums.
See [event schema](event-schema.md) for limits and all numeric enum assignments.

Neither `previous_event_hash` nor `event_hash` occurs in these bytes. Compute:

```text
SHA256(ASCII("AEGIS-CHAIN-V1") || previous_hash[32] || canonical_event_bytes)
```

The chain domain is 14 ASCII bytes. The predecessor of sequence 1 is 32 zero
bytes; later events must refer to the preceding accepted hash. Sequence/run/link
consistency across a log is a store/verifier responsibility. The current hash
function computes one link and is not a complete log verifier.

Golden files in testdata/canonical contain logical Events, expected canonical hex,
expected previous hash, and expected event hash. Tests must not regenerate expected
values. A separate Python standard-library implementation checks their bytes and
hashes. Future C implementations must consume the same vectors.
