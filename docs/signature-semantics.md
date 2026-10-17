# Canonical sealed manifest v1

Manifest JSON fields are `manifest_schema_version`, `run_id`,
`event_schema_version`, `event_count`, `first_event_hash`,
`terminal_event_hash`, `referenced_blob_set_digest`, `completion_status`,
`sealed_at_unix_nano`, `recorder_public_key_fingerprint`, `signature_algorithm`,
and `signature`. Only the signature is excluded from signed canonical bytes. Raw
JSON is never signed.

## Exact canonical bytes

| Order | Field | Encoding |
|---|---|---|
| 1 | domain | literal 17 ASCII bytes `AEGIS-MANIFEST-V1` |
| 2 | manifest_schema_version | u16, exactly 1 |
| 3 | run_id | u32 UTF-8 byte length followed by bytes |
| 4 | event_schema_version | u16, exactly 1 |
| 5 | event_count | u64 |
| 6 | first_event_hash | raw 32-byte digest |
| 7 | terminal_event_hash | raw 32-byte digest |
| 8 | referenced_blob_set_digest | raw 32-byte digest |
| 9 | completion_status | u16: 1 COMPLETED, 2 FAILED, 3 ABORTED |
| 10 | sealed_at_unix_nano | signed i64, big-endian two's complement |
| 11 | recorder_public_key_fingerprint | raw 32-byte SHA-256 digest |
| 12 | signature_algorithm | u16: 1 ED25519 |

The 64-byte signature is excluded from canonical bytes and encoded as standard
padded base64 in JSON. JSON digests use lowercase hexadecimal. Empty runs have
count zero and zero first/terminal hashes. Nonempty runs use the actual first and
terminal hashes. Run IDs use the same validation rules as events. No floating-point
values, implicit enum defaults, unknown fields, nulls, duplicate keys, or trailing
JSON are accepted.

## Referenced blob set

Compute:

```text
SHA256(
    ASCII("AEGIS-BLOBS-V1") ||
    u32(unique_digest_count) ||
    sorted_unique_raw_digest_bytes
)
```

The domain is exactly 14 ASCII bytes. Sort digests lexicographically as unsigned
bytes and deduplicate repeated references. Include the empty-payload blob when it
is referenced. Input/output hashes are not blob references. An empty set still has
a deterministic nonzero digest. More than 2^32-1 unique digests is invalid. The
verifier checks each referenced blob's content and size separately.

## Keys and signatures

The recorder-key fingerprint is SHA256 of the raw 32-byte Ed25519 public key.
Signing uses standard Ed25519 over the canonical manifest bytes. Verification pins
the expected public key from trusted caller configuration; it never trusts a key
supplied by the run directory.

Seal under the same per-run append lock: validate the full chain and blobs,
construct and sign the manifest, write a private temporary file, synchronize it,
atomically rename it to `manifest.json`, synchronize the run directory, then
acknowledge. A retry returns an existing valid manifest only when its completion
status matches. It never silently re-signs conflicting or invalid state.

The signature proves that the logical event chain and referenced payload set have
not changed since the manifest was signed by the expected key holder. It does not
establish honest or complete recording, real-world truth, trusted timestamps, or an
uncompromised host/key. External anchoring, rotation, and revocation are deferred.

Permanent fixtures in `testdata/manifest` contain logical manifests, referenced
blob hashes, exact canonical bytes, blob-set digests, and expected signatures for
a labeled deterministic test key. Go and an independent Python standard-library
encoder reproduce all non-cryptographic bytes. Changing a vector or existing enum
value requires a new manifest schema version and an ADR.
