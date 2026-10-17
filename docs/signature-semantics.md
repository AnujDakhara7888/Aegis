# Sealed manifest contract (planned; no signer yet)

Manifest schema v1 JSON fields: manifest_schema_version (u16 = 1), run_id,
event_schema_version (u16 = 1), event_count (u64), first_event_hash,
terminal_event_hash, referenced_blob_set_digest, completion_status,
sealed_at_unix_nano (i64), recorder_public_key_fingerprint, signature_algorithm,
signature. Only signature is excluded from signing. No raw JSON is signed.

Proposed manifest bytes, to receive independent golden vectors before Milestone 2:
ASCII `AEGIS-MANIFEST-V1`, u16 manifest schema, length-prefixed UTF-8 run ID, u16
event schema, u64 count, raw 32-byte first hash, raw terminal hash, raw blob-set
digest, u16 completion enum (1 COMPLETED, 2 FAILED, 3 ABORTED), i64 seal time,
raw 32-byte key fingerprint, u16 algorithm (1 ED25519). Integer/string primitives
match canonical event encoding. Empty runs have count zero and zero first/terminal
hashes. JSON digests use lowercase hex; signatures use standard padded base64.

Blob-set digest: SHA256(ASCII `AEGIS-BLOBS-V1` || u32 unique_count || sorted raw
32-byte payload digests). Sort unsigned bytes, deduplicate references, include
empty payload blobs when referenced. Input/output hashes do not imply stored blobs.
Verifier checks every referenced blob’s content and size in addition to this digest.
Fingerprint = SHA256(raw 32-byte Ed25519 public key). Verification pins the expected
key from trusted caller configuration; never trust a key supplied by a run.

Seal under the same per-run append lock: validate full chain/blobs, construct and
sign manifest, write temporary manifest, fsync, rename, sync directory, mark sealed,
acknowledge. Failed/ambiguous publication requires recovery before further appends.
A retry may return the existing matching manifest; it must not silently re-sign a
conflicting completion status. An existing invalid manifest is corruption.

The signature proves: the logical event chain and referenced payload set have not
changed since the manifest was signed by the holder of the corresponding recorder
key. It does not establish honest/complete recording, real-world truth, or trusted
timestamps. Key compromise permits signing an alternate history. External terminal
hash anchoring, rotation and revocation are deferred.
