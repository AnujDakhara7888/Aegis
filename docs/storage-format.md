# Storage format (planned, not implemented)

The data root is `.aegis/` outside the repository by default, e.g.
`$HOME/.local/share/aegis/.aegis`. No credentials belong in this checkout.

```text
.aegis/
  keys/recorder.key
  keys/recorder.pub
  recorder.token
  runs/<run-id>/events.jsonl
  runs/<run-id>/manifest.json
  runs/<run-id>/index.json
  blobs/sha256/<lowercase-sha256>
```

Directories use mode 0700 and private key/token/data files 0600 where supported.
Keys/tokens use cryptographic randomness and are never logged. Public key pinning
is independent of potentially modified run directories. One process is sole writer.

One accepted Event per newline-terminated JSON line. JSON is presentation; hashes
cover reconstructed canonical fields. Whitespace/key-order edits preserve logical
verification; field changes do not. Strict parsing rejects ambiguous encodings.
The future verifier checks schema, contiguous sequence, run identity, unique event
IDs, causal parents, every link, blob sizes/digests, and signed manifest coverage.

Append transaction under a per-run lock: authenticate; validate and bound; resolve
idempotency; verify and publish payload; assign sequence/time; encode/hash; append
full line; flush; fsync; update derived index; acknowledge. On ambiguous I/O failure,
stop appends until recovery rather than reuse uncertain state. Index persistence
failure cannot roll back a durable event; rebuild it. Retry identity excludes
server-assigned fields and compares payload presence/content plus client fields.

Blob publication: write a private temporary file, sync file, atomically publish by
content hash, sync containing directory. Verify an existing digest path before
reuse. New run files/directories require directory synchronization as well.
Filesystem/platform durability assumptions must be tested and documented before
claiming power-loss safety. Orphan blobs are acceptable; garbage collection is later.

index.json is a versioned replaceable cache of event offsets, IDs and summaries.
Deleting it must not remove authoritative data; rebuild scans and validates the log.
manifest.json is authoritative only after durable atomic publication during sealing.
Sealing/recovery details are in the linked crash and signature specifications.
