# Open-run storage format (implemented in Milestone 1)

The data root is `.aegis/` outside the repository by default, e.g.
`$HOME/.local/share/aegis/.aegis`. No credentials belong in this checkout.

```text
.aegis/
  keys/recorder.key             # future signing milestone
  keys/recorder.pub             # future signing milestone
  recorder.token                # future service milestone
  runs/<run-id>/events.jsonl
  runs/<run-id>/manifest.json   # future signing milestone
  runs/<run-id>/index.json
  blobs/sha256/<lowercase-sha256>
```

Directories use mode 0700 and private key/token/data files 0600 where supported.
Keys/tokens use cryptographic randomness and are never logged. Public key pinning
is independent of potentially modified run directories. One process is sole writer.

One accepted Event occupies exactly one newline-terminated JSON line. JSON is
presentation; hashes cover reconstructed canonical fields. Insignificant whitespace
that does not introduce a physical newline, and object-key ordering, preserve
logical verification. Field changes do not. Strict parsing rejects ambiguous
encodings. The implemented open-run verifier checks schema, contiguous sequence,
run identity, unique event IDs, backward causal parents, every link, and referenced
blob sizes/digests. Signed manifest coverage is deferred.

The current library append transaction runs under an in-process per-run lock:
clone and validate; verify the authoritative run; resolve idempotency; publish the
payload; assign sequence/time; encode/hash; append a full line; synchronize the
log; best-effort replace the derived index; acknowledge. Authentication belongs to
the future service boundary. On ambiguous append/sync failure, the store stops
appends until explicit recovery. Index persistence failure cannot roll back a
durable event. Retry identity excludes server-assigned fields and compares payload
presence/digest/size plus every client-controlled field.

Blob publication: write a private temporary file, sync file, atomically publish by
content hash, sync containing directory. Verify an existing digest path before
reuse. New run files/directories require directory synchronization as well.
Filesystem/platform durability assumptions must be tested and documented before
claiming power-loss safety. Orphan blobs are acceptable; garbage collection is later.

`index.json` schema v1 contains its schema version, run ID, event count, terminal
hash, and ordered entries of sequence, event ID, byte offset, and line length.
It is a versioned replaceable cache, never read as authority during append or
verification. Deleting or corrupting it does not remove or invent event data;
rebuild scans and validates the log and blobs before atomically replacing it.

The store currently rescans the entire run and rehashes referenced blobs before
each append. This is deliberate reference behavior, not a scalability claim.
Unreferenced orphan blobs are ignored and garbage collection is deferred.

manifest.json is authoritative only after durable atomic publication during sealing.
Sealing/recovery details are in the linked crash and signature specifications.
