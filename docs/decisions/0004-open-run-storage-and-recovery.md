# ADR 0004: Open-run storage, verification, and recovery

Status: accepted for Milestone 1, 2026-10-17.

## Context

The canonical event and hash-link formats are frozen, but a trustworthy recorder
also needs a precise durability boundary. A failed write may have written nothing,
part of a line, or the complete line. The caller cannot infer which outcome occurred
from an error alone. Derived indexes must never become more authoritative than the
event log, and retry handling must not create duplicate events.

## Decision

One `Store` instance is the sole writer for its data root. It owns an in-process
mutex per run; cross-process locking remains unsupported. A run is created
explicitly and begins with an empty, synchronized `events.jsonl`.

`Append` performs these operations while holding the run mutex:

1. Clone and validate the client input so later caller mutation cannot change it.
2. Verify the complete authoritative log and referenced blobs without repairing it.
3. Resolve an existing event ID by comparing client-controlled fields and payload
   presence, digest, and size. Identical input returns the accepted event; different
   input returns an idempotency conflict.
4. Require any parent event to exist earlier in the same run.
5. Publish and synchronize the payload blob, if present.
6. Assign run ID, sequence, observed time, predecessor hash, and event hash.
7. Append one complete JSON line and synchronize the log before acknowledgement.
8. Atomically replace the derived index. An index-write failure does not invalidate
   or hide a durable event; the index may be deleted and rebuilt from the log.

After an append or synchronization error whose disk outcome is uncertain, that
in-memory run is marked as requiring recovery. Later appends fail until
`RecoverRun` verifies the log and repairs only an incomplete final fragment. A
failure after successful log synchronization but before the response simulates a
lost acknowledgement: retry finds and returns the original event.

Blob names are lowercase SHA-256 digests. New blobs are written to a private
temporary file, synchronized, closed, atomically renamed, and followed by a
directory synchronization. Existing blobs are rehashed before reuse. Empty and
absent payloads remain distinct: an empty payload has the SHA-256 empty digest and
a zero-byte blob; an absent payload has no digest.

Verification checks strict event decoding, run identity, contiguous sequence,
unique event IDs, backward causal parents, predecessor links, recomputed event
hashes, and every referenced blob's size and digest. It ignores orphan blobs.

The index is versioned JSON containing event IDs, sequence numbers, log offsets,
line lengths, and the terminal hash. It is always derived. Append and reopen do
not trust it; `RebuildIndex` replaces it from a verified log.

## Tail classification

- Every newline-terminated line must be a complete valid event. Any invalid line,
  including the final one, is corruption.
- A final non-newline JSON value that is a complete valid event is retained and
  receives a synchronized newline during recovery.
- A final fragment for which Go's JSON parser reports an unexpected end is treated
  as an interrupted write and may be truncated to the last verified offset.
- Any other malformed final fragment is corruption and is never discarded.
- Recovery refuses to alter a run when `manifest.json` exists. Sealed-run handling
  belongs to the signing milestone.

## Alternatives considered

- Trust `index.json` during open: rejected because deletion or partial replacement
  could hide authoritative events.
- Automatically truncate on every decode error: rejected because it can erase a
  complete but modified or otherwise invalid event.
- Retry an uncertain append immediately: rejected because it may append a duplicate
  before the previous disk outcome is known.
- Introduce SQLite now: rejected because the file-backed reference behavior is an
  explicit project milestone and exposes the intended durability invariants.

## Consequences

Every append currently rescans and verifies its run, favoring correctness and a
small auditable implementation over throughput. This is intentionally inefficient
and will be measured before any indexing or caching optimization. Process-crash
tests and `fsync` calls do not prove identical power-loss behavior on every
filesystem. Cross-process writers, sealed manifests, external anchors, garbage
collection of orphan blobs, and encrypted payload storage remain future work.
