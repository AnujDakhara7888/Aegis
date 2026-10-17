# Project state

Updated: 2026-10-17 (America/New_York).

Current milestone: Milestone 1 recorder core complete. Milestone 0 and the event
format foundation were committed as `a29031f`. The storage/recovery changes from
this session are intentionally still uncommitted and have not been pushed.

## What exists now

- A documented project contract, threat model, roadmap, limitations, and four ADRs.
- Strict version-one EventInput and accepted Event types with stable readable enums.
- Bounded, ambiguity-rejecting JSON decoding and validation.
- Frozen canonical event bytes with four Go/Python permanent vectors.
- Domain-separated SHA-256 event links.
- A single-process file-backed `Store` that explicitly creates runs.
- Per-run serialized append with recorder-assigned run ID, sequence, observed time,
  predecessor hash, payload reference, and event hash.
- Content-addressed SHA-256 blobs published through synchronized temporary files
  and atomic rename; existing blobs are rehashed before reuse.
- Idempotent event-ID retry: equal client content returns the original accepted
  event, while changed fields or payload presence/content return a conflict.
- Full open-run verification of strict JSON, run identity, contiguous order,
  unique event IDs, backward same-run parents, hash links, and referenced blobs.
- Conservative explicit recovery for incomplete final JSON and valid events that
  only lost their final newline. Complete invalid or malformed data is retained
  and reported as corruption.
- Versioned derived `index.json` with event offsets and lengths. Append never trusts
  it; deletion or corruption cannot erase authoritative history, and rebuild
  atomically replaces it after full verification.
- Fault injection for partial append, synchronization failure, derived-index
  failure, and a response lost after durable append.

## Important invariants established

1. A successful `Append` returns only after the event line has been synchronized.
2. A failed append may have committed; an uncertain run blocks further appends
   until `RecoverRun` inspects authoritative state.
3. A retry after a lost response returns the original event without duplication.
4. Payload publication precedes event acknowledgement; a failed event append may
   leave an orphan blob, which does not affect verification.
5. The event log and referenced blobs are authoritative. The index is disposable.
6. Recovery truncates only a parser-confirmed incomplete terminal fragment. It
   never silently deletes a complete invalid event or malformed data.
7. Parent IDs must identify an earlier event in the same run; sequence order remains
   separate from causal relationships.
8. The implementation serializes one process's writers. It does not claim
   cross-process exclusion or distributed exactly-once behavior.

## Checks executed after the final changes

Environment: Go 1.26.2 darwin/arm64, Python 3.14.5. The sandbox cannot use the
default Go build cache, so final Go commands used
`GOCACHE=/tmp/aegis-go-build-cache`.

| Command | Result |
|---|---|
| `gofmt -w internal/event internal/store internal/verify` | Completed |
| `GOCACHE=/tmp/aegis-go-build-cache make check` | Passed |
| `go test ./...` through `make check` | All implemented packages passed |
| `go test -race ./...` through `make check` | All implemented packages passed |
| `go vet ./...` through `make check` | Passed with no diagnostics |
| `python3 -m unittest discover -s scripts -p 'test_*.py' -v` | 2 tests passed; all 4 permanent vectors and linked pair checked |
| `go test -coverpkg=./internal/store,./internal/verify -coverprofile=/tmp/aegis-storage-cover.out ./internal/store ./internal/verify` | Passed; combined statement coverage 78.9% |

One intermediate `go tool cover` summary attempt inherited the restricted default
cache and was denied by the sandbox. Re-running the final combined command with the
writable `GOCACHE` succeeded and reported `78.9%`.

Tests directly cover:

- append/reopen ordering, file modes, parent rules, and 64 concurrent appends;
- equal and conflicting retries, including absent versus empty payloads;
- shared content addresses, missing/replaced/wrong-size blobs, and orphan blobs;
- index deletion, corruption, stale-index replacement, failure, and rebuild;
- event modification, middle deletion, reordering, duplication, and JSON whitespace;
- incomplete, malformed, complete-invalid, newline-missing, and oversized tails;
- partial writes, uncertain synchronization, response loss, and sealed markers.

## Honest limitations

There is no HTTP service, CLI, Python SDK, signed manifest, invoice demonstration,
replay engine, policy enforcement, kernel integration, or UI. The recorder core is
a Go library and has not been benchmarked.

An open hash chain cannot detect deletion of a valid final suffix because it has no
separately trusted event count or terminal hash. The future signed manifest provides
that sealed-run anchor. Even a signed manifest cannot prove that the recorder was
honest, complete, uncompromised, or aware of actions outside its boundaries.

The store rescans the full log and every referenced blob before each append. This is
deliberate correctness-first reference behavior and is not intended as a throughput
design. There is no cross-process writer lock, orphan-blob garbage collection,
payload encryption, key management, or power-loss validation across filesystems.
The fault tests exercise API-visible failure semantics, not physical power removal.

Open decisions: final GitHub namespace and license review before publication;
public-key distribution and rotation; actual SBUnix source and audit bridge;
filesystem durability characterization; sealed-manifest vectors and key storage.

## Reproduction

From the repository root:

```sh
export GOCACHE=/tmp/aegis-go-build-cache
make check
```

This command does not start a service, create credentials, contact a model, or
perform a financial operation.

## Recommended commit boundaries

1. `docs: define open-run storage and recovery invariants`
   - ADR 0004 and updates to architecture, storage, recovery, limitations, roadmap,
     task checklist, README, and this project ledger.
2. `feat: add verified append-only event and blob store`
   - ID validation helper, store creation, serialized append, content-addressed
     payloads, idempotent retry, read-only verification, and tests.
3. `feat: add conservative recovery and rebuildable indexes`
   - tail classification/repair, atomic derived indexes, fault injection tests,
     sealed-marker refusal, and recovery evidence.

Because implementation and tests share several files, a single honest alternative
is `feat: complete Aegis recorder core storage and recovery`. Do not push until the
repository and publication claims receive the planned review.

## Exact next-session prompt

Continue Aegis with Milestone 2 only. Read docs/project-state.md, docs/tasks.md,
all ADRs, and the event, canonical, storage, recovery, signature, threat-model, and
limitations documents before editing. Preserve event schema v1 and its permanent
vectors. First specify and freeze canonical manifest bytes with independent Go and
Python vectors, expected-key verification, completion states, event count, first
and terminal hashes, and referenced-blob-set digest. Then implement Ed25519 key
generation/storage, atomic sealing, sealed-run verification, and rejection of later
appends. After that, implement the authenticated 127.0.0.1 HTTP service, aegisctl,
the standard-library Python SDK, and deterministic local invoice-agent demo in
small tested sections. Use cryptographic randomness, restrictive permissions,
bounded requests, structured errors, timeouts, graceful shutdown, and simulated
effects only. Do not implement replay, kernel changes, React, SQLite, protobuf,
OpenTelemetry, cloud deployment, or publish/push. Run formatting, Go tests, race
detection, vet, Python tests, end-to-end demo tests, secret checks, and update this
ledger with exact results and commit boundaries.
