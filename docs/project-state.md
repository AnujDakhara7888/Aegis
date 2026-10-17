# Project state

Updated: 2026-10-17 (America/New_York).

Current milestone: Milestone 2A signed sealing complete. The previous recorder
core milestone is committed as `18a1de3`. The signed-sealing changes described
below are uncommitted and have not been pushed.

## What exists now

- A documented project contract, threat model, roadmap, limitations, and five ADRs.
- Strict version-one event types, canonical bytes, permanent Go/Python vectors,
  domain-separated SHA-256 links, and an append-only file-backed recorder store.
- Content-addressed payloads, full open-run verification, conservative crash-tail
  recovery, idempotent event retries, and a disposable derived index.
- A frozen version-one manifest format with three permanent boundary fixtures.
  Canonical signed bytes cover run ID, event schema, event count, first and terminal
  event hashes, referenced-payload-set digest, completion status, recorder-assigned
  seal time, expected-key fingerprint, and signature algorithm.
- Standard-library Ed25519 signing and verification. Manifest JSON presentation is
  excluded from the signature, so harmless field order or whitespace changes do
  not change the authenticated statement.
- Explicit recorder key generation from cryptographic randomness. The raw key pair
  is synchronized in a temporary private directory and atomically published to
  `keys/`; existing or partial key state is never silently replaced.
- Atomic sealing under the same per-run lock as append. Equal completion-status
  retries verify and return the existing seal; a different status conflicts.
- Sealed-run verification against a caller-supplied expected public key. It checks
  the signature, full event chain, all payloads, event count, first/terminal anchors,
  and referenced-payload set.
- Append and open-run recovery refuse any run containing a manifest. A sealed
  derived index can be rebuilt only after expected-key verification.

## Important invariants established

1. An event acknowledgement follows synchronized log storage; a seal acknowledgement
   follows durable atomic manifest publication and run-directory synchronization.
2. A failed append or seal may have committed. An identical retry discovers and
   returns the durable result instead of creating a duplicate or new signature.
3. The event log and referenced blobs are authoritative while a run is open. The
   signed manifest joins them as authoritative state after sealing; the index remains
   disposable.
4. A signature is checked against an expected public key supplied outside the run
   directory. An attacker cannot establish trust by replacing history and choosing
   a new key beside it.
5. The signed count and terminal hash detect deletion of a valid final event suffix,
   which an open hash chain alone cannot detect.
6. Any existing invalid manifest fails closed. It is never overwritten or treated
   as permission to append or recover.
7. Empty runs have zero first and terminal hashes. Repeated payload references are
   deduplicated in a sorted, domain-separated payload-set digest.
8. The implementation serializes one process's writers. It does not claim
   cross-process exclusion or distributed exactly-once behavior.

## Checks executed after the final changes

Environment: Go 1.26.2 darwin/arm64, Python 3.14.5. The sandbox cannot use the
default Go build cache, so Go commands used
`GOCACHE=/tmp/aegis-go-build-cache`.

| Command | Result |
|---|---|
| `gofmt -w internal/manifest internal/store internal/verify` | Completed |
| `GOCACHE=/tmp/aegis-go-build-cache make check` | Passed |
| `go test ./...` through `make check` | All six implemented packages passed |
| `go test -race ./...` through `make check` | All six implemented packages passed |
| `go vet ./...` through `make check` | Passed with no diagnostics |
| `python3 -m unittest discover -s scripts -p 'test_*.py' -v` | 3 tests passed; 4 event fixtures and 3 manifest fixtures checked |
| `go test -coverpkg=./internal/manifest,./internal/store,./internal/verify ...` | Passed; combined statement coverage 79.7% |
| `git diff --check` | Passed |

Tests directly cover:

- strict manifest JSON, canonical-field sensitivity, stable enums, signatures,
  wrong keys, key fingerprints, blob-set ordering/deduplication, and boundary vectors;
- durable key generation, file modes, repeat generation, partial key state, broad
  private-key permissions, and public/private mismatch handling;
- empty and populated seals, equal retries, conflicting status, atomic publication,
  ambiguous publication outcome, and a response lost after durable sealing;
- event alteration, terminal-suffix deletion, payload alteration, manifest-field
  alteration, signature alteration, wrong expected key, and harmless JSON reformat;
- append/recovery rejection after sealing, invalid-manifest preservation, missing
  manifests, unsafe run IDs, and authenticated sealed-index rebuilds;
- all earlier event, append, verification, recovery, concurrency, and index tests.

## Honest limitations

There is no HTTP service, CLI, Python SDK, deterministic invoice demonstration,
replay engine, policy enforcement, kernel integration, or UI. The recorder core
and sealing functions are Go library APIs and have not been benchmarked.

Sealing proves that the verified files match a statement signed by the holder of
the expected recorder key. It cannot prove that the recorder was honest, captured
every action, used a truthful timestamp, or observed effects outside its boundary.
Key theft permits alternate signed histories. Deleting an entire run or its
manifest requires a separately trusted inventory or external anchor to detect.

The store rescans the full log and every referenced blob before each append. There
is no cross-process writer lock, key rotation/revocation, encrypted or hardware-backed
private key, orphan-blob collection, external anchoring, or physical power-loss
validation across filesystems. Raw payloads and raw private-key files are not
encrypted. Public-key distribution remains a deployment responsibility.

Open decisions: final GitHub namespace and license review before publication;
public-key distribution, rotation and revocation; external run inventory/anchoring;
actual SBUnix source and audit bridge; filesystem durability characterization.

## Reproduction

From the repository root:

```sh
export GOCACHE=/tmp/aegis-go-build-cache
make check
```

This command does not start a service, create production credentials, contact a
model, or perform a financial operation. Tests create only temporary test keys.

## Recommended commit

Use one commit for this coherent format-and-implementation milestone:

```text
feat: sign and verify sealed Aegis runs
```

It contains ADR 0005, the frozen manifest contract and vectors, key generation,
atomic sealing, expected-key verification, authenticated sealed-index rebuild,
tamper/failure tests, and updated project documentation. Do not push until the
repository and publication claims receive the planned review.

## Exact next-session prompt

Continue Aegis with the remaining Milestone 2 local-service slice. Read
`docs/project-state.md`, `docs/tasks.md`, all ADRs, and the storage, recovery,
signature, threat-model, and limitations documents before editing. Preserve event
schema v1, manifest schema v1, and all permanent vectors. Specify the HTTP contract
first, then implement a loopback-only authenticated Go service with bounded request
bodies and headers, structured errors, server timeouts, graceful shutdown, and
endpoints for health, run creation, event append, sealing, and verification. Add a
small `aegisctl` and standard-library Python SDK only after the server boundary is
tested. Use cryptographic randomness and restrictive token permissions. Do not
implement replay, kernel changes, React, SQLite, protobuf, OpenTelemetry, cloud
deployment, or publish/push. Run formatting, Go tests, race detection, vet, Python
tests, secret checks, and update this ledger with exact evidence.
