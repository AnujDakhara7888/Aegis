# Architecture and invariants

Status: Milestone 2A signed sealing implemented. Service, replay, and kernel
enforcement remain future work.

The Go Flight Recorder will accept EventInput, validate it, store payloads by
SHA-256, assign authoritative fields, and append accepted Events. The Python agent
and its supplied data are untrusted. An eventual trusted proxy mediates model/tool
operations; AgentOS and a privileged audit reader contribute kernel observations.
The runtime does not make application-supplied observations trustworthy by hashing
them. Source enum values are labels, not authenticated source identities.

Authoritative state: complete events, referenced blobs, and signed sealed manifest.
Derived state: index.json, caches, summaries, and in-memory indexes. Index loss must
be recoverable from authoritative state alone. A sole recorder process owns a data
root. Cross-process writer safety is not claimed; deployment must prevent a second
writer until a tested exclusion mechanism exists.

Invariants:
1. Accepted sequences are contiguous from one within a run, under a per-run lock.
2. Parent ID denotes causality, not physical adjacency. The store requires
   a parent to be an already accepted event in that run; cross-run lineage is later.
3. Server time is human context, not monotonic ordering. Source-local monotonic
   time requires a source instance and cannot order across processes/restarts.
4. Equal logical fields produce equal canonical bytes regardless of JSON layout
   or attribute insertion order. Invalid input is rejected before hashing.
5. The previous hash is covered once, outside the canonical event bytes.
6. An acknowledgement follows durable blob publication and log synchronization.
7. Event ID retries compare client logical content, not newly assigned timestamps.
   Equal retries return the original event; unequal retries conflict.
8. Sealing freezes a run and signs an explicit logical manifest; no appends follow.
9. Only an incomplete terminal fragment is eligible for crash-tail truncation.
10. No irreversible effect is repeated automatically during future replay.

Standard libraries and file storage are the reference design. SQLite, protobuf,
React, distributed infrastructure, WASM, and OpenTelemetry are deliberately later.
No server, replay engine, or enforcement boundary is implemented. The manifest
signer and verifier are library APIs. The file store rescans authoritative state
before each append; this favors a small, auditable reference implementation over
throughput until measurements exist.
