# ADR 0003: File-backed authority and explicit trust

Status: accepted; open-run storage implemented, signing deferred.

Context: durable acknowledgement, index rebuilding and authenticating sealed runs
must be designed before a storage engine or API is introduced.

Decision: one writer process, per-run serialized append log, content-addressed
blobs, disposable indexes and canonical Ed25519 manifests verified against a pinned
key. Acknowledge after file/directory synchronization needed for authoritative
state. Fail closed on complete corrupt records. Only incomplete crash tails are
repairable on open runs. Data root defaults outside the repository.

Alternatives: SQLite first (obscures reference durability mechanics); distributed
writers (unnecessary scope); trusting an embedded public key (permits replacement);
hash chain without signed terminal count/hash (cannot authenticate a sealed tail).

Consequences: file/directory sync ordering and error injection need explicit tests.
A local hash chain is not authenticated. Signature trust stops at the trusted
recorder/key/host; external anchoring and multi-process safety remain future work.
