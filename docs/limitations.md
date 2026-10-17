# Current limitations

Milestone 1 supplies a local recorder-core library, not a running service. It has
an append-only log, payload store, open-run verifier, derived index and conservative
tail recovery. There is no API, CLI, SDK, signed manifest, invoice demo, replay,
policy enforcement, kernel integration or UI. Open-run verification authenticates
nothing by itself; a party able to rewrite the log can recompute the chain.

The store establishes same-run backward parent existence, contiguous sequences,
hash links and referenced payload integrity. It does not establish source
authenticity or cross-event policy correctness. Callers must not mutate an
Event/map/pointer concurrently with encoding; Append clones its supplied input
before durable work. Strict decoder limits do not replace future HTTP body limits.
Payload storage is not encrypted or redacted and may expose sensitive content.

The recorder core assumes one process writer, a local filesystem and trusted host.
It has in-process per-run locks but no cross-process exclusion. It rescans each run
and every referenced blob before append, so no scale or performance claim is made.
Injected I/O failures and process-level tests do not prove power-loss behavior on
all filesystems. No multi-process, distributed transaction, universal
exactly-once, complete prompt-injection prevention or production-readiness claim.
An open run cannot detect deletion of a valid terminal suffix without a separately
trusted count/hash; signed manifests will provide that local sealed-run anchor.
A future signed log still cannot prove recorder honesty, observation completeness,
or effects outside the instrumented boundary. No measured performance numbers exist.

Format changes require a version and ADR; downstream C/Python implementations must
match golden vectors. Python currently checks vectors only, not SDK behavior.
