# Current limitations

This session supplies event format primitives, not a running recorder. There is
no durable store, log verifier, index, crash recovery, API, CLI, SDK, signed
manifest, invoice demo, replay, policy enforcement, kernel integration or UI.
Hash calculation alone cannot authenticate a run or prove a payload exists.

Structural validation does not establish parent existence, contiguous sequences,
source authenticity or cross-event policy consistency. Callers must not mutate
an Event/map/pointer concurrently with encoding; the eventual store will own an
immutable snapshot under its lock. Strict decoder byte limits do not replace HTTP
body limits or filesystem read limits. All payloads may expose sensitive content.

Later recorder implementation initially assumes a single process writer, local
filesystem and trusted host. No multi-process, distributed transaction, universal
exactly-once, complete prompt-injection prevention or production-readiness claim.
A signed log cannot prove recorder honesty, observation completeness, or effects
outside the instrumented boundary. No measured performance numbers exist.

Format changes require a version and ADR; downstream C/Python implementations must
match golden vectors. Python currently checks vectors only, not SDK behavior.
