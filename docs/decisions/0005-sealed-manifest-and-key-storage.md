# ADR 0005: Canonical sealed manifests and recorder key storage

Status: accepted for Milestone 2, 2026-10-17.

## Context

An open hash chain detects changes inside the remaining chain but has no trusted
event count or terminal anchor. An attacker who can rewrite local files can remove
a valid suffix or rebuild the entire chain. Completed runs need a signature whose
meaning is stable across JSON formatting and future language implementations.

## Decision

A sealed run has one `manifest.json`, signed with Ed25519 over the frozen canonical
manifest v1 bytes. Raw JSON is never signed. The signed fields cover the run ID,
event schema, event count, first and terminal event hashes, deterministic set of
referenced payload hashes, completion status, seal time, recorder public-key
fingerprint, and signature algorithm. Only the signature bytes are excluded.

Verification receives the expected Ed25519 public key from trusted caller
configuration. It checks the expected key's fingerprint, the signature, the entire
event chain and every referenced blob, then compares the reconstructed count,
first hash, terminal hash, and blob-set digest to the signed fields. A public key
found inside a run directory would not be an acceptable trust source.

The local recorder key pair is generated explicitly from cryptographic randomness.
Both raw key files are first written and synchronized inside a private temporary
directory. The complete directory is atomically renamed to `.aegis/keys` and the
data-root directory is synchronized. Existing or partial key state causes a
fail-closed error rather than silent replacement. The private key must have no
group or world permission bits. Key rotation and repair are deferred.

Sealing holds the same per-run mutex as append. It verifies authoritative state,
constructs and signs the manifest, atomically publishes it, synchronizes the run
directory, and only then acknowledges. Once any manifest exists, append and open-run
recovery refuse the run. An identical seal retry verifies and returns the existing
manifest; a different completion status conflicts. Invalid existing manifests are
reported as corruption and are never overwritten.

## Alternatives considered

- Sign raw JSON: rejected because whitespace and object ordering are presentation.
- Put the public key in each run and trust it: rejected because an attacker could
  replace the history, key, and signature together.
- Sign only the terminal event hash: rejected because an empty-run definition,
  event count, completion status, blob set, key identity, and algorithm would remain
  outside the authenticated statement.
- Store a PEM key through an external dependency: rejected because fixed-size raw
  Ed25519 keys are unambiguous and the initial runtime is standard-library only.

## Consequences

Sealed runs are tamper-evident relative to the expected recorder public key. This
does not prove recorder honesty, observation completeness, trusted timestamps, or
the truth of recorded content. Key theft permits alternate signed histories.
External anchoring, key rotation/revocation, hardware-backed keys, and encrypted
private-key storage remain future work.
