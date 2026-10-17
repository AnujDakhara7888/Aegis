# Permanent manifest v1 vectors

These fixtures freeze canonical manifest bytes, referenced-blob-set digests, and
Ed25519 signatures made with a deterministic test-only key. The private seed is
constructed only inside Go tests and is never a recorder credential or example
key. The public key is included so tests can verify each signature.

Go checks canonical bytes, blob-set calculation, public key, and signatures.
Python independently reconstructs canonical bytes and blob-set digests using only
its standard library. Tests read fixed expectations and never regenerate them.
Changing a fixture requires a new manifest schema version and an ADR.
