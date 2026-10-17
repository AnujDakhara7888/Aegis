# Granular acceptance checklist

## Current assignment
- [x] Inspect workspace, instructions, Git state, Go/Python versions.
- [x] Present tree, assumptions, format and checklist before edits.
- [x] Define repository layout, module, license, ignore rules and Make targets.
- [x] Write architecture, event/canonical/storage/recovery/signature contracts.
- [x] Write threat model, limitations, kernel spike, roadmap and ADRs.
- [x] Implement stable typed enums, event/input types and bounded validation.
- [x] Reject ambiguous JSON and recorder-owned fields in client input.
- [x] Implement canonical encoder with explicit absence and sorted attributes.
- [x] Freeze independent Go/Python-checked golden vectors.
- [x] Implement domain-separated SHA-256 chain calculation.
- [x] Test boundaries, all field sensitivity, enum coverage and invalid inputs.
- [x] Run gofmt, unit tests, race detector, vet and Python unittest checks.
- [x] Record actual results, limitations, commit sequence and next task.

## Remaining recorder acceptance tests (future)

### Milestone 1 storage slice — complete

- [x] Implement strict read-only verification for open logs and referenced blobs.
- [x] Classify incomplete, complete-without-newline, and corrupt final records.
- [x] Implement explicit recovery without discarding complete invalid records.
- [x] Publish content-addressed payloads with file and directory synchronization.
- [x] Serialize per-run appends and assign authoritative recorder fields.
- [x] Return identical event-ID retries and reject conflicting retries.
- [x] Build and atomically replace a fully derived index.
- [x] Reopen runs and rebuild a deleted or invalid index from authoritative state.
- [x] Test concurrent ordering, parent rules, mutation, deletion, and reordering.
- [x] Test missing/replaced blobs, partial writes, sync failure, and lost response.
- [x] Run formatting, all tests, race detection, vet, and Python vector checks.
- [x] Update storage/recovery docs and project-state with executed evidence.

### Milestone 2A signed sealing — complete

- [x] Freeze canonical manifest and blob-set bytes with Go/Python vectors.
- [x] Implement strict manifest types, validation, JSON, signing, and verification.
- [x] Generate and durably store a private recorder key pair with restrictive modes.
- [x] Seal empty and populated runs atomically under the per-run append lock.
- [x] Make equal seal retries idempotent and conflicting retries fail closed.
- [x] Verify sealed content against a caller-supplied expected public key.
- [x] Detect event, terminal-suffix, blob, manifest, signature, and wrong-key changes.
- [x] Reject append and recovery after a manifest is published.
- [x] Inject ambiguous manifest publication and lost-response failures.
- [x] Run formatting, tests, race detection, vet, and both vector checkers.
- [x] Update architecture, threat model, limitations, and project state.

### Remaining Milestone 2 work

- [ ] Authenticate non-health routes; enforce body/header/time limits.
- [ ] End-to-end deterministic invoice trace with causal edges, mock labels.
