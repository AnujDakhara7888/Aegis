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
- [ ] Preserve event order on append/reopen; serialize concurrent appends.
- [ ] Verify a clean chain and detect modification/deletion/reordering.
- [ ] Verify blob sizes/digests; detect replacement and missing blobs.
- [ ] Recover only incomplete final tails; reject complete invalid records.
- [ ] Delete/rebuild index with no information loss.
- [ ] Equal retries return original event; conflicting IDs fail.
- [ ] Inject write/sync/ack failures; no acknowledged event may go missing.
- [ ] Seal freezes appends; changed manifests and wrong expected keys fail.
- [ ] Authenticate non-health routes; enforce body/header/time limits.
- [ ] End-to-end deterministic invoice trace with causal edges, mock labels.
