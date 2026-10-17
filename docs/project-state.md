# Project state

Updated: 2026-10-17 (America/New_York).
Current milestone: Milestone 0 and the assigned first part of Milestone 1 complete.
The rest of Milestone 1 is not implemented. No changes have been committed or pushed.

## Workspace and constraints

Initial checkout: existing Git repository with .gitattributes and an initial commit;
no application code or applicable AGENTS.md. Current root is the runtime repository,
not a nested aegis-runtime directory. Neutral module: aegis.local/runtime.
Local tools: Go 1.26.2 darwin/arm64 and Python 3.14.5. Standard libraries only.
No remote/global Git configuration was changed. No kernel repository was created.

The default Go build cache under ~/Library/Caches was denied by the filesystem
sandbox during package tests. All final Go checks passed using
`GOCACHE=/tmp/aegis-go-build-cache`; no permission escalation was needed.

## Completed work

- Project scaffold, reserved-directory descriptions, MIT license, ignore rules,
  Makefile and an initial README with explicit scope and limitations.
- Architecture, threat model, event/canonical/storage/crash/signature contracts,
  kernel investigation plan, limitations, roadmap, granular checklist and 3 ADRs.
- EventInput/accepted Event distinction, stable numeric enums with readable JSON,
  bounded structural validation, strict decoding and explicit optional values.
- Rejection of duplicate fields/attribute keys, case aliases, unknown fields,
  malformed UTF-8/surrogates, nulls, missing fields and recorder-field spoofing.
- Canonical big-endian v1 encoder; sorted UTF-8 attributes; domain-separated
  SHA-256 chain calculation; no raw-JSON hashing or hidden normalization.
- Four permanent vectors checked independently in Go and Python, including a
  linked pair, optional presence, signed boundaries and Unicode ordering.
- Unit tests for every logical field's hash sensitivity, validation boundaries,
  JSON presentation independence, enum assignments and immutable concurrent reads.

## Checks actually executed

| Command | Result |
|---|---|
| `gofmt -w internal/event` | Completed after event section |
| `go test ./internal/event` | Passed after event section |
| `gofmt -w internal/canonical internal/hashchain` | Completed after encoder/chain section |
| `GOCACHE=/tmp/aegis-go-build-cache go test ./internal/canonical ./internal/hashchain` | Both packages passed |
| `GOCACHE=/tmp/aegis-go-build-cache make check` | Passed formatting check, all tests, race detector, vet and Python checks |
| `go test ./...` (inside make, with cache above) | All 3 implemented packages passed |
| `go test -race ./...` (same environment) | All 3 packages passed |
| `go vet ./...` (same environment) | Passed; no diagnostics |
| `python3 -m unittest discover -s scripts -p 'test_*.py' -v` | 2 tests passed; 4 fixtures plus linked-pair check |
| `GOCACHE=/tmp/aegis-go-build-cache go test ./internal/event -run '^$' -fuzz '^FuzzDecodeEvent$' -fuzztime=5s -parallel=2` | Passed; 119740 executions, no failure |
| `GOCACHE=/tmp/aegis-go-build-cache go test ./internal/canonical -run '^$' -fuzz '^FuzzCanonicalJSONRoundTrip$' -fuzztime=5s -parallel=2` | Passed; 229950 executions, no failure |
| `git check-ignore .aegis/keys/recorder.key .aegis/runs/sample/events.jsonl recorder.token nested/recorder.key bin/aegisctl` | All sample secret/state/build paths ignored |
| `go list -m` | aegis.local/runtime |

Documentation links/domain lengths were checked with Python assertions. An early
inspection assertion expected 16 documents rather than the actual 15; the assertion
was corrected. No code test failures or fuzz counterexamples remain. Fuzzing is
bounded evidence, not a proof of parser correctness or a performance benchmark.
Final inspection passed for local Markdown links, whitespace and terminal newlines
across 45 source/document/fixture files, domain lengths, and the fully checked
current-assignment task list. `git diff --check` also passed.

## Known limitations and open questions

No append/blob store, log verifier, derived index, recovery, HTTP service, CLI,
Python SDK, manifest signer, demo, replay, enforcement, UI, or benchmarks yet.
Reserved directories are labeled documentation only. Hash functions do not validate
whole-run order, causal parent existence, payload content or authenticity. A chain
can be rewritten without a separately trusted signed anchor. Callers must not
mutate events during encoding. See limitations.md and threat-model.md.

Unresolved: final GitHub namespace; final license approval before publication;
actual SBUnix source and supported audit bridge; tested filesystem durability
assumptions; future key distribution/rotation; independent manifest vectors before
Milestone 2. Future manifest layout is documented but not implemented or frozen by
vectors. None of these blocks the completed current assignment.

## Recommended commit sequence

1. `docs: define Aegis architecture and threat model` — scaffold, module, README,
   license, ignore rules, architecture/security/planning docs, ADRs 0001/0003.
2. `docs: specify canonical event and storage formats` — event/canonical/storage/
   recovery/signature contracts and ADR 0002.
3. `feat: define validated events and strict JSON boundaries` — internal/event.
4. `feat: add canonical event encoder and permanent golden vectors` —
   internal/canonical, fixtures and independent Python checker.
5. `feat: add domain-separated SHA-256 event chain calculation` — internal/hashchain,
   including golden chain tests; final Makefile/checklist/state ledger.

Stage each boundary deliberately; the final ledger describes the complete slice.
No Git history has been rewritten. Publishing requires a separate request/review.

## Reproduction

From the repository root:

```sh
export GOCACHE=/tmp/aegis-go-build-cache
make check
```

A writable default Go cache is sufficient outside this sandbox. This command does
not start a service, create keys, run a model or contact a financial service.

## Exact next task / next-session prompt

Continue Aegis with the remainder of Milestone 1 only. Read docs/project-state.md,
docs/tasks.md, the existing ADRs and the event, canonical, storage and crash-recovery
specifications before editing. Preserve the frozen v1 vectors. Implement a
single-recorder, per-run serialized append-only JSONL store, content-addressed
payload storage, idempotent event acceptance, a disposable rebuildable index,
full open-run chain/payload verification, and recovery that truncates only a
parser-confirmed incomplete final fragment. Specify filesystem synchronization and
ambiguous-I/O behavior before implementation. Add tests for concurrent append,
identical/conflicting retries, modification/deletion/reordering, payload replacement,
index deletion/rebuild, complete corruption, interrupted writes and lost
acknowledgements. Do not implement HTTP, CLI, SDK, signing, replay, kernel changes,
UI or publication yet. Show the incremental checklist, work in tested sections,
run go test ./..., go test -race ./..., go vet ./... and existing Python vector
checks, then update project-state.md with actual results and commit boundaries.
