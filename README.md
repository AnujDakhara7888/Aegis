# Aegis

Cross-layer record and replay for untrusted AI agents.

An agent incident can span a retrieved document, a model decision, a tool request,
and an operating-system operation. Aegis aims to connect that causal history to
capability enforcement and safe replay. The eventual local invoice demonstration
will use deterministic mock models and simulated payments, without paid APIs.

**Current stage:** Milestone 1 recorder core. This is a tested local storage
library, not an operational service or a security boundary yet. See
[project state](docs/project-state.md) for executed checks and
[tasks](docs/tasks.md) for acceptance criteria.

The current slice defines validated events, a byte-level canonical encoding,
permanent cross-language vectors, SHA-256 chaining, an append-only JSONL store,
content-addressed payloads, full open-run verification, crash-tail recovery,
idempotent retries, and a rebuildable derived index. Signing, HTTP, CLI, SDK,
replay, kernel enforcement, and the UI are future milestones. There is no runnable
invoice demo yet and no performance claim.

## Architecture

Data flow: untrusted agent → trusted recorder/proxy → event log and payload
blobs; AgentOS → privileged audit reader → host adapter → recorder. Causal parent
IDs connect decisions; per-run sequences establish physical order.
See [architecture](docs/architecture.md) and [roadmap](docs/roadmap.md).

## Local verification

Requires Go 1.26 or newer and Python 3.10 or newer; no third-party dependencies.
From the repository root:

```sh
make check
# Individual checks:
go test ./...
go test -race ./...
go vet ./...
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

If the default Go build cache is restricted, prefix `make check` with
`GOCACHE=/tmp/aegis-go-build-cache`.

Python is used only for an independent format-vector check in this slice, not an
SDK. No network services or credentials are needed.

## Security model

The future sealed history will be **tamper-evident relative to the recorder’s
signing key**. A hash chain alone can be rewritten and recomputed; it does not
authenticate history or detect suffix removal without a trusted terminal anchor.
Signing is not implemented. Open-run verification cannot detect deletion of a
valid terminal suffix without a trusted terminal count/hash. Neither signatures nor recording establish that the
recorder was honest or that it captured every action.

The recorder, host, signing key, and eventual trusted proxy/kernel are trusted.
Agent content and tool arguments are untrusted. Compromised hosts, key theft,
and actions outside instrumented boundaries are out of scope. Read the
[threat model](docs/threat-model.md) and [limitations](docs/limitations.md).

This checkout is the runtime repository, using neutral module path
`aegis.local/runtime`. SBUnix work requires the actual source repository first.
The initial license is [MIT](LICENSE), subject to review before publication.
