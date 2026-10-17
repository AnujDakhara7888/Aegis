# Roadmap

| Milestone | Deliverable and acceptance gate |
|---|---|
| 0 Project contract — complete | Scaffold, explicit invariants, byte specifications, threat model, ADRs and task list |
| 1 Recorder core — complete | Validated events, canonical vectors, hash chain, durable log/blob store, rebuildable index, recovery, verifier and fault tests |
| 2 Local service/demo — sealing complete | Ed25519 seal complete; remaining: loopback authenticated HTTP, CLI, Python SDK, deterministic invoice agent and end-to-end one-command demo |
| 3 Thin AgentOS | Inspect supplied SBUnix source, implement minimal filesystem denial, audit bridge and causal cross-layer demo |
| 4 Replay/forking | Side-effect journal, recorded results, checkpoints/resume, lineage, substitutions, first divergence and fault injection |
| 5 Broader authority | Delegation/attenuation/revocation, CPU/memory budgets, proxy, token/tool/payment budgets and scoped approvals |
| 6 Inspection UI | React/TypeScript timeline, causal edges, comparisons and verification status |
| 7 Evaluation/publication | Adversarial suite, reproducible measurements, docs/video, review license/history/secrets/claims, tagged release |

Do not delay the kernel feasibility spike until all replay features exist.
No kernel work without actual source. No publishing/pushing until separately
requested. Initial components use standard libraries and local simulated services.

Future replay defaults: pure operations may reexecute; reads and model calls use
recorded results; reversible writes simulate; irreversible writes never repeat
automatically. Approvals are branch-scoped. A live writing fork requires explicit
intent, fresh idempotency key, valid capability, required approval and new lineage.
