# Event schema v1

Schema version is 1. JSON field names use snake_case. Required enum values use the
uppercase names below, never JSON numbers. Each enum is a u16 in canonical bytes;
zero and values absent from its table are invalid. Existing numbers never move.

| Enum | Numeric assignments |
|---|---|
| source | 1 AGENT, 2 RECORDER, 3 MODEL, 4 TOOL, 5 PROXY, 6 KERNEL, 7 AUDIT_READER |
| phase | 1 INSTANT, 2 REQUEST, 3 RESPONSE, 4 START, 5 END |
| policy_decision | 1 NONE, 2 ALLOW, 3 DENY, 4 REQUIRE_APPROVAL |
| side_effect_class | 1 NONE, 2 PURE, 3 READ, 4 REVERSIBLE_WRITE, 5 IRREVERSIBLE_WRITE, 6 NONDETERMINISTIC, 7 HUMAN_APPROVAL |
| replay_behavior | 1 UNSPECIFIED, 2 REEXECUTE, 3 RECORDED_RESULT, 4 SIMULATE, 5 NEVER, 6 REQUIRE_APPROVAL |

Kind assignments:

```text
 1 RUN_STARTED           2 RUN_COMPLETED          3 RUN_FAILED
 4 DOCUMENT_RETRIEVED    5 MODEL_REQUESTED        6 MODEL_RESPONDED
 7 TOOL_REQUESTED        8 TOOL_COMPLETED         9 TOOL_FAILED
10 NETWORK_REQUESTED   11 NETWORK_COMPLETED     12 APPROVAL_REQUESTED
13 APPROVAL_GRANTED    14 APPROVAL_REJECTED      15 POLICY_ALLOWED
16 POLICY_DENIED       17 CAPABILITY_ALLOWED    18 CAPABILITY_DENIED
19 SIDE_EFFECT_PREPARED 20 SIDE_EFFECT_COMMITTED 21 CHECKPOINT_CREATED
22 BUDGET_UPDATED      23 BUDGET_EXCEEDED        24 RUNTIME_FAILED
25 KERNEL_EVENT_OBSERVED
```

EventInput has required event_id, source, kind, phase, policy_decision,
side_effect_class, replay_behavior, attributes; optional parent_event_id,
source_instance_id, source_monotonic_nano, input_hash, output_hash, capability_id,
idempotency_key, payload. Payload JSON is base64 bytes. Absence and an empty
payload are distinct. Clients cannot submit run/sequence/time/schema/chain fields.

Accepted Event replaces raw payload with optional payload_hash and required
payload_size, and adds required schema_version, run_id, sequence,
observed_at_unix_nano, previous_event_hash, event_hash. Digests are lowercase
64-character hex in JSON. Optional fields are omitted, not null. Attributes are a
required JSON object of string values; the programmatic nil map means empty.
The server assigns observed time, schema, run, sequence, hashes and payload reference.

Limits (bytes, not Unicode code points):

| Value | Limit |
|---|---|
| run/event/parent IDs | 1–128, ASCII `[A-Za-z0-9][A-Za-z0-9_-]*` |
| source_instance_id, capability_id, idempotency_key | 1–256 UTF-8 bytes when present |
| attribute count | 32 |
| attribute key | 1–64 UTF-8 bytes |
| attribute value | 0–4096 UTF-8 bytes |
| total attribute key + value bytes | 65536 |
| raw payload | 1048576 bytes (1 MiB) |
| EventInput JSON | 2097152 bytes (2 MiB) |
| accepted Event JSON | 524288 bytes (512 KiB) |

Sequence starts at 1. observed_at_unix_nano accepts signed i64, including pre-epoch
and negative values; it provides no ordering guarantee. Source monotonic time is
nonnegative and requires source_instance_id. Self-parent references are invalid;
parent existence and run ordering require store context and are deferred.
Absent payload_hash requires payload_size zero; present hashes allow empty blobs
but size must be <= 1 MiB. Input/output digests identify logical inputs/outputs;
only payload_hash references the blob store in v1.

Strict decoding rejects unknown fields, duplicate JSON keys (including escaped
aliases), malformed UTF-8, lone escaped UTF-16 surrogates, nulls, missing required
fields, wrong types, out-of-range integers, unknown enums, and trailing JSON.
Extension data belongs only in attributes. No hidden normalization or defaults.
Numeric spelling is storage syntax, not hashed text. Use strict DecodeEvent and
DecodeInput for untrusted data, not a bare json.Unmarshal into structs.

Validation is structural. It does not enforce policy, authenticate source labels,
verify digest content, or infer permission from a kind/phase/replay label. Stronger
cross-event semantics belong to later store/proxy milestones.
