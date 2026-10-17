"""Independent stdlib format oracle, not an agent SDK or fixture generator.

Run: python3 -m unittest discover -s scripts -p 'test_*.py' -v
Expected bytes/hashes are read-only, permanent fixtures. Changes require a new
schema version and ADR. This encoder consumes valid fixtures, not untrusted input.
"""
import hashlib
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENUMS = {
    "source": "AGENT RECORDER MODEL TOOL PROXY KERNEL AUDIT_READER".split(),
    "kind": "RUN_STARTED RUN_COMPLETED RUN_FAILED DOCUMENT_RETRIEVED MODEL_REQUESTED MODEL_RESPONDED TOOL_REQUESTED TOOL_COMPLETED TOOL_FAILED NETWORK_REQUESTED NETWORK_COMPLETED APPROVAL_REQUESTED APPROVAL_GRANTED APPROVAL_REJECTED POLICY_ALLOWED POLICY_DENIED CAPABILITY_ALLOWED CAPABILITY_DENIED SIDE_EFFECT_PREPARED SIDE_EFFECT_COMMITTED CHECKPOINT_CREATED BUDGET_UPDATED BUDGET_EXCEEDED RUNTIME_FAILED KERNEL_EVENT_OBSERVED".split(),
    "phase": "INSTANT REQUEST RESPONSE START END".split(),
    "policy_decision": "NONE ALLOW DENY REQUIRE_APPROVAL".split(),
    "side_effect_class": "NONE PURE READ REVERSIBLE_WRITE IRREVERSIBLE_WRITE NONDETERMINISTIC HUMAN_APPROVAL".split(),
    "replay_behavior": "UNSPECIFIED REEXECUTE RECORDED_RESULT SIMULATE NEVER REQUIRE_APPROVAL".split(),
}


def string(value):
    data = value.encode("utf-8", errors="strict")
    return struct.pack(">I", len(data)) + data


def optional(record, name, encode):
    return b"\x01" + encode(record[name]) if name in record else b"\x00"


def encode(record):
    e = record
    parts = [b"AEGIS-EVENT-V1", struct.pack(">H", e["schema_version"]),
             string(e["run_id"]), string(e["event_id"]),
             optional(e, "parent_event_id", string), struct.pack(">Qq", e["sequence"], e["observed_at_unix_nano"]),
             optional(e, "source_instance_id", string),
             optional(e, "source_monotonic_nano", lambda n: struct.pack(">q", n))]
    for name in ("source", "kind", "phase"):
        parts.append(struct.pack(">H", ENUMS[name].index(e[name]) + 1))
    for name in ("input_hash", "output_hash", "payload_hash"):
        parts.append(optional(e, name, bytes.fromhex))
    parts += [struct.pack(">Q", e["payload_size"]), optional(e, "capability_id", string)]
    for name in ("policy_decision", "side_effect_class", "replay_behavior"):
        parts.append(struct.pack(">H", ENUMS[name].index(e[name]) + 1))
    parts += [optional(e, "idempotency_key", string), struct.pack(">I", len(e["attributes"]))]
    for key in sorted(e["attributes"], key=lambda key: key.encode("utf-8")):
        parts += [string(key), string(e["attributes"][key])]
    return b"".join(parts)


class CanonicalVectors(unittest.TestCase):
    def test_permanent_vectors(self):
        files = sorted((ROOT / "testdata/canonical").glob("*.json"))
        self.assertEqual(len(files), 4)
        for path in files:
            with self.subTest(vector=path.name):
                fixture = json.loads(path.read_text(encoding="utf-8"))
                e = fixture["event"]
                actual = encode(e)
                self.assertEqual(actual.hex(), fixture["canonical_hex"])
                previous = bytes.fromhex(fixture["previous_hash"])
                self.assertEqual(len(previous), 32)
                self.assertEqual(e["previous_event_hash"], fixture["previous_hash"])
                digest = hashlib.sha256(b"AEGIS-CHAIN-V1" + previous + actual).hexdigest()
                self.assertEqual(digest, fixture["event_hash"])
                self.assertEqual(digest, e["event_hash"])

    def test_fixture_chain_link(self):
        first = json.loads((ROOT / "testdata/canonical/01-minimal.json").read_text())
        second = json.loads((ROOT / "testdata/canonical/02-linked-rich.json").read_text())
        self.assertEqual(first["event_hash"], second["previous_hash"])
        self.assertEqual(first["event"]["run_id"], second["event"]["run_id"])
        self.assertEqual(second["event"]["parent_event_id"], first["event"]["event_id"])
        self.assertEqual(second["event"]["sequence"], first["event"]["sequence"] + 1)


if __name__ == "__main__":
    unittest.main()
