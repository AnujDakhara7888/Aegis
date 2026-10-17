"""Independent standard-library checker for permanent manifest v1 fixtures."""

import base64
import hashlib
import json
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPLETION = {"COMPLETED": 1, "FAILED": 2, "ABORTED": 3}
ALGORITHM = {"ED25519": 1}


def text(value):
    encoded = value.encode("utf-8", errors="strict")
    return struct.pack(">I", len(encoded)) + encoded


def canonical(manifest):
    return b"".join(
        [
            b"AEGIS-MANIFEST-V1",
            struct.pack(">H", manifest["manifest_schema_version"]),
            text(manifest["run_id"]),
            struct.pack(">H", manifest["event_schema_version"]),
            struct.pack(">Q", manifest["event_count"]),
            bytes.fromhex(manifest["first_event_hash"]),
            bytes.fromhex(manifest["terminal_event_hash"]),
            bytes.fromhex(manifest["referenced_blob_set_digest"]),
            struct.pack(">H", COMPLETION[manifest["completion_status"]]),
            struct.pack(">q", manifest["sealed_at_unix_nano"]),
            bytes.fromhex(manifest["recorder_public_key_fingerprint"]),
            struct.pack(">H", ALGORITHM[manifest["signature_algorithm"]]),
        ]
    )


def blob_set_digest(references):
    unique = sorted({bytes.fromhex(value) for value in references})
    content = b"AEGIS-BLOBS-V1" + struct.pack(">I", len(unique)) + b"".join(unique)
    return hashlib.sha256(content).hexdigest()


class ManifestVectors(unittest.TestCase):
    def test_permanent_vectors(self):
        files = sorted((ROOT / "testdata/manifest").glob("*.json"))
        self.assertEqual(len(files), 3)
        for path in files:
            with self.subTest(vector=path.name):
                fixture = json.loads(path.read_text(encoding="utf-8"))
                manifest = fixture["manifest"]
                self.assertEqual(canonical(manifest).hex(), fixture["canonical_hex"])
                digest = blob_set_digest(fixture["referenced_blob_hashes"])
                self.assertEqual(digest, fixture["blob_set_digest"])
                self.assertEqual(digest, manifest["referenced_blob_set_digest"])
                public_key = bytes.fromhex(fixture["public_key_hex"])
                self.assertEqual(len(public_key), 32)
                self.assertEqual(
                    hashlib.sha256(public_key).hexdigest(),
                    manifest["recorder_public_key_fingerprint"],
                )
                self.assertEqual(len(base64.b64decode(manifest["signature"], validate=True)), 64)


if __name__ == "__main__":
    unittest.main()
