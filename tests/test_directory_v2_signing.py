"""Cryptographic separation of the experimental scoped Directory protocol."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from directory_publication import PublicationError, ed25519_public_bytes, ed25519_verify, signature_message
from directory_v2_contract import legacy_user_v2_distribution
from directory_v2_signing import sign_v2_snapshot, verify_v2_snapshot


class DirectoryV2SigningTests(unittest.TestCase):
    def snapshot(self):
        source = json.loads((ROOT / "tests/fixtures/directory-publication/snapshot.json").read_text())
        source["snapshot_schema_version"] = 2
        source["sequence"] = 1
        source["distributions"] = [
            legacy_user_v2_distribution(item, "0.1.96") for item in source["distributions"]
        ]
        return source

    def test_v2_bytes_roundtrip_and_strict_domain_isolation(self):
        seed = bytes(range(32))
        public = ed25519_public_bytes(seed)
        signed, envelope = sign_v2_snapshot(self.snapshot(), "test-current", seed)
        result = verify_v2_snapshot(signed, envelope, {"test-current": public})
        self.assertEqual(result["sequence"], 1)
        self.assertTrue(all(g["scope"] == "user"
                            for item in result["distributions"]
                            for policy in item["release_policies"]
                            for g in policy["targets"]))
        signature = json.loads(envelope)["signature"]
        import base64
        with self.assertRaises(PublicationError):
            ed25519_verify(public, signature_message(signed), base64.b64decode(signature))
        with self.assertRaises(PublicationError):
            verify_v2_snapshot(signed, envelope, {"other-key": public})
        with self.assertRaises(PublicationError):
            verify_v2_snapshot(signed + b" ", envelope, {"test-current": public})

        damaged = json.loads(envelope)
        damaged["signature_domain"] = "UAP-DIRECTORY-SNAPSHOT-ED25519-V1"
        with self.assertRaises(PublicationError):
            verify_v2_snapshot(signed, json.dumps(damaged).encode(), {"test-current": public})

    def test_v2_rejects_wrong_scope_without_signing(self):
        changed = self.snapshot()
        changed["distributions"][0]["release_policies"][0]["targets"][0]["scope"] = "workspace"
        with self.assertRaises(PublicationError):
            sign_v2_snapshot(changed, "test-current", bytes(range(32)))


if __name__ == "__main__":
    unittest.main()
