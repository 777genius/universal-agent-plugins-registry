"""Signed old-feed admission gates for first user-only v2 preview."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from directory_publication import PublicationError, load_public_keys
from directory_v2_bootstrap import prepare_v2_user_bootstrap
from directory_v2_signing import sign_snapshot_v2, verify_snapshot_v2

FIXTURES = ROOT / "tests/fixtures/directory-publication"


class SignedV2BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.original = (FIXTURES / "snapshot.json").read_bytes()
        self.envelope = (FIXTURES / "envelope-current.json").read_bytes()
        self.keys = load_public_keys(FIXTURES / "trusted-keys.json")
        self.now = datetime(2026, 8, 21, tzinfo=timezone.utc)

    def candidate(self, **options):
        return prepare_v2_user_bootstrap(
            self.original, self.envelope, self.keys,
            at=options.pop("at", self.now),
            installer_version=options.pop("installer_version", "0.1.96"),
            publication_id="preview-v2-1",
            source_commit="a" * 40,
            **options,
        )

    def test_v1_signature_checked_before_user_only_projection(self):
        preview = self.candidate()
        source = json.loads(self.original)
        self.assertEqual(preview["snapshot_schema_version"], 2)
        self.assertEqual(preview["sequence"], 1)
        self.assertEqual(source["snapshot_schema_version"], 1)
        self.assertEqual(preview["products"], source["products"])
        self.assertEqual(preview["evidence"], source["evidence"])
        self.assertEqual(preview["revocations"], source["revocations"])
        for d in preview["distributions"]:
            for policy in d["release_policies"]:
                self.assertTrue(all(g["scope"] == "user" for g in policy["targets"]))
                self.assertTrue(all(tuple(map(int, g["minimum_installer_version"].split("."))) >= (0, 1, 96)
                                    for g in policy["targets"]))
        self.assertEqual(self.candidate(), preview)

    def test_cannot_project_changed_unsigned_or_stale_source(self):
        damaged = self.original.replace(b'"Demo"', b'"Demu"', 1)
        with self.assertRaises(PublicationError):
            prepare_v2_user_bootstrap(damaged, self.envelope, self.keys,
                                      at=self.now, installer_version="0.1.96",
                                      publication_id="preview-v2-1", source_commit="a" * 40)
        with self.assertRaisesRegex(PublicationError, "expired"):
            self.candidate(at=self.now + timedelta(days=90))
        with self.assertRaises(PublicationError):
            self.candidate(installer_version="0.1.x")
        with self.assertRaises(PublicationError):
            prepare_v2_user_bootstrap(self.original, self.envelope, {"other": bytes(32)},
                                      at=self.now, installer_version="0.1.96",
                                      publication_id="preview-v2-1", source_commit="a" * 40)


if __name__ == "__main__":
    unittest.main()
