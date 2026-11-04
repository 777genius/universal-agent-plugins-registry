"""Real offline Ed25519 v1/v2 isolation and bootstrap-signature refusals."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from directory_publication import PublicationError, ed25519_private_key, load_public_keys
from directory_v2_contract import legacy_user_v2_distribution
from directory_v2_signing import sign_snapshot_v2, verify_snapshot_v2

FIXTURES = ROOT / "tests" / "fixtures" / "directory-publication"


class V2SignedBundleTests(unittest.TestCase):
    def setUp(self):
        original = json.loads((FIXTURES / "snapshot.json").read_text())
        original["snapshot_schema_version"] = 2
        original["sequence"] = 1
        original["distributions"] = [
            legacy_user_v2_distribution(value, "0.1.96")
            for value in original["distributions"]
        ]
        self.snapshot = original
        seed = json.loads((FIXTURES / "test-private-seeds.json").read_text())
        self.private = ed25519_private_key(seed["test-current"])
        self.keys = load_public_keys(FIXTURES / "trusted-keys.json")

    def signed(self):
        return sign_snapshot_v2(self.snapshot, "test-current", self.private)

    def test_real_ed25519_roundtrip_and_tampering(self):
        body, envelope = self.signed()
        verified = verify_snapshot_v2(body, envelope, self.keys)
        self.assertEqual(verified, self.snapshot)
        with self.assertRaisesRegex(PublicationError, "digest mismatch"):
            verify_snapshot_v2(body.replace(b'"Demo"', b'"Demu"', 1), envelope, self.keys)
        corrupted = json.loads(envelope)
        corrupted["sequence"] = 2
        with self.assertRaisesRegex(PublicationError, "sequence mismatch"):
            verify_snapshot_v2(body, json.dumps(corrupted, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n", self.keys)
        with self.assertRaisesRegex(PublicationError, "unknown"):
            verify_snapshot_v2(body, envelope, {"not-current": self.keys["test-current"]})

    def test_v1_signature_domain_cannot_validate_v2_snapshot(self):
        body, envelope = self.signed()
        changed = json.loads(envelope)
        changed["signature_domain"] = "UAP-DIRECTORY-SNAPSHOT-ED25519-V1"
        with self.assertRaises(PublicationError):
            verify_snapshot_v2(body, json.dumps(changed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n", self.keys)
        changed = json.loads(envelope)
        changed["signature"] = "A" * 86 + "=="
        with self.assertRaisesRegex(PublicationError, "invalid v2 Ed25519 signature"):
            verify_snapshot_v2(body, json.dumps(changed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n", self.keys)

    def test_v2_signed_snapshot_refuses_cross_product_identity_theft(self):
        second = copy.deepcopy(self.snapshot)
        original = second["products"][0]
        victim = copy.deepcopy(original)
        victim["id"], victim["manifest_name"] = "other", "other"
        victim["aliases"], victim["reserved_aliases"] = ["other"], ["other"]
        # The duplicate distribution reference is structurally valid but must
        # never authorize another product to claim its signed source.
        second["products"].append(victim)
        with self.assertRaisesRegex(PublicationError, "foreign distribution"):
            sign_snapshot_v2(second, "test-current", self.private)

        victim["distributions"] = ["owner/other"]
        victim["default_distribution"] = "owner/other"
        foreign = copy.deepcopy(second["distributions"][0])
        foreign["id"], foreign["product_id"] = "owner/other", "other"
        second["distributions"].append(foreign)
        victim["aliases"] = [original["aliases"][0]]
        with self.assertRaisesRegex(PublicationError, "v2 selector"):
            sign_snapshot_v2(second, "test-current", self.private)

    def test_v2_default_distribution_must_belong_to_selected_product(self):
        candidate = copy.deepcopy(self.snapshot)
        # A syntactically valid selector outside the owner's distribution set
        # must not be signed as an installable default.
        candidate["products"][0]["default_distribution"] = "foreign/distribution"
        with self.assertRaisesRegex(PublicationError, "v2 default distribution"):
            sign_snapshot_v2(candidate, "test-current", self.private)

    def test_project_runtime_proof_must_match_exact_canonical_closure(self):
        candidate = copy.deepcopy(self.snapshot)
        policy = candidate["distributions"][0]["release_policies"][0]
        grant = policy["targets"][0]
        grant["scope"] = "project"
        digest = "sha256:" + "a" * 64
        grant["canonical_closure"] = {
            "eligible": True,
            "closure_digest": digest,
            "minimum_installer_version": grant["minimum_installer_version"],
        }
        runtime = copy.deepcopy(candidate["evidence"][0])
        runtime["id"] = "project-runtime-exact"
        runtime["client"] = grant["client"]
        runtime["scope"] = "project"
        runtime["closure_digest"] = digest
        runtime["outcome"] = "passed"
        runtime["level"] = "runtime"
        candidate["evidence"].append(runtime)
        grant["current_evidence"] = [runtime["id"]]
        sign_snapshot_v2(candidate, "test-current", self.private)
        runtime["closure_digest"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(PublicationError, "qualified scoped runtime evidence"):
            sign_snapshot_v2(candidate, "test-current", self.private)

    def test_v2_expiry_contract_matches_go_reader_thirty_days(self):
        modified = copy.deepcopy(self.snapshot)
        from datetime import datetime, timedelta, timezone
        generated = datetime.fromisoformat(modified["generated_at"].replace("Z", "+00:00"))
        modified["expires_at"] = (generated + timedelta(days=31)).astimezone(
            timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(PublicationError, "snapshot lifetime"):
            sign_snapshot_v2(modified, "test-current", self.private)
        modified["expires_at"] = (generated + timedelta(days=30)).astimezone(
            timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sign_snapshot_v2(modified, "test-current", self.private)

    def test_v2_project_grant_cannot_borrow_user_runtime_proof(self):
        modified = copy.deepcopy(self.snapshot)
        grant = modified["distributions"][0]["release_policies"][0]["targets"][0]
        grant["scope"] = "project"
        with self.assertRaisesRegex(PublicationError, "qualified scoped runtime evidence"):
            sign_snapshot_v2(modified, "test-current", self.private)

    def test_cross_release_evidence_and_unqualified_scope_refused(self):
        modified = copy.deepcopy(self.snapshot)
        modified["distributions"][0]["release_policies"][0]["targets"][0]["minimum_installer_version"] = "0.1.0"
        with self.assertRaisesRegex(PublicationError, "lowered release installer floor"):
            sign_snapshot_v2(modified, "test-current", self.private)
        modified = copy.deepcopy(self.snapshot)
        modified["distributions"][0]["release_policies"][0]["targets"][0]["scope"] = "project"
        modified["distributions"][0]["release_policies"][0]["targets"][0]["client"] = "chatgpt"
        with self.assertRaises(PublicationError):
            sign_snapshot_v2(modified, "test-current", self.private)
        modified = copy.deepcopy(self.snapshot)
        modified["distributions"][0]["release_policies"][0]["targets"][0]["current_evidence"] = ["missing-id"]
        with self.assertRaisesRegex(PublicationError, "missing evidence"):
            sign_snapshot_v2(modified, "test-current", self.private)


if __name__ == "__main__":
    unittest.main()
