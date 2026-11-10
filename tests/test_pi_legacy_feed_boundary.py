"""Fail-closed legacy-feed invariants while Pi qualifies for a separate signed v1 feed.

These are guardrails for the existing shared Directory source, not proof that a
modern-client feed, Pi installation, or publication has been approved.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PiLegacyFeedBoundaryTests(unittest.TestCase):
    def assert_shared_feed_is_pi_free(self, source: dict) -> None:
        # A strict legacy reader parses the whole signed snapshot, including
        # revoked/superseded policies and active policies in suspended distributions.
        # Filtering by policy status would miss a snapshot-wide breakage.
        policies = [
            (distribution["id"], policy)
            for distribution in source["distributions"]
            for policy in distribution["release_policies"]
        ]
        self.assertTrue(policies, "empty shared Directory would make this check vacuous")
        for distribution_id, policy in policies:
            with self.subTest(distribution=distribution_id, release=policy["release_sequence"]):
                self.assertNotIn(
                    "pi", [target["client"] for target in policy["targets"]],
                    "publishing Pi into the shared 0.1.89 feed requires an explicit "
                    "old-reader compatibility/cutoff decision; use an isolated "
                    "modern-client v1 feed instead",
                )

    def test_existing_shared_directory_does_not_publish_pi(self) -> None:
        source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
        self.assert_shared_feed_is_pi_free(source)

    def test_guard_rejects_pi_in_nonactive_policy(self) -> None:
        # Revoked and superseded policy targets are still serialized into v1.
        # Test that neither can silently bypass the legacy-feed boundary.
        for status in ("revoked", "superseded"):
            with self.subTest(status=status):
                source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
                policy = next(
                    policy for distribution in source["distributions"]
                    for policy in distribution["release_policies"]
                    if policy["status"] == status
                )
                policy["targets"].append({"client": "pi"})
                with self.assertRaisesRegex(AssertionError, "publishing Pi"):
                    self.assert_shared_feed_is_pi_free(source)

    def test_v1_wire_scope_is_user_only_even_for_modern_pi(self) -> None:
        # The released v1 reader rejects explicit project scopes. New CLI
        # project placement instead verifies the signed user source grant,
        # then separately admits native project capabilities. Do not change
        # the v1 wire contract to claim a project grant.
        schema = json.loads(
            (ROOT / "schemas" / "directory-distribution.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["$defs"]["target"]["properties"]["scopes"],
            {"const": ["user"]},
        )


if __name__ == "__main__":
    unittest.main()
