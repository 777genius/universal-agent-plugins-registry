"""The reviewed Directory source stays Pi-free: Pi targets are derived.

Publication adds Pi from the pinned client capabilities
(`build_registry.with_derived_client_targets`). An authored Pi target would skip
that derivation and its installer floor, so the source never carries one.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PiLegacyFeedBoundaryTests(unittest.TestCase):
    def assert_shared_feed_is_pi_free(self, source: dict) -> None:
        # Check every policy, including revoked/superseded policies and active
        # policies in suspended distributions; all of them are signed.
        policies = [
            (distribution["id"], policy)
            for distribution in source["distributions"]
            for policy in distribution["release_policies"]
        ]
        self.assertTrue(policies, "empty shared Directory would make this check vacuous")
        for distribution_id, policy in policies:
            self.assertNotIn(
                "pi", [target["client"] for target in policy["targets"]],
                f"{distribution_id}@{policy['release_sequence']}: authored Pi target; "
                "Pi is derived from client capabilities during publication",
            )

    def test_existing_shared_directory_does_not_author_pi(self) -> None:
        source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
        self.assert_shared_feed_is_pi_free(source)

    def test_guard_rejects_pi_in_nonactive_policy(self) -> None:
        for status in ("revoked", "superseded"):
            with self.subTest(status=status):
                source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
                policy = next(
                    policy for distribution in source["distributions"]
                    for policy in distribution["release_policies"]
                    if policy["status"] == status
                )
                policy["targets"].append({"client": "pi"})
                with self.assertRaisesRegex(AssertionError, "authored Pi target"):
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
