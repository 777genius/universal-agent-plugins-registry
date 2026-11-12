"""Regression tests for BOTH protected historical Directory v1 publication gates."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from directory_publication import PublicationError
from legacy_directory_client_boundary import require_pi_free_legacy_distributions
from prepare_directory_publication import build_candidate
from sign_directory_publication import validate_bound_candidate


def pi_distribution(*, distribution_status: str = "active",
                    policy_status: str = "active") -> dict:
    return {
        "id": "owner/example",
        "status": distribution_status,
        "release_policies": [{
            "release_sequence": 1,
            "status": policy_status,
            "targets": [{
                "client": "pi", "scopes": ["user"],
                "delivery": "managed", "authentication": "required",
            }],
        }],
    }


class LegacyPiPublicationBoundaryTests(unittest.TestCase):
    def test_all_historical_policy_statuses_are_excluded(self) -> None:
        for distribution_status in ("active", "suspended"):
            for policy_status in ("active", "superseded", "revoked"):
                with self.subTest(distribution=distribution_status, policy=policy_status):
                    with self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
                        require_pi_free_legacy_distributions([
                            pi_distribution(distribution_status=distribution_status,
                                            policy_status=policy_status),
                        ])

    def test_legacy_other_clients_remain_valid(self) -> None:
        source = pi_distribution()
        source["release_policies"][0]["targets"][0]["client"] = "codex"
        require_pi_free_legacy_distributions([source])

    def test_preparer_rejects_pi_before_building_any_candidate(self) -> None:
        source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
        source = copy.deepcopy(source)
        policy = source["distributions"][0]["release_policies"][0]
        policy["targets"].append({
            "client": "pi", "scopes": ["user"],
            "delivery": "managed", "authentication": "required",
        })
        # Other heavy preparation constraints are intentionally not supplied:
        # this test proves the legacy Pi boundary executes first.
        with self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
            build_candidate(source, {}, "a" * 40, "test-run", None)

    def test_signer_rejects_a_bypassed_preparer(self) -> None:
        candidate = {
            "candidate_schema_version": 1,
            "snapshot_schema_version": 1,
            "publication_id": "test-run",
            "source_commit": "a" * 40,
            "lifetime_days": 7,
            "products": [], "distributions": [pi_distribution()],
            "evidence": [], "revocations": [],
        }
        with self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
            validate_bound_candidate(candidate)


if __name__ == "__main__":
    unittest.main()
