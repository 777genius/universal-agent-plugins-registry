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
from legacy_directory_client_boundary import (
    LEGACY_DIRECTORY_CLIENT_IDS, require_legacy_directory_clients,
)
from prepare_directory_publication import build_candidate
from sign_directory_publication import validate_bound_candidate


NEW_CLIENTS = ("hermes", "antigravity", "pi", "future-agent")


def new_distribution(client: str = "pi", *, distribution_status: str = "active",
                     policy_status: str = "active") -> dict:
    return {
        "id": "owner/example",
        "status": distribution_status,
        "release_policies": [{
            "release_sequence": 1,
            "status": policy_status,
            "targets": [{
                "client": client, "scopes": ["user"],
                "delivery": "managed", "authentication": "required",
            }],
        }],
    }


class LegacyClientPublicationBoundaryTests(unittest.TestCase):
    def test_all_historical_policy_statuses_are_excluded(self) -> None:
        for client in NEW_CLIENTS:
            for distribution_status in ("active", "suspended"):
                for policy_status in ("active", "superseded", "revoked"):
                    with self.subTest(client=client, distribution=distribution_status, policy=policy_status):
                        with self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
                            require_legacy_directory_clients([
                                new_distribution(client, distribution_status=distribution_status,
                                                 policy_status=policy_status),
                            ], [])

    def test_legacy_other_clients_remain_valid(self) -> None:
        for client in LEGACY_DIRECTORY_CLIENT_IDS:
            require_legacy_directory_clients([new_distribution(client)], [{"client": client}])
        require_legacy_directory_clients([], [{"level": "schema"}])

    def test_preparer_rejects_new_clients_before_building_any_candidate(self) -> None:
        source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
        source = copy.deepcopy(source)
        policy = source["distributions"][0]["release_policies"][0]
        policy["targets"].append({
            "client": "", "scopes": ["user"],
            "delivery": "managed", "authentication": "required",
        })
        # Other heavy preparation constraints are intentionally not supplied:
        # this test proves the frozen legacy boundary executes first.
        for client in NEW_CLIENTS:
            policy["targets"][-1]["client"] = client
            with self.subTest(client=client), self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
                build_candidate(source, {}, "a" * 40, "test-run", None)

    def test_signer_rejects_a_bypassed_preparer(self) -> None:
        candidate = {
            "candidate_schema_version": 1,
            "snapshot_schema_version": 1,
            "publication_id": "test-run",
            "source_commit": "a" * 40,
            "lifetime_days": 7,
            "products": [], "distributions": [],
            "evidence": [], "revocations": [],
        }
        for client in NEW_CLIENTS:
            candidate["distributions"] = [new_distribution(client)]
            with self.subTest(client=client), self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
                validate_bound_candidate(candidate)

    def test_unreferenced_new_client_evidence_cannot_break_legacy_readers(self) -> None:
        source = json.loads((ROOT / "registry" / "directory.json").read_text(encoding="utf-8"))
        candidate = {
            "candidate_schema_version": 1, "snapshot_schema_version": 1,
            "publication_id": "test-run", "source_commit": "a" * 40,
            "lifetime_days": 7, "products": [], "distributions": [],
            "evidence": [], "revocations": [],
        }
        # No target refers to this evidence. Old clients still parse its ID.
        for client in NEW_CLIENTS:
            source["evidence"] = candidate["evidence"] = [{"client": client}]
            with self.subTest(client=client, gate="prepare"), self.assertRaisesRegex(PublicationError, "new-client evidence"):
                build_candidate(source, {}, "a" * 40, "test-run", None)
            with self.subTest(client=client, gate="sign"), self.assertRaisesRegex(PublicationError, "new-client evidence"):
                validate_bound_candidate(candidate)


if __name__ == "__main__":
    unittest.main()
