"""Regression tests for BOTH protected historical Directory v1 publication gates."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_registry import (
    RegistryError, load_directory_source, resolve_directory, validate_directory,
    with_derived_pi_targets,
)
from directory_publication import PublicationError
from legacy_directory_client_boundary import (
    LEGACY_DIRECTORY_CLIENT_IDS, require_legacy_directory_clients,
)
from prepare_directory_publication import build_candidate
from sign_directory_publication import validate_bound_candidate, require_new_key_for_new_clients


NEW_CLIENTS = ("future-agent", "unknown-client")


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
                        with self.assertRaisesRegex(PublicationError, "unknown client target"):
                            require_legacy_directory_clients([
                                new_distribution(client, distribution_status=distribution_status,
                                                 policy_status=policy_status),
                            ], [])

    def test_legacy_other_clients_remain_valid(self) -> None:
        for client in LEGACY_DIRECTORY_CLIENT_IDS:
            require_legacy_directory_clients([new_distribution(client)], [{"client": client}])
        require_legacy_directory_clients([], [{"level": "schema"}])

    def test_released_clients_are_admitted_for_all_policy_states(self) -> None:
        for client in ("pi", "hermes", "antigravity"):
            for distribution_status in ("active", "suspended"):
                for policy_status in ("active", "superseded", "revoked"):
                    with self.subTest(client=client, distribution=distribution_status, policy=policy_status):
                        require_legacy_directory_clients(
                            [new_distribution(client, distribution_status=distribution_status,
                                              policy_status=policy_status)],
                            [{"client": client}],
                        )

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
            with self.subTest(client=client), self.assertRaisesRegex(PublicationError, "unknown client target"):
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
            with self.subTest(client=client), self.assertRaisesRegex(PublicationError, "unknown client target"):
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
            with self.subTest(client=client, gate="prepare"), self.assertRaisesRegex(PublicationError, "unknown-client evidence"):
                build_candidate(source, {}, "a" * 40, "test-run", None)
            with self.subTest(client=client, gate="sign"), self.assertRaisesRegex(PublicationError, "unknown-client evidence"):
                validate_bound_candidate(candidate)


class HistoricalSignerReuseTests(unittest.TestCase):
    def test_new_clients_cannot_use_original_key_even_if_key_id_is_renamed(self) -> None:
        old_key = json.loads(
            (ROOT / "registry" / "publication" / "trusted-keys.json").read_text(encoding="utf-8")
        )["keys"][0]
        self.assertEqual(old_key["key_id"], "uap-directory-2026-01")
        historical_public = base64.b64decode(old_key["public_key"])
        fresh_synthetic_public = b"\\x11" * 32
        for client in ("pi", "hermes", "antigravity"):
            for state in ("active", "superseded", "revoked"):
                candidate = {"distributions": [new_distribution(client, policy_status=state)], "evidence": []}
                with self.subTest(client=client, state=state):
                    with self.assertRaisesRegex(PublicationError, "historical Directory signing key"):
                        require_new_key_for_new_clients(candidate, historical_public)
                    # Distinct bytes only pass this narrow no-reuse check; they
                    # never imply a production key, signer grant or approval.
                    require_new_key_for_new_clients(candidate, fresh_synthetic_public)

    def test_unreferenced_new_client_evidence_cannot_use_historical_key(self) -> None:
        old_key = json.loads(
            (ROOT / "registry" / "publication" / "trusted-keys.json").read_text(encoding="utf-8")
        )["keys"][0]
        historical_public = base64.b64decode(old_key["public_key"])
        for client in ("pi", "hermes", "antigravity"):
            with self.subTest(client=client), self.assertRaisesRegex(
                PublicationError, "historical Directory signing key"
            ):
                require_new_key_for_new_clients(
                    {"distributions": [], "evidence": [{"client": client}]}, historical_public,
                )
        require_new_key_for_new_clients(
            {"distributions": [new_distribution("codex")], "evidence": []}, historical_public,
        )


class DerivedPiTargetTests(unittest.TestCase):
    PI = {"client": "pi", "scopes": ["user"], "delivery": "managed"}

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = load_directory_source()
        cls.derived = with_derived_pi_targets(cls.source)

    @staticmethod
    def policy(source: dict, distribution_id: str, sequence: int) -> dict:
        distribution = next(item for item in source["distributions"] if item["id"] == distribution_id)
        return next(item for item in distribution["release_policies"] if item["release_sequence"] == sequence)

    def pi_target(self, source: dict, distribution_id: str, sequence: int) -> dict | None:
        targets = self.policy(source, distribution_id, sequence)["targets"]
        return next((target for target in targets if target["client"] == "pi"), None)

    def test_only_active_or_superseded_releases_of_active_distributions_get_pi(self) -> None:
        for distribution in self.derived["distributions"]:
            for policy in distribution["release_policies"]:
                if distribution["status"] != "active" or policy["status"] not in ("active", "superseded"):
                    self.assertNotIn("pi", [target["client"] for target in policy["targets"]],
                                     f"{distribution['id']}@{policy['release_sequence']}")
        self.assertEqual(self.pi_target(self.derived, "777genius/context7", 7),
                         {**self.PI, "authentication": "not_required"})
        self.assertEqual(self.policy(self.derived, "777genius/context7", 7)["minimum_installer_version"], "0.1.102")
        revoked = copy.deepcopy(self.source)
        self.policy(revoked, "777genius/context7", 7)["status"] = "revoked"
        self.assertIsNone(self.pi_target(with_derived_pi_targets(revoked), "777genius/context7", 7))

    def test_marketing_kit_and_its_saved_dependencies_get_pi(self) -> None:
        for distribution_id, sequence in (
            ("777genius/marketing-kit", 1), ("777genius/hubspot-crm", 1),
            ("777genius/notion", 1), ("777genius/playwright-bridge", 2),
        ):
            with self.subTest(distribution=distribution_id):
                self.assertIsNotNone(self.pi_target(self.derived, distribution_id, sequence))

    def test_mcp_release_that_may_require_sse_does_not_get_pi(self) -> None:
        source = copy.deepcopy(self.source)
        policy = self.policy(source, "777genius/notion", 1)
        # Every remaining target supports SSE, so nothing bounds the transport.
        policy["targets"] = [item for item in policy["targets"] if item["client"] in {"cursor", "copilot"}]
        self.assertIsNone(self.pi_target(with_derived_pi_targets(source), "777genius/notion", 1))
        policy["targets"].insert(0, {**self.PI, "client": "codex", "authentication": "required"})
        self.assertIsNotNone(self.pi_target(with_derived_pi_targets(source), "777genius/notion", 1))

    def test_derived_targets_validate_without_pi_evidence_but_upstream_rule_stays(self) -> None:
        self.assertFalse(any(item.get("client") == "pi" for item in self.derived["evidence"]))
        validate_directory(self.derived, verify_packages=False)
        # Upstream defaults keep their evidence rule; Pi falls back to community.
        self.assertIsNone(self.pi_target(self.derived, "github/github", 1))
        self.assertEqual(resolve_directory(self.derived, "github", ["pi"])["distribution_id"],
                         "777genius/github-bridge")
        forged = copy.deepcopy(self.derived)
        self.policy(forged, "github/github", 1)["targets"].append({**self.PI, "authentication": "required"})
        with self.assertRaisesRegex(RegistryError, "lacks current positive package compatibility evidence"):
            validate_directory(forged, verify_packages=False)


if __name__ == "__main__":
    unittest.main()

