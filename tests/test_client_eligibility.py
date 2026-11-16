"""Invariants for capability-derived Pi Directory eligibility without opt-in."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_registry as registry  # noqa: E402
import client_eligibility  # noqa: E402
from client_contract import load_client_capabilities  # noqa: E402
from client_eligibility import (  # noqa: E402
    DERIVED, EXCLUDED, MARKETING_KIT, EligibilityError, derive_client_targets,
)

ATLASSIAN = "777genius/atlassian"
NOTION = "777genius/notion"
HUBSPOT = "777genius/hubspot-crm"
HTTP_FACTS = {"mcp_transports": ["streamable-http"], "dependencies": {}}


def release_of(source: dict, distribution_id: str, sequence: int = 1) -> tuple[dict, dict]:
    distribution = next(item for item in source["distributions"] if item["id"] == distribution_id)
    release = next(item for item in distribution["releases"] if item["sequence"] == sequence)
    return distribution, release


def add_pi_evidence(source: dict, distribution_id: str, sequence: int = 1, *,
                    systems=("linux", "macos", "windows"), outcome: str = "passed",
                    level: str = "materialization", installer: str = "0.1.102",
                    trusted: bool = True, tree_digest: str | None = None) -> list[str]:
    distribution, release = release_of(source, distribution_id, sequence)
    package_source = release["package_source"]
    identifiers = []
    for system in systems:
        identifier = f"pi/{distribution_id}/{sequence}/{level}/{outcome}/{system}"
        record = {
            "schema_version": 1, "id": identifier,
            "product_id": distribution["product_id"], "distribution_id": distribution_id,
            "release_sequence": sequence,
            "package_tree_digest": tree_digest or release["tree_digest"],
            "manifest_digest": release["manifest_digest"],
            "source_repository": package_source["repository"],
            "source_revision": package_source["revision"] or "f" * 40,
            "source_path": package_source["path"],
            "level": level, "outcome": outcome, "client": "pi", "client_version": "1.5.0",
            "installer_version": installer, "os": system, "architecture": "amd64",
            "observed_at": "2026-11-16T00:00:00Z",
            "artifact": {"repository": "777genius/universal-agent-plugins-registry",
                         "revision": "e" * 40, "path": f"evidence/{system}.json",
                         "digest": "sha256:" + "e" * 64},
        }
        if trusted:
            record["trust"] = {"kind": "reviewed_external"}
        source["evidence"].append(record)
        identifiers.append(identifier)
    source["evidence"].sort(key=lambda item: item["id"])
    return identifiers


def pi_target(policy: dict) -> list[dict]:
    return [target for target in policy["targets"] if target["client"] == "pi"]


class DerivedPiEligibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = registry.load_directory_source()
        self.capability = load_client_capabilities()["pi"]
        self.facts: dict[str, dict] = {}
        self.fetched: list[str] = []

    def provider(self, distribution: dict, release: dict, policy: dict) -> dict:
        self.fetched.append(distribution["id"])
        return copy.deepcopy(self.facts.get(distribution["id"], HTTP_FACTS))

    def derive(self, source: dict) -> tuple[dict, dict[tuple[str, int], dict]]:
        candidate, decisions = derive_client_targets(source, "pi", self.capability, self.provider)
        return candidate, {(item["distribution_id"], item["release_sequence"]): item for item in decisions}

    def test_compatible_release_with_three_os_evidence_derives_a_valid_signed_shape(self) -> None:
        identifiers = add_pi_evidence(self.source, ATLASSIAN)
        original = copy.deepcopy(self.source)
        candidate, decisions = self.derive(self.source)
        self.assertEqual(self.source, original, "derivation must not mutate its source")
        self.assertEqual(decisions[(ATLASSIAN, 1)]["outcome"], DERIVED)
        policy = release_of(candidate, ATLASSIAN)[0]["release_policies"][0]
        self.assertEqual(pi_target(policy), [{
            "client": "pi", "scopes": ["user"], "delivery": "managed",
            "authentication": "required",
        }])
        self.assertEqual(policy["minimum_installer_version"], "0.1.102")
        self.assertEqual(policy["current_evidence"], sorted(identifiers))
        derived = [key for key, value in decisions.items() if value["outcome"] == DERIVED]
        self.assertEqual(derived, [(ATLASSIAN, 1)], "no release may gain Pi without its own evidence")
        registry.validate_directory(candidate, verify_packages=False)
        self.assertEqual(
            registry.resolve_directory(candidate, "atlassian", ["pi"])["distribution_id"], ATLASSIAN,
        )

    def test_no_pi_without_complete_trusted_positive_exact_release_evidence(self) -> None:
        cases = {
            "none": {},
            "two-os": {"systems": ("linux", "macos")},
            "untrusted": {"trusted": False},
            "older-installer": {"installer": "0.1.101"},
            "other-bytes": {"tree_digest": "sha256:" + "0" * 64},
        }
        for name, options in cases.items():
            with self.subTest(case=name):
                source = copy.deepcopy(self.source)
                if options:
                    add_pi_evidence(source, ATLASSIAN, **options)
                self.fetched.clear()
                _, decisions = self.derive(source)
                self.assertEqual(decisions[(ATLASSIAN, 1)]["outcome"], EXCLUDED)
                self.assertIn("lacks trusted passed pi materialization evidence",
                              decisions[(ATLASSIAN, 1)]["reason"])
                self.assertEqual(self.fetched, [], "package bytes are read only after evidence")
        source = copy.deepcopy(self.source)
        add_pi_evidence(source, ATLASSIAN)
        add_pi_evidence(source, ATLASSIAN, systems=("windows",), outcome="failed", level="runtime")
        _, decisions = self.derive(source)
        self.assertIn("trusted failed pi evidence", decisions[(ATLASSIAN, 1)]["reason"])
        # An authored target cannot bypass the same gate on any distribution kind.
        source = copy.deepcopy(self.source)
        policy = release_of(source, ATLASSIAN)[0]["release_policies"][0]
        policy["minimum_installer_version"] = "0.1.102"
        policy["targets"].append({"client": "pi", "scopes": ["user"],
                                  "delivery": "managed", "authentication": "required"})
        with self.assertRaisesRegex(registry.RegistryError, "pi target is inadmissible: lacks"):
            registry.validate_directory(source, verify_packages=False)

    def test_explicit_denial_beats_capability_and_evidence(self) -> None:
        add_pi_evidence(self.source, ATLASSIAN)
        denials = {("pi", ATLASSIAN): "reviewed exclusion"}
        with mock.patch.dict(client_eligibility.EXPLICIT_DENIALS, denials):
            candidate, decisions = self.derive(self.source)
            self.assertEqual(decisions[(ATLASSIAN, 1)]["outcome"], EXCLUDED)
            self.assertIn("explicit pi denial", decisions[(ATLASSIAN, 1)]["reason"])
            self.assertEqual(pi_target(release_of(candidate, ATLASSIAN)[0]["release_policies"][0]), [])
            self.assertEqual(self.fetched, [])
            # A hand-written target cannot override the denial either.
            source = copy.deepcopy(self.source)
            policy = release_of(source, ATLASSIAN)[0]["release_policies"][0]
            policy["minimum_installer_version"] = "0.1.102"
            policy["current_evidence"] = sorted(
                item["id"] for item in source["evidence"]
                if item.get("client") == "pi" and item["distribution_id"] == ATLASSIAN
            )
            policy["targets"].append({"client": "pi", "scopes": ["user"],
                                      "delivery": "managed", "authentication": "required"})
            with self.assertRaisesRegex(registry.RegistryError, "explicit pi denial"):
                registry.validate_directory(source, verify_packages=False)
            with self.assertRaisesRegex(EligibilityError, "conflicts with its denial"):
                self.derive(source)

    def test_marketing_kit_stays_excluded_even_when_hubspot_dependency_qualifies(self) -> None:
        add_pi_evidence(self.source, HUBSPOT)
        add_pi_evidence(self.source, MARKETING_KIT)
        self.facts[MARKETING_KIT] = {"mcp_transports": [], "dependencies": {HUBSPOT: "0.1.0"}}
        _, decisions = self.derive(self.source)
        self.assertEqual(decisions[(HUBSPOT, 1)]["outcome"], DERIVED)
        self.assertEqual(decisions[(MARKETING_KIT, 1)]["outcome"], EXCLUDED)
        self.assertIn("explicit pi denial", decisions[(MARKETING_KIT, 1)]["reason"])
        self.assertNotIn(MARKETING_KIT, self.fetched)
        # The generic saved-dependency check keeps any other root fail-closed.
        self.facts[ATLASSIAN] = {"mcp_transports": ["streamable-http"], "dependencies": {NOTION: "0.1.0"}}
        add_pi_evidence(self.source, ATLASSIAN)
        _, decisions = self.derive(self.source)
        self.assertEqual(decisions[(ATLASSIAN, 1)]["outcome"], EXCLUDED)
        self.assertIn(f"dependency {NOTION}@0.1.0 is not pi-eligible", decisions[(ATLASSIAN, 1)]["reason"])
        add_pi_evidence(self.source, NOTION)
        _, decisions = self.derive(self.source)
        self.assertEqual(decisions[(ATLASSIAN, 1)]["outcome"], DERIVED)

    def test_revoked_superseded_suspended_and_unsupported_releases_never_receive_pi(self) -> None:
        for distribution_id, sequence in (
            ("777genius/context7", 1), ("777genius/context7", 2), ("777genius/agent-code-navigator", 1),
        ):
            add_pi_evidence(self.source, distribution_id, sequence)
        add_pi_evidence(self.source, "777genius/cloudflare")
        self.facts["777genius/cloudflare"] = {"mcp_transports": ["sse"], "dependencies": {}}
        add_pi_evidence(self.source, "github/github")
        _, decisions = self.derive(self.source)
        expected = {
            ("777genius/context7", 1): "release policy is revoked",
            ("777genius/context7", 2): "release policy is superseded",
            ("777genius/agent-code-navigator", 1): "distribution is suspended",
            ("777genius/agent-notifications", 1): "distribution is suspended",
            ("777genius/context7", 7): "unresolved source revision",
            ("777genius/cloudflare", 1): "MCP transport sse is 'unsupported'",
            # Raising this upstream policy floor would orphan exact-version evidence.
            ("github/github", 1): "would orphan existing exact-version evidence",
        }
        for key, reason in expected.items():
            with self.subTest(release=key):
                self.assertEqual(decisions[key]["outcome"], EXCLUDED)
                self.assertIn(reason, decisions[key]["reason"])


if __name__ == "__main__":
    unittest.main()
