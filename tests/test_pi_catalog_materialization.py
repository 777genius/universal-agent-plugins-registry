"""Offline contract tests only; they are not positive Pi installation evidence."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pi_catalog_inventory_e2e import active_sources
from pi_catalog_materialization_e2e import (
    KIND, PLATFORMS, SCOPES, SHARDS, case_tuple, selected_sources, source_identity,
    verify_report, verify_all,
)

HEAD = "a" * 40


def fixture(sources: list[dict], platform: str, shard: int) -> dict:
    results = []
    for _, item in selected_sources(sources, shard, SHARDS):
        for scope in SCOPES:
            record = {**source_identity(item), "scope": scope}
            if item["distribution_status"] == "active":
                record.update({
                    "status": "passed", "verification": "native-files-and-receipt-only",
                    "runtime_claims": False, "account_oauth_qualified": False,
                    "operations": [
                        {"argv": ["agentplugins", "add"], "exit": 0},
                        {"argv": ["agentplugins", "list"], "exit": 0},
                        {"argv": ["agentplugins", "add"], "exit": 0},
                        {"argv": ["agentplugins", "info"], "exit": 0},
                        {"argv": ["agentplugins", "update"], "exit": 1},
                        {"argv": ["agentplugins", "repair"], "exit": 0},
                        {"argv": ["agentplugins", "list"], "exit": 0},
                        {"argv": ["agentplugins", "remove"], "exit": 0},
                    ],
                })
            else:
                record["status"] = "not_eligible"
            results.append(record)
    return {
        "schema_version": 1, "kind": KIND, "source_head": HEAD,
        "uap_cli": "public npm 0.1.102",
        "native_pi": "real npm @earendil-works/pi-coding-agent@1.5.0",
        "runner_os": PLATFORMS[platform], "shard": shard, "shards": SHARDS,
        "source_count": len(sources), "scopes": list(SCOPES),
        "signed_pi_policy_published": False,
        "saved_dependency_eligibility": False, "runtime_claims": False,
        "account_authentication": "not_tested", "results": results,
    }


class PiRealMaterializationContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = active_sources(HEAD)

    def test_all_pinned_sources_have_a_native_case_or_suspended_exclusion(self) -> None:
        keys = set()
        for index, item in enumerate(self.sources):
            if item["distribution_status"] == "active":
                case = case_tuple(item, index)
                self.assertEqual(case[1], item["manifest_name"])
                self.assertEqual(case[3], item["revision"])
                self.assertIn(case[4], ("skill", "mcp", "mixed"))
            key = (item["distribution"], item["release_sequence"])
            self.assertNotIn(key, keys)
            keys.add(key)
        self.assertEqual(
            sorted(index for shard in range(SHARDS)
                   for index, _ in selected_sources(self.sources, shard, SHARDS)),
            list(range(len(self.sources))),
        )

    def test_accepts_only_explicit_native_lifecycle_receipts(self) -> None:
        for platform in PLATFORMS:
            for shard in range(SHARDS):
                with self.subTest(platform=platform, shard=shard):
                    report = fixture(self.sources, platform, shard)
                    expected = sum(item["distribution_status"] == "active"
                                   for _, item in selected_sources(self.sources, shard, SHARDS)) * 2
                    self.assertEqual(
                        verify_report(report, self.sources, HEAD, platform, shard, SHARDS),
                        expected,
                    )

    def test_dry_run_and_real_refusals_never_count_as_materialization(self) -> None:
        report = fixture(self.sources, "ubuntu-24.04", 0)
        active = next(r for r in report["results"] if r["status"] == "passed")
        for bad in ("planned", "refused", "failed", "not_eligible"):
            variant = copy.deepcopy(report)
            candidate = next(r for r in variant["results"]
                             if r["distribution"] == active["distribution"]
                             and r["release_sequence"] == active["release_sequence"]
                             and r["scope"] == active["scope"])
            candidate["status"] = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(
                RuntimeError, "native Pi lifecycle incomplete"
            ):
                verify_report(variant, self.sources, HEAD, "ubuntu-24.04", 0, SHARDS)

    def test_signed_entitlement_and_oauth_claims_are_forbidden(self) -> None:
        for field, value in (
            ("signed_pi_policy_published", True),
            ("saved_dependency_eligibility", True),
            ("account_authentication", "passed"),
            ("runtime_claims", True),
            ("source_head", "b" * 40),
            ("uap_cli", "public npm 0.1.89"),
        ):
            variant = fixture(self.sources, "macos-15", 1)
            variant[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                RuntimeError, "not exact-head native Pi evidence"
            ):
                verify_report(variant, self.sources, HEAD, "macos-15", 1, SHARDS)

    def test_duplicate_missing_and_mutated_source_fail(self) -> None:
        baseline = fixture(self.sources, "windows-2025", 2)
        mutate = (
            lambda report: report["results"].pop(),
            lambda report: report["results"].__setitem__(
                1, copy.deepcopy(report["results"][0])),
            lambda report: report["results"][0].__setitem__(
                "tree_digest", "sha256:" + "0" * 64),
            lambda report: report["results"][0].__setitem__(
                "verification", "planned-only"),
        )
        for change in mutate:
            variant = copy.deepcopy(baseline)
            change(variant)
            with self.assertRaises(RuntimeError):
                verify_report(variant, self.sources, HEAD, "windows-2025", 2, SHARDS)

    def test_excluded_distribution_never_gets_false_positive(self) -> None:
        for shard in range(SHARDS):
            baseline = fixture(self.sources, "ubuntu-24.04", shard)
            excluded = next((r for r in baseline["results"]
                             if r["status"] == "not_eligible"), None)
            if excluded is None:
                continue
            excluded["status"] = "passed"
            with self.assertRaisesRegex(RuntimeError, "suspended package"):
                verify_report(baseline, self.sources, HEAD, "ubuntu-24.04", shard, SHARDS)
            return
        self.fail("fixture must include the suspended distribution")

    def test_aggregate_requires_nine_original_artifacts(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "one original report"):
            verify_all([Path("/dev/null")] * 8, self.sources, HEAD)


if __name__ == "__main__":
    unittest.main()
