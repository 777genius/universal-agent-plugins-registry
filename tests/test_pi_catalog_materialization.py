"""Offline contract tests only; they are not positive Pi installation evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pi_catalog_inventory_e2e import active_sources, native_files
from pi_direct_source_e2e import (
    expected_package_native_names, require_removed_native_payload,
    require_expected_mcp_definitions, require_unchanged_native_scope,
)
from pi_catalog_materialization_e2e import (
    KIND, MANAGED_ROOT, MANAGED_NO_SAVE_DIAGNOSTIC, PLATFORMS, SCOPES, SHARDS,
    case_tuple, selected_sources, source_identity, verify_report, verify_all,
)

HEAD = "a" * 40


def fixture(sources: list[dict], platform: str, shard: int) -> dict:
    results = []
    for _, item in selected_sources(sources, shard, SHARDS):
        for scope in SCOPES:
            record = {**source_identity(item), "scope": scope}
            add_command = [
                "agentplugins", "add", item["source"], "--no-save",
                "--target", "pi", "--scope", scope, "--format", "json",
            ] + (["--project-root", "/tmp/project"] if scope == "project" else [])
            if item["distribution_status"] == "active" and item["distribution"] == MANAGED_ROOT:
                diagnostic = "agentplugins: " + MANAGED_NO_SAVE_DIAGNOSTIC
                record.update({
                    "status": "requires_managed_saved_install",
                    "error": f"catalog-case/{scope}: add failed: {diagnostic}",
                    "operations": [{"argv": ["agentplugins", "add"],
                                    "exit": 1, "error_tail": diagnostic}],
                })
            elif item["distribution_status"] == "active":
                record.update({
                    "status": "passed", "verification": "native-files-and-receipt-only",
                    "runtime_claims": False, "account_oauth_qualified": False,
                    "operations": [
                        {"argv": add_command, "exit": 0},
                        {"argv": ["agentplugins", "list"], "exit": 0},
                        {"argv": add_command, "exit": 0},
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
                                   and item["distribution"] != MANAGED_ROOT
                                   for _, item in selected_sources(self.sources, shard, SHARDS)) * 2
                    self.assertEqual(
                        verify_report(report, self.sources, HEAD, platform, shard, SHARDS),
                        expected,
                    )

    def test_native_names_are_derived_from_verified_package_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "state" / "managed" / "clients" / "pi" / "package"
            package.mkdir(parents=True)
            manifest = b'{"name":"package","version":"1.0.0"}'
            (package / "plugin.json").write_bytes(manifest)
            skill = package / "skills" / "correct-skill" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("original skill", encoding="utf-8")
            (package / "mcp.json").write_text(
                json.dumps({"mcpServers": {"correct-server": {"url": "https://example.invalid"}}}),
                encoding="utf-8")
            receipt = {"clients": [{"client_id": "pi", "package_revision": {
                "manifest_digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
            }}]}
            self.assertEqual(
                expected_package_native_names(Path(directory), receipt, "package", "mixed"),
                ({"correct-skill/SKILL.md"}, {"correct-server": {"url": "https://example.invalid"}}),
            )
            wrong_receipt = copy.deepcopy(receipt)
            wrong_receipt["clients"][0]["package_revision"]["manifest_digest"] = (
                "sha256:" + "0" * 64)
            with self.assertRaisesRegex(RuntimeError, "source unavailable"):
                expected_package_native_names(
                    Path(directory), wrong_receipt, "package", "mixed")
            with self.assertRaisesRegex(RuntimeError, "manifest differs"):
                expected_package_native_names(
                    Path(directory), receipt, "other-package", "mixed")

    def test_native_mcp_definitions_reject_empty_wrong_url_and_wrong_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "package" / "runtime" / "launcher.mjs"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("console.log('fixture')", encoding="utf-8")
            expected = {
                "local": {"command": "node", "args": ["${PLUGIN_ROOT}/runtime/launcher.mjs"]},
                "remote": {"url": "https://mcp.example.invalid/mcp"},
            }
            actual = {
                "local": {"command": "node", "args": [str(launcher)]},
                "remote": {"url": "https://mcp.example.invalid/mcp"},
            }
            require_expected_mcp_definitions(actual, expected, root)
            mutations = (
                lambda data: data.__setitem__("local", {}),
                lambda data: data["remote"].__setitem__("url", "https://other.invalid"),
                lambda data: data["local"].__setitem__("command", "other"),
                lambda data: data["local"].__setitem__("args", ["/tmp/other/launcher.mjs"]),
            )
            for mutation in mutations:
                changed = copy.deepcopy(actual)
                mutation(changed)
                with self.assertRaisesRegex(RuntimeError, "native Pi MCP"):
                    require_expected_mcp_definitions(changed, expected, root)

    def test_unselected_pi_scope_must_remain_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            other_scope = Path(directory) / "other" / ".pi"
            baseline = native_files(other_scope)
            require_unchanged_native_scope(other_scope, False, baseline)
            other_scope.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "unselected scope"):
                require_unchanged_native_scope(other_scope, False, baseline)
            foreign = other_scope / "mcp.json"
            foreign.write_text('{"mcpServers": {}}', encoding="utf-8")
            present = native_files(other_scope)
            require_unchanged_native_scope(other_scope, True, present)
            foreign.write_text('{"mcpServers": {"unwanted": {}}}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unselected scope"):
                require_unchanged_native_scope(other_scope, True, present)

    def test_remove_rejects_leftover_native_skill_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory)
            foreign = native / "skills" / "foreign"
            foreign.mkdir(parents=True)
            (foreign / "SKILL.md").write_text("keep", encoding="utf-8")
            original = native_files(native / "skills")
            require_removed_native_payload(native, "skill", surviving_skills=original)
            residual = native / "skills" / "removed" / "scripts"
            residual.mkdir(parents=True)
            (residual / "run.py").write_text("leftover", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "skill payload remains"):
                require_removed_native_payload(native, "skill", surviving_skills=original)
            (residual / "run.py").unlink()
            residual.rmdir()
            residual.parent.rmdir()
            (foreign / "SKILL.md").write_text("modified", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "foreign skill tree changed"):
                require_removed_native_payload(native, "skill", surviving_skills=original)

    def test_boolean_report_schema_is_not_v1(self) -> None:
        report = fixture(self.sources, "ubuntu-24.04", 0)
        report["schema_version"] = True
        with self.assertRaisesRegex(RuntimeError, "report is not exact-head"):
            verify_report(report, self.sources, HEAD, "ubuntu-24.04", 0, SHARDS)

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

    def test_native_receipts_require_exact_real_source_no_save_add(self) -> None:
        baseline = fixture(self.sources, "ubuntu-24.04", 0)
        for edit in ("dry-run", "no-save-removed", "other-source", "wrong-scope",
                     "wrong-target", "extra-flag"):
            report = copy.deepcopy(baseline)
            case = next(r for r in report["results"] if r["status"] == "passed")
            argv = next(op["argv"] for op in case["operations"]
                        if op["argv"][1] == "add")
            if edit == "dry-run":
                argv.append("--dry-run")
            elif edit == "no-save-removed":
                argv.remove("--no-save")
            elif edit == "other-source":
                argv[2] = "github:foreign/source@" + HEAD + "//plugins/other"
            elif edit == "wrong-scope":
                argv[7] = "project" if argv[7] == "user" else "user"
            elif edit == "wrong-target":
                argv[5] = "codex"
            else:
                argv.extend(["--save", "yes"])
            with self.subTest(edit=edit), self.assertRaisesRegex(
                RuntimeError, "native Pi lifecycle incomplete"
            ):
                verify_report(report, self.sources, HEAD, "ubuntu-24.04", 0, SHARDS)

    def test_managed_dependency_denial_is_real_and_never_positive_evidence(self) -> None:
        selected = next(
            (shard for shard in range(SHARDS)
             if any(item["distribution"] == MANAGED_ROOT
                    for _, item in selected_sources(self.sources, shard, SHARDS))),
            None,
        )
        self.assertIsNotNone(selected, "Marketing Kit must be present in the inventory")
        baseline = fixture(self.sources, "ubuntu-24.04", selected)
        denied = next(case for case in baseline["results"]
                      if case["distribution"] == MANAGED_ROOT)
        self.assertEqual(denied["status"], "requires_managed_saved_install")
        self.assertEqual(denied["operations"][0]["exit"], 1)
        for changed in ("false_pass", "arbitrary_refusal", "zero_exit", "extra_operation"):
            variant = copy.deepcopy(baseline)
            candidate = next(case for case in variant["results"]
                             if case["distribution"] == MANAGED_ROOT
                             and case["scope"] == denied["scope"])
            if changed == "false_pass":
                candidate["status"] = "passed"
            elif changed == "arbitrary_refusal":
                candidate["error"] = "unrelated refusal"
            elif changed == "zero_exit":
                candidate["operations"][0]["exit"] = 0
            else:
                candidate["operations"].append({"argv": ["agentplugins", "remove"],
                                                "exit": 0})
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                verify_report(variant, self.sources, HEAD, "ubuntu-24.04",
                              selected, SHARDS)

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
