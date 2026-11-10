"""Regression tests for fail-closed Pi dry-run native-state checks."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pi_direct_source_e2e import CASES, require_removed_native_payload
from pi_catalog_inventory_e2e import (
    isolated_cli_env, native_files, clone_verified_cli_cache, require_exact_checkout,
    require_published_cli_version,
    require_saved_pi_receipt,
)


class PiRepresentativeHubSpotTests(unittest.TestCase):
    def test_pinned_hubspot_case_matches_active_signed_dependency_source(self) -> None:
        root = Path(__file__).resolve().parents[1]
        directory = json.loads((root / "registry/directory.json").read_text(encoding="utf-8"))
        hubspot = next(d for d in directory["distributions"]
                       if d["id"] == "777genius/hubspot-crm")
        self.assertEqual(hubspot["status"], "active")
        active = [p for p in hubspot["release_policies"] if p["status"] == "active"]
        self.assertEqual(len(active), 1)
        release = next(r for r in hubspot["releases"]
                       if r["sequence"] == active[0]["release_sequence"])
        self.assertEqual(release["components"], ["mcp"])
        source = release["package_source"]
        self.assertIsNotNone(source["revision"], "HubSpot qualification must be pinned")
        self.assertIn(
            ("hubspot-crm-http", "hubspot-crm", source["path"],
             source["revision"], "mcp", source["repository"]),
            CASES,
            "Pi HubSpot lifecycle must test the exact immutable signed dependency source",
        )


class PiEvidenceIdentityTests(unittest.TestCase):
    def test_source_report_accepts_only_actual_checkout_head(self) -> None:
        expected = "a" * 40
        for actual in (expected, "b" * 40):
            result = subprocess.CompletedProcess([], 0, actual + "\n", "")
            with self.subTest(actual=actual), patch(
                "pi_catalog_inventory_e2e.subprocess.run", return_value=result
            ) as run:
                if actual == expected:
                    require_exact_checkout(expected)
                else:
                    with self.assertRaisesRegex(RuntimeError, "checkout HEAD differs"):
                        require_exact_checkout(expected)
                self.assertEqual(run.call_args.args[0],
                                 ["git", "rev-parse", "--verify", "HEAD"])

    def test_source_report_rejects_other_cli_versions(self) -> None:
        for version in ("agentplugins 0.1.89", "0.1.102", "", "agentplugins 0.1.102\nextra"):
            result = subprocess.CompletedProcess([], 0, version + "\n", "")
            with self.subTest(version=version), patch(
                "pi_catalog_inventory_e2e.subprocess.run", return_value=result
            ) as run:
                with self.assertRaisesRegex(RuntimeError, "qualified public 0.1.102"):
                    require_published_cli_version("/exact/bin/agentplugins")
                self.assertEqual(run.call_args.args[0], ["/exact/bin/agentplugins", "version"])

    def test_source_report_accepts_exact_public_cli_version(self) -> None:
        result = subprocess.CompletedProcess([], 0, "agentplugins 0.1.102\n", "")
        with patch("pi_catalog_inventory_e2e.subprocess.run", return_value=result) as run:
            require_published_cli_version("/exact/bin/agentplugins")
            self.assertEqual(run.call_args.args[0], ["/exact/bin/agentplugins", "version"])



class PiIsolatedChildEnvironmentTests(unittest.TestCase):
    def test_preview_does_not_inherit_runner_tokens_or_shell_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(
                "pi_catalog_inventory_e2e.os.environ",
                {
                    "PATH": "trusted-bin",
                    "GITHUB_TOKEN": "secret", "NPM_TOKEN": "secret",
                    "AWS_SECRET_ACCESS_KEY": "secret",
                    "ACTIONS_RUNTIME_TOKEN": "secret",
                    "NODE_OPTIONS": "--require /untrusted/hook.js",
                    "GIT_CONFIG_KEY_0": "http.extraheader",
                    "GIT_CONFIG_VALUE_0": "AUTHORIZATION: secret",
                    "CI": "host-value",
                },
                clear=True,
            ):
                child = isolated_cli_env(root)
            self.assertEqual(child["PATH"], "trusted-bin")
            self.assertEqual(child["CI"], "true")
            self.assertEqual(child["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(child["TMP"], str(root / "tmp"))
            self.assertEqual(child["TEMP"], child["TMP"])
            self.assertEqual(child["TMPDIR"], child["TMP"])
            self.assertTrue((root / "tmp").is_dir())
            self.assertEqual(set(child), {
                "PATH", "CI", "GIT_TERMINAL_PROMPT", "TMP", "TEMP", "TMPDIR",
            })



class PiLauncherCacheIsolationTests(unittest.TestCase):
    def test_each_case_has_a_separate_cached_published_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed"
            (seed / "0.1.102" / "platform").mkdir(parents=True)
            (seed / "0.1.102" / "platform" / "agentplugins").write_bytes(b"verified")
            first = root / "case-one"
            second = root / "case-two"
            clone_verified_cli_cache(seed, first)
            clone_verified_cli_cache(seed, second)
            (first / "0.1.102" / "platform" / "agentplugins").write_bytes(b"changed")
            self.assertEqual((second / "0.1.102" / "platform" / "agentplugins").read_bytes(),
                             b"verified")
            self.assertEqual((seed / "0.1.102" / "platform" / "agentplugins").read_bytes(),
                             b"verified")

    def test_existing_case_cache_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed, existing = root / "seed", root / "existing"
            seed.mkdir()
            existing.mkdir()
            with self.assertRaisesRegex(RuntimeError, "unexpectedly exists"):
                clone_verified_cli_cache(seed, existing)


class PiNativeSnapshotTests(unittest.TestCase):
    def test_detects_new_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            profile.mkdir()
            baseline = native_files(profile)
            (profile / "unexpected").mkdir()
            self.assertNotEqual(native_files(profile), baseline)

    def test_detects_native_file_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            profile.mkdir()
            file = profile / "settings.json"
            file.write_text("original", encoding="utf-8")
            baseline = native_files(profile)
            file.write_text("modified", encoding="utf-8")
            self.assertNotEqual(native_files(profile), baseline)

    def test_detects_new_symlink_without_dereferencing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            profile.mkdir()
            baseline = native_files(profile)
            try:
                (profile / "escape").symlink_to(Path(temp) / "not-present")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"host does not permit symlink creation: {error}")
            entries = native_files(profile)
            self.assertNotEqual(entries, baseline)
            self.assertTrue(any(entry[0] == "escape" and entry[1] == "symlink"
                                for entry in entries))


def saved_pi_receipt(scope: str) -> dict:
    # The released CLI's ordinary remote add previews saved dependency actions.
    return {
        "dry_run": True, "scope": scope, "result": "success",
        "environment": {"saved": True, "scope": scope,
                        "selected_targets": ["pi"]},
        "actions": [{"alias": "example", "client_id": "pi",
                     "action": "install", "package_digest": "sha256:" + "a" * 64}],
    }


class PiPlanningEnvelopeTests(unittest.TestCase):
    def test_accepts_saved_dependency_preview_for_both_scopes(self) -> None:
        for scope in ("user", "project"):
            with self.subTest(scope=scope):
                require_saved_pi_receipt(saved_pi_receipt(scope), scope)

    def test_accepts_multiple_pi_dependency_actions(self) -> None:
        receipt = saved_pi_receipt("project")
        receipt["actions"].append({"alias": "dependency", "client_id": "pi",
                                   "action": "install",
                                   "package_digest": "sha256:" + "b" * 64})
        require_saved_pi_receipt(receipt, "project")

    def test_rejects_unqualified_saved_dependency_preview(self) -> None:
        mutations = {
            "not_dry_run": lambda data: data.update(dry_run=False),
            "wrong_scope": lambda data: data.update(scope="project"),
            "failed_result": lambda data: data.update(result="failure"),
            "no_environment": lambda data: data.update(environment=None),
            "not_saved": lambda data: data["environment"].update(saved=False),
            "wrong_environment_scope": lambda data: data["environment"].update(scope="project"),
            "wrong_selected_targets": lambda data: data["environment"].update(selected_targets=["codex"]),
            "no_actions": lambda data: data.update(actions=[]),
            "wrong_action_target": lambda data: data["actions"][0].update(client_id="codex"),
            "missing_alias": lambda data: data["actions"][0].update(alias=""),
            "missing_action": lambda data: data["actions"][0].update(action=""),
            "unrelated_action": lambda data: data["actions"][0].update(action="remove"),
            "no_install": lambda data: data["actions"][0].update(action="unchanged"),
            "missing_digest": lambda data: data["actions"][0].pop("package_digest"),
            "untrusted_digest": lambda data: data["actions"][0].update(package_digest="unsigned"),
            "invalid_action": lambda data: data.update(actions=[None]),
        }
        for name, change in mutations.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                receipt = saved_pi_receipt("user")
                change(receipt)
                require_saved_pi_receipt(receipt, "user")



class PiNativeRemovalTests(unittest.TestCase):
    def test_removed_mcp_cannot_leave_registered_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "mcp.json"
            config.write_text('{"mcpServers":{"stale":{}}}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "registration remains"):
                require_removed_native_payload(root, "mcp")
            config.write_text('{"mcpServers":{}}', encoding="utf-8")
            require_removed_native_payload(root, "mcp")
            config.unlink()
            require_removed_native_payload(root, "mcp")

    def test_removed_skill_cannot_leave_skill_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill = root / "skills" / "package" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("stale skill", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "skill is still present"):
                require_removed_native_payload(root, "skill")
            skill.unlink()
            require_removed_native_payload(root, "skill")

    def test_remove_keeps_existing_mcp_server_but_rejects_ours(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            foreign = {"command": "node", "args": ["--version"]}
            config = root / "mcp.json"
            config.write_text('{"mcpServers":{"foreign-neighbor":'
                              '{"command":"node","args":["--version"]}}}', encoding="utf-8")
            expected = {"foreign-neighbor": foreign}
            require_removed_native_payload(root, "mcp", surviving_servers=expected)
            config.write_text('{"mcpServers":{"foreign-neighbor":'
                              '{"command":"node","args":["--version"]},"stale":{}}}',
                              encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "registration remains"):
                require_removed_native_payload(root, "mcp", surviving_servers=expected)

    def test_remove_keeps_existing_skill_but_rejects_ours(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            foreign = root / "skills" / "foreign-neighbor" / "SKILL.md"
            foreign.parent.mkdir(parents=True)
            foreign.write_text("existing", encoding="utf-8")
            expected = {"foreign-neighbor/SKILL.md"}
            require_removed_native_payload(root, "skill", surviving_skills=expected)
            own = root / "skills" / "our-package" / "SKILL.md"
            own.parent.mkdir()
            own.write_text("ours", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "still present"):
                require_removed_native_payload(root, "skill", surviving_skills=expected)

    def test_removal_accepts_unowned_neighbor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            foreign = root / "foreign-neighbor.txt"
            foreign.write_text("do not touch", encoding="utf-8")
            for kind in ("skill", "mcp"):
                require_removed_native_payload(root, kind)
            self.assertEqual(foreign.read_text(encoding="utf-8"), "do not touch")

if __name__ == "__main__":
    unittest.main()
