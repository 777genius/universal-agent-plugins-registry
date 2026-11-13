"""Offline contract tests only; they are not positive Pi installation evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pi_catalog_inventory_e2e import active_sources, native_files
from pi_direct_source_e2e import (
    expected_package_native_names, pinned_source_bytes, run_case,
    require_pinned_native_snapshot, require_removed_native_payload,
    require_expected_mcp_definitions, require_unchanged_native_scope,
    verified_private_pi_binding,
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
            native_root = Path(directory) / "profile"
            package = native_root / "extensions" / "package-v1"
            package.mkdir(parents=True)
            manifest = b'{"name":"package","version":"1.0.0"}'
            (package / "plugin.json").write_bytes(manifest)
            skill = package / "skills" / "correct-skill" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("original skill", encoding="utf-8")
            (package / "mcp.json").write_text(
                json.dumps({"mcpServers": {"correct-server": {"url": "https://example.invalid"}}}),
                encoding="utf-8")
            receipt = {"clients": [{
                "client_id": "pi",
                "native_profile_root": str(native_root),
                "target_locator": str(package),
                "physical_artifact_id": package.name,
                "package_revision": {
                    "manifest_digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
                },
            }]}
            source_files = {
                "plugin.json": manifest,
                "mcp.json": (package / "mcp.json").read_bytes(),
                "skills/correct-skill/SKILL.md": skill.read_bytes(),
            }
            source_read = source_files.__getitem__
            skills, servers, roots = expected_package_native_names(
                native_root, receipt, "package", "mixed", source_read=source_read)
            self.assertEqual(skills, {"correct-skill/SKILL.md"})
            self.assertEqual(servers, {"correct-server": {"url": "https://example.invalid"}})
            self.assertEqual(roots, (package,))
            wrong_receipt = copy.deepcopy(receipt)
            wrong_receipt["clients"][0]["package_revision"]["manifest_digest"] = (
                "sha256:" + "0" * 64)
            with self.assertRaisesRegex(RuntimeError, "source unavailable"):
                expected_package_native_names(
                    native_root, wrong_receipt, "package", "mixed",
                    source_read=source_read)
            with self.assertRaisesRegex(RuntimeError, "manifest differs"):
                expected_package_native_names(
                    native_root, receipt, "other-package", "mixed",
                    source_read=source_read)

    def test_public_pi_list_requires_exact_persisted_private_binding(self) -> None:
        # The released 0.1.102 list API intentionally omits private locators.
        # Only its matching local state receipt may authorize native inspection.
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory) / "state"
            state_root.mkdir()
            path = state_root / "state-v2.json"
            revision = "a" * 40
            digest = "sha256:" + "b" * 64
            tree = "sha256:" + "c" * 64
            package = Path(directory) / "profile" / "extensions" / "bound"
            private_binding = {
                "client_binding_id": "owned-pi", "client_id": "pi", "scope": "user",
                "native_profile_root": str(package.parent.parent),
                "physical_artifact_id": "bound", "target_locator": str(package),
                "materialization": "materialized",
                "verification": "installation_verified",
                "package_revision": {
                    "resolved_revision": revision, "tree_digest": tree,
                    "manifest_digest": digest,
                },
            }
            public = {
                "installation_id": "owned-installation", "name": "bound-plugin",
                "clients": [{
                    "client_id": "pi", "scope": "user",
                    "materialization": "materialized",
                    "verification": "installation_verified",
                    "package_revision": {
                        "resolved_revision": revision, "tree_digest": tree,
                        "manifest_digest": digest,
                    },
                }],
            }
            state = {"schema_version": 5, "installations": [{
                "installation_id": "owned-installation",
                "declared_name": "bound-plugin",
                "source": {
                    "repository": "owner/repo",
                    "package_subpath": "plugins/bound", "resolved_revision": revision,
                },
                "package": {"manifest_digest": digest},
                "clients": {"owned-pi": private_binding},
            }]}
            def write() -> None:
                path.write_text(json.dumps(state), encoding="utf-8")
            def check(view: dict = public, scope: str = "user") -> dict:
                return verified_private_pi_binding(
                    path, view, "bound-plugin", revision,
                    "owner/repo", "plugins/bound", scope)
            write()
            self.assertNotIn("target_locator", public["clients"][0])
            self.assertEqual(check(), private_binding)
            wrong_public = copy.deepcopy(public)
            wrong_public["clients"][0]["package_revision"]["manifest_digest"] = (
                "sha256:" + "0" * 64)
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                check(wrong_public)
            with self.assertRaisesRegex(RuntimeError, "public Pi receipt"):
                check(scope="project")
            state["installations"][0]["source"]["package_subpath"] = "plugins/other"
            write()
            with self.assertRaisesRegex(RuntimeError, "private Pi source"):
                check()
            state["installations"][0]["source"]["package_subpath"] = "plugins/bound"
            state["installations"][0]["clients"]["second"] = {
                **private_binding, "client_binding_id": "second"}
            write()
            with self.assertRaisesRegex(RuntimeError, "unique selected scope"):
                check()
            state["installations"][0]["clients"].pop("second")
            state["schema_version"] = True
            write()
            with self.assertRaisesRegex(RuntimeError, "schema"):
                check()
            state["schema_version"] = 5
            write()
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "absent or redirected"):
                check()
            # Windows CI may not grant symlink creation privilege; absence is
            # covered on every OS and symlink refusal on POSIX.
            if sys.platform != "win32":
                path.symlink_to(state_root / "missing")
                with self.assertRaisesRegex(RuntimeError, "absent or redirected"):
                    check()

    def test_copied_manifest_cannot_authorize_foreign_mcp_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native_root = root / "profile"
            package = native_root / "extensions" / "bound-artifact"
            (package / "runtime").mkdir(parents=True)
            launcher = package / "runtime" / "launcher.mjs"
            launcher.write_text("trusted launcher", encoding="utf-8")
            manifest = b'{"name":"bound-plugin","version":"1.0.0"}'
            (package / "plugin.json").write_bytes(manifest)
            declared = {"local": {
                "command": "node", "args": ["${PLUGIN_ROOT}/runtime/launcher.mjs"]}}
            (package / "mcp.json").write_text(
                json.dumps({"mcpServers": declared}), encoding="utf-8")
            receipt = {"clients": [{
                "client_id": "pi",
                "native_profile_root": str(native_root),
                "target_locator": str(package),
                "physical_artifact_id": package.name,
                "package_revision": {
                    "manifest_digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
                },
            }]}
            source_files = {
                "plugin.json": manifest,
                "mcp.json": (package / "mcp.json").read_bytes(),
                "runtime/launcher.mjs": launcher.read_bytes(),
            }
            source_read = source_files.__getitem__
            # A copied manifest and MCP file are not an installer-owned binding.
            foreign = root / "unrelated" / "plausible-package"
            shutil.copytree(package, foreign)
            foreign_launcher = foreign / "runtime" / "launcher.mjs"
            foreign_launcher.write_text("different executable", encoding="utf-8")
            skills, servers, roots = expected_package_native_names(
                native_root, receipt, "bound-plugin", "mcp",
                source_read=source_read)
            self.assertEqual(skills, set())
            self.assertEqual(servers, declared)
            self.assertEqual(roots, (package,))
            baseline = (skills, servers, roots)
            require_pinned_native_snapshot(
                native_root, receipt, "bound-plugin", "mcp", source_read, baseline)
            require_expected_mcp_definitions(
                {"local": {"command": "node", "args": [str(launcher)]}},
                servers, roots)
            with self.assertRaisesRegex(RuntimeError, "native Pi MCP"):
                require_expected_mcp_definitions(
                    {"local": {"command": "node", "args": [str(foreign_launcher)]}},
                    servers, roots)
            # Tampering inside the *owned* artifact must not become the
            # expected configuration merely because the private state and
            # plugin.json digest remain unchanged.
            (package / "mcp.json").write_text(
                json.dumps({"mcpServers": {"local": {
                    "command": "node", "args": ["--tampered"]}}}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "immutable pinned source"):
                require_pinned_native_snapshot(
                    native_root, receipt, "bound-plugin", "mcp", source_read, baseline)
            (package / "mcp.json").write_bytes(source_files["mcp.json"])
            launcher.write_text("tampered bound launcher", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "immutable pinned source"):
                require_pinned_native_snapshot(
                    native_root, receipt, "bound-plugin", "mcp", source_read, baseline)
            launcher.write_bytes(source_files["runtime/launcher.mjs"])
            # Deleting the bound artifact must fail closed despite the copy.
            shutil.rmtree(package)
            with self.assertRaises(RuntimeError):
                expected_package_native_names(
                    native_root, receipt, "bound-plugin", "mcp",
                    source_read=source_read)



    def test_run_case_refuses_mutated_bound_launcher_after_repair(self) -> None:
        # Offline lifecycle simulation: invoke the actual run_case checkpoints
        # and mutate only the owned package during the repair operation.
        revision = "a" * 40
        manifest = b'{"name":"fixture","version":"1.0.0"}'
        source_mcp = json.dumps({"mcpServers": {"local": {
            "command": "node",
            "args": ["${PLUGIN_ROOT}/runtime/launcher.mjs"],
        }}}).encode("utf-8")
        trusted = {
            "plugin.json": manifest,
            "mcp.json": source_mcp,
            "runtime/launcher.mjs": b"trusted launcher",
        }
        digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        tree_digest = "sha256:" + "c" * 64

        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            case_root = scratch / "offline-user"
            native_root = case_root / "home" / ".pi" / "agent"
            package = native_root / "extensions" / "bound"
            launcher = package / "runtime" / "launcher.mjs"
            state_file = case_root / "state" / "state-v2.json"
            binding = {
                "client_binding_id": "bound-pi", "client_id": "pi", "scope": "user",
                "native_profile_root": str(native_root),
                "target_locator": str(package),
                "physical_artifact_id": "bound",
                "materialization": "materialized",
                "verification": "installation_verified",
                "package_revision": {
                    "resolved_revision": revision, "tree_digest": tree_digest,
                    "manifest_digest": digest,
                },
            }
            public = {
                "installation_id": "offline-install", "name": "fixture",
                "clients": [{
                    "client_id": "pi", "scope": "user",
                    "materialization": "materialized",
                    "verification": "installation_verified",
                    "package_revision": binding["package_revision"].copy(),
                }],
            }
            state = {
                "schema_version": 5,
                "installations": [{
                    "installation_id": "offline-install", "declared_name": "fixture",
                    "source": {
                        "repository": "example/fixture",
                        "package_subpath": "plugins/example",
                        "resolved_revision": revision,
                    },
                    "package": {"manifest_digest": digest},
                    "clients": {"bound-pi": binding},
                }],
            }

            def fake_command(argv, cwd, env, *, timeout=180):
                verb = argv[1]
                result = {"argv": [Path(argv[0]).name, *argv[1:]],
                          "exit": 0, "data": {}}
                if verb == "add" and not package.exists():
                    launcher.parent.mkdir(parents=True)
                    (package / "plugin.json").write_bytes(manifest)
                    (package / "mcp.json").write_bytes(source_mcp)
                    launcher.write_bytes(trusted["runtime/launcher.mjs"])
                    foreign = {"command": "node", "args": ["--version"]}
                    (native_root / "mcp.json").write_text(json.dumps({
                        "mcpServers": {
                            "foreign-neighbor": foreign,
                            "local": {"command": "node", "args": [str(launcher)]},
                        },
                    }), encoding="utf-8")
                    state_file.write_text(json.dumps(state), encoding="utf-8")
                if verb == "list":
                    result["data"] = {"installations": [public]}
                if verb == "update":
                    result["exit"] = 1
                    result["error_tail"] = (
                        "direct full-SHA installations require explicit switch")
                if verb == "repair":
                    launcher.write_bytes(b"tampered during repair")
                return result

            with (patch("pi_direct_source_e2e.command",
                        side_effect=fake_command),
                  patch("pi_direct_source_e2e.clone_verified_cli_cache",
                        side_effect=lambda seed, destination: destination.mkdir()),
                  patch("pi_direct_source_e2e.pinned_source_bytes",
                        side_effect=lambda repo, sha, subpath, relative: trusted[relative])):
                result = run_case(
                    "agentplugins", revision, scratch,
                    ("offline", "fixture", "plugins/example", revision,
                     "mcp", "example/fixture"),
                    "user", scratch / "seed")
            self.assertEqual(result["status"], "failed")
            self.assertIn("immutable pinned source", result.get("error", ""))
            self.assertTrue(any(op["argv"][1] == "repair"
                                for op in result["operations"]))

    def test_projected_mcp_accepts_only_source_derived_stdio_rewrites(self) -> None:
        from pi_direct_source_e2e import verified_projected_mcp_source
        with tempfile.TemporaryDirectory() as directory:
            case_root = Path(directory)
            package = case_root / "profile" / "extensions" / "owned"
            package.mkdir(parents=True)
            data = case_root / "state" / "plugin-data"
            schema = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
            authored = {"$schema": schema, "mcpServers": {"owned": {
                "type": "stdio", "command": "node",
                "args": ["${PLUGIN_ROOT}/runtime/launcher.mjs"],
            }}}
            source_bytes = json.dumps(authored, indent=2).encode()
            projected = {"$schema": schema, "mcpServers": {"owned": {
                "type": "stdio", "command": "node",
                # Go ApplyStdioDataContract performs literal token replacement
                # in args. On Windows the authored forward slash remains after
                # the native PLUGIN_ROOT; it is not filepath-normalized.
                "args": [str(package) + "/runtime/launcher.mjs"],
                "env": {"PLUGIN_ROOT": str(package), "PLUGIN_DATA": str(data)},
                "cwd": str(package),
            }}}
            mcp = package / "mcp.json"
            def write(value: dict) -> None:
                mcp.write_text(json.dumps(value), encoding="utf-8")
            write(projected)
            source_read = lambda relative: source_bytes
            self.assertEqual(
                verified_projected_mcp_source(package, source_read, case_root),
                authored["mcpServers"])
            for field, wrong in (
                ("command", "other"),
                ("args", [str(case_root / "unrelated.mjs")]),
                ("cwd", str(case_root / "wrong")),
                ("env", {"PLUGIN_ROOT": str(package), "PLUGIN_DATA": str(data),
                         "FOREIGN": "injected"}),
            ):
                with self.subTest(field=field):
                    tampered = copy.deepcopy(projected)
                    tampered["mcpServers"]["owned"][field] = wrong
                    write(tampered)
                    with self.assertRaisesRegex(
                        RuntimeError, "projected Pi MCP configuration differs"
                    ):
                        verified_projected_mcp_source(package, source_read, case_root)
            tampered = copy.deepcopy(projected)
            tampered["mcpServers"]["owned"]["env"]["PLUGIN_ROOT"] = str(case_root / "foreign")
            write(tampered)
            with self.assertRaisesRegex(RuntimeError, "plugin root differs"):
                verified_projected_mcp_source(package, source_read, case_root)
            tampered = copy.deepcopy(projected)
            tampered["mcpServers"]["owned"]["env"]["PLUGIN_DATA"] = str(case_root.parent / "foreign")
            write(tampered)
            with self.assertRaisesRegex(RuntimeError, "escaped disposable ownership"):
                verified_projected_mcp_source(package, source_read, case_root)
            tampered = copy.deepcopy(projected)
            tampered["mcpServers"]["foreign"] = {"url": "https://evil.invalid"}
            write(tampered)
            with self.assertRaisesRegex(RuntimeError, "projected Pi MCP configuration differs"):
                verified_projected_mcp_source(package, source_read, case_root)

    def test_pinned_source_reader_uses_exact_git_sha_and_refuses_redirect(self) -> None:
        # Offline transport contract: no live source fetch or credentials.
        revision = "a" * 40
        url = ("https://raw.githubusercontent.com/example/fixture/" + revision
               + "/plugins/example/mcp.json")

        class Response:
            status = 200

            def __init__(self, origin: str):
                self.origin = origin

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def geturl(self):
                return self.origin

            def read(self, size: int) -> bytes:
                self_size = size
                if self_size <= 0:
                    raise AssertionError("bounded read required")
                return b"immutable-mcp"

        pinned_source_bytes.cache_clear()
        with patch("pi_direct_source_e2e.subprocess.run") as git:
            git.return_value.returncode = 0
            git.return_value.stdout = b"pinned Git object"
            self.assertEqual(
                pinned_source_bytes(
                    "777genius/universal-agent-plugins-registry",
                    revision, "plugins/example", "mcp.json"),
                b"pinned Git object")
            self.assertEqual(
                git.call_args.args[0],
                ["git", "show", f"{revision}:plugins/example/mcp.json"])
        pinned_source_bytes.cache_clear()
        with patch("pi_direct_source_e2e.urlopen", return_value=Response(url)) as fetch:
            self.assertEqual(
                pinned_source_bytes("example/fixture", revision,
                                    "plugins/example", "mcp.json"),
                b"immutable-mcp")
            self.assertEqual(fetch.call_args.args[0].full_url, url)
            self.assertEqual(fetch.call_args.kwargs["timeout"], 45)
        with patch("pi_direct_source_e2e.urlopen",
                   return_value=Response("https://untrusted.example/mcp.json")):
            with self.assertRaisesRegex(RuntimeError, "left the immutable GitHub origin"):
                pinned_source_bytes("example/fixture", revision,
                                    "plugins/example", "other.json")
        for relative in ("../other.json", "/absolute", "runtime\\launcher.mjs"):
            with self.subTest(relative=relative), self.assertRaisesRegex(
                RuntimeError, "unsafe repository or package path"
            ):
                pinned_source_bytes("example/fixture", revision,
                                    "plugins/example", relative)
        pinned_source_bytes.cache_clear()

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
            verified_roots = (root / "package",)
            require_expected_mcp_definitions(actual, expected, verified_roots)
            unrelated = root / "unrelated" / "runtime" / "launcher.mjs"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text(launcher.read_text(encoding="utf-8"), encoding="utf-8")
            mutations = (
                lambda data: data.__setitem__("local", {}),
                lambda data: data["remote"].__setitem__("url", "https://other.invalid"),
                lambda data: data["local"].__setitem__("command", "other"),
                lambda data: data["local"].__setitem__("args", ["/tmp/other/launcher.mjs"]),
                lambda data: data["local"].__setitem__("args", [str(unrelated)]),
            )
            for mutation in mutations:
                changed = copy.deepcopy(actual)
                mutation(changed)
                with self.assertRaisesRegex(RuntimeError, "native Pi MCP"):
                    require_expected_mcp_definitions(changed, expected, verified_roots)

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
