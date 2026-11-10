"""Offline Project contract negatives; no native CLI or account/runtime claim."""
from __future__ import annotations

import copy
import argparse
import base64
import json
import io
from contextlib import redirect_stderr
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from tests.test_catalog_publication_readiness import catalog, arguments, PROJECT_RELEASE_FIXTURE
from tests import test_catalog_managed_readiness as managed_tests
import catalog_managed_readiness as managed
import catalog_project_readiness as project
import catalog_publication_readiness as gate


# Deliberately synthetic CLI identity used only by offline contract fixtures.
RELEASE_FIXTURE = PROJECT_RELEASE_FIXTURE["cli"]

class ProjectReadinessTests(unittest.TestCase):
    def setUp(self):
        release = patch.object(project, "RELEASE", PROJECT_RELEASE_FIXTURE)
        release.start()
        self.addCleanup(release.stop)
        self.snapshot = catalog()
        self.case = project.expected(self.snapshot, gate.selected)

    def test_five_positive_user_six_positive_project_and_user_refusal(self):
        user = managed.expected(self.snapshot, gate.selected)
        self.assertEqual(tuple(user["targets"]), managed.LEGACY_CLIENTS)
        self.assertEqual(tuple(self.case["targets"]), managed.CLIENTS)
        self.assertEqual(self.case["placement_scope"], "project")
        self.assertEqual(self.case["signed_source_scope"], "user")
        self.assertEqual(len(managed.coverage(user)), 20)
        self.assertEqual(len(project.source_coverage(self.case)), 24)
        self.assertEqual(self.case["user_refusal"]["outcome"], "refused")
        self.assertNotIn("native_plugin_listing", self.case["proof"])
        self.assertEqual(self.case["proof"]["account_runtime"], "not_tested")
        baseline = copy.deepcopy(self.snapshot)
        baseline["distributions"] = [item for item in baseline["distributions"] if item["id"] != managed.ROOT]
        gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot), project_case=self.case)
        self.assertEqual(len([(selection, client) for selection, clients in gate.plan(self.snapshot) for client in clients]), 380)

    def test_historical_five_source_snapshot_has_no_project_case(self):
        prior = copy.deepcopy(self.snapshot)
        root = next(item for item in prior["distributions"] if item["id"] == managed.ROOT)
        root["release_policies"][0]["targets"] = [target for target in root["release_policies"][0]["targets"] if target["client"] != "copilot"]
        with patch.object(project, "RELEASE", None):
            self.assertIsNone(project.expected(prior, gate.selected))

    def test_release_authority_is_explicit_unset_and_has_exact_authenticated_assets(self):
        with patch.object(project, "RELEASE", None), self.assertRaisesRegex(ValueError, "identity is unset"):
            project.reviewed_release()
        self.assertEqual(project.reviewed_release(), PROJECT_RELEASE_FIXTURE)
        copied = project.reviewed_release()
        copied["cli"]["version"] = "modified"
        self.assertEqual(project.RELEASE, PROJECT_RELEASE_FIXTURE)
        for mutation in (
            lambda value: value.pop("checksums_digest"),
            lambda value: value.update(manifest_digest="unverified"),
            lambda value: value.update(download_url="https://example.invalid/cli"),
        ):
            value = copy.deepcopy(PROJECT_RELEASE_FIXTURE)
            mutation(value)
            with self.subTest(mutation=mutation), patch.object(project, "RELEASE", value), self.assertRaises(ValueError):
                project.reviewed_release()
        with self.assertRaises(TypeError):
            gate.expected_artifact(self.snapshot, self.snapshot, {}, {}, project_cli=RELEASE_FIXTURE)

    def entrypoint_argv(self, root, mode, *, project_binary=True):
        argv = [mode, "--feed", str(root / "feed"), "--baseline-feed", str(root / "baseline"),
                "--trusted-keys", str(root / "keys.json")]
        for field, value in vars(arguments(self.snapshot)).items():
            argv.extend(["--" + field.replace("_", "-"), str(value)])
        if mode == "verify":
            argv.extend(["--artifact", str(root / "artifact.json")])
        else:
            for name in ("binary", "managed-binary", "claude", "copilot", "opencode", "sandbox", "output"):
                argv.extend(["--" + name, str(root / name)])
            if project_binary:
                argv.extend(["--project-binary", str(root / "project-binary")])
        return argv

    def test_produce_and_verify_entrypoints_require_fixed_project_contract(self):
        baseline = {**self.snapshot, "sequence": 19}
        ctx = {"sequence": 20, "snapshot_digest": "sha256:" + "e" * 64}
        baseline_identity = {"sequence": 19, "snapshot_digest": "sha256:" + "f" * 64}
        expected = gate.expected_artifact(self.snapshot, baseline, baseline_identity, ctx)
        self.assertEqual(expected["project_dependencies"]["cli"], PROJECT_RELEASE_FIXTURE["cli"])
        for mode in ("produce", "verify"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact = root / "artifact.json"
                artifact.write_bytes(gate.publication.canonical_json(expected))
                def invoke(*, unset=False, project_binary=True):
                    with patch.object(gate, "load_feed", side_effect=((self.snapshot, ctx), (baseline, baseline_identity))), \
                            patch.object(gate, "context", return_value=ctx), \
                            patch.object(gate, "produce") as producer, \
                            patch.object(project, "RELEASE", None if unset else PROJECT_RELEASE_FIXTURE), \
                            redirect_stderr(io.StringIO()):
                        result = gate.main(self.entrypoint_argv(root, mode, project_binary=project_binary))
                    return result, producer
                result, producer = invoke()
                self.assertEqual(result, 0)
                if mode == "produce":
                    self.assertEqual(producer.call_args.args[2], expected)
                    self.assertEqual(producer.call_args.args[0].project_binary, root / "project-binary")
                    result, producer = invoke(project_binary=False)
                    self.assertEqual(result, 1)
                    producer.assert_not_called()
                else:
                    producer.assert_not_called()
                    omitted = copy.deepcopy(expected)
                    omitted.pop("project_dependencies")
                    artifact.write_bytes(gate.publication.canonical_json(omitted))
                    self.assertEqual(invoke()[0], 1)
                    forged = copy.deepcopy(expected)
                    forged["project_dependencies"]["cli"]["binary_digest"] = "sha256:" + "0" * 64
                    artifact.write_bytes(gate.publication.canonical_json(forged))
                    self.assertEqual(invoke()[0], 1)
                    artifact.write_bytes(gate.publication.canonical_json(expected))
                result, producer = invoke(unset=True)
                self.assertEqual(result, 1)
                producer.assert_not_called()

    def test_unreviewed_source_grants_floor_and_release_pin_refused(self):
        for mutate in (
            lambda root: root["release_policies"][0]["targets"].append({"client": "kiro", "scopes": ["user"], "authentication": "required", "delivery": "managed"}),
            lambda root: root["release_policies"][0]["targets"][0].update(scopes=["project"]),
            lambda root: root["release_policies"][0].update(minimum_installer_version="0.1.90"),
            lambda root: root["releases"][0].update(package_version="0.1.1"),
        ):
            value = copy.deepcopy(self.snapshot)
            mutate(next(item for item in value["distributions"] if item["id"] == managed.ROOT))
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, gate.registry.RegistryError)):
                project.expected(value, gate.selected)
        for mutate in (
            lambda cli: cli.update(version="0.1.102"),
            lambda cli: cli.update(tag="main"),
            lambda cli: cli.update(commit="main"),
            lambda cli: cli.update(binary_digest="unverified"),
            lambda cli: cli.update(download_url="https://example.invalid/cli"),
        ):
            cli = copy.deepcopy(RELEASE_FIXTURE)
            mutate(cli)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                with patch.object(project, "RELEASE", {**PROJECT_RELEASE_FIXTURE, "cli": cli}):
                    project.expected(self.snapshot, gate.selected)

    def test_canonical_artifact_rejects_missing_or_forged_project_case(self):
        expected = gate.expected_artifact(self.snapshot, self.snapshot, {"sequence": 19},
                                          {"sequence": 20})
        gate.validate_artifact(copy.deepcopy(expected), expected)
        for mutate in (
            lambda value: value.pop("project_dependencies"),
            lambda value: value["project_dependencies"].update(placement_scope="user"),
            lambda value: value["project_dependencies"].update(signed_source_scope="project"),
            lambda value: value["project_dependencies"]["cli"].update(version="0.1.102"),
            lambda value: value["project_dependencies"]["targets"].append("kiro"),
            lambda value: value["project_dependencies"]["closure"][0].update(tree_digest="sha256:" + "0" * 64),
            lambda value: value["project_dependencies"]["closure"][0]["policy"]["targets"][0].update(scopes=["project"]),
            lambda value: value["project_dependencies"]["user_refusal"].update(outcome="passed"),
            lambda value: value["project_dependencies"]["proof"].update(native_project_cleanup="not_tested"),
            lambda value: value["managed_dependencies"]["targets"].insert(2, "copilot"),
            lambda value: value["context"].update(sequence=21),
        ):
            value = copy.deepcopy(expected)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                gate.validate_artifact(value, expected)

    def test_reuses_exact_state_validator_with_project_owner_and_scope(self):
        helper = managed_tests.ManagedReadinessTests()
        helper.case = self.case
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state, ctx, aliases = helper.state(root)
            for installation in state["installations"]:
                for binding in installation["clients"].values():
                    binding["scope"] = "project"
            for receipt in state["environment_receipts"]:
                receipt["environment_id"] = "project-default"
            managed.validate_state(state, self.case, ctx, root, aliases)
            for mutate in (
                lambda value: value["environment_receipts"][0].update(environment_id="user-default"),
                lambda value: value["installations"][0]["clients"]["copilot"].update(scope="user"),
                lambda value: value["installations"][0]["directory"].update(snapshot_digest="sha256:" + "0" * 64),
                lambda value: value["installations"][0]["clients"]["copilot"]["package_revision"].update(resolved_revision="f" * 40),
            ):
                value = copy.deepcopy(state)
                mutate(value)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    managed.validate_state(value, self.case, ctx, root, aliases)

    def fixture(self, root):
        workspace, store = root / "workspace", root / "workspace/.uap/store"
        workspace.mkdir()
        installations = {}
        for selected in self.case["closure"]:
            package = store / "packages/agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
            package.mkdir(parents=True)
            (package / "plugin.json").write_text(json.dumps({"name": selected["product_id"], "version": selected["package_version"]}))
            is_root = selected["distribution_id"] == managed.ROOT
            servers = {} if is_root else {selected["product_id"]: {"type": "streamable-http", "url": "https://example.invalid/mcp"}}
            if is_root:
                skill = package / "skills/campaign-planning/SKILL.md"
                skill.parent.mkdir(parents=True)
                skill.write_text("immutable Skill bytes\n")
            else:
                (package / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
            bindings = {}
            for client in project.CLIENTS:
                target = (workspace / project.SKILL_ROOTS[client] / selected["product_id"] if client == "claude"
                          else workspace / ".uap/managed" / client / selected["product_id"])
                target.mkdir(parents=True)
                if client == "claude":
                    manifest = {"name": selected["product_id"], "version": selected["package_version"]}
                    manifest["skills" if is_root else "mcpServers"] = "./.agentplugins-runtime/skills/" if is_root else "./.mcp.json"
                    (target / ".claude-plugin").mkdir()
                    (target / ".claude-plugin/plugin.json").write_text(json.dumps(manifest))
                objects = []
                if is_root:
                    native = target / ".agentplugins-runtime/skills/campaign-planning" if client == "claude" else workspace / project.SKILL_ROOTS[client] / "campaign-planning"
                    native.mkdir(parents=True)
                    (native / "SKILL.md").write_text("immutable Skill bytes\n")
                    if client != "claude":
                        objects.append({"kind": client + "_project_skill_directory", "logical_name": "campaign-planning", "path": str(native)})
                elif client == "claude":
                    (target / ".mcp.json").write_text(json.dumps(servers))
                else:
                    path = workspace / project.MCP_PATHS[client]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    name = selected["product_id"]
                    if client == "codex":
                        with path.open("a") as stream:
                            stream.write(f'\n[mcp_servers."{name}"]\nurl="https://example.invalid/mcp"\n')
                    else:
                        key = "mcp" if client == "opencode" else "mcpServers"
                        value = json.loads(path.read_text()) if path.exists() else {key: {}}
                        value[key][name] = servers[name]
                        path.write_text(json.dumps(value))
                    objects.append({"kind": client + "_project_mcp_server", "logical_name": name, "path": str(path)})
                bindings[client] = {"client_id": client, "scope": "project", "verification": "installation_verified",
                                    "target_locator": str(target), "native_objects": objects, "affected_surfaces": [client],
                                    "physical_artifact_id": client + "-" + selected["product_id"]}
            installations[selected["distribution_id"]] = {"clients": bindings}
        return workspace, store, installations

    def test_actual_project_resource_proof_rejects_missing_receipts_paths_and_bytes(self):
        for mutation in ("none", "skill_bytes", "missing_member", "wrong_scope", "wrong_path", "wrong_endpoint", "missing_receipt", "user_listing", "missing_surfaces", "sibling_surface", "missing_claude_reference", "wrong_claude_version"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                workspace, store, installations = self.fixture(Path(temporary))
                binding = installations[managed.ROOT]["clients"]["copilot"]
                path = workspace / project.MCP_PATHS["copilot"]
                if mutation == "skill_bytes":
                    (workspace / ".github/skills/campaign-planning/SKILL.md").write_text("changed")
                elif mutation == "missing_member":
                    path.write_text('{"mcpServers": {}}')
                elif mutation == "wrong_scope":
                    binding["scope"] = "user"
                elif mutation == "wrong_path":
                    binding["native_objects"][0]["path"] = str(workspace / "wrong")
                elif mutation == "wrong_endpoint":
                    value = json.loads(path.read_text()); value["mcpServers"]["notion"]["url"] = "https://changed.invalid"; path.write_text(json.dumps(value))
                elif mutation == "missing_receipt":
                    binding["native_objects"] = []
                elif mutation == "user_listing":
                    binding.update(native_objects=[], native_plugin_listing="passed")
                elif mutation == "missing_surfaces":
                    binding.pop("affected_surfaces")
                elif mutation == "sibling_surface":
                    binding["affected_surfaces"].append("kiro")
                elif mutation in ("missing_claude_reference", "wrong_claude_version"):
                    manifest = Path(installations[managed.ROOT]["clients"]["claude"]["target_locator"]) / ".claude-plugin/plugin.json"
                    value = json.loads(manifest.read_text())
                    if mutation == "missing_claude_reference":
                        value.pop("skills")
                    else:
                        value["version"] = "9.0.0"
                    manifest.write_text(json.dumps(value))
                if mutation == "none":
                    project.validate_native_resources(installations, self.case, workspace, store)
                else:
                    with self.assertRaises(ValueError):
                        project.validate_native_resources(installations, self.case, workspace, store)

    def test_cleanup_refuses_native_member_leftover_at_either_copilot_location(self):
        for path in (".github/mcp.json", ".mcp.json"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = root / path
                config.parent.mkdir(exist_ok=True)
                config.write_text('{"mcpServers":{"notion":{"url":"https://example.invalid"}}}')
                installations = {"notion": {"clients": {"copilot": {"client_id": "copilot", "target_locator": str(root / ".uap/absent"),
                    "native_objects": [{"kind": "copilot_project_mcp_server", "logical_name": "notion", "path": str(root / ".github/mcp.json")}]}}}}
                with self.assertRaisesRegex(ValueError, "MCP member remains"):
                    project.validate_native_cleanup(installations, root)
                config.write_text('{"mcpServers":{}}')
                project.validate_native_cleanup(installations, root)

    def test_project_actions_and_applied_receipts_require_exact_scope_and_identity(self):
        aliases = {distribution: distribution.split("/")[1] for distribution in managed.PINS}
        installations = {distribution: {"installation_id": "i-" + alias} for distribution, alias in aliases.items()}
        actions = [{"alias": aliases[managed.ROOT], "client_id": client, "action": "repair"} for client in project.CLIENTS]
        results = [{"client_id": client, "operation": "repair", "installation_id": installations[managed.ROOT]["installation_id"], "outcome": "completed"} for client in project.CLIENTS]
        result = {"scope": "project", "outcome": "completed", "actions": actions, "results": results}
        project.validate_operation(result, aliases, project.CLIENTS, operation="repair", installations=installations)
        for mutate in (
            lambda value: value.update(scope="user"),
            lambda value: value.update(outcome="refused"),
            lambda value: value["actions"].pop(),
            lambda value: value["actions"][0].update(alias="notion"),
            lambda value: value["actions"][0].update(client_id="kiro"),
            lambda value: value["results"].pop(),
            lambda value: value["results"][0].update(operation="install"),
            lambda value: value["results"][0].update(installation_id="unrelated"),
        ):
            value = copy.deepcopy(result)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                project.validate_operation(value, aliases, project.CLIENTS, operation="repair", installations=installations)

    def test_stdio_project_resource_binds_released_launcher_context_and_child_arguments(self):
        for encoded in (False, True):
            with self.subTest(encoded=encoded), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                package = root / ".uap/managed/copilot/playwright"
                launcher = package / "io.github.777genius.agentplugins/managed-stdio-v1/agentplugins"
                launcher.parent.mkdir(parents=True)
                launcher.write_bytes(b"released binary fixture")
                source = {"command": "node", "args": ["${PLUGIN_ROOT}/runtime/launcher.mjs"]}
                child = ["node", str(package / "runtime/launcher.mjs")]
                wire = [base64.b64encode(arg.encode()).decode() for arg in child] if encoded else child
                entry = {"command": str(launcher), "args": ["--internal-stdio-v1", str(package),
                         str(root / ".uap/plugin-data/backend"), str(package), "plugin",
                         "--argv-base64-v1" if encoded else "--", *wire]}
                digest = gate.digest(launcher.read_bytes())
                project.validate_server(entry, source, package, cli_digest=digest, project_root=root, data_root=root / ".uap/plugin-data/backend")
                for mutate in (
                    lambda value: value.update(command="/usr/bin/agentplugins"),
                    lambda value: value["args"].__setitem__(1, str(root / "other")),
                    lambda value: value["args"].__setitem__(2, str(root / "home")),
                    lambda value: value["args"].__setitem__(2, str(root / ".uap/plugin-data/another-owned-backend")),
                    lambda value: value["args"].__setitem__(3, str(root)),
                    lambda value: value["args"].__setitem__(-1, "wrong"),
                ):
                    value = copy.deepcopy(entry)
                    mutate(value)
                    with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                        project.validate_server(value, source, package, cli_digest=digest, project_root=root, data_root=root / ".uap/plugin-data/backend")
                with self.assertRaises(ValueError):
                    project.validate_server(entry, source, package, cli_digest="sha256:" + "0" * 64, project_root=root, data_root=root / ".uap/plugin-data/backend")

    def test_user_refusal_requires_reason_nonzero_and_zero_native_portable_state_mutation(self):
        for behavior in ("refused", "directory_cache", "success", "unrelated_error", "native_mutation", "portable_mutation", "durable_mutation", "journal_mutation", "unrelated_mention", "cache_wrong_sequence"):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tools = root / "tools"
                tools.mkdir()
                args = argparse.Namespace(binary=tools / "agentplugins", project_binary=tools / "agentplugins",
                                          claude=tools / "claude", copilot=tools / "copilot", codex=tools / "codex",
                                          opencode=tools / "opencode", inspector=None, npx=None)
                for tool in tools.iterdir():
                    self.fail("fresh tools directory was not empty")
                for name in ("agentplugins", "claude", "copilot", "codex", "opencode"):
                    tool = tools / name
                    tool.write_text("#!/bin/sh\nexit 1\n")
                    tool.chmod(0o700)
                fixture = Path(__file__).parent / "fixtures/directory-publication"
                args.trusted_keys = fixture / "trusted-keys.json"
                snapshot_bytes = (fixture / "snapshot.json").read_bytes()
                ctx = {"directory_origin": "https://example.invalid/exact-ledger/", "sequence": 15, "snapshot_digest": gate.digest(snapshot_bytes)}
                case = copy.deepcopy(self.case)
                case["cli"]["binary_digest"] = gate.digest(args.binary.read_bytes())
                def invoke(argv, **kwargs):
                    self.assertEqual(argv[1:8], ["add", "marketing-kit", "--target", "copilot", "--scope", "user", "--format"])
                    profile = Path(kwargs["env"]["AGENTPLUGINS_HOME"])
                    if behavior in ("directory_cache", "cache_wrong_sequence"):
                        cache = profile / "directory-v1-cache.json"
                        cache.write_text(json.dumps({"schema_version": 1, "sequence": 14 if behavior == "cache_wrong_sequence" else 15, "snapshot": base64.b64encode(snapshot_bytes).decode(), "envelope": base64.b64encode((fixture / "envelope-current.json").read_bytes()).decode()}))
                        cache.chmod(0o600)
                    elif behavior == "native_mutation":
                        (Path(kwargs["env"]["HOME"]) / ".copilot/mcp-config.json").write_text("{}")
                    elif behavior == "portable_mutation":
                        (kwargs["cwd"] / "uap.toml").write_text("changed")
                    elif behavior == "durable_mutation":
                        (profile / "state-v2.json").write_text("{}")
                    elif behavior == "journal_mutation":
                        (profile / "operations-v2").mkdir()
                        (profile / "operations-v2/open.json").write_text("{}")
                    return SimpleNamespace(returncode=0 if behavior == "success" else 1,
                                           stdout="", stderr=("network timeout" if behavior == "unrelated_error" else
                                            "network timeout; source log mentioned missing vscode" if behavior == "unrelated_mention" else
                                            'agentplugins: no eligible directory release for "marketing-kit": 777genius/marketing-kit: release does not support complete target set; missing vscode'))
                with patch.object(gate, "child", side_effect=invoke):
                    if behavior in ("refused", "directory_cache"):
                        project.run_user_refusal(args, root / "case", case, ctx)
                    else:
                        with self.assertRaises(ValueError):
                            project.run_user_refusal(args, root / "case", case, ctx)


if __name__ == "__main__":
    unittest.main()
