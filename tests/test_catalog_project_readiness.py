"""Offline Project contract negatives; no native CLI or account/runtime claim."""
from __future__ import annotations

import copy
import base64
import json
import io
import os
from contextlib import redirect_stderr
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from tests.test_catalog_publication_readiness import catalog, arguments, paired_arguments, ProofTime, SIGNED48_FEED, SIGNED49_FEED, SIGNED49_SNAPSHOT
from tests import test_catalog_managed_readiness as managed_tests
import catalog_managed_readiness as managed
import catalog_project_readiness as project
import catalog_publication_readiness as gate


class ProjectReadinessTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = catalog()
        self.case = project.expected(self.snapshot, gate.selected)

    def test_paired_current_case_is_bound_to_the_reviewed_source_and_policy(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": "777genius/universal-agent-plugins-registry"}), \
                patch.object(gate, "datetime", ProofTime):
            args = paired_arguments(Path(temporary))
            snapshot, artifact = gate.canonical_inputs(args)
            case = artifact["project_dependencies"]
            project.validate_source_anchor(case)
            self.assertEqual(case["cli"], managed.CLI)
            for field in ("product_id", "distribution_id", "release_sequence", "package_version", "package_source", "tree_digest", "manifest_digest"):
                changed = copy.deepcopy(case)
                changed["closure"][0][field] = {**changed["closure"][0][field], "revision": "f" * 40} if field == "package_source" else 999 if field == "release_sequence" else "changed"
                with self.subTest(field=field), self.assertRaises(ValueError):
                    project.validate_source_anchor(changed)
            for mutation in ("authentication", "scopes", "floor", "grant_mask"):
                changed = copy.deepcopy(snapshot)
                root = next(item for item in changed["distributions"] if item["id"] == managed.ROOT)["release_policies"][0]
                if mutation == "authentication":
                    root["targets"][0]["authentication"] = "not_required"
                elif mutation == "scopes":
                    root["targets"][0]["scopes"] = ["project"]
                elif mutation == "floor":
                    root["minimum_installer_version"] = "0.1.115"
                else:
                    root["targets"] = [row for row in root["targets"] if row["client"] != "copilot"]
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    project.expected(changed, gate.selected)

    def test_six_positive_user_six_positive_project_and_saved_vscode_boundary(self):
        self.assertEqual(tuple(self.case["targets"]), managed.CLIENTS)
        self.assertEqual(self.case["placement_scope"], "project")
        self.assertEqual(self.case["signed_source_scope"], "user")
        self.assertEqual(len(project.source_coverage(self.case)), 24)
        release_user = managed.release_expected(self.snapshot, gate.selected)
        self.assertEqual(tuple(release_user["targets"]), managed.CLIENTS)
        self.assertEqual(len(managed.coverage(release_user)), 25)
        self.assertEqual(release_user["cli"], self.case["cli"])
        self.assertEqual(release_user["closure"], self.case["closure"])
        self.assertEqual(project.current_boundary(self.case)["kind"], "prepared_target_saved_management")
        saved = project.expected_user_saved_management(self.case, {"sequence": 20})
        self.assertEqual((saved["target"], saved["outcome"]), ("vscode", "refused"))
        self.assertNotIn("native_plugin_listing", self.case["proof"])
        self.assertEqual(self.case["proof"]["account_runtime"], "not_tested")
        self.assertEqual(self.case["proof"]["user_native_and_durable_state"],
                         "unchanged_except_exact_project_trust_claude_project_registry_and_native_runtime_caches")
        baseline = copy.deepcopy(self.snapshot)
        baseline["distributions"] = [item for item in baseline["distributions"] if item["id"] != managed.ROOT]
        gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot), project_case=self.case, release_user_case=release_user)
        self.assertEqual(len([(selection, client) for selection, clients in gate.plan(self.snapshot) for client in clients]), 380)

    def test_missing_prepared_vscode_grant_has_no_current_boundary(self):
        prior = copy.deepcopy(self.snapshot)
        root = next(item for item in prior["distributions"] if item["id"] == managed.ROOT)
        root["release_policies"][0]["targets"] = [target for target in root["release_policies"][0]["targets"] if target["client"] != "vscode"]
        with self.assertRaisesRegex(ValueError, "unqualified managed target expansion"):
            project.expected(prior, gate.selected)
        with self.assertRaisesRegex(ValueError, "unqualified current VSCode boundary"):
            project.current_boundary({**self.case, "closure": [
                {**self.case["closure"][0], "policy": {**self.case["closure"][0]["policy"], "targets": [
                    target for target in self.case["closure"][0]["policy"]["targets"] if target["client"] != "vscode"]}},
                *self.case["closure"][1:]]})

    def test_current_policy_selects_the_saved_management_boundary(self):
        current = json.loads(SIGNED49_SNAPSHOT.read_text())
        artifact = gate.expected_artifact(current, current, {"sequence": 48}, {"sequence": 49})
        self.assertEqual(artifact["vscode_user_policy_boundary"]["kind"], "prepared_target_saved_management")
        self.assertIn("vscode_user_saved_management", artifact)
        self.assertNotIn("vscode_user_refusal", artifact)
        with self.assertRaises(TypeError):
            project.expected(current, gate.selected, refusal_source=(self.snapshot, {}))
        with self.assertRaises(TypeError):
            gate.expected_artifact(self.snapshot, self.snapshot, {}, {}, project_cli=managed.CLI)

    def entrypoint_argv(self, root, mode, *, binary=True):
        argv = [mode, "--feed", str(root / "feed"), "--baseline-feed", str(root / "baseline"),
                "--trusted-keys", str(root / "keys.json")]
        for field, value in vars(arguments(self.snapshot)).items():
            argv.extend(["--" + field.replace("_", "-"), str(value)])
        if mode == "verify":
            argv.extend(["--artifact", str(root / "artifact.json")])
        else:
            for name in ("claude", "copilot", "opencode", "sandbox", "output"):
                argv.extend(["--" + name, str(root / name)])
            if binary:
                argv.extend(["--binary", str(root / "binary")])
        return argv

    def test_produce_and_verify_entrypoints_require_fixed_project_contract(self):
        baseline = {**self.snapshot, "sequence": 19}
        ctx = {"sequence": 20, "snapshot_digest": "sha256:" + "e" * 64}
        baseline_identity = {"sequence": 19, "snapshot_digest": "sha256:" + "f" * 64}
        expected = gate.expected_artifact(self.snapshot, baseline, baseline_identity, ctx)
        self.assertEqual(expected["project_dependencies"]["cli"], managed.CLI)
        for mode in ("produce", "verify"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact = root / "artifact.json"
                artifact.write_bytes(gate.publication.canonical_json(expected))
                def invoke(*, binary=True):
                    with patch.object(gate, "load_feed", side_effect=((self.snapshot, ctx), (baseline, baseline_identity))), \
                            patch.object(gate, "context", return_value=ctx), \
                            patch.object(gate, "produce") as producer, \
                            redirect_stderr(io.StringIO()):
                        result = gate.main(self.entrypoint_argv(root, mode, binary=binary))
                    return result, producer
                result, producer = invoke()
                self.assertEqual(result, 0)
                if mode == "produce":
                    self.assertEqual(producer.call_args.args[2], expected)
                    self.assertEqual(producer.call_args.args[0].binary, root / "binary")
                    result, producer = invoke(binary=False)
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

    def test_unreviewed_source_grants_floor_and_release_pin_refused(self):
        for mutate in (
            lambda root: root["release_policies"][0]["targets"].append({"client": "kiro", "scopes": ["user"], "authentication": "required", "delivery": "managed"}),
            lambda root: root["release_policies"][0]["targets"][0].update(scopes=["project"]),
            lambda root: root["release_policies"][0].update(minimum_installer_version="0.1.115"),
            lambda root: root["releases"][0].update(package_version="0.1.1"),
        ):
            value = copy.deepcopy(self.snapshot)
            mutate(next(item for item in value["distributions"] if item["id"] == managed.ROOT))
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, gate.registry.RegistryError)):
                project.expected(value, gate.selected)
        for mutate in (
            lambda cli: cli.update(version="0.1.104"),
            lambda cli: cli.update(binary_digest="sha256:" + "0" * 64),
        ):
            case = copy.deepcopy(self.case)
            mutate(case["cli"])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "released CLI differs"):
                project.expected_user_saved_management(case, {})

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
            lambda value: value["vscode_user_saved_management"].update(outcome="passed"),
            lambda value: value["vscode_user_saved_management"].update(target="copilot"),
            lambda value: value.pop("vscode_user_saved_management"),
            lambda value: value.update(vscode_user_refusal=copy.deepcopy(value["vscode_user_saved_management"])),
            lambda value: value.pop("release_user_dependencies"),
            lambda value: value["release_user_dependencies"]["targets"].remove("copilot"),
            lambda value: value["release_user_dependencies"]["cli"].update(binary_digest="sha256:" + "0" * 64),
            lambda value: value["release_user_dependencies"]["closure"].pop(),
            lambda value: value["release_user_dependencies"]["associations"].pop(),
            lambda value: value["release_user_dependencies"]["proof"].update(locked_restore="not_tested"),
            lambda value: value["release_user_dependencies"]["proof"].update(repair="not_tested"),
            lambda value: value["project_dependencies"]["proof"].update(native_project_cleanup="not_tested"),
            lambda value: value.update(managed_dependencies=copy.deepcopy(value["release_user_dependencies"])),
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
                objects = []
                # The released Claude Project package is a local marketplace
                # whose plugin root Claude Code caches for the project.
                plugin = target / ".agentplugins-plugin"
                if client == "claude":
                    manifest = {"name": selected["product_id"], "version": selected["package_version"]}
                    manifest["skills" if is_root else "mcpServers"] = "./.agentplugins-runtime/skills/" if is_root else "./.mcp.json"
                    (target / ".claude-plugin").mkdir()
                    (target / ".claude-plugin/marketplace.json").write_text(json.dumps({"plugins": [{"name": selected["product_id"]}]}))
                    (plugin / ".claude-plugin").mkdir(parents=True)
                    (plugin / ".claude-plugin/plugin.json").write_text(json.dumps(manifest))
                    objects.append({"kind": "claude_project_plugin_cache", "logical_name": selected["product_id"], "path": str(plugin)})
                if is_root:
                    native = plugin / ".agentplugins-runtime/skills/campaign-planning" if client == "claude" else workspace / project.SKILL_ROOTS[client] / "campaign-planning"
                    native.mkdir(parents=True)
                    (native / "SKILL.md").write_text("immutable Skill bytes\n")
                    if client != "claude":
                        objects.append({"kind": client + "_project_skill_directory", "logical_name": "campaign-planning", "path": str(native)})
                elif client == "claude":
                    (plugin / ".mcp.json").write_text(json.dumps(servers))
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
        for mutation in ("none", "skill_bytes", "missing_member", "wrong_scope", "wrong_path", "wrong_endpoint", "missing_receipt", "user_listing", "missing_surfaces", "sibling_surface", "missing_claude_reference", "wrong_claude_version", "missing_claude_cache_receipt", "missing_claude_marketplace"):
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
                elif mutation == "missing_claude_cache_receipt":
                    installations[managed.ROOT]["clients"]["claude"]["native_objects"] = []
                elif mutation == "missing_claude_marketplace":
                    (Path(installations[managed.ROOT]["clients"]["claude"]["target_locator"]) / ".claude-plugin/marketplace.json").unlink()
                elif mutation in ("missing_claude_reference", "wrong_claude_version"):
                    manifest = Path(installations[managed.ROOT]["clients"]["claude"]["target_locator"]) / ".agentplugins-plugin/.claude-plugin/plugin.json"
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
        project.validate_operation(result, aliases, project.CLIENTS, operation="repair", expected_scope="project", installations=installations)
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
                project.validate_operation(value, aliases, project.CLIENTS, operation="repair", expected_scope="project", installations=installations)

    def test_dependency_operation_scopes_remain_separate_for_every_positive_phase(self):
        aliases = {distribution: distribution.split("/")[1] for distribution in managed.PINS}
        installations = {distribution: {"installation_id": "i-" + alias} for distribution, alias in aliases.items()}
        for phase, operation, action in (("add", "add", "install"),
                                         ("repeat_locked_replay_update", "unchanged", "unchanged"),
                                         ("repair", "repair", "repair"),
                                         ("locked_restore", "add", "repair")):
            distributions = [managed.ROOT] if operation == "repair" else list(aliases)
            actions = [{"alias": aliases[distribution], "client_id": client, "action": action}
                       for distribution in distributions for client in managed.CLIENTS]
            results = [] if action == "unchanged" else [
                {"client_id": client, "operation": action, "installation_id": installations[distribution]["installation_id"],
                 "outcome": "completed"} for distribution in distributions for client in managed.CLIENTS]
            for scope, other_scope in (("user", "project"), ("project", "user")):
                value = {"scope": scope, "outcome": "completed", "actions": actions, "results": results}
                with self.subTest(phase=phase, scope=scope):
                    project.validate_operation(value, aliases, managed.CLIENTS, operation=operation,
                                               expected_scope=scope, installations=installations)
                    with self.assertRaisesRegex(ValueError, "scope or outcome"):
                        project.validate_operation(value, aliases, managed.CLIENTS, operation=operation,
                                                   expected_scope=other_scope, installations=installations)
                    with self.assertRaises(TypeError):
                        project.validate_operation(value, aliases, managed.CLIENTS, operation=operation,
                                                   installations=installations)
                    with self.assertRaisesRegex(ValueError, "scope or outcome"):
                        project.validate_operation(value, aliases, managed.CLIENTS, operation=operation,
                                                   expected_scope="all", installations=installations)

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


class SavedManagementBoundaryTests(unittest.TestCase):
    def setUp(self):
        for manager in (patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": "777genius/universal-agent-plugins-registry"}),
                        patch.object(gate, "datetime", ProofTime)):
            manager.start()
            self.addCleanup(manager.stop)

    def fixture(self, root):
        args = paired_arguments(root)
        for name in ("binary", "claude", "copilot", "codex", "opencode", "npx"):
            path = getattr(args, name)
            path.write_text("#!/bin/sh\nexit 1\n")
            path.chmod(0o700)
        return args, patch.dict(managed.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())})

    def invoke_fixture(self, args, artifact, behavior, calls):
        case = artifact["vscode_user_saved_management"]
        ctx = artifact["context"]
        selections = {item["distribution_id"]: item for item in artifact["project_dependencies"]["closure"]}
        reason = 'agentplugins: target vscode cannot be saved; retry agentplugins add marketing-kit --target vscode --no-save\n'
        def invoke(argv, **kwargs):
            calls.append(argv[1:])
            state = Path(kwargs["env"]["AGENTPLUGINS_HOME"])
            home = Path(kwargs["env"]["HOME"])
            if argv[1] == "info":
                self.assertEqual(argv[3:], ["--target", "vscode", "--scope", "user", "--format", "json"])
                selected = selections[argv[2]]
                feed, sequence = (SIGNED48_FEED, 48) if behavior == "cache48" else (SIGNED49_FEED, 49)
                body = (feed / f"snapshots/{sequence:020d}.json").read_bytes()
                envelope = (feed / f"snapshots/{sequence:020d}.envelope.json").read_bytes()
                if behavior != "no_cache":
                    cache = state / "directory-v1-cache.json"
                    cache.write_text(json.dumps({"schema_version": 1, "sequence": sequence,
                        "snapshot": base64.b64encode(body).decode(), "envelope": base64.b64encode(envelope).decode()}))
                    cache.chmod(0o600)
                targets = [{"client": "vscode", "scopes": ["user"], "delivery": "managed" if behavior == "managed_policy" else "prepared"}]
                data = {"product_id": selected["product_id"], "selected_distribution": selected["distribution_id"],
                        "snapshot_sequence": 48 if behavior == "warm48" else ctx["sequence"],
                        "snapshot_digest": "wrong" if behavior == "wrong_digest" else ctx["snapshot_digest"],
                        "target_compatibility": targets,
                        "selected_release": {"id": selected["distribution_id"], "release_sequence": selected["release_sequence"],
                            "package_version": selected["package_version"], "resolved_revision": selected["package_source"]["revision"],
                            "release_status": "active", "repository": selected["package_source"]["repository"], "package_path": selected["package_source"]["path"],
                            "tree_digest": selected["tree_digest"], "manifest_digest": selected["manifest_digest"],
                            "target_compatibility": targets}}
                if behavior == "bool_sequence":
                    data["snapshot_sequence"] = True
                if behavior == "bool_release":
                    data["selected_release"]["release_sequence"] = True
                if behavior == "inactive_release":
                    data["selected_release"]["release_status"] = "withdrawn"
                if behavior == "warm_raise":
                    raise ValueError("fixture warm child failure")
                if behavior == "wrong_source":
                    data["selected_release"]["resolved_revision"] = "f" * 40
                if behavior == "wrong_product":
                    data["product_id"] = "foreign-product"
                if behavior == "wrong_distribution":
                    data["selected_distribution"] = "unqualified/package"
                if behavior == "wrong_release":
                    data["selected_release"]["release_sequence"] += 1
                if behavior == "malformed_targets":
                    data["target_compatibility"] = ["vscode"]
                if behavior in ("warm_mutation", "bad_warm_and_mutation"):
                    (kwargs["cwd"] / "foreign.txt").write_text("changed")
                return SimpleNamespace(returncode=False if behavior == "warm_bool_return" else 0, stdout=json.dumps({"command": "info", "result": "success", "data": data}),
                                       stderr=" " if behavior in ("warm_stderr", "bad_warm_and_mutation") else "")
            self.assertEqual(argv[1:], ["add", "marketing-kit", "--target", "vscode", "--scope", "user", "--yes", "--format", "json"])
            if behavior in ("native_mutation", "bad_raw_and_mutation"):
                (home / ".copilot/mcp-config.json").write_text("{}")
            elif behavior == "intent_mutation":
                (state / "uap.toml").write_text("[dependencies]\n")
            elif behavior == "durable_mutation":
                (state / "state-v2.json").write_text("{}")
            elif behavior == "foreign_mutation":
                (kwargs["cwd"] / "foreign.txt").write_text("changed")
            elif behavior == "journal_mutation":
                (state / "operations-v2").mkdir()
            elif behavior == "cache_mutation":
                cache = state / "directory-v1-cache.json"
                cache.write_text(cache.read_text() + "\n")
            if behavior == "probe_raise":
                raise ValueError("fixture saved child failure")
            stderr = {"bad_raw_and_mutation": "wrong diagnostic", "padded_prefix": " " + reason, "padded_suffix": reason + " ", "missing_lf": reason[:-1],
                      "extra_lf": reason + "\n", "signed_refusal": 'agentplugins: no eligible directory release; missing vscode\n',
                      "resolving_prefix": 'Resolving and validating one Agent Plugin package for every selected target...\n' + reason}.get(behavior, reason)
            return SimpleNamespace(returncode=True if behavior == "bool_return" else 0 if behavior == "success" else 1,
                                   stdout=" " if behavior == "stdout_space" else "\n" if behavior == "stdout_lf" else "", stderr=stderr)
        return invoke

    def test_current_policy_capability_boundary_is_raw_exact_and_read_only(self):
        warm_failures = ("warm48", "wrong_digest", "cache48", "no_cache", "managed_policy", "wrong_source", "wrong_product",
                         "wrong_distribution", "wrong_release", "malformed_targets", "warm_mutation", "warm_stderr",
                         "bool_sequence", "bool_release", "inactive_release", "warm_raise", "bad_warm_and_mutation", "warm_bool_return")
        failures = (*warm_failures, "success", "stdout_space", "stdout_lf", "padded_prefix", "padded_suffix", "missing_lf", "extra_lf",
                    "signed_refusal", "resolving_prefix", "native_mutation", "intent_mutation", "durable_mutation", "foreign_mutation", "journal_mutation", "cache_mutation", "probe_raise", "bad_raw_and_mutation", "bool_return")
        for behavior in ("refused", *failures):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args, release = self.fixture(root)
                with release:
                    _, artifact = gate.canonical_inputs(args)
                    calls = []
                    with patch.object(gate, "child", side_effect=self.invoke_fixture(args, artifact, behavior, calls)), \
                            patch.object(managed, "validate_foreign_state", wraps=managed.validate_foreign_state) as foreign_guard:
                        if behavior == "refused":
                            project.run_user_saved_management(args, root / "case", artifact["vscode_user_saved_management"],
                                                              artifact["context"], artifact["project_dependencies"])
                            self.assertEqual([call[1] for call in calls[:-1]], list(managed.PINS))
                            self.assertEqual(len(calls), 5)
                        else:
                            with self.assertRaises(ValueError):
                                project.run_user_saved_management(args, root / "case", artifact["vscode_user_saved_management"],
                                                                  artifact["context"], artifact["project_dependencies"])
                            if behavior in warm_failures:
                                self.assertTrue(all(call[0] == "info" for call in calls))
                        foreign_guard.assert_called_once()

    def test_direct_saved_management_rejects_foreign_context_case_and_cli_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, release = self.fixture(root)
            with release:
                _, artifact = gate.canonical_inputs(args)
                case, ctx, source = artifact["vscode_user_saved_management"], artifact["context"], artifact["project_dependencies"]
                foreign_ctx = {**ctx, "sequence": 48, "snapshot_digest": "sha256:" + "f" * 64}
                mutations = (
                    (case, foreign_ctx, source),
                    ({**case, "context": foreign_ctx}, ctx, source),
                    ({**case, "cli": {**case["cli"], "version": "0.1.104"}}, ctx, source),
                    ({**case, "reason": "missing_vscode_signed_target_grant"}, ctx, source),
                    ({**case, "prepared_native_absence": "passed"}, ctx, source),
                    (case, ctx, {**source, "closure": source["closure"][:-1]}),
                )
                with patch.object(gate, "child") as child:
                    for changed_case, changed_ctx, changed_source in mutations:
                        with self.subTest(case=changed_case), self.assertRaises(ValueError):
                            project.run_user_saved_management(args, root / "not-created", changed_case, changed_ctx, changed_source)
                        self.assertFalse((root / "not-created").exists())
                    child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
