"""Offline contract tests; no CLI/native runtime or network."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

from tests.test_catalog_publication_readiness import catalog, unsigned_source_catalog, PROJECT_RELEASE_FIXTURE, paired_arguments, ProofTime, load_historical_source
import catalog_publication_readiness as gate
import catalog_managed_readiness as managed


class ManagedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = catalog()
        self.case = managed.expected(self.snapshot, gate.selected)

    def test_paired_release_user_preserves_four_identities_and_truthful_vscode_boundary(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": "777genius/universal-agent-plugins-registry"}), \
                patch.object(gate, "datetime", ProofTime), patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE):
            args = paired_arguments(Path(temporary))
            snapshot, artifact = gate.canonical_inputs(args)
            historical = artifact["managed_dependencies"]
            user, project = artifact["release_user_dependencies"], artifact["project_dependencies"]
            prior_snapshot, _ = load_historical_source(args, artifact["context"])
            prior = gate.project.expected(prior_snapshot, gate.selected)
            self.assertEqual(historical["cli"]["version"], "0.1.91")
            self.assertEqual(user["cli"], PROJECT_RELEASE_FIXTURE["cli"])
            self.assertEqual(user["cli"], project["cli"])
            self.assertEqual(user["placement_scope"], "user")
            self.assertEqual(user["proof"]["vscode_qualification"], "source_grant_prepared_only")
            self.assertEqual(managed.immutable_closure(user), managed.immutable_closure(prior))
            self.assertEqual(managed.immutable_closure(user), managed.immutable_closure(project))
            # Root prepared grant belongs to positive policy coverage, never
            # negative45 or an invented seventh positive User installation.
            self.assertIn((managed.ROOT, 1, "vscode", "user"), managed.coverage(user))
            self.assertNotIn("vscode", user["targets"])
            for change in ("missing", "duplicate", "foreign"):
                invalid = copy.deepcopy(user)
                if change == "missing":
                    invalid["closure"].pop()
                elif change == "duplicate":
                    invalid["closure"][-1] = copy.deepcopy(invalid["closure"][0])
                else:
                    invalid["closure"][-1]["distribution_id"] = "unqualified/package"
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "cardinality"):
                    managed.immutable_closure(invalid)

    def test_separate_case_preserves_legacy_matrix_and_exact_coverage(self):
        self.assertEqual(gate.CLI["version"], "0.1.89")
        self.assertEqual(len([(selection, client) for selection, clients in gate.plan(self.snapshot) for client in clients]), 380)
        self.assertEqual(self.case["cli"]["version"], "0.1.91")
        self.assertEqual(len(managed.coverage(self.case)), len(managed.PINS) * len(self.case["targets"]))
        baseline = copy.deepcopy(self.snapshot)
        baseline["distributions"] = [item for item in baseline["distributions"] if item["id"] != managed.ROOT]
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))
        unknown = copy.deepcopy(next(item for item in self.snapshot["distributions"] if item["id"] == managed.ROOT))
        unknown["id"] = "unqualified/new-package"
        self.snapshot["distributions"].append(unknown)
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))

    def test_published_legacy_and_candidate_copilot_source_coverage_are_distinct(self):
        self.assertEqual(tuple(self.case["targets"]), managed.LEGACY_CLIENTS)
        self.assertEqual(len(managed.coverage(self.case)), len(managed.PINS) * 5)
        historical = copy.deepcopy(self.snapshot)
        root = next(row for row in historical["distributions"] if row["id"] == managed.ROOT)
        root["release_policies"][0]["targets"] = [
            row for row in root["release_policies"][0]["targets"] if row["client"] != "copilot"
        ]
        prior = managed.expected(historical, gate.selected)
        self.assertEqual(tuple(prior["targets"]), managed.LEGACY_CLIENTS)
        self.assertEqual(len(managed.coverage(prior)), len(managed.PINS) * 5)
        for change in ("kiro", "project"):
            invalid = copy.deepcopy(self.snapshot)
            policy = next(row for row in invalid["distributions"] if row["id"] == managed.ROOT)["release_policies"][0]
            if change == "kiro":
                policy["targets"].append({"client": "kiro", "authentication": "required",
                                          "scopes": ["user"], "delivery": "managed"})
            else:
                policy["targets"][-1]["scopes"] = ["project"]
            with self.subTest(change=change), self.assertRaises((ValueError, gate.registry.RegistryError)):
                managed.expected(invalid, gate.selected)

    def test_user_coverage_cannot_qualify_a_project_scope_expansion(self):
        baseline = copy.deepcopy(self.snapshot)
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == "777genius/atlassian")
        target = next(item for item in distribution["release_policies"][0]["targets"] if item["client"] == "codex")
        target["scopes"].append("project")
        with self.assertRaisesRegex(ValueError, "uncovered target policy"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))

    def test_unreviewed_pi_signed_target_fails_legacy_readiness(self):
        # This protects the existing 0.1.89 publication gate, NOT proof that
        # its strict Directory v1 parser can understand a future Pi snapshot.
        self.assertEqual(gate.CLI["version"], "0.1.89")
        self.assertNotIn("pi", gate.CATALOG_CLIENTS)
        baseline = copy.deepcopy(self.snapshot)
        for floor in ("0.1.89", "0.1.102"):
            candidate = copy.deepcopy(baseline)
            distribution = next(item for item in candidate["distributions"]
                                if item["id"] == "777genius/atlassian")
            policy = next(item for item in distribution["release_policies"]
                          if item["status"] == "active")
            old_target = next(item for item in policy["targets"]
                              if item["client"] == "codex")
            policy["targets"].append({**copy.deepcopy(old_target), "client": "pi"})
            policy["minimum_installer_version"] = floor
            with self.subTest(floor=floor), self.assertRaisesRegex(
                ValueError, "uncovered target policy change|requires newer CLI"
            ):
                gate.policy_scope(baseline, candidate, gate.plan(candidate))

    def test_release_user_requires_fixed_authority_and_preserves_historical_case(self):
        with patch.object(gate.project, "RELEASE", None), self.assertRaisesRegex(ValueError, "identity is unset"):
            managed.release_expected(self.snapshot, gate.selected)
        with patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE):
            case = managed.release_expected(self.snapshot, gate.selected)
        self.assertEqual(case["cli"], PROJECT_RELEASE_FIXTURE["cli"])
        self.assertEqual(case["targets"], list(managed.CLIENTS))
        self.assertEqual(len(case["associations"]), 24)
        self.assertEqual(self.case["cli"], managed.CLI)
        self.assertEqual(self.case["targets"], list(managed.LEGACY_CLIENTS))
        historical = copy.deepcopy(self.snapshot)
        policy = next(item for item in historical["distributions"] if item["id"] == managed.ROOT)["release_policies"][0]
        policy["targets"] = [target for target in policy["targets"] if target["client"] != "copilot"]
        with patch.object(gate.project, "RELEASE", None):
            self.assertIsNone(managed.release_expected(historical, gate.selected))

    def test_release_user_foreign_skills_project_and_native_members_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roots = {name: root / name for name in ("home", "config", "workspace")}
            for path in roots.values():
                path.mkdir()
            paths, configs = managed.seed_foreign_state(roots)
            before = managed.snapshot_paths(paths)
            managed.validate_foreign_state(paths, before, configs)
            for path in (paths["copilot"] / "SKILL.md", roots["workspace"] / "foreign.txt"):
                original = path.read_bytes()
                path.write_text("modified")
                with self.assertRaises(ValueError):
                    managed.validate_foreign_state(paths, before, configs)
                path.write_bytes(original)
            path = next(iter(configs))
            original = path.read_bytes()
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError, "foreign native member"):
                managed.validate_foreign_state(paths, before, configs)
            path.write_bytes(original)
            # Managed additions to a shared config are allowed; its foreign
            # member must retain exactly the seeded logical value.
            document = json.loads(path.read_text())
            document[configs[path][0]]["managed-addition"] = {"url": "https://managed.invalid/mcp"}
            path.write_text(json.dumps(document))
            managed.validate_foreign_state(paths, before, configs)

    def test_release_user_real_bindings_receipts_skills_and_copilot_marketplace(self):
        with patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE):
            self.case = managed.release_expected(self.snapshot, gate.selected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state, ctx, aliases = self.state(root)
            installations = {item["directory"]["distribution_id"]: item for item in state["installations"]}
            for selected in self.case["closure"]:
                package = root / "state/store/packages/agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
                skill = package / "skills/proof/SKILL.md"
                skill.parent.mkdir(parents=True)
                skill.write_text("Immutable Skill bytes\n")
                for client, binding in installations[selected["distribution_id"]]["clients"].items():
                    binding["affected_surfaces"] = ["copilot", "vscode"] if client == "copilot" else [client]
                    target = Path(binding["target_locator"])
                    installed_skill = target / (".agentplugins-runtime/skills/proof" if client == "claude" else "skills/proof")
                    installed_skill.mkdir(parents=True)
                    (installed_skill / "SKILL.md").write_bytes(skill.read_bytes())
                    binding["receipts"] = [{"client_binding_id": binding["client_binding_id"], "phase": "committed", "active_path": str(target), "operation_id": "op"}]
                    if client in ("gemini", "opencode"):
                        binding["native_objects"] = [{"logical_name": "proof", "kind": client + "_skill_directory", "path": str(installed_skill)}]
                    if client == "copilot":
                        marketplace = target / ".github/plugin/marketplace.json"
                        marketplace.parent.mkdir(parents=True)
                        marketplace.write_text(json.dumps({"name": gate.managed_marketplace(binding["physical_artifact_id"]), "plugins": [{"name": selected["product_id"], "version": selected["package_version"], "source": "."}]}))
            managed.validate_release_user_bindings(installations, self.case, root)
            for mutation in (
                lambda binding: binding.update(scope="project"),
                lambda binding: binding.update(affected_surfaces=["copilot"]),
                lambda binding: binding.update(receipts=[]),
                lambda binding: binding["receipts"][0].update(client_binding_id="foreign"),
                lambda binding: binding["receipts"][0].update(phase="prepared"),
                lambda binding: binding["receipts"][0].update(active_path=str(root / "substitute")),
            ):
                value = copy.deepcopy(installations)
                mutation(value[managed.ROOT]["clients"]["copilot"])
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    managed.validate_release_user_bindings(value, self.case, root)
            binding = installations[managed.ROOT]["clients"]["copilot"]
            path = Path(binding["target_locator"]) / "skills/proof/SKILL.md"
            path.write_text("substitute")
            with self.assertRaisesRegex(ValueError, "Skill bytes"):
                managed.validate_release_user_bindings(installations, self.case, root)

    def test_retained_application_bytes_use_only_existing_owned_user_data_slots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = {"installations": []}
            for index in range(4):
                locator = root / "state/plugin-data" / ("backend-" + str(index))
                locator.mkdir(parents=True)
                receipt = {"locator": str(locator), "scope": "user", "data_receipt_id": "data-" + str(index)}
                (locator / ".agentplugins-data-owner.json").write_text(json.dumps(receipt))
                state["installations"].append({"data_retained": True, "clients": {}, "data_receipts": {"data": receipt}})
            managed.seed_retained_data(state, root)
            for installation in state["installations"]:
                path = Path(installation["data_receipts"]["data"]["locator"]) / "readiness-retained-data.txt"
                self.assertEqual(path.read_bytes(), b"Credential-free retained application data.\n")
                path.unlink()
            for mutation in (
                lambda value: value["installations"][0].update(data_retained=False),
                lambda value: value["installations"][0]["data_receipts"]["data"].update(locator=str(root / "outside")),
                lambda value: value["installations"][0]["data_receipts"]["data"].update(scope="project"),
            ):
                value = copy.deepcopy(state)
                mutation(value)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    managed.seed_retained_data(value, root)
            receipt = state["installations"][-1]["data_receipts"]["data"]
            marker = Path(receipt["locator"]) / ".agentplugins-data-owner.json"
            substitute = root / "substitute-marker.json"
            substitute.write_bytes(marker.read_bytes())
            marker.unlink()
            marker.symlink_to(substitute)
            with self.assertRaisesRegex(ValueError, "substituted"):
                managed.seed_retained_data(state, root)
            self.assertEqual(list(root.rglob("readiness-retained-data.txt")), [])

    def test_retained_data_rejects_symlinked_data_root_and_state_ancestor(self):
        for substituted in ("plugin-data", "state"):
            for locator_style in ("outside", "lexical"):
                with self.subTest(substituted=substituted, locator_style=locator_style), tempfile.TemporaryDirectory() as temporary:
                    parent = Path(temporary).resolve()
                    root, outside = parent / "isolated", parent / "outside"
                    root.mkdir()
                    outside.mkdir()
                    data_root = root / "state/plugin-data"
                    if substituted == "state":
                        (root / "state").symlink_to(outside, target_is_directory=True)
                        outside_data = outside / "plugin-data"
                        outside_data.mkdir()
                    else:
                        (root / "state").mkdir()
                        data_root.symlink_to(outside, target_is_directory=True)
                        outside_data = outside
                    state = {"installations": []}
                    for index in range(4):
                        actual = outside_data / ("backend-" + str(index))
                        actual.mkdir()
                        locator = actual if locator_style == "outside" else data_root / actual.name
                        receipt = {"locator": str(locator), "scope": "user", "data_receipt_id": "data-" + str(index)}
                        (actual / ".agentplugins-data-owner.json").write_text(json.dumps(receipt))
                        state["installations"].append({"data_retained": True, "clients": {}, "data_receipts": {"data": receipt}})
                    before = managed.snapshot_paths({"outside": outside})
                    with self.assertRaises(ValueError):
                        managed.seed_retained_data(state, root)
                    self.assertEqual(managed.snapshot_paths({"outside": outside}), before)
                    self.assertEqual(list(outside.rglob("readiness-retained-data.txt")), [])

    def test_retained_data_descriptor_writes_cannot_follow_a_late_data_root_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root, outside = parent / "isolated", parent / "outside"
            root.mkdir()
            outside.mkdir()
            data_root = root / "state/plugin-data"
            original_data = root / "state/original-plugin-data"
            state = {"installations": []}
            for index in range(4):
                locator = data_root / ("backend-" + str(index))
                locator.mkdir(parents=True)
                (outside / locator.name).mkdir()
                receipt = {"locator": str(locator), "scope": "user", "data_receipt_id": "data-" + str(index)}
                (locator / ".agentplugins-data-owner.json").write_text(json.dumps(receipt))
                state["installations"].append({"data_retained": True, "clients": {}, "data_receipts": {"data": receipt}})
            before = managed.snapshot_paths({"outside": outside})
            native_open, swapped = os.open, False
            def swap_before_create(path, flags, *args, **kwargs):
                nonlocal swapped
                if path == "readiness-retained-data.txt" and not swapped:
                    data_root.rename(original_data)
                    data_root.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return native_open(path, flags, *args, **kwargs)
            with patch.object(managed.os, "open", side_effect=swap_before_create):
                managed.seed_retained_data(state, root)
            self.assertTrue(swapped)
            self.assertEqual(managed.snapshot_paths({"outside": outside}), before)
            self.assertEqual(len(list(original_data.rglob("readiness-retained-data.txt"))), 4)

    def test_retained_data_descriptors_close_on_owner_validation_and_create_failure(self):
        for failure in ("owner_mismatch", "owner_fifo", "create_failure"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                state = {"installations": []}
                for index in range(4):
                    locator = root / "state/plugin-data" / ("backend-" + str(index))
                    locator.mkdir(parents=True)
                    receipt = {"locator": str(locator), "scope": "user", "data_receipt_id": "data-" + str(index)}
                    marker = locator / ".agentplugins-data-owner.json"
                    marker.write_text(json.dumps(receipt))
                    state["installations"].append({"data_retained": True, "clients": {}, "data_receipts": {"data": receipt}})
                if failure == "owner_mismatch":
                    marker.write_text('{"foreign": true}')
                elif failure == "owner_fifo":
                    marker.unlink()
                    os.mkfifo(marker)
                native_open, opened = os.open, []
                def track_open(path, flags, *args, **kwargs):
                    if failure == "create_failure" and path == "readiness-retained-data.txt":
                        raise OSError("fixture create failure")
                    descriptor = native_open(path, flags, *args, **kwargs)
                    opened.append(descriptor)
                    return descriptor
                with patch.object(managed.os, "open", side_effect=track_open):
                    with self.assertRaises((ValueError, OSError)):
                        managed.seed_retained_data(state, root)
                self.assertTrue(opened)
                for descriptor in set(opened):
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                self.assertEqual(list(root.rglob("readiness-retained-data.txt")), [])

    def test_six_user_run_applies_real_scoped_add_validation_before_acquisition(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tools = root / "tools"
            tools.mkdir()
            for name in ("agentplugins", "codex", "claude", "copilot", "opencode"):
                path = tools / name
                path.write_text("#!/bin/sh\nexit 1\n")
                path.chmod(0o700)
            args = SimpleNamespace(binary=tools / "agentplugins", project_binary=tools / "agentplugins",
                                   codex=tools / "codex", claude=tools / "claude", copilot=tools / "copilot",
                                   opencode=tools / "opencode", inspector=None, npx=None)
            release = copy.deepcopy(PROJECT_RELEASE_FIXTURE)
            release["cli"]["binary_digest"] = gate.digest(args.project_binary.read_bytes())
            actual_validator = gate.project.validate_operation
            with patch.object(gate.project, "RELEASE", release):
                self.case = managed.release_expected(self.snapshot, gate.selected)
                for payload_scope in ("user", "project"):
                    case_root = root / ("case-" + payload_scope)
                    ctx = {"sequence": 43, "snapshot_digest": "sha256:" + "f" * 64,
                           "directory_origin": "https://example.invalid/exact-ledger/"}
                    def add(argv, **kwargs):
                        self.assertEqual(argv[1:5], ["add", "marketing-kit", "--target", ",".join(managed.CLIENTS)])
                        self.assertEqual(argv[5:], ["--scope", "user", "--format", "json"])
                        state, state_ctx, aliases = self.state(case_root)
                        ctx.update(state_ctx)
                        state_root = Path(kwargs["env"]["AGENTPLUGINS_HOME"])
                        manifest, lock = state_root / "uap.toml", state_root / "uap.lock"
                        manifest.write_text('[dependencies]\nmarketing-kit = "' + managed.PINS[managed.ROOT] +
                                            '"\n[targets]\n' + ''.join(client + ' = ["marketing-kit"]\n' for client in managed.CLIENTS))
                        lock.write_text(json.dumps(self.lock()))
                        (state_root / "state-v2.json").write_text(json.dumps(state))
                        by_distribution = {item["directory"]["distribution_id"]: item for item in state["installations"]}
                        actions = [{"alias": aliases[distribution], "client_id": client, "action": "install"}
                                   for distribution in managed.PINS for client in managed.CLIENTS]
                        results = [{"client_id": client, "operation": "install", "outcome": "completed",
                                    "installation_id": by_distribution[distribution]["installation_id"]}
                                   for distribution in managed.PINS for client in managed.CLIENTS]
                        data = {"scope": payload_scope, "outcome": "completed", "actions": actions, "results": results,
                                "environment": {"saved": True, "manifest_path": str(manifest), "lock_path": str(lock)}}
                        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"command": "add", "result": "success", "data": data}))
                    with self.subTest(payload_scope=payload_scope), patch.object(gate, "child", side_effect=add) as child, \
                            patch.object(gate.project, "validate_operation", wraps=actual_validator) as validate, \
                            patch.object(gate.registry, "directory_tree_digest", side_effect=RuntimeError("stop_after_user_add")) as acquire:
                        if payload_scope == "user":
                            with self.assertRaisesRegex(RuntimeError, "stop_after_user_add"):
                                managed.run(args, case_root, self.case, ctx)
                            self.assertEqual(validate.call_count, 2)
                            acquire.assert_called_once()
                        else:
                            with self.assertRaisesRegex(ValueError, "scope or outcome"):
                                managed.run(args, case_root, self.case, ctx)
                            self.assertEqual(validate.call_count, 1)
                            acquire.assert_not_called()
                        child.assert_called_once()
                        self.assertTrue(all(call.kwargs["expected_scope"] == "user" for call in validate.call_args_list))

    def test_runtime_exposes_explicit_codex_and_owned_cursor_version_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            ambient, tool_bin, pinned = root / "ambient", root / "bin", root / "pinned"
            ambient.mkdir(); tool_bin.mkdir(); pinned.mkdir()
            for name in ("node", "npm", "npx", "codex", "cursor"):
                tool = ambient / name
                tool.write_text("#!/bin/sh\nexit 1\n")
                tool.chmod(0o700)
            codex = pinned / "codex"
            codex.write_text("#!/bin/sh\nexit 1\n")
            codex.chmod(0o700)
            (tool_bin / "codex").symlink_to(codex)
            env = {"PATH": str(ambient)}
            self.assertIsNotNone(shutil.which("codex", path=env["PATH"]))
            with patch.dict(os.environ, {"PATH": str(ambient)}):
                managed.seed_runtime(tool_bin, env, codex)
            self.assertEqual(Path(shutil.which("codex", path=env["PATH"])).resolve(), codex)
            cursor = tool_bin / "cursor"
            self.assertEqual(Path(shutil.which("cursor", path=env["PATH"])).resolve(), cursor)
            version = subprocess.run([str(cursor), "--version"], cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual((version.returncode, version.stdout.strip()), (0, "0.0.0"))
            for argv in (("plugin", "list"), ("--version", "extra")):
                result = subprocess.run([str(cursor), *argv], cwd=root, capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
            self.assertEqual(Path(shutil.which("npm", path=env["PATH"])).resolve(), ambient / "npm")
            with self.assertRaisesRegex(ValueError, "must be absolute"):
                managed.seed_runtime(tool_bin, env, Path("codex"))

            # Do not replace an existing Cursor link with a permissive fixture.
            cursor.unlink()
            cursor.symlink_to(ambient / "cursor")
            for name in ("node", "npm", "npx"):
                (tool_bin / name).unlink()
            with patch.dict(os.environ, {"PATH": str(ambient)}), self.assertRaisesRegex(ValueError, "Cursor fixture collision"):
                managed.seed_runtime(tool_bin, env, codex)
            self.assertEqual(cursor.resolve(), ambient / "cursor")

            # Substituting the explicitly linked native tool must not qualify
            # an arbitrary executable merely because its name is Codex.
            for replacement in (None, ambient / "codex"):
                for name in ("node", "npm", "npx", "codex", "cursor"):
                    (tool_bin / name).unlink(missing_ok=True)
                if replacement is not None:
                    (tool_bin / "codex").symlink_to(replacement)
                with patch.dict(os.environ, {"PATH": str(ambient)}), self.assertRaises(ValueError):
                    managed.seed_runtime(tool_bin, env, codex)

    def test_failure_diagnostics_never_copy_untrusted_response_text(self):
        result = subprocess.CompletedProcess([], 1, "codex activation failed token=PRIVATE", "/private/path https://secret.test/")
        summary = managed.failure_diagnostics("add", result)
        self.assertIn('"activation_failed"', summary)
        self.assertIn('"codex"', summary)
        for private in ("PRIVATE", "private/path", "secret.test", "token="):
            self.assertNotIn(private, summary)

    def test_codex_external_removal_uses_exact_native_identities_and_verifies_absence(self):
        identities = [(name, "agentplugins-" + f"{index:012x}")
                      for index, name in enumerate(("marketing-kit", "hubspot-crm", "notion", "playwright-bridge"))]
        entries = [{"pluginId": name + "@" + marketplace, "name": name, "marketplaceName": marketplace,
                    "installed": True, "enabled": True} for name, marketplace in identities]
        for initial in (entries, [], entries[:2]):
            calls = []
            listings = iter(({"installed": initial}, {"installed": []}))
            def command(*argv, **kwargs):
                calls.append((argv, kwargs))
                return next(listings) if argv[:2] == ("plugin", "list") else None
            managed.remove_codex_plugins(command, identities)
            self.assertEqual(calls[0], (("plugin", "list", "--json"), {}))
            self.assertEqual(calls[-1], (("plugin", "list", "--json"), {}))
            expected = []
            for name, marketplace in identities:
                expected.extend([(("plugin", "remove", name + "@" + marketplace, "--json"), {"allow_absent": True}),
                                 (("plugin", "marketplace", "remove", marketplace, "--json"), {"allow_absent": True})])
            self.assertEqual(calls[1:-1], expected)
        for malformed in ([], {}, {"installed": {}}, {"installed": entries + entries[:1]},
                          {"installed": [{**entries[0], "pluginId": "wrong@namespace"}]},
                          {"installed": [{**entries[0], "enabled": "true"}]},
                          {"installed": [{**entries[0], "name": "another-plugin", "pluginId": "another-plugin@" + identities[0][1]}]}):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                managed.validate_codex_listing(malformed, identities)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            managed.validate_codex_listing({"installed": entries[:1]}, identities, absent=True)
        # A disabled or uninstalled row is still not proof that its identity was
        # removed from Codex; the final installed[] must contain none of them.
        with self.assertRaisesRegex(ValueError, "incomplete"):
            managed.validate_codex_listing({"installed": [{**entries[0], "installed": False, "enabled": False}]}, identities, absent=True)
        with self.assertRaisesRegex(ValueError, "identities"):
            managed.remove_codex_plugins(lambda *a, **k: self.fail("must not invoke native CLI"), identities[:-1] + identities[:1])

    def test_policy_and_version_changes_fail_closed(self):
        for mutation in (
            lambda item: item["release_policies"][0].update(minimum_installer_version="0.1.90"),
            lambda item: item["release_policies"][0]["targets"].append({**item["release_policies"][0]["targets"][0], "client": "kiro"}),
            lambda item: item["releases"][0].update(package_version="0.1.1"),
        ):
            value = copy.deepcopy(self.snapshot)
            mutation(next(item for item in value["distributions"] if item["id"] == managed.ROOT))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                managed.expected(value, gate.selected)

    def lock(self):
        packages = []
        for selected in self.case["closure"]:
            source = selected["package_source"]
            packages.append({"alias": selected["product_id"], "source_key": "directory:" + selected["distribution_id"],
                "version": selected["package_version"], "digest_algorithm": "agentplugins-tree-sha256-v1",
                "tree_digest": selected["tree_digest"], "manifest_digest": selected["manifest_digest"], "targets": list(self.case["targets"]),
                "source": {"registry": {"distribution_id": selected["distribution_id"], "release_sequence": selected["release_sequence"],
                    "product_id": selected["product_id"], "repository": source["repository"], "path": source["path"], "commit": source["revision"]}},
                "required_by": [] if selected["distribution_id"] == managed.ROOT else [{"alias": "marketing-kit", "selector": {"kind": "version", "value": selected["package_version"]}}]})
        return {"lock_version": 1, "packages": packages}

    def test_exact_lock_edges_sources_and_target_inheritance(self):
        lock = self.lock()
        self.assertEqual(set(managed.validate_lock(lock, self.case)), set(managed.PINS))
        for mutation in (
            lambda value: value["packages"].pop(),
            lambda value: value["packages"][1]["targets"].pop(),
            lambda value: value["packages"][1].update(tree_digest="sha256:" + "0" * 64),
            lambda value: value["packages"][1]["source"]["registry"].update(commit="b" * 40),
            lambda value: value["packages"][1].update(required_by=[]),
            lambda value: value["packages"][1]["required_by"][0]["selector"].update(kind="range"),
            lambda value: value["packages"][1].update(version="9.0.0"),
            lambda value: value["packages"][1].update(source_key="directory:wrong/source"),
        ):
            value = copy.deepcopy(lock)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                managed.validate_lock(value, self.case)

    def state(self, root):
        state = {"installations": [], "environment_receipts": []}
        ctx = {"sequence": 43, "snapshot_digest": "sha256:" + "c" * 64}
        aliases = managed.validate_lock(self.lock(), self.case)
        for index, selected in enumerate(self.case["closure"]):
            source = selected["package_source"]
            installation = {"installation_id": f"i{index}", "origin_mode": "directory",
                "package": {"version": selected["package_version"], "manifest_digest": selected["manifest_digest"]},
                "source": {"repository": source["repository"], "package_subpath": source["path"], "resolved_revision": source["revision"], "tree_digest": selected["tree_digest"]},
                "directory": {"distribution_id": selected["distribution_id"], "desired_release_sequence": selected["release_sequence"], "snapshot_sequence": ctx["sequence"], "snapshot_digest": ctx["snapshot_digest"]}, "clients": {}}
            for client in self.case["targets"]:
                path = root / f"{index}-{client}"
                path.mkdir()
                binding = {"client_binding_id": f"b{index}-{client}", "client_id": client, "scope": "user", "materialization": "materialized", "verification": "installation_verified", "target_locator": str(path),
                    "physical_artifact_id": f"artifact-{index}-{client}",
                    "package_revision": {"version": selected["package_version"], "resolved_revision": source["revision"], "tree_digest": selected["tree_digest"], "manifest_digest": selected["manifest_digest"]}}
                installation["clients"][client] = binding
                state["environment_receipts"].append({"receipt_id": binding["client_binding_id"], "environment_id": "user-default", "phase": "committed", "alias": aliases[selected["distribution_id"]], "client_id": client,
                    "installation_id": installation["installation_id"], "client_binding_id": binding["client_binding_id"], "source_key": "directory:" + selected["distribution_id"], "package_digest": selected["tree_digest"]})
            state["installations"].append(installation)
        return state, ctx, aliases

    def test_state_receipts_revision_identity_and_confinement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state, ctx, aliases = self.state(root)
            installations, owned = managed.validate_state(state, self.case, ctx, root, aliases)
            self.assertEqual(len(installations), 4)
            self.assertEqual(len(owned), len(managed.PINS) * len(self.case["targets"]))
            for mutation in (
                lambda value: value["environment_receipts"].pop(),
                lambda value: value["environment_receipts"][0].update(phase="pending"),
                lambda value: value["environment_receipts"][0].update(environment_id="other"),
                lambda value: value["environment_receipts"][0].update(client_binding_id="wrong"),
                lambda value: value["installations"][0]["directory"].update(snapshot_sequence=42),
                lambda value: value["installations"][0]["clients"]["codex"].update(target_locator="/"),
                lambda value: value["installations"][0]["clients"]["codex"]["package_revision"].update(tree_digest="wrong"),
                lambda value: value["installations"][0]["clients"].pop("codex"),
            ):
                value = copy.deepcopy(state)
                mutation(value)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    managed.validate_state(value, self.case, ctx, root, aliases)

    def test_native_removal_leaves_exact_prepared_target_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state, ctx, aliases = self.state(root)
            before = copy.deepcopy(state)
            remaining = tuple(client for client in self.case["targets"] if client not in managed.NATIVE_TARGETS)
            for installation in state["installations"]:
                installation["clients"] = {client: binding for client, binding in installation["clients"].items() if client in remaining}
            state["environment_receipts"] = [receipt for receipt in state["environment_receipts"] if receipt["client_id"] in remaining]
            _, owned = managed.validate_state(state, self.case, ctx, root, aliases, clients=remaining)
            self.assertEqual(len(owned), len(managed.PINS) * len(remaining))
            for mutation in (
                lambda value: value["environment_receipts"].append(before["environment_receipts"][0]),
                lambda value: value["installations"][0]["clients"].update(codex=before["installations"][0]["clients"]["codex"]),
                lambda value: value["environment_receipts"].pop(),
                lambda value: value["installations"][0]["clients"].pop("cursor"),
            ):
                value = copy.deepcopy(state)
                mutation(value)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    managed.validate_state(value, self.case, ctx, root, aliases, clients=remaining)

    def test_plain_remove_keeps_only_exact_retained_data_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state, ctx, aliases = self.state(root)
            for index, installation in enumerate(state["installations"]):
                installation["data_receipts"] = {f"receipt-{index}": {"locator": str(root / f"data-{index}"), "state": "owned"}}
            initial = {item["directory"]["distribution_id"]: copy.deepcopy(item) for item in state["installations"]}
            for installation in state["installations"]:
                installation["clients"] = {}
                installation["data_retained"] = True
            for receipts in (None, []):
                state["environment_receipts"] = receipts
                managed.validate_retained_state(state, self.case, ctx, root, aliases, initial)
            state.pop("environment_receipts")
            managed.validate_retained_state(state, self.case, ctx, root, aliases, initial)
            for mutation in (
                lambda value: value["installations"].pop(),
                lambda value: value["installations"][0].update(data_retained=False),
                lambda value: value["installations"][0].update(installation_id="another"),
                lambda value: value["installations"][0].update(data_receipts={}),
                lambda value: value["installations"][0]["data_receipts"].update(forged={"secret": "PRIVATE"}),
                lambda value: value["installations"][0]["clients"].update(codex=initial[managed.ROOT]["clients"]["codex"]),
                lambda value: value["installations"][0]["source"].update(resolved_revision="b" * 40),
            ):
                value = copy.deepcopy(state)
                mutation(value)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    managed.validate_retained_state(value, self.case, ctx, root, aliases, initial)
            for receipts in ({}, False, 0, "", [{"secret": "PRIVATE"}]):
                value = {**state, "environment_receipts": receipts}
                with self.subTest(receipts=receipts), self.assertRaises(ValueError):
                    managed.validate_retained_state(value, self.case, ctx, root, aliases, initial)
            summary = managed.retained_state_summary({**state, "environment_receipts": [{"secret": "PRIVATE"}]})
            self.assertIn('"count": 4', summary)
            self.assertIn('"retained_installation_count": 4', summary)
            for private in ("PRIVATE", "secret", str(root), "marketing-kit"):
                self.assertNotIn(private, summary)
            self.assertEqual(self.case["proof"]["retained_installation_count"], 4)
            self.assertEqual(self.case["proof"]["active_binding_count"], 0)
            self.assertEqual(self.case["proof"]["installation_count"], 0)

    def test_removal_can_create_only_canonical_empty_retained_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state, ctx, aliases = self.state(root)
            initial = {item["directory"]["distribution_id"]: copy.deepcopy(item) for item in state["installations"]}
            paths = {"store": root / "state" / "store", "plugin-data": root / "state" / "plugin-data"}
            before_paths = managed.snapshot_paths(paths)
            for installation in state["installations"]:
                original = initial[installation["directory"]["distribution_id"]]
                installation.update(clients={}, data_retained=True, data_receipts={})
                for binding in original["clients"].values():
                    if binding["client_id"] in managed.NATIVE_TARGETS:
                        continue
                    backend = binding["physical_artifact_id"]
                    receipt_id = "data_" + hashlib.sha256((original["installation_id"] + "\0" + backend + "\0user").encode()).hexdigest()[:24]
                    locator = paths["plugin-data"] / backend
                    locator.mkdir(parents=True, mode=0o700)
                    paths["plugin-data"].chmod(0o700)
                    receipt = {"data_receipt_id": receipt_id, "physical_backend_id": backend, "scope": "user", "locator": str(locator),
                        "ownership_digest": "sha256:" + hashlib.sha256(("agentplugins-plugin-data-v1\0" + receipt_id + "\0" + str(locator)).encode()).hexdigest(), "state": "owned"}
                    marker = locator / ".agentplugins-data-owner.json"
                    marker.write_text(json.dumps(receipt) + "\n")
                    marker.chmod(0o600)
                    installation["data_receipts"][receipt_id] = receipt
            state["environment_receipts"] = []
            additions = managed.validate_retained_state(state, self.case, ctx, root, aliases, initial)
            self.assertEqual(len(additions), 2 * len(managed.PINS) * (len(self.case["targets"]) - len(managed.NATIVE_TARGETS)))
            managed.validate_retained_paths(before_paths, managed.snapshot_paths(paths), additions)
            (paths["plugin-data"] / "unrelated").write_text("PRIVATE")
            with self.assertRaisesRegex(ValueError, "unrelated"):
                managed.validate_retained_paths(before_paths, managed.snapshot_paths(paths), additions)
            (paths["plugin-data"] / "unrelated").unlink()
            marker.write_text("{}")
            with self.assertRaisesRegex(ValueError, "ownership"):
                managed.validate_retained_state(state, self.case, ctx, root, aliases, initial)
            existing = {"store": [], "plugin-data": [(".", 0o700, "directory"), ("keep", 0o600, "file", "old")]}
            mutated = {"store": [], "plugin-data": [(".", 0o700, "directory"), ("keep", 0o600, "file", "new")]}
            with self.assertRaisesRegex(ValueError, "existing"):
                managed.validate_retained_paths(existing, mutated, set())

    def test_offline_artifact_cannot_omit_or_forge_managed_proof(self):
        baseline = copy.deepcopy(self.snapshot)
        with patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE):
            expected = gate.expected_artifact(self.snapshot, baseline, {"sequence": 42}, {"sequence": 43})
        for mutation in (
            lambda value: value.pop("managed_dependencies"),
            lambda value: value["managed_dependencies"]["closure"].pop(),
            lambda value: value["managed_dependencies"]["associations"].pop(),
            lambda value: value["managed_dependencies"]["proof"].update(oauth="passed"),
            lambda value: value["managed_dependencies"]["cli"].update(version="0.1.89"),
        ):
            value = copy.deepcopy(expected)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gate.validate_artifact(value, expected)

    def test_snapshot_tracks_files_modes_symlinks_and_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "owned-file"
            file.write_text("initial")
            link = root / "owned-link"
            link.symlink_to(file)
            paths = {"file": file, "link": link, "absent": root / "missing", "directory": root}
            before = managed.snapshot_paths(paths)
            self.assertEqual(before, managed.snapshot_paths(paths))
            file.write_text("changed")
            self.assertNotEqual(before, managed.snapshot_paths(paths))
            before = managed.snapshot_paths(paths)
            file.chmod(0o600)
            self.assertNotEqual(before, managed.snapshot_paths(paths))
            before = managed.snapshot_paths(paths)
            link.unlink()
            link.symlink_to(root / "missing")
            self.assertNotEqual(before, managed.snapshot_paths(paths))


class PreparedCompanionPolicyTests(unittest.TestCase):
    """#462 unsigned future policy; this is not signed45 publication evidence."""
    def setUp(self):
        self.snapshot = unsigned_source_catalog()
        self.case = managed.expected(self.snapshot, gate.selected)

    def test_three_authority_shapes_keep_distinct_legacy_and_corrected_coverage(self):
        signed45 = catalog()
        historical = copy.deepcopy(signed45)
        root = next(item for item in historical["distributions"] if item["id"] == managed.ROOT)
        root["release_policies"][0]["targets"] = [target for target in root["release_policies"][0]["targets"] if target["client"] != "copilot"]
        for snapshot in (historical, signed45):
            case = managed.expected(snapshot, gate.selected)
            self.assertEqual(case["targets"], list(managed.LEGACY_CLIENTS))
            self.assertEqual(len(managed.coverage(case)), 20)
            self.assertNotIn((managed.ROOT, 1, "vscode", "user"), managed.coverage(case))
        self.assertEqual(self.case["targets"], list(managed.CLIENTS))
        self.assertEqual(len(managed.coverage(self.case)), 25)
        with patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE):
            corrected = managed.release_expected(signed45, gate.selected)
        self.assertEqual(corrected["targets"], list(managed.CLIENTS))
        self.assertEqual(len(managed.coverage(corrected)), 24)
        self.assertNotIn((managed.ROOT, 1, "vscode", "user"), managed.coverage(corrected))

    def test_missing_prepared_sibling_never_keeps_six_positive_legacy_targets(self):
        missing = copy.deepcopy(self.snapshot)
        root = next(item for item in missing["distributions"] if item["id"] == managed.ROOT)
        root["release_policies"][0]["targets"] = [target for target in root["release_policies"][0]["targets"] if target["client"] != "vscode"]
        case = managed.expected(missing, gate.selected)
        self.assertEqual(case["targets"], list(managed.LEGACY_CLIENTS))
        self.assertNotIn("copilot", case["proof"]["native_plugin_listing"])
        self.assertEqual(len(managed.coverage(case)), 20)
        with patch.object(gate.project, "RELEASE", None), self.assertRaisesRegex(ValueError, "identity is unset"):
            managed.release_expected(missing, gate.selected)

    def test_legacy_and_corrected_user_project_lanes_require_their_own_fixed_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_binary, corrected_binary = root / "legacy", root / "corrected"
            legacy_binary.write_bytes(b"offline historical binary fixture")
            corrected_binary.write_bytes(b"offline corrected binary fixture")
            release = copy.deepcopy(PROJECT_RELEASE_FIXTURE)
            release["cli"]["binary_digest"] = gate.digest(corrected_binary.read_bytes())
            args = SimpleNamespace(managed_binary=legacy_binary, project_binary=corrected_binary, codex=None)
            with patch.dict(managed.CLI, {"binary_digest": gate.digest(legacy_binary.read_bytes())}), \
                    patch.object(gate.project, "RELEASE", release), patch.object(gate, "child") as child:
                legacy = managed.expected(self.snapshot, gate.selected)
                corrected = managed.release_expected(catalog(), gate.selected)
                project_case = gate.project.expected(catalog(), gate.selected)
                for case in (legacy, corrected, project_case):
                    with self.assertRaisesRegex(ValueError, "Codex path must be absolute"):
                        managed.run(args, root / "not-created", case, {})
                with patch.object(gate.project, "RELEASE", None):
                    with self.assertRaisesRegex(ValueError, "Codex path must be absolute"):
                        managed.run(args, root / "not-created", legacy, {})
                    for case in (corrected, project_case):
                        with self.assertRaisesRegex(ValueError, "identity is unset"):
                            managed.run(args, root / "not-created", case, {})
                missing_scope = copy.deepcopy(corrected)
                missing_scope.pop("placement_scope")
                mislabeled_legacy = {**legacy, "placement_scope": "user"}
                ungranted_legacy = {**legacy, "closure": corrected["closure"]}
                for case, message in ((missing_scope, "historical managed CLI authority"),
                                      (mislabeled_legacy, "corrected managed CLI authority"),
                                      (ungranted_legacy, "requires prepared VSCode source grant"),
                                      ({**legacy, "placement_scope": "unknown"}, "targets or scope")):
                    with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                        managed.run(args, root / "not-created", case, {})
                for case in (legacy, corrected, project_case):
                    swapped = SimpleNamespace(managed_binary=corrected_binary, project_binary=legacy_binary, codex=None)
                    with self.assertRaisesRegex(ValueError, "wrong managed released binary"):
                        managed.run(swapped, root / "not-created", case, {})
                child.assert_not_called()
                self.assertFalse((root / "not-created").exists())

    def test_separate_case_preserves_legacy_matrix_and_exact_coverage(self):
        self.assertEqual(gate.CLI["version"], "0.1.89")
        self.assertEqual(len([(selection, client) for selection, clients in gate.plan(self.snapshot) for client in clients]), 380)
        self.assertEqual(self.case["cli"]["version"], "0.1.91")
        self.assertEqual(len(managed.coverage(self.case)), len(managed.PINS) * len(self.case["targets"]) + 1)
        baseline = copy.deepcopy(self.snapshot)
        baseline["distributions"] = [item for item in baseline["distributions"] if item["id"] != managed.ROOT]
        gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))
        unknown = copy.deepcopy(next(item for item in self.snapshot["distributions"] if item["id"] == managed.ROOT))
        unknown["id"] = "unqualified/new-package"
        self.snapshot["distributions"].append(unknown)
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))

    def test_published_legacy_and_candidate_copilot_source_coverage_are_distinct(self):
        self.assertEqual(tuple(self.case["targets"]), managed.CLIENTS)
        self.assertEqual(len(managed.coverage(self.case)), len(managed.PINS) * 6 + 1)
        self.assertIn((managed.ROOT, 1, "vscode", "user"), managed.coverage(self.case))
        self.assertNotIn("vscode", self.case["targets"])
        actual = next(item for item in self.snapshot["distributions"] if item["id"] == managed.ROOT)
        self.assertEqual(tuple(t["client"] for t in actual["release_policies"][0]["targets"]),
                         managed.COPILOT_AUTHORIZED_CLIENTS)
        historical = copy.deepcopy(self.snapshot)
        root = next(row for row in historical["distributions"] if row["id"] == managed.ROOT)
        root["release_policies"][0]["targets"] = [
            row for row in root["release_policies"][0]["targets"] if row["client"] not in ("copilot", "vscode")
        ]
        prior = managed.expected(historical, gate.selected)
        self.assertEqual(tuple(prior["targets"]), managed.LEGACY_CLIENTS)
        self.assertEqual(len(managed.coverage(prior)), len(managed.PINS) * 5)
        for change in ("kiro", "project", "wrong_delivery",
                       "sibling_project", "sibling_auth", "dependency_missing_sibling",
                       "dependency_mismatched_auth"):
            invalid = copy.deepcopy(self.snapshot)
            distribution = next(row for row in invalid["distributions"] if row["id"] == managed.ROOT)
            policy = distribution["release_policies"][0]
            if change == "kiro":
                policy["targets"].append({"client": "kiro", "authentication": "required",
                                          "scopes": ["user"], "delivery": "managed"})
            elif change == "project":
                policy["targets"][-1]["scopes"] = ["project"]
            elif change == "wrong_delivery":
                next(t for t in policy["targets"] if t["client"] == "vscode")["delivery"] = "managed"
            elif change == "sibling_project":
                next(t for t in policy["targets"] if t["client"] == "vscode")["scopes"] = ["project"]
            elif change == "sibling_auth":
                next(t for t in policy["targets"] if t["client"] == "vscode")["authentication"] = "not_required"
            else:
                dep_id = ("777genius/hubspot-crm" if change == "dependency_missing_sibling"
                          else "777genius/playwright-bridge")
                dependency = next(item for item in invalid["distributions"] if item["id"] == dep_id)
                dep_policy = next(p for p in dependency["release_policies"] if p["status"] == "active")
                if change == "dependency_missing_sibling":
                    dep_policy["targets"] = [t for t in dep_policy["targets"] if t["client"] != "vscode"]
                else:
                    # Playwright is credential-free for both backend siblings;
                    # forcing just VS Code to required is policy drift.
                    next(t for t in dep_policy["targets"] if t["client"] == "vscode")["authentication"] = "required"
            with self.subTest(change=change), self.assertRaises((ValueError, gate.registry.RegistryError)):
                managed.expected(invalid, gate.selected)

    def test_historical_six_requires_initial_and_terminal_copilot_native_listing(self):
        # A complete bounded composition fixture; package/native commands remain
        # offline responses, while the saved-state and Copilot parsers are real.
        for stale_registry in (False, True):
            with self.subTest(stale_registry=stale_registry), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary).resolve()
                tools = parent / "tools"
                tools.mkdir()
                for name in ("agentplugins", "codex", "claude", "copilot", "opencode"):
                    path = tools / name
                    path.write_text("#!/bin/sh\nexit 1\n")
                    path.chmod(0o700)
                args = SimpleNamespace(binary=tools / "agentplugins", managed_binary=tools / "agentplugins", project_binary=None,
                                       codex=tools / "codex", claude=tools / "claude", copilot=tools / "copilot",
                                       opencode=tools / "opencode", inspector=None, npx=None)
                root = parent / "case"
                helper = ManagedReadinessTests()
                events, current = [], {}
                ctx = {"directory_origin": "https://example.invalid/historical-policy/"}
                native_listing = gate.native_listing
                with patch.dict(managed.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}):
                    helper.case = copy.deepcopy(managed.expected(self.snapshot, gate.selected))
                    manifests = {}
                    for selected in helper.case["closure"]:
                        body = json.dumps({"name": selected["product_id"], "version": selected["package_version"]}).encode()
                        manifests[selected["distribution_id"]] = body
                        selected["manifest_digest"] = gate.digest(body)
                    def child(argv, **kwargs):
                        name = Path(argv[0]).name
                        if name == "codex":
                            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"installed": []}))
                        if name == "copilot":
                            lines = ["Installed plugins:"]
                            if current["copilot_installed"]:
                                for selected in helper.case["closure"]:
                                    binding = current["original"][selected["distribution_id"]]["clients"]["copilot"]
                                    lines.append("  • " + selected["product_id"] + "@" + gate.managed_marketplace(binding["physical_artifact_id"]) + " (v" + selected["package_version"] + ")")
                            else:
                                lines.append("  No plugins installed.")
                            return SimpleNamespace(returncode=0, stderr="", stdout="\n".join(lines) + "\n")
                        command = argv[1]
                        target = argv[argv.index("--target") + 1] if "--target" in argv else None
                        events.append(("command", command, target))
                        state_root = Path(kwargs["env"]["AGENTPLUGINS_HOME"])
                        manifest, lock, state_file = state_root / "uap.toml", state_root / "uap.lock", state_root / "state-v2.json"
                        if command == "add":
                            state, state_ctx, aliases = helper.state(root)
                            ctx.update(state_ctx)
                            for index, installation in enumerate(state["installations"]):
                                locator = state_root / "plugin-data" / ("retained-" + str(index))
                                locator.mkdir(parents=True)
                                receipt = {"data_receipt_id": "data-" + str(index), "physical_backend_id": locator.name,
                                           "scope": "user", "locator": str(locator), "state": "owned"}
                                (locator / ".agentplugins-data-owner.json").write_text(json.dumps(receipt))
                                installation["data_receipts"] = {receipt["data_receipt_id"]: receipt}
                            current.update(state=state, aliases=aliases, original=copy.deepcopy({item["directory"]["distribution_id"]: item for item in state["installations"]}), copilot_installed=True)
                            for selected in helper.case["closure"]:
                                package = state_root / "store/packages/agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
                                package.mkdir(parents=True)
                                (package / "plugin.json").write_bytes(manifests[selected["distribution_id"]])
                                if selected["distribution_id"] == managed.ROOT:
                                    (package / "uap.toml").write_text('schema_version = 1\n[dependencies]\n' + ''.join(json.dumps(key) + ' = ' + json.dumps(version) + '\n' for key, version in managed.PINS.items() if key != managed.ROOT))
                            manifest.write_text('[dependencies]\nmarketing-kit = "0.1.0"\n[targets]\n' + ''.join(client + ' = ["marketing-kit"]\n' for client in managed.CLIENTS))
                            lock.write_text(json.dumps(helper.lock()))
                            state_file.write_text(json.dumps(state))
                            data = {"scope": "user", "outcome": "completed",
                                    "actions": [{"alias": alias, "client_id": client, "action": "install"}
                                                for alias in aliases.values() for client in managed.CLIENTS],
                                    "results": [{"client_id": client, "operation": "install", "outcome": "completed",
                                                 "installation_id": current["original"][distribution]["installation_id"]}
                                                for distribution in managed.PINS for client in managed.CLIENTS],
                                    "environment": {"saved": True, "manifest_path": str(manifest), "lock_path": str(lock)}}
                        elif command == "info":
                            distribution = next(key for key, alias in current["aliases"].items() if alias == argv[2])
                            data = {"installation_id": current["original"][distribution]["installation_id"],
                                    "clients": [{"client_id": client} for client in managed.CLIENTS]}
                        elif command == "deps":
                            data = {"scope": "user", "pending_recovery": False,
                                    "facts": [{"alias": alias, "client_id": client, "owner": "user-default", "facts": []}
                                              for alias in current["aliases"].values() for client in managed.CLIENTS]}
                        elif command in ("install", "update"):
                            data = {"outcome": "completed", "results": [],
                                    "actions": [{"alias": alias, "client_id": client, "action": "unchanged"}
                                                for alias in current["aliases"].values() for client in managed.CLIENTS]}
                        elif command == "remove":
                            removed = set(managed.CLIENTS) if target is None else {target}
                            for installation in current["state"]["installations"]:
                                for client in list(installation["clients"]):
                                    if client in removed:
                                        shutil.rmtree(installation["clients"].pop(client)["target_locator"])
                                if target is None:
                                    installation["data_retained"] = True
                            current["state"]["environment_receipts"] = [receipt for receipt in current["state"]["environment_receipts"] if receipt["client_id"] not in removed]
                            state_file.write_text(json.dumps(current["state"]))
                            if target is None:
                                lock.write_text('{"lock_version":1,"packages":[]}')
                                current["copilot_installed"] = stale_registry
                            data = {"outcome": "completed"}
                        elif command == "list":
                            data = {"installations": []}
                        elif command == "doctor":
                            data = {"read_only": True, "installation_count": 0, "open_operation_count": 0,
                                    "findings": [{"status": "healthy", "code": "no_degradation_detected", "message": "no tracked degradation was detected"}]}
                        else:
                            self.fail("unexpected historical fixture command " + command)
                        value = {"command": command, "result": "success", "data": data} if command in ("add", "info", "list", "doctor") else data
                        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(value))
                    def listing(tool, env, workspace, plugin, installed, **kwargs):
                        if tool.name == "copilot":
                            events.append(("copilot", installed, plugin))
                            return native_listing(tool, env, workspace, plugin, installed, **kwargs)
                    with patch.object(gate.project, "RELEASE", None), patch.object(gate, "child", side_effect=child), \
                            patch.object(gate, "native_listing", side_effect=listing), \
                            patch.object(gate.registry, "directory_tree_digest", side_effect=lambda path: "sha256:" + path.parent.name), \
                            patch.object(managed, "validate_release_user_bindings") as release_bindings, \
                            patch.object(managed, "seed_foreign_state") as foreign, patch.object(managed, "seed_retained_data") as restore:
                        if stale_registry:
                            with self.assertRaisesRegex(ValueError, "Copilot native listing mismatch"):
                                managed.run(args, root, helper.case, ctx)
                        else:
                            managed.run(args, root, helper.case, ctx)
                            self.assertEqual(args.failure_phase, "managed:complete")
                        release_bindings.assert_not_called()
                        foreign.assert_not_called()
                        restore.assert_not_called()
                    before_status = next(index for index, event in enumerate(events) if event[:2] == ("command", "deps"))
                    initial = [event[2] for event in events[:before_status] if event[:2] == ("copilot", True)]
                    expected_plugins = {item["product_id"] for item in helper.case["closure"]}
                    self.assertEqual(len(initial), 4)
                    self.assertEqual(set(initial), expected_plugins)
                    orphan_remove = next(index for index, event in enumerate(events) if event == ("command", "remove", None))
                    final = [event[2] for event in events[orphan_remove:] if event[:2] == ("copilot", False)]
                    self.assertTrue(final)
                    if stale_registry:
                        self.assertFalse(any(event[:2] == ("command", "doctor") for event in events))
                    else:
                        self.assertEqual(len(final), 4)
                        self.assertEqual(set(final), expected_plugins)
