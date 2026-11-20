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

from tests.test_catalog_publication_readiness import catalog, paired_arguments, ProofTime
import catalog_publication_readiness as gate
import catalog_managed_readiness as managed


class ManagedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = catalog()
        self.case = managed.expected(self.snapshot, gate.selected)

    def test_paired_release_user_preserves_four_identities_and_truthful_vscode_boundary(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": "777genius/universal-agent-plugins-registry"}), \
                patch.object(gate, "datetime", ProofTime):
            args = paired_arguments(Path(temporary))
            snapshot, artifact = gate.canonical_inputs(args)
            user, project = artifact["release_user_dependencies"], artifact["project_dependencies"]
            self.assertNotIn("managed_dependencies", artifact)
            self.assertEqual(user["cli"], managed.CLI)
            self.assertEqual(user["cli"], project["cli"])
            self.assertEqual(user["placement_scope"], "user")
            self.assertEqual(user["proof"]["vscode_qualification"], "source_grant_prepared_only")
            self.assertEqual(managed.immutable_closure(user), managed.immutable_closure(project))
            self.assertEqual(managed.immutable_closure(user), gate.project.REVIEWED_SOURCE_CLOSURE)
            # Root prepared grant belongs to positive policy coverage, never
            # an invented seventh positive User installation.
            self.assertIn((managed.ROOT, 1, "vscode", "user"), managed.coverage(user))
            self.assertNotIn("vscode", user["targets"])
            self.assertFalse(set(user["targets"]) & set(managed.DERIVED_CLIENTS))
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

    def test_separate_case_preserves_matrix_and_exact_coverage(self):
        self.assertEqual(gate.CLI["version"], "0.1.114")
        self.assertEqual(len([(selection, client) for selection, clients in gate.plan(self.snapshot) for client in clients]), 380)
        self.assertEqual(self.case["cli"], managed.CLI)
        self.assertEqual(self.case["targets"], list(managed.CLIENTS))
        self.assertEqual(len(managed.coverage(self.case)), len(managed.PINS) * len(self.case["targets"]) + 1)
        baseline = copy.deepcopy(self.snapshot)
        baseline["distributions"] = [item for item in baseline["distributions"] if item["id"] != managed.ROOT]
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))
        unknown = copy.deepcopy(next(item for item in self.snapshot["distributions"] if item["id"] == managed.ROOT))
        unknown["id"] = "unqualified/new-package"
        self.snapshot["distributions"].append(unknown)
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))

    def test_user_coverage_cannot_qualify_a_project_scope_expansion(self):
        baseline = copy.deepcopy(self.snapshot)
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == "777genius/atlassian")
        target = next(item for item in distribution["release_policies"][0]["targets"] if item["client"] == "codex")
        target["scopes"].append("project")
        with self.assertRaisesRegex(ValueError, "uncovered target policy"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))

    def test_release_user_uses_the_one_pinned_cli_and_six_targets(self):
        case = managed.release_expected(self.snapshot, gate.selected)
        self.assertEqual(case["cli"], managed.CLI)
        self.assertEqual(case["targets"], list(managed.CLIENTS))
        self.assertEqual(len(case["associations"]), 24)
        self.assertEqual(self.case["cli"], managed.CLI)
        missing = copy.deepcopy(self.snapshot)
        policy = next(item for item in missing["distributions"] if item["id"] == managed.ROOT)["release_policies"][0]
        policy["targets"] = [target for target in policy["targets"] if target["client"] != "copilot"]
        with self.assertRaisesRegex(ValueError, "unqualified managed target expansion"):
            managed.release_expected(missing, gate.selected)

    def test_release_user_foreign_skills_project_and_native_members_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
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
            args = SimpleNamespace(binary=tools / "agentplugins",
                                   codex=tools / "codex", claude=tools / "claude", copilot=tools / "copilot",
                                   opencode=tools / "opencode", inspector=None, npx=None)
            actual_validator = gate.project.validate_operation
            with patch.dict(managed.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}):
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

    def test_snapshot_hashes_files_in_bounded_chunks_without_changing_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "large-fixture"
            body = b"snapshot-byte-identity\n" * 100000
            path.write_bytes(body)
            sizes = []
            original_read = os.read
            def bounded_read(fd, size):
                if not 0 < size <= 1024 * 1024:
                    raise AssertionError("snapshot read must have a fixed memory bound")
                sizes.append(size)
                return original_read(fd, size)
            with patch.object(managed.os, "read", side_effect=bounded_read), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded snapshot read")):
                actual = managed.snapshot_paths({"file": path})
            self.assertGreater(len(sizes), 1)
            self.assertEqual(actual, {"file": [(".", path.stat().st_mode & 0o7777,
                                                "file", hashlib.sha256(body).hexdigest())]})

    def test_snapshot_rejects_symlinked_state_ancestor_before_reading_foreign_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outside = root / "outside"
            outside.mkdir()
            (outside / "state-v2.json").write_text("foreign protected bytes")
            home = root / "home"
            home.mkdir()
            alias = home / "state"
            alias.symlink_to(outside, target_is_directory=True)
            self.assertEqual(managed.snapshot_paths({"alias": alias})["alias"][0][2], "symlink")
            with patch.object(managed.os, "read", side_effect=AssertionError("foreign read")):
                with self.assertRaises(ValueError):
                    managed.snapshot_paths({"protected": alias / "state-v2.json"})

    def test_disappearing_descendant_cannot_match_absent_user_root(self):
        for failure in ("file_open", "directory_open", "readlink", "file_read"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                roots = {name: root / name for name in ("home", "config", "state")}
                roots["home"].mkdir()
                roots["state"].mkdir()
                before = managed.snapshot_paths(gate.project.user_paths(roots))
                self.assertEqual(before["config"], [(".", "absent")])
                roots["config"].mkdir()
                leaf = roots["config"] / "child"
                if failure == "directory_open":
                    leaf.mkdir()
                elif failure == "readlink":
                    leaf.symlink_to("missing-target")
                else:
                    leaf.write_bytes(b"new protected state")
                info = leaf.lstat()
                identity = (info.st_dev, info.st_ino)
                triggered = []
                original_open, original_read, original_readlink = os.open, os.read, os.readlink

                def disappearing_open(path, flags, *args, **kwargs):
                    if failure in ("file_open", "directory_open") and path == "child" and "dir_fd" in kwargs:
                        triggered.append(failure)
                        if failure == "directory_open":
                            leaf.rmdir()
                        else:
                            leaf.unlink()
                    return original_open(path, flags, *args, **kwargs)

                def disappearing_readlink(path, *args, **kwargs):
                    if failure == "readlink" and path == "child" and "dir_fd" in kwargs:
                        triggered.append(failure)
                        leaf.unlink()
                    return original_readlink(path, *args, **kwargs)

                def failing_read(fd, size):
                    opened = os.fstat(fd)
                    if failure == "file_read" and (opened.st_dev, opened.st_ino) == identity:
                        triggered.append(failure)
                        raise FileNotFoundError("controlled snapshot read failure")
                    return original_read(fd, size)

                with patch.object(managed.os, "open", side_effect=disappearing_open), \
                        patch.object(managed.os, "readlink", side_effect=disappearing_readlink), \
                        patch.object(managed.os, "read", side_effect=failing_read):
                    with self.assertRaisesRegex(ValueError, "managed snapshot path") as caught:
                        gate.project.validate_user_isolation(before, roots)
                self.assertIsInstance(caught.exception.__cause__, FileNotFoundError)
                self.assertEqual(triggered, [failure])
                self.assertTrue(roots["config"].is_dir())

    def test_snapshot_preserves_missing_ancestors_leaves_and_dangling_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            present = root / "present"
            present.mkdir()
            link = present / "link"
            link.symlink_to("missing-target")
            paths = {"ancestor": root / "missing" / "leaf", "leaf": present / "missing", "link": link}
            expected = {
                "ancestor": [(".", "absent")],
                "leaf": [(".", "absent")],
                "link": [(".", link.lstat().st_mode & 0o7777, "symlink", "missing-target")],
            }
            self.assertEqual(managed.snapshot_paths(paths), expected)

    def test_project_add_reports_fixed_failure_checkpoints_without_child_data(self):
        # Only a fixed phase and exception class may reach the persisted
        # catalog failure artifact, even if the child returns private text.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tools = root / "tools"
            tools.mkdir()
            for name in ("agentplugins", "codex", "claude", "copilot", "opencode"):
                path = tools / name
                path.write_text("#!/bin/sh\\nexit 1\\n")
                path.chmod(0o700)
            args = SimpleNamespace(
                binary=tools / "agentplugins", codex=tools / "codex",
                claude=tools / "claude", copilot=tools / "copilot",
                opencode=tools / "opencode", inspector=None, npx=None,
                failure_phase=None)
            ctx = {"directory_origin": "https://example.invalid/exact-signed-feed/"}
            private = "PRIVATE_CHILD_RESPONSE_DO_NOT_LOG"
            def response(*, code=0, payload=None):
                return SimpleNamespace(returncode=code, stderr=private,
                                       stdout=json.dumps(payload or {}))
            cases = [
                ("isolated_child", ValueError(private), None),
                ("exit", None, response(code=1)),
                ("decode", None, response(payload=["not-a-dict"])),
                ("user_isolation", None, response(payload={"command": "add", "result": "success", "data": {}})),
            ]
            # This test isolates command failure labels. Genuine profile setup
            # and its integration with this runner have a separate test suite.
            with patch.dict(managed.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}), patch.object(
                    gate.project, "initialize_user_profile", side_effect=lambda _args, _root, roots, _env, _readonly:
                    managed.snapshot_paths(gate.project.user_paths(roots))):
                case = gate.project.expected(self.snapshot, gate.selected)
                self.assertIsNotNone(case)
                for index, (expected, raised, completed) in enumerate(cases):
                    with self.subTest(checkpoint=expected), patch.object(
                        gate, "child", side_effect=raised if raised is not None else None,
                        return_value=completed), patch.object(
                        gate.project, "validate_user_isolation",
                        side_effect=ValueError(private) if expected == "user_isolation" else None):
                        args.failure_phase = None
                        with self.assertRaises(ValueError):
                            managed.run(args, root / f"checkpoint-{index}", case, ctx)
                        self.assertEqual(args.failure_phase, f"project:add:{expected}")
                        self.assertNotIn(private, args.failure_phase)

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
            lambda item: item["release_policies"][0].update(minimum_installer_version="0.1.115"),
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
        expected = gate.expected_artifact(self.snapshot, baseline, {"sequence": 42}, {"sequence": 43})
        for mutation in (
            lambda value: value.pop("release_user_dependencies"),
            lambda value: value["release_user_dependencies"]["closure"].pop(),
            lambda value: value["release_user_dependencies"]["associations"].pop(),
            lambda value: value["release_user_dependencies"]["proof"].update(oauth="passed"),
            lambda value: value["release_user_dependencies"]["cli"].update(version="0.1.89"),
            lambda value: value.update(managed_dependencies=copy.deepcopy(value["release_user_dependencies"])),
        ):
            value = copy.deepcopy(expected)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gate.validate_artifact(value, expected)

    def test_snapshot_tracks_files_modes_symlinks_and_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
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


class CurrentRootPolicyTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = catalog()
        self.case = managed.expected(self.snapshot, gate.selected)

    def test_lanes_require_the_one_pinned_binary_and_a_known_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pinned, foreign = root / "pinned", root / "foreign"
            pinned.write_bytes(b"offline pinned binary fixture")
            foreign.write_bytes(b"offline foreign binary fixture")
            with patch.dict(managed.CLI, {"binary_digest": gate.digest(pinned.read_bytes())}), patch.object(gate, "child") as child:
                user = managed.release_expected(self.snapshot, gate.selected)
                project_case = gate.project.expected(self.snapshot, gate.selected)
                for case in (user, project_case):
                    with self.assertRaisesRegex(ValueError, "Codex path must be absolute"):
                        managed.run(SimpleNamespace(binary=pinned, codex=None), root / "not-created", case, {})
                    with self.assertRaisesRegex(ValueError, "wrong managed released binary"):
                        managed.run(SimpleNamespace(binary=foreign, codex=None), root / "not-created", case, {})
                    with self.assertRaisesRegex(ValueError, "missing managed released binary"):
                        managed.run(SimpleNamespace(binary=None, codex=None), root / "not-created", case, {})
                    with self.assertRaisesRegex(ValueError, "wrong managed CLI authority"):
                        managed.run(SimpleNamespace(binary=pinned, codex=None), root / "not-created",
                                    {**case, "cli": {**case["cli"], "version": "0.1.104"}}, {})
                for case in ({**user, "placement_scope": "unknown"}, {k: v for k, v in user.items() if k != "placement_scope"},
                             {**user, "targets": list(managed.COPILOT_AUTHORIZED_CLIENTS)}):
                    with self.assertRaisesRegex(ValueError, "targets or scope"):
                        managed.run(SimpleNamespace(binary=pinned, codex=None), root / "not-created", case, {})
                child.assert_not_called()
                self.assertFalse((root / "not-created").exists())

    def test_root_policy_shape_changes_fail_closed(self):
        actual = next(item for item in self.snapshot["distributions"] if item["id"] == managed.ROOT)
        self.assertEqual(set(t["client"] for t in actual["release_policies"][0]["targets"]),
                         set(managed.COPILOT_AUTHORIZED_CLIENTS) | set(managed.DERIVED_CLIENTS))
        for change in ("kiro", "project", "wrong_delivery", "missing_derived", "duplicate_target",
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
            elif change == "missing_derived":
                policy["targets"] = [t for t in policy["targets"] if t["client"] != "hermes"]
            elif change == "duplicate_target":
                policy["targets"].append(copy.deepcopy(policy["targets"][0]))
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


