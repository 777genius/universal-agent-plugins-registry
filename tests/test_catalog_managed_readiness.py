"""Offline contract tests; no CLI/native runtime or network."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from tests.test_catalog_publication_readiness import catalog
import catalog_publication_readiness as gate
import catalog_managed_readiness as managed


class ManagedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = catalog()
        self.case = managed.expected(self.snapshot, gate.selected)

    def test_separate_case_preserves_legacy_matrix_and_exact_coverage(self):
        self.assertEqual(gate.CLI["version"], "0.1.89")
        self.assertEqual(len([(selection, client) for selection, clients in gate.plan(self.snapshot) for client in clients]), 380)
        self.assertEqual(self.case["cli"]["version"], "0.1.91")
        self.assertEqual(len(managed.coverage(self.case)), 20)
        baseline = copy.deepcopy(self.snapshot)
        baseline["distributions"] = [item for item in baseline["distributions"] if item["id"] != managed.ROOT]
        gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))
        unknown = copy.deepcopy(next(item for item in self.snapshot["distributions"] if item["id"] == managed.ROOT))
        unknown["id"] = "unqualified/new-package"
        self.snapshot["distributions"].append(unknown)
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            gate.policy_scope(baseline, self.snapshot, gate.plan(self.snapshot))

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
                "tree_digest": selected["tree_digest"], "manifest_digest": selected["manifest_digest"], "targets": list(managed.CLIENTS),
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
            for client in managed.CLIENTS:
                path = root / f"{index}-{client}"
                path.mkdir()
                binding = {"client_binding_id": f"b{index}-{client}", "client_id": client, "scope": "user", "materialization": "materialized", "verification": "installation_verified", "target_locator": str(path),
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
            self.assertEqual(len(owned), 20)
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

    def test_offline_artifact_cannot_omit_or_forge_managed_proof(self):
        baseline = copy.deepcopy(self.snapshot)
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
