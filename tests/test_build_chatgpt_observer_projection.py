from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_chatgpt_observer_projection as generator  # noqa: E402
import directory_publication as publication  # noqa: E402

publication.OPENSSL = shutil.which("openssl") or publication.OPENSSL
PublicationError = publication.PublicationError


APP_ID = "plugin_asdk_app_" + "a" * 32
SNAPSHOT_DIGEST = ""


class ChatGPTProjectionGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.feed = self.root / "feed"
        self.feed.mkdir()
        (self.feed / "snapshots").mkdir()
        fixture = ROOT / "tests/fixtures/directory-publication"
        shutil.copy(fixture / "latest.json", self.feed / "latest.json")
        shutil.copy(fixture / "trusted-keys.json", self.root / "trusted-keys.json")
        self.snapshot = json.loads((fixture / "snapshot.json").read_text())
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == "example/demo")
        distribution["release_policies"] = [{
            "current_evidence": [],
            "minimum_installer_version": "0.1.6",
            "release_sequence": 2,
            "status": "active",
            "targets": [{
                "app_binding": {"app_key": "demo", "id": APP_ID, "mcp_server": "demo"},
                "authentication": "not_required",
                "client": "chatgpt",
                "delivery": "managed",
                "scopes": ["user"],
            }],
        }]
        self.snapshot["evidence"] = []
        self.write_signed_snapshot()
        self.projection = self.root / "projection"
        (self.projection / ".codex-plugin").mkdir(parents=True)
        self.write_json(self.projection / ".codex-plugin/plugin.json", {
            "name": "demo", "apps": "./.app.json", "mcpServers": "./.mcp.json",
        })
        self.write_json(self.projection / ".app.json", {"apps": {"demo": {"id": APP_ID}}})
        self.write_json(self.projection / ".mcp.json", {
            "mcpServers": {"demo": {"type": "http", "url": "https://docs.example.test/mcp"}},
        })
        self.binary = self.root / "agentplugins"
        self.binary.write_bytes(b"#!/bin/sh\n[ \"$1\" = version ] && printf 'agentplugins 0.1.18\\n'\n")
        self.binary.chmod(0o755)
        self.add = self.root / "add.json"
        self.state = self.root / "state-v2.json"
        self.write_add()
        self.write_state()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_bytes(generator.canonical_output(value))

    def write_signed_snapshot(self) -> None:
        body = publication.canonical_json(self.snapshot)
        digest = publication.sha256_digest(body)
        seeds = json.loads((ROOT / "tests/fixtures/directory-publication/test-private-seeds.json").read_text())
        private = publication.ed25519_private_key(seeds["test-current"])
        signature = publication.ed25519_sign(private, publication.signature_message(body))
        envelope = {
            "algorithm": "Ed25519",
            "envelope_schema_version": 1,
            "key_id": "test-current",
            "sequence": self.snapshot["sequence"],
            "signature": base64.b64encode(signature).decode("ascii"),
            "signature_domain": "UAP-DIRECTORY-SNAPSHOT-ED25519-V1",
            "snapshot_digest": digest,
            "snapshot_schema_version": 1,
        }
        stem = f"{self.snapshot['sequence']:020d}"
        (self.feed / "snapshots" / f"{stem}.json").write_bytes(body)
        (self.feed / "snapshots" / f"{stem}.envelope.json").write_bytes(publication.canonical_json(envelope))
        self.snapshot_digest = digest

    def release(self) -> dict[str, object]:
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == "example/demo")
        return next(item for item in distribution["releases"] if item["sequence"] == 2)

    def write_add(self, mutate=None) -> None:
        release = self.release()
        source = release["package_source"]
        identity = {
            "plugin": "demo",
            "version": release["package_version"],
            "source": f"{source['repository']}//{source['path']}",
            "revision": source["revision"],
            "tree_digest": release["tree_digest"],
            "manifest_digest": release["manifest_digest"],
            "dry_run": False,
        }
        value = {
            "schema_version": 1,
            "command": "add",
            "result": "success",
            "data": {
                **identity,
                "operation_id": "operation-demo",
                "batch": True,
                "status": "completed",
                "succeeded": 1,
                "failed": 0,
                "acquisition": {
                    "acquisition_id": "acquisition-demo",
                    "acquisition_count": 1,
                    "tree_digest": release["tree_digest"],
                    "manifest_digest": release["manifest_digest"],
                    "closure_digest": "sha256:" + "3" * 64,
                    "source_kind": "github",
                    "fetched": True,
                    "validated": True,
                },
                "target_outcomes": {
                    "chatgpt": {
                        "outcome": "passed",
                        "acquisition_id": "acquisition-demo",
                        "tree_digest": release["tree_digest"],
                        "manifest_digest": release["manifest_digest"],
                        "closure_digest": "sha256:" + "3" * 64,
                    },
                },
                "directory": {
                    "product_id": "demo",
                    "distribution_id": "example/demo",
                    "distribution_kind": "upstream",
                    "desired_release_sequence": 2,
                    "snapshot_schema": 1,
                    "snapshot_sequence": 15,
                    "snapshot_digest": self.snapshot_digest,
                },
                "targets": [{
                    "target": "chatgpt",
                    "status": "external_completed",
                    "next_action": "install in ChatGPT",
                    "output": {
                        **identity,
                        "operation_id": "operation-demo",
                        "next_action": "install in ChatGPT",
                        "result": {
                            "installation_id": "installation-demo",
                            "plan": {
                                "client_id": "chatgpt",
                                "scope": "user",
                                "status": "manual_activation_required",
                                "package_mode": "compatibility_projection",
                                "activation": "manual_activation_required",
                                "authentication": "not_required",
                                "policy": "allowed",
                                "verification": "package_validated",
                                "physical_artifact_id": "demo-fixture",
                                "components": [
                                    {"kind": "app", "name": "demo", "support": "projected"},
                                    {"kind": "mcp_server", "name": "demo", "support": "projected"},
                                ],
                                "user_actions": ["install in ChatGPT"],
                                "warnings": [],
                            },
                            "activation": {
                                "activation": "manual_activation_required",
                                "authentication": "not_required",
                                "policy": "allowed",
                                "verification": "package_validated",
                                "user_actions": ["install in ChatGPT"],
                            },
                            "requires_confirmation": False,
                            "mutated": True,
                            "group_phase": "external_completed",
                        },
                    },
                }],
            },
        }
        if mutate:
            mutate(value)
        self.write_json(self.add, value)

    def write_state(self, mutate=None) -> None:
        fixture = json.loads((ROOT / "tests/fixtures/agentplugins-0.1.14/state-v2.json").read_text())
        release = self.release()
        source = release["package_source"]
        installation = fixture["installations"][0]
        installation["installation_id"] = "installation-demo"
        installation["declared_name"] = "demo"
        installation["origin_mode"] = "directory"
        installation["directory"] = {
            "product_id": "demo", "distribution_id": "example/demo", "distribution_kind": "upstream",
            "desired_release_sequence": 2, "snapshot_schema": 1, "snapshot_sequence": 15,
            "snapshot_digest": self.snapshot_digest,
        }
        installation["source"].update({
            "repository": source["repository"], "package_subpath": source["path"],
            "resolved_revision": source["revision"], "tree_digest": release["tree_digest"],
        })
        installation["package"].update({
            "declared_name": "demo", "version": release["package_version"],
            "manifest_digest": release["manifest_digest"],
        })
        original = next(iter(installation["clients"].values()))
        original.update({
            "client_id": "chatgpt", "target_locator": str(self.projection),
            "physical_artifact_id": "demo-fixture",
            "package_revision": {
                "version": release["package_version"], "resolved_revision": source["revision"],
                "tree_digest": release["tree_digest"], "manifest_digest": release["manifest_digest"],
                "distribution_id": "example/demo", "release_sequence": 2,
            },
            "affected_surfaces": ["chatgpt"],
        })
        managed_digest = generator.projection_artifact_digest(self.projection)
        original["native_objects"] = [{
            "object_id": "package:chatgpt:demo-fixture",
            "kind": "managed_package_directory",
            "logical_name": "demo",
            "path": str(self.projection),
            "managed_digest": managed_digest,
            "protection_class": "managed",
        }]
        receipt = original["receipts"][-1]
        receipt.update({
            "client_binding_id": original["client_binding_id"],
            "active_path": str(self.projection),
            "staging_path": str(self.projection.parent / ".agentplugins-staging-demo"),
            "backup_path": str(self.projection.parent / ".agentplugins-backup-demo"),
            "after_digest": managed_digest,
        })
        installation["clients"] = {original["client_binding_id"]: original}
        if mutate:
            mutate(fixture)
        self.write_json(self.state, fixture)

    def args(self, output: Path | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            feed=self.feed,
            trusted_keys=self.root / "trusted-keys.json",
            now="2026-08-30T00:00:00Z",
            minimum_sequence=15,
            add_evidence=self.add,
            state=self.state,
            projection_root=self.projection,
            cli_binary=self.binary,
            installer_version="0.1.18",
            product_id="demo",
            distribution_id="example/demo",
            release_sequence=2,
            app_key="demo",
            app_id=APP_ID,
            observed_at="2026-08-30T00:00:00Z",
            output=output or self.root / "generated",
        )

    def generate(self, output: Path | None = None) -> tuple[dict[str, object], dict[str, object]]:
        args = self.args(output)
        app, receipt = generator.build(args)
        generator.write_outputs(args.output, app, receipt)
        return app, receipt

    def test_builds_existing_canonical_contract_from_signed_and_cli_evidence(self) -> None:
        self.assertEqual(
            generator.projection_artifact_digest(self.projection),
            "sha256:ff1ef3d924a011c7d8139e5ef721cda5561e5a5c18bc5c76a537c73c6b66d956",
        )
        app, receipt = self.generate()
        self.assertEqual(app, {"apps": {"demo": {"id": APP_ID}}})
        self.assertEqual(receipt["application_id"], APP_ID)
        self.assertEqual(receipt["product_id"], "demo")
        self.assertEqual(receipt["tuple"], {
            "adapter_version": "0.1.18",
            "architecture": "amd64",
            "binary_digest": "sha256:" + hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "client_version": None,
            "dependency_identity": "remote-mcp:docs.example.test",
            "distribution_id": "example/demo",
            "distribution_kind": "upstream",
            "installer_version": "0.1.18",
            "manifest_digest": "sha256:" + "2" * 64,
            "observed_at": "2026-08-30T00:00:00Z",
            "os": "linux",
            "package_version": "1.0.0",
            "product_id": "demo",
            "release_sequence": 2,
            "snapshot_digest": self.snapshot_digest,
            "snapshot_sequence": 15,
            "source_path": "plugins/demo",
            "source_repository": "example/plugins",
            "source_revision": "a" * 40,
            "tree_digest": "sha256:" + "1" * 64,
        })
        for name, value in (("app-binding.json", app), ("projection-receipt.json", receipt)):
            body = (self.root / "generated" / name).read_bytes()
            self.assertEqual(body, generator.canonical_output(value))
            self.assertFalse(body.endswith(b"\n"))
            self.assertEqual((self.root / "generated" / name).stat().st_mode & 0o777, 0o640)

    def test_same_inputs_produce_identical_bytes(self) -> None:
        self.generate(self.root / "first")
        self.generate(self.root / "second")
        for name in ("app-binding.json", "projection-receipt.json"):
            self.assertEqual((self.root / "first" / name).read_bytes(), (self.root / "second" / name).read_bytes())

    def test_wrong_requested_or_projected_app_id_fails_closed(self) -> None:
        for label, mutate in (
            ("argument", lambda: setattr(self.args(), "app_id", "plugin_asdk_app_" + "b" * 32)),
            ("projection", lambda: self.write_json(self.projection / ".app.json", {"apps": {"demo": {"id": "plugin_asdk_app_" + "b" * 32}}})),
        ):
            with self.subTest(label=label):
                args = self.args(self.root / f"out-{label}")
                if label == "argument":
                    args.app_id = "plugin_asdk_app_" + "b" * 32
                else:
                    mutate()
                with self.assertRaises(PublicationError):
                    generator.build(args)
                self.assertFalse(args.output.exists())
                if label == "projection":
                    self.write_json(self.projection / ".app.json", {"apps": {"demo": {"id": APP_ID}}})

    def test_stale_snapshot_fails_closed(self) -> None:
        self.snapshot["expires_at"] = "2026-08-29T00:00:00Z"
        self.write_signed_snapshot()
        with self.assertRaisesRegex(PublicationError, "expired"):
            generator.build(self.args())

    def test_release_source_and_digest_mismatches_fail_closed(self) -> None:
        cases = (
            ("source", lambda value: value["data"].update({"revision": "b" * 40})),
            ("digest", lambda value: value["data"]["directory"].update({"snapshot_digest": "sha256:" + "0" * 64})),
            ("release", lambda value: value["data"]["directory"].update({"desired_release_sequence": 1})),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                self.write_add(mutate)
                with self.assertRaises(PublicationError):
                    generator.build(self.args())
                self.write_add()

    def test_wrong_cli_version_and_extra_signed_target_field_fail_closed(self) -> None:
        self.binary.write_bytes(b"#!/bin/sh\nprintf 'agentplugins 0.1.19\\n'\n")
        self.binary.chmod(0o755)
        with self.assertRaisesRegex(PublicationError, "version output"):
            generator.build(self.args())
        self.binary.write_bytes(b"#!/bin/sh\n[ \"$1\" = version ] && printf 'agentplugins 0.1.18\\n'\n")
        self.binary.chmod(0o755)
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == "example/demo")
        distribution["release_policies"][0]["targets"][0]["app_binding"]["extra"] = True
        self.write_signed_snapshot()
        with self.assertRaises(PublicationError):
            generator.build(self.args())

    def test_ambiguous_state_client_and_extra_projection_field_fail_closed(self) -> None:
        def duplicate(state):
            installation = state["installations"][0]
            client = copy.deepcopy(next(iter(installation["clients"].values())))
            client["client_binding_id"] = "client-second"
            installation["clients"]["client-second"] = client

        self.write_state(duplicate)
        with self.assertRaises(PublicationError):
            generator.build(self.args())
        self.write_state()
        self.write_json(self.projection / ".app.json", {"apps": {"demo": {"id": APP_ID, "extra": True}}})
        with self.assertRaises(PublicationError):
            generator.build(self.args())

    def test_output_directory_is_create_once(self) -> None:
        self.generate()
        with self.assertRaisesRegex(PublicationError, "already exists"):
            self.generate()

    def test_existing_empty_output_directory_is_never_replaced(self) -> None:
        output = self.root / "occupied"
        output.mkdir()
        app, receipt = generator.build(self.args(output))
        with self.assertRaisesRegex(PublicationError, "already exists"):
            generator.write_outputs(output, app, receipt)
        self.assertEqual(list(output.iterdir()), [])

    def test_projection_byte_tamper_fails_managed_receipt_binding(self) -> None:
        self.write_json(self.projection / ".mcp.json", {
            "mcpServers": {"demo": {"type": "http", "url": "https://evil.example.test/mcp"}},
        })
        with self.assertRaisesRegex(PublicationError, "managed projection digest"):
            generator.build(self.args())

    def test_binary_path_swap_executes_authenticated_image_and_fails_authority_recheck(self) -> None:
        real_run = generator.subprocess.run
        original_parent = self.binary.parent
        moved_parent = original_parent.with_name(original_parent.name + "-moved")

        def swap_then_run(*args, **kwargs):
            original_parent.rename(moved_parent)
            original_parent.mkdir()
            replacement = original_parent / "agentplugins"
            replacement.write_bytes(b"#!/bin/sh\nprintf 'agentplugins 9.9.9\\n'\n")
            replacement.chmod(0o755)
            return real_run(*args, **kwargs)

        with mock.patch.object(generator.subprocess, "run", side_effect=swap_then_run):
            with self.assertRaisesRegex(PublicationError, "ancestor pathname was replaced"):
                generator.validate_binary(self.binary, "0.1.18")
        shutil.rmtree(original_parent)
        moved_parent.rename(original_parent)

    def test_binary_leaf_swap_cannot_change_executed_image(self) -> None:
        saved = self.binary.with_name("agentplugins-authenticated")
        real_run = generator.subprocess.run
        observed: list[str] = []

        def swap_then_run(*args, **kwargs):
            self.binary.rename(saved)
            self.binary.write_bytes(b"#!/bin/sh\nprintf 'agentplugins 9.9.9\\n'\n")
            self.binary.chmod(0o755)
            completed = real_run(*args, **kwargs)
            observed.append(completed.stdout)
            return completed

        try:
            with mock.patch.object(generator.subprocess, "run", side_effect=swap_then_run):
                with self.assertRaisesRegex(PublicationError, "changed during version verification"):
                    generator.validate_binary(self.binary, "0.1.18")
            self.assertEqual(observed, ["agentplugins 0.1.18\n"])
        finally:
            self.binary.unlink(missing_ok=True)
            saved.rename(self.binary)

    def test_atomic_publish_loses_race_without_replacing_winner(self) -> None:
        output = self.root / "raced"
        app, receipt = generator.build(self.args(output))
        real_rename = generator._rename_noreplace

        def install_winner(parent_descriptor, source, destination):
            os.mkdir(destination, mode=0o700, dir_fd=parent_descriptor)
            winner_dir = os.open(destination, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_descriptor)
            try:
                winner = os.open("winner", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=winner_dir)
                try:
                    os.write(winner, b"winner")
                finally:
                    os.close(winner)
            finally:
                os.close(winner_dir)
            return real_rename(parent_descriptor, source, destination)

        with mock.patch.object(generator, "_rename_noreplace", side_effect=install_winner):
            with self.assertRaisesRegex(PublicationError, "already exists"):
                generator.write_outputs(output, app, receipt)
        self.assertEqual((output / "winner").read_bytes(), b"winner")


if __name__ == "__main__":
    unittest.main()
