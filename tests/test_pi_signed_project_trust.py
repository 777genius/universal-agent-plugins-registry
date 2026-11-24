"""Offline Project trust oracle regressions; not native Pi or production evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pi_signed_project_trust as trust
from pi_signed_catalog_saved_e2e import native_fingerprint


class PiProjectTrustTests(unittest.TestCase):
    def fixture(self, root):
        project, user = root / "project", root / "user"
        project.mkdir()
        project = project.resolve()
        user.mkdir()
        native = project / ".pi"
        artifact = native / "extensions" / "physical-id"
        artifact.mkdir(parents=True)
        (artifact / "payload.txt").write_bytes(b"package")
        skill = native / "skills" / "owned-skill"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_bytes(b"skill")
        server = {"url": "https://example.invalid/mcp", "timeout": 5}
        mcp = native / "mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"owned-mcp": server}}), encoding="utf-8")
        seq, snapshot = 49, "sha256:" + "a" * 64
        dist, alias, owner, binding_id = "example/pkg", "pkg", "installation-id", "binding-id"
        digest, manifest, revision = "sha256:" + "b" * 64, "sha256:" + "c" * 64, "d" * 40
        package = {"source_key": "directory:" + dist, "tree_digest": digest,
                   "manifest_digest": manifest, "source": {"registry": {
                       "distribution_id": dist, "release_sequence": 1, "commit": revision}}}
        binding = {"client_binding_id": binding_id, "client_id": "pi", "scope": "project",
                   "physical_artifact_id": "physical-id", "target_locator": str(artifact),
                   "native_objects": [
                       {"kind": "pi_project_skill_directory", "logical_name": "owned-skill", "path": str(skill)},
                       {"kind": "pi_project_mcp_server", "logical_name": "owned-mcp", "path": str(mcp)}]}
        state = {"schema_version": 5, "installations": [{
            "installation_id": owner, "origin_mode": "directory", "directory": {
                "distribution_id": dist, "desired_release_sequence": 1,
                "snapshot_sequence": seq, "snapshot_digest": snapshot},
            "source": {"resolved_revision": revision, "tree_digest": digest},
            "package": {"manifest_digest": manifest}, "clients": {binding_id: binding}}],
            "environment_receipts": [{"alias": alias, "client_id": "pi", "installation_id": owner,
                                      "client_binding_id": binding_id, "source_key": "directory:" + dist,
                                      "package_digest": digest}]}
        state_path = project / ".uap" / "state-v2.json"
        state_path.parent.mkdir()
        state_path.write_text(json.dumps(state), encoding="utf-8")
        hook = user / trust.HOOK_ENTRY
        hook.parent.mkdir(parents=True)
        hook.write_bytes(b"test-only hook bytes")
        doc = {"schema_version": 1, "projects": {str(project): {"physical-id": {
            "extensions": {"physical-id": trust.trust_tree_digest(artifact)},
            "skills": {"owned-skill": trust.trust_tree_digest(skill)},
            "mcp_servers": {"owned-mcp": trust.trust_value_digest(server)}}}}}
        record = user / trust.HOOK_RECORD
        record.write_text(json.dumps(doc), encoding="utf-8")
        return user, project, {alias: package}, {dist: owner}, (seq, snapshot)

    def test_trust_digests_use_producer_framing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nested").mkdir()
            (root / "nested" / "a").write_bytes(b"payload")
            framed = b"d\0nested\0f\0nested/a\0" + hashlib.sha256(b"payload").hexdigest().encode() + b"\0"
            self.assertEqual("sha256:" + hashlib.sha256(framed).hexdigest(),
                             trust.trust_tree_digest(root))
        value = {"é": [True, None, -0.0], "a": "é"}
        framed = "o2:s1:as2:és2:éa3:tnd8000000000000000".encode("utf-8")
        self.assertEqual("sha256:" + hashlib.sha256(framed).hexdigest(),
                         trust.trust_value_digest(value))

    def test_project_record_requires_exact_hook_receipt_and_bytes(self):
        for tamper in ("none", "hook", "record", "owner", "skill", "mcp", "foreign", "duplicate"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as tmp:
                args = self.fixture(Path(tmp))
                user, project = args[:2]
                if tamper == "hook":
                    (user / trust.HOOK_ENTRY).write_bytes(b"wrong hook")
                elif tamper == "record":
                    (user / trust.HOOK_RECORD).write_text('{"schema_version":1,"projects":{}}')
                elif tamper == "owner":
                    state = project / ".uap" / "state-v2.json"
                    state.write_text(state.read_text().replace("installation-id", "wrong-id"))
                elif tamper == "skill":
                    (project / ".pi/skills/owned-skill/SKILL.md").write_bytes(b"modified")
                elif tamper == "mcp":
                    (project / ".pi/mcp.json").write_text('{"mcpServers":{"owned-mcp":{"url":"https://other.invalid"}}}')
                elif tamper == "foreign":
                    (project / ".pi/settings.json").write_text("{}")
                elif tamper == "duplicate":
                    (user / trust.HOOK_RECORD).write_text('{"schema_version":1,"schema_version":1,"projects":{}}')
                with patch.object(trust, "HOOK_SHA256", hashlib.sha256(b"test-only hook bytes").hexdigest()):
                    if tamper == "none":
                        trust.verify_project_trust(*args)
                    else:
                        with self.assertRaises(RuntimeError):
                            trust.verify_project_trust(*args)

    def test_only_exact_project_trust_files_and_empty_locks_are_permitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            user = args[0]
            for name in trust.HOOK_LOCKS:
                (user / name).write_bytes(b"")
            trust.check_opposite_after_project(user, {}, native_fingerprint(user))
            (user / "settings.json").write_text("{}")
            with self.assertRaises(RuntimeError):
                trust.check_opposite_after_project(user, {}, native_fingerprint(user))
            (user / "settings.json").unlink()
            with self.assertRaises(RuntimeError):
                trust.check_removed(user, {}, native_fingerprint(user), had_mcp=False, project_user=True)
            (user / trust.HOOK_ENTRY).unlink()
            (user / trust.HOOK_RECORD).unlink()
            trust.check_removed(user, {}, native_fingerprint(user), had_mcp=False, project_user=True)
            (user / next(iter(trust.HOOK_LOCKS))).write_bytes(b"foreign")
            with self.assertRaises(RuntimeError):
                trust.check_removed(user, {}, native_fingerprint(user), had_mcp=False, project_user=True)

    def test_empty_mcp_scaffolding_only_after_observed_mcp_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mcp.json").write_text('{"mcpServers":{}}')
            (root / trust.MCP_LOCK).write_bytes(b"")
            trust.check_removed(root, {}, native_fingerprint(root), had_mcp=True)
            with self.assertRaises(RuntimeError):
                trust.check_removed(root, {}, native_fingerprint(root), had_mcp=False)
            (root / "mcp.json").write_text('{"mcpServers":{"leaked":{}}}')
            with self.assertRaises(RuntimeError):
                trust.check_removed(root, {}, native_fingerprint(root), had_mcp=True)


if __name__ == "__main__":
    unittest.main()
