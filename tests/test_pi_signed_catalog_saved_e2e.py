"""Offline fail-closed tests. Never grant production signing/eligibility."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pi_signed_catalog_saved_e2e as subject


class FullSignedCatalogTests(unittest.TestCase):
    def sources(self):
        return [
            {"distribution": f"777genius/example-{i:02d}", "release_sequence": 1,
             "distribution_status": "active", "manifest_name": f"example-{i:02d}",
             "revision": "a" * 40, "authored_revision": "a" * 40,
             "source": f"github:777genius/example-{i:02d}@{'a'*40}//packages/{i:02d}",
             "tree_digest": "sha256:" + "b" * 64,
             "manifest_digest": "sha256:" + "c" * 64}
            for i in range(36)
        ] + [{"distribution": "777genius/suspended", "release_sequence": 1,
              "distribution_status": "suspended"}]

    def test_six_shards_cover_every_active_release_scope_once(self):
        sources = self.sources()
        cases = [
            (s["distribution"], s["release_sequence"], scope)
            for shard in range(subject.SHARDS)
            for s, scope in subject.expected_shard(sources, shard)
        ]
        self.assertEqual(72, len(cases))
        self.assertEqual(72, len(set(cases)))
        self.assertFalse(any("suspended" in label for label, _, _ in cases))

    def test_missing_duplicate_or_skipped_case_never_passes_shard(self):
        sources = self.sources()
        shard = 0
        reports = [
            {"distribution": s["distribution"], "release_sequence": s["release_sequence"],
             "scope": scope, "status": "passed", "snapshot_sequence": 48,
             "installed_dependency_count": 1}
            for s, scope in subject.expected_shard(sources, shard)
        ]
        subject.verify_shard(reports, sources, shard)
        for bad in (reports[:-1], reports + [reports[0]],
                    [dict(reports[0], status="skipped"), *reports[1:]],
                    [dict(reports[0], status="refused"), *reports[1:]],
                    [dict(reports[0], snapshot_sequence=None), *reports[1:]],
                    [dict(reports[0], installed_dependency_count=0), *reports[1:]]):
            with self.subTest(bad=bad[0]), self.assertRaises(RuntimeError):
                subject.verify_shard(bad, sources, shard)

    def test_catalog_drift_or_bad_shard_fails(self):
        with self.assertRaises(RuntimeError):
            subject.expected_shard(self.sources()[:-2], 0)
        with self.assertRaises(RuntimeError):
            subject.expected_shard(self.sources(), 6)

    def test_native_snapshot_checks_actual_bytes_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            file = root / "mcp.json"
            file.write_text('{"mcpServers":{}}', encoding="utf-8")
            before = subject.native_fingerprint(root)
            file.write_text('{"mcpServers":{"evil":{}}}', encoding="utf-8")
            self.assertNotEqual(before, subject.native_fingerprint(root))
            link = root / "linked.json"
            try:
                link.symlink_to(file)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this Windows test runner")
            with self.assertRaises(RuntimeError):
                subject.native_fingerprint(root)

    def test_native_transport_requires_nonempty_mcp_and_valid_skill(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(RuntimeError):
                subject.check_native_contract(root, ["mcp"])
            (root / "mcp.json").write_text('{"mcpServers":{"empty":{}}}', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                subject.check_native_contract(root, ["mcp"])
            (root / "mcp.json").write_text(
                '{"mcpServers":{"real":{"command":"node","args":["server.js"]}}}',
                encoding="utf-8")
            subject.check_native_contract(root, ["mcp"])
            with self.assertRaises(RuntimeError):
                subject.check_native_contract(root, ["mcp", "skills"])
            skill = root / "skills" / "sample" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("A real skill", encoding="utf-8")
            subject.check_native_contract(root, ["mcp", "skills"])

    def test_authored_revision_is_not_current_test_commit(self):
        item = self.sources()[0]
        release = {"release_sequence": 1, "resolved_revision": "d" * 40,
                   "repository": "777genius/example-00", "package_path": "packages/00",
                   "tree_digest": item["tree_digest"],
                   "manifest_digest": item["manifest_digest"]}
        with self.assertRaises(RuntimeError):
            subject.check_root_source({"release": release}, item)
        item["authored_revision"] = None
        subject.check_root_source({"release": release}, item)
        release["repository"] = "777genius/other"
        with self.assertRaises(RuntimeError):
            subject.check_root_source({"release": release}, item)
        release["repository"] = "777genius/example-00"
        release["tree_digest"] = "sha256:" + "e" * 64
        with self.assertRaises(RuntimeError):
            subject.check_root_source({"release": release}, item)

    def test_signed_info_rejects_missing_pi_grant(self):
        record = {"command": "info", "result": "success", "data": {
            "selected_distribution": "777genius/a", "product_id": "id",
            "snapshot_sequence": 48, "snapshot_digest": "sha256:" + "0" * 64,
            "selected_release": {
                "id": "777genius/a", "release_status": "active",
                "release_sequence": 1, "resolved_revision": "a" * 40,
                "repository": "777genius/a", "package_path": "",
                "tree_digest": "sha256:" + "b" * 64,
                "manifest_digest": "sha256:" + "c" * 64,
                "package_version": "0.1.0", "target_compatibility": []}}}
        with patch.object(subject, "invoke", return_value=record):
            with self.assertRaisesRegex(RuntimeError, "grant"):
                subject.signed_info("cli", {}, Path("."), "777genius/a", "user")
            record["data"]["selected_release"]["target_compatibility"] = [
                {"client": "pi", "delivery": "managed", "scopes": ["user"]}]
            self.assertEqual((48, "sha256:" + "0" * 64),
                             subject.signed_info("cli", {}, Path("."), "777genius/a", "user")["snapshot"])


if __name__ == "__main__":
    unittest.main()
