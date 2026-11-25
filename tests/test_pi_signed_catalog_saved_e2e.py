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
             "package_version": "1.0.0", "components": ["mcp"],
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
             "snapshot_digest": "sha256:" + "d" * 64,
             "installed_dependency_count": 1,
             "installed_distributions": [s["distribution"]]}
            for s, scope in subject.expected_shard(sources, shard)
        ]
        expected = (48, "sha256:" + "d" * 64)
        subject.verify_shard(reports, sources, shard, expected)
        for wrong in ((49, expected[1]), (48, "sha256:" + "e" * 64),
                      (True, expected[1]), (48, "bad")):
            with self.subTest(pin=wrong), self.assertRaises(RuntimeError):
                subject.verify_shard(reports, sources, shard, wrong)
        for bad in (reports[:-1], reports + [reports[0]],
                    [dict(reports[0], status="skipped"), *reports[1:]],
                    [dict(reports[0], status="refused"), *reports[1:]],
                    [dict(reports[0], snapshot_sequence=None), *reports[1:]],
                    [dict(reports[0], installed_dependency_count=0), *reports[1:]],
                    [dict(reports[0], installed_dependency_count=2), *reports[1:]],
                    [dict(reports[0], installed_distributions=None), *reports[1:]],
                    [dict(reports[0], installed_distributions=[{}]), *reports[1:]],
                    [dict(reports[0], installed_distributions=["wrong/root"]), *reports[1:]],
                    [dict(reports[0], installed_dependency_count=2,
                          installed_distributions=[reports[0]["distribution"]] * 2), *reports[1:]]):
            with self.subTest(bad=bad[0]), self.assertRaises(RuntimeError):
                subject.verify_shard(bad, sources, shard, expected)

    def test_wrong_authenticated_publication_refused_before_add(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            item = self.sources()[0]
            with (
                patch.object(subject, "fresh_case", return_value=({}, root, root, root)),
                patch.object(subject, "native_root", return_value=root),
                patch.object(subject, "native_fingerprint", return_value={}),
                patch.object(subject, "signed_info",
                             return_value={"snapshot": (49, "sha256:" + "d" * 64)}),
                patch.object(subject, "invoke") as invoke,
            ):
                with self.assertRaisesRegex(RuntimeError, "expected approved publication"):
                    subject.run_case("cli", root, item, "project", (50, "sha256:" + "e" * 64))
                invoke.assert_not_called()

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

    def test_native_extensions_reject_directory_only_or_empty_placeholder(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "extensions" / "nested").mkdir(parents=True)
            with self.assertRaises(RuntimeError):
                subject.check_native_contract(root, ["extensions"])
            extension = root / "extensions" / "nested" / "plugin.ts"
            extension.write_text("", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                subject.check_native_contract(root, ["extensions"])
            extension.write_text("export default {};\n", encoding="utf-8")
            subject.check_native_contract(root, ["extensions"])

    def test_doctor_cannot_mutate_saved_files_or_either_native_scope(self):
        valid = {"command": "doctor", "data": {
            "read_only": True, "installation_count": 1,
            "open_operation_count": 0, "findings": []}}
        for scope in ("user", "project"):
            for target in ("uap.lock", "uap.toml", "active", "other"):
                with self.subTest(scope=scope, target=target):
                    with tempfile.TemporaryDirectory() as d:
                        root = Path(d)
                        portable = root / "portable"
                        portable.mkdir()
                        (portable / "uap.lock").write_text("lock-before", encoding="utf-8")
                        (portable / "uap.toml").write_text("toml-before", encoding="utf-8")
                        project = root / "project"
                        project.mkdir()
                        env = {"PI_CODING_AGENT_DIR": str(root / "home" / ".pi" / "agent")}
                        active = subject.native_root(env, project, scope)
                        other_scope = "project" if scope == "user" else "user"
                        other = subject.native_root(env, project, other_scope)
                        if target in ("active", "other"):
                            path = (active if target == "active" else other) / "unexpected.txt"
                            path.parent.mkdir(parents=True, exist_ok=True)
                        else:
                            path = portable / target

                        def mutate(*_args):
                            path.write_text("modified", encoding="utf-8")
                            return valid

                        with patch.object(subject, "invoke", side_effect=mutate):
                            with self.assertRaisesRegex(RuntimeError, "doctor modified"):
                                subject.observe_readonly_doctor(
                                    "cli", env, project, portable, scope, "root", 1)
                        with patch.object(subject, "invoke", return_value=valid):
                            subject.observe_readonly_doctor(
                                "cli", env, project, portable, scope, "root", 1)

    def test_marketing_kit_dependency_closure_cannot_omit_hubspot(self):
        required = {"777genius/marketing-kit", "777genius/notion",
                    "777genius/hubspot-crm", "777genius/playwright-bridge"}
        subject.check_known_dependency_closure("777genius/marketing-kit", required)
        for child in required:
            with self.subTest(child=child), self.assertRaises(RuntimeError):
                subject.check_known_dependency_closure("777genius/marketing-kit",
                                                       required - {child})
        with self.assertRaises(RuntimeError):
            subject.check_known_dependency_closure("777genius/marketing-kit",
                                                   required | {"777genius/unreviewed"})

    def test_dependency_graph_rejects_reachable_cycles_and_orphans(self):
        def graph(**parents):
            return {alias: {"required_by": [{"alias": parent} for parent in edges]}
                    for alias, edges in parents.items()}

        subject.check_dependency_graph(graph(root=[]), "root")
        subject.check_dependency_graph(
            graph(root=[], a=["root"], b=["root"], c=["a", "b"]), "root")
        for invalid in (graph(root=[], a=["root", "b"], b=["a"]),
                        graph(root=[], a=["root", "a"]),
                        graph(root=[], a=[]),
                        graph(root=[], a=["b"], b=["a"])):
            with self.subTest(graph=invalid), self.assertRaisesRegex(
                    RuntimeError, "orphaned or cyclic"):
                subject.check_dependency_graph(invalid, "root")

    def test_authored_revision_is_not_current_test_commit(self):
        item = self.sources()[0]
        release = {"release_sequence": 1, "resolved_revision": "d" * 40,
                   "package_version": item["package_version"],
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

    def test_authored_version_must_match_normalized_signed_info(self):
        item = self.sources()[0]
        release = {"release_sequence": 1, "resolved_revision": item["revision"],
                   "repository": "777genius/example-00", "package_path": "packages/00",
                   "tree_digest": item["tree_digest"], "manifest_digest": item["manifest_digest"],
                   "package_version": ""}
        with self.assertRaisesRegex(RuntimeError, "reviewed catalog source"):
            subject.check_root_source({"release": release}, item)
        item["package_version"] = ""
        subject.check_root_source({"release": release}, item)
        release["package_version"] = "1.0.0"
        with self.assertRaisesRegex(RuntimeError, "reviewed catalog source"):
            subject.check_root_source({"release": release}, item)

    def test_saved_version_wire_omission_only_for_versionless_release(self):
        missing = object()
        for signed_version, lock_version, receipt_version, passes in (
            ("", missing, missing, True),
            ("", "", "", True),
            ("", None, missing, False),
            ("", missing, None, False),
            ("", "1.0.0", missing, False),
            ("", missing, "1.0.0", False),
            ("1.0.0", "1.0.0", "1.0.0", True),
            ("1.0.0", missing, "1.0.0", False),
            ("1.0.0", "1.0.0", missing, False),
        ):
            with self.subTest(version=signed_version, passes=passes), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                project = root / "project"
                project.mkdir()
                env = {"PI_CODING_AGENT_DIR": str(root / "native")}
                native = subject.native_root(env, project, "user")
                native.mkdir()
                (native / "mcp.json").write_text(
                    '{"mcpServers":{"example":{"command":"node"}}}', encoding="utf-8")
                source = self.sources()[0]
                source["package_version"] = signed_version
                dist, alias = source["distribution"], source["manifest_name"]
                release = {"id": dist, "release_sequence": 1,
                           "resolved_revision": source["revision"],
                           "repository": "777genius/example-00", "package_path": "packages/00",
                           "tree_digest": source["tree_digest"], "manifest_digest": source["manifest_digest"],
                           "package_version": signed_version}
                package = {"alias": alias, "source_key": "directory:" + dist, "targets": ["pi"],
                           "tree_digest": release["tree_digest"], "manifest_digest": release["manifest_digest"],
                           "source": {"registry": {"distribution": dist, "distribution_id": dist,
                                                   "product_id": "example", "release_sequence": 1,
                                                   "repository": release["repository"], "path": release["package_path"],
                                                   "commit": release["resolved_revision"]}}}
                revision = {"distribution_id": dist, "release_sequence": 1,
                            "resolved_revision": release["resolved_revision"],
                            "tree_digest": release["tree_digest"], "manifest_digest": release["manifest_digest"]}
                if lock_version is not missing:
                    package["version"] = lock_version
                if receipt_version is not missing:
                    revision["version"] = receipt_version
                (root / "uap.lock").write_text(json.dumps({"packages": [package]}), encoding="utf-8")
                receipt = {"installation_id": "example-owner", "directory": {
                    "recorded_distribution": dist, "recorded_release_sequence": 1,
                    "recorded_revision": release["resolved_revision"], "recorded_snapshot_sequence": 49},
                    "clients": [{"client_id": "pi", "scope": "user", "materialization": "materialized",
                                 "verification": "installation_verified", "package_revision": revision}]}
                info = {"product_id": "example", "release": release, "snapshot": (49, "sha256:" + "d" * 64)}
                with (patch.object(subject, "signed_info", return_value=info),
                      patch.object(subject, "invoke", return_value={"data": {"installations": [receipt]}}),
                      patch.object(subject, "observe_readonly_doctor")):
                    args = ("cli", env, project, root, "user", source, {}, {}, info["snapshot"])
                    if passes:
                        subject.inspect_saved(*args)
                    else:
                        with self.assertRaises(RuntimeError):
                            subject.inspect_saved(*args)

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
            release = record["data"]["selected_release"]
            # An upstream manifest may have no version. Its authenticated
            # source SHA, digests and release sequence remain required.
            release["package_version"] = ""
            self.assertEqual("", subject.signed_info(
                "cli", {}, Path("."), "777genius/a", "user")["release"]["package_version"])
            release["resolved_revision"] = "not-a-commit"
            with self.assertRaisesRegex(RuntimeError, "identity"):
                subject.signed_info("cli", {}, Path("."), "777genius/a", "user")
            release["resolved_revision"] = "a" * 40
            release["manifest_digest"] = "not-a-digest"
            with self.assertRaisesRegex(RuntimeError, "identity"):
                subject.signed_info("cli", {}, Path("."), "777genius/a", "user")
            release["manifest_digest"] = "sha256:" + "c" * 64
            del release["package_version"]
            self.assertEqual("", subject.signed_info(
                "cli", {}, Path("."), "777genius/a", "user")["release"]["package_version"])
            for invalid in (None, 1, False):
                release["package_version"] = invalid
                with self.assertRaisesRegex(RuntimeError, "identity"):
                    subject.signed_info("cli", {}, Path("."), "777genius/a", "user")


if __name__ == "__main__":
    unittest.main()
