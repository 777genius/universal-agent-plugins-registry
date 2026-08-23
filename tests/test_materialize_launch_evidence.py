from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import materialize_launch_evidence as evidence
import prepare_directory_publication as prepare


GIT = "/usr/bin/git"


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output([GIT, "-C", str(repo), *args], text=True).strip()


def tuple_value(plugin: str, client: str, ordinal: int) -> dict:
    revision = hashlib.sha1(f"revision-{plugin}".encode()).hexdigest()
    return {
        "product_id": plugin,
        "tree_digest": "sha256:" + hashlib.sha256(f"tree-{plugin}".encode()).hexdigest(),
        "manifest_digest": "sha256:" + hashlib.sha256(f"manifest-{plugin}".encode()).hexdigest(),
        "distribution_id": f"publisher/{plugin}",
        "distribution_kind": "community",
        "release_sequence": 1,
        "package_version": "1.0.0",
        "source_repository": "owner/repository",
        "source_revision": revision,
        "source_path": f"plugins/{plugin}",
        "snapshot_sequence": 1,
        "snapshot_digest": "sha256:" + "1" * 64,
        "binary_digest": "sha256:" + "2" * 64,
        "dependency_identity": f"dependency-{plugin}",
        "installer_version": "0.1.12",
        "adapter_version": "0.1.12",
        "client_version": f"client-{client}-1",
        "os": "linux",
        "architecture": "amd64",
        "observed_at": f"2026-08-23T00:{ordinal:02d}:00Z",
    }


def authoritative_rows() -> list[dict]:
    rows = []
    ordinal = 0
    for plugin in sorted(evidence.HEROES):
        for client in sorted(evidence.HERO_CLIENTS):
            rows.append({
                "id": f"{ordinal:024x}", "scenario": "hero_5x3_runtime",
                "plugin": plugin, "client": client, "level": "runtime",
                "outcome": "passed", "tuple": tuple_value(plugin, client, ordinal),
                "reason": "observed", "details": {
                    "evidence_basis": "protected_external_observer",
                    "native_discovery_proof": True,
                },
            })
            ordinal += 1
    rows.append({
        "id": f"{ordinal:024x}", "scenario": "chatgpt_registered_binding",
        "plugin": "cloudflare-docs", "client": "chatgpt", "level": "oauth",
        "outcome": "passed", "tuple": tuple_value("cloudflare-docs", "chatgpt", ordinal),
        "reason": "observed", "details": {
            "evidence_basis": "protected_external_observer",
            "native_discovery_proof": True,
        },
    })
    return rows


class LaunchEvidenceBundleTests(unittest.TestCase):
    def launch(self, observer: bytes) -> dict:
        return {
            "schema_version": 3,
            "run": {
                "mode": "enforced", "runtime_claims": True,
                "github_sha": "a" * 40, "github_run_id": "123",
                "observer_bundle_digest": evidence.sha256(observer),
            },
            "directory": {"sequence": 7, "snapshot_digest": "sha256:" + "b" * 64},
            "matrix": authoritative_rows(),
            "summary": {"required_gates_complete": True, "hero_runtime_results": 15},
        }

    def build(self, root: Path):
        observer = evidence.canonical_json({"schema_version": 1, "signed": True})
        (root / "launch-evidence.json").write_text(json.dumps(self.launch(observer), indent=2) + "\n")
        (root / "signed-observer-bundle.json").write_bytes(observer)
        with mock.patch.object(evidence, "validate_with_schema"):
            return evidence.build_bundle(
                root, repository="owner/repository",
                workflow="owner/repository/.github/workflows/launch-evidence-e2e.yml",
                source_ref="refs/heads/main", source_digest="a" * 40,
                expected_run_id="123", expected_publication_id="456",
                expected_sequence=7, expected_snapshot_digest="sha256:" + "b" * 64,
                expected_source_commit="c" * 40,
            )

    def test_selects_only_exact_authoritative_runtime_and_oauth_matrix(self) -> None:
        rows = authoritative_rows()
        rows.append({"scenario": "hero_5x3_lifecycle", "level": "materialization"})
        selected = evidence.selected_rows({"matrix": rows})
        self.assertEqual(len(selected), 16)
        self.assertEqual(sum(row["level"] == "runtime" for row in selected), 15)
        self.assertEqual(sum(row["level"] == "oauth" for row in selected), 1)

    def test_duplicate_applicability_is_rejected(self) -> None:
        rows = authoritative_rows()
        rows[-1] = dict(rows[-1], id="different")
        rows.append(dict(rows[-1]))
        with self.assertRaisesRegex(evidence.EvidenceError, "expected 16|duplicate"):
            evidence.selected_rows({"matrix": rows})

    def test_bundle_is_canonical_bounded_and_checksum_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            digest, files = self.build(root)
            self.assertEqual(digest, evidence.sha256(files["launch-evidence.json"]))
            self.assertEqual(len([path for path in files if path.startswith("directory-evidence/records/")]), 16)
            self.assertEqual(
                files["launch-evidence.json"],
                evidence.canonical_json(json.loads(files["launch-evidence.json"])),
            )
            expected_checksums = evidence.checksum_bytes({key: value for key, value in files.items() if key != "SHA256SUMS"})
            self.assertEqual(files["SHA256SUMS"], expected_checksums)
            evidence.write_bundle(root, files)
            evidence.verify_exact_bundle(root, files)
            (root / "extra.json").write_text("{}\n")
            with self.assertRaisesRegex(evidence.EvidenceError, "paths differ"):
                evidence.verify_exact_bundle(root, files)


class PermanentCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "test")
        git(self.repo, "config", "user.email", "test@example.com")
        (self.repo / "registry").mkdir()
        directory = {
            "schema_version": 1,
            "products": [],
            "distributions": [{
                "id": "publisher/demo", "product_id": "demo",
                "release_policies": [{"release_sequence": 1, "current_evidence": []}],
            }],
            "evidence": [],
        }
        (self.repo / "registry" / "directory.json").write_bytes(evidence.canonical_json(directory))
        git(self.repo, "add", "registry/directory.json")
        git(self.repo, "commit", "-qm", "base")
        self.parent = git(self.repo, "rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def files(self) -> tuple[str, dict[str, bytes]]:
        record = {
            "schema_version": 1, "id": "launch/demo/codex/runtime/0123456789abcdef01234567",
            "product_id": "demo", "distribution_id": "publisher/demo", "release_sequence": 1,
            "package_tree_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
            "source_repository": "owner/repository", "source_revision": "3" * 40,
            "source_path": "plugins/demo", "level": "runtime", "outcome": "passed",
            "client": "codex", "client_version": "1", "installer_version": "0.1.12",
            "adapter_version": "0.1.12", "os": "linux", "architecture": "amd64",
            "dependency_identity": "dependency", "observed_at": "2026-08-23T00:00:00Z",
        }
        path = "directory-evidence/records/demo-codex-runtime.json"
        launch = evidence.canonical_json({"launch": True})
        record_body = evidence.canonical_json(record)
        digest = evidence.sha256(launch)
        index = {
            "schema_version": 1, "launch_evidence_digest": digest,
            "repository": "owner/repository",
            "workflow": "owner/repository/.github/workflows/launch-evidence-e2e.yml",
            "source_ref": "refs/heads/main", "source_digest": "4" * 40,
            "records": [{"id": record["id"], "path": path, "digest": evidence.sha256(record_body)}],
        }
        files = {
            "launch-evidence.json": launch,
            "signed-observer-bundle.json": evidence.canonical_json({"bundle": True}),
            path: record_body,
            "directory-evidence/index.json": evidence.canonical_json(index),
        }
        files["SHA256SUMS"] = evidence.checksum_bytes(files)
        return digest, files

    def test_two_ref_commits_are_bounded_and_acyclic(self) -> None:
        digest, files = self.files()
        result = evidence.materialize_commits(
            self.repo, self.repo, self.repo, files, repository="owner/repository",
            main_parent=self.parent, ledger_parent=self.parent, digest=digest,
        )
        ledger = result["ledger_commit"]
        main = result["main_commit"]
        self.assertEqual(git(self.repo, "show", "-s", "--format=%P", ledger), self.parent)
        self.assertEqual(git(self.repo, "show", "-s", "--format=%P", main), self.parent)
        self.assertEqual(git(self.repo, "diff", "--name-only", self.parent, main), "registry/directory.json")
        self.assertEqual(
            subprocess.run(
                [GIT, "-C", str(self.repo), "grep", "-F", ledger, ledger],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).returncode,
            1,
        )
        source = json.loads(subprocess.check_output([
            GIT, "-C", str(self.repo), "show", f"{main}:registry/directory.json",
        ]))
        pointer = source["evidence"][0]
        self.assertEqual(pointer["artifact"]["revision"], ledger)
        self.assertEqual(pointer["trust"]["source_digest"], "4" * 40)
        self.assertEqual(result["approval_target"], self.parent)

    def test_existing_immutable_digest_root_is_rejected(self) -> None:
        digest, files = self.files()
        first = evidence.materialize_commits(
            self.repo, self.repo, self.repo, files, repository="owner/repository",
            main_parent=self.parent, ledger_parent=self.parent, digest=digest,
        )
        git(self.repo, "checkout", "-q", "--detach", first["ledger_commit"])
        with self.assertRaisesRegex(evidence.EvidenceError, "already exists"):
            evidence.materialize_commits(
                self.repo, self.repo, self.repo, files, repository="owner/repository",
                main_parent=first["ledger_commit"], ledger_parent=first["ledger_commit"], digest=digest,
            )

    def test_new_pass_replaces_current_pointer_but_preserves_history(self) -> None:
        _, files = self.files()
        index = json.loads(files["directory-evidence/index.json"])
        current = json.loads(files[index["records"][0]["path"]])
        current.update({"artifact": {}, "trust": {}})
        previous = dict(current)
        previous["id"] = "launch/demo/codex/runtime/previous"
        previous["observed_at"] = "2026-08-22T00:00:00Z"
        source = json.loads((self.repo / "registry" / "directory.json").read_text())
        source["evidence"] = [previous]
        source["distributions"][0]["release_policies"][0]["current_evidence"] = [previous["id"]]

        updated = evidence.update_directory(source, [current])

        self.assertEqual({item["id"] for item in updated["evidence"]}, {previous["id"], current["id"]})
        self.assertEqual(
            updated["distributions"][0]["release_policies"][0]["current_evidence"],
            [current["id"]],
        )


class ProtectedWorkflowChainTests(unittest.TestCase):
    def test_attested_workflow_source_can_differ_from_ledger_artifact_revision(self) -> None:
        leaf = evidence.canonical_json({"schema_version": 1})
        launch = evidence.canonical_json({
            "run": {"mode": "enforced", "runtime_claims": True},
            "summary": {"required_gates_complete": True, "hero_runtime_results": 15},
        })
        record_id = "launch/demo/codex/runtime/0123456789abcdef01234567"
        root = "registry/evidence/sha256/" + hashlib.sha256(launch).hexdigest()
        leaf_path = "directory-evidence/records/demo.json"
        workflow = "owner/repository/.github/workflows/launch-evidence-e2e.yml"
        source_digest = "a" * 40
        ledger_revision = "b" * 40
        index = evidence.canonical_json({
            "launch_evidence_digest": evidence.sha256(launch),
            "records": [{"id": record_id, "path": leaf_path, "digest": evidence.sha256(leaf)}],
            "repository": "owner/repository", "workflow": workflow,
            "source_ref": "refs/heads/main", "source_digest": source_digest,
        })
        pointer = {
            "id": record_id,
            "artifact": {
                "repository": "owner/repository", "revision": ledger_revision,
                "path": f"{root}/{leaf_path}", "digest": evidence.sha256(leaf),
            },
            "trust": {
                "kind": "github_actions", "workflow": workflow,
                "source_ref": "refs/heads/main", "source_digest": source_digest,
                "attested_artifact": {
                    "repository": "owner/repository", "revision": ledger_revision,
                    "path": f"{root}/launch-evidence.json", "digest": evidence.sha256(launch),
                },
                "evidence_index": {
                    "repository": "owner/repository", "revision": ledger_revision,
                    "path": f"{root}/directory-evidence/index.json", "digest": evidence.sha256(index),
                },
            },
        }
        config = {"trusted_evidence_workflows": [{
            "workflow": workflow, "protected_source_ref": "refs/heads/main",
            "source_digest_policy": "protected_workflow_source",
            "allow_self_hosted_runners": False,
        }], "trusted_external_evidence": []}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(prepare, "validate_with_schema"), \
             mock.patch.object(prepare.Path, "is_file", return_value=True), \
             mock.patch.object(prepare.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            prepare.verify_evidence_trust(
                pointer, config, Path(temporary), leaf,
                attested_body=launch, index_body=index,
            )
        command = run.call_args.args[0]
        self.assertIn("--source-digest", command)
        self.assertIn(source_digest, command)
        self.assertNotEqual(source_digest, ledger_revision)


if __name__ == "__main__":
    unittest.main()
