from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts import publish_skillspector_reports as publisher
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError, canonical_json, format_timestamp, sha256_digest
from tests.test_skillspector_reports import item


def report() -> tuple[dict, dict]:
    selection = {"schema_version": 1, "sources": [item()]}
    record = scanner.empty_record(item())
    record["errors"] = [{"code": "acquisition_failed", "message": "Source unavailable."}]
    document = {"schema_version": 1, "source_commit": "c" * 40,
                "generated_at": format_timestamp(datetime.now(timezone.utc) - timedelta(seconds=5)),
                "scope": "selected_sources", "scanner": scanner.SCANNER, "profile": scanner.PROFILE,
                "selection_digest": sha256_digest(canonical_json(selection)), "records": [record]}
    return document, selection


class FakeGitHub:
    def __init__(self, previous: dict | None = None, conflict: bool = False, main: str = "c" * 40):
        self.previous = previous
        self.conflict = conflict
        self.main = main
        self.calls = []

    def request(self, method, path, data=None, **kwargs):
        self.calls.append((method, path, data))
        if path == "git/ref/heads/main":
            return {"object": {"sha": self.main}}
        if method == "GET" and path.startswith("git/ref/"):
            return {"object": {"sha": "a" * 40}} if self.previous else None
        if method == "GET":
            return canonical_json(self.previous)
        if self.conflict and method == "PATCH":
            raise PublicationError("GitHub report publication request failed (HTTP 422)")
        return {"sha": "b" * 40}


class PublicationTests(unittest.TestCase):
    def validate(self, document, selection):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.json").write_bytes(canonical_json(document))
            (root / "selection.json").write_bytes(canonical_json(selection))
            return publisher.validate_report(root / "index.json", root / "selection.json", "c" * 40)

    def test_failed_scan_is_published_truthfully(self):
        document, selection = report()
        self.assertEqual(self.validate(document, selection), document)

    def test_expanded_report_covers_128_selected_roots_and_rejects_129(self):
        document, selection = report()
        selection['sources'] = [item(id=f'fixture/skill-{n}',path=f'skills/skill-{n}') for n in range(128)]
        document['records'] = [scanner.empty_record(source) for source in selection['sources']]
        document['selection_digest'] = sha256_digest(canonical_json(selection))
        self.assertEqual(self.validate(document, selection), document)
        extra = item(id='fixture/skill-128',path='skills/skill-128')
        selection['sources'].append(extra)
        document['records'].append(scanner.empty_record(extra))
        document['selection_digest'] = sha256_digest(canonical_json(selection))
        with self.assertRaises(PublicationError):self.validate(document, selection)

    def test_artifact_must_cover_this_source_and_every_selected_identity(self):
        original, selection = report()
        variants = []
        document = copy.deepcopy(original); document["source_commit"] = "d" * 40; variants.append(document)
        document = copy.deepcopy(original); document["selection_digest"] = "sha256:" + "e" * 64; variants.append(document)
        document = copy.deepcopy(original); document["records"] = []; variants.append(document)
        document = copy.deepcopy(original); document["records"] *= 2; variants.append(document)
        document = copy.deepcopy(original); document["records"][0]["source"]["revision"] = "f" * 40; variants.append(document)
        document = copy.deepcopy(original); document["records"][0]["findings_truncated"] = True; variants.append(document)
        document = copy.deepcopy(original); document["generated_at"] = "2999-01-01T00:00:00Z"; variants.append(document)
        for document in variants:
            with self.subTest(document=document), self.assertRaises(PublicationError):
                self.validate(document, selection)

    def test_initial_publication_creates_only_literal_data_path_and_branch(self):
        document, _ = report()
        github = FakeGitHub()
        publisher.publish(github, document)
        tree = next(data for method, path, data in github.calls if path == "git/trees")
        self.assertEqual(tree, {"tree": [{"path": publisher.REPORT_PATH, "mode": "100644", "type": "blob", "sha": "b" * 40}]})
        commit = next(data for method, path, data in github.calls if path == "git/commits")
        self.assertEqual(commit["parents"], [])
        self.assertEqual(github.calls[-1], ("POST", "git/refs", {"ref": "refs/heads/skillspector-reports", "sha": "b" * 40}))

    def test_newer_report_advances_existing_branch_without_force(self):
        document, _ = report()
        previous = copy.deepcopy(document)
        previous["generated_at"] = "2026-01-01T00:00:00Z"
        github = FakeGitHub(previous)
        publisher.publish(github, document)
        self.assertEqual(github.calls[-1], ("PATCH", "git/refs/heads/skillspector-reports", {"sha": "b" * 40, "force": False}))
        commit = next(data for method, path, data in github.calls if path == "git/commits")
        self.assertEqual(commit["parents"], ["a" * 40])

    def test_equal_or_older_report_cannot_overwrite_a_newer_result(self):
        document, _ = report()
        for generated_at in (document["generated_at"], "2999-01-01T00:00:00Z"):
            previous = copy.deepcopy(document)
            previous["generated_at"] = generated_at
            github = FakeGitHub(previous)
            with self.assertRaises(PublicationError):
                publisher.publish(github, document)
            self.assertTrue(all(method == "GET" for method, _, _ in github.calls))

    def test_concurrent_update_fails_without_force_retry(self):
        document, _ = report()
        previous = copy.deepcopy(document); previous["generated_at"] = "2026-01-01T00:00:00Z"
        github = FakeGitHub(previous, conflict=True)
        with self.assertRaises(PublicationError):
            publisher.publish(github, document)
        self.assertEqual(len([call for call in github.calls if call[0] == "PATCH"]), 1)

    def test_report_from_obsolete_main_cannot_overwrite_newer_configuration(self):
        document, _ = report()
        github = FakeGitHub(main="f" * 40)
        with self.assertRaises(PublicationError):
            publisher.publish(github, document)
        self.assertEqual(len(github.calls), 1)


if __name__ == "__main__":
    unittest.main()
