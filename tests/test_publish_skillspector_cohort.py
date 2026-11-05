"""CAS publication and readback of a separate signed nine-source feed."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

from scripts import publish_skillspector_cohort as publisher
from scripts import skillspector_cohort_release_protocol as protocol
from scripts import skillspector_candidate_signature
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError, canonical_json
from tests.test_skillspector_cohort_release_protocol import (
    EXPIRES, GENERATED, KEY_ID, KEYS, MAIN_SHA, NOW,
    REPORT_SHA, SEED, qualified_fixture,
)


class FakeGitHub:
    """Minimal exact Git-object/branch CAS contract used by the publisher."""

    def __init__(self):
        self.refs = {"main": MAIN_SHA, publisher.REPORT_BRANCH: REPORT_SHA}
        self.blobs = {}
        self.commits = {}
        self.pending_entries = None
        self.writes = []

    def request(self, method, path, data=None, *, raw=False):
        if method == "GET" and path.startswith("git/ref/heads/"):
            branch = path[len("git/ref/heads/"):]
            return ({"object": {"sha": self.refs[branch]}}
                    if branch in self.refs else None)
        if method == "GET" and path.startswith("git/trees/"):
            head = path[len("git/trees/"):].split("?", 1)[0]
            hashes = self.commits[head]["blob_shas"]
            return {"truncated": False, "tree": [
                {"path": name, "type": "blob", "mode": "100644", "sha": digest}
                for name, digest in hashes.items()
            ]}
        if method == "GET" and path.startswith("contents/"):
            name, head = path[len("contents/"):].split("?ref=", 1)
            return self.commits[head]["files"].get(name)
        if method == "POST" and path == "git/blobs":
            body = base64.b64decode(data["content"], validate=True)
            key = publisher.git_blob_sha(body)
            self.blobs[key] = body
            self.writes.append(("blob", key))
            return {"sha": key}
        if method == "POST" and path == "git/commits":
            assert self.pending_entries is not None
            sha = hashlib.sha1(f"test-commit-{len(self.commits)}".encode()).hexdigest()
            files = {name: self.blobs[blob] for name, blob in self.pending_entries.items()}
            parent = data["parents"][0] if data["parents"] else None
            self.commits[sha] = {
                "files": files, "blob_shas": dict(self.pending_entries),
                "parent": parent,
            }
            self.writes.append(("commit", sha))
            self.pending_entries = None
            return {"sha": sha}
        if method == "POST" and path == "git/refs":
            assert data["ref"] == "refs/heads/" + publisher.BRANCH
            assert publisher.BRANCH not in self.refs
            self.refs[publisher.BRANCH] = data["sha"]
            self.writes.append(("ref-create", data["sha"]))
            return {"ref": data["ref"]}
        if method == "PATCH" and path == "git/refs/heads/" + publisher.BRANCH:
            assert data["force"] is False
            assert self.commits[data["sha"]]["parent"] == self.refs[publisher.BRANCH]
            self.refs[publisher.BRANCH] = data["sha"]
            self.writes.append(("ref-cas", data["sha"]))
            return {"ref": path}
        raise AssertionError(f"unhandled fake GitHub request {method} {path}")


class CohortPublisherTests(unittest.TestCase):
    def fixture(self, generated=GENERATED, expires=EXPIRES):
        """Qualify and test-sign a source-pinned release with a public test key."""
        proof, sources, previous = qualified_fixture()
        with mock.patch.object(skillspector_candidate_signature,
                               "load_verified_previous", return_value=previous):
            release = protocol.build_release(
                proof, sources, Path("/verified-v3"), MAIN_SHA,
                generated, expires, now=NOW)
            envelope = protocol.sign_release(
                release, KEYS, KEY_ID, SEED, Path("/verified-v3"),
                lambda: sources, now=NOW)
        return scanner.report_json(release), canonical_json(envelope), previous, sources

    def do_publish(self, github, body, envelope, previous, sources, expected_head=None):
        """Exercise exact checks and a deterministic Git-tree transport fake."""
        def create_tree(fake, entries, *, known_trees=None):
            self.assertIs(fake, github)
            self.assertTrue(entries)
            github.pending_entries = dict(entries)
            return {"sha": "f" * 40}
        with mock.patch.object(skillspector_candidate_signature,
                               "load_verified_previous", return_value=previous), \
             mock.patch.object(publisher, "create_filtered_tree", side_effect=create_tree):
            return publisher.publish(
                github, body, envelope, KEYS, Path("/verified-v3"),
                lambda: sources, expected_head, now=NOW)

    def test_first_publication_uses_separate_branch_and_exact_readback(self):
        github = FakeGitHub()
        body, envelope, previous, sources = self.fixture()
        commit = self.do_publish(github, body, envelope, previous, sources)
        self.assertEqual(github.refs[publisher.BRANCH], commit)
        self.assertEqual(github.refs[publisher.REPORT_BRANCH], REPORT_SHA)
        self.assertEqual(github.refs["main"], MAIN_SHA)
        files = github.commits[commit]["files"]
        self.assertEqual(len(files), 3)
        pointer = json.loads(files[publisher.POINTER])
        self.assertEqual(pointer["sequence"], 1)
        self.assertEqual(pointer["release_digest"], publisher.sha256_digest(body))
        self.assertEqual(files[pointer["release_path"]], body)
        self.assertEqual(files[pointer["envelope_path"]], envelope)
        self.assertTrue(all(name.startswith(publisher.PREFIX) for name in files))
        self.assertTrue(any(x[0] == "ref-create" for x in github.writes))

    def test_idempotent_publication_and_next_monotonic_sequence(self):
        github = FakeGitHub()
        body, envelope, previous, sources = self.fixture()
        first = self.do_publish(github, body, envelope, previous, sources)
        before = len(github.writes)
        self.assertEqual(self.do_publish(github, body, envelope, previous, sources, first), first)
        self.assertEqual(len(github.writes), before)
        newer_body, newer_envelope, newer_previous, newer_sources = self.fixture(
            generated="2026-11-05T12:30:00Z", expires="2026-11-06T12:30:00Z")
        second = self.do_publish(github, newer_body, newer_envelope,
                                 newer_previous, newer_sources, first)
        self.assertNotEqual(first, second)
        self.assertEqual(github.commits[second]["parent"], first)
        self.assertEqual(json.loads(github.commits[second]["files"][publisher.POINTER])["sequence"], 2)
        self.assertTrue(any(x[0] == "ref-cas" for x in github.writes))

    def test_old_head_and_main_or_report_move_are_not_replayed(self):
        github = FakeGitHub()
        body, envelope, previous, sources = self.fixture()
        with self.assertRaises(publisher.StaleCohortPublication):
            self.do_publish(github, body, envelope, previous, sources, "a" * 40)
        github.refs["main"] = "a" * 40
        with self.assertRaises(PublicationError):
            self.do_publish(github, body, envelope, previous, sources)
        github.refs["main"] = MAIN_SHA
        github.refs[publisher.REPORT_BRANCH] = "a" * 40
        with self.assertRaises(PublicationError):
            self.do_publish(github, body, envelope, previous, sources)
        self.assertNotIn(publisher.BRANCH, github.refs)

    def test_wrong_fresh_signed_roots_or_modified_candidate_cannot_publish(self):
        github = FakeGitHub()
        body, envelope, previous, sources = self.fixture()
        bad_sources = json.loads(json.dumps(sources))
        bad_sources["sources"][0]["revision"] = "0" * 40
        with self.assertRaises(PublicationError):
            self.do_publish(github, body, envelope, previous, bad_sources)
        tampered = bytearray(body)
        tampered[-5] ^= 1
        with self.assertRaises(PublicationError):
            self.do_publish(github, bytes(tampered), envelope, previous, sources)
        self.assertNotIn(publisher.BRANCH, github.refs)

    def test_existing_cohort_foreign_or_executable_files_are_rejected(self):
        github = FakeGitHub()
        body, envelope, previous, sources = self.fixture()
        first = self.do_publish(github, body, envelope, previous, sources)
        github.commits[first]["files"]["malware.sh"] = b"evil"
        github.commits[first]["blob_shas"]["malware.sh"] = publisher.git_blob_sha(b"evil")
        with self.assertRaises(PublicationError):
            self.do_publish(github, body, envelope, previous, sources, first)

    def test_previous_pointer_and_signed_history_reject_tampering(self):
        for kind in ("pointer_bytes", "release_bytes", "envelope_bytes"):
            github = FakeGitHub()
            body, envelope, previous, sources = self.fixture()
            first = self.do_publish(github, body, envelope, previous, sources)
            files = github.commits[first]["files"]
            pointer = json.loads(files[publisher.POINTER])
            if kind == "pointer_bytes":
                old = files[publisher.POINTER]
                files[publisher.POINTER] = old + b" "
            elif kind == "release_bytes":
                path = pointer["release_path"]
                data = files[path] + b" "
                files[path] = data
                github.commits[first]["blob_shas"][path] = publisher.git_blob_sha(data)
            else:
                path = pointer["envelope_path"]
                data = files[path] + b" "
                files[path] = data
                github.commits[first]["blob_shas"][path] = publisher.git_blob_sha(data)
            with self.subTest(kind=kind), self.assertRaises(PublicationError):
                self.do_publish(github, body, envelope, previous, sources, first)

    def test_data_only_whitelist_and_pointer_type_limits(self):
        self.assertTrue(publisher.allowed_path(publisher.POINTER))
        self.assertTrue(publisher.allowed_path(publisher.PREFIX + "releases/" + "a" * 64 + ".json"))
        for path in ("install.sh", "v3/index.json", "releases/../../bad.json",
                     "releases/latest.json", "envelopes/../evil.json", ""):
            self.assertFalse(publisher.allowed_path(publisher.PREFIX + path))
        github = FakeGitHub()
        body, envelope, previous, sources = self.fixture()
        first = self.do_publish(github, body, envelope, previous, sources)
        pointer = json.loads(github.commits[first]["files"][publisher.POINTER])
        pointer["sequence"] = True
        github.commits[first]["files"][publisher.POINTER] = canonical_json(pointer)
        with self.assertRaises(PublicationError):
            self.do_publish(github, body, envelope, previous, sources, first)


if __name__ == "__main__":
    unittest.main()
