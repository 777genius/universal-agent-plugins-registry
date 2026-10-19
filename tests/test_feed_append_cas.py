from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from feed_append_cas import CasError, append_feed


def git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *arguments], check=True, text=True,
        capture_output=True,
    ).stdout.strip()


class FeedAppendCasTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.remote = root / "remote.git"
        self.repo = root / "publisher"
        git(root, "init", "--bare", "-q", str(self.remote))
        git(root, "init", "-q", str(self.repo))
        git(self.repo, "config", "user.name", "iliya")
        git(self.repo, "config", "user.email", "iliyazelenkog@gmail.com")
        (self.repo / "seed").write_text("test-only\n")
        git(self.repo, "add", "seed")
        git(self.repo, "commit", "-qm", "test: seed disposable ledger")
        self.base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "remote", "add", "origin", str(self.remote))
        self.advance(self.base)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def advance(self, commit: str) -> None:
        git(self.repo, "push", "-q", "origin", f"{commit}:refs/heads/directory-publication-ledger")

    def commit_path(self, parent: str, path: str, body: str, message: str) -> str:
        git(self.repo, "checkout", "-q", "--detach", parent)
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        git(self.repo, "add", path)
        git(self.repo, "commit", "-qm", message)
        return git(self.repo, "rev-parse", "HEAD")

    def feed_commit(self, parent: str, feed: str, sequence: int) -> str:
        git(self.repo, "checkout", "-q", "--detach", parent)
        stem = f"{sequence:020d}"
        paths = [f"{feed}/latest.json", f"{feed}/snapshots/{stem}.envelope.json",
                 f"{feed}/snapshots/{stem}.json"]
        if feed == "discovery":
            paths.append(f"{feed}/search/{stem}.json")
        for path in paths:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"{feed} sequence {sequence}\n")
        git(self.repo, "add", *paths)
        git(self.repo, "commit", "-qm", f"chore({feed}): publish sequence {sequence}")
        return git(self.repo, "rev-parse", "HEAD")

    def remote_ref(self, ref: str) -> str:
        return git(self.repo, "ls-remote", "--refs", "origin", ref).split("\t", 1)[0]

    def test_rebases_only_signed_feed_over_unrelated_ledger_appends(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)
        security = self.feed_commit(self.base, "security", 1)
        self.advance(security)
        status, commit = append_feed(self.repo, "origin", feed="discovery", candidate=candidate, sequence=1)
        self.assertEqual(status, "published")
        self.assertEqual(git(self.repo, "show", "-s", "--format=%P", commit), security)
        self.assertEqual(git(self.repo, "show", f"{commit}:security/latest.json"), "security sequence 1")
        self.assertEqual(git(self.repo, "show", f"{commit}:discovery/latest.json"), "discovery sequence 1")
        self.assertEqual(self.remote_ref("refs/heads/directory-publication-ledger"), commit)
        self.assertEqual(self.remote_ref("refs/tags/discovery-index-sequence-00000000000000000001"), commit)

    def test_same_feed_movement_fails_without_losing_latest(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)
        other = self.feed_commit(self.base, "discovery", 1)
        self.advance(other)
        with self.assertRaisesRegex(CasError, "signed feed advanced"):
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate, sequence=1)
        self.assertEqual(self.remote_ref("refs/heads/directory-publication-ledger"), other)

    def test_lost_push_response_is_idempotently_reconciled(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)

        def lost_response(arguments: list[str]) -> bool:
            git(self.repo, *arguments)
            return False

        self.assertEqual(
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate,
                        sequence=1, push_runner=lost_response),
            ("published", candidate),
        )
        self.assertEqual(
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate, sequence=1),
            ("committed", candidate),
        )

    def test_unrelated_ledger_race_retries_with_new_parent(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)
        security = self.feed_commit(self.base, "security", 1)
        raced = False

        def race(arguments: list[str]) -> bool:
            nonlocal raced
            if not raced:
                raced = True
                self.advance(security)
                return False
            git(self.repo, *arguments)
            return True

        status, commit = append_feed(self.repo, "origin", feed="discovery", candidate=candidate,
                                     sequence=1, push_runner=race)
        self.assertEqual(status, "published")
        self.assertEqual(git(self.repo, "show", "-s", "--format=%P", commit), security)

    def test_tag_only_partial_publication_is_not_accepted(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)

        def tag_only(arguments: list[str]) -> bool:
            git(self.repo, "push", "-q", "origin",
                f"{candidate}:refs/tags/discovery-index-sequence-00000000000000000001")
            return False

        with self.assertRaisesRegex(CasError, "not current for the protected feed lineage"):
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate,
                        sequence=1, push_runner=tag_only)
        self.assertEqual(self.remote_ref("refs/heads/directory-publication-ledger"), self.base)

    def test_replay_tag_on_unrelated_history_is_denied(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)
        tree = git(self.repo, "show", "-s", "--format=%T", self.base)
        unrelated = git(self.repo, "commit-tree", tree, "-m", "unrelated root")
        forged = self.feed_commit(unrelated, "discovery", 1)
        git(self.repo, "push", "-q", "--force", "origin",
            f"{forged}:refs/heads/directory-publication-ledger")
        git(self.repo, "push", "-q", "origin",
            f"{forged}:refs/tags/discovery-index-sequence-00000000000000000001")
        with self.assertRaisesRegex(CasError, "tag conflicts"):
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate, sequence=1)

    def test_advance_then_revert_same_feed_is_not_unrelated_movement(self) -> None:
        candidate = self.feed_commit(self.base, "discovery", 1)
        advance = self.feed_commit(self.base, "discovery", 1)
        git(self.repo, "checkout", "-q", "--detach", advance)
        git(self.repo, "rm", "-qr", "discovery")
        git(self.repo, "commit", "-qm", "revert discovery feed")
        reverted = git(self.repo, "rev-parse", "HEAD")
        self.advance(reverted)
        with self.assertRaisesRegex(CasError, "signed feed advanced"):
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate, sequence=1)
        preflight = subprocess.run(
            [sys.executable, str(ROOT / "scripts/feed_append_cas.py"), "history-verify",
             "--repo", str(self.repo), "--base", self.base, "--head", reverted,
             "--feed", "discovery"], capture_output=True, text=True,
        )
        self.assertNotEqual(preflight.returncode, 0)
        self.assertIn("protected feed changed", preflight.stderr)

    def test_security_cannot_publish_over_a_newer_discovery_dependency(self) -> None:
        candidate = self.feed_commit(self.base, "security", 1)
        discovery = self.feed_commit(self.base, "discovery", 1)
        self.advance(discovery)
        with self.assertRaisesRegex(CasError, "signed feed advanced"):
            append_feed(self.repo, "origin", feed="security", dependency_feed="discovery",
                        candidate=candidate, sequence=1)
        self.assertEqual(self.remote_ref("refs/heads/directory-publication-ledger"), discovery)

    def test_discovery_recovery_preserves_authenticated_historical_files(self) -> None:
        first = self.feed_commit(self.base, "discovery", 1)
        recovery_tag = "refs/tags/discovery-index-sequence-00000000000000000001"
        git(self.repo, "tag", recovery_tag, first)
        git(self.repo, "checkout", "-q", "--detach", first)
        git(self.repo, "rm", "-qr", "discovery")
        git(self.repo, "commit", "-qm", "test: simulate lost feed tree")
        missing = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "--detach", missing)
        git(self.repo, "checkout", recovery_tag, "--", "discovery")
        stem = f"{2:020d}"
        for path in (f"discovery/search/{stem}.json", f"discovery/snapshots/{stem}.json",
                     f"discovery/snapshots/{stem}.envelope.json"):
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("discovery sequence 2\n")
        (self.repo / "discovery/latest.json").write_text("discovery sequence 2\n")
        git(self.repo, "add", "discovery")
        git(self.repo, "commit", "-qm", "chore(discovery): publish sequence 2")
        candidate = git(self.repo, "rev-parse", "HEAD")
        self.advance(first)
        self.advance(missing)
        git(self.repo, "push", "-q", "origin", f"{first}:{recovery_tag}")
        status, published = append_feed(
            self.repo, "origin", feed="discovery", candidate=candidate, sequence=2,
            recovery_tag=recovery_tag,
        )
        self.assertEqual(status, "published")
        self.assertEqual(git(self.repo, "show", f"{published}:discovery/search/{1:020d}.json"),
                         "discovery sequence 1")

    def test_replay_old_security_tag_cannot_authorize_stale_deploy(self) -> None:
        first = self.feed_commit(self.base, "security", 1)
        self.advance(first)
        git(self.repo, "push", "-q", "origin",
            f"{first}:refs/tags/security-index-sequence-00000000000000000001")
        second = self.feed_commit(first, "security", 2)
        self.advance(second)
        with self.assertRaisesRegex(CasError, "tag conflicts"):
            append_feed(self.repo, "origin", feed="security", dependency_feed="discovery",
                        candidate=first, sequence=1)

    def test_dependency_advance_after_push_readback_is_not_success(self) -> None:
        candidate = self.feed_commit(self.base, "security", 1)

        def advance_after_push(arguments: list[str]) -> bool:
            git(self.repo, *arguments)
            discovery = self.feed_commit(candidate, "discovery", 1)
            self.advance(discovery)
            return False

        with self.assertRaisesRegex(CasError, "not current for the protected feed lineage"):
            append_feed(self.repo, "origin", feed="security", dependency_feed="discovery",
                        candidate=candidate, sequence=1, push_runner=advance_after_push)

    def test_discovery_cannot_deploy_older_security_after_push_readback(self) -> None:
        security_one = self.feed_commit(self.base, "security", 1)
        self.advance(security_one)
        candidate = self.feed_commit(security_one, "discovery", 1)

        def advance_security_after_push(arguments: list[str]) -> bool:
            git(self.repo, *arguments)
            security_two = self.feed_commit(candidate, "security", 2)
            self.advance(security_two)
            return False

        with self.assertRaisesRegex(CasError, "not current for the protected feed lineage"):
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate,
                        sequence=1, push_runner=advance_security_after_push)

    def test_discovery_replay_cannot_deploy_older_security(self) -> None:
        security_one = self.feed_commit(self.base, "security", 1)
        self.advance(security_one)
        candidate = self.feed_commit(security_one, "discovery", 1)
        self.advance(candidate)
        git(self.repo, "push", "-q", "origin",
            f"{candidate}:refs/tags/discovery-index-sequence-00000000000000000001")
        security_two = self.feed_commit(candidate, "security", 2)
        self.advance(security_two)
        with self.assertRaisesRegex(CasError, "tag conflicts"):
            append_feed(self.repo, "origin", feed="discovery", candidate=candidate, sequence=1)


if __name__ == "__main__":
    unittest.main()
