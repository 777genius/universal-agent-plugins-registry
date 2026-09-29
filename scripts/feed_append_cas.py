#!/usr/bin/env python3
"""Append one signed auxiliary feed over unrelated ledger movement."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Sequence

from directory_publication_cas import CasError, _git, _require_sha, validate_feed_append


LEDGER_REF = "refs/heads/directory-publication-ledger"
FEED_TAG = {
    "discovery": "discovery-index-sequence-",
    "security": "security-index-sequence-",
}


def _refs(repo: Path, remote: str, tag: str) -> tuple[str, str | None]:
    result = _git(repo, ["ls-remote", "--refs", remote, LEDGER_REF, tag])
    found: dict[str, str] = {}
    for line in result.stdout.splitlines():
        oid, ref = line.split("\t", 1)
        _require_sha(oid, ref)
        if ref in found or ref not in (LEDGER_REF, tag):
            raise CasError("invalid or duplicate remote ref")
        found[ref] = oid
    if LEDGER_REF not in found:
        raise CasError("ledger branch is missing")
    return found[LEDGER_REF], found.get(tag)


def _fetch(repo: Path, remote: str, oid: str) -> None:
    _require_sha(oid, "remote object")
    _git(repo, ["fetch", "--no-tags", remote, oid])
    if _git(repo, ["cat-file", "-t", oid]).stdout.strip() != "commit":
        raise CasError("remote object is not a commit")


def _feed_tree(repo: Path, commit: str, feed: str) -> str:
    return _git(repo, ["ls-tree", commit, "--", feed]).stdout.strip()


def _unrelated_history(repo: Path, base: str, head: str, feeds: Sequence[str]) -> bool:
    if _git(repo, ["merge-base", "--is-ancestor", base, head], check=False).returncode != 0:
        return False
    previous = base
    for descendant in _git(
        repo, ["rev-list", "--reverse", "--ancestry-path", f"{base}..{head}"],
    ).stdout.splitlines():
        if _git(repo, ["show", "-s", "--format=%P", descendant]).stdout.strip() != previous:
            return False
        if _git(repo, ["diff", "--quiet", previous, descendant, "--", *feeds], check=False).returncode != 0:
            return False
        previous = descendant
    return previous == head


def _validate_candidate(
    repo: Path, parent: str, candidate: str, feed: str, sequence: int,
    recovery_tag: str | None,
) -> None:
    if recovery_tag is None:
        validate_feed_append(repo, parent, candidate)
        return
    if feed != "discovery" or not re.fullmatch(
        r"refs/tags/discovery-index-sequence-[0-9]{20}", recovery_tag,
    ):
        raise CasError("invalid Discovery recovery tag")
    if int(recovery_tag.rsplit("-", 1)[1]) + 1 != sequence:
        raise CasError("recovery tag is not the immediate sequence predecessor")
    tagged = _git(repo, ["rev-parse", f"{recovery_tag}^{{commit}}"] ).stdout.strip()
    _require_sha(tagged, "recovery tag")
    if _git(repo, ["merge-base", "--is-ancestor", tagged, parent], check=False).returncode != 0:
        raise CasError("recovery tag is not in the ledger lineage")
    if _feed_tree(repo, parent, feed):
        raise CasError("recovery requires an absent ledger feed")
    stem = f"{sequence:020d}"
    new_paths = {
        f"{feed}/latest.json", f"{feed}/search/{stem}.json",
        f"{feed}/snapshots/{stem}.envelope.json", f"{feed}/snapshots/{stem}.json",
    }
    old_paths = set(_git(repo, ["ls-tree", "-r", "--name-only", tagged, "--", feed]).stdout.splitlines())
    if not old_paths or f"{feed}/latest.json" not in old_paths or new_paths.intersection(old_paths) != {f"{feed}/latest.json"}:
        raise CasError("recovery tag conflicts with the new sequence")
    changed = _git(
        repo, ["diff-tree", "--no-commit-id", "--name-status", "--no-renames", "-r", parent, candidate],
    ).stdout.splitlines()
    if set(changed) != {f"A\t{path}" for path in old_paths | new_paths}:
        raise CasError("recovery append changed unexpected paths")
    for path in old_paths - {f"{feed}/latest.json"}:
        if _git(repo, ["ls-tree", tagged, "--", path]).stdout != _git(repo, ["ls-tree", candidate, "--", path]).stdout:
            raise CasError("recovery changed an authenticated historical feed file")


def _metadata(repo: Path, candidate: str) -> dict[str, str]:
    fields = _git(
        repo, ["show", "-s", "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI", candidate],
    ).stdout.strip().split("\x00")
    if len(fields) != 6:
        raise CasError("candidate commit identity is malformed")
    return dict(zip((
        "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE",
    ), fields))


def _rebind(repo: Path, candidate: str, parent: str, feed: str,
            sequence: int, recovery_tag: str | None) -> str:
    if _git(repo, ["show", "-s", "--format=%P", candidate]).stdout.strip() == parent:
        return candidate
    paths = _git(
        repo, ["diff-tree", "--no-commit-id", "--name-only", "-r", f"{candidate}^", candidate],
    ).stdout.splitlines()
    with tempfile.TemporaryDirectory(prefix="uap-feed-index-") as temporary:
        environment = {**os.environ, "GIT_INDEX_FILE": str(Path(temporary) / "index")}
        _git(repo, ["read-tree", parent], env=environment)
        for path in paths:
            entry = _git(repo, ["ls-tree", candidate, "--", path]).stdout.strip().split(None, 3)
            if len(entry) != 4 or entry[:2] != ["100644", "blob"] or entry[3] != path:
                raise CasError("candidate append contains an invalid file")
            _git(repo, ["update-index", "--add", "--cacheinfo", entry[0], entry[2], path], env=environment)
        tree = _git(repo, ["write-tree"], env=environment).stdout.strip()
    message = _git(repo, ["show", "-s", "--format=%B", candidate]).stdout
    rebound = _git(
        repo, ["commit-tree", tree, "-p", parent], input_text=message.rstrip("\n") + "\n",
        env={**os.environ, **_metadata(repo, candidate)},
    ).stdout.strip()
    _validate_candidate(repo, parent, rebound, feed, sequence, recovery_tag)
    if _feed_tree(repo, rebound, feed) != _feed_tree(repo, candidate, feed):
        raise CasError("rebinding changed signed feed bytes")
    return rebound


def append_feed(
    repo: Path, remote: str, *, feed: str, candidate: str, sequence: int,
    recovery_tag: str | None = None, dependency_feed: str | None = None,
    attempts: int = 3, push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> tuple[str, str]:
    if feed not in FEED_TAG or not 1 <= sequence <= 9_007_199_254_740_991:
        raise CasError("invalid feed or sequence")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    _require_sha(candidate, "candidate")
    if dependency_feed not in (None, "discovery") or (dependency_feed and feed != "security"):
        raise CasError("invalid feed dependency")
    protected_feeds = (feed,) if dependency_feed is None else (feed, dependency_feed)
    # Discovery may rebind over a newer Security append before publishing, but
    # its Pages job copies Security from the returned commit. A later Security
    # append therefore makes that commit unsafe to deploy.
    deployment_feeds = ("discovery", "security") if feed == "discovery" else protected_feeds
    base = _git(repo, ["show", "-s", "--format=%P", candidate]).stdout.strip()
    _require_sha(base, "candidate parent")
    _validate_candidate(repo, base, candidate, feed, sequence, recovery_tag)
    expected_message = f"chore({feed}): publish sequence {sequence}\n\n"
    if _git(repo, ["show", "-s", "--format=%B", candidate]).stdout != expected_message:
        raise CasError("candidate does not match the requested feed sequence")
    tag = f"refs/tags/{FEED_TAG[feed]}{sequence:020d}"
    for _ in range(attempts):
        try:
            head, tagged = _refs(repo, remote, tag)
            _fetch(repo, remote, head)
        except subprocess.CalledProcessError:
            continue
        if tagged is not None:
            _fetch(repo, remote, tagged)
            tagged_parent = _git(repo, ["show", "-s", "--format=%P", tagged]).stdout.strip()
            _validate_candidate(repo, tagged_parent, tagged, feed, sequence, recovery_tag)
            if (_git(repo, ["show", "-s", "--format=%B", tagged]).stdout != expected_message
                    or _feed_tree(repo, tagged, feed) != _feed_tree(repo, candidate, feed)
                    or not _unrelated_history(repo, base, tagged_parent, protected_feeds)
                    or not _unrelated_history(repo, tagged, head, deployment_feeds)):
                raise CasError("immutable sequence tag conflicts with candidate")
            return "committed", tagged
        if not _unrelated_history(repo, base, head, protected_feeds):
            raise CasError("ledger moved outside candidate lineage or signed feed advanced")
        rebound = _rebind(repo, candidate, head, feed, sequence, recovery_tag)
        arguments = [
            "push", "--atomic", f"--force-with-lease={LEDGER_REF}:{head}",
            f"--force-with-lease={tag}:", remote,
            f"{rebound}:{LEDGER_REF}", f"{rebound}:{tag}",
        ]
        if push_runner is not None:
            push_runner(arguments)
        else:
            _git(repo, arguments, check=False)
        # A missing receive-pack response is resolved from the refs, not retried blind.
        try:
            observed_head, observed_tag = _refs(repo, remote, tag)
        except subprocess.CalledProcessError:
            continue
        if observed_tag == rebound:
            _fetch(repo, remote, observed_head)
            if not _unrelated_history(repo, rebound, observed_head, deployment_feeds):
                raise CasError("sequence tag is not current for the protected feed lineage")
            return "published", rebound
        if observed_tag is not None:
            raise CasError("sequence tag changed during publication")
        if observed_head == head:
            continue
        # An unrelated append won the race. The next iteration verifies its feed tree.
    raise CasError("feed append CAS did not reach an authenticated state")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    append = commands.add_parser("append")
    append.add_argument("--repo", type=Path, default=Path.cwd())
    append.add_argument("--remote", default="origin")
    append.add_argument("--feed", choices=sorted(FEED_TAG), required=True)
    append.add_argument("--candidate", required=True)
    append.add_argument("--sequence", type=int, required=True)
    append.add_argument("--recovery-tag")
    append.add_argument("--dependency-feed", choices=["discovery"])
    history = commands.add_parser("history-verify")
    history.add_argument("--repo", type=Path, default=Path.cwd())
    history.add_argument("--base", required=True)
    history.add_argument("--head", required=True)
    history.add_argument("--feed", choices=sorted(FEED_TAG), required=True)
    history.add_argument("--dependency-feed", choices=["discovery"])
    args = parser.parse_args()
    try:
        if args.command == "history-verify":
            _require_sha(args.base, "history base")
            _require_sha(args.head, "history head")
            feeds = (args.feed,) if args.dependency_feed is None else (args.feed, args.dependency_feed)
            if args.dependency_feed and args.feed != "security":
                raise CasError("invalid feed dependency")
            if not _unrelated_history(args.repo, args.base, args.head, feeds):
                raise CasError("protected feed changed in intervening ledger history")
            print("valid")
            return 0
        status, commit = append_feed(
            args.repo, args.remote, feed=args.feed, candidate=args.candidate,
            sequence=args.sequence, recovery_tag=args.recovery_tag,
            dependency_feed=args.dependency_feed,
        )
    except (CasError, OSError, subprocess.SubprocessError) as error:
        print(f"feed-append-cas: {error}", file=sys.stderr)
        return 1
    print(f"{status} {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
