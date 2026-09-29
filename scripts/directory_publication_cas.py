#!/usr/bin/env python3
"""Create and publish the Directory's deterministic same-tree CAS marker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


GIT = "/usr/bin/git"
SHA_RE = re.compile(r"[0-9a-f]{40}")
PUBLICATION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
MARKER_NAME = "uap-directory-publisher[bot]"
MARKER_EMAIL = "uap-directory-publisher[bot]@users.noreply.github.com"
MARKER_VERSION = 2
MAX_SOURCE_FUTURE_SKEW_SECONDS = 300
PROMOTION_INTENT_PREFIX = "refs/tags/directory-publication-schema-1-promotion-intent-"


class CasError(RuntimeError):
    """The requested publication does not match an allowed exact ref state."""


def _git(repo: Path, arguments: Sequence[str], *, input_text: str | None = None,
         check: bool = True, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [GIT, "-C", str(repo), *arguments], input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, env=env,
    )


def _require_sha(value: str, label: str) -> None:
    if SHA_RE.fullmatch(value) is None:
        raise CasError(f"{label} must be a full lowercase object ID")


def marker_timestamp(repo: Path, source: str) -> int:
    """Place a v2 marker immediately after its source in Git chronology."""
    _require_sha(source, "source commit")
    raw = _git(repo, ["show", "-s", "--format=%ct", source]).stdout.strip()
    if re.fullmatch(r"[0-9]+", raw) is None:
        raise CasError("source commit timestamp is invalid")
    timestamp = int(raw) + 1
    if timestamp > int(time.time()) + MAX_SOURCE_FUTURE_SKEW_SECONDS:
        raise CasError("source commit timestamp is unreasonably far in the future")
    return timestamp


def marker_message(source: str, publication_id: str) -> str:
    _require_sha(source, "source commit")
    if PUBLICATION_ID_RE.fullmatch(publication_id) is None:
        raise CasError("publication ID is invalid")
    return (
        "chore(directory): record publication marker\n\n"
        f"Directory-Publication-Marker: {MARKER_VERSION}\n"
        f"Publication-ID: {publication_id}\n"
        f"Source-Commit: {source}\n"
    )


def create_marker(repo: Path, source: str, publication_id: str) -> str:
    """Write deterministic marker P: one parent, source tree, no changed paths."""
    _require_sha(source, "source commit")
    source_type = _git(repo, ["cat-file", "-t", source]).stdout.strip()
    if source_type != "commit":
        raise CasError("source object is not a commit")
    tree = _git(repo, ["show", "-s", "--format=%T", source]).stdout.strip()
    timestamp = marker_timestamp(repo, source)
    identity_env = dict(os.environ)
    identity_env.update({
        "GIT_AUTHOR_NAME": MARKER_NAME,
        "GIT_AUTHOR_EMAIL": MARKER_EMAIL,
        "GIT_AUTHOR_DATE": f"@{timestamp} +0000",
        "GIT_COMMITTER_NAME": MARKER_NAME,
        "GIT_COMMITTER_EMAIL": MARKER_EMAIL,
        "GIT_COMMITTER_DATE": f"@{timestamp} +0000",
    })
    marker = _git(
        repo, ["commit-tree", tree, "-p", source],
        input_text=marker_message(source, publication_id), env=identity_env,
    ).stdout.strip()
    validate_marker(repo, marker, source, publication_id)
    return marker


def validate_marker(repo: Path, marker: str, source: str, publication_id: str) -> None:
    _require_sha(marker, "marker commit")
    _require_sha(source, "source commit")
    if marker == source:
        raise CasError("marker commit must differ from its source")
    parents = _git(repo, ["show", "-s", "--format=%P", marker]).stdout.strip().split()
    if parents != [source]:
        raise CasError("marker commit does not have exactly the source parent")
    marker_tree = _git(repo, ["show", "-s", "--format=%T", marker]).stdout.strip()
    source_tree = _git(repo, ["show", "-s", "--format=%T", source]).stdout.strip()
    if marker_tree != source_tree:
        raise CasError("marker commit tree differs from source tree")
    if _git(repo, ["diff", "--quiet", source, marker], check=False).returncode != 0:
        raise CasError("marker commit changes paths")
    raw_message = _git(repo, ["show", "-s", "--format=%B", marker]).stdout
    if raw_message != marker_message(source, publication_id) + "\n":
        raise CasError("marker commit message differs from deterministic contract")
    timestamp = str(marker_timestamp(repo, source))
    expected_body = (
        f"tree {source_tree}\n"
        f"parent {source}\n"
        f"author {MARKER_NAME} <{MARKER_EMAIL}> {timestamp} +0000\n"
        f"committer {MARKER_NAME} <{MARKER_EMAIL}> {timestamp} +0000\n"
        "\n"
        + marker_message(source, publication_id)
    )
    expected_oid = _git(repo, ["hash-object", "-t", "commit", "--stdin"], input_text=expected_body).stdout.strip()
    if marker != expected_oid:
        raise CasError("marker commit object differs from deterministic contract")
    metadata = _git(repo, ["show", "-s", "--format=%an%n%ae%n%at%n%cn%n%ce%n%ct", marker]).stdout.splitlines()
    if metadata != [MARKER_NAME, MARKER_EMAIL, timestamp, MARKER_NAME, MARKER_EMAIL, timestamp]:
        raise CasError("marker commit identity or timestamp differs from deterministic contract")


@dataclass(frozen=True)
class RefState:
    main: str | None
    ledger: str | None
    sequence_tag: str | None


@dataclass(frozen=True)
class RebasedPublication:
    status: str
    signed: str
    materialized: str
    ledger_head: str


def read_ref_state(repo: Path, remote: str, main_ref: str, ledger_ref: str, tag_ref: str) -> RefState:
    completed = _git(repo, ["ls-remote", "--refs", remote, main_ref, ledger_ref, tag_ref])
    observed: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        fields = line.split("\t", 1)
        if len(fields) != 2:
            raise CasError("remote returned a malformed ref line")
        oid, ref = fields
        if ref in observed or SHA_RE.fullmatch(oid) is None:
            raise CasError("remote returned an invalid or duplicate ref")
        observed[ref] = oid
    return RefState(observed.get(main_ref), observed.get(ledger_ref), observed.get(tag_ref))


def validate_materialized_descendant(repo: Path, materialized: str, signed: str) -> None:
    """Authenticate the one allowed post-publication ledger descendant.

    Site materialization is deliberately a separate, single-parent commit.  It
    may change the Pages tree, but it cannot change any signed registry byte.
    This lets an exact workflow rerun distinguish its own completed deployment
    transaction from arbitrary forward movement of the protected ledger.
    """
    _require_sha(materialized, "materialized ledger")
    _require_sha(signed, "signed ledger")
    if materialized == signed:
        raise CasError("materialized ledger must differ from the signed ledger")
    parents = _git(repo, ["show", "-s", "--format=%P", materialized]).stdout.strip().split()
    if parents != [signed]:
        raise CasError("materialized ledger is not the exact signed-commit child")
    if _git(repo, ["diff", "--quiet", signed, materialized, "--", "registry", "discovery", "security"], check=False).returncode != 0:
        raise CasError("materialized ledger changed signed registry bytes or feed bytes")
    message = _git(repo, ["show", "-s", "--format=%B", materialized]).stdout
    if message != "chore(directory): materialize signed production site\n\n":
        raise CasError("materialized ledger commit message is invalid")


def validate_feed_append(repo: Path, previous: str, descendant: str) -> None:
    """Authenticate one immutable Discovery or Security publication append."""
    message = _git(repo, ["show", "-s", "--format=%B", descendant]).stdout
    match = re.fullmatch(
        r"chore\((discovery|security)\): publish sequence ([1-9][0-9]*)\n\n",
        message,
    )
    if match is None:
        raise CasError("staged ledger has an unsupported post-materialization append")
    feed, raw_sequence = match.groups()
    sequence = int(raw_sequence)
    if sequence > 9_007_199_254_740_991:
        raise CasError("staged ledger feed sequence exceeds the JSON-safe range")
    stem = f"{sequence:020d}"
    expected = {
        f"{feed}/latest.json": {"A", "M"},
        f"{feed}/snapshots/{stem}.envelope.json": {"A"},
        f"{feed}/snapshots/{stem}.json": {"A"},
    }
    if feed == "discovery":
        expected[f"{feed}/search/{stem}.json"] = {"A"}
    changes = _git(
        repo,
        ["diff-tree", "--no-commit-id", "--name-status", "--no-renames", "-r", previous, descendant],
    ).stdout.splitlines()
    actual: dict[str, str] = {}
    for change in changes:
        fields = change.split("\t")
        if len(fields) != 2 or fields[1] in actual:
            raise CasError("staged ledger feed append has malformed path changes")
        actual[fields[1]] = fields[0]
    if set(actual) != set(expected) or any(actual[path] not in statuses for path, statuses in expected.items()):
        raise CasError("staged ledger feed append is not the exact immutable publication shape")
    for path in expected:
        entry = _git(repo, ["ls-tree", descendant, "--", path]).stdout.strip().split(None, 3)
        if len(entry) != 4 or entry[0] != "100644" or entry[1] != "blob" or entry[3] != path:
            raise CasError("staged ledger feed append contains a non-regular publication file")


def validate_discovery_recovery_append(repo: Path, previous: str, descendant: str, tagged: str) -> None:
    """Accept only PR2a's exact protected-tag restoration of an absent feed."""
    _require_sha(tagged, "Discovery recovery tag")
    message = _git(repo, ["show", "-s", "--format=%B", descendant]).stdout
    match = re.fullmatch(r"chore\(discovery\): publish sequence ([1-9][0-9]*)\n\n", message)
    if match is None:
        raise CasError("invalid Discovery recovery commit message")
    sequence = int(match.group(1))
    if sequence < 2 or sequence > 9_007_199_254_740_991:
        raise CasError("invalid Discovery recovery sequence")
    if _git(repo, ["merge-base", "--is-ancestor", tagged, previous], check=False).returncode != 0:
        raise CasError("Discovery recovery tag is outside the ledger lineage")
    if _git(repo, ["ls-tree", previous, "--", "discovery"]).stdout.strip():
        raise CasError("Discovery recovery requires an absent ledger feed")
    old_paths = set(_git(repo, ["ls-tree", "-r", "--name-only", tagged, "--", "discovery"]).stdout.splitlines())
    stem = f"{sequence:020d}"
    new_paths = {
        "discovery/latest.json", f"discovery/search/{stem}.json",
        f"discovery/snapshots/{stem}.envelope.json", f"discovery/snapshots/{stem}.json",
    }
    if (not old_paths or "discovery/latest.json" not in old_paths
            or old_paths & new_paths != {"discovery/latest.json"}):
        raise CasError("Discovery recovery tag conflicts with the new sequence")
    changes = set(_git(
        repo, ["diff-tree", "--no-commit-id", "--name-status", "--no-renames", "-r", previous, descendant],
    ).stdout.splitlines())
    if changes != {f"A\t{path}" for path in old_paths | new_paths}:
        raise CasError("Discovery recovery changes unexpected paths")
    for path in old_paths - {"discovery/latest.json"}:
        if _git(repo, ["ls-tree", tagged, "--", path]).stdout != _git(repo, ["ls-tree", descendant, "--", path]).stdout:
            raise CasError("Discovery recovery changed authenticated historical bytes")
    for path in old_paths | new_paths:
        entry = _git(repo, ["ls-tree", descendant, "--", path]).stdout.strip().split(None, 3)
        if len(entry) != 4 or entry[:2] != ["100644", "blob"] or entry[3] != path:
            raise CasError("Discovery recovery contains a non-regular file")


def _validate_feed_or_recovery(repo: Path, remote: str, previous: str, descendant: str) -> None:
    try:
        validate_feed_append(repo, previous, descendant)
        return
    except CasError as ordinary_error:
        message = _git(repo, ["show", "-s", "--format=%B", descendant]).stdout
        match = re.fullmatch(r"chore\(discovery\): publish sequence ([2-9]|[1-9][0-9]+)\n\n", message)
        if match is None:
            raise ordinary_error
        sequence = int(match.group(1))
        recovery_tag = f"refs/tags/discovery-index-sequence-{sequence - 1:020d}"
        tagged = read_ref_state(
            repo, remote, "refs/heads/__unused-main", "refs/heads/__unused-ledger", recovery_tag,
        ).sequence_tag
        if tagged is None:
            raise ordinary_error
        if _git(repo, ["fetch", "--no-tags", remote, tagged], check=False).returncode != 0:
            raise CasError("cannot acquire Discovery recovery tag target")
        if _git(repo, ["cat-file", "-t", tagged]).stdout.strip() != "commit":
            raise CasError("Discovery recovery tag must name a commit")
        validate_discovery_recovery_append(repo, previous, descendant, tagged)


def validate_staged_lineage(repo: Path, current: str, signed: str, remote: str = "origin") -> str:
    """Return the exact site materialization below safe signed-feed appends."""
    _require_sha(current, "current ledger")
    _require_sha(signed, "signed ledger")
    if _git(repo, ["merge-base", "--is-ancestor", signed, current], check=False).returncode != 0:
        raise CasError("signed ledger is not an ancestor of the current ledger")
    descendants = _git(
        repo, ["rev-list", "--reverse", "--ancestry-path", f"{signed}..{current}"],
    ).stdout.splitlines()
    if not descendants:
        raise CasError("staged publication has no materialized site commit")
    materialized = descendants[0]
    validate_materialized_descendant(repo, materialized, signed)
    previous = materialized
    for descendant in descendants[1:]:
        parents = _git(repo, ["show", "-s", "--format=%P", descendant]).stdout.strip().split()
        if parents != [previous]:
            raise CasError("staged ledger has a non-linear post-materialization append")
        _validate_feed_or_recovery(repo, remote, previous, descendant)
        previous = descendant
    if _git(repo, ["diff", "--quiet", signed, current, "--", "registry"], check=False).returncode != 0:
        raise CasError("staged ledger changed signed registry bytes")
    return materialized


def atomic_transition(
    repo: Path, remote: str, *, source: str, marker: str, ledger_old: str,
    ledger_new: str, sequence_tag: str, attempts: int = 3,
    push_runner: Callable[[Sequence[str]], bool] | None = None,
    materialized_output: Path | None = None,
) -> str:
    """Publish only exact pre-state, accept only exact committed state, else fail."""
    for value, label in ((source, "source"), (marker, "marker"), (ledger_old, "old ledger"), (ledger_new, "new ledger")):
        _require_sha(value, label)
    if not sequence_tag.startswith("refs/tags/directory-publication-schema-1-sequence-"):
        raise CasError("sequence tag is outside the publication namespace")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    main_ref = "refs/heads/main"
    ledger_ref = "refs/heads/directory-publication-ledger"
    before = RefState(source, ledger_old, None)
    committed = RefState(marker, ledger_new, ledger_new)
    if materialized_output is not None:
        materialized_output.unlink(missing_ok=True)

    def accept(state: RefState) -> str | None:
        if state == committed:
            return "committed"
        if state.main == marker and state.sequence_tag == ledger_new and state.ledger is not None:
            # ls-remote proves the ref identity, then fetch and inspect that
            # exact immutable object before treating it as our rerun state.
            fetched = _git(repo, ["fetch", "--no-tags", remote, state.ledger], check=False)
            if fetched.returncode != 0:
                raise CasError("cannot acquire materialized ledger descendant")
            validate_materialized_descendant(repo, state.ledger, ledger_new)
            if materialized_output is not None:
                materialized_output.write_text(state.ledger + "\n", encoding="ascii")
            return "materialized"
        return None

    def push(arguments: Sequence[str]) -> bool:
        if push_runner is not None:
            return push_runner(arguments)
        return _git(repo, list(arguments), check=False).returncode == 0

    arguments = [
        "-c", "core.hooksPath=/dev/null", "push", "--atomic",
        f"--force-with-lease={main_ref}:{source}",
        f"--force-with-lease={ledger_ref}:{ledger_old}",
        f"--force-with-lease={sequence_tag}:",
        remote,
        f"{marker}:{main_ref}", f"{ledger_new}:{ledger_ref}", f"{ledger_new}:{sequence_tag}",
    ]
    for _attempt in range(attempts):
        try:
            state = read_ref_state(repo, remote, main_ref, ledger_ref, sequence_tag)
        except subprocess.CalledProcessError:
            continue
        accepted = accept(state)
        if accepted is not None:
            return accepted
        if state != before:
            raise CasError(f"publication ref conflict: observed {state}")
        push(arguments)
        # Always perform exact multi-ref readback.  This also resolves a lost
        # receive-pack response without regenerating any object or sequence.
        try:
            state = read_ref_state(repo, remote, main_ref, ledger_ref, sequence_tag)
        except subprocess.CalledProcessError:
            continue
        if state == committed:
            return "published"
        accepted = accept(state)
        if accepted is not None:
            return accepted
        if state != before:
            raise CasError(f"publication ref conflict after push: observed {state}")
    raise CasError("publication push failed with exact pre-state still present")


def materialize_transition(
    repo: Path, remote: str, *, ledger_old: str, ledger_new: str, attempts: int = 3,
    push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> str:
    """Advance the ledger with an exact lease, accepting only exact readback."""
    _require_sha(ledger_old, "old ledger")
    _require_sha(ledger_new, "new ledger")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    ledger_ref = "refs/heads/directory-publication-ledger"

    def read() -> str | None:
        return read_ref_state(repo, remote, "refs/heads/__unused-main", ledger_ref, "refs/tags/__unused-tag").ledger

    arguments = [
        "-c", "core.hooksPath=/dev/null", "push",
        f"--force-with-lease={ledger_ref}:{ledger_old}", remote,
        f"{ledger_new}:{ledger_ref}",
    ]
    for _attempt in range(attempts):
        observed = read()
        if observed == ledger_new:
            return "committed"
        if observed != ledger_old:
            raise CasError(f"materialization ledger conflict: observed {observed}")
        succeeded = push_runner(arguments) if push_runner is not None else _git(repo, arguments, check=False).returncode == 0
        del succeeded  # Exact readback, not the transport response, is authoritative.
        observed = read()
        if observed == ledger_new:
            return "published"
        if observed != ledger_old:
            raise CasError(f"materialization ledger conflict after push: observed {observed}")
    raise CasError("materialization push failed with exact pre-state still present")


def validate_signed_directory_append(repo: Path, ledger_old: str, signed: str, sequence_tag: str) -> None:
    """Authenticate the prepared Directory delta independently of its parent SHA."""
    if _git(repo, ["show", "-s", "--format=%P", signed]).stdout.strip().split() != [ledger_old]:
        raise CasError("signed ledger is not the exact old-ledger child")
    if _git(repo, ["show", "-s", "--format=%B", signed]).stdout != "chore(directory): publish signed snapshot\n\n":
        raise CasError("signed Directory commit message is invalid")
    sequence = int(sequence_tag.rsplit("-", 1)[1])
    if sequence < 1:
        raise CasError("sequence tag must name a positive sequence")
    stem = f"{sequence:020d}"
    expected = {
        "registry/schemas/1/latest.json": {"A", "M"},
        f"registry/schemas/1/snapshots/{stem}.envelope.json": {"A"},
        f"registry/schemas/1/snapshots/{stem}.json": {"A"},
    }
    if sequence == 1:
        expected["registry/schemas/1/ledger-contract.json"] = {"A"}
    changed = _git(
        repo, ["diff-tree", "--no-commit-id", "--name-status", "--no-renames", "-r", ledger_old, signed],
    ).stdout.splitlines()
    actual: dict[str, str] = {}
    for change in changed:
        fields = change.split("\t")
        if len(fields) != 2 or fields[1] in actual:
            raise CasError("signed Directory append has malformed path changes")
        actual[fields[1]] = fields[0]
    if set(actual) != set(expected) or any(actual[path] not in statuses for path, statuses in expected.items()):
        raise CasError("signed Directory append is not the exact immutable publication shape")
    for path in expected:
        entry = _git(repo, ["ls-tree", signed, "--", path]).stdout.strip().split(None, 3)
        if len(entry) != 4 or entry[0] != "100644" or entry[1] != "blob" or entry[3] != path:
            raise CasError("signed Directory append contains a non-regular publication file")


def _root_entries(repo: Path, commit: str) -> dict[bytes, bytes]:
    raw = subprocess.run(
        [GIT, "-C", str(repo), "ls-tree", "-z", commit],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout
    entries: dict[bytes, bytes] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        header, separator, name = entry.partition(b"\t")
        if not separator or not name or name in entries or len(header.split(b" ")) != 3:
            raise CasError("commit has malformed root tree entries")
        entries[name] = entry
    return entries


def _replace_root_entries(repo: Path, base: str, donor: str, names: set[bytes]) -> str:
    entries = _root_entries(repo, base)
    donated = _root_entries(repo, donor)
    for name in names:
        if name in donated:
            entries[name] = donated[name]
        else:
            entries.pop(name, None)
    data = b"\0".join(entries.values()) + b"\0"
    result = subprocess.run(
        [GIT, "-C", str(repo), "mktree", "-z"], input=data,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout.decode("ascii").strip()


def _commit_like(repo: Path, template: str, tree: str, parent: str) -> str:
    metadata = _git(
        repo, ["show", "-s", "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI", template],
    ).stdout.strip().split("\0")
    if len(metadata) != 6:
        raise CasError("prepared commit metadata is malformed")
    author, author_email, author_date, committer, committer_email, committer_date = metadata
    _headers, separator, message = _git(repo, ["cat-file", "-p", template]).stdout.partition("\n\n")
    if not separator:
        raise CasError("prepared commit message is missing")
    if (author, author_email, committer, committer_email) != (
        MARKER_NAME, MARKER_EMAIL, MARKER_NAME, MARKER_EMAIL,
    ):
        raise CasError("prepared commit does not have the publisher identity")
    identity_env = dict(os.environ)
    identity_env.update({
        "GIT_AUTHOR_NAME": author, "GIT_AUTHOR_EMAIL": author_email,
        "GIT_AUTHOR_DATE": author_date, "GIT_COMMITTER_NAME": committer,
        "GIT_COMMITTER_EMAIL": committer_email, "GIT_COMMITTER_DATE": committer_date,
    })
    return _git(repo, ["commit-tree", tree, "-p", parent], input_text=message, env=identity_env).stdout.strip()


def reassemble_materialization(
    repo: Path, *, ledger_old: str, prepared_signed: str, prepared_materialized: str,
    ledger_head: str, sequence_tag: str, remote: str = "origin",
) -> tuple[str, str]:
    """Reparent approved Directory and static bytes over feed-only ledger movement."""
    for value, label in ((ledger_old, "old ledger"), (prepared_signed, "prepared signed"),
                         (prepared_materialized, "prepared materialized"), (ledger_head, "current ledger")):
        _require_sha(value, label)
    if not re.fullmatch(r"refs/tags/directory-publication-schema-1-sequence-[0-9]{20}", sequence_tag):
        raise CasError("sequence tag is outside the publication namespace")
    validate_signed_directory_append(repo, ledger_old, prepared_signed, sequence_tag)
    validate_materialized_descendant(repo, prepared_materialized, prepared_signed)
    if _git(repo, ["merge-base", "--is-ancestor", ledger_old, ledger_head], check=False).returncode != 0:
        raise CasError("current ledger does not descend from the prepared ledger parent")
    previous = ledger_old
    for descendant in _git(repo, ["rev-list", "--reverse", "--ancestry-path", f"{ledger_old}..{ledger_head}"]).stdout.splitlines():
        if _git(repo, ["show", "-s", "--format=%P", descendant]).stdout.strip().split() != [previous]:
            raise CasError("intervening ledger history is not linear")
        _validate_feed_or_recovery(repo, remote, previous, descendant)
        previous = descendant
    old_roots = _root_entries(repo, ledger_old)
    signed_roots = _root_entries(repo, prepared_signed)
    head_roots = _root_entries(repo, ledger_head)
    materialized_roots = _root_entries(repo, prepared_materialized)
    if {name for name in old_roots.keys() | signed_roots.keys() if old_roots.get(name) != signed_roots.get(name)} != {b"registry"}:
        raise CasError("prepared signed commit changes non-registry root trees")
    if any(old_roots.get(name) != head_roots.get(name) for name in old_roots.keys() | head_roots.keys() if name not in {b"discovery", b"security"}):
        raise CasError("intervening ledger changed non-feed root trees")
    if any(signed_roots.get(name) != materialized_roots.get(name) for name in signed_roots.keys() | materialized_roots.keys() if name in {b"registry", b"discovery", b"security"}):
        raise CasError("prepared materialization changed registry or feed root trees")
    signed_tree = _replace_root_entries(repo, ledger_head, prepared_signed, {b"registry"})
    signed = _commit_like(repo, prepared_signed, signed_tree, ledger_head)
    validate_signed_directory_append(repo, ledger_head, signed, sequence_tag)
    materialized_tree = _replace_root_entries(repo, prepared_materialized, ledger_head, {b"discovery", b"security"})
    materialized = _commit_like(repo, prepared_materialized, materialized_tree, signed)
    validate_materialized_descendant(repo, materialized, signed)
    if any(_root_entries(repo, materialized).get(name) != materialized_roots.get(name)
           for name in materialized_roots.keys() | _root_entries(repo, materialized).keys()
           if name not in {b"discovery", b"security"}):
        raise CasError("rebased materialization changed prepared static bytes")
    return signed, materialized


def atomic_materialized_transition(
    repo: Path, remote: str, *, source: str, marker: str, ledger_old: str,
    signed: str, materialized: str, sequence_tag: str, publication_id: str,
    attempts: int = 3,
    push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> str:
    """Publish P, S and M in one ref transaction, with S the sole parent of M."""
    for value, label in (
        (source, "source"), (marker, "marker"), (ledger_old, "old ledger"),
        (signed, "signed ledger"), (materialized, "materialized ledger"),
    ):
        _require_sha(value, label)
    if not re.fullmatch(r"refs/tags/directory-publication-schema-1-sequence-[0-9]{20}", sequence_tag):
        raise CasError("sequence tag is outside the publication namespace")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    validate_marker(repo, marker, source, publication_id)
    validate_signed_directory_append(repo, ledger_old, signed, sequence_tag)
    validate_materialized_descendant(repo, materialized, signed)

    main_ref = "refs/heads/main"
    ledger_ref = "refs/heads/directory-publication-ledger"
    before = RefState(source, ledger_old, None)
    committed = RefState(marker, materialized, signed)
    arguments = [
        "-c", "core.hooksPath=/dev/null", "push", "--atomic",
        f"--force-with-lease={main_ref}:{source}",
        f"--force-with-lease={ledger_ref}:{ledger_old}",
        f"--force-with-lease={sequence_tag}:",
        remote,
        f"{marker}:{main_ref}", f"{materialized}:{ledger_ref}",
        f"{signed}:{sequence_tag}",
    ]
    for _attempt in range(attempts):
        try:
            state = read_ref_state(repo, remote, main_ref, ledger_ref, sequence_tag)
        except subprocess.CalledProcessError:
            continue
        if state == committed:
            return "committed"
        if state != before:
            raise CasError(f"materialized publication ref conflict: observed {state}")
        if push_runner is not None:
            push_runner(arguments)
        else:
            _git(repo, arguments, check=False)
        try:
            state = read_ref_state(repo, remote, main_ref, ledger_ref, sequence_tag)
        except subprocess.CalledProcessError:
            continue
        if state == committed:
            return "published"
        if state != before:
            raise CasError(f"materialized publication ref conflict after push: observed {state}")
    raise CasError("materialized publication push failed with exact pre-state still present")


def atomic_rebased_materialized_transition(
    repo: Path, remote: str, *, source: str, marker: str, ledger_old: str,
    prepared_signed: str, prepared_materialized: str, authenticated_head: str,
    sequence_tag: str, publication_id: str, attempts: int = 3,
    push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> RebasedPublication:
    """Publish H->S1->M1 after feed-only movement, never trusting a new H silently.

    ``authenticated_head`` is verified by the protected caller, including the
    current feed signatures. If a feed wins the lease, the caller must fetch,
    reauthenticate and invoke this function again with that exact new head.
    """
    for value, label in ((source, "source"), (marker, "marker"), (ledger_old, "old ledger"),
                         (prepared_signed, "prepared signed"), (prepared_materialized, "prepared materialized"),
                         (authenticated_head, "authenticated head")):
        _require_sha(value, label)
    if not re.fullmatch(r"refs/tags/directory-publication-schema-1-sequence-[0-9]{20}", sequence_tag):
        raise CasError("sequence tag is outside the publication namespace")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    validate_marker(repo, marker, source, publication_id)
    main_ref = "refs/heads/main"
    ledger_ref = "refs/heads/directory-publication-ledger"

    def read() -> RefState:
        return read_ref_state(repo, remote, main_ref, ledger_ref, sequence_tag)

    def accept_existing(state: RefState) -> RebasedPublication | None:
        if state.main != marker or state.sequence_tag is None or state.ledger is None:
            return None
        for oid in (state.sequence_tag, state.ledger):
            if _git(repo, ["fetch", "--no-tags", remote, oid], check=False).returncode != 0:
                raise CasError("cannot acquire completed materialized publication")
        materialized = validate_staged_lineage(repo, state.ledger, state.sequence_tag, remote=remote)
        parent = _git(repo, ["rev-parse", f"{state.sequence_tag}^" ]).stdout.strip()
        expected_signed, expected_materialized = reassemble_materialization(
            repo, ledger_old=ledger_old, prepared_signed=prepared_signed,
            prepared_materialized=prepared_materialized, ledger_head=parent,
            sequence_tag=sequence_tag, remote=remote,
        )
        if (state.sequence_tag, materialized) != (expected_signed, expected_materialized):
            raise CasError("committed publication differs from prepared signed or site bytes")
        if (state.ledger != expected_materialized and authenticated_head != state.ledger):
            raise CasError("post-publication feed movement was not authenticated by the caller")
        if (state.ledger == expected_materialized
                and authenticated_head not in (parent, expected_materialized)):
            raise CasError("completed publication differs from the authenticated caller head")
        return RebasedPublication("committed", expected_signed, expected_materialized, state.ledger)

    try:
        state = read()
    except subprocess.CalledProcessError as error:
        raise CasError("cannot read current publication refs") from error
    accepted = accept_existing(state)
    if accepted is not None:
        return accepted
    if state != RefState(source, authenticated_head, None):
        raise CasError(f"materialized publication ref conflict: observed {state}")
    signed, materialized = reassemble_materialization(
        repo, ledger_old=ledger_old, prepared_signed=prepared_signed,
        prepared_materialized=prepared_materialized, ledger_head=authenticated_head,
        sequence_tag=sequence_tag, remote=remote,
    )
    arguments = [
        "-c", "core.hooksPath=/dev/null", "push", "--atomic",
        f"--force-with-lease={main_ref}:{source}",
        f"--force-with-lease={ledger_ref}:{authenticated_head}",
        f"--force-with-lease={sequence_tag}:", remote,
        f"{marker}:{main_ref}", f"{materialized}:{ledger_ref}", f"{signed}:{sequence_tag}",
    ]
    for _attempt in range(attempts):
        try:
            state = read()
        except subprocess.CalledProcessError:
            continue
        accepted = accept_existing(state)
        if accepted is not None:
            return accepted
        if state != RefState(source, authenticated_head, None):
            raise CasError(f"materialized publication ref conflict: observed {state}")
        if push_runner is not None:
            push_runner(arguments)
        else:
            _git(repo, arguments, check=False)
        try:
            state = read()
        except subprocess.CalledProcessError:
            continue
        accepted = accept_existing(state)
        if accepted is not None:
            return RebasedPublication("published", accepted.signed, accepted.materialized, accepted.ledger_head)
        if state != RefState(source, authenticated_head, None):
            raise CasError(f"materialized publication ref conflict after push: observed {state}")
    raise CasError("materialized publication push failed with exact pre-state still present")


def evidence_transition(
    repo: Path, remote: str, *, main_old: str, main_new: str,
    ledger_old: str, ledger_new: str, approval_target: str, approval_tag: str,
    attempts: int = 3,
    push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> str:
    """Atomically append evidence, select it on main, and approve the gated ledger.

    The approval tag deliberately targets ``approval_target``: that is the
    exact staged publication whose protected live gate produced the evidence.
    Discovery-only commits may already follow it before the permanent evidence
    child is appended to ``ledger_old``.
    """
    for value, label in (
        (main_old, "old main"), (main_new, "new main"),
        (ledger_old, "old ledger"), (ledger_new, "new ledger"),
        (approval_target, "approval target"),
    ):
        _require_sha(value, label)
    if approval_tag != "refs/tags/directory-publication-schema-1-launch-approved":
        raise CasError("launch approval tag is outside the fixed namespace")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    if _git(repo, ["merge-base", "--is-ancestor", approval_target, ledger_old], check=False).returncode != 0:
        raise CasError("approval target is not an ancestor of the evidence parent")
    if _git(repo, ["show", "-s", "--format=%P", ledger_new]).stdout.strip().split() != [ledger_old]:
        raise CasError("evidence ledger commit is not the exact parent child")
    if _git(repo, ["show", "-s", "--format=%P", main_new]).stdout.strip().split() != [main_old]:
        raise CasError("evidence main commit is not the exact parent child")
    main_ref = "refs/heads/main"
    ledger_ref = "refs/heads/directory-publication-ledger"
    before = RefState(main_old, ledger_old, None)
    committed = RefState(main_new, ledger_new, approval_target)
    arguments = [
        "-c", "core.hooksPath=/dev/null", "push", "--atomic",
        f"--force-with-lease={main_ref}:{main_old}",
        f"--force-with-lease={ledger_ref}:{ledger_old}",
        f"--force-with-lease={approval_tag}:",
        remote,
        f"{main_new}:{main_ref}", f"{ledger_new}:{ledger_ref}",
        f"{approval_target}:{approval_tag}",
    ]
    for _attempt in range(attempts):
        try:
            state = read_ref_state(repo, remote, main_ref, ledger_ref, approval_tag)
        except subprocess.CalledProcessError:
            continue
        if state == committed:
            return "committed"
        if state != before:
            raise CasError(f"evidence publication ref conflict: observed {state}")
        if push_runner is not None:
            push_runner(arguments)
        else:
            _git(repo, arguments, check=False)
        # The transport response is never authoritative. Resolve success,
        # conflict, or safe retry from one exact three-ref readback.
        try:
            state = read_ref_state(repo, remote, main_ref, ledger_ref, approval_tag)
        except subprocess.CalledProcessError:
            continue
        if state == committed:
            return "published"
        if state != before:
            raise CasError(f"evidence publication ref conflict after push: observed {state}")
    raise CasError("evidence publication push failed with exact pre-state still present")


def production_transition(
    repo: Path, remote: str, *, production_new: str, production_tag: str,
    attempts: int = 3, push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> str:
    """Select the exact tree deployed to Pages using a monotonic CAS tag."""
    _require_sha(production_new, "new production commit")
    if production_tag != "refs/tags/directory-publication-schema-1-production":
        raise CasError("production tag is outside the fixed namespace")
    if not 1 <= attempts <= 3:
        raise CasError("attempt count must be between one and three")
    if _git(repo, ["cat-file", "-t", production_new]).stdout.strip() != "commit":
        raise CasError("new production object is not a commit")

    def read() -> str | None:
        return read_ref_state(
            repo, remote, "refs/heads/__unused-main",
            "refs/heads/__unused-ledger", production_tag,
        ).sequence_tag

    for _attempt in range(attempts):
        observed = read()
        if observed == production_new:
            return "committed"
        if observed is not None:
            fetched = _git(repo, ["fetch", "--no-tags", remote, observed], check=False)
            if fetched.returncode != 0:
                continue
            if _git(repo, ["merge-base", "--is-ancestor", production_new, observed], check=False).returncode == 0:
                return "superseded"
            if _git(repo, ["merge-base", "--is-ancestor", observed, production_new], check=False).returncode != 0:
                raise CasError("production tag update would roll back or change ledger lineage")
        lease = f"--force-with-lease={production_tag}:{observed or ''}"
        arguments = [
            "-c", "core.hooksPath=/dev/null", "push", lease, remote,
            f"{production_new}:{production_tag}",
        ]
        if push_runner is not None:
            push_runner(arguments)
        else:
            _git(repo, arguments, check=False)
        current = read()
        if current == production_new:
            return "published"
        if current != observed:
            if current is not None:
                _git(repo, ["fetch", "--no-tags", remote, current])
                if _git(repo, ["merge-base", "--is-ancestor", production_new, current], check=False).returncode == 0:
                    return "superseded"
            raise CasError(f"production tag conflict after push: observed {current}")
    raise CasError("production tag push failed with exact pre-state still present")


def promotion_intent_ref(sequence: int) -> str:
    if not 1 <= sequence <= 9_007_199_254_740_991:
        raise CasError("promotion intent sequence is invalid")
    return f"{PROMOTION_INTENT_PREFIX}{sequence:020d}"


def _snapshot_identity(repo: Path, signed: str, sequence: int) -> tuple[str, str]:
    path = f"registry/schemas/1/snapshots/{sequence:020d}.json"
    body = _git(repo, ["show", f"{signed}:{path}"]).stdout.encode("utf-8")
    snapshot = json.loads(body)
    if snapshot.get("sequence") != sequence or not isinstance(snapshot.get("publication_id"), str):
        raise CasError("signed snapshot identity differs from promotion intent")
    return snapshot["publication_id"], "sha256:" + hashlib.sha256(body).hexdigest()


def create_promotion_intent(
    repo: Path, *, materialized: str, signed: str, sequence: int,
    publication_id: str, snapshot_digest: str, readiness_digest: str,
) -> str:
    """Create a deterministic annotated tag object binding owner approval to M."""
    for value, label in ((materialized, "materialized"), (signed, "signed")):
        _require_sha(value, label)
    ref = promotion_intent_ref(sequence)
    if _git(repo, ["show", "-s", "--format=%P", materialized]).stdout.strip().split() != [signed]:
        raise CasError("promotion intent M is not the exact signed child")
    validate_materialized_descendant(repo, materialized, signed)
    actual_id, actual_digest = _snapshot_identity(repo, signed, sequence)
    if (publication_id, snapshot_digest) != (actual_id, actual_digest):
        raise CasError("promotion intent differs from signed snapshot identity")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", readiness_digest) is None:
        raise CasError("promotion readiness digest is invalid")
    timestamp = _git(repo, ["show", "-s", "--format=%ct", materialized]).stdout.strip()
    if not timestamp.isdigit():
        raise CasError("materialized timestamp is invalid")
    name = ref.removeprefix("refs/tags/")
    body = (
        f"object {materialized}\n"
        "type commit\n"
        f"tag {name}\n"
        f"tagger {MARKER_NAME} <{MARKER_EMAIL}> {timestamp} +0000\n"
        "\n"
        "Directory-Promotion-Intent: 1\n"
        f"Publication-ID: {publication_id}\n"
        f"Sequence: {sequence}\n"
        f"Signed-Commit: {signed}\n"
        f"Materialized-Commit: {materialized}\n"
        f"Snapshot-Digest: {snapshot_digest}\n"
        f"Readiness-Digest: {readiness_digest}\n"
    )
    tag = _git(repo, ["mktag"], input_text=body).stdout.strip()
    _require_sha(tag, "promotion intent tag object")
    return tag


def parse_promotion_intent(repo: Path, ref: str, tag: str) -> dict[str, str | int]:
    if not re.fullmatch(r"refs/tags/directory-publication-schema-1-promotion-intent-[0-9]{20}", ref):
        raise CasError("promotion intent is outside the protected namespace")
    _require_sha(tag, "promotion intent object")
    if _git(repo, ["cat-file", "-t", tag]).stdout.strip() != "tag":
        raise CasError("promotion intent must be an annotated tag")
    body = _git(repo, ["cat-file", "-p", tag]).stdout
    match = re.fullmatch(
        r"object ([0-9a-f]{40})\ntype commit\ntag ([A-Za-z0-9._-]+)\n"
        r"tagger uap-directory-publisher\[bot\] <uap-directory-publisher\[bot\]@users\.noreply\.github\.com> [0-9]+ \+0000\n\n"
        r"Directory-Promotion-Intent: 1\nPublication-ID: ([A-Za-z0-9][A-Za-z0-9._-]{0,127})\n"
        r"Sequence: ([1-9][0-9]*)\nSigned-Commit: ([0-9a-f]{40})\n"
        r"Materialized-Commit: ([0-9a-f]{40})\nSnapshot-Digest: (sha256:[0-9a-f]{64})\n"
        r"Readiness-Digest: (sha256:[0-9a-f]{64})\n",
        body,
    )
    if match is None:
        raise CasError("promotion intent object has invalid fields")
    materialized, tag_name, publication_id, raw_sequence, signed, advertised_materialized, digest, readiness = match.groups()
    sequence = int(raw_sequence)
    if (ref != promotion_intent_ref(sequence) or tag_name != ref.removeprefix("refs/tags/")
            or advertised_materialized != materialized):
        raise CasError("promotion intent ref and target disagree")
    if _git(repo, ["show", "-s", "--format=%P", materialized]).stdout.strip().split() != [signed]:
        raise CasError("promotion intent target is not the exact signed child")
    actual_id, actual_digest = _snapshot_identity(repo, signed, sequence)
    if (publication_id, digest) != (actual_id, actual_digest):
        raise CasError("promotion intent differs from signed snapshot")
    validate_materialized_descendant(repo, materialized, signed)
    return {"materialized": materialized, "signed": signed, "publication_id": publication_id,
            "sequence": sequence, "snapshot_digest": digest, "readiness_digest": readiness}


def publish_promotion_intent(
    repo: Path, remote: str, *, materialized: str, signed: str, sequence: int,
    publication_id: str, snapshot_digest: str, readiness_digest: str,
    attempts: int = 3, push_runner: Callable[[Sequence[str]], bool] | None = None,
) -> str:
    """Create-only protected intent, accepting only its exact persisted tag."""
    ref = promotion_intent_ref(sequence)
    expected = create_promotion_intent(
        repo, materialized=materialized, signed=signed, sequence=sequence,
        publication_id=publication_id, snapshot_digest=snapshot_digest,
        readiness_digest=readiness_digest,
    )
    ledger_ref = "refs/heads/directory-publication-ledger"
    sequence_ref = f"refs/tags/directory-publication-schema-1-sequence-{sequence:020d}"
    tagged_signed = read_ref_state(
        repo, remote, "refs/heads/__unused-main", "refs/heads/__unused-ledger", sequence_ref,
    ).sequence_tag
    if tagged_signed != signed:
        raise CasError("promotion intent signed commit is not the immutable Directory sequence tag")
    for _attempt in range(attempts):
        state = read_ref_state(repo, remote, "refs/heads/__unused-main", ledger_ref, ref)
        if state.sequence_tag == expected:
            return "committed"
        if state.sequence_tag is not None:
            raise CasError("promotion intent ref already names another object")
        if state.ledger is None:
            raise CasError("promotion intent ledger is absent")
        if _git(repo, ["fetch", "--no-tags", remote, state.ledger], check=False).returncode != 0:
            continue
        if _git(repo, ["merge-base", "--is-ancestor", materialized, state.ledger], check=False).returncode != 0:
            raise CasError("promotion intent target is not in current ledger lineage")
        arguments = ["-c", "core.hooksPath=/dev/null", "push", f"--force-with-lease={ref}:",
                     remote, f"{expected}:{ref}"]
        if push_runner is not None:
            push_runner(arguments)
        else:
            _git(repo, arguments, check=False)
        state = read_ref_state(repo, remote, "refs/heads/__unused-main", ledger_ref, ref)
        if state.sequence_tag == expected:
            return "published"
        if state.sequence_tag is not None:
            raise CasError("promotion intent ref changed after push")
    raise CasError("promotion intent push failed with exact pre-state still present")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    marker_parser = subparsers.add_parser("marker")
    marker_parser.add_argument("--repo", type=Path, default=Path.cwd())
    marker_parser.add_argument("--source", required=True)
    marker_parser.add_argument("--publication-id", required=True)
    marker_parser.add_argument("--output", type=Path)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--repo", type=Path, default=Path.cwd())
    publish_parser.add_argument("--remote", default="origin")
    publish_parser.add_argument("--source", required=True)
    publish_parser.add_argument("--marker", required=True)
    publish_parser.add_argument("--ledger-old", required=True)
    publish_parser.add_argument("--ledger-new", required=True)
    publish_parser.add_argument("--sequence-tag", required=True)
    publish_parser.add_argument("--materialized-output", type=Path)
    materialize_parser = subparsers.add_parser("materialize")
    materialize_parser.add_argument("--repo", type=Path, default=Path.cwd())
    materialize_parser.add_argument("--remote", default="origin")
    materialize_parser.add_argument("--ledger-old", required=True)
    materialize_parser.add_argument("--ledger-new", required=True)
    atomic_materialize_parser = subparsers.add_parser("materialize-publish")
    atomic_materialize_parser.add_argument("--repo", type=Path, default=Path.cwd())
    atomic_materialize_parser.add_argument("--remote", default="origin")
    atomic_materialize_parser.add_argument("--source", required=True)
    atomic_materialize_parser.add_argument("--marker", required=True)
    atomic_materialize_parser.add_argument("--ledger-old", required=True)
    atomic_materialize_parser.add_argument("--signed", required=True)
    atomic_materialize_parser.add_argument("--materialized", required=True)
    atomic_materialize_parser.add_argument("--sequence-tag", required=True)
    atomic_materialize_parser.add_argument("--publication-id", required=True)
    rebase_parser = subparsers.add_parser("materialize-rebase-publish")
    rebase_parser.add_argument("--repo", type=Path, default=Path.cwd())
    rebase_parser.add_argument("--remote", default="origin")
    rebase_parser.add_argument("--source", required=True)
    rebase_parser.add_argument("--marker", required=True)
    rebase_parser.add_argument("--ledger-old", required=True)
    rebase_parser.add_argument("--prepared-signed", required=True)
    rebase_parser.add_argument("--prepared-materialized", required=True)
    rebase_parser.add_argument("--authenticated-head", required=True)
    rebase_parser.add_argument("--sequence-tag", required=True)
    rebase_parser.add_argument("--publication-id", required=True)
    rebase_parser.add_argument("--result", type=Path, required=True)
    evidence_parser = subparsers.add_parser("evidence-publish")
    evidence_parser.add_argument("--repo", type=Path, default=Path.cwd())
    evidence_parser.add_argument("--remote", default="origin")
    evidence_parser.add_argument("--main-old", required=True)
    evidence_parser.add_argument("--main-new", required=True)
    evidence_parser.add_argument("--ledger-old", required=True)
    evidence_parser.add_argument("--ledger-new", required=True)
    evidence_parser.add_argument("--approval-target", required=True)
    evidence_parser.add_argument(
        "--approval-tag",
        default="refs/tags/directory-publication-schema-1-launch-approved",
    )
    production_parser = subparsers.add_parser("production-publish")
    production_parser.add_argument("--repo", type=Path, default=Path.cwd())
    production_parser.add_argument("--remote", default="origin")
    production_parser.add_argument("--production-new", required=True)
    production_parser.add_argument(
        "--production-tag",
        default="refs/tags/directory-publication-schema-1-production",
    )
    intent_parser = subparsers.add_parser("promotion-intent-publish")
    intent_parser.add_argument("--repo", type=Path, default=Path.cwd())
    intent_parser.add_argument("--remote", default="origin")
    intent_parser.add_argument("--materialized", required=True)
    intent_parser.add_argument("--signed", required=True)
    intent_parser.add_argument("--sequence", type=int, required=True)
    intent_parser.add_argument("--publication-id", required=True)
    intent_parser.add_argument("--snapshot-digest", required=True)
    intent_parser.add_argument("--readiness-digest", required=True)
    verify_materialized_parser = subparsers.add_parser("materialize-verify")
    verify_materialized_parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_materialized_parser.add_argument("--signed", required=True)
    verify_materialized_parser.add_argument("--materialized", required=True)
    staged_lineage_parser = subparsers.add_parser("staged-lineage-verify")
    staged_lineage_parser.add_argument("--repo", type=Path, default=Path.cwd())
    staged_lineage_parser.add_argument("--signed", required=True)
    staged_lineage_parser.add_argument("--current", required=True)
    args = parser.parse_args()
    try:
        if args.command == "marker":
            result = create_marker(args.repo, args.source, args.publication_id)
            if args.output:
                args.output.write_text(result + "\n", encoding="ascii")
        elif args.command == "publish":
            result = atomic_transition(
                args.repo, args.remote, source=args.source, marker=args.marker,
                ledger_old=args.ledger_old, ledger_new=args.ledger_new,
                sequence_tag=args.sequence_tag,
                materialized_output=args.materialized_output,
            )
        elif args.command == "materialize":
            result = materialize_transition(
                args.repo, args.remote, ledger_old=args.ledger_old,
                ledger_new=args.ledger_new,
            )
        elif args.command == "materialize-publish":
            result = atomic_materialized_transition(
                args.repo, args.remote, source=args.source, marker=args.marker,
                ledger_old=args.ledger_old, signed=args.signed,
                materialized=args.materialized, sequence_tag=args.sequence_tag,
                publication_id=args.publication_id,
            )
        elif args.command == "materialize-rebase-publish":
            published = atomic_rebased_materialized_transition(
                args.repo, args.remote, source=args.source, marker=args.marker,
                ledger_old=args.ledger_old, prepared_signed=args.prepared_signed,
                prepared_materialized=args.prepared_materialized,
                authenticated_head=args.authenticated_head, sequence_tag=args.sequence_tag,
                publication_id=args.publication_id,
            )
            args.result.write_text(json.dumps({
                "status": published.status, "signed": published.signed,
                "materialized": published.materialized, "ledger_head": published.ledger_head,
            }, sort_keys=True) + "\n", encoding="ascii")
            result = published.status
        elif args.command == "evidence-publish":
            result = evidence_transition(
                args.repo, args.remote, main_old=args.main_old, main_new=args.main_new,
                ledger_old=args.ledger_old, ledger_new=args.ledger_new,
                approval_target=args.approval_target, approval_tag=args.approval_tag,
            )
        elif args.command == "production-publish":
            result = production_transition(
                args.repo, args.remote, production_new=args.production_new,
                production_tag=args.production_tag,
            )
        elif args.command == "promotion-intent-publish":
            result = publish_promotion_intent(
                args.repo, args.remote, materialized=args.materialized,
                signed=args.signed, sequence=args.sequence,
                publication_id=args.publication_id,
                snapshot_digest=args.snapshot_digest,
                readiness_digest=args.readiness_digest,
            )
        elif args.command == "materialize-verify":
            validate_materialized_descendant(args.repo, args.materialized, args.signed)
            result = "valid"
        else:
            result = validate_staged_lineage(args.repo, args.current, args.signed)
    except (CasError, OSError, subprocess.SubprocessError) as error:
        print(f"directory-publication-cas: {error}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
