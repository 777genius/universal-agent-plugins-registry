#!/usr/bin/env python3
"""Publish a signed nine-source SkillSpector release on an isolated CAS branch.

The existing v1/v2/v3 report publisher never reads or writes this branch.
Only an independently authenticated main-only signer may call publish().
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from scripts import skillspector_cohort_release_protocol as protocol
from scripts import skillspector_reports as scanner
from scripts.directory_publication import (
    PublicationError, canonical_json, parse_json_bytes, parse_timestamp,
    require, sha256_digest,
)
from scripts.skillspector_publication_transport import create_filtered_tree

BRANCH = "skillspector-cohort-releases"
REPORT_BRANCH = "skillspector-reports"
PREFIX = "reports/skillspector/cohort/v1/"
POINTER = PREFIX + "latest.json"
MAX_PUBLICATION_FILES = 1024
MAX_POINTER_BYTES = 4096
RELEASE_PATH = re.compile(r"releases/[0-9a-f]{64}\.json\Z")
ENVELOPE_PATH = re.compile(r"envelopes/[0-9a-f]{64}\.json\Z")
SHA = protocol.SHA
DIGEST = protocol.DIGEST
POINTER_FIELDS = {
    "schema_version", "kind", "sequence", "source_commit",
    "report_commit", "release_path", "envelope_path",
    "release_digest", "envelope_digest", "generated_at", "expires_at",
}


class StaleCohortPublication(PublicationError):
    """A report, main, or isolated cohort branch advanced since qualification."""


def git_blob_sha(body: bytes) -> str:
    """Calculate the Git object identity for the exact signed artifact bytes."""
    return hashlib.sha1(
        b"blob " + str(len(body)).encode("ascii") + b"\x00" + body).hexdigest()


def checked_head(github, branch: str) -> str | None:
    """Require a valid SHA from the exact GitHub branch ref, if it exists."""
    ref = github.request("GET", f"git/ref/heads/{branch}")
    require(ref is None or isinstance(ref, dict) and
            isinstance(ref.get("object"), dict) and
            isinstance(ref["object"].get("sha"), str) and
            SHA.fullmatch(ref["object"]["sha"]) is not None,
            "GitHub cohort reference has invalid identity")
    return None if ref is None else ref["object"]["sha"]


def allowed_path(path: str) -> bool:
    """Keep the independent branch data-only and specific to v1 releases."""
    if not isinstance(path, str) or not path.startswith(PREFIX):
        return False
    relative = path[len(PREFIX):]
    return relative == "latest.json" or (
        RELEASE_PATH.fullmatch(relative) is not None or
        ENVELOPE_PATH.fullmatch(relative) is not None
    )


def checked_tree(github, head: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """Collect only previously published immutable blobs, no foreign paths."""
    if head is None:
        return {}, {}
    tree = github.request("GET", f"git/trees/{head}?recursive=1")
    require(isinstance(tree, dict) and tree.get("truncated") is False
            and isinstance(tree.get("tree"), list), "previous cohort tree unavailable")
    require(len(tree["tree"]) <= MAX_PUBLICATION_FILES * 4,
            "previous cohort tree exceeds bounded inventory")
    entries, subtrees = {}, {}
    for item in tree["tree"]:
        require(isinstance(item, dict) and
                isinstance(item.get("path"), str) and
                isinstance(item.get("sha"), str) and
                SHA.fullmatch(item["sha"]) is not None,
                "malformed previous cohort Git tree")
        path = item["path"]
        if item.get("type") == "tree":
            require(PREFIX.startswith(path + "/") or path.startswith(PREFIX),
                    "foreign tree in isolated cohort branch")
            subtrees[path] = item["sha"]
        else:
            require(item.get("type") == "blob" and item.get("mode") == "100644"
                    and allowed_path(path) and path not in entries,
                    "foreign or executable blob in isolated cohort branch")
            entries[path] = item["sha"]
    require(len(entries) <= MAX_PUBLICATION_FILES,
            "previous cohort file inventory exceeds bound")
    require(POINTER in entries, "existing cohort branch is missing latest pointer")
    return entries, subtrees


def read_pointer(github, head: str | None) -> dict | None:
    """Read the current pointer by immutable SHA and validate its structure."""
    if head is None:
        return None
    body = github.request("GET", f"contents/{POINTER}?ref={head}", raw=True)
    require(type(body) is bytes and len(body) <= MAX_POINTER_BYTES,
            "current cohort pointer is unavailable")
    pointer = parse_json_bytes(body, "cohort pointer", max_bytes=MAX_POINTER_BYTES)
    require(isinstance(pointer, dict) and set(pointer) == POINTER_FIELDS
            and canonical_json(pointer) == body
            and type(pointer["schema_version"]) is int and pointer["schema_version"] == 1
            and pointer["kind"] == "skillspector-cohort-latest-v1"
            and type(pointer["sequence"]) is int
            and 1 <= pointer["sequence"] < 2**53,
            "existing cohort pointer is invalid")
    require(isinstance(pointer["source_commit"], str)
            and SHA.fullmatch(pointer["source_commit"]) is not None
            and isinstance(pointer["report_commit"], str)
            and SHA.fullmatch(pointer["report_commit"]) is not None,
            "existing cohort source pointers are invalid")
    require(allowed_path(pointer["release_path"]) and
            RELEASE_PATH.fullmatch(pointer["release_path"][len(PREFIX):]) is not None
            and allowed_path(pointer["envelope_path"]) and
            ENVELOPE_PATH.fullmatch(pointer["envelope_path"][len(PREFIX):]) is not None
            and pointer["release_digest"] == "sha256:" +
                pointer["release_path"][len(PREFIX + "releases/"):-len(".json")]
            and pointer["envelope_digest"] == "sha256:" +
                pointer["envelope_path"][len(PREFIX + "envelopes/"):-len(".json")],
            "existing cohort immutable content addresses differ")
    parse_timestamp(pointer["generated_at"], "cohort pointer generated_at")
    parse_timestamp(pointer["expires_at"], "cohort pointer expires_at")
    return pointer


def publish(
    github, body: bytes, envelope_bytes: bytes, trusted_keys: dict[str, bytes],
    previous_dir: Path, fresh_source_loader: Callable[[], dict],
    expected_cohort_head: str | None, *, now: datetime | None = None,
) -> str:
    """CAS-publish only an exact validated release on a separate branch.

    No signing material is used here. Signer and publisher call a privileged,
    independently fresh, Ed25519-verifying source loader before this function.
    """
    current = datetime.now(timezone.utc) if now is None else now
    require(callable(fresh_source_loader), "cohort publication requires live signed feeds")
    release = protocol.verify_release(body, envelope_bytes, trusted_keys,
                                      previous_dir, now=current)
    fresh = fresh_source_loader()
    require(isinstance(fresh, dict) and
            scanner.report_json(fresh) == scanner.report_json(release["signed_sources"]),
            "current signed Community/Directory sources changed before publication")
    source_commit = release["source_commit"]
    report_commit = release["candidate"]["base_report_commit"]
    require(checked_head(github, "main") == source_commit,
            "main advanced since signed cohort qualification")
    require(checked_head(github, REPORT_BRANCH) == report_commit,
            "v3 report branch advanced since signed cohort qualification")

    head = checked_head(github, BRANCH)
    if head != expected_cohort_head:
        raise StaleCohortPublication("isolated cohort branch advanced since preflight")
    entries, subtrees = checked_tree(github, head)
    previous = read_pointer(github, head)
    release_digest, envelope_digest = sha256_digest(body), sha256_digest(envelope_bytes)
    release_path = PREFIX + "releases/" + release_digest[7:] + ".json"
    envelope_path = PREFIX + "envelopes/" + envelope_digest[7:] + ".json"
    if previous is not None:
        if previous["release_digest"] == release_digest and previous["envelope_digest"] == envelope_digest:
            require(entries.get(release_path) == git_blob_sha(body)
                    and entries.get(envelope_path) == git_blob_sha(envelope_bytes),
                    "already published cohort bytes are missing or altered")
            return head
        require(parse_timestamp(previous["generated_at"], "previous cohort generated_at")
                < parse_timestamp(release["generated_at"], "new cohort generated_at"),
                "cohort publication timestamp must advance monotonically")
    sequence = 1 if previous is None else previous["sequence"] + 1
    require(sequence < 2**53, "cohort publication sequence exhausted")
    pointer = {
        "schema_version": 1, "kind": "skillspector-cohort-latest-v1",
        "sequence": sequence, "source_commit": source_commit,
        "report_commit": report_commit,
        "release_path": release_path, "envelope_path": envelope_path,
        "release_digest": release_digest, "envelope_digest": envelope_digest,
        "generated_at": release["generated_at"], "expires_at": release["expires_at"],
    }
    files = {
        POINTER: canonical_json(pointer),
        release_path: body,
        envelope_path: envelope_bytes,
    }
    require(len(entries) + len(files) <= MAX_PUBLICATION_FILES,
            "cohort branch has reached bounded immutable history")
    for path, data in files.items():
        blob_sha = git_blob_sha(data)
        if path in entries and path != POINTER:
            require(entries[path] == blob_sha,
                    "immutable cohort release path has conflicting bytes")
        if entries.get(path) != blob_sha:
            payload = {"content": base64.b64encode(data).decode("ascii"),
                       "encoding": "base64"}
            blob = github.request("POST", "git/blobs", payload)
            require(isinstance(blob, dict) and blob.get("sha") == blob_sha,
                    "uploaded cohort blob differs from canonical bytes")
        entries[path] = blob_sha
    tree = create_filtered_tree(github, entries, known_trees=subtrees)
    commit = github.request("POST", "git/commits", {
        "message": f"chore(skillspector): publish signed cohort v1 sequence {sequence}",
        "tree": tree["sha"], "parents": [head] if head else [],
        "author": {"name": "777genius",
                   "email": "13103045+777genius@users.noreply.github.com",
                   "date": release["generated_at"]},
    })
    require(isinstance(commit, dict) and
            isinstance(commit.get("sha"), str) and
            SHA.fullmatch(commit["sha"]) is not None,
            "cohort Git commit is invalid")
    if checked_head(github, "main") != source_commit or checked_head(github, REPORT_BRANCH) != report_commit:
        raise StaleCohortPublication("source or v3 report changed before cohort pointer write")
    if checked_head(github, BRANCH) != head:
        raise StaleCohortPublication("another cohort publication won the CAS lease")
    if head is None:
        github.request("POST", "git/refs", {
            "ref": f"refs/heads/{BRANCH}", "sha": commit["sha"]})
    else:
        github.request("PATCH", f"git/refs/heads/{BRANCH}", {
            "sha": commit["sha"], "force": False})
    # The new branch pointer and each content object must read back exact.
    require(checked_head(github, BRANCH) == commit["sha"],
            "new cohort branch reference failed readback")
    for path, expected in files.items():
        found = github.request("GET", f"contents/{path}?ref={commit['sha']}", raw=True)
        require(type(found) is bytes and found == expected,
                "cohort immutable artifact readback differs")
    protocol.verify_release(files[release_path], files[envelope_path],
                            trusted_keys, previous_dir, now=current)
    return commit["sha"]
