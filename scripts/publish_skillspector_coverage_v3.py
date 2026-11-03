#!/usr/bin/env python3
"""Validate and atomically publish display-only SkillSpector v3 coverage."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scripts import publish_skillspector_reports as v1
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts import publish_skillspector_coverage as v2
from scripts.skillspector_publication_transport import GitHub, MAX_TREE_ENTRIES, create_filtered_tree
from scripts.directory_publication import (PublicationError, canonical_json, parse_json_bytes,
    parse_timestamp, read_bytes_bounded, read_json, require, sha256_digest)

REPOSITORY = v1.REPOSITORY
BRANCH = v1.BRANCH
PREFIX = "reports/skillspector/v3/"
MANIFEST_PATH = PREFIX + "index.json"
LEGACY_PATH = v1.REPORT_PATH
MAX_API_BYTES = 32 << 20
MAX_TREE_UPLOAD_BYTES = 8 << 20
CONTROL_FILES = {"index.json": coverage.MAX_MANIFEST_BYTES,
    "selection.json": coverage.MAX_SELECTION_BYTES, "attempts.json": coverage.MAX_STATE_BYTES,
    "coverage.json": coverage.MAX_DISCOVERY_BYTES, "recovery.json": 1 << 20}


class SupersededCoverage(PublicationError):
    """The public pointer cannot advance; acknowledged checkpoints need recovery."""


read_json = scanner.read_report_json


def parse_report(body, label, *, max_bytes):
    require(len(body) <= max_bytes, label + " exceeds byte limit")
    return scanner.parse_scanner_json(body, label)


def raw_file(commit, relative, maximum, *, optional=False, version=3):
    require(version in (2, 3), "unsupported report version")
    require(coverage.SHA.fullmatch(commit) is not None, "invalid report branch commit")
    require(relative in CONTROL_FILES or coverage.SHARD_PATH.fullmatch(relative) is not None,
            "unsupported report path")
    # Public immutable URLs avoid API quotas and deliberately receive no credentials.
    request = urllib.request.Request(
        f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/reports/skillspector/v{version}/{relative}",
        headers={"Accept": "application/json", "User-Agent": "uap-skillspector-coverage"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(maximum + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404 and optional:
            return None
        raise PublicationError(f"Public coverage read failed (HTTP {error.code})") from None
    require(len(body) <= maximum, "public coverage file exceeds limit")
    return body


def previous(github, output_dir, *, fetch=raw_file):
    ref = github.request("GET", f"git/ref/heads/{BRANCH}")
    if ref is None:
        return None
    head = ref["object"]["sha"]
    require(coverage.SHA.fullmatch(head) is not None, "invalid report branch head")
    body = fetch(head, "index.json", coverage.MAX_MANIFEST_BYTES, optional=True)
    version = 3
    if body is None:
        version = 2
        body = fetch(head, "index.json", v2.coverage.MAX_MANIFEST_BYTES, optional=True, version=2)
    if body is None:
        return None
    manifest = parse_report(body, "previous manifest", max_bytes=coverage.MAX_MANIFEST_BYTES)
    coverage.validate_manifest(manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    coverage.write_bounded(output_dir / "index.json", manifest, coverage.MAX_MANIFEST_BYTES)
    files = [(name, maximum) for name, maximum in CONTROL_FILES.items() if name != "index.json"]
    files.extend((part["path"], part["bytes"]) for part in manifest["shards"])

    def download(item):
        relative, maximum = item
        contents = fetch(head, relative, maximum, optional=relative in {"coverage.json", "recovery.json"}, version=version)
        if contents is not None:
            document = parse_report(contents, "previous " + relative, max_bytes=maximum)
            if relative == "recovery.json":
                from scripts.skillspector_recovery import validate_state
                validate_state(document)
            coverage.write_bounded(output_dir / relative, document, maximum)

    # This process only copies static JSON; scanner subprocesses are in separate serial jobs.
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(download, files))
    coverage.read_bundle(output_dir)
    return head


def validate_directory(directory, source_commit):
    require(coverage.SHA.fullmatch(source_commit) is not None, "invalid source commit")
    require(directory.is_dir() and not directory.is_symlink(), "report directory must be regular")
    bundle = coverage.read_bundle(directory)
    require(bundle is not None, "report manifest is missing")
    require(bundle["manifest"]["schema_version"] == 3, "only v3 bundles can be published here")
    coverage.validate_manifest(bundle["manifest"], current_policy=True)
    require(bundle["manifest"]["source_commit"] == source_commit, "coverage was produced from another source commit")
    require(not scanner.has_public_credentials(bundle),
            "coverage contains unredacted credential-shaped report text")
    allowed = set(CONTROL_FILES) | {part["path"] for part in bundle["manifest"]["shards"]}
    present = set()
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "coverage artifacts cannot contain symlinks")
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            require(relative in allowed, "coverage artifact contains an unexpected file")
            present.add(relative)
    require({"index.json", "selection.json", "attempts.json"} <= present, "coverage controls are missing")
    if "coverage.json" in present:
        summary = read_json(directory / "coverage.json", max_bytes=coverage.MAX_DISCOVERY_BYTES)
        coverage.validate_discovery_summary(summary, bundle["selection"], source_commit)
    if "recovery.json" in present:
        from scripts.skillspector_recovery import read_state
        read_state(directory / "recovery.json")
    return bundle


def durable_receipt(directory, source_commit):
    """Only an authenticated, uploaded current run acknowledgement permits defer."""
    from scripts.skillspector_recovery import read_state
    try:
        state = read_state(directory / "recovery.json")
    except (PublicationError, OSError, ValueError, KeyError, TypeError, RecursionError):
        return False
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    return bool(run_id.isdecimal() and attempt.isdecimal() and any(
        row["run_id"] == int(run_id) and row["run_attempt"] == int(attempt) and
        row["head_sha"] == source_commit and row["artifacts"] for row in state["runs"]))


def delivery_status(status, source_commit, *, path=None, report_commit=None):
    value = {"schema_version": 1, "status": status, "source_commit": source_commit,
             "report_commit": report_commit}
    if path is not None:
        coverage.write_bounded(path, value, 4096)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(f"\nSkillSpector delivery: **{status}**. Source `{source_commit}`.\n")
    print(canonical_json(value).decode())


def publish(github, directory, source_commit, *, fetch=raw_file):
    bundle = validate_directory(directory, source_commit)
    require((bundle.get("discovery") or {}).get("catalog", {}).get("mode") != "controlled_immutable_regression",
            "controlled regression reports are artifacts and cannot replace catalog publication")
    manifest = bundle["manifest"]
    main = github.request("GET", "git/ref/heads/main")
    require(main is not None, "main ref is unavailable during coverage publication")
    if main["object"]["sha"] != source_commit:
        raise SupersededCoverage("refusing coverage from obsolete main")
    ref = github.request("GET", f"git/ref/heads/{BRANCH}")
    head = ref["object"]["sha"] if ref else None
    require(head is None or coverage.SHA.fullmatch(head) is not None, "invalid report branch head")
    prior_manifest, old_entries, old_trees = None, {}, {}
    duplicate_publication = False
    if head:
        prior_body = fetch(head, "index.json", coverage.MAX_MANIFEST_BYTES, optional=True)
        if prior_body is not None:
            prior_manifest = parse_report(prior_body, "previous manifest", max_bytes=coverage.MAX_MANIFEST_BYTES)
            coverage.validate_manifest(prior_manifest)
            current_at = parse_timestamp(manifest["generated_at"], "generated_at")
            previous_at = parse_timestamp(prior_manifest["generated_at"], "previous generated_at")
            if current_at == previous_at:
                # A re-run of an already published artifact is idempotent.
                # Identical timestamps with different contents remain an error.
                require(manifest == prior_manifest, "conflicting report with identical timestamp")
                duplicate_publication = True
            if current_at < previous_at:
                raise SupersededCoverage("newer coverage is already published")
        tree = github.request("GET", f"git/trees/{head}?recursive=1")
        require(tree is not None and tree.get("truncated") is False, "report tree is unavailable or truncated")
        for item in tree["tree"]:
            if item["type"] == "blob":
                require(item["mode"] == "100644", "report branch contains executable data")
                old_entries[item["path"]] = item["sha"]
            elif item["type"] == "tree":
                old_trees[item["path"]] = item["sha"]
    if duplicate_publication:
        # Matching metadata is insufficient: the existing immutable tree must
        # contain the exact bytes of every validated local artifact, including
        # optional coverage.json when discovery metadata was generated.
        files = [name for name in CONTROL_FILES if (directory / name).is_file()]
        files.extend(part["path"] for part in manifest["shards"])
        for relative in files:
            body = read_bytes_bounded(directory / relative,
                                      CONTROL_FILES.get(relative, coverage.MAX_SHARD_BYTES))
            blob_sha = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
            require(old_entries.get(PREFIX + relative) == blob_sha,
                    "identical report publication file differs")
        return head
    entries = {}
    # Keep every supported v1/v2 control and content-addressed shard byte exact.
    # Older clients can continue using the last complete legacy publication.
    for path, sha in old_entries.items():
        relative = path.removeprefix(v2.PREFIX)
        if path == LEGACY_PATH or (path.startswith(v2.PREFIX) and
                (relative in v2.CONTROL_FILES or coverage.SHARD_PATH.fullmatch(relative))):
            entries[path] = sha
    if prior_manifest:
        for descriptor in prior_manifest["shards"]:
            path = PREFIX + descriptor["path"]
            require(path in old_entries, "previous manifest references missing shard")
            entries[path] = old_entries[path]
    files = [name for name in CONTROL_FILES if (directory / name).is_file()]
    files.extend(part["path"] for part in manifest["shards"])
    pending, pending_hashes = [], {}
    pending_bytes = len(canonical_json({"tree": []}))

    def flush():
        nonlocal pending_bytes
        if not pending:
            return
        # Tree inline content creates many UTF-8 JSON blobs in one bounded API write.
        # Flat temporary names make the response's blob identities directly verifiable.
        staged = github.request("POST", "git/trees", {"tree": pending})
        require(staged is not None and staged.get("truncated") is False, "staged upload tree is incomplete")
        actual = {entry["path"]: entry["sha"] for entry in staged["tree"]}
        require(actual == pending_hashes, "uploaded blob identity differs")
        pending.clear()
        pending_hashes.clear()
        pending_bytes = len(canonical_json({"tree": []}))

    for relative in files:
        maximum = CONTROL_FILES.get(relative, coverage.MAX_SHARD_BYTES)
        body = read_bytes_bounded(directory / relative, maximum)
        # Git's object identity lets unchanged content-addressed shards retain their blobs.
        blob_sha = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
        path = PREFIX + relative
        if old_entries.get(path) != blob_sha:
            entry = {"path": f"blob{len(pending):05d}", "mode": "100644", "type": "blob", "content": body.decode("utf-8")}
            entry_bytes = len(canonical_json(entry))
            if pending and (len(pending) >= MAX_TREE_ENTRIES or
                            pending_bytes + entry_bytes + 1 > MAX_TREE_UPLOAD_BYTES):
                flush()
                entry["path"] = "blob00000"
            if pending_bytes + entry_bytes + 1 > MAX_TREE_UPLOAD_BYTES:
                # Only unusually large controls/shards take a standalone blob write.
                blob = github.request("POST", "git/blobs", {"content": base64.b64encode(body).decode(), "encoding": "base64"})
                require(blob is not None and blob.get("sha") == blob_sha, "uploaded blob identity differs")
            else:
                pending.append(entry)
                pending_hashes[entry["path"]] = blob_sha
                pending_bytes += entry_bytes + 1
        entries[path] = blob_sha
    flush()
    # Only filtered files survive; incremental bases are fresh verified prefixes,
    # never the unfiltered tree of the previous report branch.
    tree = create_filtered_tree(github, entries, known_trees=old_trees)
    commit = github.request("POST", "git/commits", {"message": f"chore(skillspector): publish automatic static coverage {manifest['generated_at']}",
        "tree": tree["sha"], "parents": [head] if head else [],
        "author": {"name": "777genius", "email": "13103045+777genius@users.noreply.github.com",
                   "date": manifest["generated_at"]}})
    # Check again after uploading blobs, before the single pointer update.
    main = github.request("GET", "git/ref/heads/main")
    require(main is not None, "main ref is unavailable during coverage publication")
    if main["object"]["sha"] != source_commit:
        raise SupersededCoverage("main changed during coverage publication")
    if head:
        github.request("PATCH", f"git/refs/heads/{BRANCH}", {"sha": commit["sha"], "force": False})
    else:
        github.request("POST", "git/refs", {"ref": f"refs/heads/{BRANCH}", "sha": commit["sha"]})
    return commit["sha"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("previous")
    download.add_argument("--output-dir", type=Path, required=True)
    for name in ("check", "publish"):
        operation = commands.add_parser(name)
        operation.add_argument("--report-dir", type=Path, required=True)
        operation.add_argument("--source-commit", required=True)
        operation.add_argument("--status-file", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "previous":
            previous(GitHub(os.environ.get("GITHUB_TOKEN", "")), args.output_dir)
        elif args.command == "check":
            validate_directory(args.report_dir, args.source_commit)
        else:
            token = os.environ.get("GITHUB_TOKEN", "")
            require(bool(token), "publication token is missing")
            commit = publish(GitHub(token), args.report_dir, args.source_commit)
            delivery_status("published", args.source_commit, path=args.status_file, report_commit=commit)
        return 0
    except SupersededCoverage as error:
        recoverable = durable_receipt(args.report_dir, args.source_commit)
        delivery_status("superseded_with_durable_recovery" if recoverable else "superseded_without_recovery",
                        args.source_commit, path=args.status_file)
        print(f"SkillSpector coverage superseded: {error}; previous publication retained", file=sys.stderr)
        return 0 if recoverable else 3
    except (PublicationError, OSError, ValueError, KeyError, TypeError, RecursionError, urllib.error.URLError) as error:
        if args.command == "publish":
            delivery_status("failed_with_durable_recovery" if durable_receipt(args.report_dir, args.source_commit) else "failed",
                            args.source_commit, path=args.status_file)
        print(f"SkillSpector coverage publication failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
