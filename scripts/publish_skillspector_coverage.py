#!/usr/bin/env python3
"""Validate and atomically publish display-only SkillSpector v2 coverage."""
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
from scripts import skillspector_coverage as coverage
from scripts.directory_publication import (PublicationError, canonical_json, parse_json_bytes,
    parse_timestamp, read_bytes_bounded, read_json, require, sha256_digest)

REPOSITORY = v1.REPOSITORY
BRANCH = v1.BRANCH
PREFIX = "reports/skillspector/v2/"
MANIFEST_PATH = PREFIX + "index.json"
LEGACY_PATH = v1.REPORT_PATH
MAX_API_BYTES = 32 << 20
MAX_TREE_UPLOAD_BYTES = 8 << 20
CONTROL_FILES = {"index.json": coverage.MAX_MANIFEST_BYTES,
    "selection.json": coverage.MAX_SELECTION_BYTES, "attempts.json": coverage.MAX_STATE_BYTES,
    "coverage.json": coverage.MAX_DISCOVERY_BYTES}


class GitHub:
    def __init__(self, token=""):
        self.token = token

    def request(self, method, path, data=None):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "uap-skillspector-coverage"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        body = None if data is None else canonical_json(data)
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/{path}",
            data=body, headers=headers, method=method)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    payload = response.read(MAX_API_BYTES + 1)
                break
            except urllib.error.HTTPError as error:
                if error.code == 404 and method == "GET":
                    return None
                diagnostic = error.read(8192).lower()
                retry = error.code == 429 or error.code == 403 and (
                    error.headers.get("Retry-After") is not None or b"secondary rate limit" in diagnostic)
                if retry and attempt < 3:
                    raw_delay = error.headers.get("Retry-After", "60")
                    require(raw_delay.isdigit() and int(raw_delay) <= 60,
                            "GitHub pacing exceeds this publication budget; prior report retained")
                    time.sleep(max(1, int(raw_delay)))
                    continue
                raise PublicationError(f"GitHub coverage request failed (HTTP {error.code})") from None
        require(len(payload) <= MAX_API_BYTES, "GitHub response exceeds limit")
        return parse_json_bytes(payload, "GitHub coverage response", max_bytes=MAX_API_BYTES)


def raw_file(commit, relative, maximum, *, optional=False):
    require(coverage.SHA.fullmatch(commit) is not None, "invalid report branch commit")
    require(relative in CONTROL_FILES or coverage.SHARD_PATH.fullmatch(relative) is not None,
            "unsupported report path")
    # Public immutable URLs avoid API quotas and deliberately receive no credentials.
    request = urllib.request.Request(
        f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{PREFIX}{relative}",
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
    if body is None:
        return None
    manifest = parse_json_bytes(body, "previous manifest", max_bytes=coverage.MAX_MANIFEST_BYTES)
    coverage.validate_manifest(manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    coverage.write_bounded(output_dir / "index.json", manifest, coverage.MAX_MANIFEST_BYTES)
    files = [(name, maximum) for name, maximum in CONTROL_FILES.items() if name != "index.json"]
    files.extend((part["path"], part["bytes"]) for part in manifest["shards"])

    def download(item):
        relative, maximum = item
        contents = fetch(head, relative, maximum, optional=relative == "coverage.json")
        if contents is not None:
            document = parse_json_bytes(contents, "previous " + relative, max_bytes=maximum)
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
    require(bundle["manifest"]["source_commit"] == source_commit, "coverage was produced from another source commit")
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
    return bundle


def publish(github, directory, source_commit, *, fetch=raw_file):
    bundle = validate_directory(directory, source_commit)
    manifest = bundle["manifest"]
    main = github.request("GET", "git/ref/heads/main")
    require(main is not None and main["object"]["sha"] == source_commit, "refusing coverage from obsolete main")
    ref = github.request("GET", f"git/ref/heads/{BRANCH}")
    head = ref["object"]["sha"] if ref else None
    require(head is None or coverage.SHA.fullmatch(head) is not None, "invalid report branch head")
    prior_manifest, old_entries = None, {}
    if head:
        prior_body = fetch(head, "index.json", coverage.MAX_MANIFEST_BYTES, optional=True)
        if prior_body is not None:
            prior_manifest = parse_json_bytes(prior_body, "previous manifest", max_bytes=coverage.MAX_MANIFEST_BYTES)
            coverage.validate_manifest(prior_manifest)
            require(parse_timestamp(manifest["generated_at"], "generated_at") >
                    parse_timestamp(prior_manifest["generated_at"], "previous generated_at"), "refusing stale coverage")
        tree = github.request("GET", f"git/trees/{head}?recursive=1")
        require(tree is not None and tree.get("truncated") is False, "report tree is unavailable or truncated")
        for item in tree["tree"]:
            if item["type"] == "blob":
                require(item["mode"] == "100644", "report branch contains executable data")
                old_entries[item["path"]] = item["sha"]
    entries = {}
    if LEGACY_PATH in old_entries:
        # The old frontend keeps its exact v1 bytes throughout the v2 rollout.
        entries[LEGACY_PATH] = old_entries[LEGACY_PATH]
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
            if pending and pending_bytes + entry_bytes + 1 > MAX_TREE_UPLOAD_BYTES:
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
    # No base_tree: only literal controls, immutable current/previous shards, and legacy JSON survive.
    tree = github.request("POST", "git/trees", {"tree": [
        {"path": path, "mode": "100644", "type": "blob", "sha": sha} for path, sha in sorted(entries.items())]})
    commit = github.request("POST", "git/commits", {"message": f"chore(skillspector): publish automatic static coverage {manifest['generated_at']}",
        "tree": tree["sha"], "parents": [head] if head else []})
    # Check again after uploading blobs, before the single pointer update.
    main = github.request("GET", "git/ref/heads/main")
    require(main is not None and main["object"]["sha"] == source_commit, "main changed during coverage publication")
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
    args = parser.parse_args()
    try:
        if args.command == "previous":
            previous(GitHub(os.environ.get("GITHUB_TOKEN", "")), args.output_dir)
        elif args.command == "check":
            validate_directory(args.report_dir, args.source_commit)
        else:
            token = os.environ.get("GITHUB_TOKEN", "")
            require(bool(token), "publication token is missing")
            print(publish(GitHub(token), args.report_dir, args.source_commit))
        return 0
    except (PublicationError, OSError, ValueError, KeyError, TypeError, RecursionError, urllib.error.URLError) as error:
        print(f"SkillSpector coverage publication failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
