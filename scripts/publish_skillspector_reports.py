#!/usr/bin/env python3
"""Publish one validated, display-only report on its dedicated data branch."""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from scripts.directory_publication import (
    PublicationError, canonical_json, parse_json_bytes, parse_timestamp, read_json,
    require, sha256_digest, validate_with_schema,
)
from scripts.skillspector_reports import MAX_REPORT_BYTES, PROFILE, SCANNER, SCHEMA, load_selection

REPOSITORY = "777genius/universal-agent-plugins-registry"
BRANCH = "skillspector-reports"
REPORT_PATH = "reports/skillspector/v1/index.json"


class GitHub:
    def __init__(self, token: str = ""):
        self.token = token

    def request(self, method: str, path: str, data=None, *, raw=False):
        headers = {"Accept": "application/vnd.github.raw+json" if raw else "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "uap-skillspector-reports"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        body = None if data is None else canonical_json(data)
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/{path}",
                                         data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read(MAX_REPORT_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404 and method == "GET":
                return None
            raise PublicationError(f"GitHub report publication request failed (HTTP {error.code})") from None
        require(len(payload) <= MAX_REPORT_BYTES, "GitHub response exceeds report limit")
        return payload if raw else parse_json_bytes(payload, "GitHub response", max_bytes=MAX_REPORT_BYTES)


def previous_report(github: GitHub) -> tuple[str | None, bytes | None]:
    ref = github.request("GET", f"git/ref/heads/{BRANCH}")
    if ref is None:
        return None, None
    head = ref["object"]["sha"]
    require(isinstance(head, str) and re.fullmatch(r"[0-9a-f]{40}", head), "invalid report branch head")
    body = github.request("GET", f"contents/{REPORT_PATH}?ref={head}", raw=True)
    require(body is not None, "report branch has no expected report")
    return head, body


def validate_report(path: Path, selection_path: Path, source_commit: str) -> dict:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_commit)), "invalid source commit")
    require(path.is_file() and not path.is_symlink(), "report must be a regular file")
    report = read_json(path, max_bytes=MAX_REPORT_BYTES)
    validate_with_schema(report, SCHEMA)
    require(report["source_commit"] == source_commit, "report was produced from another source commit")
    require(report["scanner"] == SCANNER and report["profile"] == PROFILE, "unsupported static scan profile")
    selection = load_selection(selection_path)
    require(report["selection_digest"] == sha256_digest(canonical_json(selection)), "report selection differs")
    expected = {item["id"]: item for item in selection["sources"]}
    require(len(report["records"]) == len(expected), "report must include every selected source")
    seen = set()
    generated = parse_timestamp(report["generated_at"], "generated_at")
    require(generated <= datetime.now(timezone.utc), "report is from the future")
    for record in report["records"]:
        item = expected.get(record["id"])
        require(item is not None and record["id"] not in seen, "unknown or repeated report subject")
        seen.add(record["id"])
        require(all(record["source"][key] == item[key] for key in ("repository", "revision", "path")),
                "report subject differs from selected immutable source")
        require(all(record[key] == item[key] for key in ("kind", "plugin_path")), "report subject kind differs")
        if record["scanned_at"] is not None:
            require(parse_timestamp(record["scanned_at"], "scanned_at") <= generated, "scan is newer than report")
        require(record["status"] != "complete" or not record["errors"], "complete report has errors")
        require(record["finding_count"] >= len(record["findings"]), "invalid finding count")
        require(record["findings_truncated"] == (record["finding_count"] > len(record["findings"])),
                "invalid findings truncation flag")
    return report


def publish(github: GitHub, report: dict) -> str:
    main = github.request("GET", "git/ref/heads/main")
    require(main is not None and main["object"]["sha"] == report["source_commit"],
            "refusing report from an obsolete main commit")
    head, previous = previous_report(github)
    if previous is not None:
        old = parse_json_bytes(previous, "previous report", max_bytes=MAX_REPORT_BYTES)
        require(parse_timestamp(report["generated_at"], "generated_at") >
                parse_timestamp(old["generated_at"], "previous generated_at"), "refusing stale report publication")
    body = canonical_json(report)
    # No base tree: the data branch contains exactly this one non-executable file.
    blob = github.request("POST", "git/blobs", {"content": base64.b64encode(body).decode(), "encoding": "base64"})
    tree = github.request("POST", "git/trees", {"tree": [
        {"path": REPORT_PATH, "mode": "100644", "type": "blob", "sha": blob["sha"]}]})
    commit = github.request("POST", "git/commits", {
        "message": f"chore(skillspector): publish static reports {report['generated_at']}",
        "tree": tree["sha"], "parents": [head] if head else []})
    if head:
        # Non-fast-forward updates fail if another writer won the race.
        github.request("PATCH", f"git/refs/heads/{BRANCH}", {"sha": commit["sha"], "force": False})
    else:
        github.request("POST", "git/refs", {"ref": f"refs/heads/{BRANCH}", "sha": commit["sha"]})
    return commit["sha"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    previous = subcommands.add_parser("previous")
    previous.add_argument("--output", type=Path, required=True)
    for command in ("check", "publish"):
        operation = subcommands.add_parser(command)
        operation.add_argument("--report", type=Path, required=True)
        operation.add_argument("--selection", type=Path, default=Path("registry/skillspector-selection.json"))
        operation.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "previous":
            _, body = previous_report(GitHub())
            if body is not None:
                args.output.write_bytes(body)
        else:
            report = validate_report(args.report, args.selection, args.source_commit)
            if args.command == "publish":
                token = os.environ.get("GITHUB_TOKEN", "")
                require(bool(token), "publication token is missing")
                print(publish(GitHub(token), report))
        return 0
    except (PublicationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"SkillSpector publication failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
