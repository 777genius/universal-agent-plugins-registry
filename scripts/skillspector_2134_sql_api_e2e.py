#!/usr/bin/env python3
"""Fail-closed, immutable no-LLM comparison of a documented SQL API lookup.

This is a read-only maintenance qualification, not a report publisher.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from scripts.skillspector_2134_json_version_e2e import run, scan_tree
from scripts.skillspector_2134_metadata_e2e import security

SOURCE_COMMIT = "4d7d8e075e1b0d899965496bacf2811be5d94091"
SOURCE_ROOT = "plugins/cloudflare/skills/durable-objects"
SOURCE_BLOB = "b595f1c2182f3b7d6f944d7ba0ac59667fba78aa"
BASE = "1f563af2e4f10e28145792d6549bcff564cd8a00"
CANDIDATE = "d80ef6f73cd89df1625bb99cc008b196a1a1b716"
TARGET_LINE = "Search: `blockConcurrencyWhile`, `idFromName`, `getByName`, `setAlarm`, `sql.exec`"


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=15
    ).strip()


def identity(ref: dict) -> str:
    if not isinstance(ref, dict):
        raise ValueError("non-object reference evidence")
    return json.dumps(ref, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def target(ref: dict) -> bool:
    return (
        ref.get("source_path") == "SKILL.md"
        and ref.get("line") == 38
        and ref.get("reference_kind") == "quoted_or_code"
        and ref.get("status") == "missing"
        and ref.get("target_path") is None
        and ref.get("evidence") == TARGET_LINE
    )


def compare(old: dict, new: dict) -> dict:
    a = old.get("analysis_completeness")
    b = new.get("analysis_completeness")
    if not isinstance(a, dict) or not isinstance(b, dict):
        raise ValueError("missing analysis coverage evidence")
    old_refs, new_refs = a.get("references"), b.get("references")
    if not isinstance(old_refs, list) or not isinstance(new_refs, list):
        raise ValueError("missing reference ledger")
    known = [row for row in old_refs if target(row)]
    deleted = collections.Counter(map(identity, old_refs)) - collections.Counter(map(identity, new_refs))
    added = collections.Counter(map(identity, new_refs)) - collections.Counter(map(identity, old_refs))
    if len(known) != 1 or deleted != collections.Counter([identity(known[0])]) or added:
        raise ValueError("exact one-row documented SQL lookup difference is not proved")
    if security(old) != security(new):
        raise ValueError("independent security findings are not preserved")
    # The source also has static_parse_limit/analyzer_incomplete. Removing one
    # false missing-reference row must not certify the remaining limitations.
    if (
        a.get("status") != "partial" or a.get("is_complete") is not False
        or b.get("status") != "partial" or b.get("is_complete") is not False
        or any(b.get(field) != a.get(field) for field in
               ("partially_inspected_files", "entirely_uninspected_files"))
    ):
        raise ValueError("unexpected Partial/Complete promotion or inspection change")
    return {
        "baseline_status": a["status"], "candidate_status": b["status"],
        "false_sql_reference_removed": 1,
        "other_references_unchanged": True,
        "independent_candidate_security_findings_unchanged": True,
        "original_published_v3_security_parity": "requires_signed_group_and_occurrence_checks",
        "prior_published_partial_remains_uncertified": True,
        "production_partial_reduction": 0, "production_error_reduction": 0,
        "safe_for_automatic_publication": False,
    }


PUBLISHED_REF = "7771404dcdfc5b3855f1319b5e9a2bc19d0c7acf"
PUBLISHED_SHARD = (
    "reports/skillspector/v3/shards/"
    "32d0ccd64b2cea5366d73bc9856ffd628c92af340e5e90d0d0f55c9b1bd7dd02.json"
)
PUBLISHED_DIGEST = "32d0ccd64b2cea5366d73bc9856ffd628c92af340e5e90d0d0f55c9b1bd7dd02"
PUBLISHED_RECORD_ID = "plugin:777genius/cloudflare-bridge/durable-objects"
PUBLISHED_SOURCE_DIGEST = "sha256:62934e1b8e470a7e2588aaafc7d3bc07251b313f4ef6c5948f47f962119fcc80"


def published_source_risks(original: dict, candidate: dict) -> dict:
    """Reject loss of any independently attested, untruncated signed finding.

    Raw scanner issues and v3 grouped findings have different wrappers; compare
    exact source line, risk rule, severity, and stable match fingerprint, with
    multiplicity. Never treat identical generated finding IDs as security proof.
    """
    if (
        original.get("id") != PUBLISHED_RECORD_ID
        or original.get("status") != "partial"
        or original.get("freshness") != "current"
        or original.get("findings_truncated") is not False
        or original.get("coverage", {}).get("grouping_complete") is not True
        or original.get("source", {}).get("revision") != SOURCE_COMMIT
        or original.get("source", {}).get("path") != SOURCE_ROOT
        or original.get("source", {}).get("content_digest") != PUBLISHED_SOURCE_DIGEST
    ):
        raise ValueError("original published v3 source identity/status cannot be authenticated")
    groups = original.get("findings")
    issues = candidate.get("issues")
    if not isinstance(groups, list) or not isinstance(issues, list):
        raise ValueError("missing signed finding groups or candidate raw issues")
    required = collections.Counter()
    for item in groups:
        if not isinstance(item, dict) or type(item.get("raw_count")) is not int or item["raw_count"] < 1:
            raise ValueError("malformed signed risk finding")
        fingerprint = item.get("match_fingerprint")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise ValueError("invalid signed risk fingerprint")
        required[(item.get("rule"), item.get("severity"),
                  item.get("path"), item.get("line"), fingerprint)] += item["raw_count"]
    actual = collections.Counter()
    for item in issues:
        if not isinstance(item, dict):
            raise ValueError("malformed candidate issue")
        if item.get("id") in {"AE1", "AE7"} and item.get("tags") == ["coverage"]:
            continue
        location = item.get("location")
        if not isinstance(location, dict):
            raise ValueError("candidate issue has no source location")
        fingerprint = item.get("match_fingerprint")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise ValueError("candidate lost issue fingerprint")
        actual[(item.get("id"), item.get("severity"),
                location.get("file"), location.get("start_line"), fingerprint)] += 1
    if required - actual:
        raise ValueError("candidate lost a source-bound original signed security finding")
    raw = original.get("raw_finding_count")
    if type(raw) is not int or raw < sum(required.values()):
        raise ValueError("signed original raw findings are inconsistent")
    return {
        "published_signed_risk_groups_preserved": len(groups),
        "published_signed_grouped_occurrences_preserved": sum(required.values()),
        "published_raw_finding_count": raw,
        "published_unattributed_raw_count": raw - sum(required.values()),
        "published_original_remains_partial": True,
    }


def load_published(path: Path) -> dict:
    if git_head(path) != PUBLISHED_REF:
        raise ValueError("published signed report checkout is not pinned")
    raw = (path / PUBLISHED_SHARD).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PUBLISHED_DIGEST:
        raise ValueError("published signed source shard SHA-256 changed")
    shard = json.loads(raw)
    if shard.get("repository") != "777genius/universal-agent-plugins-registry":
        raise ValueError("published report shard has wrong repository")
    matches = [r for r in shard.get("records", []) if r.get("id") == PUBLISHED_RECORD_ID]
    if len(matches) != 1:
        raise ValueError("published source identity missing or ambiguous")
    return matches[0]



def main() -> int:
    ap = argparse.ArgumentParser()
    for name in ("baseline", "candidate", "source", "published", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    for path, expected in ((args.baseline, BASE), (args.candidate, CANDIDATE),
                           (args.source, SOURCE_COMMIT)):
        if git_head(path) != expected:
            raise ValueError("immutable source or scanner Git HEAD drift")
    skill = args.source / SOURCE_ROOT
    raw = (skill / "SKILL.md").read_bytes()
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if digest != SOURCE_BLOB or TARGET_LINE not in raw.decode("utf-8").splitlines():
        raise ValueError("exact pinned source SKILL.md content differs")
    snapshot = scan_tree(skill)
    old_exit, old = run(args.baseline / ".venv/bin/skillspector", skill, allow_risk_exit=True)
    if scan_tree(skill) != snapshot:
        raise ValueError("baseline scanner modified immutable source")
    new_exit, new = run(args.candidate / ".venv/bin/skillspector", skill, allow_risk_exit=True)
    if scan_tree(skill) != snapshot:
        raise ValueError("candidate scanner modified immutable source")
    proof = {
        "kind": "skillspector-sql-api-source-readonly-v1",
        "source_repository": "777genius/universal-agent-plugins-registry",
        "source_commit": SOURCE_COMMIT,
        "source_root": SOURCE_ROOT,
        "source_skill_git_blob": SOURCE_BLOB,
        "full_acquired_tree_digest": snapshot,
        "baseline_scanner_commit": BASE, "candidate_scanner_commit": CANDIDATE,
        "baseline_exit": old_exit, "candidate_exit": new_exit,
        **compare(old, new),
        **published_source_risks(load_published(args.published), new),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Fail-closed SQL API source qualification: {error}", file=sys.stderr)
        sys.exit(1)
