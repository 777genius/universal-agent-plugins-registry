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
CANDIDATE = "d07df2d02cb8beca0805c4ec67983cd8e4e8e60c"
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
        "original_published_v3_security_parity": "not_yet_proved",
        "prior_published_partial_remains_uncertified": True,
        "production_partial_reduction": 0, "production_error_reduction": 0,
        "safe_for_automatic_publication": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    for name in ("baseline", "candidate", "source", "output"):
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
