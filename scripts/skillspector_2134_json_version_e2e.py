#!/usr/bin/env python3
"""Exact immutable real-CLI comparison for SkillSpector JSON VERSION semantics.

Read-only qualification, not a report publisher or automatic Complete promotion.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_REPORT = 8 << 20
SOURCE_COMMIT = "7de1ef7cc831f62d205dfa589063f3831f66391b"
SOURCE_SKILL_BLOB = "121e813665d7fe7512e4a59ad0c341b92d8d124c"
BASE_SCANNER = "54824463814a0be01360792523ec7245a69190fc"
CANDIDATE = "4951c8c39bb667d722bc8889bfe966872767341b"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def scan_tree(root: Path) -> str:
    """Hash every pinned input byte before and after both analyzer processes."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError("invalid pinned Skill root")
    hashes = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in immutable canary source")
        if not path.is_file():
            continue
        data = path.read_bytes()
        total += len(data)
        if total > 16 << 20 or len(hashes) >= 2048:
            raise ValueError("source inventory exceeds canary bounds")
        hashes.append((path.relative_to(root).as_posix(), digest(data)))
    if not hashes or not (root / "SKILL.md").is_file():
        raise ValueError("empty source or missing SKILL.md")
    return digest(json.dumps(hashes, separators=(",", ":"), ensure_ascii=False).encode())


def run(scanner: Path, skill: Path) -> tuple[int, dict]:
    with tempfile.TemporaryDirectory(prefix="uap-json-version-e2e-") as home:
        env = {"HOME": home, "PATH": os.defpath, "LANG": "C.UTF-8",
               "PYTHONNOUSERSITE": "1", "LANGCHAIN_TRACING_V2": "false",
               "LANGSMITH_TRACING": "false", "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "120",
               "SKILLSPECTOR_OSV_TIMEOUT": "3"}
        completed = subprocess.run(
            [str(scanner.resolve()), "scan", str(skill.resolve()), "--no-llm", "--format",
             "json", "--fail-on-incomplete"],
            cwd=home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=180,
        )
    if completed.returncode not in (0, 1) or not (0 < len(completed.stdout) <= MAX_REPORT) or        len(completed.stderr) > MAX_REPORT:
        raise ValueError("scanner process or report did not finish in bounds")
    result = json.loads(completed.stdout)
    if not isinstance(result, dict) or result.get("suppressed_count") != 0 or result.get("suppressed") != []:
        raise ValueError("scanner suppressed content evidence")
    metadata = result.get("metadata") or {}
    if (metadata.get("skillspector_version") != "2.13.4" or
        metadata.get("llm_requested") is not False or metadata.get("inference_usage") != [] or
        result.get("execution_successful") is not True):
        raise ValueError("scanner provenance or execution differs")
    coverage = result.get("analysis_completeness")
    if not isinstance(coverage, dict):
        raise ValueError("missing scanner coverage result")
    status = coverage.get("status")
    is_complete = coverage.get("is_complete")
    if (status == "partial" and (is_complete is not False or completed.returncode != 1)
        or status in {"complete", "complete_with_caveats"}
        and (is_complete is not True or completed.returncode != 0)
        or status not in {"partial", "complete", "complete_with_caveats"}):
        raise ValueError("inconsistent no-LLM coverage status and CLI exit")
    return completed.returncode, result


def ref_identity(ref: dict) -> str:
    return json.dumps(ref, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def version_row(row: dict) -> bool:
    return (row.get("source_path") == "SKILL.md" and row.get("line") == 153 and
            row.get("status") == "missing" and row.get("reference_kind") == "quoted_or_code" and
            '"VERSION": "1.0.0"' in row.get("evidence", ""))


def content_findings(report: dict) -> collections.Counter:
    if not isinstance(report.get("issues"), list) or not all(
        isinstance(issue, dict) for issue in report["issues"]
    ):
        raise ValueError("invalid security issue evidence")
    def coverage_only(issue):
        tags = issue.get("tags", [])
        # Never exempt a finding that also carries independent security evidence.
        # Exempt only pure coverage tags; mixed content/policy/security tags
        # are independent findings that must survive the candidate scan.
        return (issue.get("id") in {"AE1", "AE7"} and isinstance(tags, list)
                and tags == ["coverage"])
    return collections.Counter(
        json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for item in report.get("issues", [])
        if isinstance(item, dict) and not coverage_only(item)
    )


def assert_delta(old: dict, new: dict) -> dict:
    old_refs = old["analysis_completeness"]["references"]
    new_refs = new["analysis_completeness"]["references"]
    if (not isinstance(old_refs, list) or not isinstance(new_refs, list)
        or not all(isinstance(row, dict) for row in old_refs + new_refs)):
        raise ValueError("missing or malformed reference evidence")
    old_versions = [x for x in old_refs if version_row(x)]
    new_versions = [x for x in new_refs if version_row(x)]
    old_keys = collections.Counter(ref_identity(x) for x in old_refs)
    new_keys = collections.Counter(ref_identity(x) for x in new_refs)
    deleted = old_keys - new_keys
    added = new_keys - old_keys
    if (len(old_versions) != 1 or new_versions or
        deleted != collections.Counter({ref_identity(old_versions[0]): 1}) or added):
        raise ValueError("candidate removed another reference or retained fake VERSION dependency")
    if (not isinstance(old.get("issues"), list) or not isinstance(new.get("issues"), list) or
        content_findings(old) != content_findings(new)):
        raise ValueError("non-coverage security findings changed")
    if new.get("analysis_completeness", {}).get("partially_inspected_files", 0) >        old.get("analysis_completeness", {}).get("partially_inspected_files", 0):
        raise ValueError("candidate increased uninspected-file count")
    # A missing interpreter operand can never be "complete_with_caveats".
    remaining_executables = [
        row for row in new_refs
        if row.get("status") == "missing"
        and row.get("reference_kind") == "inline_command"
    ]
    if remaining_executables:
        coverage = new["analysis_completeness"]
        ledger = coverage.get("ledger_exceptions")
        if (coverage.get("status") != "partial"
            or coverage.get("is_complete") is not False
            or not isinstance(ledger, list)
            or not any(isinstance(row, dict)
                       and row.get("reason_code") == "referenced_uninspected"
                       for row in ledger)):
            raise ValueError("candidate falsely considers missing executable covered")
    return {"fake_version_rows_removed": len(old_versions), "new_reference_rows": len(new_refs),
            "retained_reference_rows": len(old_refs) - len(old_versions),
            "noncoverage_finding_groups_unchanged": True,
            "remaining_missing_executable_rows": len(remaining_executables),
            "baseline_completeness": old["analysis_completeness"]["status"],
            "candidate_completeness": new["analysis_completeness"]["status"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline_root = args.baseline.resolve(strict=True)
    candidate_root = args.candidate.resolve(strict=True)
    source = args.source.resolve(strict=True)
    for root, expected in ((baseline_root, BASE_SCANNER), (candidate_root, CANDIDATE)):
        actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        if actual != expected:
            raise ValueError("scanner checkout differs from pinned commit")
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() != SOURCE_COMMIT:
        raise ValueError("upstream real Skill commit changed")
    skill = source / "skills/asc-workflow"
    raw = (skill / "SKILL.md").read_bytes()
    git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if git_blob != SOURCE_SKILL_BLOB:
        raise ValueError("immutable real SKILL.md blob differs")
    before = scan_tree(skill)
    old_code, old = run(baseline_root / ".venv/bin/skillspector", skill)
    if scan_tree(skill) != before:
        raise ValueError("baseline scanner mutated source")
    new_code, new = run(candidate_root / ".venv/bin/skillspector", skill)
    if scan_tree(skill) != before:
        raise ValueError("candidate scanner mutated source")
    difference = assert_delta(old, new)
    proof = {"kind": "skillspector-json-version-v2134-readonly",
             "source_commit": SOURCE_COMMIT, "source_tree_digest": before,
             "base_scanner": BASE_SCANNER, "candidate_scanner": CANDIDATE,
             "baseline_exit": old_code, "candidate_exit": new_code,
             "safe_for_automatic_publication": False, **difference}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("Exact-source qualification failed closed: " + str(exc), file=sys.stderr)
        sys.exit(1)
