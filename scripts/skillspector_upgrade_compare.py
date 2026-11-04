#!/usr/bin/env python3
"""Read-only, pinned SkillSpector 2.13.1 vs 2.13.3 coverage canary.

Never executes an input Skill or mutates the production scan/profile policy.
Both scanners see identical immutable fixtures, limits, and CLI arguments.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

REAL_SKILL_BLOB = "121e813665d7fe7512e4a59ad0c341b92d8d124c"
EXPECTED = {"old": "2.13.1", "new": "2.13.3"}
FIXTURES = {
    "complete_control": (
        "---\nname: clean-example\ndescription: Plain documentation with no local files.\n---\n"
        "Explain the result in ordinary language.\n"
    ),
    "true_missing_executable": (
        "---\nname: missing-script\ndescription: A missing executable must block Complete.\n---\n"
        "Run " + chr(96) + "python3 scripts/emit.py" + chr(96) + " to generate the report.\n"
    ),
    "json_version_literal": (
        "---\nname: version-example\ndescription: JSON version literal classification.\n---\n"
        "\"VERSION\": \"1.0.0\",\n"
    ),
    "typed_data_field": (
        "---\nname: field-example\ndescription: Typed data field documentation.\n---\n"
        "| Field | Type | Description |\n| --- | --- | --- |\n"
        "| " + chr(96) + "data.id" + chr(96) + " | uuid | Public record identifier. |\n"
    ),
}


def version(scanner: Path) -> str:
    done = subprocess.run([str(scanner), "--version"], capture_output=True, text=True,
                          timeout=20, check=True)
    return (done.stdout + done.stderr).strip()


def scan(scanner: Path, root: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="skillspector-canary-home-") as home:
        env = {
            "PATH": os.defpath,
            "HOME": home,
            "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "LANGCHAIN_TRACING_V2": "false",
            "LANGSMITH_TRACING": "false",
            "SKILLSPECTOR_OSV_TIMEOUT": "3",
            "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "55",
            "SKILLSPECTOR_MAX_STATIC_ANALYSIS_SECONDS_PER_ARTIFACT": "30",
        }
        done = subprocess.run(
            [str(scanner), "scan", str(root), "--no-llm", "--format", "json",
             "--fail-on-incomplete"],
            cwd=home, env=env, capture_output=True, timeout=120, check=False,
        )
    if done.returncode not in (0, 1) or not done.stdout:
        raise AssertionError(
            (root.name, done.returncode, done.stderr.decode(errors="replace")[-600:])
        )
    result = json.loads(done.stdout)
    coverage = result["analysis_completeness"]
    if result.get("execution_successful") is not True:
        raise AssertionError(("Scanner did not finish execution", root.name))
    # Public JSON reports expose issues, not the internal graph filtered_findings.
    issues = result["issues"]
    if not isinstance(issues, list) or any(not isinstance(issue, dict) for issue in issues):
        raise AssertionError(("Malformed public findings", root.name))
    # The actual CLI contract reports reasons in ledger_exceptions.reason_code,
    # not in a top-level `reasons` list. Do not silently emit an empty reason census.
    exceptions = coverage["ledger_exceptions"]
    if not isinstance(exceptions, list) or any(not isinstance(item, dict) for item in exceptions):
        raise AssertionError(("Malformed inspection ledger exceptions", root.name))
    reasons = Counter(item.get("reason_code", "unknown") for item in exceptions)
    missing = Counter(
        item.get("reference_kind", "unknown")
        for item in coverage.get("references", [])
        if item.get("status") == "missing"
    )
    return {
        "exit_code": done.returncode,
        "status": coverage["status"],
        "is_complete": coverage["is_complete"],
        "reason_counts": dict(sorted(reasons.items())),
        "missing_reference_kinds": dict(sorted(missing.items())),
        "missing_reference_count": sum(missing.values()),
        "finding_count": len(issues),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--real-skill", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    scanners = {"old": args.old.resolve(), "new": args.new.resolve()}
    versions = {name: version(scanner) for name, scanner in scanners.items()}
    for name, expected in EXPECTED.items():
        if not versions[name].endswith("v" + expected):
            raise AssertionError(("Unexpected pinned scanner release", name, versions[name]))

    source = args.real_skill.resolve() / "SKILL.md"
    if source.is_symlink() or not source.is_file():
        raise AssertionError("Real pinned skill manifest is not a regular file")
    body = source.read_bytes()
    oid = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
    if oid != REAL_SKILL_BLOB:
        raise AssertionError(("Real skill changed", oid))

    results = {}
    with tempfile.TemporaryDirectory(prefix="skillspector-upgrade-inputs-") as directory:
        inputs = Path(directory)
        for name, instructions in FIXTURES.items():
            root = inputs / name
            root.mkdir()
            (root / "SKILL.md").write_text(instructions, encoding="utf-8")
        for name, scanner in scanners.items():
            reports = {}
            for fixture in FIXTURES:
                reports[fixture] = scan(scanner, inputs / fixture)
            reports["real_asc_workflow"] = scan(scanner, source.parent)
            results[name] = reports

    for name, reports in results.items():
        complete = reports["complete_control"]
        missing = reports["true_missing_executable"]
        if complete["status"] != "complete" or not complete["is_complete"] or complete["exit_code"] != 0:
            raise AssertionError(("Clean control must be Complete", name, complete))
        if (missing["status"] != "partial" or missing["is_complete"]
                or missing["exit_code"] != 1 or "reference_missing" not in missing["reason_counts"]
                or missing["missing_reference_kinds"].get("inline_command", 0) < 1):
            raise AssertionError(("Real missing executable must stay Partial", name, missing))

    evidence = {
        "format": "uap.skillspector.release-comparison.v1",
        "immutable_real_skill_blob": oid,
        "scanner_versions": versions,
        "same_cli_args": ["--no-llm", "--format", "json", "--fail-on-incomplete"],
        "results": results,
        "production_policy_changed": False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
