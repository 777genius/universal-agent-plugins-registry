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
    "directory_uninspected": (
        "---\nname: docs-folder\ndescription: Directory presence is not full inspection.\n---\n"
        "Read [the acquired docs directory](./docs/) before acting.\n"
    ),
    "traversal_reference": (
        "---\nname: escaped-dependency\ndescription: Parent traversal cannot be inspected.\n---\n"
        "Run [the outside script](../outside-runner.sh) to produce the output.\n"
    ),
    "symlink_outside_root": (
        "---\nname: linked-dependency\ndescription: External symlink is not inspected.\n---\n"
        "Run [the linked script](./scripts/runner.sh) to produce the output.\n"
    ),
    "opaque_binary": (
        "---\nname: binary-document\ndescription: Binary input is not fully inspectable.\n---\n"
        "Read [the binary file](./data/payload.bin) as input.\n"
    ),
    "traversal_encoded_parent": (
        "---\nname: encoded-escape\ndescription: Check encoded external dependency.\n---\n"
        "Run [the outside script](%2e%2e/outside-runner.sh) to produce the output.\n"
    ),
    "traversal_inline_command": (
        "---\nname: inline-escape\ndescription: Check executable outside the bundle.\n---\n"
        "Run " + chr(96) + "python3 ../outside-runner.sh" + chr(96) + " to produce the output.\n"
    ),
    "traversal_drive_relative": (
        "---\nname: drive-relative\ndescription: Check local Windows drive dependency.\n---\n"
        "Run [the outside script](C:../outside-runner.sh) to produce the output.\n"
    ),
    "traversal_python_option": (
        "---\nname: option-escape\ndescription: Check interpreter option script dependency.\n---\n"
        "Run " + chr(96) + "python3 -u ../outside-runner.sh" + chr(96)
        + " to produce the output.\n"
    ),
    "traversal_windows_drive": (
        "---\nname: drive-escape\ndescription: Check explicit Windows drive reference.\n---\n"
        "Run [the outside script](C:/outside-runner.sh) to produce the output.\n"
    ),
    "file_uri_outside_root": (
        "---\nname: local-file-uri\ndescription: Local file URI cannot be inspected.\n---\n"
        "Run [the outside script]({outside_uri}) to produce the report.\n"
        "Read [the instructions](SKILL.md).\n"
    ),
    "typed_data_field": (
        "---\nname: field-example\ndescription: Typed data field documentation.\n---\n"
        "| Field | Type | Description |\n| --- | --- | --- |\n"
        "| " + chr(96) + "data.id" + chr(96) + " | uuid | Public record identifier. |\n"
    ),
}


def input_fingerprint(root: Path) -> str:
    """Fail closed if either scanner mutates a shared fixture or pinned real root."""
    records: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            kind, payload = "link", os.readlink(path).encode()
        elif path.is_file():
            kind, payload = "file", path.read_bytes()
        elif path.is_dir():
            kind, payload = "dir", b""
        else:
            raise AssertionError(("Unexpected input kind", relative))
        records.append(f"{relative}\t{kind}\t{hashlib.sha256(payload).hexdigest()}")
    return hashlib.sha256("\n".join(records).encode()).hexdigest()


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
        "rejected_partial_count": sum(
            item.get("status") == "rejected" and item.get("disposition") == "partial"
            for item in coverage.get("references", [])
        ),
        "finding_count": len(issues),
        "finding_rules": sorted({str(issue.get("id", "")) for issue in issues}),
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
            (root / "SKILL.md").write_text(
                instructions.replace("{outside_uri}", (inputs / "outside-runner.sh").as_uri()),
                encoding="utf-8",
            )
        (inputs / "directory_uninspected" / "docs").mkdir()
        (inputs / "directory_uninspected" / "docs" / "guide.md").write_text(
            "Acquired documentation, not inspected directory contents.\n", encoding="utf-8"
        )
        (inputs / "opaque_binary" / "data").mkdir()
        (inputs / "opaque_binary" / "data" / "payload.bin").write_bytes(b"\0\xffopaque\0")
        (inputs / "outside-runner.sh").write_text("# outside root: never execute\n", encoding="utf-8")
        (inputs / "symlink_outside_root" / "scripts").mkdir()
        (inputs / "symlink_outside_root" / "scripts" / "runner.sh").symlink_to(
            inputs / "outside-runner.sh"
        )
        fingerprints = {name: input_fingerprint(inputs / name) for name in FIXTURES}
        fingerprints["real_asc_workflow"] = input_fingerprint(source.parent)
        outside_fingerprint = hashlib.sha256((inputs / "outside-runner.sh").read_bytes()).hexdigest()
        try:
            for name, scanner in scanners.items():
                reports = {}
                results[name] = reports
                for fixture in FIXTURES:
                    root = inputs / fixture
                    reports[fixture] = scan(scanner, root)
                    if input_fingerprint(root) != fingerprints[fixture]:
                        raise AssertionError(("Scanner mutated its fixture", name, fixture))
                reports["real_asc_workflow"] = scan(scanner, source.parent)
                if input_fingerprint(source.parent) != fingerprints["real_asc_workflow"]:
                    raise AssertionError(("Scanner mutated pinned real skill", name))
                if hashlib.sha256((inputs / "outside-runner.sh").read_bytes()).hexdigest() != outside_fingerprint:
                    raise AssertionError(("Scanner mutated out-of-root target", name))

        finally:
            # Retain all completed CLI measurements when a later scan fails or times out.
            evidence = {
                "format": "uap.skillspector.release-comparison.v1",
                "input_sha256": fingerprints,
                "immutable_real_skill_blob": oid,
                "scanner_versions": versions,
                "same_cli_args": ["--no-llm", "--format", "json", "--fail-on-incomplete"],
                "results": results,
                "production_policy_changed": False,
                "candidate_fork_sha": "13963c56dfce8f708079018100ac24f32b85b9a7",
            }
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(evidence, indent=2, sort_keys=True))

    for name, reports in results.items():
        complete = reports["complete_control"]
        missing = reports["true_missing_executable"]
        if complete["status"] != "complete" or not complete["is_complete"] or complete["exit_code"] != 0:
            raise AssertionError(("Clean control must be Complete", name, complete))
        if (missing["status"] != "partial" or missing["is_complete"]
                or missing["exit_code"] != 1 or "reference_missing" not in missing["reason_counts"]
                or missing["missing_reference_kinds"].get("inline_command", 0) < 1):
            raise AssertionError(("Real missing executable must stay Partial", name, missing))

    for name, reports in results.items():
        for fixture in ("directory_uninspected", "symlink_outside_root", "opaque_binary"):
            record = reports[fixture]
            if (record["status"] != "partial" or record["is_complete"]
                    or record["exit_code"] != 1):
                raise AssertionError(("Uninspectable input must stay Partial", name, fixture, record))

    for name, reports in results.items():
        record = reports["real_asc_workflow"]
        if (record["status"] != "partial" or record["is_complete"]
                or record["exit_code"] != 1
                or "reference_missing" not in record["reason_counts"]):
            raise AssertionError(("Pinned real skill lost incomplete-reference evidence", name, record))

    # A proven pre-existing false Complete is recorded as a baseline regression,
    # never accepted in the fork candidate. Do not weaken either side's real
    # missing-script and uninspected-directory safety gates above.
    old_traversal = results["old"]["traversal_reference"]
    new_traversal = results["new"]["traversal_reference"]
    if old_traversal["status"] != "complete" or not old_traversal["is_complete"]:
        raise AssertionError(("Expected pinned production traversal bug changed", old_traversal))
    if (
        new_traversal["status"] != "partial"
        or new_traversal["is_complete"]
        or new_traversal["exit_code"] != 1
        or not new_traversal["reason_counts"].get("referenced_uninspected")
        or new_traversal["rejected_partial_count"] < 1
    ):
        raise AssertionError(("Fork still calls out-of-root dependency Complete", new_traversal))

    for fixture in (
        "traversal_encoded_parent",
        "traversal_inline_command",
        "traversal_windows_drive",
        "traversal_drive_relative",
        "traversal_python_option",
        "file_uri_outside_root",
    ):
        record = results["new"][fixture]
        if (
            record["status"] != "partial"
            or record["is_complete"]
            or record["exit_code"] != 1
            or not record["reason_counts"].get("referenced_uninspected")
            or record["rejected_partial_count"] < 1
        ):
            raise AssertionError(("Fork calls escaping dependency Complete", fixture, record))

    # Do not introduce additional false missing paths from typed data documentation.
    if (results["new"]["typed_data_field"]["missing_reference_count"] >
            results["old"]["typed_data_field"]["missing_reference_count"]):
        raise AssertionError(("Typed data field reference regression", results["new"]["typed_data_field"]))

    # Source-byte coverage is independent from an external-reference caveat:
    # a complete SKILL.md self-reference must not yield a spurious HIGH AE1.
    if "AE1" in results["new"]["file_uri_outside_root"]["finding_rules"]:
        raise AssertionError(("Spurious AE1 for a fully inspected source",
                              results["new"]["file_uri_outside_root"]))

    old_version = results["old"]["json_version_literal"]
    new_version = results["new"]["json_version_literal"]
    if old_version["missing_reference_count"] < 1 or old_version["is_complete"]:
        raise AssertionError(("Pinned production VERSION false positive not reproduced", old_version))
    if (
        new_version["status"] != "complete"
        or not new_version["is_complete"]
        or new_version["missing_reference_count"] != 0
        or new_version["exit_code"] != 0
    ):
        raise AssertionError(("Fork did not fix strict JSON VERSION false reference", new_version))




if __name__ == "__main__":
    main()
