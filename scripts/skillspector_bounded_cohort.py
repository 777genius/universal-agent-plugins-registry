#!/usr/bin/env python3
"""Fail-closed preparation of nine immutable scanner upgrade subjects.

Never relabels Partial, changes v3 reports, executes Skills or authorizes
publication. This is only the admission gate for a later versioned cohort.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys
from contextlib import ExitStack
from pathlib import Path

OLD_SCANNER = {"id": "skillspector", "version": "2.13.1",
               "revision": "f3b25697d76256998ca9d42c198d256258d4c035"}
NEW_SCANNER = {"id": "skillspector", "version": "2.13.3",
               "revision": "604a1cff1249ec4023012be4bdb77eac20621893"}
BRAIDS_SHA = "79c913e9d27854d88c7ee58aa9906bd2b45001b4"
BRAIDS = ("braids", "braids-audit", "braids-claims", "braids-depth",
          "braids-help", "braids-review", "braids-risk")
COHORT = {
    **{("vyas-devgna/braids", BRAIDS_SHA, f"skills/{name}"): "yaml" for name in BRAIDS},
    ("indranilbanerjee/digital-marketing-pro", "be4142b25bba6d424962a7788432dd813e6b768c",
     "skills/sitemap-manager"): "xml",
    ("teachskillofskills-ai/digitalmarketingpro-techshu", "e97a5bdd91601024a9cfa870807a8d3c81dc3caf",
     "skills/sitemap-manager"): "xml",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
YAML_METADATA = re.compile(
    r"""^\s*(?:metadata\.)?[a-z][a-z0-9_-]*-version\s*:\s*(["'])\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\1\s*$"""
)
XML_PROLOG = re.compile(r"""^\s*<\?xml\s+version=(["'])1\.0\1\s+encoding=(["'])UTF-8\2\s*\?>\s*$""")


class CohortRejected(ValueError):
    """Source identity or bounded old-analysis evidence is not proven."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CohortRejected(message)


def identity(item: dict) -> tuple[str, str, str]:
    return item["repository"], item["revision"], item["path"]


def canon(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canon(value)).hexdigest()


def checked_old_partial(record: dict, item: dict, kind: str) -> None:
    require(record.get("id") == item["id"], "report ID changed")
    require(record.get("freshness") == "current" and record.get("target_revision") == item["revision"],
            "historical or changed source cannot be promoted")
    source = record.get("source", {})
    require(all(source.get(k) == item[k] for k in ("repository", "revision", "path")),
            "report source differs from immutable selection")
    require(DIGEST.fullmatch(source.get("content_digest") or "") is not None,
            "missing source content digest")
    require(record.get("scanner") == OLD_SCANNER and record.get("status") == "partial" and
            record.get("coverage", {}).get("status") == "partial",
            "not a current old-scanner Partial")
    coverage = record["coverage"]
    reasons = coverage.get("reasons")
    require(isinstance(reasons, list) and bool(reasons) and
            all(isinstance(reason, dict) and reason.get("code") == "reference_missing" for reason in reasons),
            "other coverage limitation must stay Partial")
    require(not coverage.get("reference_evidence_truncated"),
            "truncated reference evidence must stay Partial")
    refs = coverage.get("references")
    require(isinstance(refs, list) and bool(refs) and coverage.get("references_total") == len(refs),
            "reference evidence is not wholly retained")
    missing = [ref for ref in refs if ref.get("status") == "missing"]
    require(bool(missing) and all(ref.get("status") in {"missing", "resolved"} and
            (ref.get("status") != "resolved" or ref.get("disposition") == "analyzed") for ref in refs),
            "uninspected, rejected or unresolved dependency must stay Partial")
    # Production 2.13.1 mirrors each missing reference in errors and the
    # reference-resolution ledger. These are not independent limitations.
    # Match *every* row by position; unrelated failures or extra partial
    # ledger evidence still fail closed.
    positions = [(ref.get("source_path"), ref.get("line")) for ref in missing]
    require(len(set(positions)) == len(missing) and
            all(ref.get("source_path") == "SKILL.md" and type(ref.get("line")) is int
                and ref["line"] > 0 and ref.get("reference_kind") == "quoted_or_code"
                and ref.get("disposition") == "partial" and ref.get("target_path") is None
                for ref in missing),
            "missing reference identity does not match strict metadata")
    errors = record.get("errors")
    require(isinstance(errors, list) and len(errors) == len(missing) and
            all(isinstance(row, dict) and row.get("code") == "reference_missing"
                for row in errors),
            "unrelated scanner error must stay Partial")
    ledger = coverage.get("ledger_exceptions")
    require(isinstance(ledger, list) and coverage.get("ledger_exceptions_total") == len(missing)
            and len(ledger) == len(missing) and
            all(isinstance(row, dict) and row.get("reason_code") == "reference_missing"
                and row.get("phase") == "reference_resolution"
                and row.get("outcome") == "partial" and row.get("fatal") is False
                and row.get("start_line") == row.get("end_line") for row in ledger)
            and sorted((row["path"], row["start_line"]) for row in ledger) == sorted(positions),
            "additional or mismatched ledger limitation must stay Partial")
    pattern = YAML_METADATA if kind == "yaml" else XML_PROLOG
    require(all(isinstance(ref.get("evidence"), str) and pattern.fullmatch(ref["evidence"]) for ref in missing),
            "missing reference is not exactly qualified metadata")
    require(record.get("execution", {}).get("state") == "completed" and
            record.get("execution", {}).get("exit_code") in (0, 1), "old scan did not complete")


def build_plan(previous: dict, current_selection: dict, report_commit: str) -> dict:
    """Require nine old/current pinned records without rewriting any report.

    The caller MUST pass a fully verified skillspector_coverage_v3.read_bundle
    result (shards, attempts, schemas and source lineage already validated).
    """
    require(SHA.fullmatch(report_commit) is not None, "invalid immutable report commit")
    manifest, selection, records = previous["manifest"], previous["selection"], previous["records"]
    from scripts import skillspector_contract as contract
    from scripts import skillspector_reports as scanner

    require(manifest["schema_version"] == 3 and manifest["scanner"] == OLD_SCANNER and
            manifest["coverage"]["selected"] > 9 and
            (manifest.get("profile"), manifest.get("profiles")) in (
                (contract.LEGACY_POLICY, list(scanner.LEGACY_PROFILES.values())),
                (contract.PROFILE, scanner.ALL_PROFILES),
            ),
            "not the current full-v3 producer policy")
    require(manifest["selection_digest"] == digest(selection), "baseline selection digest differs")
    by_key, live_by_key = {}, {}
    for item in selection["sources"]:
        key = identity(item)
        if key in COHORT:
            require(key not in by_key, "duplicate prior cohort subject")
            by_key[key] = item
    for item in current_selection["sources"]:
        key = identity(item)
        if key in COHORT:
            require(key not in live_by_key, "duplicate live cohort subject")
            live_by_key[key] = item
    require(set(by_key) == set(COHORT) and set(live_by_key) == set(COHORT),
            "pinned source missing or changed revision")
    chosen = []
    for key in sorted(COHORT):
        item = by_key[key]
        require(item == live_by_key[key], "live cohort identity/ID changed")
        record = records.get(item["id"])
        require(record is not None, "no current report for pinned source")
        checked_old_partial(record, item, COHORT[key])
        chosen.append(copy.deepcopy(item))
    require(len({item["id"] for item in chosen}) == 9, "repeated cohort report ID")
    return {"schema_version": 1, "kind": "skillspector-bounded-cohort-preflight",
            "source_commit": manifest["source_commit"],
            "base_report_commit": report_commit, "base_manifest_digest": digest(manifest),
            "baseline_scanner": copy.deepcopy(OLD_SCANNER), "candidate_scanner": copy.deepcopy(NEW_SCANNER),
            "selection": {"schema_version": selection["schema_version"], "sources": chosen},
            "live_selection_verified": False,
            "candidate_status": "not_scanned", "publication_authorized": False}


def write_plan_exclusively(path: Path, plan: dict) -> None:
    """Create one proof without following symlinks, even during a path swap."""
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"),
            "safe cohort output requires no-follow directory descriptors")
    absolute = path.absolute()
    require(absolute.name not in {"", ".", ".."}, "invalid cohort output filename")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        directory = os.open(absolute.anchor, directory_flags)
        stack.callback(os.close, directory)
        for part in absolute.parts[1:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            try:
                child = os.open(part, directory_flags, dir_fd=directory)
            except OSError as error:
                raise CohortRejected("cohort output path contains an unsafe directory") from error
            stack.callback(os.close, child)
            directory = child
        try:
            existing = os.stat(absolute.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(not stat.S_ISLNK(existing.st_mode), "cohort output cannot be a symlink")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        output = os.open(absolute.name, flags, 0o600, dir_fd=directory)
        with os.fdopen(output, "wb") as stream:
            stream.write(canon(plan))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-dir", type=Path, required=True)
    parser.add_argument("--current-selection", type=Path, required=True)
    parser.add_argument("--report-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from scripts import skillspector_coverage_v3 as coverage

    previous = coverage.read_bundle(args.previous_dir)
    require(previous is not None, "verified prior report bundle missing")
    # Both exact generations are valid authenticated baselines. The nine
    # individual old Partial witnesses must still satisfy build_plan().
    coverage.validate_manifest(previous["manifest"])
    current = coverage.load_selection(args.current_selection)
    plan = build_plan(previous, current, args.report_commit)
    write_plan_exclusively(args.output, plan)
    print("Prepared nine baseline source pins; live discovery remains unverified. No Complete or publication.")
    return 0


if __name__ == "__main__":
    if not __package__:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    raise SystemExit(main())
