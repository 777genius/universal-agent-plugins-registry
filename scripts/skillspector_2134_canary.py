"""Read-only, immutable-source pilot for the SkillSpector 2.13.4 migration.

NEVER changes v3 reports, retry state, scanner policy, signed release or install
eligibility. Its evidence is only an input to a separate, reviewed promotion.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

SCANNER = {"id": "skillspector", "version": "2.13.4", "revision": "54824463814a0be01360792523ec7245a69190fc"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REASONS = {"reference_missing", "static_parse_limit", "opaque_content", "obfuscated_instruction_text",
           "recovery_conflict_attempt_limit", "extended_budget_exhausted"}


def validate_cases(cases: dict) -> list[dict]:
    if type(cases) is not dict or set(cases) != {"schema_version", "source_report_commit", "cases"}:
        raise ValueError("invalid canary manifest")
    if type(cases["schema_version"]) is not int or cases["schema_version"] != 1 or not isinstance(cases["source_report_commit"], str) or not SHA.fullmatch(cases["source_report_commit"]):
        raise ValueError("invalid immutable baseline commit")
    entries = cases["cases"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 12:
        raise ValueError("invalid bounded canary selection")
    seen = set()
    for item in entries:
        if type(item) is not dict or set(item) != {"id", "kind", "plugin_path", "repository", "revision",
                                                    "path", "content_digest", "status", "reason", "finding_count"}:
            raise ValueError("invalid canary source fields")
        if not isinstance(item["id"], str) or not item["id"] or item["id"] in seen:
            raise ValueError("duplicate or empty canary ID")
        seen.add(item["id"])
        if item["kind"] not in {"standalone_skill", "plugin_skill"} or not isinstance(item["repository"], str) or \
           not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item["repository"]) or \
           not isinstance(item["revision"], str) or not SHA.fullmatch(item["revision"]):
            raise ValueError("invalid canary source identity")
        if not isinstance(item["path"], str) or item["path"].startswith("/") or \
           any(part in ("", ".", "..") for part in item["path"].split("/")):
            raise ValueError("nonportable canary source path")
        if (item["kind"] == "standalone_skill" and item["plugin_path"] is not None) or \
           (item["kind"] == "plugin_skill" and not isinstance(item["plugin_path"], str)):
            raise ValueError("invalid plugin source scope")
        if not isinstance(item["content_digest"], str) or not DIGEST.fullmatch(item["content_digest"]) or \
           item["status"] != "partial" or item["reason"] not in REASONS or \
           type(item["finding_count"]) is not int or not 0 <= item["finding_count"] <= 1_000_000:
            raise ValueError("invalid baseline evidence")
    return entries


def compare(item: dict, record: dict) -> dict:
    """Neither scanner status nor fewer findings constitutes a safe migration."""
    if record["source"]["repository"] != item["repository"] or \
       record["source"]["revision"] != item["revision"] or \
       record["source"]["path"] != item["path"] or \
       record["source"]["content_digest"] != item["content_digest"]:
        raise ValueError("rescan source differs from immutable baseline")
    if record["scanner"] != SCANNER or record["status"] not in {"complete", "partial", "error"}:
        raise ValueError("untrusted scanner identity or status")
    if record["status"] == "complete" and (record["coverage"]["status"] != "complete" or
        record["execution"]["state"] != "completed" or record["coverage"]["reasons"] or
        record["coverage"].get("fully_inspected_files", 0) <= 0 or
        record["coverage"].get("grouping_complete") is not True or
        record["coverage"].get("ledger_exceptions") or
        record["coverage"].get("reference_evidence_truncated") or
        record["errors"] or record["coverage"]["partially_inspected_files"] or
        record["coverage"]["entirely_uninspected_files"] or
        record["findings_truncated"]):
        raise ValueError("claimed Complete lacks complete evidence")
    status = record["status"]
    found = record["finding_count"]
    return {
        "id": item["id"], "old_status": item["status"], "old_reason": item["reason"],
        "new_status": status, "old_findings": item["finding_count"], "new_findings": found,
        "same_source": True,
        # Always require an independent version-bound finding review before promotion.
        "manual_finding_review_required": True,
        "candidate_complete": status == "complete", "fewer_findings": found < item["finding_count"],
        "coverage_reasons": sorted(set(x["code"] for x in record["coverage"]["reasons"])),
        "error_codes": sorted(set(x["code"] for x in record["errors"])),
    }


def scan(executable: Path, cases: dict) -> dict:
    from scripts import skillspector_reports as scanner
    from scripts import skillspector_coverage_v3 as coverage
    from scripts.build_bridges import PinnedRepository
    from scripts.discovery_checkpoint import WorkBudget
    from scripts.directory_publication import sha256_digest, canonical_json

    with tempfile.TemporaryDirectory(prefix="skillspector-2134-canary-version-") as directory:
        code, body = scanner.run_scanner(executable, ["--version"], Path(directory), 15)
    if code != 0 or body.strip() != b"SkillSpector v2.13.4":
        raise ValueError("canary scanner executable/version mismatch")

    # The canary is an isolated process; published scanner and profiles remain unchanged.
    scanner.SCANNER = copy.deepcopy(SCANNER)
    standard = copy.deepcopy(scanner.STANDARD_PROFILE_DOCUMENT)
    standard["upgrade_canary_scanner_revision"] = SCANNER["revision"]
    scanner.PROFILE_DOCUMENTS["static-standard-v3"] = standard
    scanner.PROFILES["static-standard-v3"] = {
        "id": "static-standard-v3", "digest": sha256_digest(canonical_json(standard))}

    results = []
    for item in validate_cases(cases):
        subject = {key: item[key] for key in ("id", "kind", "plugin_path", "repository", "revision", "path")}
        budget = WorkBudget(300)
        pin = PinnedRepository(item["repository"], item["revision"], None,
            github_token=os.environ.get("GITHUB_TOKEN"), work_budget=budget)
        try:
            # Reuse the production acquisition, immutable byte digest and scanner limits.
            record = coverage.scan_selected(executable, subject, pin, budget,
                                            profile_id="static-standard-v3")
        finally:
            pin.close()
        results.append(compare(item, record))
    counts = Counter(row["new_status"] for row in results)
    return {
        "schema_version": 1, "kind": "skillspector-upgrade-canary-readonly",
        "candidate_scanner": SCANNER, "base_report_commit": cases["source_report_commit"],
        "result_counts": {key: counts[key] for key in ("complete", "partial", "error")},
        "safe_for_automatic_publication": False, "results": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--scanner", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    validate_cases(cases)
    result = scan(args.scanner.resolve(strict=True), cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "measurement_only", "result_counts": result["result_counts"],
                      "promotion_authorized": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Canary failed closed: " + str(error), file=sys.stderr)
        sys.exit(1)
