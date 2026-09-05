#!/usr/bin/env python3
"""Build deterministic LintAI assessments for exact Discovery package bytes."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from scripts.build_bridges import BridgeError, PinnedRepository
from scripts.build_discovery_index import bounded_package_files, materialize_package
from scripts.build_registry import directory_tree_digest, digest_bytes
from scripts.directory_publication import (
    PublicationError, canonical_json, parse_json_bytes, read_json, require, sha256_digest, validate_with_schema,
)


ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_SCHEMA = ROOT / "schemas" / "discovery-snapshot.schema.json"
SECURITY_SCHEMA = ROOT / "schemas" / "security-snapshot.schema.json"
SCANNER = {"id": "lintai", "version": "0.1.2"}
POLICY_ID = "agent-plugin-install"
POLICY_VERSION = 1
MAX_REPORT_BYTES = 8 << 20
MAX_FINDINGS = 32
MAX_WORKERS = 16

BLOCKING_CODES = frozenset({
    "SEC102", "SEC103", "SEC330", "SEC344",
    "SEC637", "SEC640", "SEC645", "SEC648",
    "SEC652", "SEC653", "SEC654", "SEC658", "SEC659", "SEC660",
    "SEC665", "SEC666", "SEC671", "SEC672",
    "SEC674", "SEC675", "SEC676", "SEC680", "SEC681", "SEC682",
    "SEC684", "SEC686", "SEC697", "SEC698", "SEC701", "SEC702",
    "SEC706", "SEC710", "SEC717", "SEC718", "SEC725", "SEC726",
    "SEC729", "SEC730", "SEC733", "SEC734", "SEC738", "SEC742",
})


def policy() -> dict[str, Any]:
    policy_document = {
        "id": POLICY_ID,
        "version": POLICY_VERSION,
        "blocking_confidence": "high",
        "blocking_rule_codes": sorted(BLOCKING_CODES),
        "deny_is_blocking": True,
    }
    return {"id": POLICY_ID, "version": POLICY_VERSION, "digest": sha256_digest(canonical_json(policy_document))}


def subject(record: dict[str, Any]) -> tuple[str, str]:
    return record["tree_digest"], record["manifest_digest"]


def previous_records(path: Path | None) -> dict[tuple[str, str], dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    snapshot = read_json(path, max_bytes=MAX_REPORT_BYTES)
    validate_with_schema(snapshot, SECURITY_SCHEMA)
    if snapshot.get("scanner") != SCANNER or snapshot.get("policy") != policy():
        return {}
    return {
        (record["subject"]["tree_digest"], record["subject"]["manifest_digest"]): record
        for record in snapshot["records"]
        if record["outcome"] != "check_unavailable"
    }


def disposition(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "")).lower()
    confidence = str(finding.get("confidence", "")).lower()
    code = str(finding.get("rule_code", ""))
    return "blocking" if severity == "deny" or (confidence == "high" and code in BLOCKING_CODES) else "warning"


def normalized_finding(finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    start = location.get("start") if isinstance(location.get("start"), dict) else {}
    result = {
        "code": unicodedata.normalize("NFC", str(finding.get("rule_code", ""))),
        "disposition": disposition(finding),
        "severity": str(finding.get("severity", "")).lower(),
        "confidence": str(finding.get("confidence", "")).lower(),
        "category": unicodedata.normalize("NFC", str(finding.get("category", "")).lower()),
        "path": unicodedata.normalize("NFC", str(location.get("normalized_path", "")).replace("\\", "/")),
        "message": unicodedata.normalize("NFC", str(finding.get("message", "")))[:2000],
    }
    if type(start.get("line")) is int and start["line"] > 0:
        result["line"] = start["line"]
    require(result["code"] and result["message"], "LintAI returned an incomplete finding")
    return result


def assessment_from_report(record: dict[str, Any], body: bytes) -> dict[str, Any]:
    require(0 < len(body) <= MAX_REPORT_BYTES, "LintAI report is empty or oversized")
    report = parse_json_bytes(body, "LintAI report", max_bytes=MAX_REPORT_BYTES)
    require(isinstance(report, dict), "LintAI report must be an object")
    require(report.get("schema_version") == 1, "LintAI report schema is unsupported")
    require(report.get("tool") == SCANNER, "LintAI scanner identity is unsupported")
    report_policy = report.get("policy")
    require(isinstance(report_policy, dict) and report_policy.get("id") == POLICY_ID and report_policy.get("version") == POLICY_VERSION,
            "LintAI policy identity is unsupported")
    require(report.get("runtime_errors") == [], "LintAI reported incomplete runtime coverage")
    stats = report.get("stats")
    require(isinstance(stats, dict) and type(stats.get("scanned_files")) is int and stats["scanned_files"] >= 0,
            "LintAI scan count is invalid")
    findings = report.get("findings")
    require(isinstance(findings, list), "LintAI findings are invalid")
    normalized = [normalized_finding(item) for item in findings if isinstance(item, dict)]
    require(len(normalized) == len(findings), "LintAI finding is invalid")
    normalized.sort(key=lambda item: (
        item["disposition"], item["code"], item["path"], item.get("line", 0), item["message"],
    ))
    blocking = sum(item["disposition"] == "blocking" for item in normalized)
    warnings = len(normalized) - blocking
    outcome = "blocking_findings" if blocking else "warnings" if warnings else "no_blocking_findings"
    return {
        "subject": {"tree_digest": record["tree_digest"], "manifest_digest": record["manifest_digest"]},
        "outcome": outcome,
        "counts": {"blocking": blocking, "warnings": warnings, "total": len(normalized)},
        "scanned_files": stats["scanned_files"],
        "report_digest": digest_bytes(body),
        "findings": normalized[:MAX_FINDINGS],
    }


def unavailable(record: dict[str, Any], code: str) -> dict[str, Any]:
    return {
        "subject": {"tree_digest": record["tree_digest"], "manifest_digest": record["manifest_digest"]},
        "outcome": "check_unavailable",
        "counts": {"blocking": 0, "warnings": 0, "total": 0},
        "scanned_files": 0,
        "error_code": code,
        "findings": [],
    }


def scan_materialized(lintai: Path, record: dict[str, Any], root: Path) -> dict[str, Any]:
    require(directory_tree_digest(root) == record["tree_digest"], "Discovery tree digest changed during security scan")
    require(digest_bytes((root / "plugin.json").read_bytes()) == record["manifest_digest"],
            "Discovery manifest digest changed during security scan")
    environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR") if key in os.environ}
    completed = subprocess.run(
        [str(lintai), "scan-agent-plugin", str(root)], cwd=root, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    require(completed.returncode in {0, 1}, "LintAI scan process failed")
    require(len(completed.stderr) <= 64 << 10, "LintAI diagnostics are oversized")
    return assessment_from_report(record, completed.stdout)


def verify_scanner(lintai: Path) -> None:
    environment = {
        key: os.environ[key]
        for key in ("SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR")
        if key in os.environ
    }
    completed = subprocess.run(
        [str(lintai), "version"], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
    )
    require(completed.returncode == 0, "LintAI version probe failed")
    require(completed.stdout == b"lintai 0.1.2\n" and completed.stderr == b"",
            "LintAI scanner version is unsupported")


def scan_repository(lintai: Path, repository: str, revision: str, records: list[dict[str, Any]],
                    mirror_root: Path | None, github_token: str | None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        pinned = PinnedRepository(repository, revision, mirror_root, github_token=github_token if mirror_root is None else None)
    except (BridgeError, OSError, subprocess.SubprocessError):
        return [unavailable(record, "acquisition_failed") for record in records]
    try:
        for record in records:
            try:
                files = bounded_package_files(pinned, record["package_path"])
                with tempfile.TemporaryDirectory(prefix="uap-security-package-") as temporary:
                    root = Path(temporary)
                    materialize_package(files, root)
                    results.append(scan_materialized(lintai, record, root))
            except (BridgeError, OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError):
                results.append(unavailable(record, "scan_failed"))
    finally:
        pinned.close()
    return results


def build_security_candidate(discovery: dict[str, Any], lintai: Path, previous: dict[tuple[str, str], dict[str, Any]],
                             generated_at: str, mirror_root: Path | None = None, workers: int = 8,
                             github_token: str | None = None) -> dict[str, Any]:
    validate_with_schema(discovery, DISCOVERY_SCHEMA)
    require(discovery.get("complete") is True, "Security indexing requires a complete Discovery snapshot")
    require(lintai.is_file() and not lintai.is_symlink(), "LintAI executable is unavailable")
    verify_scanner(lintai)
    require(1 <= workers <= MAX_WORKERS, "security workers are out of range")
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for record in discovery["records"]:
        if record["availability"] == "available":
            unique.setdefault(subject(record), record)
    results = {key: value for key, value in previous.items() if key in unique}
    jobs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for key, record in unique.items():
        if key not in results:
            jobs.setdefault((record["repository"], record["revision"]), []).append(record)
    if jobs:
        with ThreadPoolExecutor(max_workers=min(workers, len(jobs)), thread_name_prefix="security-repository") as executor:
            futures = {
                executor.submit(scan_repository, lintai, repository, revision, records, mirror_root, github_token): (repository, revision)
                for (repository, revision), records in jobs.items()
            }
            for future in as_completed(futures):
                for record in future.result():
                    results[(record["subject"]["tree_digest"], record["subject"]["manifest_digest"])] = record
    ordered = sorted(results.values(), key=lambda item: (item["subject"]["tree_digest"], item["subject"]["manifest_digest"]))
    checked = sum(record["outcome"] != "check_unavailable" for record in ordered)
    total = len(unique)
    unavailable_count = total - checked
    complete = len(ordered) == total and (total == 0 or unavailable_count <= max(10, total // 20))
    candidate = {
        "candidate_schema_version": 1,
        "generated_at": generated_at,
        "complete": complete,
        "discovery": {"sequence": discovery["sequence"], "snapshot_digest": sha256_digest(canonical_json(discovery))},
        "scanner": SCANNER,
        "policy": policy(),
        "coverage": {"subjects": total, "checked": checked, "unavailable": unavailable_count},
        "records": ordered,
    }
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--discovery-snapshot", type=Path, required=True)
    parser.add_argument("--previous-security-snapshot", type=Path)
    parser.add_argument("--lintai", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mirror-root", type=Path)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    try:
        discovery = read_json(args.discovery_snapshot)
        candidate = build_security_candidate(
            discovery, args.lintai, previous_records(args.previous_security_snapshot),
            generated_at=discovery["generated_at"], mirror_root=args.mirror_root,
            workers=args.workers, github_token=os.environ.get("GITHUB_TOKEN"),
        )
        args.output.write_bytes(canonical_json(candidate))
        return 0 if candidate["complete"] else 3
    except (OSError, ValueError, BridgeError, PublicationError, subprocess.SubprocessError) as error:
        print(f"Security index build failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
