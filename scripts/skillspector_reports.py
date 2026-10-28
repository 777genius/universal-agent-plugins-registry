#!/usr/bin/env python3
"""Bounded, display-only static reports for explicitly selected immutable skills.

This is independent of LintAI, signed installation policy, and plugin validity.
Untrusted repositories are inert Git blobs; skill scripts are never executed.
"""
from __future__ import annotations

import argparse
import copy
import os
import resource
import subprocess
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from scripts.build_bridges import BridgeError, PinnedRepository
from scripts.build_discovery_index import DiscoveryError, bounded_package_files, materialize_package
from scripts.build_registry import RegistryError, directory_tree_digest, digest_bytes, parse_json_bytes as parse_scanner_json
from scripts.directory_publication import (
    PublicationError, canonical_json, format_timestamp, parse_timestamp, read_json,
    require, sha256_digest, validate_with_schema,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/skillspector-reports-v1.schema.json"
SELECTION_SCHEMA = ROOT / "schemas/skillspector-selection-v1.schema.json"
SCANNER = {"id": "skillspector", "version": "2.13.1", "revision": "f3b25697d76256998ca9d42c198d256258d4c035"}
MAX_REPORT_BYTES = 8 << 20
MAX_FINDINGS = 32
MAX_ERRORS = 16
MAX_FILES = 512
MAX_TREE_BYTES = 4 << 20
SCAN_TIMEOUT = 60
PROFILE_DOCUMENT = {
    "id": "static-only-v1", "arguments": ["--no-llm", "--format", "json", "--fail-on-incomplete"],
    "transitive": False, "author_baselines": False, "max_files": MAX_FILES,
    "max_tree_bytes": MAX_TREE_BYTES, "timeout_seconds": SCAN_TIMEOUT,
    "workflow_seconds": 45, "osv_timeout_seconds": 3,
    "network": "scanner-default-no-transitive", "normalization_version": 1,
    "cache_max_age_seconds": 86400,
}
PROFILE = {"id": PROFILE_DOCUMENT["id"], "digest": sha256_digest(canonical_json(PROFILE_DOCUMENT))}


def now() -> str:
    return format_timestamp(datetime.now(timezone.utc))


def clean(value: str, limit: int = 2000) -> str:
    return "".join(c for c in unicodedata.normalize("NFC", value) if c.isprintable() or c in "\n\t")[:limit]


def environment(home: Path) -> dict[str, str]:
    # Never inherit API keys, tracing, custom rules, Python paths, or author config.
    return {"PATH": os.defpath, "HOME": str(home), "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1",
            "LANGCHAIN_TRACING_V2": "false", "LANGSMITH_TRACING": "false",
            "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "45", "SKILLSPECTOR_OSV_TIMEOUT": "3"}


def output_limit() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT_BYTES, MAX_REPORT_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_scanner(scanner: Path, arguments: list[str], home: Path, timeout: int) -> tuple[int, bytes]:
    # File-backed output plus a child limit bounds diagnostics/report allocation.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        completed = subprocess.run([str(scanner), *arguments], cwd=home, env=environment(home),
                                   stdout=stdout, stderr=stderr, timeout=timeout, check=False,
                                   preexec_fn=output_limit)
        require(stderr.tell() <= MAX_REPORT_BYTES, "scanner diagnostics exceed limit")
        require(stdout.tell() <= MAX_REPORT_BYTES, "scanner output exceeds limit")
        stdout.seek(0)
        return completed.returncode, stdout.read(MAX_REPORT_BYTES + 1)


def verify_scanner(scanner: Path) -> None:
    require(scanner.is_file() and not scanner.is_symlink(), "SkillSpector executable is unavailable")
    with tempfile.TemporaryDirectory(prefix="uap-skillspector-version-") as directory:
        code, body = run_scanner(scanner, ["--version"], Path(directory), 15)
    require(code == 0 and body.strip() == b"SkillSpector v2.13.1", "SkillSpector version is unsupported")


def load_selection(path: Path) -> dict[str, Any]:
    selection = read_json(path, max_bytes=256 << 10)
    validate_with_schema(selection, SELECTION_SCHEMA)
    ids = [item["id"] for item in selection["sources"]]
    require(len(ids) == len(set(ids)), "selection IDs must be unique")
    for item in selection["sources"]:
        if item["kind"] == "plugin_skill":
            parent = item["plugin_path"]
            prefix = parent + "/" if parent else ""
            relative = item["path"][len(prefix):] if item["path"].startswith(prefix) else ""
            require(relative.startswith("skills/") and len(relative.split("/")) == 2,
                    "plugin skill must be an immediate skills/* root under plugin_path")
        else:
            require(item["plugin_path"] is None, "standalone skill cannot have plugin_path")
    return selection


def cache_records(path: Path | None) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    try:
        report = read_json(path, max_bytes=MAX_REPORT_BYTES)
        validate_with_schema(report, SCHEMA)
        if report["scanner"] != SCANNER or report["profile"] != PROFILE:
            return {}
        return {(r["source"]["repository"], r["source"]["revision"], r["source"]["path"], r["source"]["content_digest"]): r
                for r in report["records"] if r["status"] == "complete" and
                0 <= (datetime.now(timezone.utc) - parse_timestamp(r["scanned_at"], "scanned_at")).total_seconds() < 86400}
    except (PublicationError, RecursionError):
        # Prior output is an optional optimization, never a prerequisite for a
        # fresh scan. Scanner/schema upgrades and damaged caches are misses.
        return {}


def empty_record(item: dict[str, Any]) -> dict[str, Any]:
    return {"id": item["id"], "kind": item["kind"], "plugin_path": item["plugin_path"], "skill_name": None,
            "source": {key: item[key] for key in ("repository", "revision", "path")} | {"content_digest": None},
            "scanned_at": None, "status": "error", "finding_count": 0, "findings_truncated": False,
            "findings": [], "errors": []}


def add_error(record: dict[str, Any], code: str, message: str) -> None:
    if len(record["errors"]) < MAX_ERRORS:
        record["errors"].append({"code": clean(code, 120), "message": clean(message)})


def normalize_report(record: dict[str, Any], body: bytes, returncode: int, root: Path) -> dict[str, Any]:
    require(0 < len(body) <= MAX_REPORT_BYTES, "SkillSpector report is empty or oversized")
    report = parse_scanner_json(body, "SkillSpector report")
    require(isinstance(report, dict), "SkillSpector report must be an object")
    metadata = report.get("metadata")
    require(isinstance(metadata, dict) and metadata.get("skillspector_version") == SCANNER["version"],
            "SkillSpector report identity is unsupported")
    require(metadata.get("llm_requested") is False and metadata.get("inference_usage") == [],
            "SkillSpector report is not static-only")
    require(report.get("suppressed_count") == 0 and report.get("suppressed") == [], "suppressed findings are forbidden")
    completeness = report.get("analysis_completeness")
    require(isinstance(completeness, dict) and type(completeness.get("is_complete")) is bool,
            "SkillSpector completeness is missing")
    require(type(report.get("execution_successful")) is bool and type(completeness.get("execution_successful")) is bool,
            "SkillSpector execution status is missing")
    findings = report.get("issues")
    require(isinstance(findings, list), "SkillSpector findings are invalid")
    normalized = []
    for finding in findings:
        require(isinstance(finding, dict), "SkillSpector finding is invalid")
        location = finding.get("location")
        require(isinstance(location, dict), "SkillSpector finding location is invalid")
        rule, severity = finding.get("id"), finding.get("severity")
        message = finding.get("explanation") or finding.get("finding")
        path = location.get("file")
        require(isinstance(rule, str) and bool(rule) and isinstance(message, str) and bool(message), "SkillSpector finding is incomplete")
        require(severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, "SkillSpector severity is invalid")
        require(isinstance(path, str) and bool(path), "SkillSpector finding path is invalid")
        # Upstream normally emits relative paths. Never publish temporary absolute paths.
        if Path(path).is_absolute():
            try:
                path = Path(path).relative_to(root).as_posix()
            except ValueError:
                raise PublicationError("SkillSpector finding path escapes selected root")
        require(".." not in Path(path).parts and "\\" not in path, "SkillSpector finding path escapes selected root")
        require(clean(rule, 120) and clean(message) and clean(path, 1000), "SkillSpector finding contains only display controls")
        output = {"rule": clean(rule, 120), "severity": severity, "message": clean(message), "path": clean(path, 1000)}
        line = location.get("start_line")
        if type(line) is int and line > 0:
            output["line"] = line
        normalized.append(output)
    severity_rank = {name: rank for rank, name in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))}
    normalized.sort(key=lambda f: (severity_rank[f["severity"]], f["rule"], f["path"], f.get("line", 0), f["message"]))
    record.update(finding_count=len(normalized), findings=normalized[:MAX_FINDINGS], findings_truncated=len(normalized) > MAX_FINDINGS)
    coverage_complete = completeness["is_complete"] is True and completeness.get("status") == "complete"
    for key in ("partially_inspected_files", "entirely_uninspected_files"):
        require(type(completeness.get(key)) is int and completeness[key] >= 0, "SkillSpector file coverage is invalid")
        coverage_complete = coverage_complete and completeness[key] == 0
    require(type(completeness.get("fully_inspected_files")) is int and completeness["fully_inspected_files"] >= 0,
            "SkillSpector file coverage is invalid")
    coverage_complete = coverage_complete and completeness["fully_inspected_files"] > 0
    successful = report["execution_successful"] is True and completeness["execution_successful"] is True
    record["status"] = "complete" if successful and coverage_complete else "partial" if successful else "error"
    if returncode not in (0, 1):
        record["status"] = "error"
        add_error(record, "scanner_exit", "SkillSpector did not finish successfully.")
    for key in ("errors", "runtime_errors", "limitations", "ledger_exceptions"):
        diagnostics = report.get(key, []) if key in ("errors", "runtime_errors") else completeness.get(key, [])
        require(isinstance(diagnostics, list), "SkillSpector diagnostics are invalid")
        if diagnostics:
            if record["status"] == "complete":
                record["status"] = "partial"
            for diagnostic in diagnostics:
                if isinstance(diagnostic, dict):
                    add_error(record, str(diagnostic.get("reason_code") or key), str(diagnostic.get("message") or "Analysis coverage is incomplete."))
                else:
                    add_error(record, key, "Analysis coverage is incomplete.")
    statuses = completeness.get("analyzer_statuses")
    require(isinstance(statuses, list) and bool(statuses), "SkillSpector analyzer coverage is missing")
    expected = {"artifact_integrity", "static_patterns_prompt_injection", "static_yara"}
    completed = {a.get("analyzer_id") for a in statuses if isinstance(a, dict) and a.get("status") == "completed"}
    if not expected.issubset(completed):
        if record["status"] == "complete":
            record["status"] = "partial"
        add_error(record, "analyzer_coverage_missing", "Required static analyzer coverage is missing.")
    for analyzer in statuses:
        require(isinstance(analyzer, dict), "SkillSpector analyzer status is invalid")
        if analyzer.get("status") not in {"completed", "not_applicable", "disabled"} or (
                analyzer.get("status") == "disabled" and analyzer.get("analyzer_id") not in {
                    "semantic_developer_intent", "semantic_quality_policy", "semantic_security_discovery", "meta_analyzer"}) or any(
                analyzer.get(key, 0) != 0 for key in ("failed", "partial", "skipped", "unaccounted")):
            if record["status"] == "complete":
                record["status"] = "partial"
            add_error(record, "analyzer_incomplete", "A static analyzer did not complete its planned analysis.")
    if record["status"] != "complete" and not record["errors"]:
        add_error(record, "analysis_incomplete", "SkillSpector reported incomplete analysis or failed execution.")
    record["report_digest"] = digest_bytes(body)
    return record


def scan_source(scanner: Path, item: dict[str, Any], pinned: PinnedRepository,
                cached: dict[tuple[str, str, str, str], dict[str, Any]]) -> dict[str, Any]:
    record = empty_record(item)
    try:
        files = bounded_package_files(pinned, item["path"])
        tree_bytes = sum(len(body) for _, _, body in files)
        if len(files) > MAX_FILES or tree_bytes > MAX_TREE_BYTES:
            add_error(record, "input_limit_exceeded",
                      f"Selected skill contains {len(files)} files and {tree_bytes} bytes; "
                      f"limits are {MAX_FILES} files and {MAX_TREE_BYTES} bytes.")
            return record
        require(any(path == "SKILL.md" for path, _, _ in files), "selected root has no SKILL.md")
        with tempfile.TemporaryDirectory(prefix="uap-skillspector-") as temporary:
            home = Path(temporary)
            root = home / "content"
            root.mkdir()
            materialize_package(files, root)
            digest = directory_tree_digest(root)
            record["source"]["content_digest"] = digest
            document = (root / "SKILL.md").read_text(encoding="utf-8")
            if document.startswith("---\n") and "\n---" in document[4:]:
                header = document[4:].split("\n---", 1)[0]
                require(len(header.encode("utf-8")) <= 65536, "skill frontmatter exceeds limit")
                frontmatter = yaml.safe_load(header)
                if isinstance(frontmatter, dict) and isinstance(frontmatter.get("name"), str):
                    record["skill_name"] = clean(frontmatter["name"], 200) or None
            key = (item["repository"], item["revision"], item["path"], digest)
            if key in cached:
                previous = cached[key]
                if previous["kind"] == item["kind"] and previous["plugin_path"] == item["plugin_path"]:
                    result = copy.deepcopy(previous)
                    result["id"] = item["id"]
                    return result
            record["scanned_at"] = now()
            code, body = run_scanner(scanner, ["scan", str(root), *PROFILE_DOCUMENT["arguments"]], home, SCAN_TIMEOUT)
            require(directory_tree_digest(root) == digest, "selected bytes changed during scan")
            return normalize_report(record, body, code, root)
    except subprocess.TimeoutExpired:
        record["status"] = "error"
        add_error(record, "scan_timeout", f"Static scan exceeded its {SCAN_TIMEOUT}-second deadline.")
        return record
    except (BridgeError, DiscoveryError, PublicationError, RegistryError, OSError, ValueError, RecursionError, yaml.YAMLError, subprocess.SubprocessError):
        record["status"] = "error"
        add_error(record, "scan_failed", "Selected skill could not be acquired, parsed, or scanned completely.")
        return record


def build_reports(selection: dict[str, Any], scanner: Path, cached: dict | None = None,
                  mirror_root: Path | None = None, github_token: str | None = None, *,
                  source_commit: str) -> dict[str, Any]:
    validate_with_schema(selection, SELECTION_SCHEMA)
    verify_scanner(scanner)
    records = []
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in selection["sources"]:
        groups.setdefault((item["repository"], item["revision"]), []).append(item)
    for (repository, revision), items in sorted(groups.items()):
        try:
            pinned = PinnedRepository(repository, revision, mirror_root, github_token=github_token if mirror_root is None else None)
        except (BridgeError, OSError, subprocess.SubprocessError):
            for item in items:
                record = empty_record(item)
                add_error(record, "acquisition_failed", "Selected immutable source could not be acquired.")
                records.append(record)
            continue
        try:
            records.extend(scan_source(scanner, item, pinned, cached or {}) for item in items)
        finally:
            pinned.close()
    report = {"schema_version": 1, "source_commit": source_commit, "generated_at": now(), "scope": "selected_sources", "scanner": SCANNER,
              "profile": PROFILE, "selection_digest": sha256_digest(canonical_json(selection)),
              "records": sorted(records, key=lambda r: r["id"])}
    validate_with_schema(report, SCHEMA)
    require(len(canonical_json(report)) <= MAX_REPORT_BYTES, "display report exceeds size limit")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, default=ROOT / "registry/skillspector-selection.json")
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--source-commit", required=True, help="Exact trusted registry checkout commit")
    parser.add_argument("--mirror-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build_reports(load_selection(args.selection), args.scanner.resolve(), cache_records(args.previous),
                               args.mirror_root, os.environ.get("GITHUB_TOKEN"), source_commit=args.source_commit)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(report))
        return 0
    except (BridgeError, PublicationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"SkillSpector report build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
