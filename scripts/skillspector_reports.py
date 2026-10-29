#!/usr/bin/env python3
"""Bounded, display-only static reports for explicitly selected immutable skills.

This is independent of LintAI, signed installation policy, and plugin validity.
Untrusted repositories are inert Git blobs; skill scripts are never executed.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import os
import re
import resource
import signal
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
    PublicationError, canonical_json, format_timestamp, parse_timestamp, read_bytes_bounded, read_json,
    require, sha256_digest, validate_with_schema,
)
from scripts.skillspector_exceptions import EXCEPTION_SET_DIGEST, matching_exception

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

# Versioned separately from the legacy selected-source publisher. The outer
# process deadline includes startup and JSON serialization; both scanner-owned
# deadlines must expire first so an incomplete report can still be returned.
STANDARD_PROFILE_DOCUMENT = PROFILE_DOCUMENT | {
    "id": "static-standard-v3", "normalization_version": 3,
    "static_artifact_seconds": 30, "cache_max_age_seconds": None,
    "exception_set_digest": EXCEPTION_SET_DIGEST,
}
EXTENDED_PROFILE_DOCUMENT = STANDARD_PROFILE_DOCUMENT | {
    "id": "static-extended-v3", "timeout_seconds": 180,
    "workflow_seconds": 150, "static_artifact_seconds": 90,
    "max_files": 2048, "max_tree_bytes": 16 << 20,
}
PROFILE_DOCUMENTS = {p["id"]: p for p in (STANDARD_PROFILE_DOCUMENT, EXTENDED_PROFILE_DOCUMENT)}
PROFILES = {key: {"id": key, "digest": sha256_digest(canonical_json(value))}
            for key, value in PROFILE_DOCUMENTS.items()}
STANDARD_PROFILE = PROFILES[STANDARD_PROFILE_DOCUMENT["id"]]
EXTENDED_PROFILE = PROFILES[EXTENDED_PROFILE_DOCUMENT["id"]]

# These reasons describe bounded resources or transient acquisition. Parser,
# missing-reference and unsupported-format limitations do not become retryable
# merely because the scanner emitted them with a high severity.
RETRYABLE_REASONS = frozenset({"scan_timeout", "preparation_timeout", "acquisition_failed",
    "runtime_limit", "archive_time_limit", "size_limit", "input_limit_exceeded", "acquisition_transfer_limit",
    "total_bytes_limit", "artifact_count_limit", "network_error", "network_timeout",
    "osv_request_failed", "osv_timeout"})
DISABLED_STATIC_ANALYZERS = frozenset({"semantic_developer_intent", "semantic_quality_policy",
    "semantic_security_discovery", "meta_analyzer"})
MAX_REFERENCE_EVIDENCE_BYTES = 1 << 20
REFERENCE_FIELDS = frozenset({"source_path", "line", "column", "evidence", "target_path", "status",
    "disposition", "reference_kind"})
REFERENCE_KINDS = frozenset({"markdown_image", "documentation_image", "markdown_link", "inline_command",
    "quoted_or_code", "plain_path"})
LEDGER_FIELDS = frozenset({"reason_code", "message", "path", "start_line", "end_line", "outcome", "phase",
    "error_class", "analyzers", "fatal", "scope"})
REFERENCE_MESSAGES = {
    "missing": ("A local path-like reference does not match any bundled artifact, "
                "such as a file the skill writes at runtime."),
    "ambiguous": "A local path-like reference matched more than one bundled artifact and could not be resolved to a single target.",
}

# Public examples can contain provider-shaped credentials even when the
# scanner correctly reports them as findings. Never republish these values.
# This deliberately covers the observed Stripe secret/restricted key formats;
# it is not a general secret detector, and repository push protection remains
# the final fail-closed boundary for other formats.
STRIPE_SECRET_KEY = re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9_])")
REDACTED_CREDENTIAL = "[REDACTED Stripe key]"
REPORT_IDENTITY_FIELDS = frozenset({"id", "rule", "finding_id", "finding_ids", "match_fingerprint",
    "source", "source_identity", "source_digest", "source_sha256", "source_url", "report_digest",
    "path", "file", "source_path", "target_path", "plugin_path", "code", "reason_code", "analyzer_id"})


def has_public_credentials(value: Any, *, depth: int = 0) -> bool:
    require(depth <= 64, "SkillSpector public evidence is too deeply nested")
    if isinstance(value, str):
        return STRIPE_SECRET_KEY.search(value) is not None
    if isinstance(value, list):
        return any(has_public_credentials(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return any(has_public_credentials(key, depth=depth + 1) or
                   has_public_credentials(item, depth=depth + 1) for key, item in value.items())
    return False


def redact_public_record(record: dict[str, Any]) -> dict[str, Any]:
    """Project display text after source, finding and exception identities exist.

    A source path or opaque identity cannot be rewritten without changing its
    meaning. If one contains a recognized credential, fail closed instead.
    """
    def redact(value: Any, depth: int = 0) -> Any:
        require(depth <= 64, "SkillSpector public evidence is too deeply nested")
        if isinstance(value, str):
            return STRIPE_SECRET_KEY.sub(REDACTED_CREDENTIAL, value)
        if isinstance(value, list):
            return [redact(item, depth + 1) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                cleaned = STRIPE_SECRET_KEY.sub(REDACTED_CREDENTIAL, key)
                require(cleaned not in result, "SkillSpector evidence keys collide after credential redaction")
                result[cleaned] = copy.deepcopy(item) if key in REPORT_IDENTITY_FIELDS else redact(item, depth + 1)
            return result
        return value

    result = copy.deepcopy(record)
    for key in ("skill_name", "findings", "coverage", "errors"):
        if key in result:
            result[key] = redact(result[key])
    require(not has_public_credentials(result), "Credential-shaped text remains in structural SkillSpector data")
    return result


def report_json(value: Any) -> bytes:
    """Deterministic display JSON; never used for signed directory documents.

    Reports legitimately contain fractional confidence and timing/evidence
    values. The signed feed's integer-only canonicalization remains unchanged.
    """
    def walk(item: Any, depth: int = 0) -> None:
        require(depth <= 64, "SkillSpector display JSON is too deeply nested")
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            require(math.isfinite(item), "SkillSpector display JSON contains a non-finite number")
            return
        if isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
            return
        require(isinstance(item, dict), "SkillSpector display JSON contains an unsupported value")
        keys = set()
        for key, child in item.items():
            require(isinstance(key, str), "SkillSpector display JSON key is not a string")
            identity = unicodedata.normalize("NFC", key).casefold()
            require(identity not in keys, "SkillSpector display JSON contains colliding keys")
            keys.add(identity)
            walk(child, depth + 1)

    try:
        walk(value)
        return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise PublicationError("SkillSpector display JSON is invalid") from error


def read_report_json(path: Path, *, max_bytes: int = MAX_REPORT_BYTES) -> Any:
    try:
        result = parse_scanner_json(read_bytes_bounded(path, max_bytes), str(path))
        report_json(result)  # Also rejects overflow such as 1e999, not just NaN.
        return result
    except RegistryError as error:
        raise PublicationError(str(error)) from error


def empty_record_v3(item: dict[str, Any], profile_id: str = "static-standard-v3") -> dict[str, Any]:
    require(profile_id in PROFILES, "unknown static analysis profile")
    record = empty_record(item)
    record.update(scanner=copy.deepcopy(SCANNER), profile=copy.deepcopy(PROFILES[profile_id]),
        execution={"state": "failed", "started_at": None, "finished_at": None,
                   "exit_code": None, "acquisition_seconds": None, "analysis_seconds": None},
        coverage={"status": "not_started", "fully_inspected_files": 0,
                  "partially_inspected_files": 0, "entirely_uninspected_files": 0,
                  "reasons": [], "analyzers": [], "original_findings": []},
        raw_finding_count=0, finding_group_count=0)
    return record


def safe_report_value(value: Any, *, depth: int = 0) -> Any:
    """Keep complete JSON evidence within the already bounded upstream report.

    Remove terminal/display controls, but do not shorten matching snippets or
    evidence before computing identities. A long shared prefix is not proof
    that two different findings describe the same problem.
    """
    require(depth <= 32, "SkillSpector evidence is too deeply nested")
    if isinstance(value, str):
        return clean(value, len(value))
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        require(math.isfinite(value), "SkillSpector evidence is not finite")
        return value
    if isinstance(value, list):
        return [safe_report_value(v, depth=depth + 1) for v in value]
    require(isinstance(value, dict), "SkillSpector evidence is not JSON")
    result = {}
    for key, item in value.items():
        require(isinstance(key, str), "SkillSpector evidence key is invalid")
        cleaned = clean(key, len(key))
        require(cleaned not in result, "SkillSpector evidence keys collide after sanitization")
        result[cleaned] = safe_report_value(item, depth=depth + 1)
    return result


def report_path(value: Any, root: Path) -> str:
    require(isinstance(value, str) and bool(value), "SkillSpector finding path is invalid")
    directory = value.endswith("/")
    if Path(value).is_absolute():
        try:
            value = Path(value).relative_to(root).as_posix()
            if directory:
                value += "/"
        except ValueError:
            raise PublicationError("SkillSpector finding path escapes selected root")
    core = value[:-1] if value.endswith("/") else value
    require(core and "\\" not in value and all(part not in {"", ".", ".."} for part in core.split("/")),
            "SkillSpector finding path escapes selected root")
    require(len(value) <= 1000 and clean(value, len(value)) == value,
            "SkillSpector finding path is not display-safe")
    return value


def add_coverage_reason(record: dict, code: str, message: str, *,
                        analyzer_id: str | None = None, path: str | None = None,
                        start_line: int | None = None, end_line: int | None = None,
                        seen: set[bytes] | None = None) -> None:
    reason = {"code": clean(code, 120), "message": clean(message),
              "retryable": code in RETRYABLE_REASONS}
    if analyzer_id:
        reason["analyzer_id"] = clean(analyzer_id, 200)
    if path:
        reason["path"] = clean(path, 1000)
    for key, value in (("start_line", start_line), ("end_line", end_line)):
        if value is not None:
            require(type(value) is int and 1 <= value < 2**53, "SkillSpector coverage position is invalid")
            reason[key] = value
    if start_line is not None and end_line is not None:
        require(end_line >= start_line, "SkillSpector coverage line range is invalid")
    if seen is not None:
        identity = report_json(reason)
        if identity in seen:
            return
        seen.add(identity)
        record["coverage"]["reasons"].append(reason)
    elif reason not in record["coverage"]["reasons"]:
        record["coverage"]["reasons"].append(reason)


def reference_evidence(record: dict, completeness: dict, root: Path, *, reason_keys: set[bytes]) -> None:
    """Retain reference and ledger context without inferring package intent.

    A missing path can belong to the caller's project, a dependency, or a file
    created when the skill is used. The upstream locations and snippets allow
    that distinction to be reviewed; absence alone does not establish it.
    """
    coverage = record["coverage"]
    for key in ("references", "ledger_exceptions"):
        values = completeness.get(key, [])
        require(isinstance(values, list) and len(values) <= 10_000_000, "SkillSpector reference evidence is invalid")
        coverage[key], coverage[key + "_total"] = [], len(values)
        for raw in values:
            require(isinstance(raw, dict), "SkillSpector reference evidence row is invalid")
            value = safe_report_value(raw)
            if key == "references":
                require(REFERENCE_FIELDS <= value.keys() <= REFERENCE_FIELDS | {"source_sha256"},
                        "SkillSpector reference fields are invalid")
                value["source_path"] = report_path(raw["source_path"], root)
                for field in ("line", "column"):
                    require(type(value[field]) is int and 1 <= value[field] < 2**53,
                            "SkillSpector reference position is invalid")
                require(isinstance(value["evidence"], str) and all(isinstance(value[field], str) for field in
                        ("status", "disposition", "reference_kind")) and value["status"] in {"resolved", "missing", "ambiguous", "rejected"}
                        and value["disposition"] in {"analyzed", "partial", "failed", "out_of_scope"}
                        and value["reference_kind"] in REFERENCE_KINDS, "SkillSpector reference state is invalid")
                require((value["target_path"] is not None) == (value["status"] == "resolved"),
                        "SkillSpector reference target differs from resolution")
                if value["target_path"] is not None:
                    value["target_path"] = report_path(raw["target_path"], root)
                if "source_sha256" in value:
                    require(isinstance(value["source_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"]),
                            "SkillSpector reference source digest is invalid")
                if value["status"] in REFERENCE_MESSAGES:
                    code = "reference_missing" if value["status"] == "missing" else "reference_unresolved"
                    add_coverage_reason(record, code, REFERENCE_MESSAGES[value["status"]],
                        path=value["source_path"], seen=reason_keys)
                    coverage["status"] = "partial"
                elif value["status"] == "resolved" and value["disposition"] != "analyzed":
                    add_coverage_reason(record, "referenced_uninspected", "A referenced artifact was not completely inspected.",
                        path=value["source_path"], seen=reason_keys)
                    coverage["status"] = "partial"
            else:
                require({"reason_code", "message"} <= value.keys() <= LEDGER_FIELDS,
                        "SkillSpector ledger fields are invalid")
                for field, maximum in (("reason_code", 120), ("message", MAX_REPORT_BYTES),
                                       ("phase", 200), ("error_class", 200), ("scope", 200)):
                    if field in value:
                        require(isinstance(value[field], str) and 0 < len(value[field]) <= maximum,
                                "SkillSpector ledger text is invalid")
                if "path" in value:
                    value["path"] = report_path(raw["path"], root)
                for field in ("start_line", "end_line"):
                    if value.get(field) is not None:
                        require(type(value[field]) is int and 1 <= value[field] < 2**53,
                                "SkillSpector ledger position is invalid")
                if value.get("start_line") is not None and value.get("end_line") is not None:
                    require(value["end_line"] >= value["start_line"], "SkillSpector ledger line range is invalid")
                require("outcome" not in value or isinstance(value["outcome"], str) and
                        value["outcome"] in {"completed", "partial", "failed", "skipped", "out_of_scope"},
                        "SkillSpector ledger outcome is invalid")
                require("fatal" not in value or type(value["fatal"]) is bool, "SkillSpector ledger fatal flag is invalid")
                if "analyzers" in value:
                    require(isinstance(value["analyzers"], list) and len(value["analyzers"]) <= 1000 and
                            all(isinstance(analyzer, str) and 0 < len(analyzer) <= 200 for analyzer in value["analyzers"]),
                            "SkillSpector ledger analyzers are invalid")
            coverage[key].append(value)
    coverage["reference_evidence_truncated"] = False
    # Keep this additive context below a fixed aggregate budget, leaving the
    # existing report budget for analyzer results and content findings. Every
    # input row is validated before a whole-row prefix can be omitted.
    publication_budget = MAX_REPORT_BYTES - (128 << 10)
    limit_reference_evidence(coverage, min(MAX_REFERENCE_EVIDENCE_BYTES, max(0, publication_budget // 4)))
    if coverage["reference_evidence_truncated"]:
        add_coverage_reason(record, "normalization_truncated", "Some reference or ledger evidence exceeded the publication byte or count budget.",
                            seen=reason_keys)
        coverage["status"] = "partial"
    if coverage["status"] == "partial" and record["status"] == "complete":
        record["status"] = "partial"


def limit_reference_evidence(coverage: dict, maximum: int) -> int:
    """Bound the two evidence arrays, returning bytes above their empty arrays."""
    used = 0
    for key, count_limit in (("references", 1024), ("ledger_exceptions", 100000)):
        retained = []
        for value in coverage[key][:count_limit]:
            size = len(report_json(value)) - 1 + bool(retained)
            if used + size > maximum:
                break
            retained.append(value)
            used += size
        coverage[key] = retained
    coverage["reference_evidence_truncated"] = any(
        coverage[key + "_total"] > len(coverage[key]) for key in ("references", "ledger_exceptions"))
    return used


def coverage_finding(finding: dict) -> bool:
    """Classify only coverage semantics verified in the pinned scanner source.

    AE2/3/4/6 are content signals and must remain visible. Likewise, SC9 without
    an explicit inspection limitation still reports concealed executable code.
    """
    rule, tags = finding.get("id"), finding.get("tags", [])
    if rule in {"AE1", "AE7"} and "coverage" in tags:
        return True
    if rule == "AE5" and "artifact-integrity" in tags:
        return True
    evidence = finding.get("evidence") or {}
    return (rule == "SC9" and evidence.get("excluded_inspection_incomplete") is True
            and finding.get("pattern") in {"Excluded Artifact Inspection Incomplete",
                                            "Referenced Excluded Artifact Uninspected"})


def normalize_location(location: dict, root: Path) -> dict:
    require(isinstance(location, dict), "SkillSpector occurrence is invalid")
    result = {"path": report_path(location.get("file"), root)}
    for upstream, output, minimum in (("start_line", "line", 1), ("end_line", "end_line", 1),
                                     ("start_column", "start_column", 0), ("end_column", "end_column", 0)):
        value = location.get(upstream)
        if value is not None:
            require(type(value) is int and minimum <= value < 2**53, "SkillSpector position is invalid")
            result[output] = value
    if "end_line" in result and "line" in result:
        require(result["end_line"] >= result["line"], "SkillSpector line range is invalid")
    if result.get("end_line", result.get("line")) == result.get("line") and "end_column" in result and "start_column" in result:
        require(result["end_column"] >= result["start_column"], "SkillSpector column range is invalid")
    for key in ("source_identity", "source_digest", "source_url", "transitive_depth"):
        if key in location:
            result[key] = safe_report_value(location[key])
    return result


def normalize_report_v3(record: dict[str, Any], body: bytes, returncode: int, root: Path) -> dict[str, Any]:
    # Preserve the legacy trust boundary: exact scanner, no LLMs or suppressions,
    # explicit execution and analyzer coverage, and canonical source locations.
    normalize_report(record, body, returncode, root)
    report = parse_scanner_json(body, "SkillSpector report")
    completeness = report["analysis_completeness"]
    record["execution"]["state"] = "failed" if record["status"] == "error" else "completed"
    record["execution"]["exit_code"] = returncode
    record["execution"]["finished_at"] = now()
    coverage = record["coverage"]
    reason_keys = {report_json(reason) for reason in coverage["reasons"]}
    coverage["status"] = "complete" if record["status"] == "complete" else "partial"
    for key in ("fully_inspected_files", "partially_inspected_files", "entirely_uninspected_files"):
        coverage[key] = completeness[key]
    coverage["analyzers"] = safe_report_value(completeness["analyzer_statuses"])
    for key in ("errors", "runtime_errors", "limitations", "ledger_exceptions"):
        values = report.get(key, []) if key in ("errors", "runtime_errors") else completeness.get(key, [])
        for diagnostic in values:
            if isinstance(diagnostic, dict):
                code = str(diagnostic.get("reason_code") or key)
                analyzers = diagnostic.get("analyzers", [])
                add_coverage_reason(record, code, str(diagnostic.get("message") or "Analysis coverage is incomplete."),
                    analyzer_id=diagnostic.get("analyzer_id") or (analyzers[0] if analyzers else None),
                    path=diagnostic.get("path"), seen=reason_keys)
            else:
                add_coverage_reason(record, key, str(diagnostic) or "Analysis coverage is incomplete.", seen=reason_keys)
    for analyzer in coverage["analyzers"]:
        if analyzer.get("status") not in {"completed", "not_applicable", "disabled"} or (
            analyzer.get("status") == "disabled" and analyzer.get("analyzer_id") not in DISABLED_STATIC_ANALYZERS
        ) or any(analyzer.get(key, 0) != 0 for key in ("failed", "partial", "skipped", "unaccounted")):
            add_coverage_reason(record, str(analyzer.get("reason_code") or "analyzer_incomplete"),
                str(analyzer.get("message") or "A static analyzer did not complete its planned work."),
                analyzer_id=analyzer.get("analyzer_id"), seen=reason_keys)
    reference_evidence(record, completeness, root, reason_keys=reason_keys)
    groups: dict[str, dict] = {}
    group_positions: dict[str, set[bytes]] = {}
    group_finding_ids: dict[str, set[str]] = {}
    raw_count = content_count = 0
    for raw in report["issues"]:
        finding = safe_report_value(raw)
        evidence = finding.get("evidence") or {}
        require(isinstance(evidence, dict), "SkillSpector finding evidence is invalid")
        confidence = finding.get("confidence")
        require(confidence is None or (type(confidence) in (int, float) and 0 <= confidence <= 1),
                "SkillSpector confidence is invalid")
        location = normalize_location(finding["location"], root)
        raw_occurrences = finding.get("occurrences") or [finding["location"]]
        require(isinstance(raw_occurrences, list), "SkillSpector occurrences are invalid")
        occurrences = [normalize_location(value, root) for value in raw_occurrences]
        # Preserve the original upstream shape with paths made relative. This is
        # retained for coverage signals even though they are not content findings.
        finding["location"]["file"] = location["path"]
        if finding.get("occurrences"):
            for occurrence, normalized in zip(finding["occurrences"], occurrences):
                occurrence["file"] = normalized["path"]
        count = len(occurrences)
        raw_count += count
        if finding["id"] == "SC9" and not coverage_finding(finding) and any(evidence.get(key) is True for key in
                ("excluded_inspection_incomplete", "partially_analyzed_executable", "excluded_from_analysis")):
            # A confirmed concealed executable may ALSO be outside analysis.
            # Preserve its content signal while exposing the coverage gap.
            add_coverage_reason(record, "unsupported_content",
                "Executable content was detected, but its behavior was not fully inspected.", path=location["path"], seen=reason_keys)
            coverage["status"] = "partial"
            if record["status"] == "complete":
                record["status"] = "partial"
        if coverage_finding(finding):
            coverage["original_findings"].append(finding)
            nested = evidence.get("reasons", [])
            require(isinstance(nested, list), "SkillSpector coverage evidence reasons are invalid")
            if nested:
                for reason in nested:
                    require(isinstance(reason, dict), "SkillSpector coverage reason is invalid")
                    add_coverage_reason(record, str(reason.get("reason_code") or "coverage_limitation"),
                        str(reason.get("message") or finding.get("explanation") or "Analysis coverage is incomplete."),
                        path=evidence.get("target_path") or location["path"], seen=reason_keys)
            else:
                code = "size_limit" if finding["id"] in {"AE5", "AE7"} else "unsupported_content"
                add_coverage_reason(record, str(evidence.get("inspection_limitation_reason") or code),
                    str(finding.get("explanation") or finding.get("finding") or "Artifact could not be fully inspected."),
                    path=location["path"], seen=reason_keys)
            coverage["status"] = "partial"
            if record["status"] == "complete":
                record["status"] = "partial"
            continue
        content_count += count
        # Every distinguishing upstream field participates. Locations may be
        # grouped only with the scanner's full-match fingerprint; otherwise an
        # identical message on another line is not proof of one problem.
        identity = {key: value for key, value in raw.items()
                    if key not in {"finding_id", "location", "occurrences"}}
        if not finding.get("match_fingerprint"):
            identity["locations"] = occurrences
        identity["source"] = record["source"]
        group_id = sha256_digest(report_json(identity))
        finding_id = finding.get("finding_id")
        require(finding_id is None or isinstance(finding_id, str), "SkillSpector finding ID is invalid")
        for occurrence in occurrences:
            if finding_id:
                occurrence["finding_id"] = finding_id
        if group_id not in groups:
            group = {"id": group_id, "rule": finding["id"], "severity": finding["severity"],
                "message": finding.get("explanation") or finding["finding"], **location,
                "finding_ids": [], "match_fingerprint": finding.get("match_fingerprint"),
                "evidence": evidence, "confidence": confidence, "review_status": "unreviewed",
                "occurrences": [], "raw_count": 0}
            for key in ("category", "pattern", "finding", "remediation", "code_snippet", "intent", "tags",
                        "context", "source_identity", "source_digest", "source_url", "transitive_depth"):
                if key in finding:
                    group[key] = finding[key]
            groups[group_id] = group
            group_positions[group_id] = set()
            group_finding_ids[group_id] = set()
        group = groups[group_id]
        group["raw_count"] += count
        if finding_id and finding_id not in group_finding_ids[group_id]:
            group["finding_ids"].append(finding_id)
            group_finding_ids[group_id].add(finding_id)
        for occurrence in occurrences:
            position = {k: v for k, v in occurrence.items() if k != "finding_id"}
            position_key = report_json(position)
            if position_key not in group_positions[group_id]:
                group["occurrences"].append(occurrence)
                group_positions[group_id].add(position_key)
    severity_rank = {name: rank for rank, name in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))}
    normalized = sorted(groups.values(), key=lambda f: (severity_rank[f["severity"]], f["rule"], f["path"], f.get("line", 0), f["id"]))
    if record["profile"] == PROFILES.get(record["profile"]["id"]):
        for group in normalized:
            exception = matching_exception(record["source"], record["scanner"], record["profile"], group)
            if exception is not None:
                group["review_status"] = "false_positive"
                group["exception"] = exception
    upstream_truncated = any(reason["code"] == "output_limit" for reason in coverage["reasons"])
    coverage["grouping_complete"] = not upstream_truncated
    record.update(raw_finding_count=raw_count, finding_count=content_count,
                  finding_group_count=len(normalized), findings=normalized, findings_truncated=upstream_truncated)
    if coverage["status"] != "complete" and not coverage["reasons"]:
        for error in record["errors"]:
            add_coverage_reason(record, error["code"], error["message"], seen=reason_keys)
    # The raw report has a hard byte cap, and its publication projection also
    # needs one. Never silently produce a complete report after losing evidence.
    publication_budget = MAX_REPORT_BYTES - (128 << 10)
    if len(report_json(record)) > publication_budget:
        add_coverage_reason(record, "normalization_truncated", "The complete static analysis evidence exceeded the publication byte budget.",
                            seen=reason_keys)
        record["findings_truncated"] = True
        coverage["grouping_complete"] = False
        coverage["status"] = "partial"
        if record["status"] == "complete":
            record["status"] = "partial"
        record["findings"] = []
        remaining = publication_budget - len(report_json(record))
        if remaining < 0:
            # Reference context cannot crowd out the bounded control/analyzer
            # evidence. Retain whole rows and their original totals; a capped
            # context stays an explicit coverage limitation, never a finding.
            payload = sum(len(report_json(coverage[key])) - 3 for key in ("references", "ledger_exceptions"))
            retained_payload = limit_reference_evidence(coverage, max(0, payload + remaining))
            remaining += payload - retained_payload
        require(remaining >= 0, "SkillSpector coverage evidence exceeds publication budget")
        # Compute each group's encoded size once. Re-encoding the full record
        # after every removal would make adversarial high-volume output quadratic.
        # report_json includes one terminal newline; array elements do not.
        # Retain a prefix so the severity order and whole occurrences survive.
        prefix_bytes = retained = 0
        for index, group in enumerate(normalized):
            size = len(report_json(group)) - 1 + bool(index)
            if prefix_bytes + size > remaining:
                break
            prefix_bytes += size
            retained = index + 1
        record["findings"] = normalized[:retained]
        record["findings_truncated"] = upstream_truncated or retained < len(normalized)
        coverage["grouping_complete"] = not record["findings_truncated"]
        require(len(report_json(record)) <= publication_budget,
                "SkillSpector coverage evidence exceeds publication budget")
    return redact_public_record(record)


def environment_v3(home: Path, profile_id: str, timeout: float | None = None) -> dict[str, str]:
    require(profile_id in PROFILE_DOCUMENTS, "unknown static analysis profile")
    profile = PROFILE_DOCUMENTS[profile_id]
    actual_timeout = profile["timeout_seconds"] if timeout is None else timeout
    require(type(actual_timeout) in (int, float) and math.isfinite(actual_timeout) and actual_timeout > 1,
            "static analysis needs a bounded positive process deadline")
    workflow = min(profile["workflow_seconds"], max(0.1, actual_timeout - min(15, actual_timeout / 4)))
    return environment(home) | {
        "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": str(workflow),
        "SKILLSPECTOR_MAX_STATIC_ANALYSIS_SECONDS_PER_ARTIFACT": str(min(profile["static_artifact_seconds"], workflow)),
        "SKILLSPECTOR_OSV_TIMEOUT": str(profile["osv_timeout_seconds"]),
    }


def run_scanner_v3(scanner: Path, arguments: list[str], home: Path, timeout: float,
                   profile_id: str = "static-standard-v3") -> tuple[int, bytes]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        with subprocess.Popen([str(scanner), *arguments], cwd=home,
            env=environment_v3(home, profile_id, timeout), stdout=stdout, stderr=stderr,
            start_new_session=True, preexec_fn=output_limit) as process:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Parser helper children share this new process group. Killing
                # only the scanner parent would leave work running past budget.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
            returncode = process.returncode
        require(stderr.tell() <= MAX_REPORT_BYTES, "scanner diagnostics exceed limit")
        require(stdout.tell() <= MAX_REPORT_BYTES, "scanner output exceeds limit")
        stdout.seek(0)
        return returncode, stdout.read(MAX_REPORT_BYTES + 1)


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
