#!/usr/bin/env python3
"""Rolling, bounded static SkillSpector coverage; source content remains inert."""
from __future__ import annotations

import argparse
import copy
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import jsonschema
import yaml

from scripts import skillspector_reports as legacy
from scripts.build_bridges import BridgeError, PinnedRepository
from scripts.build_discovery_index import DiscoveryError, DiscoveryInputLimitError, bounded_package_files, materialize_package
from scripts.build_registry import RegistryError, directory_tree_digest
from scripts.directory_publication import (PublicationError, canonical_json, parse_timestamp,
    read_bytes_bounded, read_json, require, sha256_digest)
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget, atomic_json

ROOT = Path(__file__).resolve().parents[1]
MAX_SOURCES = 10_000
MAX_SHARDS = 10_000
MAX_MANIFEST_BYTES = 4 << 20
MAX_SHARD_BYTES = 8 << 20
MAX_SELECTION_BYTES = 32 << 20
MAX_STATE_BYTES = 8 << 20
MAX_DISCOVERY_BYTES = 16 << 20
MAX_WORKER_BYTES = 32 << 20
MAX_TOTAL_SHARD_BYTES = 256 << 20
MAX_SHARD_RECORDS = 256
MAX_PARTITIONS = 8
MAX_ATTEMPTS = 128
CACHE_SECONDS = 7 * 86400
ERROR_RETRY_SECONDS = 86400
PREPARATION_SECONDS = 120
SCANNER = legacy.SCANNER
PROFILE_DOCUMENT = legacy.PROFILE_DOCUMENT | {
    "id": "static-only-v2", "cache_max_age_seconds": CACHE_SECONDS,
    "cache_partial": True, "error_retry_seconds": ERROR_RETRY_SECONDS,
    "preparation_timeout_seconds": PREPARATION_SECONDS,
}
PROFILE = {"id": PROFILE_DOCUMENT["id"], "digest": sha256_digest(canonical_json(PROFILE_DOCUMENT))}
SELECTION_SCHEMA = ROOT / "schemas/skillspector-auto-selection-v1.schema.json"
MANIFEST_SCHEMA = ROOT / "schemas/skillspector-manifest-v2.schema.json"
SHARD_SCHEMA = ROOT / "schemas/skillspector-shard-v2.schema.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
SHARD_PATH = re.compile(r"^shards/([0-9a-f]{64})\.json$")


@lru_cache(maxsize=8)
def validator(path: Path):
    return jsonschema.Draft202012Validator(read_json(path, max_bytes=1 << 20))


def schema(value, path: Path):
    error = next(validator(path).iter_errors(value), None)
    require(error is None, f"{path.name}: {error.message if error else ''}")


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), f"invalid {label} fields")


def timestamp(value, label):
    parsed = parse_timestamp(value, label)
    require(parsed <= datetime.now(timezone.utc), f"{label} is from the future")
    return parsed


def source_digest(item):
    return sha256_digest(canonical_json({k: item[k] for k in
        ("kind", "repository", "revision", "path", "plugin_path")}))


def logical_digest(item):
    """Scheduling identity only; never a key for reusable scan evidence."""
    subject = {key: item[key] for key in ("kind", "repository", "path", "plugin_path")}
    subject["repository"] = subject["repository"].lower()
    return sha256_digest(canonical_json(subject))


def update_history(selection, attempts, previous=None):
    """Keep the latest actual attempt for each currently selected logical root."""
    subjects = {}
    for item in selection["sources"]:
        subjects.setdefault(logical_digest(item), item)
    history = {}
    for key, entry in (previous or {}).items():
        if key in subjects:
            history[key] = {"id": subjects[key]["id"], "logical_digest": key,
                            "last_attempted_at": entry["last_attempted_at"]}
    by_id = {item["id"]: item for item in selection["sources"]}
    for attempt in attempts.values():
        key = logical_digest(by_id[attempt["id"]])
        if key not in history or attempt["last_attempted_at"] > history[key]["last_attempted_at"]:
            history[key] = {"id": subjects[key]["id"], "logical_digest": key,
                            "last_attempted_at": attempt["last_attempted_at"]}
    return history


def compatible_history(previous, selection):
    if not previous:
        return {}
    # Old v2 bundles predate scheduling history. Their already validated exact
    # attempts establish history; pending roots establish no attempt evidence.
    history = previous.get("history")
    if history is None:
        history = update_history(previous["selection"], previous["attempts"])
    return update_history(selection, {}, history)


def partition_for(repository: str, count: int = MAX_PARTITIONS) -> int:
    return int(hashlib.sha256(repository.lower().encode()).hexdigest(), 16) % count


def load_selection(path: Path):
    selection = read_json(path, max_bytes=MAX_SELECTION_BYTES)
    validate_selection(selection)
    return selection


def validate_selection(selection):
    schema(selection, SELECTION_SCHEMA)
    ids, roots = set(), set()
    for item in selection["sources"]:
        require(item["id"] not in ids, "selection IDs must be unique")
        ids.add(item["id"])
        # Plugin and standalone evidence are distinct joins, even for the same bytes.
        identity = (item["kind"], item["repository"].lower(), item["revision"], item["path"], item["plugin_path"])
        require(identity not in roots, "selection contains a repeated immutable subject")
        roots.add(identity)
        for field in ("path", "plugin_path"):
            value = item[field]
            require(value is None or value == "" or all(p not in {".", "..", ".git"} for p in value.split("/")),
                    "selection contains an unsafe path")
        if item["kind"] == "plugin_skill":
            require(isinstance(item["plugin_path"], str), "plugin skill must have a plugin path")
            prefix = item["plugin_path"] + "/" if item["plugin_path"] else ""
            relative = item["path"][len(prefix):] if item["path"].startswith(prefix) else ""
            require(relative.startswith("skills/") and len(relative.split("/")) == 2,
                    "plugin skill must be an immediate skills/* root under plugin_path")
        else:
            require(item["plugin_path"] is None, "standalone skill cannot have plugin_path")


@lru_cache(maxsize=1)
def record_validator():
    return jsonschema.Draft202012Validator(read_json(legacy.SCHEMA, max_bytes=1 << 20)["properties"]["records"]["items"])


def validate_record(record, item, generated):
    error = next(record_validator().iter_errors(record), None)
    require(error is None, "invalid static record")
    require(record["id"] == item["id"], "record ID differs from selection")
    require(all(record["source"][key] == item[key] for key in ("repository", "revision", "path")),
            "record immutable subject differs from selection")
    require(all(record[key] == item[key] for key in ("kind", "plugin_path")), "record kind differs from selection")
    require(record["status"] != "complete" or not record["errors"], "complete record has errors")
    require(record["finding_count"] >= len(record["findings"]), "invalid finding count")
    require(record["findings_truncated"] == (record["finding_count"] > len(record["findings"])), "invalid truncation flag")
    if record["scanned_at"] is not None:
        require(timestamp(record["scanned_at"], "scanned_at") <= generated, "scan is newer than artifact")
    for finding in record["findings"]:
        path = finding["path"]
        require(not Path(path).is_absolute() and "\\" not in path and ".." not in Path(path).parts,
                "finding path escapes selected root")


def validate_manifest(manifest):
    schema(manifest, MANIFEST_SCHEMA)
    require(manifest["scanner"] == SCANNER and manifest["profile"] == PROFILE, "unsupported static scanner/profile")
    timestamp(manifest["generated_at"], "generated_at")
    coverage = manifest["coverage"]
    require(coverage["reported"] == sum(s["record_count"] for s in manifest["shards"]), "incorrect reported count")
    require(coverage["selected"] == coverage["reported"] + coverage["pending"], "incorrect pending count")
    paths = set()
    for part in manifest["shards"]:
        match = SHARD_PATH.fullmatch(part["path"])
        require(match is not None and part["digest"] == "sha256:" + match[1], "shard name and digest differ")
        require(part["path"] not in paths, "repeated shard descriptor")
        paths.add(part["path"])
    require(sum(s["bytes"] for s in manifest["shards"]) <= MAX_TOTAL_SHARD_BYTES, "total shard budget exceeded")
    seen_plugins = set()
    for subject in manifest["plugin_coverage"]:
        key = (subject["repository"].lower(), subject["plugin_path"])
        require(key not in seen_plugins, "repeated plugin coverage subject")
        seen_plugins.add(key)
        require(subject["selected"] == subject["reported"] + subject["pending"], "incorrect plugin pending count")
    require(sum(subject["selected"] for subject in manifest["plugin_coverage"]) <= coverage["selected"] and
        sum(subject["reported"] for subject in manifest["plugin_coverage"]) <= coverage["reported"] and
        sum(subject["pending"] for subject in manifest["plugin_coverage"]) <= coverage["pending"],
        "plugin coverage exceeds total coverage")


def plugin_coverage(selection, records):
    """Selected root coverage is independent of the completeness of any one scan."""
    subjects = {}
    for item in selection["sources"]:
        if item["kind"] != "plugin_skill":
            continue
        key = (item["repository"].lower(), item["plugin_path"])
        counts = subjects.setdefault(key, {"repository": item["repository"], "plugin_path": item["plugin_path"],
            "selected": 0, "reported": 0, "pending": 0})
        counts["selected"] += 1
        counts["reported"] += item["id"] in records
        counts["pending"] += item["id"] not in records
    return [subjects[key] for key in sorted(subjects)]


def read_bundle(directory: Path | None):
    """Validate all persisted progress before it can supply cache evidence."""
    if directory is None or not (directory / "index.json").exists():
        return None
    require(directory.is_dir() and not directory.is_symlink(), "bundle directory must be regular")
    for name in ("index.json", "selection.json", "attempts.json"):
        require((directory / name).is_file() and not (directory / name).is_symlink(), "bundle controls must be regular files")
    manifest = read_json(directory / "index.json", max_bytes=MAX_MANIFEST_BYTES)
    validate_manifest(manifest)
    selection = load_selection(directory / "selection.json")
    digest = sha256_digest(canonical_json(selection))
    require(manifest["selection_digest"] == digest, "bundle selection digest differs")
    require(manifest["coverage"]["selected"] == len(selection["sources"]), "bundle selection count differs")
    expected = {item["id"]: item for item in selection["sources"]}
    generated = timestamp(manifest["generated_at"], "generated_at")
    records = {}
    for part in manifest["shards"]:
        path = directory / part["path"]
        require(path.is_file() and not path.is_symlink() and not path.parent.is_symlink(), "shard must be a regular file")
        body = read_bytes_bounded(path, MAX_SHARD_BYTES)
        require(len(body) == part["bytes"] and sha256_digest(body) == part["digest"], "shard bytes differ")
        shard = read_json(path, max_bytes=MAX_SHARD_BYTES)
        schema(shard, SHARD_SCHEMA)
        require(shard["scanner"] == SCANNER and shard["profile"] == PROFILE, "shard profile differs")
        require(shard["repository"] == part["repository"], "shard repository differs")
        require(len(shard["records"]) == part["record_count"], "shard record count differs")
        for record in shard["records"]:
            item = expected.get(record["id"])
            require(item is not None and record["id"] not in records, "unknown or repeated static record")
            require(item["repository"] == part["repository"], "record repository differs")
            validate_record(record, item, generated)
            records[record["id"]] = record
    state = read_json(directory / "attempts.json", max_bytes=MAX_STATE_BYTES)
    state_fields = ("schema_version", "source_commit", "generated_at", "selection_digest", "attempts")
    exact(state, (*state_fields, "history") if isinstance(state, dict) and "history" in state else state_fields, "attempt state")
    require(state["schema_version"] == 2 and state["source_commit"] == manifest["source_commit"] and
            state["generated_at"] == manifest["generated_at"] and state["selection_digest"] == digest,
            "attempt state identity differs")
    require(isinstance(state["attempts"], list) and len(state["attempts"]) <= MAX_SOURCES, "invalid attempt list")
    attempts = {}
    for attempt in state["attempts"]:
        exact(attempt, ("id", "source_digest", "last_attempted_at", "status"), "attempt")
        item = expected.get(attempt["id"])
        record = records.get(attempt["id"])
        require(item is not None and record is not None and attempt["id"] not in attempts, "unknown or repeated attempt")
        require(attempt["source_digest"] == source_digest(item) and attempt["status"] == record["status"], "attempt subject differs")
        at = timestamp(attempt["last_attempted_at"], "last_attempted_at")
        require(at <= generated, "attempt is newer than bundle")
        require(record["scanned_at"] is None or parse_timestamp(record["scanned_at"], "scanned_at") <= at,
                "attempt precedes its scan")
        attempts[attempt["id"]] = attempt
    require(set(attempts) == set(records), "attempt state must cover every reported source")
    if "history" in state:
        require(isinstance(state["history"], list) and len(state["history"]) <= MAX_SOURCES,
                "invalid logical scheduling history")
        history, history_ids = {}, set()
        for entry in state["history"]:
            exact(entry, ("id", "logical_digest", "last_attempted_at"), "logical history")
            require(isinstance(entry["id"], str) and isinstance(entry["logical_digest"], str),
                    "invalid logical history identity")
            item = expected.get(entry["id"])
            key = entry["logical_digest"]
            require(item is not None and key == logical_digest(item) and key not in history and
                    entry["id"] not in history_ids, "unknown or repeated logical history subject")
            require(timestamp(entry["last_attempted_at"], "logical last_attempted_at") <= generated,
                    "logical history is newer than bundle")
            history[key] = entry
            history_ids.add(entry["id"])
        for attempt in attempts.values():
            entry = history.get(logical_digest(expected[attempt["id"]]))
            require(entry is not None and entry["last_attempted_at"] >= attempt["last_attempted_at"],
                    "logical history precedes or omits a current attempt")
    else:
        history = update_history(selection, attempts)
    require(manifest["plugin_coverage"] == plugin_coverage(selection, records),
            "plugin coverage differs from selected and reported roots")
    summary_path = directory / "coverage.json"
    if summary_path.exists():
        require(summary_path.is_file() and not summary_path.is_symlink(), "discovery summary must be regular")
        validate_discovery_summary(read_json(summary_path, max_bytes=MAX_DISCOVERY_BYTES), selection, manifest["source_commit"])
    return {"manifest": manifest, "selection": selection, "records": records, "attempts": attempts, "history": history}


def compatible_previous(previous, selection):
    if not previous:
        return {}, {}
    records, attempts = {}, {}
    for item in selection["sources"]:
        old = previous["attempts"].get(item["id"])
        if old and old["source_digest"] == source_digest(item):
            records[item["id"]] = copy.deepcopy(previous["records"][item["id"]])
            attempts[item["id"]] = copy.deepcopy(old)
    return records, attempts


def plan_attempts(selection, previous, partition_index, partition_count, maximum_attempts, *, current=None):
    require(type(partition_count) is int and 1 <= partition_count <= MAX_PARTITIONS, "invalid partition count")
    require(type(partition_index) is int and 0 <= partition_index < partition_count, "invalid partition index")
    require(type(maximum_attempts) is int and 1 <= maximum_attempts <= MAX_ATTEMPTS, "invalid maximum attempts")
    current = current or datetime.now(timezone.utc)
    _, attempts = compatible_previous(previous, selection)
    history = compatible_history(previous, selection)
    eligible = []
    for position, item in enumerate(selection["sources"]):
        if partition_for(item["repository"], partition_count) != partition_index:
            continue
        old = attempts.get(item["id"])
        if old:
            age = (current - parse_timestamp(old["last_attempted_at"], "last_attempted_at")).total_seconds()
            deadline = ERROR_RETRY_SECONDS if old["status"] == "error" else CACHE_SECONDS
            if age < deadline:
                continue
        logical = history.get(logical_digest(item))
        if old is not None:
            priority, last_attempt, tie = 2, old["last_attempted_at"], 0
        elif logical is not None:
            priority, last_attempt, tie = 1, logical["last_attempted_at"], position
        else:
            priority, last_attempt, tie = 0, "", position
        eligible.append((priority, last_attempt, tie, item["id"], item))
    eligible.sort(key=lambda entry: entry[:4])
    return [entry[4] for entry in eligible[:maximum_attempts]]


def scan_selected(scanner, item, pinned, budget):
    record = legacy.empty_record(item)
    try:
        pinned.work_budget = WorkBudget(min(PREPARATION_SECONDS, budget.remaining()))
        files = bounded_package_files(pinned, item["path"], max_files=legacy.MAX_FILES,
            max_file_bytes=legacy.MAX_TREE_BYTES, max_tree_bytes=legacy.MAX_TREE_BYTES)
        require(any(path == "SKILL.md" for path, _, _ in files), "selected root has no SKILL.md")
        with tempfile.TemporaryDirectory(prefix="uap-skillspector-") as directory:
            home = Path(directory)
            root = home / "content"
            root.mkdir()
            materialize_package(files, root, pinned.work_budget)
            digest = directory_tree_digest(root)
            record["source"]["content_digest"] = digest
            document = (root / "SKILL.md").read_text(encoding="utf-8")
            if document.startswith("---\n") and "\n---" in document[4:]:
                header = document[4:].split("\n---", 1)[0]
                require(len(header.encode()) <= 65536, "skill frontmatter exceeds limit")
                frontmatter = yaml.safe_load(header)
                if isinstance(frontmatter, dict) and isinstance(frontmatter.get("name"), str):
                    record["skill_name"] = legacy.clean(frontmatter["name"], 200) or None
            record["scanned_at"] = legacy.now()
            code, body = legacy.run_scanner(scanner, ["scan", str(root), *PROFILE_DOCUMENT["arguments"]],
                home, min(legacy.SCAN_TIMEOUT, budget.remaining()))
            require(directory_tree_digest(root) == digest, "selected bytes changed during scan")
            return legacy.normalize_report(record, body, code, root)
    except subprocess.TimeoutExpired:
        legacy.add_error(record, "scan_timeout", "Static scan exceeded its bounded deadline.")
    except CheckpointYield:
        legacy.add_error(record, "preparation_timeout", "Source preparation exceeded its bounded deadline.")
    except DiscoveryInputLimitError as error:
        legacy.add_error(record, "input_limit_exceeded", f"Selected skill exceeds the {legacy.MAX_FILES}-file / "
            f"{legacy.MAX_TREE_BYTES}-byte static scan input limits: {error}")
    except (BridgeError, DiscoveryError, PublicationError, RegistryError, OSError, ValueError,
            RecursionError, yaml.YAMLError, subprocess.SubprocessError):
        legacy.add_error(record, "scan_failed", "Selected skill could not be acquired, parsed, or scanned completely.")
    record["status"] = "error"
    return record


def scan_partition(selection, scanner, previous, *, source_commit, partition_index=0,
                   partition_count=MAX_PARTITIONS, maximum_attempts=MAX_ATTEMPTS,
                   budget_seconds=2100, mirror_root=None):
    validate_selection(selection)
    require(SHA.fullmatch(source_commit) is not None, "invalid source commit")
    require(type(budget_seconds) in (int, float) and 0 < budget_seconds <= 2100, "invalid scan budget")
    legacy.verify_scanner(scanner)
    budget = WorkBudget(budget_seconds)
    chosen = plan_attempts(selection, previous, partition_index, partition_count, maximum_attempts)
    groups = {}
    for item in chosen:
        groups.setdefault((item["repository"], item["revision"]), []).append(item)
    outcomes = []
    for (repository, revision), items in groups.items():
        try:
            remaining = budget.remaining()
        except CheckpointYield:
            break
        if remaining < 1:
            break
        try:
            pinned = PinnedRepository(repository, revision, mirror_root,
                github_token=os.environ.get("GITHUB_TOKEN") if mirror_root is None else None,
                work_budget=WorkBudget(min(PREPARATION_SECONDS, budget.remaining())))
        except (BridgeError, OSError, subprocess.SubprocessError, CheckpointYield):
            for item in items:
                record = legacy.empty_record(item)
                legacy.add_error(record, "acquisition_failed", "Selected immutable source could not be acquired.")
                outcomes.append({"id": item["id"], "source_digest": source_digest(item),
                    "last_attempted_at": legacy.now(), "record": record})
            continue
        try:
            for item in items:
                try:
                    if budget.remaining() < 1:
                        break
                except CheckpointYield:
                    break
                record = scan_selected(scanner, item, pinned, budget)
                outcomes.append({"id": item["id"], "source_digest": source_digest(item),
                    "last_attempted_at": legacy.now(), "record": record})
        finally:
            pinned.close()
    return {"schema_version": 2, "source_commit": source_commit, "generated_at": legacy.now(),
        "selection_digest": sha256_digest(canonical_json(selection)), "scanner": SCANNER, "profile": PROFILE,
        "partition": {"index": partition_index, "count": partition_count}, "attempts": outcomes}


def validate_worker(worker, selection, source_commit):
    exact(worker, ("schema_version", "source_commit", "generated_at", "selection_digest", "scanner", "profile", "partition", "attempts"), "worker")
    require(worker["schema_version"] == 2 and worker["source_commit"] == source_commit and
            worker["scanner"] == SCANNER and worker["profile"] == PROFILE and
            worker["selection_digest"] == sha256_digest(canonical_json(selection)), "worker provenance differs")
    generated = timestamp(worker["generated_at"], "worker generated_at")
    part = worker["partition"]
    exact(part, ("index", "count"), "worker partition")
    require(type(part["count"]) is int and 1 <= part["count"] <= MAX_PARTITIONS and
            type(part["index"]) is int and 0 <= part["index"] < part["count"], "invalid worker partition")
    require(isinstance(worker["attempts"], list) and len(worker["attempts"]) <= MAX_ATTEMPTS, "worker exceeds attempt limit")
    expected, seen = {item["id"]: item for item in selection["sources"]}, set()
    for attempt in worker["attempts"]:
        exact(attempt, ("id", "source_digest", "last_attempted_at", "record"), "worker attempt")
        item = expected.get(attempt["id"])
        require(item is not None and attempt["id"] not in seen, "unknown or repeated worker attempt")
        seen.add(attempt["id"])
        require(partition_for(item["repository"], part["count"]) == part["index"], "worker subject belongs to another partition")
        require(attempt["source_digest"] == source_digest(item), "worker source digest differs")
        at = timestamp(attempt["last_attempted_at"], "last_attempted_at")
        require(at <= generated, "attempt is newer than worker")
        validate_record(attempt["record"], item, at)
    return worker


def shard_document(repository, records):
    return {"schema_version": 2, "scanner": SCANNER, "profile": PROFILE, "repository": repository, "records": records}


def write_bounded(path, document, maximum):
    body = canonical_json(document)
    require(len(body) <= maximum, f"{path.name} exceeds byte limit")
    # Checkpoint helper uses atomic replace and fsync; its own cap is 32 MiB.
    atomic_json(path, document)
    return body


def validate_discovery_summary(summary, selection, source_commit):
    """The resolution cache is data, and must describe exactly this selection."""
    base_fields = ("schema_version", "source_commit", "generated_at", "scope", "catalog", "bounds",
        "listings_observed", "repositories_observed", "repositories_resolved", "repositories_retained",
        "selected_roots", "selection_digest", "complete", "selection_truncated", "diagnostic_counts",
        "diagnostics", "diagnostics_truncated", "resolution_cache")
    outcome_fields = ("source_states", "plugin_states", "repository_aliases", "catalog_coverage")
    extended = isinstance(summary, dict) and any(field in summary for field in outcome_fields)
    exact(summary, base_fields + outcome_fields if extended else base_fields, "discovery summary")
    require(summary["schema_version"] == 1 and summary["source_commit"] == source_commit and
        summary["scope"] == "bounded_catalog_and_reviewed_sources" and
        summary["selection_digest"] == sha256_digest(canonical_json(selection)) and
        summary["selected_roots"] == len(selection["sources"]), "discovery summary identity differs")
    timestamp(summary["generated_at"], "discovery generated_at")
    for field in ("listings_observed", "repositories_observed", "repositories_resolved", "repositories_retained", "selected_roots"):
        require(type(summary[field]) is int and 0 <= summary[field] <= MAX_SOURCES, "invalid discovery count")
    for field in ("complete", "selection_truncated", "diagnostics_truncated"):
        require(type(summary[field]) is bool, "invalid discovery completeness")
    bounds = summary["bounds"]
    exact(bounds, ("pages", "listings", "roots"), "discovery bounds")
    require(type(bounds["pages"]) is int and 1 <= bounds["pages"] <= 50 and
        bounds["listings"] == MAX_SOURCES and bounds["roots"] == MAX_SOURCES, "unsupported discovery bounds")
    require(isinstance(summary["catalog"], dict) and type(summary["catalog"].get("complete")) is bool,
        "invalid catalog diagnostics")
    if "directory" in summary["catalog"]:
        directory = summary["catalog"]["directory"]
        exact(directory, ("state", "reason", "sequence", "source_commit", "snapshot_digest"), "Directory acquisition identity")
        require(directory["state"] in {"resolved", "unavailable"}, "invalid Directory acquisition state")
        if directory["state"] == "resolved":
            require(directory["reason"] is None and type(directory["sequence"]) is int and
                1 <= directory["sequence"] < 2**53 and isinstance(directory["source_commit"], str) and
                SHA.fullmatch(directory["source_commit"]) is not None and isinstance(directory["snapshot_digest"], str) and
                re.fullmatch(r"sha256:[0-9a-f]{64}", directory["snapshot_digest"]) is not None, "invalid Directory snapshot identity")
        else:
            require(directory["reason"] == "directory_acquisition_failed" and
                all(directory[key] is None for key in ("sequence", "source_commit", "snapshot_digest")) and
                not summary["complete"], "unavailable Directory cannot claim complete discovery")
    require(isinstance(summary["diagnostic_counts"], dict) and all(isinstance(k, str) and
        type(v) is int and v >= 0 for k, v in summary["diagnostic_counts"].items()), "invalid diagnostic counts")

    def diagnostics(values):
        require(isinstance(values, list) and len(values) <= 256, "invalid discovery diagnostics")
        for value in values:
            require(isinstance(value, dict) and set(value) <= {"code", "repository", "id", "count", "path", "candidates"} and
                isinstance(value.get("code"), str) and 0 < len(value["code"]) <= 200, "invalid discovery diagnostic")
            require(all(isinstance(v, str) and len(v) <= (1025 if k == "id" else 1000) and
                not any(ord(char) < 32 or ord(char) == 127 for char in v)
                for k, v in value.items() if k not in {"count", "candidates"}),
                "invalid diagnostic text")
            require("count" not in value or type(value["count"]) is int and value["count"] >= 0, "invalid diagnostic count")
            if "candidates" in value:
                require(isinstance(value["candidates"], list) and len(value["candidates"]) <= 64 and
                    all(isinstance(path, str) and len(path) <= 1000 and
                        re.fullmatch(r"(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)?", path) is not None and
                        not any(part in {".", ".."} for part in path.split("/")) for path in value["candidates"]) and
                    len(set(value["candidates"])) == len(value["candidates"]) and
                    type(value.get("count")) is int and value["count"] >= len(value["candidates"]),
                    "invalid discovery candidate paths")

    diagnostics(summary["diagnostics"])
    cache = summary["resolution_cache"]
    require(isinstance(cache, dict) and len(cache) <= MAX_SOURCES, "invalid resolution cache")
    subjects = {item["id"]: item for item in selection["sources"]}
    for repository, entry in cache.items():
        exact(entry, ("revision", "hints_digest", "selected_ids", "diagnostics"), "resolution cache entry")
        require(isinstance(repository, str) and len(repository) <= 200 and
            isinstance(entry["revision"], str) and SHA.fullmatch(entry["revision"]) is not None and
            isinstance(entry["hints_digest"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", entry["hints_digest"]) is not None,
            "invalid cached repository identity")
        require(isinstance(entry["selected_ids"], list) and len(entry["selected_ids"]) <= MAX_SOURCES and
            len(set(entry["selected_ids"])) == len(entry["selected_ids"]), "invalid cached selection IDs")
        for identifier in entry["selected_ids"]:
            item = subjects.get(identifier)
            require(item is not None and item["repository"].lower() == repository.lower() and
                item["revision"] == entry["revision"], "cached subject differs from selection")
        diagnostics(entry["diagnostics"])
    if extended:
        def text(value, maximum=200):
            return isinstance(value, str) and 0 < len(value) <= maximum and not any(ord(c) < 32 or ord(c) == 127 for c in value)

        def path(value):
            return isinstance(value, str) and len(value) <= 1000 and \
                re.fullmatch(r"(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)?", value) is not None and \
                not any(part in {".", ".."} for part in value.split("/"))

        def revision(value):
            return value is None or isinstance(value, str) and SHA.fullmatch(value) is not None

        def identities(values):
            require(isinstance(values, list) and len(values) <= MAX_SOURCES and
                all(isinstance(identifier, str) and identifier in subjects for identifier in values) and
                len(set(values)) == len(values), "invalid resolved selection IDs")

        source_states = summary["source_states"]
        require(isinstance(source_states, list) and summary["listings_observed"] <= len(source_states) <= 2 * MAX_SOURCES,
            "invalid source resolution states")
        observed_ids = set()
        for state in source_states:
            exact(state, ("id", "repository", "state", "current", "reason", "revision", "path", "selected_ids", "candidates"),
                "source resolution state")
            require(text(state["id"], 1025) and state["id"] not in observed_ids and text(state["repository"], 512),
                "invalid source resolution identity")
            observed_ids.add(state["id"])
            require(state["state"] in {"resolved", "historical", "unresolved", "unavailable", "unsupported"} and
                type(state["current"]) is bool and state["current"] == (state["state"] == "resolved") and
                (state["reason"] is None if state["current"] else text(state["reason"])), "invalid source resolution status")
            require(revision(state["revision"]) and (state["path"] is None or path(state["path"])),
                "invalid resolved source identity")
            identities(state["selected_ids"])
            require(bool(state["selected_ids"]) == (state["state"] in {"resolved", "historical"}),
                "source resolution does not match selected subjects")
            if state["current"]:
                require(state["revision"] is not None and state["path"] is not None and
                    all(subjects[identifier]["revision"] == state["revision"] and
                        subjects[identifier]["repository"].casefold() == state["repository"].casefold() and
                        subjects[identifier]["path"] == state["path"] for identifier in state["selected_ids"]),
                    "current resolution differs from immutable subject")
            require(isinstance(state["candidates"], list) and len(state["candidates"]) <= 64 and
                all(path(candidate) for candidate in state["candidates"]) and
                len(set(state["candidates"])) == len(state["candidates"]), "invalid source resolution candidates")

        coverage = summary["catalog_coverage"]
        kinds = ("resolved", "historical", "unresolved", "unavailable", "unsupported")
        exact(coverage, ("observed", *kinds), "catalog coverage")
        require(all(type(count) is int and 0 <= count <= MAX_SOURCES for count in coverage.values()) and
            coverage["observed"] == summary["listings_observed"] and
            sum(coverage[kind] for kind in kinds) == coverage["observed"] and
            all(coverage[kind] == sum(state["state"] == kind for state in source_states[:coverage["observed"]])
                for kind in kinds), "catalog coverage differs from source outcomes")

        plugin_states = summary["plugin_states"]
        require(isinstance(plugin_states, list) and len(plugin_states) <= MAX_SOURCES, "invalid plugin resolution states")
        plugin_ids = set()
        for state in plugin_states:
            exact(state, ("id", "repository", "plugin_path", "revision", "state", "reason", "skills_total", "selected_ids"),
                "plugin resolution state")
            require(text(state["id"]) and state["id"] not in plugin_ids and text(state["repository"]) and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*", state["repository"]) is not None and
                path(state["plugin_path"]) and revision(state["revision"]), "invalid plugin resolution identity")
            plugin_ids.add(state["id"])
            require(state["state"] in {"resolved", "not_applicable", "unresolved", "unavailable"} and
                (state["reason"] is None if state["state"] == "resolved" else text(state["reason"])) and
                (state["skills_total"] is None or type(state["skills_total"]) is int and 0 <= state["skills_total"] <= MAX_SOURCES),
                "invalid plugin resolution status")
            identities(state["selected_ids"])
            require(all(subjects[identifier]["kind"] == "plugin_skill" and
                subjects[identifier]["repository"].casefold() == state["repository"].casefold() and
                subjects[identifier]["plugin_path"] == state["plugin_path"] for identifier in state["selected_ids"]),
                "plugin resolution differs from selected subjects")
            if state["state"] == "resolved":
                require(state["revision"] is not None and bool(state["selected_ids"]) and
                    len(state["selected_ids"]) == state["skills_total"] and
                    all(subjects[identifier]["revision"] == state["revision"] for identifier in state["selected_ids"]),
                    "resolved plugin inventory is incomplete")
            if state["state"] == "not_applicable":
                require(state["skills_total"] == 0 and not state["selected_ids"], "non-skill plugin has scan subjects")

        aliases = summary["repository_aliases"]
        require(isinstance(aliases, list) and len(aliases) <= MAX_SOURCES, "invalid repository aliases")
        alias_ids = set()
        for alias in aliases:
            exact(alias, ("repository", "canonical_repository", "revision"), "repository alias")
            require(all(text(alias[key]) and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*", alias[key]) is not None
                for key in ("repository", "canonical_repository")) and alias["repository"] not in alias_ids and
                alias["repository"].casefold() != alias["canonical_repository"].casefold() and
                alias["revision"] is not None and revision(alias["revision"]), "invalid verified repository alias")
            alias_ids.add(alias["repository"])
    return summary


def merge_reports(selection, previous, workers, *, source_commit, output_dir, discovery_summary=None):
    validate_selection(selection)
    require(SHA.fullmatch(source_commit) is not None, "invalid source commit")
    require(workers, "worker artifacts are required")
    records, attempts = compatible_previous(previous, selection)
    history = compatible_history(previous, selection)
    partitions, seen = set(), set()
    expected_count = workers[0]["partition"]["count"]
    for worker in workers:
        validate_worker(worker, selection, source_commit)
        part = worker["partition"]
        require(part["count"] == expected_count and part["index"] not in partitions, "repeated/inconsistent worker partition")
        partitions.add(part["index"])
        for outcome in worker["attempts"]:
            require(outcome["id"] not in seen, "repeated attempt across workers")
            seen.add(outcome["id"])
            old = attempts.get(outcome["id"])
            require(old is None or outcome["last_attempted_at"] >= old["last_attempted_at"], "worker regresses an attempt")
            records[outcome["id"]] = outcome["record"]
            attempts[outcome["id"]] = {key: outcome[key] for key in ("id", "source_digest", "last_attempted_at")}
            attempts[outcome["id"]]["status"] = outcome["record"]["status"]
    require(partitions == set(range(expected_count)), "missing worker partition")
    history = update_history(selection, attempts, history)
    output_dir.mkdir(parents=True, exist_ok=True)
    grouped = defaultdict(list)
    for record in sorted(records.values(), key=lambda r: r["id"]):
        grouped[record["source"]["repository"]].append(record)
    descriptors = []
    for repository, group in sorted(grouped.items()):
        parts, pending = [], []
        overhead = len(canonical_json(shard_document(repository, [])))
        pending_bytes = overhead
        for record in group:
            record_bytes = len(canonical_json(record)) + 1
            if pending and (len(pending) == MAX_SHARD_RECORDS or pending_bytes + record_bytes > MAX_SHARD_BYTES):
                parts.append(pending)
                pending = []
                pending_bytes = overhead
            pending.append(record)
            pending_bytes += record_bytes
        if pending:
            parts.append(pending)
        for part in parts:
            shard = shard_document(repository, part)
            body = canonical_json(shard)
            require(len(body) <= MAX_SHARD_BYTES, "single record exceeds shard budget")
            digest = sha256_digest(body)
            path = "shards/" + digest.removeprefix("sha256:") + ".json"
            write_bounded(output_dir / path, shard, MAX_SHARD_BYTES)
            descriptors.append({"repository": repository, "path": path, "digest": digest,
                                "bytes": len(body), "record_count": len(part)})
    generated = legacy.now()
    digest = sha256_digest(canonical_json(selection))
    manifest = {"schema_version": 2, "source_commit": source_commit, "generated_at": generated,
        "scope": "selected_sources", "scanner": SCANNER, "profile": PROFILE, "selection_digest": digest,
        "coverage": {"selected": len(selection["sources"]), "reported": len(records), "pending": len(selection["sources"]) - len(records)},
        "plugin_coverage": plugin_coverage(selection, records),
        "shards": descriptors}
    validate_manifest(manifest)
    write_bounded(output_dir / "selection.json", selection, MAX_SELECTION_BYTES)
    write_bounded(output_dir / "attempts.json", {"schema_version": 2, "source_commit": source_commit,
        "generated_at": generated, "selection_digest": digest,
        "attempts": sorted(attempts.values(), key=lambda a: a["id"]),
        "history": sorted(history.values(), key=lambda entry: entry["logical_digest"])}, MAX_STATE_BYTES)
    if discovery_summary is not None:
        summary = read_json(discovery_summary, max_bytes=MAX_DISCOVERY_BYTES)
        validate_discovery_summary(summary, selection, source_commit)
        write_bounded(output_dir / "coverage.json", summary, MAX_DISCOVERY_BYTES)
    write_bounded(output_dir / "index.json", manifest, MAX_MANIFEST_BYTES)
    read_bundle(output_dir)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--scanner", type=Path, required=True)
    scan.add_argument("--partition-index", type=int, required=True)
    scan.add_argument("--partition-count", type=int, default=MAX_PARTITIONS)
    scan.add_argument("--maximum-attempts", type=int, default=MAX_ATTEMPTS)
    scan.add_argument("--budget-seconds", type=int, default=2100)
    scan.add_argument("--mirror-root", type=Path)
    scan.add_argument("--output", type=Path, required=True)
    merge = commands.add_parser("merge")
    merge.add_argument("--workers", type=Path, nargs="+", required=True)
    merge.add_argument("--output-dir", type=Path, required=True)
    merge.add_argument("--discovery-summary", type=Path)
    for command in (scan, merge):
        command.add_argument("--selection", type=Path, required=True)
        command.add_argument("--previous-dir", type=Path)
        command.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        selection = load_selection(args.selection)
        previous = read_bundle(args.previous_dir)
        if args.command == "scan":
            worker = scan_partition(selection, args.scanner.resolve(), previous, source_commit=args.source_commit,
                partition_index=args.partition_index, partition_count=args.partition_count,
                maximum_attempts=args.maximum_attempts, budget_seconds=args.budget_seconds, mirror_root=args.mirror_root)
            validate_worker(worker, selection, args.source_commit)
            write_bounded(args.output, worker, MAX_WORKER_BYTES)
        else:
            workers = [read_json(path, max_bytes=MAX_WORKER_BYTES) for path in args.workers]
            manifest = merge_reports(selection, previous, workers, source_commit=args.source_commit,
                output_dir=args.output_dir, discovery_summary=args.discovery_summary)
            print(canonical_json(manifest["coverage"]).decode().strip())
        return 0
    except (PublicationError, CheckpointYield, OSError, ValueError, KeyError, TypeError, RecursionError,
            subprocess.SubprocessError) as error:
        print(f"SkillSpector coverage failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
