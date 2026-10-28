#!/usr/bin/env python3
"""Bounded SkillSpector queue with separate execution and analysis evidence."""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from scripts import skillspector_coverage as v2
from scripts import skillspector_reports as scanner
from scripts import skillspector_contract as contract
from scripts.build_bridges import BridgeError, PinnedRepository
from scripts.build_discovery_index import DiscoveryError, DiscoveryInputLimitError, materialize_package
from scripts.skillspector_acquisition import AcquisitionTransferLimit, bounded_package_files
from scripts.build_registry import RegistryError, directory_tree_digest
from scripts.directory_publication import PublicationError, canonical_json, format_timestamp, parse_timestamp, require, sha256_digest
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget

SCANNER, PROFILE = scanner.SCANNER, contract.PROFILE
MAX_SOURCES, MAX_PARTITIONS, MAX_ATTEMPTS = v2.MAX_SOURCES, v2.MAX_PARTITIONS, v2.MAX_ATTEMPTS
MAX_MANIFEST_BYTES, MAX_STATE_BYTES = 16 << 20, 64 << 20
MAX_SHARD_BYTES, MAX_SELECTION_BYTES = v2.MAX_SHARD_BYTES, v2.MAX_SELECTION_BYTES
MAX_DISCOVERY_BYTES, MAX_WORKER_BYTES = v2.MAX_DISCOVERY_BYTES, v2.MAX_WORKER_BYTES
MAX_TOTAL_SHARD_BYTES, MAX_SHARD_RECORDS = v2.MAX_TOTAL_SHARD_BYTES, v2.MAX_SHARD_RECORDS
SHA, SHARD_PATH = v2.SHA, v2.SHARD_PATH
PREPARATION_SECONDS = 120
RESOURCE_REASONS = frozenset({"scan_timeout", "runtime_limit", "archive_time_limit", "size_limit",
    "input_limit_exceeded", "acquisition_transfer_limit", "total_bytes_limit", "artifact_count_limit", "output_limit", "normalization_truncated"})
TRANSIENT_REASONS = frozenset({"acquisition_failed", "preparation_timeout", "network_error", "network_timeout",
    "osv_request_failed", "osv_timeout"})
PERMANENT_REASONS = frozenset({"static_parse_limit", "reference_missing", "reference_unresolved",
    "unsupported_content", "reference_extraction_limit", "opaque_content", "obfuscated_instruction_text",
    "excluded_executable_content", "source_invalid"})
read_json = scanner.read_report_json
report_json = scanner.report_json
validate_selection = v2.validate_selection
validate_discovery_summary = v2.validate_discovery_summary
source_digest, logical_digest, partition_for = v2.source_digest, v2.logical_digest, v2.partition_for


def write_bounded(path, value, maximum):
    body = report_json(value)
    require(len(body) <= maximum, f"{path.name} exceeds byte limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink() and not path.parent.is_symlink(), "report output must be regular")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".report-", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return body


def load_selection(path):
    selection = read_json(path, max_bytes=MAX_SELECTION_BYTES)
    validate_selection(selection)
    return selection


def validate_manifest(manifest, *, current_policy=False):
    if manifest.get("schema_version") == 2:
        return v2.validate_manifest(manifest)
    v2.schema(manifest, contract.MANIFEST_SCHEMA)
    require(len(manifest["profiles"]) == 2 and
            {profile["id"] for profile in manifest["profiles"]} == set(scanner.PROFILES), "invalid declared profile set")
    if current_policy:
        require(manifest["scanner"] == SCANNER and manifest["profile"] == PROFILE and
                manifest["profiles"] == list(scanner.PROFILES.values()), "unsupported current report policy")
    v2.timestamp(manifest["generated_at"], "generated_at")
    coverage = manifest["coverage"]
    def check_counts(counts):
        require(counts["selected"] == counts["complete"] + counts["partial"] + counts["error"] + counts["pending"],
                "analysis coverage does not partition selected sources")
        require(counts["reported"] == counts["complete"] + counts["partial"] + counts["error"] + counts["stale"] and
                counts["stale"] <= counts["pending"], "historical evidence counts differ")
    check_counts(coverage)
    require(coverage["reported"] == sum(part["record_count"] for part in manifest["shards"]), "reported count differs")
    seen = set()
    for part in manifest["shards"]:
        match = SHARD_PATH.fullmatch(part["path"])
        require(match is not None and part["digest"] == "sha256:" + match[1] and part["path"] not in seen,
                "invalid or repeated immutable shard")
        seen.add(part["path"])
    require(sum(part["bytes"] for part in manifest["shards"]) <= MAX_TOTAL_SHARD_BYTES, "total report budget exceeded")
    plugins = set()
    for plugin in manifest["plugin_coverage"]:
        key = (plugin["repository"].lower(), plugin["plugin_path"])
        require(key not in plugins, "repeated plugin coverage")
        plugins.add(key)
        check_counts(plugin)
    for key in coverage:
        require(sum(plugin[key] for plugin in manifest["plugin_coverage"]) <= coverage[key], "plugin totals exceed coverage")
    return manifest


def read_bundle(directory):
    if directory is None or not (directory / "index.json").exists():
        return None
    for name in ("index.json", "selection.json", "attempts.json"):
        require((directory / name).is_file() and not (directory / name).is_symlink(), "bundle controls must be regular files")
    manifest = read_json(directory / "index.json", max_bytes=MAX_MANIFEST_BYTES)
    if manifest.get("schema_version") == 2:
        return v2.read_bundle(directory)
    require(directory.is_dir() and not directory.is_symlink(), "bundle must be regular")
    validate_manifest(manifest)
    selection = load_selection(directory / "selection.json")
    require(manifest["selection_digest"] == sha256_digest(canonical_json(selection)), "selection digest differs")
    generated = v2.timestamp(manifest["generated_at"], "generated_at")
    expected = {item["id"]: item for item in selection["sources"]}
    records = {}
    for part in manifest["shards"]:
        path = directory / part["path"]
        require(not path.is_symlink() and not path.parent.is_symlink(), "shard must be regular")
        body = v2.read_bytes_bounded(path, MAX_SHARD_BYTES)
        require(len(body) == part["bytes"] and sha256_digest(body) == part["digest"], "immutable shard bytes differ")
        shard = read_json(path, max_bytes=MAX_SHARD_BYTES)
        v2.schema(shard, contract.SHARD_SCHEMA)
        require(shard["scanner"] == manifest["scanner"] and shard["profile"] == manifest["profile"] and
                shard["repository"] == part["repository"] and len(shard["records"]) == part["record_count"],
                "shard provenance differs")
        for record in shard["records"]:
            item = expected.get(record["id"])
            require(item is not None and record["id"] not in records, "unknown or repeated report")
            require(item["repository"] == part["repository"], "shard subject differs")
            contract.validate_record(record, item, generated, scheduled=True,
                allowed_profiles=manifest["profiles"], scanner_identity=manifest["scanner"],
                repository_aliases=manifest["repository_aliases"])
            records[record["id"]] = record
    require(manifest["coverage"] == contract.analysis_counts(selection, records), "analysis counts differ from evidence")
    require(manifest["plugin_coverage"] == contract.plugin_counts(selection, records), "plugin counts differ from evidence")
    state = read_json(directory / "attempts.json", max_bytes=MAX_STATE_BYTES)
    v2.exact(state, ("schema_version", "source_commit", "generated_at", "selection_digest", "attempts", "queue_cursor"), "queue state")
    require(state["schema_version"] == 3 and all(state[key] == manifest[key] for key in
            ("source_commit", "generated_at", "selection_digest")), "queue provenance differs")
    require(type(state["queue_cursor"]) is int and 0 <= state["queue_cursor"] < 3, "invalid queue cursor")
    require(isinstance(state["attempts"], list) and len(state["attempts"]) <= MAX_SOURCES, "invalid attempts")
    attempts = {}
    for attempt in state["attempts"]:
        validate_attempt(attempt, expected, generated, manifest=manifest)
        require(attempt["id"] not in attempts and attempt["id"] in records, "duplicate attempt or missing report")
        require(records[attempt["id"]]["retry"] == retry_summary(attempt) and
                records[attempt["id"]]["attempt_history"] == attempt["history"], "report retry state differs")
        attempts[attempt["id"]] = attempt
    require(all(record["retry"]["attempt_count"] == 0 or identifier in attempts
                for identifier, record in records.items()), "report retry state has no persisted attempt")
    summary = None
    if (directory / "coverage.json").exists():
        require(not (directory / "coverage.json").is_symlink(), "discovery summary must be regular")
        summary = read_json(directory / "coverage.json", max_bytes=MAX_DISCOVERY_BYTES)
        validate_discovery_summary(summary, selection, manifest["source_commit"])
        for key in ("source_states", "plugin_states", "repository_aliases", "catalog_coverage"):
            require(manifest[key] == summary.get(key, None if key == "catalog_coverage" else []), "manifest discovery differs")
        current_ids = {identifier for entry in summary.get("source_states", []) if entry["current"] for identifier in entry["selected_ids"]}
        historical_ids = {identifier for entry in summary.get("source_states", []) if not entry["current"]
                          for identifier in entry["selected_ids"]} - current_ids
        require(all(records[identifier]["freshness"] == "historical" for identifier in historical_ids if identifier in records),
                "unavailable source is presented as current analysis")
    else:
        require(not any(manifest[key] for key in ("source_states", "plugin_states", "repository_aliases", "catalog_coverage")),
                "discovery metadata requires its validated summary")
    return {"manifest": manifest, "selection": selection, "records": records, "attempts": attempts,
            "queue_cursor": state["queue_cursor"], "discovery": summary}


def validate_attempt(attempt, expected, generated, *, manifest=None):
    v2.exact(attempt, ("id", "source_digest", "profile", "scanner", "policy_digest", "last_attempted_at", "status",
        "attempt_count", "fingerprint", "next_attempt_at", "next_profile", "disposition", "reason", "history"), "attempt")
    item = expected.get(attempt["id"])
    require(item is not None and attempt["source_digest"] == source_digest(item), "attempt subject differs")
    expected_scanner = manifest["scanner"] if manifest else SCANNER
    expected_profiles = manifest["profiles"] if manifest else list(scanner.PROFILES.values())
    expected_policy = manifest["profile"] if manifest else PROFILE
    require(attempt["scanner"] == expected_scanner and attempt["profile"] in expected_profiles and
            attempt["policy_digest"] == expected_policy["digest"], "attempt scanner policy differs")
    require(v2.timestamp(attempt["last_attempted_at"], "last_attempted_at") <= generated, "attempt is from future")
    schema = v2.validator(contract.RECORD_SCHEMA).schema
    import jsonschema
    for value, specification in ((retry_summary(attempt), schema["properties"]["retry"]),
                                 (attempt["history"], schema["properties"]["attempt_history"])):
        require(next(jsonschema.Draft202012Validator(specification).iter_errors(value), None) is None, "invalid retry/history shape")
    require(0 < attempt["attempt_count"] <= contract.RETRY_POLICY["maximum_attempts_per_identity"] and
            bool(attempt["history"]) and attempt["history"][-1]["at"] == attempt["last_attempted_at"], "invalid bounded attempt history")
    require(attempt["history"][-1]["status"] == attempt["status"] and
            attempt["history"][-1]["profile"] == attempt["profile"] and
            attempt["history"][-1]["fingerprint"] == attempt["fingerprint"], "attempt differs from final history entry")
    require(all(v2.timestamp(entry["at"], "history.at") <= generated for entry in attempt["history"]), "history is from future")
    if attempt["next_attempt_at"] is not None:
        require(parse_timestamp(attempt["next_attempt_at"], "next_attempt_at") >=
                parse_timestamp(attempt["last_attempted_at"], "last_attempted_at"), "retry precedes attempt")
    require((attempt["disposition"] == "scheduled") == (attempt["next_attempt_at"] is not None and attempt["next_profile"] is not None),
            "retry disposition differs from schedule")


def retry_summary(attempt):
    return {key: attempt[key] for key in ("attempt_count", "next_attempt_at", "next_profile", "reason", "disposition")} | {
        "latest_status": attempt["status"]}


def compatible_attempts(previous, selection):
    if not previous or previous["manifest"]["schema_version"] != 3:
        return {}
    return {item["id"]: copy.deepcopy(previous["attempts"][item["id"]]) for item in selection["sources"]
        if item["id"] in previous["attempts"] and previous["attempts"][item["id"]]["source_digest"] == source_digest(item) and
           previous["attempts"][item["id"]]["policy_digest"] == PROFILE["digest"]}


def verified_aliases(previous, selection, discovery_summary=None):
    """Carry rename proof only while it still binds the selected target pin."""
    current = (discovery_summary or {}).get("repository_aliases", [])
    result = {alias["repository"].casefold(): copy.deepcopy(alias) for alias in current}
    observed = {state["repository"].casefold() for state in (discovery_summary or {}).get("source_states", [])
                if state["current"]}
    for alias in (previous or {}).get("manifest", {}).get("repository_aliases", []):
        provider = alias["repository"].casefold()
        # A fresh observation with no redirect can be a recreated old name.
        # It overrides historical rename metadata, even if a commit is shared.
        if provider in result or provider in observed:
            continue
        names = {provider, alias["canonical_repository"].casefold()}
        if any(item["revision"] == alias["revision"] and item["repository"].casefold() in names
               for item in selection["sources"]):
            result[provider] = copy.deepcopy(alias)
    return [result[key] for key in sorted(result)]


def previous_records(previous, selection, *, repository_aliases=None):
    if not previous:
        return {}
    aliases = verified_aliases(previous, selection) if repository_aliases is None else repository_aliases
    by_logical = {logical_digest(item): previous["records"].get(item["id"]) for item in previous["selection"]["sources"]}
    result = {}
    for item in selection["sources"]:
        prior = by_logical.get(logical_digest(item))
        if prior is None:
            matches = [previous["records"][old["id"]] for old in previous["selection"]["sources"]
                if old["id"] in previous["records"] and old["kind"] == item["kind"] and
                old["path"] == item["path"] and old["plugin_path"] == item["plugin_path"] and
                contract.same_repository(old["repository"], item["repository"], item["revision"], aliases)]
            # An alias does not justify choosing arbitrarily between old subjects.
            prior = matches[0] if len(matches) == 1 else None
        if prior is None:
            continue
        if not contract.same_repository(prior["source"]["repository"], item["repository"], item["revision"], aliases):
            continue
        record = copy.deepcopy(prior) if "coverage" in prior else contract.import_legacy(prior,
            profile=previous["manifest"]["profile"], scanner_identity=previous["manifest"]["scanner"])
        record["id"] = item["id"]
        record["target_revision"] = item["revision"]
        record["freshness"] = "current" if (record["source"]["repository"].casefold() == item["repository"].casefold() and
            record["source"]["revision"] == item["revision"] and contract.known_profile(record)) else "historical"
        result[item["id"]] = record
    return result


def plan_attempts(selection, previous, partition_index, partition_count, maximum_attempts, *, current=None, excluded_ids=(),
                  repository_aliases=None):
    require(type(partition_count) is int and 1 <= partition_count <= MAX_PARTITIONS, "invalid partition count")
    require(type(partition_index) is int and 0 <= partition_index < partition_count, "invalid partition index")
    require(type(maximum_attempts) is int and 1 <= maximum_attempts <= MAX_ATTEMPTS, "invalid maximum attempts")
    current = current or datetime.now(timezone.utc)
    attempts, records = compatible_attempts(previous, selection), previous_records(previous, selection, repository_aliases=repository_aliases)
    lanes = {key: [] for key in ("new", "retry", "changed")}
    for position, item in enumerate(selection["sources"]):
        if item["id"] in excluded_ids or partition_for(item["repository"], partition_count) != partition_index:
            continue
        attempt, record = attempts.get(item["id"]), records.get(item["id"])
        if attempt:
            if attempt["disposition"] != "scheduled" or parse_timestamp(attempt["next_attempt_at"], "next_attempt_at") > current:
                continue
            lane, last = "retry", attempt["last_attempted_at"]
        elif record is not None:
            lane, last = "changed", record["scanned_at"] or ""
        else:
            lane, last = "new", ""
        lanes[lane].append((last, position, item))
    queues = {key: deque(entry[2] for entry in sorted(values, key=lambda entry: entry[:2])) for key, values in lanes.items()}
    order = contract.RETRY_POLICY["queue_lanes"]
    cursor = (previous or {}).get("queue_cursor", 0)
    result = []
    while len(result) < maximum_attempts and any(queues.values()):
        lane = order[cursor]
        cursor = (cursor + 1) % len(order)
        if queues[lane]:
            result.append(queues[lane].popleft())
    return result


def reason_codes(record):
    return {value["code"] for value in record["coverage"]["reasons"]} | {value["code"] for value in record["errors"]}


def make_attempt(item, record, previous_attempt=None, previous_record=None, *, at=None):
    at = at or scanner.now()
    count = (previous_attempt["attempt_count"] if previous_attempt else 0) + 1
    require(count <= contract.RETRY_POLICY["maximum_attempts_per_identity"], "attempt limit exhausted")
    reasons = reason_codes(record)
    fingerprint = sha256_digest(report_json({"source_digest": source_digest(item), "scanner": record["scanner"],
        "profile": record["profile"], "status": record["status"], "reasons": sorted(reasons),
        "groups": [finding["id"] for finding in record["findings"]]}))
    disposition, reason, delay, next_profile = "blocked", "persistent_limitation", None, None
    if record["status"] == "complete":
        disposition, reason = "none", "complete"
    elif reasons & RESOURCE_REASONS:
        if record["profile"] == scanner.STANDARD_PROFILE:
            disposition, reason, delay, next_profile = "scheduled", "extended_profile_required", 0, scanner.EXTENDED_PROFILE["id"]
        else:
            disposition, reason = "exhausted", "extended_budget_exhausted"
    elif reasons & TRANSIENT_REASONS:
        delays = contract.RETRY_POLICY["network_delays_seconds"]
        if count <= len(delays):
            disposition, reason, delay, next_profile = "scheduled", "transient_source_failure", delays[count - 1], record["profile"]["id"]
        else:
            disposition, reason = "exhausted", "transient_retry_limit"
    elif reasons & PERMANENT_REASONS:
        reason = sorted(reasons & PERMANENT_REASONS)[0]
    elif record["profile"] == scanner.STANDARD_PROFILE and count == 1:
        disposition, reason, delay, next_profile = "scheduled", "analyzer_retry", 900, scanner.EXTENDED_PROFILE["id"]
    if count >= contract.RETRY_POLICY["maximum_attempts_per_identity"] and disposition == "scheduled":
        disposition, reason, delay, next_profile = "exhausted", "attempt_limit", None, None
    history = copy.deepcopy((previous_attempt or {}).get("history", (previous_record or {}).get("attempt_history", [])))
    history.append({"at": at, "profile": copy.deepcopy(record["profile"]), "status": record["status"],
        "fingerprint": fingerprint, "reason": reason,
        "acquisition_seconds": record["execution"]["acquisition_seconds"], "analysis_seconds": record["execution"]["analysis_seconds"]})
    return {"id": item["id"], "source_digest": source_digest(item), "profile": copy.deepcopy(record["profile"]),
        "scanner": copy.deepcopy(SCANNER), "policy_digest": PROFILE["digest"], "last_attempted_at": at,
        "status": record["status"], "attempt_count": count, "fingerprint": fingerprint,
        "next_attempt_at": format_timestamp(parse_timestamp(at, "at") + timedelta(seconds=delay)) if delay is not None else None,
        "next_profile": next_profile, "disposition": disposition, "reason": reason,
        "history": history[-contract.RETRY_POLICY["history_limit"]:]}


def fail(record, code, message):
    scanner.add_error(record, code, message)
    scanner.add_coverage_reason(record, code, message)
    record["status"] = "error"
    record["execution"]["state"] = "failed"
    record["execution"]["finished_at"] = scanner.now()
    return record


def scan_selected(executable, item, pinned, budget, *, profile_id="static-standard-v3"):
    record = scanner.empty_record_v3(item, profile_id)
    profile = scanner.PROFILE_DOCUMENTS[profile_id]
    record["execution"]["started_at"] = scanner.now()
    started, analysis_started = time.monotonic(), None
    try:
        pinned.work_budget = WorkBudget(min(PREPARATION_SECONDS, budget.remaining()))
        files = bounded_package_files(pinned, item["path"], max_files=profile["max_files"],
            max_file_bytes=profile["max_tree_bytes"], max_tree_bytes=profile["max_tree_bytes"])
        require(any(path == "SKILL.md" for path, _, _ in files), "selected root has no SKILL.md")
        with tempfile.TemporaryDirectory(prefix="uap-skillspector-v3-") as directory:
            home, root = Path(directory), Path(directory) / "content"
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
                    record["skill_name"] = scanner.clean(frontmatter["name"], 200) or None
            record["scanned_at"] = scanner.now()
            record["execution"]["acquisition_seconds"] = round(time.monotonic() - started, 6)
            timeout = min(profile["timeout_seconds"], budget.remaining())
            require(timeout > 1, "scan budget exhausted during preparation")
            analysis_started = time.monotonic()
            code, body = scanner.run_scanner_v3(executable, ["scan", str(root), *profile["arguments"]], home, timeout, profile_id)
            record["execution"]["analysis_seconds"] = round(time.monotonic() - analysis_started, 6)
            require(directory_tree_digest(root) == digest, "source bytes changed during scan")
            # Normalize transactionally: a malformed/oversized upstream report
            # must not leave legacy-shaped or half-validated findings on the
            # error record and make the entire worker artifact unpublishable.
            return scanner.normalize_report_v3(copy.deepcopy(record), body, code, root)
    except subprocess.TimeoutExpired:
        fail(record, "scan_timeout", "The bounded static analysis deadline was reached.")
    except CheckpointYield:
        fail(record, "preparation_timeout", "Source preparation reached its bounded deadline.")
    except AcquisitionTransferLimit:
        fail(record, "acquisition_transfer_limit", "Source acquisition reached its bounded Git transfer allowance.")
    except DiscoveryInputLimitError:
        fail(record, "input_limit_exceeded", f"Source exceeds {profile['max_files']} files or {profile['max_tree_bytes']} bytes in this profile.")
    except (BridgeError, DiscoveryError, RegistryError, OSError):
        fail(record, "acquisition_failed", "The immutable source could not be acquired completely.")
    except (PublicationError, ValueError, RecursionError, yaml.YAMLError, subprocess.SubprocessError):
        fail(record, "scan_failed", "The scanner output or source could not be processed completely.")
    finally:
        if analysis_started is None:
            record["execution"]["acquisition_seconds"] = round(time.monotonic() - started, 6)
        else:
            record["execution"]["analysis_seconds"] = round(time.monotonic() - analysis_started, 6)
    return record


def scan_partition(selection, executable, previous, *, source_commit, partition_index=0,
                   partition_count=MAX_PARTITIONS, maximum_attempts=MAX_ATTEMPTS,
                   budget_seconds=2100, mirror_root=None, discovery_summary=None):
    validate_selection(selection)
    require(SHA.fullmatch(source_commit) is not None, "invalid source commit")
    require(type(budget_seconds) in (int, float) and 0 < budget_seconds <= 2100, "invalid scan budget")
    scanner.verify_scanner(executable)
    budget = WorkBudget(budget_seconds)
    historical_ids = set()
    if discovery_summary:
        current_ids = {identifier for state in discovery_summary.get("source_states", []) if state["current"]
                       for identifier in state["selected_ids"]}
        historical_ids = {identifier for state in discovery_summary.get("source_states", []) if not state["current"]
                          for identifier in state["selected_ids"]} - current_ids
    aliases = verified_aliases(previous, selection, discovery_summary)
    chosen = plan_attempts(selection, previous, partition_index, partition_count, maximum_attempts,
                           excluded_ids=historical_ids, repository_aliases=aliases)
    old_attempts, old_records = compatible_attempts(previous, selection), previous_records(previous, selection, repository_aliases=aliases)
    outcomes, pins = [], {}
    try:
        for item in chosen:
            try:
                if budget.remaining() < 2:
                    break
            except CheckpointYield:
                break
            old = old_attempts.get(item["id"])
            profile_id = old["next_profile"] if old else scanner.STANDARD_PROFILE["id"]
            key = (item["repository"], item["revision"])
            acquisition_started = time.monotonic()
            acquisition_seconds = 0
            try:
                if key not in pins:
                    pins[key] = PinnedRepository(*key, mirror_root,
                        github_token=os.environ.get("GITHUB_TOKEN") if mirror_root is None else None,
                        work_budget=WorkBudget(min(PREPARATION_SECONDS, budget.remaining())))
                    acquisition_seconds = time.monotonic() - acquisition_started
                record = scan_selected(executable, item, pins[key], budget, profile_id=profile_id)
                record["execution"]["acquisition_seconds"] = round(record["execution"]["acquisition_seconds"] + acquisition_seconds, 6)
            except (BridgeError, OSError, subprocess.SubprocessError, CheckpointYield):
                record = fail(scanner.empty_record_v3(item, profile_id), "acquisition_failed", "The immutable repository could not be acquired.")
                record["execution"]["acquisition_seconds"] = round(time.monotonic() - acquisition_started, 6)
            attempt = make_attempt(item, record, old, old_records.get(item["id"]))
            outcome = {"attempt": attempt, "record": record}
            if len(report_json(outcomes)) + len(report_json(outcome)) + 4096 > MAX_WORKER_BYTES:
                break  # Completed prior work remains publishable; unpersisted work is still queued.
            outcomes.append(outcome)
    finally:
        for pinned in pins.values():
            pinned.close()
    return {"schema_version": 3, "source_commit": source_commit, "generated_at": scanner.now(),
        "selection_digest": sha256_digest(canonical_json(selection)), "scanner": SCANNER, "profile": PROFILE,
        "partition": {"index": partition_index, "count": partition_count}, "attempts": outcomes}


def validate_worker(worker, selection, source_commit):
    v2.exact(worker, ("schema_version", "source_commit", "generated_at", "selection_digest", "scanner", "profile", "partition", "attempts"), "worker")
    require(worker["schema_version"] == 3 and worker["source_commit"] == source_commit and worker["scanner"] == SCANNER and
        worker["profile"] == PROFILE and worker["selection_digest"] == sha256_digest(canonical_json(selection)), "worker provenance differs")
    generated = v2.timestamp(worker["generated_at"], "worker.generated_at")
    part = worker["partition"]
    v2.exact(part, ("index", "count"), "partition")
    require(type(part["count"]) is int and 1 <= part["count"] <= MAX_PARTITIONS and
            type(part["index"]) is int and 0 <= part["index"] < part["count"], "invalid partition")
    require(isinstance(worker["attempts"], list) and len(worker["attempts"]) <= MAX_ATTEMPTS, "worker attempt bound exceeded")
    expected, seen = {item["id"]: item for item in selection["sources"]}, set()
    for outcome in worker["attempts"]:
        v2.exact(outcome, ("attempt", "record"), "worker outcome")
        attempt = outcome["attempt"]
        validate_attempt(attempt, expected, generated)
        item = expected[attempt["id"]]
        require(item["id"] not in seen and partition_for(item["repository"], part["count"]) == part["index"], "repeated or misplaced worker subject")
        seen.add(item["id"])
        contract.validate_record(outcome["record"], item, parse_timestamp(attempt["last_attempted_at"], "attempt.at"))
        require(outcome["record"]["profile"] == attempt["profile"] and outcome["record"]["status"] == attempt["status"], "outcome differs from attempt")
    return worker


def shard_document(repository, records):
    return {"schema_version": 3, "scanner": SCANNER, "profile": PROFILE, "repository": repository, "records": records}


def merge_reports(selection, previous, workers, *, source_commit, output_dir, discovery_summary=None):
    validate_selection(selection)
    require(SHA.fullmatch(source_commit) is not None and workers, "source commit and worker artifacts required")
    summary = discovery_summary
    if isinstance(summary, Path):
        summary = read_json(summary, max_bytes=MAX_DISCOVERY_BYTES)
    if summary is not None:
        validate_discovery_summary(summary, selection, source_commit)
        summary = copy.deepcopy(summary)
        summary["repository_aliases"] = verified_aliases(previous, selection, summary)
    # Without a discovery artifact there is nowhere to persist validated alias
    # evidence. Exact-repository history remains usable, but no rename is guessed.
    aliases = (summary or {}).get("repository_aliases", [])
    records, attempts = previous_records(previous, selection, repository_aliases=aliases), compatible_attempts(previous, selection)
    expected = {item["id"]: item for item in selection["sources"]}
    partitions, seen = set(), set()
    expected_count = workers[0]["partition"]["count"]
    for worker in workers:
        validate_worker(worker, selection, source_commit)
        part = worker["partition"]
        require(part["count"] == expected_count and part["index"] not in partitions, "inconsistent worker partitions")
        partitions.add(part["index"])
        for outcome in worker["attempts"]:
            attempt, new = outcome["attempt"], outcome["record"]
            identifier = attempt["id"]
            require(identifier not in seen, "repeated attempt across partitions")
            seen.add(identifier)
            old_attempt, old_record = attempts.get(identifier), records.get(identifier)
            require(old_attempt is None or attempt["last_attempted_at"] >= old_attempt["last_attempted_at"], "worker regresses progress")
            require(attempt["attempt_count"] == (old_attempt["attempt_count"] + 1 if old_attempt else 1), "attempt count is not consecutive")
            # An acquisition/scan failure must not erase useful prior evidence.
            if new["status"] == "error" and old_record is not None and old_record["status"] != "error":
                record = old_record
            else:
                record = copy.deepcopy(new)
                record["freshness"] = "current"
            records[identifier] = record
            attempts[identifier] = copy.deepcopy(attempt)
    require(partitions == set(range(expected_count)), "missing worker partition")
    current_ids = {identifier for state in (summary or {}).get("source_states", []) if state["current"] for identifier in state["selected_ids"]}
    historical_ids = {identifier for state in (summary or {}).get("source_states", []) if not state["current"]
                      for identifier in state["selected_ids"]} - current_ids
    for identifier, record in records.items():
        record["target_revision"] = expected[identifier]["revision"]
        if identifier in historical_ids:
            record["freshness"] = "historical"
        if identifier in attempts:
            record["retry"] = retry_summary(attempts[identifier])
            record["attempt_history"] = copy.deepcopy(attempts[identifier]["history"])
        else:
            record["retry"] = {"attempt_count": 0, "next_attempt_at": None, "next_profile": None,
                "reason": "source_unavailable" if identifier in historical_ids else "source_or_profile_changed",
                "disposition": "blocked" if identifier in historical_ids else "none", "latest_status": record["status"]}
            record.setdefault("attempt_history", [])
    output_dir.mkdir(parents=True, exist_ok=True)
    grouped = defaultdict(list)
    for record in sorted(records.values(), key=lambda value: value["id"]):
        grouped[expected[record["id"]]["repository"]].append(record)
    descriptors = []
    for repository, group in sorted(grouped.items()):
        parts, pending = [], []
        size = len(report_json(shard_document(repository, [])))
        for record in group:
            record_size = len(report_json(record)) + 1
            if pending and (len(pending) >= MAX_SHARD_RECORDS or size + record_size > MAX_SHARD_BYTES):
                parts.append(pending)
                pending, size = [], len(report_json(shard_document(repository, [])))
            pending.append(record)
            size += record_size
        if pending:
            parts.append(pending)
        for part in parts:
            document = shard_document(repository, part)
            body = report_json(document)
            digest = sha256_digest(body)
            relative = "shards/" + digest.removeprefix("sha256:") + ".json"
            write_bounded(output_dir / relative, document, MAX_SHARD_BYTES)
            descriptors.append({"repository": repository, "path": relative, "digest": digest, "bytes": len(body), "record_count": len(part)})
    generated, selection_hash = scanner.now(), sha256_digest(canonical_json(selection))
    manifest = {"schema_version": 3, "source_commit": source_commit, "generated_at": generated,
        "scope": "selected_sources", "scanner": SCANNER, "profile": PROFILE, "profiles": list(scanner.PROFILES.values()),
        "selection_digest": selection_hash, "coverage": contract.analysis_counts(selection, records),
        "plugin_coverage": contract.plugin_counts(selection, records), "shards": descriptors,
        **{key: (summary or {}).get(key, None if key == "catalog_coverage" else []) for key in
           ("source_states", "plugin_states", "repository_aliases", "catalog_coverage")}}
    validate_manifest(manifest, current_policy=True)
    write_bounded(output_dir / "selection.json", selection, MAX_SELECTION_BYTES)
    write_bounded(output_dir / "attempts.json", {"schema_version": 3, "source_commit": source_commit,
        "generated_at": generated, "selection_digest": selection_hash, "attempts": sorted(attempts.values(), key=lambda value: value["id"]),
        "queue_cursor": ((previous or {}).get("queue_cursor", 0) + max(1, len(seen))) % 3}, MAX_STATE_BYTES)
    if summary is not None:
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
    for command in (scan, merge):
        command.add_argument("--selection", type=Path, required=True)
        command.add_argument("--previous-dir", type=Path)
        command.add_argument("--source-commit", required=True)
        command.add_argument("--discovery-summary", type=Path)
    args = parser.parse_args()
    try:
        selection, previous = load_selection(args.selection), read_bundle(args.previous_dir)
        summary = read_json(args.discovery_summary, max_bytes=MAX_DISCOVERY_BYTES) if args.discovery_summary else None
        if summary:
            validate_discovery_summary(summary, selection, args.source_commit)
        if args.command == "scan":
            worker = scan_partition(selection, args.scanner.resolve(), previous, source_commit=args.source_commit,
                partition_index=args.partition_index, partition_count=args.partition_count, maximum_attempts=args.maximum_attempts,
                budget_seconds=args.budget_seconds, mirror_root=args.mirror_root, discovery_summary=summary)
            validate_worker(worker, selection, args.source_commit)
            write_bounded(args.output, worker, MAX_WORKER_BYTES)
        else:
            workers = [read_json(path, max_bytes=MAX_WORKER_BYTES) for path in args.workers]
            manifest = merge_reports(selection, previous, workers, source_commit=args.source_commit,
                output_dir=args.output_dir, discovery_summary=summary)
            print(json.dumps(manifest["coverage"], sort_keys=True))
        return 0
    except (PublicationError, CheckpointYield, OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        print(f"SkillSpector v3 coverage failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
