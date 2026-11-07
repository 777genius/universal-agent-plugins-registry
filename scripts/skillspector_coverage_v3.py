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
from contextlib import contextmanager
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
MAX_SOURCES, MAX_PARTITIONS = 20_000, v2.MAX_PARTITIONS
# Broader manual admission shares the same deadline/output budgets. Keep normal
# admission unchanged until a real larger run measures its useful throughput.
MAX_ATTEMPTS, DEFAULT_ATTEMPTS = 512, v2.MAX_ATTEMPTS
MAX_MANIFEST_BYTES, MAX_STATE_BYTES = 16 << 20, 64 << 20
MAX_SHARD_BYTES, MAX_SELECTION_BYTES = v2.MAX_SHARD_BYTES, v2.MAX_SELECTION_BYTES
MAX_DISCOVERY_BYTES, MAX_WORKER_BYTES = v2.MAX_DISCOVERY_BYTES, v2.MAX_WORKER_BYTES
# V3 retains historical evidence while adding eight bounded scan partitions.
# The v2 aggregate ceiling was already at ~249 MiB in production before the
# next batch; keep an independent finite cap without weakening shard limits.
MAX_TOTAL_SHARD_BYTES = 512 << 20
MAX_SHARD_RECORDS = v2.MAX_SHARD_RECORDS
SHA, SHARD_PATH = v2.SHA, v2.SHARD_PATH
PREPARATION_SECONDS = 120
# A normalized record is capped below MAX_REPORT_BYTES. Reserve its entire
# allowance, plus bounded retry history/envelope metadata, before executing it.
MAX_OUTCOME_BYTES = scanner.MAX_REPORT_BYTES + (128 << 10)
RESOURCE_REASONS = frozenset({"scan_timeout", "runtime_limit", "archive_time_limit", "size_limit",
    "input_limit_exceeded", "acquisition_transfer_limit", "total_bytes_limit", "artifact_count_limit", "output_limit", "normalization_truncated"})
TRANSIENT_REASONS = frozenset({"acquisition_failed", "preparation_timeout", "network_error", "network_timeout",
    "osv_request_failed", "osv_timeout"})
PERMANENT_REASONS = frozenset({"static_parse_limit", "reference_missing", "reference_unresolved", "referenced_uninspected",
    "unsupported_content", "reference_extraction_limit", "opaque_content", "obfuscated_instruction_text",
    "excluded_executable_content", "source_invalid"})
read_json = scanner.read_report_json
report_json = scanner.report_json
source_digest, logical_digest, partition_for = v2.source_digest, v2.logical_digest, v2.partition_for


def validate_selection(selection):
    return v2.validate_selection(selection, maximum_sources=MAX_SOURCES)


def validate_discovery_summary(summary, selection, source_commit):
    return v2.validate_discovery_summary(summary, selection, source_commit, maximum_sources=MAX_SOURCES)


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
    # Immutable published manifests have either the original two profiles or
    # the strictly pinned old/new pair. Unknown scanner policies fail closed.
    legacy = (manifest["scanner"] == SCANNER and
              manifest["profile"] == contract.LEGACY_POLICY and
              manifest["profiles"] == list(scanner.LEGACY_PROFILES.values()))
    current = (manifest["scanner"] == SCANNER and
               manifest["profile"] == PROFILE and
               manifest["profiles"] == scanner.ALL_PROFILES)
    require(legacy or current, "unsupported report policy generation")
    if current_policy:
        require(current, "unsupported current report policy")
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
    total_shard_bytes = sum(part["bytes"] for part in manifest["shards"])
    require(total_shard_bytes <= MAX_TOTAL_SHARD_BYTES,
            f"total report budget exceeded: {total_shard_bytes} > {MAX_TOTAL_SHARD_BYTES} bytes")
    plugins = set()
    for plugin in manifest["plugin_coverage"]:
        key = (plugin["repository"].lower(), plugin["plugin_path"])
        require(key not in plugins, "repeated plugin coverage")
        plugins.add(key)
        check_counts(plugin)
    for key in coverage:
        require(sum(plugin[key] for plugin in manifest["plugin_coverage"]) <= coverage[key], "plugin totals exceed coverage")
    if "execution_summary" in manifest:
        execution = manifest["execution_summary"]
        count = execution["partition_count"]
        received, missing = execution["received_partitions"], execution["missing_partitions"]
        require(received == sorted(set(received)) and missing == sorted(set(missing)) and
                not set(received) & set(missing) and set(received) | set(missing) == set(range(count)),
                "execution partitions do not partition the expected workers")
        require(execution["attempted_sources"] <= coverage["selected"] and
                execution["recovered_sources"] <= coverage["selected"], "execution source counts exceed selection")
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
           previous["attempts"][item["id"]]["scanner"] == SCANNER and
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


def scheduling_group(item):
    """Share a turn per standalone repository or independently listed plugin."""
    return item["kind"], item["repository"].casefold(), item["plugin_path"]


MAX_COHERENT_PLUGIN_ROOTS = 16


def lane_quotas(lanes, order, cursor, maximum_attempts):
    """Reserve per-lane admission exactly as the original one-at-a-time policy."""
    available = {name: len(entries) for name, entries in lanes.items()}
    quotas = {name: 0 for name in lanes}
    total = 0
    while total < maximum_attempts and any(available.values()):
        lane = order[cursor]
        cursor = (cursor + 1) % len(order)
        if available[lane]:
            available[lane] -= 1
            quotas[lane] += 1
            total += 1
    return quotas


def fair_lane(entries, previous, lane_budget):
    # Rotate never-attempted and previously attempted groups. A partially
    # checked plugin can finish its remaining small batch without moving ahead
    # of every new source or using slots reserved for retries/changed sources.
    attempted = {}
    for item in (previous or {}).get("selection", {}).get("sources", []):
        attempt = (previous or {}).get("attempts", {}).get(item["id"])
        if attempt is not None:
            key = scheduling_group(item)
            attempted[key] = max(attempted.get(key, ""), attempt["last_attempted_at"])
    grouped = defaultdict(deque)
    for entry in sorted(entries, key=lambda entry: entry[:2]):
        grouped[scheduling_group(entry[2])].append(entry)
    ordered = sorted(grouped, key=lambda key: (attempted.get(key, ""), grouped[key][0][:2]))
    cold = deque(key for key in ordered if key not in attempted)
    continuing = deque(key for key in ordered if key in attempted)
    groups = deque()
    while cold or continuing:
        if cold:
            groups.append(cold.popleft())
        if continuing:
            groups.append(continuing.popleft())
    result = deque()
    served = set()
    while groups:
        key = groups.popleft()
        group = grouped[key]
        take = 1
        if key[0] == "plugin_skill" and len(result) < lane_budget:
            # Reserve a turn only for a group that has not yet received one
            # in this scheduling pass. Otherwise a competitor can consume two
            # slots while a 15-root package receives only 14 of its 15.
            available = lane_budget - len(result)
            reserved = 1 if any(other not in served for other in groups) else 0
            take = min(len(group), MAX_COHERENT_PLUGIN_ROOTS,
                       max(1, available - reserved))
        for _ in range(take):
            result.append(group.popleft()[2])
        served.add(key)
        if group:
            groups.append(key)
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
    order = contract.RETRY_POLICY["queue_lanes"]
    cursor = (previous or {}).get("queue_cursor", 0)
    quotas = lane_quotas(lanes, order, cursor, maximum_attempts)
    # Changed source/profile evidence is honestly displayed as Outdated until
    # rescanned. When both queues are deep, use half of the new-only allowance
    # for that existing backlog. Due retries keep their original quota, and
    # new Skills still receive bounded, nonzero admission on every pass.
    # A 16-root new plugin must still fit its original admission window;
    # do not cut that window in half just to prefer older individual roots.
    refresh = min(quotas["new"] // 2,
                  max(0, quotas["new"] - MAX_COHERENT_PLUGIN_ROOTS),
                  len(lanes["changed"]) - quotas["changed"])
    quotas["new"] -= refresh
    quotas["changed"] += refresh
    queues = {key: fair_lane(values, previous, quotas[key]) for key, values in lanes.items()}
    # The chosen per-lane prefix already contains coherent plugin groups.
    # Interleave execution across lanes, rather than letting a 15-Skill group
    # spend the worker's wall-clock budget before due retries can start.
    result = []
    while any(quotas.values()):
        lane = order[cursor]
        cursor = (cursor + 1) % len(order)
        if quotas[lane]:
            result.append(queues[lane].popleft())
            quotas[lane] -= 1
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


class WorkerDeferred(Exception):
    """The worker cannot supply a whole attempt; the source remains queued."""


def profile_timeout(budget, profile):
    timeout = profile["timeout_seconds"]
    try:
        remaining = budget.remaining()
    except CheckpointYield as error:
        raise WorkerDeferred("worker deadline reached before analysis") from error
    if remaining < timeout:
        raise WorkerDeferred("worker cannot provide the full analysis profile")
    return timeout


@contextmanager
def preparation_budget(budget, profile):
    # Reserve the process's full declared allowance. A worker tail must not
    # masquerade as a source deadline or consume a retry with a smaller profile.
    timeout = profile_timeout(budget, profile)
    available = budget.deadline - budget.monotonic() - timeout
    if available <= 0:
        raise WorkerDeferred("worker cannot prepare a full analysis attempt")
    preparation = WorkBudget(PREPARATION_SECONDS, monotonic=budget.monotonic)
    worker_limited = budget.deadline - timeout < preparation.deadline
    preparation.deadline = min(preparation.deadline, budget.deadline - timeout)
    try:
        yield preparation
    except CheckpointYield as error:
        if worker_limited:
            raise WorkerDeferred("worker preparation allowance reached") from error
        raise


def scan_selected(executable, item, pinned, budget, *, profile_id="static-standard-v3"):
    record = scanner.empty_record_v3(item, profile_id)
    profile = scanner.PROFILE_DOCUMENTS[profile_id]
    record["execution"]["started_at"] = scanner.now()
    started, analysis_started = time.monotonic(), None
    try:
        with tempfile.TemporaryDirectory(prefix="uap-skillspector-v3-") as directory:
            home, root = Path(directory), Path(directory) / "content"
            root.mkdir()
            with preparation_budget(budget, profile) as pinned.work_budget:
                files = bounded_package_files(pinned, item["path"], max_files=profile["max_files"],
                    max_file_bytes=profile["max_tree_bytes"], max_tree_bytes=profile["max_tree_bytes"])
                require(any(path == "SKILL.md" for path, _, _ in files), "selected root has no SKILL.md")
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
            timeout = profile_timeout(budget, profile)
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
                    partition_count=MAX_PARTITIONS, maximum_attempts=DEFAULT_ATTEMPTS,
                    budget_seconds=2100, mirror_root=None, discovery_summary=None,
                    checkpoint=None, resume=None, slice_attempts=None):
    validate_selection(selection)
    require(SHA.fullmatch(source_commit) is not None, "invalid source commit")
    require(type(budget_seconds) in (int, float) and 0 < budget_seconds <= 2100, "invalid scan budget")
    require(slice_attempts is None or type(slice_attempts) is int and 1 <= slice_attempts <= maximum_attempts,
            "invalid slice attempt bound")
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
    if resume is not None:
        validate_worker(resume, selection, source_commit)
        require(resume["partition"] == {"index": partition_index, "count": partition_count},
                "checkpoint partition differs")
        require(len(resume["attempts"]) <= maximum_attempts, "checkpoint exceeds requested attempt bound")
        by_id = {item["id"]: item for item in selection["sources"]}
        for outcome in resume["attempts"]:
            attempt = outcome["attempt"]
            old = old_attempts.get(attempt["id"])
            require(old is None or attempt["last_attempted_at"] >= old["last_attempted_at"],
                    "checkpoint regresses progress")
            require(attempt == make_attempt(by_id[attempt["id"]], outcome["record"], old,
                    old_records.get(attempt["id"]), at=attempt["last_attempted_at"]),
                    "checkpoint attempt lineage differs")
        outcomes = copy.deepcopy(resume["attempts"])
    completed = {outcome["attempt"]["id"] for outcome in outcomes}

    def document(entries):
        return {"schema_version": 3, "source_commit": source_commit, "generated_at": scanner.now(),
            "selection_digest": sha256_digest(canonical_json(selection)), "scanner": SCANNER, "profile": PROFILE,
            "partition": {"index": partition_index, "count": partition_count}, "attempts": entries}

    def persist():
        value = document(outcomes)
        require(len(report_json(value)) <= MAX_WORKER_BYTES, "worker checkpoint exceeds byte bound")
        if checkpoint is not None:
            checkpoint(copy.deepcopy(value))
        return value

    # Even scanner verification/setup failures leave an honest empty checkpoint.
    persist()
    scanner.verify_scanner(executable)
    budget = WorkBudget(budget_seconds)
    admitted = 0
    try:
        for item in chosen:
            if item["id"] in completed:
                continue
            if len(outcomes) >= maximum_attempts or slice_attempts is not None and admitted >= slice_attempts:
                break
            if len(report_json(document(outcomes))) + MAX_OUTCOME_BYTES > MAX_WORKER_BYTES:
                break  # Defer before acquisition: an executed result must always fit.
            old = old_attempts.get(item["id"])
            profile_id = old["next_profile"] if old else scanner.STANDARD_PROFILE["id"]
            profile = scanner.PROFILE_DOCUMENTS[profile_id]
            key = (item["repository"], item["revision"])
            acquisition_started = time.monotonic()
            acquisition_seconds = 0
            try:
                profile_timeout(budget, profile)
                if key not in pins:
                    with preparation_budget(budget, profile) as acquisition_budget:
                        pins[key] = PinnedRepository(*key, mirror_root,
                            github_token=os.environ.get("GITHUB_TOKEN") if mirror_root is None else None,
                            work_budget=acquisition_budget)
                    acquisition_seconds = time.monotonic() - acquisition_started
                record = scan_selected(executable, item, pins[key], budget, profile_id=profile_id)
                record["execution"]["acquisition_seconds"] = round(record["execution"]["acquisition_seconds"] + acquisition_seconds, 6)
            except WorkerDeferred:
                break  # No outcome: retain prior evidence, retry identity and attempt count.
            except (BridgeError, OSError, subprocess.SubprocessError, CheckpointYield):
                record = fail(scanner.empty_record_v3(item, profile_id), "acquisition_failed", "The immutable repository could not be acquired.")
                record["execution"]["acquisition_seconds"] = round(time.monotonic() - acquisition_started, 6)
            attempt = make_attempt(item, record, old, old_records.get(item["id"]))
            outcome = {"attempt": attempt, "record": scanner.redact_public_record(record)}
            require(len(report_json(outcome)) <= MAX_OUTCOME_BYTES, "normalized outcome exceeds reserved capacity")
            # Validate the new transaction once; all preceding outcomes were
            # already validated, avoiding quadratic full-checkpoint validation.
            validate_worker(document([outcome]), selection, source_commit)
            outcomes.append(outcome)
            admitted += 1
            persist()
    finally:
        for pinned in pins.values():
            pinned.close()
    return persist()


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


def coalesce_workers(workers, selection, source_commit, *, expected_partition_count=None):
    """Accept cumulative checkpoints only when their outcomes extend exactly."""
    require(isinstance(workers, (list, tuple)) and bool(workers), "worker artifacts required")
    require(expected_partition_count is None or type(expected_partition_count) is int and
            1 <= expected_partition_count <= MAX_PARTITIONS, "invalid expected partition count")
    by_partition = {}
    count = expected_partition_count
    for value in workers:
        validate_worker(value, selection, source_commit)
        part = value["partition"]
        if count is None:
            count = part["count"]
        require(part["count"] == count, "worker partition count differs from preparation")
        prior = by_partition.get(part["index"])
        if prior is not None:
            short, long = sorted((prior, value), key=lambda entry: len(entry["attempts"]))
            require(short["attempts"] == long["attempts"][:len(short["attempts"])],
                    "conflicting cumulative worker checkpoints")
            if len(short["attempts"]) < len(long["attempts"]):
                require(short["generated_at"] <= long["generated_at"], "worker checkpoint timestamp regresses")
                value = long
            else:
                value = max((prior, value), key=lambda entry: entry["generated_at"])
        by_partition[part["index"]] = value
    return [by_partition[index] for index in sorted(by_partition)], count


def apply_outcome(records, attempts, item, outcome, *, replay=False):
    """Commit one record/retry transaction while retaining useful failed-scan fallback."""
    attempt, new = outcome["attempt"], outcome["record"]
    identifier = item["id"]
    old_attempt, old_record = attempts.get(identifier), records.get(identifier)
    if replay and old_attempt is not None and attempt["attempt_count"] <= old_attempt["attempt_count"]:
        if attempt["attempt_count"] == old_attempt["attempt_count"]:
            require(attempt == old_attempt, "recovered attempt conflicts with persisted progress")
            if old_record is not None and old_record["status"] == new["status"]:
                controls = {"freshness", "target_revision", "retry", "attempt_history"}
                require({key: value for key, value in old_record.items() if key not in controls} ==
                        {key: value for key, value in new.items() if key not in controls},
                        "recovered record conflicts with persisted evidence")
        else:
            final = attempt["history"][-1]
            require(final in old_attempt["history"], "recovered older attempt has no persisted lineage")
        return False
    require(old_attempt is None or attempt["last_attempted_at"] >= old_attempt["last_attempted_at"],
            "worker regresses progress")
    require(attempt["attempt_count"] == (old_attempt["attempt_count"] + 1 if old_attempt else 1),
            "attempt count is not consecutive")
    require(attempt == make_attempt(item, new, old_attempt, old_record, at=attempt["last_attempted_at"]),
            "worker attempt lineage differs")
    if new["status"] == "error" and old_record is not None and old_record["status"] != "error":
        record = old_record
    else:
        record = copy.deepcopy(new)
        record["freshness"] = "current"
    persisted_attempt = copy.deepcopy(attempt)
    if old_attempt is not None and old_record is not None and predecessor_uncertain(old_record) and new["status"] == "error":
        # A later failed execution cannot resolve an unavailable predecessor,
        # even when both the old and new report contain no acquired content.
        mark_missing_predecessor(record, persisted_attempt)
    records[identifier] = record
    attempts[identifier] = persisted_attempt
    return True


def shard_document(repository, records):
    return {"schema_version": 3, "scanner": SCANNER, "profile": PROFILE, "repository": repository, "records": records}


def merge_reports(selection, previous, workers, *, source_commit, output_dir, discovery_summary=None,
                  expected_partition_count=None, allow_partial_workers=False, recovered_sources=0):
    validate_selection(selection)
    require(SHA.fullmatch(source_commit) is not None and workers, "source commit and worker artifacts required")
    require(type(recovered_sources) is int and 0 <= recovered_sources <= len(selection["sources"]),
            "invalid recovered source count")
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
    require(type(allow_partial_workers) is bool and (not allow_partial_workers or expected_partition_count is not None),
            "partial assembly requires an independently expected partition count")
    workers, expected_count = coalesce_workers(workers, selection, source_commit,
                                             expected_partition_count=expected_partition_count)
    partitions, seen = set(), set()
    for worker in workers:
        part = worker["partition"]
        require(part["count"] == expected_count and part["index"] not in partitions, "inconsistent worker partitions")
        partitions.add(part["index"])
        for outcome in worker["attempts"]:
            attempt, new = outcome["attempt"], outcome["record"]
            identifier = attempt["id"]
            require(identifier not in seen, "repeated attempt across partitions")
            seen.add(identifier)
            apply_outcome(records, attempts, expected[identifier], outcome)
    require(allow_partial_workers or partitions == set(range(expected_count)), "missing worker partition")
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
        # Cached, historical and useful fallback records cross the same public
        # text boundary as new scanner results, before shard bytes are hashed.
        public = scanner.redact_public_record(record)
        grouped[expected[record["id"]]["repository"]].append(public)
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
        "scope": "selected_sources", "scanner": SCANNER, "profile": PROFILE, "profiles": scanner.ALL_PROFILES,
        "selection_digest": selection_hash, "coverage": contract.analysis_counts(selection, records),
        "plugin_coverage": contract.plugin_counts(selection, records), "shards": descriptors,
        "execution_summary": {"partition_count": expected_count, "received_partitions": sorted(partitions),
            "missing_partitions": sorted(set(range(expected_count)) - partitions),
            "attempted_sources": len(seen), "recovered_sources": recovered_sources},
        **{key: (summary or {}).get(key, None if key == "catalog_coverage" else []) for key in
           ("source_states", "plugin_states", "repository_aliases", "catalog_coverage")}}
    validate_manifest(manifest, current_policy=True)
    write_bounded(output_dir / "selection.json", selection, MAX_SELECTION_BYTES)
    write_bounded(output_dir / "attempts.json", {"schema_version": 3, "source_commit": source_commit,
        "generated_at": generated, "selection_digest": selection_hash, "attempts": sorted(attempts.values(), key=lambda value: value["id"]),
        "queue_cursor": ((previous or {}).get("queue_cursor", 0) + len(seen)) % 3}, MAX_STATE_BYTES)
    if summary is not None:
        write_bounded(output_dir / "coverage.json", summary, MAX_DISCOVERY_BYTES)
    write_bounded(output_dir / "index.json", manifest, MAX_MANIFEST_BYTES)
    read_bundle(output_dir)
    return manifest


def recovery_analysis(record):
    """Analysis equality excludes provenance that naturally varies per execution.

    The upstream report digest can change with raw execution metadata. Retain the
    chosen original digest; never manufacture a new digest or ignore source bytes,
    execution state/exit code, coverage, findings or any other analysis field.
    """
    volatile = {"scanned_at", "report_digest", "freshness", "target_revision", "retry", "attempt_history"}
    value = {key: copy.deepcopy(child) for key, child in record.items() if key not in volatile}
    value["execution"] = {key: child for key, child in value["execution"].items()
        if key not in {"started_at", "finished_at", "acquisition_seconds", "analysis_seconds"}}
    return report_json(value)


def recovery_history_contains(history, entries):
    return bool(entries) and any(history[index:index + len(entries)] == entries
        for index in range(len(history) - len(entries) + 1))


def mark_recovery_uncertainty(record, attempt, reason, message):
    """Limit publication and schedule bounded work without changing real scan history."""
    scanner.add_coverage_reason(record, reason, message)
    scanner.add_coverage_reason(record, "normalization_truncated",
        "Recovery evidence is not fully represented as one complete original report; a fresh scan is required.")
    if record["status"] != "error":
        record["status"] = record["coverage"]["status"] = "partial"
        record["findings_truncated"] = True
        record["coverage"]["grouping_complete"] = False
    operational = {"recovery_conflict", "recovery_conflict_attempt_limit",
        "recovery_predecessor_unavailable", "recovery_predecessor_unavailable_attempt_limit"}
    if attempt["reason"] not in operational:
        can_retry = attempt["attempt_count"] < contract.RETRY_POLICY["maximum_attempts_per_identity"]
        profile = record["profile"]["id"]
        next_profile = attempt["next_profile"] or (profile if profile in scanner.PROFILES else attempt["profile"]["id"])
        next_at = max(scanner.now(), attempt["next_attempt_at"] or attempt["last_attempted_at"])
        attempt.update(disposition="scheduled" if can_retry else "exhausted",
            reason=reason if can_retry else reason + "_attempt_limit",
            next_attempt_at=next_at if can_retry else None,
            next_profile=next_profile if can_retry else None)


def predecessor_uncertain(record):
    return any(reason["code"] == "recovery_predecessor_unavailable" for reason in record["coverage"]["reasons"])


def mark_missing_predecessor(record, attempt):
    mark_recovery_uncertainty(record, attempt, "recovery_predecessor_unavailable",
        "An authenticated execution has a complete original attempt history, but its predecessor report was "
        "outside the bounded recovery window. This original evidence is retained with uncertainty until a fresh scan.")


def quarantine_recovery(records, attempts, item, outcome):
    """Keep an original adverse report and disclose that alternate evidence is omitted.

    Attempt numbers belong to the originating queue lineage. A conflicting fork
    does not reset that history or fabricate another scanner execution. Existing
    fields can represent this publication limitation and a bounded fresh retry.
    """
    identifier = item["id"]
    old, new = records[identifier], outcome["record"]

    def rank(record):
        # Prefer content warnings over a clean report. The tie break uses only
        # preserved original fields, so derived quarantine flags cannot change
        # the representative on a replay or when batch order changes.
        original = {key: record.get(key) for key in ("source", "scanner", "profile", "skill_name",
            "scanned_at", "report_digest", "findings", "errors", "raw_finding_count", "finding_group_count")}
        return (bool(record["finding_count"] or record["findings"]), record["finding_count"],
                len(record["findings"]), record["execution"]["state"] != "failed", report_json(original))

    retained = copy.deepcopy(max((old, new), key=rank))
    mark_recovery_uncertainty(retained, attempts[identifier], "recovery_conflict",
        "Independent authenticated executions disagree. This original report is retained; "
        "other authenticated outcomes are not fully represented. Their immutable checkpoint artifacts remain available.")
    records[identifier] = retained


def recover_previous(selection, previous, recovery_bundles, *, source_commit, discovery_summary, output_dir,
                     diagnostics=None):
    """Reconcile authenticated older-run outcomes at exact currently selected identities.

    The transport authenticates producing runs/artifacts before this pure boundary.
    Original selection, discovery and worker validation are repeated here. Nothing
    becomes current solely because it was present in an older artifact.
    """
    validate_selection(selection)
    validate_discovery_summary(discovery_summary, selection, source_commit)
    aliases = verified_aliases(previous, selection, discovery_summary)
    records = previous_records(previous, selection, repository_aliases=aliases)
    attempts = compatible_attempts(previous, selection)
    targets = {source_digest(item): item for item in selection["sources"]}
    require(len(targets) == len(selection["sources"]), "ambiguous recovery target identity")
    diagnostics = {} if diagnostics is None else diagnostics
    diagnostics.update(equivalent_executions=0, conflicting_executions=0,
        missing_predecessor_executions=0, examples=[])
    outcomes, grouped, seen_outcomes = [], {}, set()
    identities = {}
    # Prefix strictness applies to each actual producing run/attempt, including
    # snapshots split across separate artifact packages. Origin-less legacy pure
    # callers retain strict conflict behavior; only authenticated origins may fork.
    batches = []
    for batch in recovery_bundles:
        origin = batch.get("execution_origin")
        if origin is None:
            batches.append(batch)
            continue
        v2.exact(origin, ("run_id", "run_attempt"), "recovery execution origin")
        require(all(type(value) is int and value > 0 for value in origin.values()), "invalid recovery execution origin")
        key = origin["run_id"], origin["run_attempt"]
        if key in grouped:
            prior = grouped[key]
            require(prior["selection"] == batch["selection"] and prior["discovery"] == batch["discovery"],
                    "one execution origin has conflicting preparation snapshots")
            prior["workers"].extend(batch["workers"])
        else:
            grouped[key] = {**batch, "workers": list(batch["workers"])}
            batches.append(grouped[key])
    for batch in batches:
        origin = batch.get("execution_origin")
        original_selection, original_summary = batch["selection"], batch["discovery"]
        original_commit = batch.get("source_commit", original_summary["source_commit"])
        validate_selection(original_selection)
        validate_discovery_summary(original_summary, original_selection, original_commit)
        require(original_summary.get("catalog", {}).get("mode") != "controlled_immutable_regression",
                "controlled regression artifacts cannot recover production evidence")
        workers, _ = coalesce_workers(batch["workers"], original_selection, original_commit)
        original_items = {item["id"]: item for item in original_selection["sources"]}
        for worker in workers:
            for value in worker["attempts"]:
                original = original_items[value["attempt"]["id"]]
                target = targets.get(source_digest(original))
                if target is None:
                    continue
                outcome = copy.deepcopy(value)
                for key in ("attempt", "record"):
                    outcome[key]["id"] = target["id"]
                identity = (source_digest(target), outcome["attempt"]["attempt_count"])
                prior = identities.get(identity)
                require(prior is None or prior[0] == outcome or origin is not None and prior[1] is not None,
                        "conflicting recovered outcomes")
                identities.setdefault(identity, (outcome, origin))
                outcome_digest = sha256_digest(report_json(outcome))
                if outcome_digest not in seen_outcomes:
                    seen_outcomes.add(outcome_digest)
                    attempt = outcome["attempt"]
                    require(len(attempt["history"]) >= attempt["attempt_count"] and
                        all(left["at"] <= right["at"] for left, right in zip(attempt["history"], attempt["history"][1:])),
                        "recovered attempt history is incomplete or regresses")
                    prefix = attempt["history"][:-1]
                    parent = {"attempt_count": attempt["attempt_count"] - 1, "history": prefix} if attempt["attempt_count"] > 1 else None
                    require(attempt == make_attempt(target, outcome["record"], parent,
                        {"attempt_history": prefix}, at=attempt["last_attempted_at"]), "recovered attempt lineage differs")
                    outcomes.append((target, outcome, origin))
    # Authentication and a complete, self-consistent original history can retain
    # higher-count evidence when a bounded window has not yet acquired its parent.
    # It remains explicitly uncertain, and never restarts its counter at one.
    unanchored = set()
    uncertain_ids = set()  # Only newly unanchored evidence in this recovery batch propagates.
    for item, outcome, origin in outcomes:
        attempt = outcome["attempt"]
        if attempt["attempt_count"] == 1:
            continue
        persisted = attempts.get(item["id"])
        prefix = attempt["history"][:-1]
        epoch = attempt["history"][-attempt["attempt_count"]:]
        represented = epoch if origin is not None else attempt["history"]
        known = persisted is not None and (recovery_history_contains(persisted["history"], represented) or
            persisted["attempt_count"] == attempt["attempt_count"] - 1 and persisted["history"][-len(prefix):] == prefix)
        known = known or bool(prefix) and any(parent["attempt"]["attempt_count"] == attempt["attempt_count"] - 1 and
            parent["attempt"]["history"][-len(prefix):] == prefix
            for parent_item, parent, _ in outcomes if parent_item["id"] == item["id"])
        if not known and origin is not None and persisted is not None and persisted["attempt_count"] >= attempt["attempt_count"]:
            continue  # Independent authenticated forks use reconciliation below.
        if not known:
            require(origin is not None and len(epoch) == attempt["attempt_count"] and
                    all(entry["profile"] in scanner.ALL_PROFILES for entry in epoch),
                    "recovered attempt count is not consecutive: missing predecessor")
            unanchored.add(sha256_digest(report_json(outcome)))
            uncertain_ids.add(item["id"])
    applied, recovered_ids = 0, set()
    for item, outcome, origin in sorted(outcomes, key=lambda value: (
            value[1]["attempt"]["last_attempted_at"], value[1]["attempt"]["attempt_count"], value[0]["id"],
            sha256_digest(report_json(value[1])))):
        old_attempt, old_record = attempts.get(item["id"]), records.get(item["id"])
        if origin is not None and old_attempt is None and outcome["attempt"]["attempt_count"] == 1:
            # A new identity may legitimately carry older source/policy history.
            # Its current epoch has no retry predecessor; preserve the verified
            # original prefix instead of recomputing it from an unrelated snapshot.
            attempts[item["id"]] = copy.deepcopy(outcome["attempt"])
            if old_record is None or old_record["status"] == "error" or outcome["record"]["status"] != "error":
                records[item["id"]] = copy.deepcopy(outcome["record"])
                records[item["id"]]["freshness"] = "current"
            if item["id"] in uncertain_ids:
                mark_missing_predecessor(records[item["id"]], attempts[item["id"]])
            applied += 1
            recovered_ids.add(item["id"])
            continue
        if sha256_digest(report_json(outcome)) in unanchored and (old_attempt is None or
                outcome["attempt"]["attempt_count"] > old_attempt["attempt_count"]):
            identifier = item["id"]
            attempts[identifier] = copy.deepcopy(outcome["attempt"])
            if old_record is None or old_record["status"] == "error":
                records[identifier] = copy.deepcopy(outcome["record"])
                records[identifier]["freshness"] = "current"
            elif outcome["record"]["status"] != "error":
                quarantine_recovery(records, attempts, item, outcome)
            mark_missing_predecessor(records[identifier], attempts[identifier])
            diagnostics["missing_predecessor_executions"] += 1
            if len(diagnostics["examples"]) < 32:
                diagnostics["examples"].append({"id": identifier, "reason": "recovery_predecessor_unavailable",
                    "execution_origin": copy.deepcopy(origin)})
            applied += 1
            recovered_ids.add(identifier)
            continue
        if origin is not None and old_attempt is not None:
            attempt = outcome["attempt"]
            scheduling = {"reason", "disposition", "next_attempt_at", "next_profile"}
            if predecessor_uncertain(old_record) and \
                    {key: value for key, value in old_attempt.items() if key not in scheduling} == \
                    {key: value for key, value in attempt.items() if key not in scheduling}:
                continue  # Exact original execution replay; retain its existing uncertainty/schedule.
            if attempt == old_attempt and outcome["record"]["status"] == "error" and old_record["status"] != "error":
                continue  # Exact replay of a failure already retaining useful prior evidence.
            if attempt["attempt_count"] < old_attempt["attempt_count"] and \
                    recovery_history_contains(old_attempt["history"], attempt["history"][-attempt["attempt_count"]:]):
                if old_record["status"] == "error" and predecessor_uncertain(old_record) and outcome["record"]["status"] != "error":
                    records[item["id"]] = copy.deepcopy(outcome["record"])
                    records[item["id"]]["freshness"] = "current"
                    mark_missing_predecessor(records[item["id"]], old_attempt)
                    recovered_ids.add(item["id"])
                continue
            follows = attempt["attempt_count"] == old_attempt["attempt_count"] + 1 and \
                old_attempt["history"][-len(attempt["history"][:-1]):] == attempt["history"][:-1]
            if not follows:
                if recovery_analysis(old_record) == recovery_analysis(outcome["record"]):
                    diagnostics["equivalent_executions"] += 1
                else:
                    before = copy.deepcopy((old_record, old_attempt))
                    quarantine_recovery(records, attempts, item, outcome)
                    if predecessor_uncertain(old_record) or item["id"] in uncertain_ids:
                        mark_missing_predecessor(records[item["id"]], attempts[item["id"]])
                    if (records[item["id"]], attempts[item["id"]]) != before:
                        recovered_ids.add(item["id"])
                    diagnostics["conflicting_executions"] += 1
                    if len(diagnostics["examples"]) < 32:
                        diagnostics["examples"].append({"id": item["id"], "reason": "recovery_conflict",
                            "execution_origin": copy.deepcopy(origin)})
                continue
        if apply_outcome(records, attempts, item, outcome, replay=True):
            applied += 1
            recovered_ids.add(item["id"])
            if item["id"] in uncertain_ids:
                mark_missing_predecessor(records[item["id"]], attempts[item["id"]])
    aligned = {"manifest": {"schema_version": 3, "scanner": SCANNER, "profile": PROFILE,
            "profiles": scanner.ALL_PROFILES, "repository_aliases": aliases},
        "selection": selection, "records": records, "attempts": attempts,
        "queue_cursor": ((previous or {}).get("queue_cursor", 0) + applied) % 3}
    empty = {"schema_version": 3, "source_commit": source_commit, "generated_at": scanner.now(),
        "selection_digest": sha256_digest(canonical_json(selection)), "scanner": SCANNER, "profile": PROFILE,
        "partition": {"index": 0, "count": 1}, "attempts": []}
    return merge_reports(selection, aligned, [empty], source_commit=source_commit, output_dir=output_dir,
        discovery_summary=discovery_summary, expected_partition_count=1, recovered_sources=len(recovered_ids))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--scanner", type=Path, required=True)
    scan.add_argument("--partition-index", type=int, required=True)
    scan.add_argument("--partition-count", type=int, default=MAX_PARTITIONS)
    scan.add_argument("--maximum-attempts", type=int, default=DEFAULT_ATTEMPTS)
    scan.add_argument("--slice-attempts", type=int)
    scan.add_argument("--budget-seconds", type=int, default=2100)
    scan.add_argument("--mirror-root", type=Path)
    scan.add_argument("--output", type=Path, required=True)
    merge = commands.add_parser("merge")
    merge.add_argument("--workers", type=Path, nargs="+", required=True)
    merge.add_argument("--output-dir", type=Path, required=True)
    merge.add_argument("--expected-partition-count", type=int)
    merge.add_argument("--allow-partial-workers", action="store_true")
    merge.add_argument("--recovered-sources", type=int, default=0)
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
            resume = read_json(args.output, max_bytes=MAX_WORKER_BYTES) if args.output.exists() else None
            worker = scan_partition(selection, args.scanner.resolve(), previous, source_commit=args.source_commit,
                partition_index=args.partition_index, partition_count=args.partition_count, maximum_attempts=args.maximum_attempts,
                budget_seconds=args.budget_seconds, mirror_root=args.mirror_root, discovery_summary=summary,
                resume=resume, slice_attempts=args.slice_attempts,
                checkpoint=lambda value: write_bounded(args.output, value, MAX_WORKER_BYTES))
            validate_worker(worker, selection, args.source_commit)
            write_bounded(args.output, worker, MAX_WORKER_BYTES)
        else:
            workers = [read_json(path, max_bytes=MAX_WORKER_BYTES) for path in args.workers]
            manifest = merge_reports(selection, previous, workers, source_commit=args.source_commit,
                output_dir=args.output_dir, discovery_summary=summary,
                expected_partition_count=args.expected_partition_count, allow_partial_workers=args.allow_partial_workers,
                recovered_sources=args.recovered_sources)
            print(json.dumps(manifest["coverage"], sort_keys=True))
        return 0
    except (PublicationError, CheckpointYield, OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        print(f"SkillSpector v3 coverage failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
