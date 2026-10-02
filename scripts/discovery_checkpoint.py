"""Bounded, atomic Discovery progress. Never contains package bytes or tokens."""
from __future__ import annotations

import json
import math
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from scripts.directory_publication import PublicationError, canonical_json, parse_timestamp, sha256_digest

MAX_BYTES = 32 << 20
MAX_ENTRIES = 10_000
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
MANIFEST = re.compile(r"^(?:[A-Za-z0-9._-]+/)*plugin\.json$")


class CheckpointYield(Exception):
    """A cooperative slice boundary, neither a scan error nor completeness."""


class WorkBudget:
    def __init__(self, seconds, *, monotonic=None):
        check(type(seconds) in {int, float} and math.isfinite(seconds) and 0 < seconds <= 86400,
              "work budget must be finite, positive and at most 86400 seconds")
        self.monotonic = monotonic or time.monotonic
        self.deadline = self.monotonic() + seconds

    def check(self):
        if self.monotonic() >= self.deadline:
            raise CheckpointYield("work budget exhausted; checkpoint preserved")

    def remaining(self):
        seconds = self.deadline - self.monotonic()
        if seconds <= 0:
            raise CheckpointYield("work budget exhausted; checkpoint preserved")
        return seconds

    def wait(self, seconds, sleep):
        # Honor an already-received retry/pacing delay even across the slice
        # boundary. Yielding before it would let the next process immediately
        # retry and bypass the server's backoff. Production waits are bounded.
        sleep(seconds)
        self.check()


def check(condition, message):
    if not condition:
        raise ValueError("Discovery checkpoint: " + message)


def keys(value, expected):
    check(type(value) is dict and set(value) == set(expected), "invalid fields")


def bounded_list(value):
    check(type(value) is list and len(value) <= MAX_ENTRIES, "invalid entry count")


def text(value, limit=4096):
    check(type(value) is str and len(value) <= limit, "invalid string")


def diagnostics(value):
    bounded_list(value)
    for item in value:
        keys(item, {"kind", "repository", "path", "error"})
        for field in item.values():
            text(field, 65536)
        check(item["kind"] in {"unsupported_source", "unavailable", "invalid", "scan_error"}, "invalid diagnostic")


def implementation_digest(root):
    files = [root / "scripts" / name for name in (
        "build_discovery_index.py", "discovery_checkpoint.py", "build_bridges.py",
        "build_registry.py", "directory_publication.py",
    )] + sorted((root / "schemas").rglob("*.json"))
    return sha256_digest(canonical_json({str(path.relative_to(root)): sha256_digest(path.read_bytes()) for path in files}))


def atomic_json(path, value):
    data = canonical_json(value)
    check(len(data) <= MAX_BYTES, "size limit exceeded")
    path.parent.mkdir(parents=True, exist_ok=True)
    check(not path.parent.is_symlink(), "symlink directory")
    check(not path.is_symlink(), "symlink destination")
    descriptor, temporary = tempfile.mkstemp(prefix=".discovery-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def acquisition_payload(value, queries, maximum_size):
    keys(value, {"complete", "refresh_paths", "stages"})
    check(type(value["complete"]) is bool, "invalid completion")
    check(type(value["refresh_paths"]) is dict and len(value["refresh_paths"]) <= MAX_ENTRIES, "invalid refresh paths")
    check(not queries or not value["refresh_paths"], "unexpected refresh paths in full acquisition")
    for repository, paths in value["refresh_paths"].items():
        check(REPOSITORY.fullmatch(repository) is not None, "invalid repository")
        bounded_list(paths)
        for path in paths:
            text(path)
            check(not path or MANIFEST.fullmatch(path + "/plugin.json") is not None, "invalid package path")
            check(not any(part in {".", ".."} for part in path.split("/")), "unsafe package path")
    check(type(value["stages"]) is dict and set(value["stages"]).issubset(queries), "invalid search stages")
    for query, stage in value["stages"].items():
        keys(stage, {"queue", "partitions", "items", "diagnostics"})
        for field in ("queue", "partitions", "items"):
            bounded_list(stage[field])
        intervals = []
        for interval in stage["queue"]:
            check(type(interval) is list and len(interval) == 2, "invalid queue interval")
            check(all(type(bound) is int for bound in interval), "invalid queue bounds")
            intervals.append(interval)
        for partition in stage["partitions"]:
            keys(partition, {"query", "size_min", "size_max", "total_count"})
            low, high = partition["size_min"], partition["size_max"]
            check(type(low) is int and type(high) is int, "invalid partition bounds")
            check(partition["query"] == f"{query} size:{low}..{high}", "invalid partition query")
            check(type(partition["total_count"]) is int and 0 <= partition["total_count"] <= 90, "invalid partition count")
            intervals.append([low, high])
        cursor = 0
        for low, high in sorted(intervals):
            check(type(low) is int and type(high) is int and low == cursor and low <= high <= maximum_size, "search coverage is invalid")
            cursor = high + 1
        check(cursor == maximum_size + 1, "search coverage is incomplete")
        seen = set()
        for item in stage["items"]:
            keys(item, {"repository", "manifest_path"})
            # These are inert API hit strings, not paths to read or fetch. Keep
            # unsupported hits so the ordinary candidate filter emits exactly
            # the same diagnostics after a resumed search.
            text(item["repository"])
            text(item["manifest_path"])
            check(item["manifest_path"].rsplit("/", 1)[-1] == "plugin.json", "invalid manifest basename")
            identity = (item["repository"].casefold(), item["manifest_path"].casefold())
            check(identity not in seen, "duplicate search item")
            seen.add(identity)
        diagnostics(stage["diagnostics"])
    if value["complete"]:
        check(set(value["stages"]) == set(queries) and all(not stage["queue"] for stage in value["stages"].values()), "unfinished acquisition")


class DiscoveryCheckpoint:
    def __init__(self, directory, *, root, config, mode, generated_at=None, previous_records=(), now=None):
        self.directory = Path(directory)
        self.now = now or datetime.now(timezone.utc)
        effective = "discover" if mode == "refresh" and not previous_records else mode
        queries = [] if effective == "refresh" else [config["query"]]
        for seed in config["seeds"] if queries else []:
            queries.extend(config["query"] + " repo:" + seed["repository"] + (" path:" + prefix if prefix else "") for prefix in seed["paths"] or [""])
        self.queries = list(dict.fromkeys(queries))
        self.maximum_size = config["maximum_file_size"]
        self.binding = {"implementation": implementation_digest(root), "source_commit": os.environ.get("GITHUB_SHA"), "config": sha256_digest(canonical_json(config)), "mode": mode,
                        "refresh_previous": sha256_digest(canonical_json(previous_records)) if effective == "refresh" else None}
        self.path = self.directory / "acquisition.json"
        if self.path.exists():
            envelope = self.read(self.path, "acquisition")
            check(envelope["binding"] == self.binding, "configuration, mode or implementation changed")
            if generated_at is not None:
                check(generated_at == envelope["generated_at"], "generated_at changed")
            self.generated_at = envelope["generated_at"]
            self.payload = envelope["payload"]
            acquisition_payload(self.payload, self.queries, self.maximum_size)
        else:
            self.generated_at = generated_at or self.now.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.payload = {"complete": False, "refresh_paths": {}, "stages": {}}
        self.fresh(self.generated_at)
        self.results = {}
        self.validation_binding = None

    def fresh(self, timestamp):
        try:
            parsed = parse_timestamp(timestamp, "checkpoint.generated_at")
        except PublicationError as error:
            raise ValueError("Discovery checkpoint: invalid timestamp") from error
        check(0 <= (self.now - parsed).total_seconds() <= 86400, "stale or future checkpoint")

    def read(self, path, kind):
        check(not path.is_symlink() and path.stat().st_size <= MAX_BYTES, "invalid file or size")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                check(key not in result, "duplicate JSON key")
                result[key] = value
            return result
        try:
            with path.open("rb") as stream:
                body = stream.read(MAX_BYTES + 1)
            check(len(body) <= MAX_BYTES, "size limit exceeded")
            value = json.loads(body, object_pairs_hook=unique)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("Discovery checkpoint: invalid JSON") from error
        keys(value, {"checkpoint_schema_version", "kind", "generated_at", "binding", "payload", "payload_digest"})
        check(type(value["checkpoint_schema_version"]) is int and value["checkpoint_schema_version"] == 1 and value["kind"] == kind, "invalid version or kind")
        text(value["generated_at"], 32)
        self.fresh(value["generated_at"])
        try:
            payload_digest = sha256_digest(canonical_json(value["payload"]))
        except (PublicationError, RecursionError) as error:
            raise ValueError("Discovery checkpoint: invalid payload") from error
        check(type(value["payload_digest"]) is str and DIGEST.fullmatch(value["payload_digest"]) is not None and value["payload_digest"] == payload_digest, "payload digest mismatch")
        return value

    def envelope(self, kind, binding, payload):
        return {"checkpoint_schema_version": 1, "kind": kind, "generated_at": self.generated_at,
                "binding": binding, "payload": payload, "payload_digest": sha256_digest(canonical_json(payload))}

    def save_acquisition(self):
        acquisition_payload(self.payload, self.queries, self.maximum_size)
        atomic_json(self.path, self.envelope("acquisition", self.binding, self.payload))

    def start_validation(self, context, validate_records):
        check(self.payload["complete"], "acquisition is incomplete")
        self.validation_binding = sha256_digest(canonical_json({"acquisition": self.envelope("acquisition", self.binding, self.payload), "context": context}))
        path = self.directory / "validation.json"
        if not path.exists():
            return
        envelope = self.read(path, "validation")
        check(envelope["generated_at"] == self.generated_at and type(envelope["binding"]) is str and DIGEST.fullmatch(envelope["binding"]) is not None, "invalid validation binding")
        payload = envelope["payload"]
        keys(payload, {"results"})
        check(type(payload["results"]) is dict and len(payload["results"]) <= MAX_ENTRIES, "invalid repository result count")
        all_records = []
        for repository, result in payload["results"].items():
            check(REPOSITORY.fullmatch(repository) is not None, "invalid result repository")
            keys(result, {"input_digest", "records", "diagnostics"})
            check(type(result["input_digest"]) is str and DIGEST.fullmatch(result["input_digest"]) is not None, "invalid input digest")
            bounded_list(result["records"])
            identities = set()
            for entry in result["records"]:
                check(type(entry) is list and len(entry) == 2, "invalid record entry")
                identity, record = entry
                text(identity)
                parts = identity.split("\x00")
                check(len(parts) == 2 and REPOSITORY.fullmatch(parts[0]) is not None
                      and (not parts[1] or MANIFEST.fullmatch(parts[1] + "/plugin.json") is not None)
                      and not any(part in {".", ".."} for part in parts[1].split("/")), "invalid record identity")
                check(identity not in identities, "duplicate record identity")
                identities.add(identity)
                all_records.append(record)
            check(len(all_records) <= MAX_ENTRIES, "invalid total record count")
            diagnostics(result["diagnostics"])
            check(not any(item["kind"] == "scan_error" for item in result["diagnostics"]), "cached scan error")
        validate_records(all_records)
        if envelope["binding"] == self.validation_binding:
            self.results = payload["results"]

    def result(self, repository, input_digest):
        result = self.results.get(repository)
        if result and result["input_digest"] == input_digest:
            return result["records"], result["diagnostics"]
        return None

    def save_result(self, repository, input_digest, records, result_diagnostics):
        diagnostics(result_diagnostics)
        if any(item["kind"] == "scan_error" for item in result_diagnostics):
            return
        self.results[repository] = {"input_digest": input_digest, "records": records, "diagnostics": result_diagnostics}
        self.save_validation()

    def save_validation(self):
        check(self.validation_binding is not None, "validation has not started")
        atomic_json(self.directory / "validation.json", self.envelope("validation", self.validation_binding, {"results": self.results}))
