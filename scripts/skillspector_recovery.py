#!/usr/bin/env python3
"""Bounded, read-only Actions checkpoint transport and authenticated recovery.

Scanner jobs never receive publication credentials. Immutable Actions artifacts
are the remote acknowledgement; only canonical main runs can feed production.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError, canonical_json, parse_timestamp, require
from scripts.publish_skillspector_reports import REPOSITORY
from scripts.skillspector_publication_transport import GitHub, GitHubTransportError

WORKFLOW = ".github/workflows/skillspector-reports.yml"
ARTIFACT = re.compile(r"skillspector-checkpoint-(?:a([1-9][0-9]{0,3})-)?p([0-7])-s([1-3])\Z")
STATE_FILE = "recovery.json"
MAX_STATE_BYTES = 32 << 20
MAX_RUNS = 1024
MAX_RUN_ARTIFACTS = 192
MAX_LIST_PAGES = 5
MAX_STATUS_BYTES = 256 << 10
MAX_RECOVERY_RUNS = 8
MAX_ARCHIVE_BYTES = 128 << 20
MAX_TOTAL_BYTES = 1 << 30
RETENTION_DAYS = 90
FILES = {"selection.json": coverage.MAX_SELECTION_BYTES,
         "coverage.json": coverage.MAX_DISCOVERY_BYTES,
         "worker.json": coverage.MAX_WORKER_BYTES}
MAX_PROVENANCE_BYTES = 16 << 10


def integer(value, label):
    require(type(value) is int and 0 < value < 2**63, "invalid " + label)
    return value


def validate_state(value, *, max_bytes=None, max_runs=None):
    max_bytes = MAX_STATE_BYTES if max_bytes is None else max_bytes
    max_runs = MAX_RUNS if max_runs is None else max_runs
    require(isinstance(value, dict) and set(value) in ({"schema_version", "runs"}, {"schema_version", "runs", "cursor"}), "invalid recovery state fields")
    cursor = value.get("cursor")
    if cursor is not None:
        coverage.v2.exact(cursor, ("before", "page", "offset"), "recovery cursor")
        coverage.v2.timestamp(cursor["before"], "recovery cursor.before")
        require(type(cursor["page"]) is int and 1 <= cursor["page"] <= 10000 and
                type(cursor["offset"]) is int and 0 <= cursor["offset"] < 100, "invalid recovery cursor")
    require(value["schema_version"] == 1 and isinstance(value["runs"], list) and
            len(value["runs"]) <= max_runs, "invalid recovery state")
    seen = set()
    for run in value["runs"]:
        require(isinstance(run, dict) and {"run_id", "run_attempt", "head_sha", "created_at", "artifacts"} <= set(run) <=
                {"run_id", "run_attempt", "head_sha", "created_at", "artifacts", "rejections", "complete"}, "invalid recovery acknowledgement")
        require(type(run.get("complete", True)) is bool and isinstance(run.get("rejections", []), list) and
                len(run.get("rejections", [])) <= MAX_RUN_ARTIFACTS, "invalid recovery quarantine")
        for rejection in run.get("rejections", []):
            coverage.v2.exact(rejection, ("id", "reason"), "recovery rejection")
            integer(rejection["id"], "rejected artifact id")
            require(rejection["reason"] in {"invalid_checkpoint", "expired_checkpoint", "excluded_controlled", "unsupported_policy"},
                    "invalid rejection reason")
        key = (integer(run["run_id"], "run id"), integer(run["run_attempt"], "run attempt"))
        require(key not in seen and coverage.SHA.fullmatch(run["head_sha"]), "duplicate or invalid recovery run")
        seen.add(key)
        coverage.v2.timestamp(run["created_at"], "recovery.created_at")
        require(len(run["created_at"]) <= 32, "recovery timestamp exceeds bound")
        require(isinstance(run["artifacts"], list) and len(run["artifacts"]) <= MAX_RUN_ARTIFACTS, "invalid acknowledged artifacts")
        ids = set()
        for artifact in run["artifacts"]:
            coverage.v2.exact(artifact, ("id", "digest"), "acknowledged artifact")
            require(integer(artifact["id"], "artifact id") not in ids and
                    re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]), "invalid artifact acknowledgement")
            ids.add(artifact["id"])
        rejected_ids = [row["id"] for row in run.get("rejections", [])]
        require(len(rejected_ids) == len(set(rejected_ids)) and not ids.intersection(rejected_ids) and
                len(ids) + len(rejected_ids) <= MAX_RUN_ARTIFACTS,
                "recovery artifact disposition count differs")
    require(len(canonical_json(value)) <= max_bytes, "recovery acknowledgements exceed limit")
    return value


def compact_state(value, *, now=None):
    """Keep the newest valid acknowledgements within fixed count/byte/age limits.

    Older published files may be read within a finite 2x repair envelope. We
    never trust malformed records, and the next write uses the strict budget.
    """
    validate_state(value, max_bytes=MAX_STATE_BYTES * 2, max_runs=MAX_RUNS * 2)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=RETENTION_DAYS)
    ordered = sorted((run for run in value["runs"]
                      if parse_timestamp(run["created_at"], "created_at") >= cutoff),
                     key=lambda run: (run["created_at"], run["run_id"], run["run_attempt"]))
    result = {"schema_version": 1, "runs": ordered}
    if "cursor" in value:
        result["cursor"] = value["cursor"]
    # Exact canonical encoding size, without repeatedly serializing a large list.
    total = len(canonical_json({**result, "runs": []}))
    sizes = [len(canonical_json(run)) - 1 for run in ordered]
    total += sum(sizes) + max(0, len(ordered) - 1)
    start = 0
    while start < len(ordered) and (len(ordered) - start > MAX_RUNS or total > MAX_STATE_BYTES):
        total -= sizes[start] + (1 if len(ordered) - start > 1 else 0)
        start += 1
    result["runs"] = ordered[start:]
    return validate_state(result)


def read_state(path):
    if not path.exists():
        return {"schema_version": 1, "runs": []}
    require(path.is_file() and not path.is_symlink(), "recovery state must be regular")
    return compact_state(scanner.read_report_json(path, max_bytes=MAX_STATE_BYTES * 2))


def merge_state(*states, now=None):
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=RETENTION_DAYS)
    runs, cursor = {}, None
    for state in states:
        validate_state(state)
        if "cursor" in state:
            cursor = state["cursor"]
        for run in state["runs"]:
            if parse_timestamp(run["created_at"], "created_at") < cutoff:
                continue
            key = run["run_id"], run["run_attempt"]
            if key in runs:
                old = runs[key]
                require(all(old[field] == run[field] for field in ("head_sha", "created_at")),
                        "conflicting recovery acknowledgement")
                entries = {row["id"]: row for row in old["artifacts"]}
                for artifact in run["artifacts"]:
                    require(artifact["id"] not in entries or entries[artifact["id"]] == artifact,
                            "conflicting acknowledged artifact")
                    entries[artifact["id"]] = artifact
                rejections = {row["id"]: row for row in old.get("rejections", [])}
                rejections.update({row["id"]: row for row in run.get("rejections", [])})
                run = {**run, "artifacts": sorted(entries.values(), key=lambda r: r["id"]),
                       "rejections": sorted(rejections.values(), key=lambda r: r["id"])}
            runs[key] = run
    return compact_state({"schema_version": 1, "runs": list(runs.values()), "cursor": cursor}, now=now)


def validate_provenance(value, documents, *, allow_unsupported_policy=False):
    coverage.v2.exact(value, ("schema_version", "repository", "workflow", "run_id", "run_attempt", "head_branch",
        "head_sha", "event", "corpus", "partition", "slice", "files"), "checkpoint provenance")
    require(value["schema_version"] == 1 and value["repository"] == REPOSITORY and value["workflow"] == WORKFLOW,
            "checkpoint repository/workflow differs")
    integer(value["run_id"], "run id")
    integer(value["run_attempt"], "run attempt")
    require(isinstance(value["head_branch"], str) and 0 < len(value["head_branch"]) <= 255 and
            coverage.SHA.fullmatch(value["head_sha"]) and value["event"] in {"push", "schedule", "workflow_dispatch", "pull_request"} and
            value["corpus"] in {"catalog", "controlled"} and type(value["partition"]) is int and
            0 <= value["partition"] < 8 and type(value["slice"]) is int and 1 <= value["slice"] <= 3,
            "invalid checkpoint execution provenance")
    require(set(value["files"]) == set(FILES) and set(documents) == set(FILES), "checkpoint file set differs")
    for name, maximum in FILES.items():
        row, body = value["files"][name], documents[name]
        coverage.v2.exact(row, ("bytes", "digest"), "checkpoint file digest")
        require(0 < len(body) <= maximum and row == {"bytes": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest()},
                "checkpoint file identity differs")
    selection = scanner.parse_scanner_json(documents["selection.json"], "recovery selection")
    summary = scanner.parse_scanner_json(documents["coverage.json"], "recovery discovery")
    worker = scanner.parse_scanner_json(documents["worker.json"], "recovery worker")
    coverage.validate_selection(selection)
    coverage.validate_discovery_summary(summary, selection, value["head_sha"])
    unsupported = worker.get("scanner") != coverage.SCANNER or worker.get("profile") != coverage.PROFILE
    if unsupported and allow_unsupported_policy:
        require(worker.get("schema_version") == 3 and worker.get("source_commit") == value["head_sha"] and
                worker.get("selection_digest") == coverage.sha256_digest(canonical_json(selection)),
                "obsolete checkpoint source identity differs")
    else:
        coverage.validate_worker(worker, selection, value["head_sha"])
    require(worker["partition"]["index"] == value["partition"], "checkpoint partition differs")
    require((summary.get("catalog", {}).get("mode") == "controlled_immutable_regression") == (value["corpus"] == "controlled"),
            "checkpoint corpus differs")
    require(not scanner.has_public_credentials(worker), "checkpoint contains unredacted report text")
    return {"selection": selection, "discovery": summary, "source_commit": value["head_sha"], "workers": [worker],
            "unsupported_policy": unsupported,
            "execution_origin": {"run_id": value["run_id"], "run_attempt": value["run_attempt"]}}


def pack(plan_dir, worker_path, output_dir, *, slice_index, environment=None):
    env = os.environ if environment is None else environment
    documents = {name: scanner.read_bytes_bounded(worker_path if name == "worker.json" else plan_dir / name, maximum)
                 for name, maximum in FILES.items()}
    worker = scanner.parse_scanner_json(documents["worker.json"], "checkpoint worker")
    value = {"schema_version": 1, "repository": env.get("GITHUB_REPOSITORY"), "workflow": WORKFLOW,
        "run_id": int(env["GITHUB_RUN_ID"]), "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "head_branch": env["GITHUB_REF_NAME"], "head_sha": env["GITHUB_SHA"],
        "event": env["GITHUB_EVENT_NAME"], "corpus": env.get("SCAN_CORPUS", "catalog"),
        "partition": worker["partition"]["index"], "slice": slice_index,
        "files": {name: {"bytes": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest()}
                  for name, body in documents.items()}}
    validate_provenance(value, documents)
    require(not output_dir.exists(), "checkpoint package already exists")
    output_dir.mkdir(parents=True)
    for name, body in documents.items():
        (output_dir / name).write_bytes(body)
    coverage.write_bounded(output_dir / "provenance.json", value, MAX_PROVENANCE_BYTES)
    return value


def trusted_run(run, workflow_id):
    require(isinstance(run, dict) and isinstance(run.get("repository"), dict) and
            isinstance(run.get("head_repository"), dict) and run.get("repository", {}).get("full_name") == REPOSITORY and
            run.get("head_repository", {}).get("full_name") == REPOSITORY and run.get("workflow_id") == workflow_id and
            run.get("path") == WORKFLOW and run.get("head_branch") == "main" and
            run.get("event") in {"push", "schedule", "workflow_dispatch"} and run.get("status") == "completed" and
            coverage.SHA.fullmatch(run.get("head_sha", "")), "recovery requires a completed canonical main run")
    integer(run.get("id"), "run id")
    integer(run.get("run_attempt"), "run attempt")
    coverage.v2.timestamp(run.get("created_at"), "run.created_at")
    return run


def trusted_main_run(github, run, workflow_id, *, main_sha=None, ancestry=None):
    """A tag named main cannot supply code outside the actual main history."""
    if run is None or not isinstance(run, dict):
        raise GitHubTransportError("GitHub producing-run evidence unavailable; recovery deferred")
    trusted_run(run, workflow_id)
    if main_sha is None:
        main = github.request("GET", "git/ref/heads/main")
        if not isinstance(main, dict) or not isinstance(main.get("object"), dict):
            raise GitHubTransportError("GitHub main-branch evidence unavailable; recovery deferred")
        main_sha = main["object"].get("sha")
    if not isinstance(main_sha, str) or not coverage.SHA.fullmatch(main_sha):
        raise GitHubTransportError("GitHub main-branch evidence invalid; recovery deferred")
    if run["head_sha"] != main_sha and (ancestry is None or run["head_sha"] not in ancestry):
        comparison = github.request("GET", f"compare/{run['head_sha']}...{main_sha}?per_page=1")
        if not isinstance(comparison, dict) or comparison.get("status") not in {"ahead", "identical", "behind", "diverged"}:
            raise GitHubTransportError("GitHub ancestry evidence unavailable; recovery deferred")
        if comparison["status"] in {"ahead", "identical"} and not all(
                isinstance(comparison.get(key), dict) and isinstance(comparison[key].get("sha"), str) and
                coverage.SHA.fullmatch(comparison[key]["sha"]) for key in ("base_commit", "merge_base_commit")):
            raise GitHubTransportError("GitHub ancestry evidence invalid; recovery deferred")
        require(comparison["status"] in {"ahead", "identical"} and comparison.get("base_commit", {}).get("sha") == run["head_sha"] and
                comparison.get("merge_base_commit", {}).get("sha") == run["head_sha"],
                "producing source is outside the explicit main branch history")
        if ancestry is not None:
            ancestry.add(run["head_sha"])
    return run


def assembly_worker_paths(directory, selection, source_commit, *, run_id, run_attempt):
    """Accept the downloader's flat single-artifact or named multi-artifact layout."""
    require(directory.is_dir() and not directory.is_symlink(), "worker download directory must be regular")
    entries = sorted(directory.iterdir())
    require(0 < len(entries) <= 24, "worker download count exceeds bound")
    allowed = set(FILES) | {"provenance.json"}
    flat = (directory / "worker.json").exists()
    packages = [directory] if flat else entries
    if flat:
        require({path.name for path in entries} == allowed, "flat checkpoint contains unexpected files")
    result = []
    for package in packages:
        require(package.is_dir() and not package.is_symlink(), "checkpoint package must be a regular directory")
        match = None if flat else ARTIFACT.fullmatch(package.name)
        require(flat or match is not None and match[1] is not None and int(match[1]) == run_attempt,
                "checkpoint directory belongs to another run attempt")
        require({path.name for path in package.iterdir()} == allowed, "checkpoint package files differ")
        for path in package.iterdir():
            require(path.is_file() and not path.is_symlink(), "checkpoint package files must be regular")
        provenance = scanner.read_report_json(package / "provenance.json", max_bytes=MAX_PROVENANCE_BYTES)
        documents = {name: scanner.read_bytes_bounded(package / name, maximum) for name, maximum in FILES.items()}
        batch = validate_provenance(provenance, documents)
        require(provenance["run_id"] == run_id and provenance["run_attempt"] == run_attempt and
                provenance["head_sha"] == source_commit and batch["selection"] == selection,
                "checkpoint does not belong to the current prepared run")
        require(flat or provenance["partition"] == int(match[2]) and provenance["slice"] == int(match[3]),
                "checkpoint directory partition/slice differs")
        result.append(package / "worker.json")
    return result


class StripRedirectCredentials(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        require(newurl.startswith("https://"), "artifact redirect must use HTTPS")
        redirected = super().redirect_request(request, fp, code, message, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


def download_archive(artifact_id, token):
    integer(artifact_id, "artifact id")
    request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip",
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
                 "User-Agent": "uap-skillspector-recovery"})
    with urllib.request.build_opener(StripRedirectCredentials()).open(request, timeout=30) as response:
        body = response.read(MAX_ARCHIVE_BYTES + 1)
    require(len(body) <= MAX_ARCHIVE_BYTES, "checkpoint archive exceeds limit")
    return body


def unpack_archive(body, artifact, run, output_dir, *, allow_controlled=False, allow_unsupported_policy=False):
    require(isinstance(artifact.get("digest"), str) and artifact["digest"] == "sha256:" + hashlib.sha256(body).hexdigest(),
            "remote checkpoint archive digest differs")
    match = ARTIFACT.fullmatch(artifact.get("name", ""))
    require(match is not None and artifact.get("expired") is False and
            artifact.get("workflow_run", {}).get("id") == run["id"] and
            artifact.get("workflow_run", {}).get("head_sha") == run["head_sha"] and
            artifact.get("workflow_run", {}).get("head_branch") == "main", "artifact run provenance differs")
    allowed = set(FILES) | {"provenance.json"}
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        entries = archive.infolist()
        require(len(entries) == len(allowed) and {row.filename for row in entries} == allowed,
                "checkpoint archive contains unexpected or duplicate files")
        require(sum(row.file_size for row in entries) <= sum(FILES.values()) + MAX_PROVENANCE_BYTES,
                "checkpoint archive expansion exceeds limit")
        documents = {}
        for row in entries:
            maximum = FILES.get(row.filename, MAX_PROVENANCE_BYTES)
            mode = (row.external_attr >> 16) & 0o170000
            require(mode in (0, 0o100000) and not row.is_dir() and 0 < row.file_size <= maximum,
                    "checkpoint archive entry must be bounded regular data")
            with archive.open(row) as source:
                documents[row.filename] = source.read(maximum + 1)
            require(len(documents[row.filename]) == row.file_size, "checkpoint archive entry size differs")
    provenance = scanner.parse_scanner_json(documents.pop("provenance.json"), "checkpoint provenance")
    batch = validate_provenance(provenance, documents, allow_unsupported_policy=allow_unsupported_policy)
    require(provenance["head_branch"] == "main" and (provenance["corpus"] == "catalog" or allow_controlled) and
            provenance["run_id"] == run["id"] and provenance["run_attempt"] == run["run_attempt"] and
            provenance["head_sha"] == run["head_sha"] and provenance["event"] == run["event"] and
            (match[1] is None or provenance["run_attempt"] == int(match[1])) and
            provenance["partition"] == int(match[2]) and provenance["slice"] == int(match[3]),
            "checkpoint cannot cross branch/corpus/run attempt boundary")
    require(not output_dir.exists(), "recovery staging path already exists")
    output_dir.mkdir(parents=True)
    for name in FILES:
        (output_dir / name).write_bytes(documents[name])
    coverage.write_bounded(output_dir / "provenance.json", provenance, MAX_PROVENANCE_BYTES)
    return batch


def load_recovery_batches(directory):
    require(directory.is_dir() and not directory.is_symlink(), "recovery staging must be regular")
    children = sorted(directory.iterdir())
    require(len(children) <= (MAX_RECOVERY_RUNS + 1) * MAX_RUN_ARTIFACTS, "recovery staging exceeds artifact bound")
    batches = []
    for child in children:
        require(child.is_dir() and not child.is_symlink(), "invalid recovery staging entry")
        require({p.name for p in child.iterdir()} == set(FILES) | {"provenance.json"}, "recovery staging files differ")
        for path in child.iterdir():
            require(path.is_file() and not path.is_symlink(), "recovery files must be regular")
        value = scanner.read_report_json(child / "provenance.json", max_bytes=MAX_PROVENANCE_BYTES)
        documents = {name: scanner.read_bytes_bounded(child / name, maximum) for name, maximum in FILES.items()}
        require(value["head_branch"] == "main" and value["corpus"] == "catalog", "only main catalog checkpoints recover")
        batch = validate_provenance(value, documents)
        batch.pop("unsupported_policy")
        batches.append(batch)
    return batches


def run_artifacts(github, run_id):
    result = []
    for page in range(1, 4):
        listing = github.request("GET", f"actions/runs/{run_id}/artifacts?per_page=100&page={page}")
        require(isinstance(listing, dict) and isinstance(listing.get("artifacts"), list), "recovery artifact listing unavailable")
        result.extend(row for row in listing["artifacts"] if ARTIFACT.fullmatch(row.get("name", "")))
        require(len(result) <= MAX_RUN_ARTIFACTS, "recovery run artifact bound exceeded")
        if len(listing["artifacts"]) < 100:
            return result
    require(listing.get("total_count", 0) <= 300, "recovery artifact page bound exceeded")
    return result


def collect(github, directory, state, *, token, current_run=None, current_id=None, fetch_archive=None, now=None):
    """Advance a persistent created-at anchored cursor despite newer arrivals."""
    now = now or datetime.now(timezone.utc)
    fetch_archive = fetch_archive or download_archive
    workflow = github.request("GET", "actions/workflows/skillspector-reports.yml")
    require(isinstance(workflow, dict), "canonical recovery workflow unavailable")
    workflow_id = integer(workflow.get("id"), "workflow id")
    main = github.request("GET", "git/ref/heads/main")
    if not isinstance(main, dict) or not isinstance(main.get("object"), dict):
        raise GitHubTransportError("GitHub main-branch evidence unavailable; recovery deferred")
    main_sha, ancestry = main["object"].get("sha"), set()
    if not isinstance(main_sha, str) or not coverage.SHA.fullmatch(main_sha):
        raise GitHubTransportError("GitHub main-branch evidence invalid; recovery deferred")
    validate_state(state)
    acknowledged = {(r["run_id"], r["run_attempt"]): r for r in state["runs"]}
    cursor = state.get("cursor") or {"before": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "page": 1, "offset": 0}
    cutoff = now - timedelta(days=RETENTION_DAYS)
    if parse_timestamp(cursor["before"], "cursor.before") < cutoff:
        cursor = {"before": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "page": 1, "offset": 0}
    accepted, consumed, bytes_read, rejected, deferred = [], 0, 0, [], False
    directory.mkdir(parents=True, exist_ok=True)

    def process(run, *, force=False):
        nonlocal consumed, bytes_read, deferred
        key = run["id"], run["run_attempt"]
        old = acknowledged.get(key)
        if old:
            require(old["head_sha"] == run["head_sha"], "acknowledged run source changed")
            if old.get("complete", True) and not force:
                return True
        if consumed >= MAX_RECOVERY_RUNS:
            deferred = True
            return False
        artifacts = run_artifacts(github, run["id"])
        if not artifacts:
            return True  # Cursor advances; empty legacy runs do not fill acknowledgement state.
        artifact_acks = {row["id"]: row for row in (old or {}).get("artifacts", [])}
        quarantine = {row["id"]: row for row in (old or {}).get("rejections", [])}
        complete = True
        for artifact in sorted(artifacts, key=lambda a: a["name"]):
            identifier = integer(artifact.get("id"), "artifact id")
            if identifier in artifact_acks or identifier in quarantine:
                continue
            size = artifact.get("size_in_bytes")
            if type(size) is int and 0 < size <= MAX_ARCHIVE_BYTES and bytes_read + size > MAX_TOTAL_BYTES:
                deferred, complete = True, False
                break
            try:
                require(artifact.get("expired") is False, "checkpoint expired")
                require(type(size) is int and 0 < size <= MAX_ARCHIVE_BYTES, "checkpoint archive exceeds limit")
                body = fetch_archive(identifier, token)
                bytes_read += len(body)
                require(bytes_read <= MAX_TOTAL_BYTES, "recovery download budget exceeded")
                with zipfile.ZipFile(io.BytesIO(body)) as archive:
                    info = archive.getinfo("provenance.json")
                    require(0 < info.file_size <= MAX_PROVENANCE_BYTES, "checkpoint provenance exceeds bound")
                    envelope = scanner.parse_scanner_json(archive.read(info), "checkpoint provenance")
                attempt = integer(envelope.get("run_attempt"), "checkpoint run attempt")
                require(attempt <= run["run_attempt"], "checkpoint run attempt differs")
                producing = run if attempt == run["run_attempt"] else trusted_main_run(github, github.request("GET",
                    f"actions/runs/{run['id']}/attempts/{attempt}"), workflow_id, main_sha=main_sha, ancestry=ancestry)
                require(attempt <= run["run_attempt"] and producing["id"] == run["id"], "checkpoint run attempt differs")
                target = directory / f"{run['id']}-{attempt}-{identifier}"
                batch = unpack_archive(body, artifact, producing, target, allow_controlled=True, allow_unsupported_policy=True)
                if envelope.get("corpus") == "controlled" or batch["unsupported_policy"]:
                    shutil.rmtree(target)
                    reason = "excluded_controlled" if envelope.get("corpus") == "controlled" else "unsupported_policy"
                    quarantine[identifier] = {"id": identifier, "reason": reason}
                    rejected.append({"artifact_id": identifier, "reason": reason})
                else:
                    artifact_acks[identifier] = {"id": identifier, "digest": artifact["digest"]}
            except GitHubTransportError:
                raise
            except (PublicationError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
                # A permanently bad immutable artifact must not starve independent work.
                reason = "expired_checkpoint" if artifact.get("expired") is True else "invalid_checkpoint"
                quarantine[identifier] = {"id": identifier, "reason": reason}
                rejected.append({"artifact_id": identifier, "reason": reason})
        accepted.append({"run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
            "created_at": run["created_at"], "artifacts": sorted(artifact_acks.values(), key=lambda row: row["id"]),
            "rejections": sorted(quarantine.values(), key=lambda row: row["id"]), "complete": complete})
        consumed += 1
        return complete

    if current_run is not None:
        run = github.request("GET", f"actions/runs/{integer(current_run, 'current run')}")
        require(run and run.get("id") == current_run, "current acknowledgement run differs")
        run = trusted_main_run(github, {**run, "status": "completed"}, workflow_id, main_sha=main_sha, ancestry=ancestry)
        process(run, force=True)
        next_cursor = state.get("cursor")
    else:
        page, offset = cursor["page"], cursor["offset"]
        next_cursor = dict(cursor)
        finished = False
        for _ in range(MAX_LIST_PAGES):
            query = urllib.parse.urlencode({"branch": "main", "status": "completed", "per_page": 100,
                                           "page": page, "created": "<=" + cursor["before"]})
            result = github.request("GET", f"actions/workflows/{workflow_id}/runs?{query}")
            require(isinstance(result, dict) and isinstance(result.get("workflow_runs"), list), "recovery run listing unavailable")
            listed = result["workflow_runs"]
            require(len(listed) <= 100, "recovery run page exceeds bound")
            for index in range(offset, len(listed)):
                run = listed[index]
                next_cursor = {"before": cursor["before"], "page": page, "offset": index}
                try:
                    trusted_main_run(github, run, workflow_id, main_sha=main_sha, ancestry=ancestry)
                except GitHubTransportError:
                    raise
                except (PublicationError, TypeError, ValueError):
                    identifier = run.get("id") if isinstance(run, dict) else None
                    safe_id = identifier if type(identifier) is int and 0 < identifier < 2**63 else None
                    rejected.append({"run_id": safe_id, "reason": "untrusted_run"})
                    continue
                if parse_timestamp(run["created_at"], "created_at") < cutoff:
                    finished = True
                    break
                if run["id"] != current_id and not process(run):
                    deferred = True
                    break
                next_cursor = {"before": cursor["before"], "page": page, "offset": index + 1}
                if next_cursor["offset"] == 100:
                    next_cursor.update(page=page + 1, offset=0)
            else:
                if len(listed) < 100:
                    finished = True
                if not finished:
                    page, offset = page + 1, 0
                    next_cursor = {"before": cursor["before"], "page": page, "offset": 0}
                    continue
            break
        else:
            deferred = True
        if finished:
            next_cursor = None  # Next preparation starts a new anchored cycle.
    value = merge_state(state, {"schema_version": 1, "runs": accepted, "cursor": next_cursor}, now=now)
    return value, {"status": "deferred" if deferred else "ready", "runs": consumed, "bytes": bytes_read,
        "retention_days": RETENTION_DAYS, "maximum_runs_per_prepare": MAX_RECOVERY_RUNS,
        "cursor": next_cursor, "rejected": rejected[:MAX_RECOVERY_RUNS * MAX_RUN_ARTIFACTS + 500]}


def recover_plan(github, plan_dir, source_commit, *, token, current_id=None):
    previous = coverage.read_bundle(plan_dir / "previous")
    state = read_state(plan_dir / "previous" / STATE_FILE)
    staged = plan_dir / "recovery"
    if staged.exists() or staged.is_symlink():
        require(staged.is_dir() and not staged.is_symlink(), "recovery staging must be regular")
        shutil.rmtree(staged)  # Failed read-only attempts have no receipt; remote originals remain intact.
    new_state, summary = collect(github, staged, state, token=token, current_id=current_id)
    # A rerun of prepare can recover the same run's earlier acknowledged slices.
    if int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")) > 1 and current_id is not None:
        new_state, own = collect(github, staged, new_state, token=token, current_run=current_id)
        summary["rejected"].extend(own["rejected"])
        summary["runs"] += own["runs"]
    batches = load_recovery_batches(staged)
    summary["recovered_sources"] = 0
    summary["reconciliation"] = {"equivalent_executions": 0, "conflicting_executions": 0,
                                 "missing_predecessor_executions": 0, "examples": []}
    if batches:
        selection = coverage.load_selection(plan_dir / "selection.json")
        discovery = scanner.read_report_json(plan_dir / "coverage.json", max_bytes=coverage.MAX_DISCOVERY_BYTES)
        recovered = coverage.recover_previous(selection, previous, batches, source_commit=source_commit,
            discovery_summary=discovery, output_dir=plan_dir / "previous-recovered",
            diagnostics=summary["reconciliation"])
        summary["recovered_sources"] = recovered["execution_summary"]["recovered_sources"]
        # The plan already carries the complete prior bundle to every worker.
        # Replace it after validation instead of uploading a second ~300 MiB copy.
        coverage.read_bundle(plan_dir / "previous-recovered")
        prior_dir = plan_dir / "previous"
        baseline = scanner.read_bytes_bounded(prior_dir / "publication-base.json", 4096) if (prior_dir / "publication-base.json").exists() else None
        old_dir = plan_dir / "previous-original"
        require(not old_dir.exists(), "unexpected prior recovery staging")
        if prior_dir.exists():
            os.replace(prior_dir, old_dir)
        os.replace(plan_dir / "previous-recovered", prior_dir)
        if baseline is not None:
            (prior_dir / "publication-base.json").write_bytes(baseline)
        if old_dir.exists():
            shutil.rmtree(old_dir)
    coverage.write_bounded(plan_dir / STATE_FILE, new_state, MAX_STATE_BYTES)
    coverage.write_bounded(plan_dir / "recovery-status.json", summary, MAX_STATUS_BYTES)
    shutil.rmtree(staged)
    return summary


def restore_current(github, plan_dir, worker_path, *, token, partition, environment=None, fetch_archive=None):
    """Resume earlier attempts of this same trusted main run before rescanning."""
    env = os.environ if environment is None else environment
    if int(env.get("GITHUB_RUN_ATTEMPT", "1")) <= 1:
        return 0
    summary = scanner.read_report_json(plan_dir / "coverage.json", max_bytes=coverage.MAX_DISCOVERY_BYTES)
    if env.get("SCAN_CORPUS") == "controlled" or summary.get("catalog", {}).get("mode") == "controlled_immutable_regression":
        return 0
    require(env.get("GITHUB_REF") == "refs/heads/main", "same-run production resume requires main")
    workflow = github.request("GET", "actions/workflows/skillspector-reports.yml")
    run_id, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
    metadata = github.request("GET", f"actions/runs/{run_id}")
    run = trusted_main_run(github, {**metadata, "status": "completed"}, workflow["id"])
    require(run["id"] == run_id and run["run_attempt"] == attempt and run["head_sha"] == env["GITHUB_SHA"],
            "same-run checkpoint source differs")
    selection = coverage.load_selection(plan_dir / "selection.json")
    digest = coverage.sha256_digest(canonical_json(selection))
    staged, candidates = plan_dir / "same-run-resume", []
    if staged.exists() or staged.is_symlink():
        require(staged.is_dir() and not staged.is_symlink(), "same-run staging must be regular")
        shutil.rmtree(staged)
    staged.mkdir(parents=True, exist_ok=True)
    download = fetch_archive or download_archive
    downloaded = 0
    for artifact in run_artifacts(github, run_id):
        match = ARTIFACT.fullmatch(artifact["name"])
        if int(match[2]) != partition or match[1] is not None and int(match[1]) >= attempt:
            continue
        artifact_id = integer(artifact.get("id"), "artifact id")
        body = download(artifact_id, token)
        downloaded += len(body)
        require(downloaded <= MAX_TOTAL_BYTES, "same-run resume download bound exceeded")
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            info = archive.getinfo("provenance.json")
            require(info.file_size <= MAX_PROVENANCE_BYTES, "same-run provenance exceeds bound")
            provenance = scanner.parse_scanner_json(archive.read(info), "same-run provenance")
        old_attempt = integer(provenance.get("run_attempt"), "earlier run attempt")
        require(old_attempt < attempt, "same-run resume cannot use current/future attempt")
        producing = trusted_main_run(github, github.request("GET", f"actions/runs/{run_id}/attempts/{old_attempt}"), workflow["id"])
        target = staged / str(artifact_id)
        batch = unpack_archive(body, artifact, producing, target)
        candidate = batch["workers"][0]
        if candidate["selection_digest"] == digest:
            candidates.append((old_attempt, candidate))
        shutil.rmtree(target)
    if worker_path.exists():
        candidates.append((attempt, scanner.read_report_json(worker_path, max_bytes=coverage.MAX_WORKER_BYTES)))
    shutil.rmtree(staged)
    if not candidates:
        return 0
    latest = max(row[0] for row in candidates)
    workers, _ = coverage.coalesce_workers([row[1] for row in candidates if row[0] == latest], selection, env["GITHUB_SHA"])
    require(len(workers) == 1 and workers[0]["partition"]["index"] == partition, "same-run resume partition differs")
    previous = coverage.read_bundle(plan_dir / "previous")
    persisted = coverage.compatible_attempts(previous, selection)
    remaining = []
    for outcome in workers[0]["attempts"]:
        old = persisted.get(outcome["attempt"]["id"])
        if old is not None and old["attempt_count"] >= outcome["attempt"]["attempt_count"]:
            # Preparation already reconciled independent main runs. A retry's
            # earlier checkpoint cannot replace published progress. This does
            # not acknowledge its artifact: unseen alternate evidence remains
            # eligible for the next normal preparation's reconciliation.
            continue
        remaining.append(outcome)
    if not remaining:
        return 0
    workers[0]["attempts"] = remaining
    coverage.write_bounded(worker_path, workers[0], coverage.MAX_WORKER_BYTES)
    return len(remaining)


def execution_config(event, *, corpus="", maximum_attempts="", scan_budget_seconds="", discovery_pages=""):
    require(event in {"pull_request", "push", "schedule", "workflow_dispatch"}, "unsupported scan event")
    if event == "pull_request":
        corpus, maximum_attempts, scan_budget_seconds, discovery_pages = "controlled", "8", "300", "1"
    corpus = corpus or "catalog"
    attempts, budget, pages = int(maximum_attempts or "128"), int(scan_budget_seconds or "2100"), int(discovery_pages or "50")
    require(corpus in {"catalog", "controlled"} and attempts in {8, 128, 256, 512} and
            budget in {300, 600, 2100} and pages in {1, 50}, "unsupported scan configuration")
    return {"corpus": corpus, "maximum_attempts": str(attempts), "scan_budget_seconds": str(budget),
            "discovery_pages": str(pages), "partition_count": "1" if corpus == "controlled" else "8",
            "partitions": "[0]" if corpus == "controlled" else "[0,1,2,3,4,5,6,7]"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("configure")
    listing = commands.add_parser("list-workers")
    listing.add_argument("--directory", type=Path, required=True)
    listing.add_argument("--selection", type=Path, required=True)
    listing.add_argument("--source-commit", required=True)
    listing.add_argument("--run-id", type=int, required=True)
    listing.add_argument("--run-attempt", type=int, required=True)
    package = commands.add_parser("pack")
    package.add_argument("--plan-dir", type=Path, required=True)
    package.add_argument("--worker", type=Path, required=True)
    package.add_argument("--output-dir", type=Path, required=True)
    package.add_argument("--slice", type=int, required=True)
    recover = commands.add_parser("recover")
    recover.add_argument("--plan-dir", type=Path, required=True)
    recover.add_argument("--source-commit", required=True)
    ack = commands.add_parser("acknowledge")
    ack.add_argument("--plan-dir", type=Path, required=True)
    ack.add_argument("--report-dir", type=Path, required=True)
    resume = commands.add_parser("resume-current")
    resume.add_argument("--plan-dir", type=Path, required=True)
    resume.add_argument("--worker", type=Path, required=True)
    resume.add_argument("--partition", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "configure":
            config = execution_config(os.environ["GITHUB_EVENT_NAME"], corpus=os.environ.get("CONFIG_CORPUS", ""),
                maximum_attempts=os.environ.get("CONFIG_ATTEMPTS", ""), scan_budget_seconds=os.environ.get("CONFIG_BUDGET", ""),
                discovery_pages=os.environ.get("CONFIG_PAGES", ""))
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                for key, value in config.items():
                    stream.write(f"{key}={value}\n")
        elif args.command == "list-workers":
            paths = assembly_worker_paths(args.directory, coverage.load_selection(args.selection), args.source_commit,
                run_id=args.run_id, run_attempt=args.run_attempt)
            print("\n".join(str(path) for path in paths))
        elif args.command == "pack":
            pack(args.plan_dir, args.worker, args.output_dir, slice_index=args.slice)
        else:
            token = os.environ.get("GITHUB_TOKEN", "")
            require(bool(token), "read-only Actions token is missing")
            github = GitHub(token)
            if args.command == "resume-current":
                restored = restore_current(github, args.plan_dir, args.worker, token=token, partition=args.partition)
                print(canonical_json({"status": "resumed" if restored else "no_resume_needed",
                    "restored_sources": restored, "partition": args.partition}).decode())
            elif args.command == "recover":
                require(os.environ.get("GITHUB_REF") == "refs/heads/main", "production recovery requires main")
                result = recover_plan(github, args.plan_dir, args.source_commit, token=token,
                    current_id=int(os.environ["GITHUB_RUN_ID"]))
                print(canonical_json(result).decode())
            else:
                state = read_state(args.plan_dir / STATE_FILE)
                state, summary = collect(github, args.plan_dir / "acknowledged", state, token=token,
                    current_run=int(os.environ["GITHUB_RUN_ID"]))
                coverage.write_bounded(args.report_dir / STATE_FILE, state, MAX_STATE_BYTES)
        return 0
    except (PublicationError, OSError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile,
            urllib.error.URLError) as error:
        print(f"SkillSpector recovery failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
