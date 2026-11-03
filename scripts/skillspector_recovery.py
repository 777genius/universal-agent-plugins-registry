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
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError, canonical_json, parse_timestamp, require
from scripts.publish_skillspector_reports import REPOSITORY
from scripts.skillspector_publication_transport import GitHub

WORKFLOW = ".github/workflows/skillspector-reports.yml"
ARTIFACT = re.compile(r"skillspector-checkpoint-p([0-7])-s([1-3])\Z")
STATE_FILE = "recovery.json"
MAX_STATE_BYTES = 1 << 20
MAX_RUNS = 512
MAX_RECOVERY_RUNS = 8
MAX_ARCHIVE_BYTES = 128 << 20
MAX_TOTAL_BYTES = 1 << 30
RETENTION_DAYS = 90
FILES = {"selection.json": coverage.MAX_SELECTION_BYTES,
         "coverage.json": coverage.MAX_DISCOVERY_BYTES,
         "worker.json": coverage.MAX_WORKER_BYTES}
MAX_PROVENANCE_BYTES = 16 << 10


def integer(value, label):
    require(type(value) is int and value > 0, "invalid " + label)
    return value


def validate_state(value):
    coverage.v2.exact(value, ("schema_version", "runs"), "recovery state")
    require(value["schema_version"] == 1 and isinstance(value["runs"], list) and
            len(value["runs"]) <= MAX_RUNS, "invalid recovery state")
    seen = set()
    for run in value["runs"]:
        coverage.v2.exact(run, ("run_id", "run_attempt", "head_sha", "created_at", "artifacts"), "recovery acknowledgement")
        key = (integer(run["run_id"], "run id"), integer(run["run_attempt"], "run attempt"))
        require(key not in seen and coverage.SHA.fullmatch(run["head_sha"]), "duplicate or invalid recovery run")
        seen.add(key)
        coverage.v2.timestamp(run["created_at"], "recovery.created_at")
        require(isinstance(run["artifacts"], list) and len(run["artifacts"]) <= 24, "invalid acknowledged artifacts")
        ids = set()
        for artifact in run["artifacts"]:
            coverage.v2.exact(artifact, ("id", "digest"), "acknowledged artifact")
            require(integer(artifact["id"], "artifact id") not in ids and
                    re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]), "invalid artifact acknowledgement")
            ids.add(artifact["id"])
    require(len(canonical_json(value)) <= MAX_STATE_BYTES, "recovery acknowledgements exceed limit")
    return value


def read_state(path):
    if not path.exists():
        return {"schema_version": 1, "runs": []}
    require(path.is_file() and not path.is_symlink(), "recovery state must be regular")
    return validate_state(scanner.read_report_json(path, max_bytes=MAX_STATE_BYTES))


def merge_state(*states, now=None):
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=RETENTION_DAYS)
    runs = {}
    for state in states:
        for run in validate_state(state)["runs"]:
            if parse_timestamp(run["created_at"], "created_at") < cutoff:
                continue
            key = run["run_id"], run["run_attempt"]
            require(key not in runs or runs[key] == run, "conflicting recovery acknowledgement")
            runs[key] = run
    require(len(runs) <= MAX_RUNS, "recovery run retention bound exceeded")
    return validate_state({"schema_version": 1, "runs": sorted(runs.values(), key=lambda r: (r["created_at"], r["run_id"], r["run_attempt"]))})


def validate_provenance(value, documents, *, allow_unsupported_policy=False):
    coverage.v2.exact(value, ("schema_version", "repository", "workflow", "run_id", "run_attempt", "head_branch",
        "head_sha", "event", "corpus", "partition", "slice", "files"), "checkpoint provenance")
    require(value["schema_version"] == 1 and value["repository"] == REPOSITORY and value["workflow"] == WORKFLOW,
            "checkpoint repository/workflow differs")
    integer(value["run_id"], "run id")
    integer(value["run_attempt"], "run attempt")
    require(isinstance(value["head_branch"], str) and 0 < len(value["head_branch"]) <= 255 and
            coverage.SHA.fullmatch(value["head_sha"]) and value["event"] in {"push", "schedule", "workflow_dispatch"} and
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
            "unsupported_policy": unsupported}


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
    require(isinstance(run, dict) and run.get("repository", {}).get("full_name") == REPOSITORY and
            run.get("head_repository", {}).get("full_name") == REPOSITORY and run.get("workflow_id") == workflow_id and
            run.get("path") == WORKFLOW and run.get("head_branch") == "main" and
            run.get("event") in {"push", "schedule", "workflow_dispatch"} and run.get("status") == "completed" and
            coverage.SHA.fullmatch(run.get("head_sha", "")), "recovery requires a completed canonical main run")
    integer(run.get("id"), "run id")
    integer(run.get("run_attempt"), "run attempt")
    coverage.v2.timestamp(run.get("created_at"), "run.created_at")
    return run


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
            provenance["partition"] == int(match[1]) and provenance["slice"] == int(match[2]),
            "checkpoint cannot cross branch/corpus/run attempt boundary")
    require(not output_dir.exists(), "recovery staging path already exists")
    output_dir.mkdir(parents=True)
    for name, contents in documents.items():
        (output_dir / name).write_bytes(contents)
    coverage.write_bounded(output_dir / "provenance.json", provenance, MAX_PROVENANCE_BYTES)
    return batch


def load_recovery_batches(directory):
    require(directory.is_dir() and not directory.is_symlink(), "recovery staging must be regular")
    children = sorted(directory.iterdir())
    require(len(children) <= MAX_RECOVERY_RUNS * 24, "recovery staging exceeds artifact bound")
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


def collect(github, directory, state, *, token, current_run=None, current_id=None, fetch_archive=None, now=None):
    """Discover oldest unacknowledged main runs; finite retention is explicit."""
    now = now or datetime.now(timezone.utc)
    fetch_archive = fetch_archive or download_archive
    workflow = github.request("GET", "actions/workflows/skillspector-reports.yml")
    require(isinstance(workflow, dict), "canonical recovery workflow unavailable")
    workflow_id = integer(workflow.get("id"), "workflow id")
    acknowledged = {(r["run_id"], r["run_attempt"]): r for r in validate_state(state)["runs"]}
    runs, deferred = [], False
    if current_run is not None:
        # Assembly may acknowledge its own running run; it is not a recovery source yet.
        run = github.request("GET", f"actions/runs/{integer(current_run, 'current run')}")
        require(run and run.get("head_branch") == "main" and run.get("workflow_id") == workflow_id,
                "current acknowledgement is not canonical main")
        run = {**run, "status": "completed"}
        runs = [trusted_run(run, workflow_id)]
    else:
        cutoff = now - timedelta(days=RETENTION_DAYS)
        for page in range(1, MAX_RUNS // 100 + 1):
            result = github.request("GET", f"actions/workflows/{workflow_id}/runs?branch=main&status=completed&per_page=100&page={page}")
            require(isinstance(result, dict) and isinstance(result.get("workflow_runs"), list), "recovery run listing unavailable")
            listed = result["workflow_runs"]
            for run in listed:
                if run.get("id") == current_id:
                    continue
                trusted_run(run, workflow_id)
                if parse_timestamp(run["created_at"], "created_at") >= cutoff:
                    runs.append(run)
            if len(listed) < 100 or any(parse_timestamp(r["created_at"], "created_at") < cutoff for r in listed):
                break
        else:
            deferred = True
    runs.sort(key=lambda r: (r["created_at"], r["id"]))
    accepted, consumed, bytes_read, rejected = [], 0, 0, []
    directory.mkdir(parents=True, exist_ok=True)
    for run in runs:
        key = run["id"], run["run_attempt"]
        if key in acknowledged:
            require(acknowledged[key]["head_sha"] == run["head_sha"], "acknowledged run source changed")
            continue
        if consumed >= MAX_RECOVERY_RUNS:
            deferred = True
            break
        listing = github.request("GET", f"actions/runs/{run['id']}/artifacts?per_page=100")
        require(isinstance(listing, dict) and isinstance(listing.get("artifacts"), list) and
                listing.get("total_count", len(listing["artifacts"])) <= 100, "recovery artifact listing exceeds bound")
        artifacts = [a for a in listing["artifacts"] if ARTIFACT.fullmatch(a.get("name", ""))]
        require(len(artifacts) <= 24, "recovery run artifact count exceeds bound")
        # Legacy/controlled runs with no canonical checkpoint packages need no replay.
        if not artifacts:
            accepted.append({"run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
                             "created_at": run["created_at"], "artifacts": []})
            continue
        artifact_acks = []
        run_paths = []
        try:
            for artifact in sorted(artifacts, key=lambda a: a["name"]):
                require(artifact.get("expired") is False, "unacknowledged checkpoint expired; operator recovery required")
                size = artifact.get("size_in_bytes")
                require(type(size) is int and 0 < size <= MAX_ARCHIVE_BYTES and bytes_read + size <= MAX_TOTAL_BYTES,
                        "recovery download budget exceeded")
                body = fetch_archive(integer(artifact["id"], "artifact id"), token)
                bytes_read += len(body)
                require(bytes_read <= MAX_TOTAL_BYTES, "recovery download budget exceeded")
                # A rerun can leave immutable artifacts from an earlier attempt. Authenticate that exact attempt.
                with zipfile.ZipFile(io.BytesIO(body)) as archive:
                    info = archive.getinfo("provenance.json")
                    require(0 < info.file_size <= MAX_PROVENANCE_BYTES, "checkpoint provenance exceeds bound")
                    envelope = scanner.parse_scanner_json(archive.read(info), "checkpoint provenance")
                attempt = integer(envelope.get("run_attempt"), "checkpoint run attempt")
                producing = run if attempt == run["run_attempt"] else trusted_run(github.request("GET",
                    f"actions/runs/{run['id']}/attempts/{attempt}"), workflow_id)
                require(attempt <= run["run_attempt"] and producing["id"] == run["id"], "checkpoint run attempt differs")
                target = directory / f"{run['id']}-{attempt}-{artifact['id']}"
                batch = unpack_archive(body, artifact, producing, target, allow_controlled=True, allow_unsupported_policy=True)
                if envelope.get("corpus") == "controlled" or batch["unsupported_policy"]:
                    # Authenticated controlled evidence is acknowledged, never recovered.
                    shutil.rmtree(target)
                    rejected.append({"artifact_id": artifact["id"], "reason":
                        "excluded_controlled" if envelope.get("corpus") == "controlled" else "unsupported_policy"})
                else:
                    run_paths.append(target)
                artifact_acks.append({"id": artifact["id"], "digest": artifact["digest"]})
        except Exception:
            for target in run_paths:
                shutil.rmtree(target)
            raise
        accepted.append({"run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
                         "created_at": run["created_at"], "artifacts": artifact_acks})
        consumed += 1
    return merge_state(state, {"schema_version": 1, "runs": accepted}, now=now), {
        "status": "deferred" if deferred else "ready", "runs": consumed, "bytes": bytes_read,
        "retention_days": RETENTION_DAYS, "maximum_runs_per_prepare": MAX_RECOVERY_RUNS,
        "rejected": rejected}


def recover_plan(github, plan_dir, source_commit, *, token, current_id=None):
    previous = coverage.read_bundle(plan_dir / "previous")
    state = read_state(plan_dir / "previous" / STATE_FILE)
    staged = plan_dir / "recovery"
    new_state, summary = collect(github, staged, state, token=token, current_id=current_id)
    batches = load_recovery_batches(staged)
    if batches:
        selection = coverage.load_selection(plan_dir / "selection.json")
        discovery = scanner.read_report_json(plan_dir / "coverage.json", max_bytes=coverage.MAX_DISCOVERY_BYTES)
        coverage.recover_previous(selection, previous, batches, source_commit=source_commit,
            discovery_summary=discovery, output_dir=plan_dir / "previous-recovered")
        # The plan already carries the complete prior bundle to every worker.
        # Replace it after validation instead of uploading a second ~300 MiB copy.
        coverage.read_bundle(plan_dir / "previous-recovered")
        prior_dir = plan_dir / "previous"
        old_dir = plan_dir / "previous-original"
        require(not old_dir.exists(), "unexpected prior recovery staging")
        if prior_dir.exists():
            os.replace(prior_dir, old_dir)
        os.replace(plan_dir / "previous-recovered", prior_dir)
        if old_dir.exists():
            shutil.rmtree(old_dir)
    coverage.write_bounded(plan_dir / STATE_FILE, new_state, MAX_STATE_BYTES)
    coverage.write_bounded(plan_dir / "recovery-status.json", summary, 32 << 10)
    shutil.rmtree(staged)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
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
    args = parser.parse_args()
    try:
        if args.command == "pack":
            pack(args.plan_dir, args.worker, args.output_dir, slice_index=args.slice)
        else:
            token = os.environ.get("GITHUB_TOKEN", "")
            require(bool(token), "read-only Actions token is missing")
            github = GitHub(token)
            if args.command == "recover":
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
