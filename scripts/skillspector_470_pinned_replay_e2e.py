"""Read-only real immutable-source proof for #470; never starts a fifth scan."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from scripts.skillspector_470_epoch import (
    BASELINE_REPORT_COMMIT, BASELINE_SOURCE_COMMIT, OLD_POLICY_DIGEST,
    OLD_SCANNER_REVISION, PINS, start_epoch,
)

REPO = "777genius/universal-agent-plugins-registry"
BASE = (
    f"https://raw.githubusercontent.com/{REPO}/{BASELINE_REPORT_COMMIT}"
    "/reports/skillspector/v3"
)
INDEX_BLOB_SHA = "181b4e95c0f6de5d4535f91031b35dfde7d27a86"
SHARD_DIGESTS = {
    "alchaincyf/elon-musk-skill": "71db2a5fd1f185dd071272dfdc55332405c40a8b9f0d597277b031832901f3f3",
    "gogf/skills": "888ac8fe47e347c526fa77737ffb9d3bbe26782c7e5cbc025afc9f8e527c9efd",
}
ACQUISITION_ARTIFACT_ID = 13953054225
ACQUISITION_ARTIFACT_SHA256 = "fbeca520416e63873da427d79ec9c383aa8c620ebfd797d57365d82264d33a86"


def get_bytes(url: str, *, maximum: int, token: str | None = None) -> bytes:
    headers = {"User-Agent": "skillspector-470-readonly-source-proof", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as response:
        data = response.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ValueError("missing or oversized immutable input")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verified_index() -> dict:
    raw = get_bytes(BASE + "/index.json", maximum=12_000_000)
    git_blob_hash = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    if git_blob_hash != INDEX_BLOB_SHA:
        raise ValueError("original pinned index Git blob changed")
    index = json.loads(raw)
    if not (
        index.get("schema_version") == 3
        and index.get("source_commit") == BASELINE_SOURCE_COMMIT
        and index.get("profile", {}).get("digest") == OLD_POLICY_DIGEST
        and index.get("scanner", {}).get("revision") == OLD_SCANNER_REVISION
        and index.get("coverage", {}).get("error") == 39
        and index.get("coverage", {}).get("partial") == 11050
    ):
        raise ValueError("immutable source report metadata disagrees")
    return index


# The original seven-day Actions ZIP was independently checked in November 2026,
# but GitHub now returns HTTP 410 for artifact 13953054225. The original
# successful job's authenticated logs remain available and print the *same*
# five pinned source receipts. Never report a re-verification of missing ZIP.
ACQUISITION_RUN_ID = 43237932304
ACQUISITION_JOB_ID = 131250237483
ACQUISITION_HEAD_SHA = "dc80a9cc7e605d555305b2161ddf17f4115a9d2d"
# (file_count, total_bytes, non-ascii paths, directory tree SHA, status, issues)
EXPECTED_LOG_SOURCES = {
    ("alchaincyf/elon-musk-skill", "65af7c9a5395cc996d17f55b5bde37e6ed72cf4f", ""): (
        12, 5438866, 3, "sha256:d70458fd6f6848efa1bef76f81e809faea8440535782ce8721917affdc5ea6bf",
        "partial", 8,
    ),
    ("gogf/skills", "c22b6e4115e1a3747676419bba98fee99af6beff", "skills/goframe-v2"): (
        962, 4418429, 400, "sha256:75689483353de0f1a54387367d3f38b094022f219c8057021b8c9295a8bba90a",
        "partial", 108,
    ),
    ("zenstory-ai/drama-skills", "8cf7404981b7095b498e061832bb3c9ffd6a42be", "skills/short-drama"): (
        31, 621272, 6, "sha256:501bb8d7c77a08e7bf50ca575899f55975a13425e2480680f6c35ec7a4a2ffcd",
        "partial", 10,
    ),
    ("zenstory-ai/drama-skills", "8cf7404981b7095b498e061832bb3c9ffd6a42be", "skills/short-drama-develop"): (
        36, 235483, 15, "sha256:38693b12ac8700c78402ecf1f45093e8fd8d3623a3dc4421e0562bc209cba359",
        "complete", 1,
    ),
    ("zenstory-ai/drama-skills", "8cf7404981b7095b498e061832bb3c9ffd6a42be", "skills/short-drama-edit"): (
        29, 232288, 1, "sha256:7448ad456b0cbd3fddfe516871ac4b9e03c2a5e2453faccc49ef12ac90d9468a",
        "partial", 15,
    ),
}


def parse_original_job_log(raw: bytes) -> dict:
    """Only accept the *single* final JSON receipt from a pinned original job.

    This re-verifies the original GitHub-hosted source-bound observation, NOT
    the expired artifact ZIP. Any omitted/changed source is a hard failure.
    """
    try:
        content = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ValueError("original GitHub job log is not UTF-8") from error
    receipts = []
    for line in content.splitlines():
        match = re.fullmatch(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z (.*)", line)
        if not match or not match.group(1).startswith('[{"file_count":'):
            continue
        try:
            receipts.append(json.loads(match.group(1)))
        except (ValueError, TypeError) as error:
            raise ValueError("malformed original GitHub receipt") from error
    if len(receipts) != 1 or not isinstance(receipts[0], list):
        raise ValueError("missing or ambiguous original GitHub job receipt")
    rows = receipts[0]
    if len(rows) != len(EXPECTED_LOG_SOURCES):
        raise ValueError("missing original immutable source receipt")
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("malformed original source evidence")
        key = (row.get("repository"), row.get("revision"), row.get("selected_root"))
        if key not in EXPECTED_LOG_SOURCES or key in seen:
            raise ValueError("original source identity changed or duplicated")
        seen.add(key)
        count, total, unicode_files, tree_digest, scan_status, issues = EXPECTED_LOG_SOURCES[key]
        if (
            row.get("status") != "complete_acquisition"
            or type(row.get("file_count")) is not int or row["file_count"] != count
            or type(row.get("total_bytes")) is not int or row["total_bytes"] != total
            or type(row.get("unicode_files")) is not int or row["unicode_files"] != unicode_files
            or row.get("tree_digest") != tree_digest
            or row.get("scan_status") != scan_status
            or type(row.get("scan_issue_count")) is not int
            or row["scan_issue_count"] != issues
        ):
            raise ValueError("original source digests, scan findings or coverage changed")
    if seen != set(EXPECTED_LOG_SOURCES):
        raise ValueError("original source ledger incomplete")
    return {"schema_version": 1, "status": "passed", "sources": rows,
            "verification_source": "original_authenticated_github_job_log",
            "expired_artifact_zip_reverified": False}


def download_authenticated_log(token: str) -> bytes:
    """REST uses 302; never send GitHub's token to object storage."""
    url = f"https://api.github.com/repos/{REPO}/actions/jobs/{ACQUISITION_JOB_ID}/logs"
    class RefuseAutomaticRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    request = urllib.request.Request(url, headers={
        "User-Agent": "skillspector-470-readonly-source-proof",
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    })
    try:
        with urllib.request.build_opener(RefuseAutomaticRedirect()).open(request, timeout=30):
            raise ValueError("original job log did not return expected signed redirect")
    except urllib.error.HTTPError as error:
        if error.code not in (302, 303, 307, 308):
            raise
        signed_url = error.headers.get("Location", "")
    parsed = urllib.parse.urlparse(signed_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("unsafe original GitHub job-log redirect")
    return get_bytes(signed_url, maximum=3_000_000)


def original_qualification() -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN with actions:read required for original logs")
    jobs = json.loads(get_bytes(
        f"https://api.github.com/repos/{REPO}/actions/runs/{ACQUISITION_RUN_ID}/jobs?per_page=100",
        maximum=2_000_000, token=token,
    ))
    candidates = [
        job for job in jobs.get("jobs", []) if job.get("id") == ACQUISITION_JOB_ID
    ]
    if len(candidates) != 1 or not (
        candidates[0].get("run_id") == ACQUISITION_RUN_ID
        and candidates[0].get("head_sha") == ACQUISITION_HEAD_SHA
        and candidates[0].get("name") == "pinned-five-root-acquisition"
        and candidates[0].get("status") == "completed"
        and candidates[0].get("conclusion") == "success"
    ):
        raise ValueError("original GitHub job identity or result does not match")
    return parse_original_job_log(download_authenticated_log(token))


def run_readonly_proof() -> dict:
    index = verified_index()
    qualification = original_qualification()
    shards = {item["repository"]: item for item in index["shards"] if item["repository"] in SHARD_DIGESTS}
    selection = {
        item["id"]: item for item in index["source_states"] if item.get("id") in PINS
    }
    acquired = {
        (item["repository"], item["revision"], item["selected_root"]): item
        for item in qualification["sources"]
    }
    if len(shards) != 2 or len(selection) != 2 or len(acquired) != len(qualification["sources"]):
        raise ValueError("missing or duplicate original proof identity")

    output = []
    for source_id, (repository, revision, root) in PINS.items():
        shard_name = SHARD_DIGESTS[repository]
        entry = shards[repository]
        if entry.get("path") != f"shards/{shard_name}.json":
            raise ValueError("shard location drift")
        raw = get_bytes(BASE + "/" + entry["path"], maximum=200_000)
        if (
            sha256(raw) != shard_name
            or entry.get("digest") != "sha256:" + shard_name
            or entry.get("bytes") != len(raw)
            or entry.get("record_count") != 1
        ):
            raise ValueError("signed manifest vs immutable shard mismatch")
        shard = json.loads(raw)
        records = shard.get("records")
        if (
            shard.get("schema_version") != 3
            or not isinstance(records, list)
            or len(records) != 1
            or records[0].get("id") != source_id
            or shard.get("repository") != repository
        ):
            raise ValueError("wrong source in original immutable shard")
        state = selection[source_id]
        if not (
            state.get("current") is True
            and state.get("state") == "resolved"
            and state.get("revision") == revision
            and state.get("path") == root
            and state.get("selected_ids") == [source_id]
        ):
            raise ValueError("original selected identity or freshness changed")
        acquired_identity = (repository, revision, root)
        qualified = acquired.get(acquired_identity)
        if not qualified or qualified.get("scan_status") != "partial" or qualified.get("scan_issue_count", 0) < 1:
            raise ValueError("actual acquisition did not yield the expected incomplete real scan")
        epoch = start_epoch(
            source_id=source_id, published_record=records[0], signed_manifest=index,
            qualification=qualified, report_commit=BASELINE_REPORT_COMMIT,
        )
        if (
            epoch.get("production_error_reduction") != 0
            or epoch.get("migration_authorized") is not False
            or epoch.get("safe_for_automatic_publication") is not False
            or epoch.get("new_epoch_attempts") != []
            or len(epoch["original_record"]["attempt_history"]) != 8
            or epoch["original_record"]["retry"]["attempt_count"] != 4
        ):
            raise ValueError("shadow qualification attempted to promote original Error")
        output.append({
            "source_id": source_id,
            "source_revision": revision,
            "original_shard_sha256": "sha256:" + shard_name,
            "original_record_digest": epoch["original_record_digest"],
            "original_history_digest": epoch["original_history_digest"],
            "qualified_tree_digest": epoch["qualified_tree_digest"],
            "qualified_file_count": qualified["file_count"],
            "real_scanner_status": qualified["scan_status"],
            "real_scanner_issues": qualified["scan_issue_count"],
            "published_status": "error",
            "production_error_reduction": 0,
            "certified_complete": False,
        })
    return {
        "schema_version": 1, "kind": "skillspector-470-original-source-replay",
        "original_report_commit": BASELINE_REPORT_COMMIT,
        "original_index_git_blob_sha": INDEX_BLOB_SHA,
        "original_acquisition_artifact_id": ACQUISITION_ARTIFACT_ID,
        "original_acquisition_zip_sha256_historical_only": ACQUISITION_ARTIFACT_SHA256,
        "original_evidence_source": qualification["verification_source"],
        "expired_artifact_zip_reverified": qualification["expired_artifact_zip_reverified"],
        "published_scanner_revision": OLD_SCANNER_REVISION,
        "sources": output,
        "publication_authorized": False,
        "production_error_reduction": 0,
    }


if __name__ == "__main__":
    proof = run_readonly_proof()
    destination = sys.argv[1] if len(sys.argv) > 1 else ""
    payload = json.dumps(proof, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    if destination:
        Path(destination).write_text(payload, encoding="utf-8")
    print(payload)
