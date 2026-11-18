"""Read-only real immutable-source proof for #470; never starts a fifth scan."""
from __future__ import annotations

import hashlib
import io
import json
import os
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


def original_qualification() -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN with actions:read is required to inspect original Actions artifact")
    url = f"https://api.github.com/repos/{REPO}/actions/artifacts/{ACQUISITION_ARTIFACT_ID}/zip"
    # Actions artifact API returns an authenticated 302 to an object-store URL.
    # Never forward the GitHub Bearer credential to that other host: doing so
    # may both leak a token and make the signed download return HTTP 401.
    class RefuseAutomaticRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None

    api_request = urllib.request.Request(
        url, headers={
            "User-Agent": "skillspector-470-readonly-source-proof",
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }
    )
    try:
        with urllib.request.build_opener(RefuseAutomaticRedirect()).open(api_request, timeout=30):
            raise ValueError("GitHub artifact download did not return expected redirect")
    except urllib.error.HTTPError as exc:
        if exc.code not in (302, 303, 307, 308):
            raise
        signed_url = exc.headers.get("Location", "")
    target = urllib.parse.urlparse(signed_url)
    if target.scheme != "https" or not target.hostname or target.username or target.password:
        raise ValueError("GitHub artifact supplied unsafe redirect URL")
    raw = get_bytes(signed_url, maximum=2_000_000)  # no Authorization header
    if sha256(raw) != ACQUISITION_ARTIFACT_SHA256:
        raise ValueError("original acquisition qualification ZIP bytes changed")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.testzip() is not None or archive.namelist() != ["skillspector-unicode-acceptance.json"]:
            raise ValueError("invalid original qualification ZIP integrity or members")
        proof = json.loads(archive.read("skillspector-unicode-acceptance.json"))
    if proof.get("schema_version") != 1 or proof.get("status") != "passed":
        raise ValueError("original acquisition qualification was not passing")
    return proof


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
        "original_acquisition_zip_sha256": ACQUISITION_ARTIFACT_SHA256,
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
