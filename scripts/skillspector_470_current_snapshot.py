"""Read-only, snapshot-pinned current-source eligibility audit for #470/#482.

The older five Unicode acquisition qualifications are NOT a permission to
replay an exhausted v3 retry against a later selected source revision. All
outcomes here are diagnostic: no policy migration, scanner run or publication.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPORT_COMMIT = "6df76df0834b89445f78856aaf889b4124b44e5f"
INDEX_GIT_BLOB = "e94580363502cebaa83839014b2c464ce4e80c62"
SOURCE_COMMIT = "198b33f29df7dc71e1a48c5879edb2ed95a9e20d"
SCANNER_REVISION = "f3b25697d76256998ca9d42c198d256258d4c035"
REPO = "777genius/universal-agent-plugins-registry"
BASE = f"https://raw.githubusercontent.com/{REPO}/{REPORT_COMMIT}/reports/skillspector/v3"
# Original independently qualified 2026-11-14 Error identities (#488/#493).
ORIGINAL_PINS = {
    "alchaincyf/elon-musk-skill/elon-musk-perspective":
        ("alchaincyf/elon-musk-skill", "65af7c9a5395cc996d17f55b5bde37e6ed72cf4f", ""),
    "gogf/skills/goframe-v2":
        ("gogf/skills", "c22b6e4115e1a3747676419bba98fee99af6beff", "skills/goframe-v2"),
    "alchaincyf/feynman-skill/feynman-perspective":
        ("alchaincyf/feynman-skill", "b804a7fba592091d5d44844ab7bb75ca26bbfc2a", ""),
    "alchaincyf/naval-skill/naval-perspective":
        ("alchaincyf/naval-skill", "b7600569776be0bd880e8457b1eae42df9f1d3e5", ""),
    "alchaincyf/taleb-skill/taleb-perspective":
        ("alchaincyf/taleb-skill", "6045c4d8ad1ea3a6e4b0872421c755c36782d1c8", ""),
}


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def git_blob_sha(body: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\\0" + body).hexdigest()


def get_bytes(relative: str, limit: int) -> bytes:
    # No untrusted source execution, authentication tokens, or mutable branch.
    with urllib.request.urlopen(BASE + "/" + relative, timeout=90) as response:
        body = response.read(limit + 1)
    require(0 < len(body) <= limit, "missing or oversized immutable source")
    return body


def classify(*, identifier: str, state: dict, record: dict) -> dict:
    """Pure fail-closed admission; never interpret a newer source as repaired."""
    require(identifier in ORIGINAL_PINS, "unqualified original identity")
    repository, prior_revision, path = ORIGINAL_PINS[identifier]
    require(state.get("id") == identifier
            and state.get("repository") == repository
            and state.get("path") == path
            and state.get("current") is True
            and state.get("selected_ids") == [identifier]
            and state.get("state") == "resolved", "invalid current selection")
    source = record.get("source") or {}
    require(record.get("id") == identifier
            and source.get("repository") == repository
            and source.get("path") == path
            and source.get("revision") == state.get("revision")
            and record.get("target_revision") == state.get("revision")
            and record.get("freshness") == "current"
            and record.get("scanner", {}).get("revision") == SCANNER_REVISION,
            "selected revision or scanner evidence differs")
    revision = source["revision"]
    changed = revision != prior_revision
    if not changed:
        retry = record.get("retry") or {}
        require(record.get("status") == "error"
                and source.get("content_digest") is None
                and {x.get("code") for x in record.get("errors", [])} == {"acquisition_failed"}
                and {x.get("code") for x in record.get("coverage", {}).get("reasons", [])} == {"acquisition_failed"}
                and retry.get("attempt_count") == 4
                and retry.get("disposition") == "exhausted"
                and retry.get("reason") == "transient_retry_limit"
                and retry.get("next_attempt_at") is None
                and len(record.get("attempt_history", [])) == 8,
                "unchanged pin lacks genuine exhausted Error provenance")
    else:
        require(record.get("status") != "complete"
                and isinstance(source.get("content_digest"), str),
                "changed source must not be certified by historical qualification")
    return {
        "source_id": identifier,
        "original_revision": prior_revision,
        "current_revision": revision,
        "current_status": record["status"],
        "outcome": "same_pin_exhausted" if not changed else "superseded_qualification",
        "eligible_for_future_review": not changed,
        "migration_authorized": False,
        "safe_for_automatic_publication": False,
        "production_error_reduction": 0,
    }


def audit() -> dict:
    index_raw = get_bytes("index.json", 12_000_000)
    require(git_blob_sha(index_raw) == INDEX_GIT_BLOB, "immutable index Git blob mismatch")
    index = json.loads(index_raw)
    require(index.get("schema_version") == 3
            and index.get("source_commit") == SOURCE_COMMIT
            and index.get("scanner", {}).get("revision") == SCANNER_REVISION,
            "unexpected report source or scanner")
    states = index.get("source_states", [])
    shards = index.get("shards", [])
    require(isinstance(states, list) and isinstance(shards, list), "malformed manifest")
    output = []
    for identifier, (repository, _, _) in ORIGINAL_PINS.items():
        matches = [x for x in states if x.get("id") == identifier]
        manifests = [x for x in shards if x.get("repository") == repository]
        require(len(matches) == len(manifests) == 1, "ambiguous selected source/shard")
        manifest = manifests[0]
        path = manifest["path"]
        require(path.startswith("shards/") and path.endswith(".json")
                and path == f"shards/{manifest['digest'][7:]}.json",
                "invalid immutable shard path")
        raw = get_bytes(path, 2_000_000)
        require(len(raw) == manifest["bytes"]
                and sha256(raw) == manifest["digest"][7:],
                "source shard digest or byte length differs")
        shard = json.loads(raw)
        records = shard.get("records", [])
        require(shard.get("repository") == repository
                and shard.get("scanner") == index["scanner"]
                and len(records) == manifest["record_count"] == 1,
                "shard provenance or record count differs")
        output.append(classify(identifier=identifier, state=matches[0], record=records[0]))
    require(sum(x["outcome"] == "same_pin_exhausted" for x in output) == 3
            and sum(x["outcome"] == "superseded_qualification" for x in output) == 2,
            "pinned November 18 snapshot classification changed")
    return {
        "report_commit": REPORT_COMMIT, "report_index_git_blob": INDEX_GIT_BLOB,
        "producer_source_commit": SOURCE_COMMIT, "scanner_revision": SCANNER_REVISION,
        "scope": "historical five-source eligibility as of immutable published snapshot",
        "entries": output, "current_same_pin_exhausted": 3,
        "superseded_qualifications": 2,
        "migration_authorized": False, "safe_for_automatic_publication": False,
        "production_error_reduction": 0,
    }


if __name__ == "__main__":
    report = audit()
    if len(sys.argv) == 2:
        Path(sys.argv[1]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
