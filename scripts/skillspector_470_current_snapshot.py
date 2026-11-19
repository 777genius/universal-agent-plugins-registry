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
# Independently pinned Git blobs, not a synthetic record retry summary.
SELECTION_GIT_BLOB = "a47d37ff72b6d1346fa4467261db93fca1bfca7b"
ATTEMPTS_GIT_BLOB = "a9f33ff172c6946f4174d808a6ea0092aec4768f"
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
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def get_bytes(relative: str, limit: int) -> bytes:
    # No untrusted source execution, authentication tokens, or mutable branch.
    with urllib.request.urlopen(BASE + "/" + relative, timeout=90) as response:
        body = response.read(limit + 1)
    require(0 < len(body) <= limit, "missing or oversized immutable source")
    return body


def verified_finding_groups(record: dict) -> dict:
    """Summarize every existing group without rewriting independent evidence."""
    findings = record.get("findings")
    require(isinstance(findings, list) and record.get("findings_truncated") is False
            and type(record.get("finding_count")) is int
            and type(record.get("finding_group_count")) is int
            and record["finding_group_count"] == len(findings),
            "published security finding groups are missing or truncated")
    ids: set[str] = set()
    instances = 0
    for group in findings:
        require(isinstance(group, dict) and isinstance(group.get("occurrences"), list)
                and isinstance(group.get("finding_ids"), list)
                and type(group.get("raw_count")) is int,
                "malformed published security finding group")
        occurrences = group["occurrences"]
        group_ids = group["finding_ids"]
        require(len(occurrences) == len(group_ids) == group["raw_count"],
                "finding occurrence count or membership changed")
        current_ids = [x.get("finding_id") if isinstance(x, dict) else None for x in occurrences]
        require(all(isinstance(x, str) and x for x in current_ids)
                and sorted(current_ids) == sorted(group_ids)
                and len(set(current_ids)) == len(current_ids)
                and not ids.intersection(current_ids),
                "finding IDs are absent, duplicated or cross independent groups")
        ids.update(current_ids)
        instances += len(occurrences)
    require(instances == record["finding_count"],
            "published finding occurrence totals disagree")
    canonical = json.dumps(findings, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return {"finding_group_count": len(findings), "finding_occurrences": instances,
            "original_findings_sha256": "sha256:" + sha256(canonical)}


def canonical_json(value: object) -> bytes:
    """Match the published SHA-256 digest profile, including its terminal LF."""
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def verify_attempt_ledger(index: dict, selection: dict, ledger: dict,
                          records: dict[str, dict]) -> dict:
    """Independent queue-state vs immutable-shard proof; no retry authorization.

    Records contains only the three same-pin exhausted Error identities.
    The caller verifies Git blobs before JSON decoding, so this comparison
    cannot be satisfied by rewriting a published record's retry summary.
    """
    require(isinstance(selection, dict) and isinstance(selection.get("sources"), list)
            and "sha256:" + sha256(canonical_json(selection)) == index["selection_digest"],
            "independent immutable selection digest differs")
    require(isinstance(ledger, dict)
            and ledger.get("schema_version") == 3
            and ledger.get("source_commit") == index["source_commit"]
            and ledger.get("selection_digest") == index["selection_digest"]
            and ledger.get("generated_at") == index["generated_at"]
            and type(ledger.get("queue_cursor")) is int
            and 0 <= ledger["queue_cursor"] < 3
            and isinstance(ledger.get("attempts"), list),
            "independent queue-state provenance differs")
    selected: dict[str, dict] = {}
    for item in selection["sources"]:
        require(isinstance(item, dict) and isinstance(item.get("id"), str),
                "malformed immutable selection item")
        if item["id"] in records:
            require(item["id"] not in selected, "duplicate selected retry identity")
            selected[item["id"]] = item
    require(set(selected) == set(records), "missing same-pin immutable source selection")
    found: dict[str, dict] = {}
    for attempt in ledger["attempts"]:
        require(isinstance(attempt, dict), "malformed persisted retry attempt")
        identifier = attempt.get("id")
        if identifier not in records:
            continue
        require(identifier not in found, "duplicate persisted retry identity")
        item, record = selected[identifier], records[identifier]
        source = record["source"]
        require(all(source.get(k) == item.get(k) for k in ("repository", "revision", "path"))
                and record["target_revision"] == item["revision"],
                "persisted retry source pin differs from immutable record")
        subject = {k: item[k] for k in
                   ("kind", "repository", "revision", "path", "plugin_path")}
        expected_source_digest = "sha256:" + sha256(canonical_json(subject))
        history = attempt.get("history")
        require(attempt.get("source_digest") == expected_source_digest
                and attempt.get("scanner") == index["scanner"]
                and attempt.get("policy_digest") == index["profile"]["digest"]
                and attempt.get("profile") == record.get("profile")
                and attempt.get("status") == "error"
                and type(attempt.get("attempt_count")) is int
                and attempt["attempt_count"] == 4
                and attempt.get("disposition") == "exhausted"
                and attempt.get("reason") == "transient_retry_limit"
                and attempt.get("next_attempt_at") is None
                and attempt.get("next_profile") is None
                and isinstance(history, list) and len(history) == 8
                and history == record.get("attempt_history")
                and all(isinstance(event, dict) and event.get("status") == "error"
                        for event in history)
                and history[-1].get("reason") == "transient_retry_limit"
                and history[-1].get("at") == attempt.get("last_attempted_at")
                and history[-1].get("fingerprint") == attempt.get("fingerprint")
                and history[-1].get("profile") == attempt.get("profile")
                and record["retry"] == {
                    "attempt_count": attempt["attempt_count"],
                    "next_attempt_at": attempt["next_attempt_at"],
                    "next_profile": attempt["next_profile"],
                    "reason": attempt["reason"],
                    "disposition": attempt["disposition"],
                    "latest_status": attempt["status"],
                }, "independent persisted attempt does not match original Error")
        found[identifier] = {
            "source_digest": expected_source_digest,
            "history_digest": "sha256:" + sha256(canonical_json(history)),
            "independent_persisted_attempt_verified": True,
            "migration_authorized": False,
        }
    require(set(found) == set(records), "missing independent persisted attempts")
    return found


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
    security = verified_finding_groups(record)
    revision = source["revision"]
    changed = revision != prior_revision
    if not changed:
        retry = record.get("retry") or {}
        require(record.get("status") == "error"
                and isinstance(retry, dict)
                and source.get("content_digest") is None
                and {x.get("code") for x in record.get("errors", [])} == {"acquisition_failed"}
                and {x.get("code") for x in record.get("coverage", {}).get("reasons", [])} == {"acquisition_failed"}
                and retry.get("attempt_count") == 4
                and retry.get("disposition") == "exhausted"
                and retry.get("reason") == "transient_retry_limit"
                and retry.get("next_attempt_at") is None
                and retry.get("next_profile") is None
                and retry.get("latest_status") == "error"
                and isinstance(record.get("attempt_history"), list)
                and len(record["attempt_history"]) == 8
                and all(isinstance(event, dict) and event.get("status") == "error"
                        for event in record["attempt_history"])
                and record["attempt_history"][-1].get("reason") == "transient_retry_limit",
                "unchanged pin lacks genuine exhausted Error provenance")
    else:
        require(record.get("status") == "partial"
                and record.get("retry", {}).get("reason") == "reference_missing"
                and security["finding_group_count"] == 1
                and security["finding_occurrences"] == 8
                and isinstance(source.get("content_digest"), str),
                "changed source must not be certified by historical qualification")
    return {
        "source_id": identifier,
        "original_revision": prior_revision,
        "current_revision": revision,
        "current_status": record["status"],
        "original_security": security,
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
    unchanged_records: dict[str, dict] = {}
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
                and shard.get("profile") == index["profile"]
                and len(records) == manifest["record_count"] == 1,
                "shard provenance or record count differs")
        receipt = classify(identifier=identifier, state=matches[0], record=records[0])
        output.append(receipt)
        if receipt["outcome"] == "same_pin_exhausted":
            unchanged_records[identifier] = records[0]
    require(sum(x["outcome"] == "same_pin_exhausted" for x in output) == 3
            and sum(x["outcome"] == "superseded_qualification" for x in output) == 2,
            "pinned November 18 snapshot classification changed")
    # Verify the independent immutable persisted queue state, not only the record.
    selection_raw = get_bytes("selection.json", 25_000_000)
    attempts_raw = get_bytes("attempts.json", 110_000_000)
    require(git_blob_sha(selection_raw) == SELECTION_GIT_BLOB,
            "independent immutable selection Git blob mismatch")
    require(git_blob_sha(attempts_raw) == ATTEMPTS_GIT_BLOB,
            "independent immutable attempt ledger Git blob mismatch")
    receipts = verify_attempt_ledger(index, json.loads(selection_raw),
                                     json.loads(attempts_raw), unchanged_records)
    for entry in output:
        if entry["source_id"] in receipts:
            entry["independent_attempt_ledger"] = receipts[entry["source_id"]]
    return {
        "selection_git_blob": SELECTION_GIT_BLOB,
        "attempts_git_blob": ATTEMPTS_GIT_BLOB,
        "independent_exhausted_attempts_verified": len(receipts),
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
