"""Unpublished versioned acquisition-requalification shadow ledger for #470.

This component neither authorizes a fifth production attempt nor publishes a
scan. Its inputs must be independently authenticated against immutable v3
shards and a real no-LLM acquisition; it cannot serve as signer approval.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re

BASELINE_REPORT_COMMIT = "7771404dcdfc5b3855f1319b5e9a2bc19d0c7acf"
BASELINE_SOURCE_COMMIT = "a12bd3bdffab6991a2541220a16a0a9d6447e47e"
OLD_POLICY_DIGEST = "sha256:acf4ec4bbeafc4bb6814745eb1411324f627b6924b40b8436d17e9dd2aad18ec"
OLD_SCANNER_REVISION = "f3b25697d76256998ca9d42c198d256258d4c035"
EPOCH_ID = "acquisition-requalification-unicode-v1"
EPOCH_POLICY = {
    "id": EPOCH_ID,
    "max_new_attempts_per_qualified_identity": 1,
    "previous_report_commit": BASELINE_REPORT_COMMIT,
    "preserve_prior_history": True,
    "publication_authorized": False,
}
PINS = {
    "alchaincyf/elon-musk-skill/elon-musk-perspective": (
        "alchaincyf/elon-musk-skill", "65af7c9a5395cc996d17f55b5bde37e6ed72cf4f", ""
    ),
    "gogf/skills/goframe-v2": (
        "gogf/skills", "c22b6e4115e1a3747676419bba98fee99af6beff", "skills/goframe-v2"
    ),
}


def digest(value: object) -> str:
    body = json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


NEW_POLICY_DIGEST = digest(EPOCH_POLICY)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def start_epoch(*, source_id: str, published_record: dict, signed_manifest: dict,
                qualification: dict, report_commit: str) -> dict:
    """Freeze all eight previous events outside the legacy max-8 schema."""
    require(report_commit == BASELINE_REPORT_COMMIT, "wrong immutable published report")
    require(source_id in PINS, "unqualified source identity")
    repository, revision, path = PINS[source_id]
    require(signed_manifest.get("schema_version") == 3
            and signed_manifest.get("source_commit") == BASELINE_SOURCE_COMMIT
            and signed_manifest.get("profile", {}).get("digest") == OLD_POLICY_DIGEST
            and signed_manifest.get("scanner", {}).get("revision") == OLD_SCANNER_REVISION,
            "changed signed report policy, scanner or catalog")
    source = published_record.get("source")
    require(isinstance(source, dict), "malformed original source")
    require(published_record.get("id") == source_id
            and published_record.get("status") == "error"
            and published_record.get("freshness") == "current"
            and source.get("repository", "").casefold() == repository
            and source.get("revision") == revision
            and source.get("path") == path
            and source.get("content_digest") is None
            and published_record.get("target_revision") == revision
            and published_record.get("scanner") == signed_manifest.get("scanner")
            and isinstance(signed_manifest.get("profiles"), list)
            and published_record.get("profile") in signed_manifest["profiles"],
            "source identity, freshness or status drift")
    require({x.get("code") for x in published_record.get("errors", [])} == {"acquisition_failed"}
            and {x.get("code") for x in published_record.get("coverage", {}).get("reasons", [])}
            == {"acquisition_failed"}, "not the qualified acquisition failure")
    retry, history = published_record.get("retry") or {}, published_record.get("attempt_history")
    require(retry.get("attempt_count") == 4 and retry.get("disposition") == "exhausted"
            and retry.get("reason") == "transient_retry_limit"
            and retry.get("latest_status") == "error"
            and retry.get("next_attempt_at") is None and retry.get("next_profile") is None
            and isinstance(history, list) and len(history) == 8
            and all(isinstance(x, dict) and x.get("status") == "error" for x in history)
            and history[-1].get("reason") == "transient_retry_limit",
            "old exhausted lineage is invalid")
    require(isinstance(qualification, dict)
            and qualification.get("repository") == repository
            and qualification.get("revision") == revision
            and qualification.get("selected_root") == path
            and qualification.get("status") == "complete_acquisition"
            and isinstance(qualification.get("tree_digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", qualification["tree_digest"]) is not None
            and type(qualification.get("file_count")) is int and qualification["file_count"] > 0
            and qualification.get("scan_status") in ("partial", "complete"),
            "no authenticated immutable complete-acquisition observation")
    frozen = copy.deepcopy(published_record)
    return {
        "schema_version": 1, "kind": "skillspector-470-versioned-shadow-epoch",
        "epoch_id": EPOCH_ID, "new_policy_digest": NEW_POLICY_DIGEST,
        "old_policy_digest": OLD_POLICY_DIGEST,
        "original_report_commit": report_commit,
        "source_id": source_id, "source_revision": revision,
        "qualified_tree_digest": qualification["tree_digest"],
        "original_record_digest": digest(frozen),
        "original_history_digest": digest(frozen["attempt_history"]),
        "original_record": frozen, "new_epoch_attempts": [],
        "max_new_epoch_attempts": 1, "migration_authorized": False,
        "safe_for_automatic_publication": False, "production_error_reduction": 0,
    }


def record_shadow_observation(epoch: dict, *, source_id: str, revision: str,
                              tree_digest: str, scan: dict | None = None,
                              failed_acquisition: dict | None = None) -> dict:
    """Consume one shadow attempt whether scan succeeds or acquisition fails.

    This remains an unsigned observation, NEVER a production retry grant.
    """
    require(epoch.get("kind") == "skillspector-470-versioned-shadow-epoch"
            and epoch.get("epoch_id") == EPOCH_ID
            and epoch.get("new_policy_digest") == NEW_POLICY_DIGEST
            and epoch.get("old_policy_digest") == OLD_POLICY_DIGEST
            and epoch.get("original_report_commit") == BASELINE_REPORT_COMMIT,
            "unrecognized or rolled-back epoch")
    original = epoch.get("original_record")
    require(isinstance(original, dict)
            and digest(original) == epoch.get("original_record_digest")
            and digest(original.get("attempt_history")) == epoch.get("original_history_digest"),
            "original signed lineage or record mutated")
    require(source_id in PINS and source_id == epoch.get("source_id") == original.get("id")
            and revision == epoch.get("source_revision") == PINS[source_id][1]
            and tree_digest == epoch.get("qualified_tree_digest"),
            "source or acquired tree changed since qualification")
    require(epoch.get("migration_authorized") is False
            and epoch.get("safe_for_automatic_publication") is False
            and epoch.get("production_error_reduction") == 0
            and epoch.get("max_new_epoch_attempts") == 1,
            "shadow proof attempted to authorize production")
    attempts = epoch.get("new_epoch_attempts")
    require(isinstance(attempts, list) and len(attempts) == 0,
            "epoch already consumed or replayed")
    # An acquisition failure also consumes the sole new-epoch observation.
    # Otherwise a failed fifth attempt could be silently retried indefinitely.
    if failed_acquisition is not None:
        require(scan is None and isinstance(failed_acquisition, dict)
                and failed_acquisition.get("status") == "error"
                and failed_acquisition.get("reason_code") == "acquisition_failed"
                and failed_acquisition.get("source_id") == source_id
                and failed_acquisition.get("source_revision") == revision,
                "invalid failed-acquisition observation")
        result = copy.deepcopy(epoch)
        result["new_epoch_attempts"] = [{
            "attempt_number_within_epoch": 1,
            "actual_scanner_status": "error",
            "failed_acquisition_digest": digest(failed_acquisition),
            "certified_complete": False,
        }]
        return result
    completeness = scan.get("analysis_completeness") if isinstance(scan, dict) else None
    metadata = scan.get("metadata") if isinstance(scan, dict) else None
    require(isinstance(completeness, dict)
            and (completeness.get("status"), completeness.get("is_complete")) in (
                ("partial", False), ("complete", True), ("complete_with_caveats", True))
            and scan.get("execution_successful") is True
            and completeness.get("execution_successful") is True
            and isinstance(metadata, dict)
            and metadata.get("skillspector_version") == "2.13.1"
            and metadata.get("llm_requested") is False
            and metadata.get("inference_usage") == []
            and isinstance(scan.get("issues"), list),
            "not a real successful scan observation")
    # A report with omitted filtered/suppressed findings is not a faithful
    # security observation, regardless of its scanner completeness status.
    suppressed = scan.get("suppressed")
    suppressed_count = scan.get("suppressed_count")
    before = completeness.get("findings_before_filtering")
    after = completeness.get("findings_after_filtering")
    require(
        type(before) is int and type(after) is int
        and type(suppressed_count) is int
        and 0 <= after <= before
        and isinstance(suppressed, list)
        and len(scan["issues"]) == after
        and len(suppressed) == suppressed_count
        and before == after + suppressed_count
        and all(isinstance(x, dict) for x in [*scan["issues"], *suppressed]),
        "inconsistent scanner finding accounting",
    )
    result = copy.deepcopy(epoch)
    result["new_epoch_attempts"] = [{
        "attempt_number_within_epoch": 1,
        "actual_scanner_status": completeness["status"],
        "observed_scan_digest": digest(scan),
        "observed_security_issues": copy.deepcopy(scan["issues"]),
        "observed_suppressed_issues": copy.deepcopy(suppressed),
        "observed_analysis_completeness": copy.deepcopy(completeness),
        "certified_complete": False,
    }]
    return result
