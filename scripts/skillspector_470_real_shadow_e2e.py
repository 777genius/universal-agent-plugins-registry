#!/usr/bin/env python3
"""One real immutable acquisition+no-LLM scan in an UNSIGNED #470 shadow epoch.

This is NOT a production retry, not authorization for a fifth legacy attempt,
and not certification of a complete source. Preserve the old report, source
identity, all scanner findings and analysis coverage in an artifact.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.build_bridges import PinnedRepository
from scripts.build_registry import directory_tree_digest
from scripts.discovery_checkpoint import WorkBudget
from scripts.skillspector_acquisition import bounded_package_files, materialize_scanned_files
from scripts import skillspector_reports as static
from scripts.skillspector_470_epoch import (
    BASELINE_REPORT_COMMIT, OLD_SCANNER_REVISION, PINS, require,
    start_epoch, record_shadow_observation,
)

ID = "gogf/skills/goframe-v2"
REPOSITORY, REVISION, ROOT = PINS[ID]
SCANNER_CHECKOUT = Path("scanner")
SCANNER_BINARY = SCANNER_CHECKOUT / ".venv/bin/skillspector"
REPORT_DIR = Path("signed-baseline/reports/skillspector/v3")
INDEX_GIT_BLOB = "181b4e95c0f6de5d4535f91031b35dfde7d27a86"
CURRENT_REPORT_COMMIT = "2d0c924bd0ebc16b819a71bb759dd4bac0a57199"
CURRENT_INDEX_GIT_BLOB = "c1404b1381f514388b9d829247fea0ce64ceeb27"
CURRENT_REPORT_DIR = Path("signed-current/reports/skillspector/v3")
SHARD_SHA256 = "888ac8fe47e347c526fa77737ffb9d3bbe26782c7e5cbc025afc9f8e527c9efd"
# These are the original independent five-root acquisition receipts from #43237932304.
TREE_SHA256 = "sha256:75689483353de0f1a54387367d3f38b094022f219c8057021b8c9295a8bba90a"
FILE_COUNT, TREE_BYTES, NON_ASCII_PATHS = 962, 4418429, 400


def git_blob(body: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def validate_no_llm_scan(report: dict, exit_code: int) -> str:
    """Reject a successful process with partial/missing analyzer evidence."""
    require(type(exit_code) is int and exit_code in (0, 1), "unexpected scanner exit")
    require(isinstance(report, dict) and isinstance(report.get("metadata"), dict)
            and report["metadata"].get("skillspector_version") == "2.13.1"
            and report["metadata"].get("llm_requested") is False
            and report["metadata"].get("inference_usage") == []
            and report.get("execution_successful") is True,
            "not a verified pinned no-LLM scanner observation")
    coverage = report.get("analysis_completeness")
    require(isinstance(coverage, dict)
            and coverage.get("execution_successful") is True
            and type(coverage.get("is_complete")) is bool
            and coverage.get("status") in ("partial", "complete", "complete_with_caveats")
            and (coverage["is_complete"] == (coverage["status"] != "partial")),
            "scanner completeness or coverage is inconsistent")
    require(isinstance(report.get("issues"), list), "scanner findings unavailable")
    return coverage["status"]


def load_immutable_original() -> tuple[dict, dict]:
    require(subprocess.check_output(
        ["git", "-C", "signed-baseline", "rev-parse", "HEAD"], text=True
    ).strip() == BASELINE_REPORT_COMMIT, "wrong immutable historical report")
    body = (REPORT_DIR / "index.json").read_bytes()
    require(git_blob(body) == INDEX_GIT_BLOB, "original report Git blob changed")
    index = json.loads(body)
    require(isinstance(index.get("shards"), list), "invalid original shard manifest")
    descriptors = [x for x in index["shards"] if x.get("repository") == REPOSITORY]
    require(len(descriptors) == 1, "original source shard missing/ambiguous")
    shard = descriptors[0]
    require(shard.get("path") == f"shards/{SHARD_SHA256}.json"
            and shard.get("digest") == f"sha256:{SHARD_SHA256}",
            "original signed shard identity differs")
    raw = (REPORT_DIR / shard["path"]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SHARD_SHA256
            and shard.get("bytes") == len(raw), "original shard bytes differ")
    records = json.loads(raw).get("records")
    require(isinstance(records, list) and len(records) == 1
            and records[0].get("id") == ID, "original Error record differs")
    # Independent current signed source lease: an old exhausted Error is not
    # a valid current replay candidate if the selected source has since moved.
    require(subprocess.check_output(
        ["git", "-C", "signed-current", "rev-parse", "HEAD"], text=True
    ).strip() == CURRENT_REPORT_COMMIT, "wrong current signed report")
    current_bytes = (CURRENT_REPORT_DIR / "index.json").read_bytes()
    require(git_blob(current_bytes) == CURRENT_INDEX_GIT_BLOB,
            "current published report Git blob changed")
    current_index = json.loads(current_bytes)
    require(current_index.get("scanner") == index.get("scanner")
            and current_index.get("profile") == index.get("profile"),
            "current analyzer/policy drift requires separate qualification")
    current_states = [x for x in current_index.get("source_states", []) if x.get("id") == ID]
    require(len(current_states) == 1 and current_states[0].get("current") is True
            and current_states[0].get("revision") == REVISION
            and ID in current_states[0].get("selected_ids", []),
            "source revision is no longer current in latest pinned published cohort")
    current_shards = [x for x in current_index.get("shards", [])
                      if x.get("repository") == REPOSITORY]
    require(len(current_shards) == 1
            and current_shards[0].get("digest") == "sha256:" + SHARD_SHA256
            and current_shards[0].get("path") == f"shards/{SHARD_SHA256}.json",
            "current published source evidence differs")
    new_raw = (CURRENT_REPORT_DIR / current_shards[0]["path"]).read_bytes()
    require(new_raw == raw and current_shards[0].get("bytes") == len(new_raw),
            "current published Error/security evidence changed")
    return index, records[0]


def scan_exact_source() -> tuple[dict, dict]:
    require(subprocess.check_output(
        ["git", "-C", str(SCANNER_CHECKOUT), "rev-parse", "HEAD"], text=True
    ).strip() == OLD_SCANNER_REVISION, "analyzer SHA does not match original policy")
    executable = SCANNER_BINARY.resolve()
    static.verify_scanner(executable)
    pinned = PinnedRepository(REPOSITORY, REVISION, None, work_budget=WorkBudget(150))
    try:
        files = bounded_package_files(
            pinned, ROOT, max_files=2048, max_file_bytes=16 << 20, max_tree_bytes=16 << 20
        )
        require(len(files) == FILE_COUNT
                and sum(len(body) for _, _, body in files) == TREE_BYTES
                and sum(not path.isascii() for path, _, _ in files) == NON_ASCII_PATHS
                and any(path == "SKILL.md" for path, _, _ in files)
                and all(mode in (0o644, 0o755) for _, mode, _ in files),
                "immutable acquired source differs from original acquisition")
        with tempfile.TemporaryDirectory(prefix="skillspector-470-shadow-source-") as folder:
            source = Path(folder)
            materialize_scanned_files(files, source, pinned.work_budget)
            tree = directory_tree_digest(source)
            require(tree == TREE_SHA256, "immutable source tree changed")
            with tempfile.TemporaryDirectory(prefix="skillspector-470-shadow-home-") as home:
                code, body = static.run_scanner_v3(
                    executable,
                    ["scan", str(source), "--no-llm", "--format", "json", "--fail-on-incomplete"],
                    Path(home), 180, "static-extended-v3",
                )
            report = static.parse_scanner_json(body, "pinned goframe shadow scan")
            status = validate_no_llm_scan(report, code)
            require(directory_tree_digest(source) == TREE_SHA256,
                    "source mutated during scanner inspection")
        qualified = {
            "repository": REPOSITORY, "revision": REVISION, "selected_root": ROOT,
            "status": "complete_acquisition", "tree_digest": TREE_SHA256,
            "file_count": FILE_COUNT, "scan_status": "partial" if status == "partial" else "complete",
        }
        return qualified, report
    finally:
        pinned.close()


def run(output: Path) -> dict:
    index, original = load_immutable_original()
    qualified, report = scan_exact_source()
    shadow = start_epoch(
        source_id=ID, published_record=original, signed_manifest=index,
        qualification=qualified, report_commit=BASELINE_REPORT_COMMIT,
    )
    observed = record_shadow_observation(
        shadow, source_id=ID, revision=REVISION, tree_digest=TREE_SHA256, scan=report,
    )
    require(len(observed["new_epoch_attempts"]) == 1
            and len(observed["original_record"]["attempt_history"]) == 8
            and observed["new_epoch_attempts"][0]["observed_security_issues"] == report["issues"]
            and observed["new_epoch_attempts"][0]["observed_suppressed_issues"] == report["suppressed"]
            and observed["new_epoch_attempts"][0]["certified_complete"] is False
            and observed["migration_authorized"] is False
            and observed["safe_for_automatic_publication"] is False
            and observed["production_error_reduction"] == 0,
            "shadow observation lost evidence or attempted production promotion")
    proof = {
        "schema_version": 1,
        "kind": "skillspector-470-real-source-unsigned-shadow",
        "historical_report_sha": BASELINE_REPORT_COMMIT,
        "current_published_report_sha": CURRENT_REPORT_COMMIT,
        "current_index_git_blob_sha": CURRENT_INDEX_GIT_BLOB,
        "historical_index_git_blob_sha": INDEX_GIT_BLOB,
        "historical_shard_sha256": "sha256:" + SHARD_SHA256,
        "immutable_source_revision": REVISION,
        "immutable_source_tree_sha256": TREE_SHA256,
        "scanner_revision": OLD_SCANNER_REVISION,
        "real_scanner_status": observed["new_epoch_attempts"][0]["actual_scanner_status"],
        "observed_issue_count": len(report["issues"]),
        "observed_suppressed_count": len(report["suppressed"]),
        "published_error_reduction": 0,
        "publication_authorized": False,
        "certified_complete": False,
        "observation": observed,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(proof, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/skillspector-470-real-shadow.json")
    receipt = run(destination)
    print(json.dumps({
        "source_id": ID, "scan_status": receipt["real_scanner_status"],
        "issues_preserved": receipt["observed_issue_count"],
        "suppressed_preserved": receipt["observed_suppressed_count"],
        "production_error_reduction": 0, "publication_authorized": False,
    }, sort_keys=True))
