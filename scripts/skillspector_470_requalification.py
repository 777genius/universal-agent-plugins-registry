"""Read-only immutable-bundle qualification for issue #470's Unicode acquisition roots.

No fifth attempt, retry-policy migration, record mutation, or Skill certification
is performed here. An eligibility receipt must never be used as a Complete.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
from pathlib import Path

from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_contract as contract
from scripts.directory_publication import require, sha256_digest

BASELINE_REPORT_COMMIT = "7771404dcdfc5b3855f1319b5e9a2bc19d0c7acf"
BASELINE_SOURCE_COMMIT = "a12bd3bdffab6991a2541220a16a0a9d6447e47e"
# These exact source SHA pins have separately archived no-LLM acquisition proof.
COHORT = (
    # The human-facing name lives in selection.id; the actual source path is
    # empty for the repository-root skill. Never infer a checkout path from ID.
    ("alchaincyf/elon-musk-skill", "65af7c9a5395cc996d17f55b5bde37e6ed72cf4f", ""),
    ("gogf/skills", "c22b6e4115e1a3747676419bba98fee99af6beff", "skills/goframe-v2"),
)
COHORT_IDS = {
    "alchaincyf/elon-musk-skill": "alchaincyf/elon-musk-skill/elon-musk-perspective",
    "gogf/skills": "gogf/skills/goframe-v2",
}


def qualify(bundle: dict, *, report_commit: str) -> dict:
    """Require the original current Error, 4-attempt lineage and immutable pin."""
    require(report_commit == BASELINE_REPORT_COMMIT, "wrong immutable published commit")
    manifest = bundle["manifest"]
    require(manifest["schema_version"] == 3 and
            manifest["source_commit"] == BASELINE_SOURCE_COMMIT and
            manifest["scanner"] == coverage.SCANNER and
            manifest["profile"] == coverage.PROFILE,
            "unreviewed scanner, catalog source or retry policy")
    # The directory can legitimately contain several registry identities for
    # the same upstream path. Only cohort ambiguity matters to this bounded
    # admission proof: never fail on unrelated duplicate source paths, but
    # refuse even one extra candidate for either qualified immutable root.
    cohort_keys = set(COHORT)
    require(len(cohort_keys) == len(COHORT), "duplicate qualified cohort pin")
    index = {}
    for item in bundle["selection"]["sources"]:
        key = (item["repository"].casefold(), item["revision"], item["path"])
        if key not in cohort_keys:
            continue
        require(key not in index, "ambiguous qualified immutable source identity")
        index[key] = item
    receipts = []
    for repository, revision, path in COHORT:
        item = index.get((repository, revision, path))
        require(item is not None and item["id"] == COHORT_IDS[repository],
                "qualified immutable source ID or checkout path no longer selected")
        record = bundle["records"].get(item["id"])
        attempt = bundle["attempts"].get(item["id"])
        require(record is not None and attempt is not None, "missing original report or attempt")
        require(record["freshness"] == "current" and record["status"] == "error" and
                record["source"]["repository"].casefold() == repository and
                record["source"]["revision"] == revision and
                record["source"]["path"] == path and
                record["source"]["content_digest"] is None and
                record["target_revision"] == revision and
                record["scanner"] == coverage.SCANNER and
                record["profile"] in manifest["profiles"] and
                "acquisition_failed" in coverage.reason_codes(record),
                "root is not the original current source-proven acquisition Error")
        require(attempt["id"] == item["id"] and
                attempt["source_digest"] == coverage.source_digest(item) and
                attempt["scanner"] == coverage.SCANNER and
                attempt["policy_digest"] == contract.PROFILE["digest"] and
                attempt["profile"] == record["profile"] and
                attempt["status"] == "error" and
                attempt["attempt_count"] == contract.RETRY_POLICY["maximum_attempts_per_identity"] == 4 and
                attempt["disposition"] == "exhausted" and
                attempt["reason"] == "transient_retry_limit" and
                attempt["next_attempt_at"] is None and attempt["next_profile"] is None and
                # The current retry epoch has four attempts, but these two
                # immutable roots retain four earlier attempts as well.
                # Never truncate or reset their eight-entry forensic history.
                len(attempt["history"]) == 8 and
                all(event["status"] == "error" for event in attempt["history"]) and
                attempt["history"][-1]["reason"] == "transient_retry_limit" and
                record["attempt_history"] == attempt["history"] and
                record["retry"] == coverage.retry_summary(attempt),
                "not an intact exhausted four-attempt immutable ledger")
        receipts.append({
            "id": item["id"],
            "source": {k: item[k] for k in ("kind", "repository", "revision", "path", "plugin_path")},
            "source_digest": attempt["source_digest"],
            "old_policy_digest": attempt["policy_digest"],
            "old_attempt_count": attempt["attempt_count"],
            "old_history_entry_count": len(attempt["history"]),
            "old_disposition": attempt["disposition"],
            # Acquisition errors can predate any normalized scanner report:
            # absence of report_digest is genuine evidence, never a failure to
            # report a source-bound digest. Hash the full authenticated record.
            "old_report_digest_present": "report_digest" in record,
            "old_report_digest": record.get("report_digest"),
            "old_record_digest": sha256_digest(coverage.report_json(record)),
            "old_history_digest": sha256_digest(coverage.report_json(attempt["history"])),
            "old_findings_digest": sha256_digest(coverage.report_json(record["findings"])),
            "old_finding_count": record["finding_count"],
            "old_findings_truncated": record["findings_truncated"],
            "candidate_for_new_policy_epoch_only": True,
            "new_attempt_authorized": False,
            "candidate_complete": False,
        })
    require(len(receipts) == 2 and len({x["id"] for x in receipts}) == 2,
            "cohort does not resolve to two unique roots")
    return {"schema_version": 1, "kind": "skillspector-470-readonly-cohort-audit",
            "baseline_report_commit": BASELINE_REPORT_COMMIT,
            "baseline_source_commit": BASELINE_SOURCE_COMMIT,
            "cohort_size": 2, "production_error_reduction": 0,
            "published_reports_mutated": False, "ready_for_auto_promotion": False,
            "receipts": receipts}


def verify_checkout(root: Path) -> None:
    """Bind input to a clean checkout of the exact immutable Git tree."""
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True)
    require(head.stdout.strip() == BASELINE_REPORT_COMMIT,
            "report checkout does not match original immutable Git SHA")
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain",
                             "--untracked-files=all"],
                            capture_output=True, text=True, check=True)
    require(not status.stdout.strip(), "immutable report checkout has uncommitted changes")


def external_output(root: Path, path: Path, *, checkout_root: Path | None = None) -> Path:
    """Never write anywhere in the original immutable Git checkout, even via symlinks."""
    checkout = (checkout_root or root).resolve(strict=True)
    source = root.resolve(strict=True)
    require(source == checkout or checkout in source.parents,
            "invalid immutable checkout boundary")
    output = path.resolve(strict=False)
    require(output != checkout and checkout not in output.parents,
            "read-only audit cannot write into immutable published checkout")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--published", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.published.resolve(strict=True)
    require(tuple(part.name for part in (root.parent.parent, root.parent, root)) ==
            ("reports", "skillspector", "v3"),
            "immutable published path must end in reports/skillspector/v3")
    checkout_root = root.parents[2]
    verify_checkout(root)
    # Existing v3 reader validates all immutable shards, records, attempt
    # histories, scanner policies, selection digest, and bounds.
    before = (root / "index.json").read_bytes()
    bundle = coverage.read_bundle(root)
    require((root / "index.json").read_bytes() == before,
            "published manifest changed during read-only audit")
    proof = qualify(bundle, report_commit=BASELINE_REPORT_COMMIT)
    destination = external_output(root, args.output, checkout_root=checkout_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: proof[k] for k in proof if k != "receipts"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
