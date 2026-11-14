"""Read-only, immutable-source pilot for the SkillSpector 2.13.4 migration.

NEVER changes v3 reports, retry state, scanner policy, signed release or install
eligibility. Its evidence is only an input to a separate, reviewed promotion.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import urllib.request
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

SCANNER = {"id": "skillspector", "version": "2.13.4", "revision": "54824463814a0be01360792523ec7245a69190fc"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REASONS = {"reference_missing", "static_parse_limit", "opaque_content", "obfuscated_instruction_text",
           "recovery_conflict_attempt_limit", "extended_budget_exhausted"}


def validate_cases(cases: dict) -> list[dict]:
    if type(cases) is not dict or set(cases) != {"schema_version", "source_report_commit", "manifest_digest", "cases"}:
        raise ValueError("invalid canary manifest")
    if type(cases["schema_version"]) is not int or cases["schema_version"] != 1 or not isinstance(cases["source_report_commit"], str) or not SHA.fullmatch(cases["source_report_commit"]):
        raise ValueError("invalid immutable baseline commit")
    if not isinstance(cases["manifest_digest"], str) or not DIGEST.fullmatch(cases["manifest_digest"]):
        raise ValueError("invalid immutable manifest digest")
    entries = cases["cases"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 12:
        raise ValueError("invalid bounded canary selection")
    seen = set()
    for item in entries:
        if type(item) is not dict or set(item) != {"id", "kind", "plugin_path", "repository", "revision",
                                                    "path", "content_digest", "status", "reason", "finding_count"}:
            raise ValueError("invalid canary source fields")
        if not isinstance(item["id"], str) or not item["id"] or item["id"] in seen:
            raise ValueError("duplicate or empty canary ID")
        seen.add(item["id"])
        if item["kind"] not in {"standalone_skill", "plugin_skill"} or not isinstance(item["repository"], str) or \
           not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item["repository"]) or \
           not isinstance(item["revision"], str) or not SHA.fullmatch(item["revision"]):
            raise ValueError("invalid canary source identity")
        if not isinstance(item["path"], str) or item["path"].startswith("/") or \
           any(part in ("", ".", "..") for part in item["path"].split("/")):
            raise ValueError("nonportable canary source path")
        if (item["kind"] == "standalone_skill" and item["plugin_path"] is not None) or \
           (item["kind"] == "plugin_skill" and not isinstance(item["plugin_path"], str)):
            raise ValueError("invalid plugin source scope")
        if not isinstance(item["content_digest"], str) or not DIGEST.fullmatch(item["content_digest"]) or \
           item["status"] != "partial" or item["reason"] not in REASONS or \
           type(item["finding_count"]) is not int or not 0 <= item["finding_count"] <= 1_000_000:
            raise ValueError("invalid baseline evidence")
    return entries



def _fetch_published(commit: str, relative_path: str, maximum: int) -> bytes:
    # Every path is an exact manifest member under an immutable 40-hex Git SHA.
    # No caller-controlled host, branch or redirect target is accepted.
    import urllib.parse
    url = ("https://raw.githubusercontent.com/777genius/universal-agent-plugins-registry/"
           + commit + "/reports/skillspector/v3/" + relative_path)
    request = urllib.request.Request(url, headers={"User-Agent": "uap-skillspector-readonly-qualification"})
    with urllib.request.urlopen(request, timeout=45) as result:
        if urllib.parse.urlsplit(result.geturl()).hostname != "raw.githubusercontent.com":
            raise ValueError("immutable GitHub content redirected to an unexpected host")
        body = result.read(maximum + 1)
    if not body or len(body) > maximum:
        raise ValueError("published baseline exceeds its strict byte limit")
    return body


def verify_published_baseline(cases: dict, *, fetcher=None) -> list[dict]:
    """Re-read the *original* immutable Git publication, not a user fixture claim.

    Only matching source, original normalized findings and signed/publication-era
    record identity can be compared. No change to history, retries or status.
    """
    entries = validate_cases(cases)
    commit = cases["source_report_commit"]
    get = fetcher or (lambda relative, maximum: _fetch_published(commit, relative, maximum))
    manifest_body = get("index.json", 16 << 20)
    if "sha256:" + hashlib.sha256(manifest_body).hexdigest() != cases["manifest_digest"]:
        raise ValueError("published v3 manifest SHA-256 differs from immutable baseline")
    manifest = json.loads(manifest_body)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 3 or not SHA.fullmatch(str(manifest.get("source_commit", ""))):
        raise ValueError("invalid published v3 manifest identity")
    shards = manifest.get("shards")
    if not isinstance(shards, list) or not shards:
        raise ValueError("missing published v3 shard inventory")
    by_repository = {}
    for descriptor in shards:
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("repository"), str):
            raise ValueError("invalid published shard identity")
        by_repository.setdefault(descriptor["repository"].lower(), []).append(descriptor)
    evidence, fetched = [], {}
    for entry in entries:
        repo = entry["repository"].lower()
        candidates = by_repository.get(repo, [])
        if len(candidates) != 1:
            raise ValueError("pinned baseline repository is missing or ambiguous")
        shard = candidates[0]
        path, digest, size = shard.get("path"), shard.get("digest"), shard.get("bytes")
        if (not isinstance(path, str) or not re.fullmatch(r"shards/[0-9a-f]{64}\.json", path) or
            not isinstance(digest, str) or not DIGEST.fullmatch(digest) or
            path != "shards/" + digest[7:] + ".json" or type(size) is not int or not 0 < size <= 8 << 20):
            raise ValueError("invalid published content-addressed shard")
        if path not in fetched:
            body = get(path, 8 << 20)
            if len(body) != size or "sha256:" + hashlib.sha256(body).hexdigest() != digest:
                raise ValueError("published v3 shard violates its immutable digest")
            published = json.loads(body)
            if (not isinstance(published, dict) or published.get("schema_version") != 3 or
                published.get("repository", "").lower() != repo or
                not isinstance(published.get("records"), list) or
                len(published["records"]) != shard.get("record_count")):
                raise ValueError("published v3 shard contents differ from manifest")
            fetched[path] = published["records"]
        records = [r for r in fetched[path] if r.get("id") == entry["id"]]
        if len(records) != 1:
            raise ValueError("canary selection has no unique published baseline")
        original = records[0]
        if (original.get("kind") != entry["kind"] or original.get("plugin_path") != entry["plugin_path"] or
            original.get("source", {}).get("repository", "").lower() != repo or
            any(original.get("source", {}).get(k) != entry[k] for k in ("revision", "path", "content_digest")) or
            original.get("freshness") != "current" or original.get("status") != "partial" or
            original.get("finding_count") != entry["finding_count"] or
            original.get("retry", {}).get("reason") != entry["reason"] or
            original.get("scanner", {}).get("version") != "2.13.1"):
            raise ValueError("canary fixture is not identical to immutable published source evidence")
        evidence.append({"id": entry["id"], "original_report_digest": original.get("report_digest"),
                         "original_finding_group_count": original.get("finding_group_count"),
                         "original_findings_sha256": "sha256:" + hashlib.sha256(json.dumps(original.get("findings", []),
                             ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
                         "original_finding_groups": finding_group_evidence(original),
                         "original_shard_digest": digest})
    return evidence


def finding_group_evidence(record: dict) -> dict:
    """Expose original/candidate group identities without redefining scanner findings.

    A count can remain unchanged while a different security group disappears.
    Group IDs are the published v3 SHA-256 fingerprints; no inferred matching
    across analyzer versions can authorize a safety conclusion.
    """
    groups = record.get("findings")
    total = record.get("finding_group_count")
    coverage = record.get("coverage")
    if (not isinstance(groups, list) or type(total) is not int or total < 0 or
        not isinstance(coverage, dict)):
        raise ValueError("missing independently reviewable finding-group evidence")
    complete = (coverage.get("grouping_complete") is True and
                record.get("findings_truncated") is False)
    if complete and len(groups) != total:
        raise ValueError("finding-group enumeration contradicts complete grouping")
    if type(record.get("finding_count")) is not int or record["finding_count"] < 0:
        raise ValueError("invalid normalized finding count")
    def content_digest(value):
        return "sha256:" + hashlib.sha256(json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    ids = set()
    normalized = []
    for group in groups:
        if (not isinstance(group, dict) or not isinstance(group.get("id"), str) or
            not DIGEST.fullmatch(group["id"]) or group["id"] in ids or
            not isinstance(group.get("rule"), str) or
            group.get("severity") not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} or
            not isinstance(group.get("path"), str) or
            type(group.get("raw_count")) is not int or group["raw_count"] <= 0 or
            not isinstance(group.get("occurrences"), list) or
            len(group["occurrences"]) != group["raw_count"]):
            raise ValueError("invalid or duplicate normalized security finding group")
        ids.add(group["id"])
        normalized.append({**{key: group[key] for key in
                           ("id", "rule", "severity", "path")},
                           "raw_count": group["raw_count"],
                           "occurrence_count": len(group["occurrences"]),
                           "normalized_group_sha256": content_digest(group)})
    if complete and sum(group["raw_count"] for group in groups) != record["finding_count"]:
        raise ValueError("normalized finding count contradicts complete grouping")
    coverage_findings = coverage.get("original_findings", [])
    if not isinstance(coverage_findings, list):
        raise ValueError("invalid original coverage finding evidence")
    return {"grouping_complete": complete, "group_count": total,
            "groups": sorted(normalized, key=lambda group: group["id"]),
            "coverage_finding_count": len(coverage_findings),
            "coverage_findings_sha256": content_digest(coverage_findings)}


def finding_group_delta(original: dict, candidate: dict) -> dict:
    """Report unmatched groups for mandatory manual review; never auto-promote."""
    current = finding_group_evidence(candidate)
    old = original["original_finding_groups"]
    old_by_id = {group["id"]: group for group in old["groups"]}
    new_by_id = {group["id"]: group for group in current["groups"]}
    old_ids, new_ids = set(old_by_id), set(new_by_id)
    changed_common = sorted(group_id for group_id in (old_ids & new_ids)
        if old_by_id[group_id]["normalized_group_sha256"] !=
           new_by_id[group_id]["normalized_group_sha256"])
    return {
        "old_group_count": old["group_count"],
        "new_group_count": current["group_count"],
        "old_grouping_complete": old["grouping_complete"],
        "new_grouping_complete": current["grouping_complete"],
        "old_groups_not_in_candidate": sorted(old_ids - new_ids),
        "candidate_groups_not_in_old": sorted(new_ids - old_ids),
        "matching_ids_with_changed_occurrences_or_evidence": changed_common,
        "candidate_groups": current["groups"],
        "old_coverage_finding_count": old["coverage_finding_count"],
        "new_coverage_finding_count": current["coverage_finding_count"],
        "coverage_findings_digest_changed": (
            old["coverage_findings_sha256"] != current["coverage_findings_sha256"]),
        "independent_review_required": True,
        "eligible_for_no_loss_assertion": (
            old["grouping_complete"] and current["grouping_complete"] and
            not (old_ids - new_ids) and not changed_common and
            old["coverage_findings_sha256"] == current["coverage_findings_sha256"]),
    }


def candidate_profile_identity() -> dict:
    """Bind the measured report to the exact unpatched 2.13.4 scanner profile."""
    from scripts import skillspector_reports as scanner
    from scripts.directory_publication import canonical_json, sha256_digest

    document = candidate_profile(scanner.STANDARD_PROFILE_DOCUMENT)
    return {"id": document["id"], "digest": sha256_digest(canonical_json(document))}


def compare(item: dict, record: dict) -> dict:
    """Neither scanner status nor fewer findings constitutes a safe migration."""
    if record["source"]["repository"] != item["repository"] or \
       record["source"]["revision"] != item["revision"] or \
       record["source"]["path"] != item["path"] or \
       record["source"]["content_digest"] != item["content_digest"]:
        raise ValueError("rescan source differs from immutable baseline")
    if record["scanner"] != SCANNER or record["status"] not in {"complete", "partial", "error"}:
        raise ValueError("untrusted scanner identity or status")
    if record.get("profile") != candidate_profile_identity():
        raise ValueError("candidate profile identity does not match the exact 2.13.4 scan policy")
    if record["status"] == "complete":
        coverage = record["coverage"]
        analyzers = coverage.get("analyzers", [])
        required = {"artifact_integrity", "static_patterns_prompt_injection", "static_yara"}
        completed = {a.get("analyzer_id") for a in analyzers if isinstance(a, dict)
                     and a.get("status") == "completed"}
        if (coverage["status"] != "complete" or record["execution"]["state"] != "completed" or
            record["execution"].get("exit_code") not in (0, 1) or coverage["reasons"] or
            coverage.get("fully_inspected_files", 0) <= 0 or
            coverage.get("grouping_complete") is not True or
            coverage.get("ledger_exceptions") or
            coverage.get("reference_evidence_truncated") or record["errors"] or
            coverage["partially_inspected_files"] or coverage["entirely_uninspected_files"] or
            record["findings_truncated"] or not required.issubset(completed) or
            any(not isinstance(a, dict) or a.get("status") not in
                {"completed", "not_applicable", "disabled"} for a in analyzers)):
            raise ValueError("claimed Complete lacks complete evidence")
    status = record["status"]
    found = record["finding_count"]
    return {
        "id": item["id"], "old_status": item["status"], "old_reason": item["reason"],
        "new_status": status, "old_findings": item["finding_count"], "new_findings": found,
        "same_source": True,
        # Always require an independent version-bound finding review before promotion.
        "manual_finding_review_required": True,
        "candidate_complete": status == "complete", "fewer_findings": found < item["finding_count"],
        "coverage_reasons": sorted(set(x["code"] for x in record["coverage"]["reasons"])),
        "error_codes": sorted(set(x["code"] for x in record["errors"])),
    }


def candidate_profile(production_profile: dict) -> dict:
    """Never attest an unapplied v2.13.1 maintenance patch on raw 2.13.4.

    This read-only canary intentionally checks out NVIDIA\u0027s unmodified source.
    Keep its semantic identity distinct from every published UAP profile.
    """
    document = copy.deepcopy(production_profile)
    document.pop("reference_inventory_patch", None)
    document["reference_analyzer_semantics"] = "unmodified-upstream-2.13.4"
    document["upgrade_canary_scanner_revision"] = SCANNER["revision"]
    return document


def scan(executable: Path, cases: dict) -> dict:
    from scripts import skillspector_reports as scanner
    from scripts import skillspector_coverage_v3 as coverage
    from scripts.build_bridges import PinnedRepository
    from scripts.discovery_checkpoint import WorkBudget
    from scripts.directory_publication import sha256_digest, canonical_json

    with tempfile.TemporaryDirectory(prefix="skillspector-2134-canary-version-") as directory:
        code, body = scanner.run_scanner(executable, ["--version"], Path(directory), 15)
    if code != 0 or body.strip() != b"SkillSpector v2.13.4":
        raise ValueError("canary scanner executable/version mismatch")

    # The canary is an isolated process; published scanner and profiles remain unchanged.
    scanner.SCANNER = copy.deepcopy(SCANNER)
    standard = candidate_profile(scanner.STANDARD_PROFILE_DOCUMENT)
    scanner.PROFILE_DOCUMENTS["static-standard-v3"] = standard
    scanner.PROFILES["static-standard-v3"] = candidate_profile_identity()

    original_evidence = verify_published_baseline(cases)
    results = []
    for item in validate_cases(cases):
        subject = {key: item[key] for key in ("id", "kind", "plugin_path", "repository", "revision", "path")}
        budget = WorkBudget(300)
        pin = PinnedRepository(item["repository"], item["revision"], None,
            github_token=os.environ.get("GITHUB_TOKEN"), work_budget=budget)
        try:
            # Reuse the production acquisition, immutable byte digest and scanner limits.
            record = coverage.scan_selected(executable, subject, pin, budget,
                                            profile_id="static-standard-v3")
        finally:
            pin.close()
        comparison = compare(item, record)
        comparison["candidate_report_digest"] = record.get("report_digest")
        comparison["finding_group_delta"] = finding_group_delta(
            original_evidence[len(results)], record)
        results.append(comparison)
    counts = Counter(row["new_status"] for row in results)
    return {
        "schema_version": 1, "kind": "skillspector-upgrade-canary-readonly",
        "candidate_scanner": SCANNER, "base_report_commit": cases["source_report_commit"],
        "result_counts": {key: counts[key] for key in ("complete", "partial", "error")},
        "safe_for_automatic_publication": False, "original_evidence": original_evidence, "results": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--scanner", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    validate_cases(cases)
    result = scan(args.scanner.resolve(strict=True), cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Source-bound and finding-group counts are safe to show in immutable CI logs.
    # Keep raw source content and raw findings in the proof artifact, never logs.
    source_by_id = {item["id"]: item for item in cases["cases"]}
    rows = []
    for row in result["results"]:
        change = row["finding_group_delta"]
        source = source_by_id[row["id"]]
        rows.append({
            "id": row["id"], "revision": source["revision"],
            "content_digest": source["content_digest"],
            "old_status": row["old_status"], "new_status": row["new_status"],
            "coverage_reasons": row["coverage_reasons"], "error_codes": row["error_codes"],
            "old_findings": row["old_findings"], "new_findings": row["new_findings"],
            "old_groups": change["old_group_count"], "new_groups": change["new_group_count"],
            "removed_groups": len(change["old_groups_not_in_candidate"]),
            "changed_group_evidence": len(change["matching_ids_with_changed_occurrences_or_evidence"]),
            "finding_review_required": change["independent_review_required"],
            "no_loss_proven": change["eligible_for_no_loss_assertion"],
            "same_immutable_source": row["same_source"],
        })
    print(json.dumps({"status": "measurement_only", "result_counts": result["result_counts"],
                      "promotion_authorized": False, "case_evidence": rows}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Canary failed closed: " + str(error), file=sys.stderr)
        sys.exit(1)
