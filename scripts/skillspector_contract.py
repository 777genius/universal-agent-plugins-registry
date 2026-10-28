"""Version 3 display report contract; independent of signed installation policy."""
from __future__ import annotations

import copy
from pathlib import Path

from scripts import skillspector_reports as scanner
from scripts import skillspector_coverage as v2
from scripts.directory_publication import canonical_json, require, sha256_digest

ROOT = Path(__file__).resolve().parents[1]
RECORD_SCHEMA = ROOT / "schemas/skillspector-record-v3.schema.json"
MANIFEST_SCHEMA = ROOT / "schemas/skillspector-manifest-v3.schema.json"
SHARD_SCHEMA = ROOT / "schemas/skillspector-shard-v3.schema.json"
RETRY_POLICY = {"network_delays_seconds": [900, 3600, 14400], "extended_delay_seconds": 0,
                "maximum_attempts_per_identity": 4, "history_limit": 8,
                "queue_lanes": ["new", "retry", "changed"], "normalization_version": 3}
POLICY_DOCUMENT = {"id": "static-policy-v3", "profiles": list(scanner.PROFILES.values()),
                   "retry": RETRY_POLICY, "preparation_seconds": 120}
PROFILE = {"id": POLICY_DOCUMENT["id"], "digest": sha256_digest(canonical_json(POLICY_DOCUMENT))}


def known_profile(record):
    return (record["scanner"] == scanner.SCANNER and
            record["profile"] == scanner.PROFILES.get(record["profile"]["id"]))


def import_legacy(record, *, profile=None, scanner_identity=None):
    """Preserve old results as historical evidence, never manufacture coverage.

    Legacy publication discarded IDs/evidence and capped finding and reason
    arrays. Each visible entry remains separate; exact deduplication is unknown.
    """
    item = {key: record[key] for key in ("id", "kind", "plugin_path")}
    item.update({key: record["source"][key] for key in ("repository", "revision", "path")})
    converted = scanner.empty_record_v3(item)
    converted.update(copy.deepcopy(record))
    converted["profile"] = copy.deepcopy(profile or v2.PROFILE)
    converted["scanner"] = copy.deepcopy(scanner_identity or v2.SCANNER)
    converted["legacy_format"] = 2
    converted["freshness"] = "historical"
    converted["target_revision"] = record["source"]["revision"]
    converted["execution"] = {"state": "failed" if record["status"] == "error" else "completed",
        "started_at": record["scanned_at"], "finished_at": None, "exit_code": None,
        "acquisition_seconds": None, "analysis_seconds": None}
    converted["coverage"]["status"] = {"complete": "complete", "partial": "partial", "error": "not_started"}[record["status"]]
    converted["coverage"]["grouping_complete"] = False
    converted["coverage"]["reasons"] = [{**reason, "retryable": False} for reason in record["errors"]]
    converted["raw_finding_count"] = record["finding_count"]
    converted["finding_group_count"] = len(record["findings"])
    converted["findings"] = []
    for index, finding in enumerate(record["findings"]):
        location = {key: finding[key] for key in ("path", "line") if key in finding}
        converted["findings"].append({**copy.deepcopy(finding),
            "id": sha256_digest(canonical_json({"source": record["source"], "position": index, "finding": finding})),
            "finding_ids": [], "match_fingerprint": None, "evidence": {}, "confidence": None,
            "review_status": "unreviewed", "occurrences": [location], "raw_count": 1})
    return converted


def validate_record(record, item, generated, *, scheduled=False):
    v2.schema(record, RECORD_SCHEMA)
    require(record["id"] == item["id"] and record["kind"] == item["kind"] and
            record["plugin_path"] == item["plugin_path"], "record selection identity differs")
    require(record["source"]["repository"].lower() == item["repository"].lower() and
            record["source"]["path"] == item["path"], "record source identity differs")
    historical = record.get("freshness") == "historical"
    if "legacy_format" in record:
        require(historical and record["profile"] in (v2.PROFILE, scanner.PROFILE),
                "legacy evidence must retain its historical profile")
    require(historical or record["source"]["revision"] == item["revision"], "current record revision differs")
    require(historical or known_profile(record), "current report uses an obsolete scanner/profile")
    if scheduled:
        require(all(key in record for key in ("freshness", "target_revision", "retry", "attempt_history")),
                "scheduled report lacks queue state")
        require(record["target_revision"] == item["revision"], "record target revision differs")
    if record["scanned_at"] is not None:
        require(v2.timestamp(record["scanned_at"], "scanned_at") <= generated, "record is newer than its artifact")
    for key in ("started_at", "finished_at"):
        if record["execution"][key] is not None:
            require(v2.timestamp(record["execution"][key], key) <= generated, "execution is newer than artifact")
    require(record["raw_finding_count"] >= record["finding_count"] >= len(record["findings"]), "invalid raw finding counts")
    require(record["finding_group_count"] >= len(record["findings"]), "invalid finding group count")
    if "legacy_format" not in record:
        require(record["findings_truncated"] == (record["finding_group_count"] > len(record["findings"])),
                "invalid grouped finding truncation")
        if not record["findings_truncated"]:
            require(record["finding_count"] == sum(finding["raw_count"] for finding in record["findings"]),
                    "content finding count differs from preserved signals")
    ids = set()
    for finding in record["findings"]:
        require(finding["id"] not in ids, "duplicate finding group identity")
        ids.add(finding["id"])
        for location in [finding, *finding["occurrences"]]:
            path = location["path"]
            require(not Path(path).is_absolute() and "\\" not in path and
                    all(part not in {"", ".", ".."} for part in path.split("/")), "finding location escapes source")
        require(finding["review_status"] == "unreviewed", "automated scan cannot claim human confirmation")
    if record["status"] == "complete" and "legacy_format" not in record:
        require(record["execution"]["state"] == "completed" and record["execution"]["exit_code"] in (0, 1) and
                record["coverage"]["status"] == "complete" and not record["coverage"]["reasons"] and
                not record["errors"] and record["coverage"]["fully_inspected_files"] > 0 and
                record["coverage"]["partially_inspected_files"] == 0 and
                record["coverage"]["entirely_uninspected_files"] == 0, "complete report lacks complete analysis")
        completed = {value.get("analyzer_id") for value in record["coverage"]["analyzers"] if value.get("status") == "completed"}
        require({"artifact_integrity", "static_patterns_prompt_injection", "static_yara"} <= completed,
                "complete report lacks required analyzer evidence")
        for analyzer in record["coverage"]["analyzers"]:
            require(analyzer.get("status") in {"completed", "not_applicable", "disabled"} and
                    not any(analyzer.get(key, 0) != 0 for key in ("failed", "partial", "skipped", "unaccounted")) and
                    (analyzer.get("status") != "disabled" or analyzer.get("analyzer_id") in scanner.DISABLED_STATIC_ANALYZERS),
                    "complete report contains incomplete analyzer evidence")
    return record


def analysis_counts(selection, records):
    counts = {key: 0 for key in ("selected", "reported", "pending", "complete", "partial", "error", "stale")}
    for item in selection["sources"]:
        counts["selected"] += 1
        record = records.get(item["id"])
        if record is None:
            counts["pending"] += 1
        else:
            counts["reported"] += 1
            if record.get("freshness", "current") == "historical":
                counts["stale"] += 1
                counts["pending"] += 1
            else:
                counts[record["status"]] += 1
    return counts


def plugin_counts(selection, records):
    groups = {}
    for item in selection["sources"]:
        if item["kind"] == "plugin_skill":
            groups.setdefault((item["repository"].lower(), item["plugin_path"]), []).append(item)
    return [{"repository": items[0]["repository"], "plugin_path": path,
             **analysis_counts({"sources": items}, records)} for (_, path), items in sorted(groups.items())]
