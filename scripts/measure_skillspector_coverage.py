#!/usr/bin/env python3
"""Measure published coverage without equating an existing report with success.

Reads only local JSON or immutable Git blobs. It never runs source content.
Missing historical telemetry is reported as unknown, not inferred from dates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def measure(manifest, discovery, records, *, snapshot=None):
    statuses = Counter(record["status"] for record in records)
    reasons = Counter(code for record in records for code in
                      {reason["code"] for reason in record.get("errors", [])})
    timings = {}
    for field in ("acquisition_seconds", "analysis_seconds"):
        values = sorted(record.get("execution", {}).get(field) for record in records
                        if isinstance(record.get("execution", {}).get(field), (int, float)))
        timings[field] = {"measured_sources": len(values), "unmeasured_sources": len(records) - len(values),
                         "total": round(sum(values), 3) if values else None,
                         "p50": values[(len(values) - 1) // 2] if values else None,
                         "p95": values[int((len(values) - 1) * .95)] if values else None,
                         "maximum": values[-1] if values else None}
    return {"schema_version": 1, "snapshot": snapshot, "generated_at": manifest["generated_at"],
            "catalog_coverage": {"listings_observed": discovery.get("listings_observed"),
                "repositories_observed": discovery.get("repositories_observed"),
                "repositories_resolved": discovery.get("repositories_resolved"),
                "selected_roots": manifest["coverage"]["selected"],
                "resolution_reasons": discovery.get("diagnostic_counts", {}),
                "exact_listing_resolution": discovery.get("catalog_coverage"),
                "diagnostics_truncated": discovery.get("diagnostics_truncated")},
            "analysis_coverage": {**manifest["coverage"], "complete": statuses["complete"],
                "partial": statuses["partial"], "error": statuses["error"]},
            "incompleteness_sources_by_reason": dict(sorted(reasons.items(), key=lambda pair: (-pair[1], pair[0]))),
            "findings": {"raw_reported": sum(record.get("raw_finding_count", record["finding_count"]) for record in records),
                "published_entries": sum(len(record["findings"]) for record in records),
                "truncated_reports": sum(record["findings_truncated"] for record in records),
                "unique_problem_count": None},
            "timings": timings,
            "limitations": ["Catalog listings and selected roots are different populations.",
                "Reason counts overlap: one source can have several limitations.",
                "Legacy errors and findings are capped; cause counts are lower bounds.",
                "Missing acquisition/analysis durations cannot be recovered from publication timestamps.",
                "Truncated legacy findings cannot establish the exact number of unique problems."]}


def stable_result(record):
    return hashlib.sha256(canonical({key: record.get(key) for key in
        ("status", "source", "finding_count", "findings", "errors")})).hexdigest()


def compare(previous, current):
    old = {record["id"]: record for record in previous}
    result = Counter()
    for record in current:
        prior = old.get(record["id"])
        if prior is None:
            result["new_report"] += 1
        elif record["source"] != prior["source"]:
            result["changed_source"] += 1
        elif stable_result(record) == stable_result(prior):
            key = "unchanged_cached_report" if record["scanned_at"] == prior["scanned_at"] else "repeated_same_result"
            result[key] += 1
            if record["status"] != "complete":
                result[key + "_incomplete"] += 1
        else:
            result["changed_result"] += 1
    return dict(result)


def read_snapshot(read):
    manifest = json.loads(read("index.json"))
    discovery = json.loads(read("coverage.json"))
    records = [record for part in manifest["shards"] for record in json.loads(read(part["path"]))["records"]]
    return manifest, discovery, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--git-repository", type=Path)
    parser.add_argument("--prefix", default="reports/skillspector/v2/")
    parser.add_argument("--history", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.git_repository:
        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(args.git_repository), *arguments], stderr=subprocess.DEVNULL)
        snapshots = []
        cache = {}
        for commit in git("log", f"-{min(max(args.history, 1), 32)}", "--format=%H").decode().splitlines():
            def read(relative):
                key = relative if relative.startswith("shards/") else (commit, relative)
                if key not in cache:
                    cache[key] = git("show", f"{commit}:{args.prefix}{relative}")
                return cache[key]
            try:
                manifest, discovery, records = read_snapshot(read)
            except subprocess.CalledProcessError:
                continue  # Snapshot predates this explicit report format.
            snapshots.append((commit, manifest, discovery, records))
        if not snapshots:
            parser.error("no snapshots exist at the selected format prefix")
        commit, manifest, discovery, records = snapshots[0]
        result = measure(manifest, discovery, records, snapshot=commit)
        result["history"] = [{"from": older[0], "to": newer[0], **compare(older[3], newer[3])}
                             for newer, older in zip(snapshots, snapshots[1:])]
    elif args.report_dir:
        result = measure(*read_snapshot(lambda name: (args.report_dir / name).read_bytes()))
    else:
        parser.error("--report-dir or --git-repository is required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result["analysis_coverage"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
