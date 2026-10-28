#!/usr/bin/env python3
"""Measure a reviewed immutable corpus without executing its skill content.

Raw scanner JSON and the full v3 display record are retained beside each
measurement, so profile comparisons do not rely on truncated finding samples.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import copy
import json
import tempfile
import time
from pathlib import Path

from scripts import skillspector_reports as reports
from scripts.build_bridges import PinnedRepository
from scripts.build_discovery_index import bounded_package_files, materialize_package
from scripts.build_registry import directory_tree_digest
from scripts.directory_publication import require, sha256_digest
from scripts.discovery_checkpoint import WorkBudget


def measure(item, profile_id, scanner, mirror_root, output_dir):
    profile = reports.PROFILE_DOCUMENTS[profile_id]
    record = reports.empty_record_v3(item, profile_id)
    target = output_dir / sha256_digest(reports.report_json([item, profile_id]))[7:]
    target.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    acquisition = None
    analysis = None
    pinned = None
    summary = {"id": item["id"], "source": copy.deepcopy(record["source"]), "profile": reports.PROFILES[profile_id]}
    try:
        pinned = PinnedRepository(item["repository"], item["revision"], mirror_root,
                                  work_budget=WorkBudget(120))
        files = bounded_package_files(pinned, item["path"], max_files=profile["max_files"],
            max_file_bytes=profile["max_tree_bytes"], max_tree_bytes=profile["max_tree_bytes"])
        require(any(path == "SKILL.md" for path, _, _ in files), "selected root has no SKILL.md")
        summary.update(files=len(files), bytes=sum(len(body) for _, _, body in files))
        with tempfile.TemporaryDirectory(prefix="skillspector-measure-") as temporary:
            home = Path(temporary)
            root = home / "content"
            root.mkdir()
            materialize_package(files, root, pinned.work_budget)
            digest = directory_tree_digest(root)
            record["source"]["content_digest"] = summary["source"]["content_digest"] = digest
            record["scanned_at"] = record["execution"]["started_at"] = reports.now()
            prepared = time.monotonic()
            acquisition = round(prepared - started, 3)
            code, body = reports.run_scanner_v3(scanner,
                ["scan", str(root), *profile["arguments"]], home, profile["timeout_seconds"], profile_id)
            analysis = round(time.monotonic() - prepared, 3)
            (target / "raw.json").write_bytes(body)
            invocation = {"exit_code": code, "acquisition_seconds": acquisition, "analysis_seconds": analysis,
                          "content_digest": digest, "scanned_at": record["scanned_at"]}
            (target / "invocation.json").write_bytes(reports.report_json(invocation))
            record["execution"].update(acquisition_seconds=acquisition, analysis_seconds=analysis)
            reports.normalize_report_v3(record, body, code, root)
            require(directory_tree_digest(root) == digest, "selected bytes changed during scan")
        normalized = reports.report_json(record)
        (target / "record.json").write_bytes(normalized)
        summary.update(status=record["status"], raw_findings=record["raw_finding_count"],
            content_findings=record["finding_count"], groups=record["finding_group_count"],
            false_positive_groups=sum(f["review_status"] == "false_positive" for f in record["findings"]),
            coverage_findings=len(record["coverage"]["original_findings"]),
            raw_report_digest=sha256_digest(body), normalized_record_digest=sha256_digest(normalized),
            reason_counts=dict(collections.Counter(r["code"] for r in record["coverage"]["reasons"])))
    except Exception as error:
        summary.update(status="error", error=type(error).__name__, message=str(error))
    finally:
        if pinned is not None:
            pinned.close()
    summary.update(acquisition_seconds=acquisition, analysis_seconds=analysis)
    (target / "summary.json").write_bytes(reports.report_json(summary))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--mirror-root", type=Path)
    parser.add_argument("--profiles", nargs="+", choices=sorted(reports.PROFILES), default=sorted(reports.PROFILES))
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    require(1 <= args.workers <= 3, "measurement workers must be between one and three")
    selection = reports.load_selection(args.selection)
    require(len(selection["sources"]) <= 32, "controlled profile corpus exceeds 32 sources")
    scanner = args.scanner.resolve()
    reports.verify_scanner(scanner)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    jobs = [(item, profile) for item in selection["sources"] for profile in args.profiles]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(measure, item, profile, scanner, args.mirror_root, args.output_dir)
                   for item, profile in jobs]
        results = [future.result() for future in futures]
    result = {"schema_version": 1, "generated_at": reports.now(), "scanner": reports.SCANNER,
              "profile_documents": reports.PROFILE_DOCUMENTS, "measurements": results}
    (args.output_dir / "summary.json").write_bytes(reports.report_json(result))
    print(json.dumps({"sources": len(selection["sources"]), "measurements": len(results),
                      "statuses": dict(collections.Counter(row["status"] for row in results))}, sort_keys=True))
    return 1 if any(row["status"] == "error" for row in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
