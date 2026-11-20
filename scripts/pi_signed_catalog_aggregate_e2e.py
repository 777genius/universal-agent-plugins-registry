#!/usr/bin/env python3
"""Fail-closed independent cross-shard evidence gate for signed saved Pi E2E.

Only aggregates authentic results produced by the manual positive matrix; it
never signs, changes a feed, or treats a planned installation as evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from pi_signed_catalog_saved_e2e import (
    PLATFORMS, PUBLIC_CLI, REPO, SHA, SHARDS, catalog_sources, digest,
    expected_shard, require, require_exact_checkout, verify_shard,
)


def aggregate_reports(folder: Path, head: str, sources: list[dict]) -> dict:
    require(folder.is_dir() and not folder.is_symlink(), "missing safe signed evidence directory")
    expected_files = {
        f"pi-signed-full-{platform}-{shard}.json"
        for platform in PLATFORMS for shard in range(SHARDS)
    }
    require({p.name for p in folder.iterdir()} == expected_files,
            "missing, duplicated or unexpected cross-OS/shard signed evidence")
    snapshot = None
    seen = set()
    totals = {platform: 0 for platform in PLATFORMS}
    for platform in PLATFORMS:
        for shard in range(SHARDS):
            path = folder / f"pi-signed-full-{platform}-{shard}.json"
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024,
                    "unsafe or oversized signed shard artifact")
            report = json.loads(path.read_text(encoding="utf-8"))
            require(isinstance(report, dict)
                    and report.get("kind") == "pi-signed-full-catalog-saved-production-e2e"
                    and report.get("source_head") == head
                    and report.get("platform") == platform
                    and type(report.get("shard")) is int and report["shard"] == shard
                    and report.get("cli_version") == PUBLIC_CLI
                    and report.get("signed_production_default") is True
                    and report.get("synthetic_signed_feed") is False
                    and report.get("status") == "passed"
                    and isinstance(report.get("cases"), list),
                    "mismatched, refused or nonproduction signed shard report")
            cases = report["cases"]
            verify_shard(cases, sources, shard)
            for case in cases:
                identity = (platform, case["distribution"], case["release_sequence"], case["scope"])
                require(identity not in seen, "duplicate cross-shard signed scope evidence")
                seen.add(identity)
                release = (case["snapshot_sequence"], case.get("snapshot_digest"))
                require(type(release[0]) is int and release[0] > 0 and digest(release[1]),
                        "unsigned or missing authenticated snapshot digest")
                require(snapshot is None or release == snapshot,
                        "cross-OS/shard tests used different signed snapshots")
                snapshot = release
                totals[platform] += 1
    require(len(seen) == 72 * len(PLATFORMS)
            and all(count == 72 for count in totals.values()),
            "signed saved production coverage is not 72/72 on every OS")
    return {"status": "passed", "source_head": head, "cli_version": PUBLIC_CLI,
            "snapshot_sequence": snapshot[0], "snapshot_digest": snapshot[1],
            "scope_executions": len(seen), "per_os": totals,
            "signed_production_default": True, "synthetic_signed_feed": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require(SHA.fullmatch(args.source_head) is not None
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == REPO
            and os.environ.get("RUNNER_OS") == "Linux",
            "aggregate requires authentic exact-source GitHub Actions runner")
    require_exact_checkout(args.source_head)
    result = aggregate_reports(args.artifacts, args.source_head, catalog_sources(args.source_head))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Signed saved Pi cross-OS aggregate:", json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
