#!/usr/bin/env python3
"""Prepare a reproducible, non-publishing SkillSpector regression selection."""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from scripts import skillspector_coverage_v3 as coverage


def prepare(selection, source_commit, output_dir):
    coverage.validate_selection(selection)
    coverage.require(len(selection["sources"]) <= 32, "controlled corpus exceeds 32 sources")
    coverage.require(coverage.SHA.fullmatch(source_commit) is not None, "invalid source commit")
    groups = defaultdict(list)
    for item in selection["sources"]:
        if item["kind"] == "plugin_skill":
            groups[(item["repository"], item["plugin_path"], item["revision"])].append(item)
    repositories = {item["repository"] for item in selection["sources"]}
    summary = {"schema_version": 1, "source_commit": source_commit, "generated_at": coverage.scanner.now(),
        "scope": "bounded_catalog_and_reviewed_sources",
        "catalog": {"complete": True, "pages": 0, "provider_total": 0, "error": None,
                    "mode": "controlled_immutable_regression"},
        "bounds": {"pages": 1, "listings": 10000, "roots": 10000},
        "listings_observed": 0, "repositories_observed": len(repositories), "repositories_resolved": len(repositories),
        "repositories_retained": 0, "selected_roots": len(selection["sources"]),
        "selection_digest": coverage.sha256_digest(coverage.canonical_json(selection)),
        "complete": True, "selection_truncated": False, "diagnostic_counts": {}, "diagnostics": [],
        "diagnostics_truncated": False, "resolution_cache": {}, "repository_aliases": [],
        "catalog_coverage": {key: 0 for key in ("observed", "resolved", "historical", "unresolved", "unavailable", "unsupported")},
        "source_states": [{"id": item["id"], "repository": item["repository"].lower(), "state": "resolved", "current": True,
            "reason": None, "revision": item["revision"], "path": item["path"], "selected_ids": [item["id"]], "candidates": []}
            for item in selection["sources"]],
        "plugin_states": [{"id": "controlled/" + items[0]["id"], "repository": repository, "plugin_path": path,
            "revision": revision, "state": "resolved", "reason": None, "skills_total": len(items),
            "selected_ids": [item["id"] for item in items]} for (repository, path, revision), items in groups.items()]}
    coverage.validate_discovery_summary(summary, selection, source_commit)
    coverage.write_bounded(output_dir / "selection.json", selection, coverage.MAX_SELECTION_BYTES)
    coverage.write_bounded(output_dir / "coverage.json", summary, coverage.MAX_DISCOVERY_BYTES)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    prepare(coverage.load_selection(args.selection), args.source_commit, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
