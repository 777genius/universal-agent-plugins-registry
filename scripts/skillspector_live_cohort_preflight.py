#!/usr/bin/env python3
"""Read-only check of nine immutable candidate roots against fresh signed feeds.

Never promotes Partial, signs findings, updates the report branch or executes
Skill content. The authenticated Community/Directory snapshots are fetched
independently of the old v3 selection used by the candidate CLI.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from scripts import discover_skillspector_sources as discovery
from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import sha256_digest, canonical_json
from scripts.discovery_checkpoint import WorkBudget

SHA = admission.SHA
DIGEST = admission.DIGEST


def require(condition: bool, message: str) -> None:
    """Reject missing, conflicting or unverifiable live identities."""
    if not condition:
        raise admission.CohortRejected(message)


def verified_snapshot_metadata(metadata: dict, label: str) -> dict:
    """Preserve exact identifiers of an already verified, current signed feed."""
    require(isinstance(metadata, dict) and metadata.get("state") == "resolved"
            and metadata.get("reason") is None
            and type(metadata.get("sequence")) is int and metadata["sequence"] > 0
            and isinstance(metadata.get("source_commit"), str)
            and SHA.fullmatch(metadata["source_commit"]) is not None
            and isinstance(metadata.get("snapshot_digest"), str)
            and DIGEST.fullmatch(metadata["snapshot_digest"]) is not None,
            f"{label} signed snapshot identity differs")
    return {key: metadata[key] for key in ("sequence", "source_commit", "snapshot_digest")}


def verify_live_pins(
    previous: dict, plan: dict, community: list[dict], community_meta: dict,
    directory: list[dict], directory_meta: dict,
) -> dict:
    """Require nine exact current signed package pins without relabeling scans.

    This checks a fresh signed package SOURCE, not live provider listing IDs,
    candidate scan results, independent publication authorization or safety.
    """
    community_id = verified_snapshot_metadata(community_meta, "Community")
    directory_id = verified_snapshot_metadata(directory_meta, "Directory")
    require(isinstance(community, list) and isinstance(directory, list),
            "signed package inventory is invalid")
    require(isinstance(plan, dict) and plan.get("kind") == "skillspector-bounded-cohort-preflight"
            and plan.get("candidate_status") == "not_scanned"
            and plan.get("live_selection_verified") is False
            and plan.get("publication_authorized") is False,
            "input cohort plan is not read-only")
    require(plan == admission.build_plan(
        previous, previous["selection"], plan["base_report_commit"]),
        "candidate plan differs from verified old-v3 report")
    selected = plan["selection"]["sources"]
    require(len(selected) == len(admission.COHORT) == 9,
            "exact source cohort count differs")
    packages = {}
    for plugin in community:
        require(isinstance(plugin, dict) and isinstance(plugin.get("name"), str),
                "invalid signed Community package identity")
        name = plugin["name"]
        require(name not in packages, "duplicate signed Community package ID")
        packages[name] = plugin
    target_roots = {(item["repository"].casefold(), item["plugin_path"]) for item in selected}
    directory_roots = {}
    for plugin in directory:
        require(isinstance(plugin, dict) and isinstance(plugin.get("source"), dict),
                "invalid signed Directory package")
        source = plugin["source"]
        key = (source["repository"].casefold(), source["path"])
        if key not in target_roots:
            continue
        if key in directory_roots:
            require(directory_roots[key]["source"] == source,
                    "conflicting signed Directory revisions for one target root")
        directory_roots[key] = plugin

    claimed = {}
    result = []
    for item in selected:
        require(item.get("kind") == "plugin_skill"
                and isinstance(item.get("id"), str)
                and item["id"].startswith("plugin:community:"),
                "candidate is not a signed Community plugin Skill")
        package_name = item["id"].split("/", 1)[0][len("plugin:"):]
        plugin = packages.get(package_name)
        require(plugin is not None and plugin.get("available") is True
                and isinstance(plugin.get("components"), list)
                and "skills" in plugin["components"],
                "candidate package is missing from current signed Community snapshot")
        source = plugin.get("source")
        require(isinstance(source, dict)
                and all(source.get(key) == item[key] for key in ("repository", "revision"))
                and source.get("path") == item["plugin_path"],
                "signed Community source pin or package root differs")
        expected_name = "community:" + sha256_digest(
            canonical_json([source["repository"], source["path"]]))[7:39]
        require(package_name == plugin["name"] == expected_name,
                "signed Community plugin identity differs")
        prefix = (source["path"] + "/" if source["path"] else "") + "skills/"
        require(item["path"].startswith(prefix), "Skill root is outside signed package")
        suffix = item["path"][len(prefix):]
        require(bool(suffix) and "/" not in suffix and item["id"] == "plugin:" + package_name + "/" + suffix,
                "signed Skill root identity differs")
        for key in ("tree_digest", "manifest_digest"):
            require(isinstance(plugin.get(key), str)
                    and DIGEST.fullmatch(plugin[key]) is not None,
                    "signed Community package digest is invalid")
        require(type(plugin.get("expected_skills")) is int
                and plugin["expected_skills"] > 0,
                "signed Community Skill inventory is invalid")
        root_key = (item["repository"].casefold(), item["plugin_path"])
        if root_key in directory_roots:
            other = directory_roots[root_key]["source"]
            require(other["repository"].casefold() == item["repository"].casefold()
                    and other["revision"] == item["revision"]
                    and other["path"] == item["plugin_path"],
                    "a newer signed Directory source overrides the Community pin")
        claimed[package_name] = claimed.get(package_name, 0) + 1
        old = previous["records"][item["id"]]
        require(isinstance(old["source"].get("content_digest"), str)
                and DIGEST.fullmatch(old["source"]["content_digest"]) is not None,
                "prior source digest is unavailable")
        result.append({
            "id": item["id"], "repository": item["repository"],
            "revision": item["revision"], "path": item["path"],
            "plugin_path": item["plugin_path"],
            "content_digest": old["source"]["content_digest"],
            "signed_package_id": package_name,
            "signed_package_tree_digest": plugin["tree_digest"],
            "signed_package_manifest_digest": plugin["manifest_digest"],
        })
    for name, count in claimed.items():
        require(count <= packages[name]["expected_skills"],
                "signed Community inventory has fewer Skills than the cohort")
    require(len({row["id"] for row in result}) == 9,
            "duplicate bounded live source")
    return {
        "schema_version": 1, "kind": "skillspector-signed-community-cohort-preflight",
        "base_report_commit": plan["base_report_commit"],
        "base_manifest_digest": plan["base_manifest_digest"],
        "community": community_id, "directory": directory_id,
        "source_pins_verified_against_fresh_signed_feeds": True,
        "provider_listing_verified": False,
        "candidate_scan_verified": False,
        "publication_authorized": False,
        "sources": result,
    }


def main() -> int:
    """Check immutable v3 baseline and fetch both current signed package feeds."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-dir", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    previous = coverage.read_bundle(args.previous_dir)
    require(previous is not None, "prior v3 report bundle is incomplete")
    coverage.validate_manifest(previous["manifest"], current_policy=True)
    lease = scanner.read_report_json(args.previous_dir / "publication-base.json", max_bytes=4096)
    require(lease.get("report_commit") is not None
            and SHA.fullmatch(lease["report_commit"]) is not None,
            "prior report commit lease is invalid")
    plan = scanner.read_report_json(args.plan, max_bytes=1 << 20)
    require(plan.get("base_report_commit") == lease["report_commit"],
            "cohort plan is bound to a different report lease")
    budget = WorkBudget(300)
    community, community_meta = discovery.load_published_community_plugins(budget)
    directory, directory_meta = discovery.load_published_plugins(budget)
    proof = verify_live_pins(previous, plan, community, community_meta,
                             directory, directory_meta)
    admission.write_plan_exclusively(args.output, proof)
    print("Verified nine current signed Community source pins; no scan publication.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
