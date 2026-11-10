#!/usr/bin/env python3
"""Prepare an UNSIGNED, isolated Directory v1 Pi source candidate for review.

This is not a signing, approval, feed promotion, or evidence of signed Pi installs.
The existing registry/directory.json and historical signed feed stay untouched.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

from pi_catalog_inventory_e2e import ROOT, SHA, active_sources, require, require_exact_checkout

REVIEW_FIELDS = {"distribution", "release_sequence", "tree_digest", "transport",
                 "authentication", "evidence_url"}
TRANSPORTS = {"stdio", "streamable-http", "skills"}
AUTHENTICATION = {"required", "not_required", "unknown"}
RUNNER_OS = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}
PLATFORMS = set(RUNNER_OS)
SCOPES = ("user", "project")
MARKETING_KIT = "777genius/marketing-kit"


def expected_cases(sources: list[dict]) -> dict[tuple[str, int, str], dict]:
    return {(source["distribution"], source["release_sequence"], scope): source
            for source in sources for scope in SCOPES}


def validate_platform_report(report: dict, platform: str, head: str,
                             sources: list[dict]) -> tuple[int, int]:
    """Require complete exact-source evidence; never convert a refusal into PASS."""
    require(platform in PLATFORMS and report.get("runner_os") == RUNNER_OS[platform]
            and type(report.get("schema_version")) is int
            and report["schema_version"] == 1
            and report.get("source_commit") == head
            and report.get("cli_version") == "0.1.102"
            and report.get("kind") == "pi-direct-source-planning"
            and report.get("signed_pi_policy_published") is False
            and report.get("runtime_claims") is False
            and report.get("account_authentication") == "not_tested"
            and report.get("scopes") == list(SCOPES)
            and type(report.get("active_policy_count")) is int
            and report["active_policy_count"] == len(sources),
            f"{platform}: invalid or unqualified source evidence")
    expected = expected_cases(sources)
    results = report.get("results")
    require(isinstance(results, list) and len(results) == len(expected),
            f"{platform}: missing or duplicate cases")
    seen: set[tuple[str, int, str]] = set()
    planned = refused = 0
    for case in results:
        require(isinstance(case, dict), f"{platform}: malformed case")
        require(type(case.get("release_sequence")) is int,
                f"{platform}: invalid release sequence in case")
        key = (case.get("distribution"), case["release_sequence"], case.get("scope"))
        require(key in expected and key not in seen, f"{platform}: unknown or repeated case")
        seen.add(key)
        source = expected[key]
        require(all(case.get(field) == source[field] for field in
                    ("source", "revision", "tree_digest", "manifest_name",
                     "distribution_status", "components")),
                f"{platform}: mismatched immutable source evidence")
        status = case.get("status")
        if source["distribution_status"] != "active":
            require(status == "not_eligible" and "exit_code" not in case
                    and "planned_actions" not in case,
                    f"{platform}: suspended source was accepted")
        elif status == "planned":
            require(type(case.get("exit_code")) is int and case["exit_code"] == 0,
                    f"{platform}: planned case has no successful CLI exit")
            actions = case.get("planned_actions")
            require(isinstance(actions, list) and len(actions) > 0
                    and all(isinstance(action, dict)
                            and action.get("client_id") == "pi"
                            and action.get("action") in {"install", "unchanged"}
                            for action in actions),
                    f"{platform}: invalid Pi-only installation plan")
            require(any(
                action.get("action") == "install"
                and action.get("alias") == source["manifest_name"]
                and action.get("revision") == source["revision"]
                and action.get("package_digest") == source["tree_digest"]
                for action in actions),
                f"{platform}: planned root identity missing")
            planned += 1
        else:
            # Source-planning refusals are never positive signed eligibility.
            require(source["distribution"] == MARKETING_KIT and status == "refused",
                    f"{platform}: unexpected eligibility failure")
            require(type(case.get("exit_code")) is int and case["exit_code"] != 0
                    and "planned_actions" not in case,
                    f"{platform}: refusal lacks a real failed CLI exit")
            refused += 1
    require(len(seen) == len(expected), f"{platform}: incomplete evidence")
    eligible = sum(source["distribution_status"] == "active" for source in sources) * 2
    require(planned + refused == eligible and refused in {0, 2},
            f"{platform}: invalid eligibility totals")
    return planned, refused


def proposed_source(source: dict, sources: list[dict], reviews: dict) -> dict:
    """Add reviewed Pi targets only to active policies in an in-memory copy."""
    require(isinstance(reviews, dict) and set(reviews) == {"schema_version", "source_commit", "reviews"}
            and reviews["schema_version"] == 1 and isinstance(reviews["reviews"], list),
            "review document contract is invalid")
    source_map = {(item["distribution"], item["release_sequence"]): item
                  for item in sources if item["distribution_status"] == "active"}
    review_map: dict[tuple[str, int], dict] = {}
    for record in reviews["reviews"]:
        require(isinstance(record, dict) and set(record) == REVIEW_FIELDS,
                "Pi transport/auth review has missing or extra fields")
        key = (record["distribution"], record["release_sequence"])
        require(key in source_map and key not in review_map,
                "unqualified or duplicate Pi target review")
        reviewed = source_map[key]
        require(record["tree_digest"] == reviewed["tree_digest"]
                and record["transport"] in TRANSPORTS
                and record["authentication"] in AUTHENTICATION
                and isinstance(record["evidence_url"], str)
                and record["evidence_url"].startswith("https://")
                and len(record["evidence_url"]) > len("https://"),
                "Pi review is not pinned to the exact source and public evidence")
        require((record["transport"] == "skills") == (reviewed["components"] == ["skills"]),
                "Pi component/transport classification mismatches reviewed source")
        review_map[key] = record
    require(set(review_map) == set(source_map), "all active Pi targets require explicit reviews")

    result = copy.deepcopy(source)
    for distribution in result["distributions"]:
        if distribution["status"] != "active":
            continue
        for policy in distribution["release_policies"]:
            key = (distribution["id"], policy["release_sequence"])
            if policy["status"] != "active":
                continue
            require(key in review_map and not any(t["client"] == "pi" for t in policy["targets"]),
                    "modern candidate overlaps a legacy Pi policy")
            policy["targets"].append({
                "client": "pi", "scopes": ["user"], "delivery": "managed",
                "authentication": review_map[key]["authentication"],
            })
            version = tuple(int(part) for part in policy["minimum_installer_version"].split("."))
            require(len(version) == 3, "invalid installer version")
            if version < (0, 1, 102):
                policy["minimum_installer_version"] = "0.1.102"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--report", required=True, action="append", help="linux=PATH, macos=PATH or windows=PATH")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(SHA.fullmatch(args.source_head) is not None, "source HEAD must be a full SHA")
    require_exact_checkout(args.source_head)
    require(not args.output.resolve().is_relative_to(ROOT.resolve()),
            "unsigned candidate must stay outside the repository and publication tree")

    source_path = ROOT / "registry/directory.json"
    original = source_path.read_bytes()
    sources = active_sources(args.source_head)
    reports = {}
    for value in args.report:
        label, sep, name = value.partition("=")
        require(sep and label in PLATFORMS and label not in reports, "duplicate or invalid OS report")
        reports[label] = json.loads(Path(name).read_text(encoding="utf-8"))
    require(set(reports) == PLATFORMS, "all three independent OS reports required")
    counts = {platform: validate_platform_report(data, platform, args.source_head, sources)
              for platform, data in reports.items()}
    require(len(set(counts.values())) == 1, "cross-OS outcomes differ")

    reviews = json.loads(args.review.read_text(encoding="utf-8"))
    require(reviews.get("source_commit") == args.source_head, "review source HEAD differs")
    candidate = proposed_source(json.loads(original), sources, reviews)
    # The ordinary v1 validator also enforces canonical client order, signed
    # source constraints and positive upstream materialization evidence.
    # Never emit an apparently ready modern feed when those checks fail.
    from build_registry import validate_directory
    validate_directory(candidate, verify_packages=False)
    require(source_path.read_bytes() == original, "legacy Directory source changed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    require(not args.output.exists(), "refusing to overwrite candidate")
    args.output.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"UNSIGNED modern v1 candidate only: OS coverage={counts}; "
          "no Ed25519 signature, approval, feed or 72/72 signed eligibility")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, RuntimeError) as error:
        print(f"Pi modern candidate refused: {error}", file=sys.stderr)
        sys.exit(1)
