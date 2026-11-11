#!/usr/bin/env python3
"""Real, credential-free Pi materialization for pinned catalog sources.

This is direct-source --no-save native installation evidence, NOT signed v1
entitlement, saved dependency closure, provider authentication, or tool runtime.
Do not use its PASS count to turn the signed 70/72 planner into 72/72.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone

from directory_publication import read_json
from pi_catalog_inventory_e2e import (
    SHA, active_sources, require, require_exact_checkout,
    require_published_cli_version, seed_verified_cli_cache,
)
from pi_direct_source_e2e import run_case

PLATFORMS = {"ubuntu-24.04": "Linux", "macos-15": "macOS", "windows-2025": "Windows"}
SCOPES = ("user", "project")
SHARDS = 3
KIND = "pi-pinned-source-native-materialization"
SOURCE = re.compile(r"^github:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([a-f0-9]{40})//([A-Za-z0-9_./-]+)$")


def case_tuple(item: dict, index: int) -> tuple:
    """Derive native assertions only from the immutable reviewed Directory source."""
    match = SOURCE.fullmatch(item["source"])
    require(match is not None, "unqualified remote Pi materialization source")
    repo, revision, path = match.groups()
    require(revision == item["revision"] and ".." not in Path(path).parts
            and not path.startswith("/") and bool(item["manifest_name"]),
            "source identity or path is not pinned")
    components = frozenset(item["components"])
    require(components in {frozenset({"mcp"}), frozenset({"skills"}),
                           frozenset({"mcp", "skills"})},
            "unqualified component kind for Pi")
    kind = ("mixed" if len(components) == 2 else
            "skill" if "skills" in components else "mcp")
    return (f"catalog-{index:02d}", item["manifest_name"], path, revision, kind, repo)


def source_identity(item: dict) -> dict:
    return {key: item[key] for key in (
        "distribution", "distribution_status", "release_sequence", "components",
        "manifest_name", "revision", "tree_digest", "source"
    )}


def selected_sources(sources: list[dict], shard: int, shards: int) -> list[tuple[int, dict]]:
    require(shards == SHARDS and 0 <= shard < shards, "invalid catalog shard")
    return [(index, item) for index, item in enumerate(sources)
            if index % shards == shard]


def verify_report(report: dict, sources: list[dict], head: str,
                  platform: str, shard: int, shards: int) -> int:
    """Fail closed on omitted, repeated, unpinned or non-materialized cases."""
    require(isinstance(report, dict) and report.get("schema_version") == 1
            and type(report.get("shard")) is int and report["shard"] == shard
            and type(report.get("shards")) is int and report["shards"] == shards
            and report.get("kind") == KIND and report.get("source_head") == head
            and report.get("runner_os") == PLATFORMS[platform]
            and report.get("uap_cli") == "public npm 0.1.102"
            and report.get("native_pi") == "real npm @earendil-works/pi-coding-agent@1.5.0"
            and report.get("signed_pi_policy_published") is False
            and report.get("saved_dependency_eligibility") is False
            and report.get("runtime_claims") is False
            and report.get("account_authentication") == "not_tested"
            and report.get("scopes") == list(SCOPES)
            and type(report.get("source_count")) is int
            and report["source_count"] == len(sources),
            f"{platform}/{shard}: report is not exact-head native Pi evidence")
    cases = report.get("results")
    selected = selected_sources(sources, shard, shards)
    require(isinstance(cases, list) and len(cases) == len(selected) * len(SCOPES),
            f"{platform}/{shard}: incomplete materialization report")
    expected = {
        (item["distribution"], item["release_sequence"], scope): item
        for _, item in selected for scope in SCOPES
    }
    seen: set[tuple[str, int, str]] = set()
    passed = 0
    for case in cases:
        require(isinstance(case, dict) and type(case.get("release_sequence")) is int,
                f"{platform}/{shard}: invalid case")
        key = (case.get("distribution"), case["release_sequence"], case.get("scope"))
        require(key in expected and key not in seen,
                f"{platform}/{shard}: duplicate or foreign case")
        seen.add(key)
        item = expected[key]
        require(all(case.get(field) == value for field, value
                    in source_identity(item).items()),
                f"{platform}/{shard}: wrong immutable source")
        if item["distribution_status"] != "active":
            require(case.get("status") == "not_eligible"
                    and "operations" not in case,
                    f"{platform}/{shard}: suspended package got an installation")
            continue
        require(case.get("status") == "passed"
                and case.get("verification") == "native-files-and-receipt-only"
                and case.get("runtime_claims") is False
                and case.get("account_oauth_qualified") is False
                and isinstance(case.get("operations"), list)
                and len(case["operations"]) >= 8
                and any(op.get("argv", [None, None])[1] == "add"
                        and op.get("exit") == 0 for op in case["operations"]
                        if isinstance(op, dict) and isinstance(op.get("argv"), list)
                        and len(op["argv"]) >= 2)
                and any(op.get("argv", [None, None])[1] == "remove"
                        and op.get("exit") == 0 for op in case["operations"]
                        if isinstance(op, dict) and isinstance(op.get("argv"), list)
                        and len(op["argv"]) >= 2),
                f"{platform}/{shard}: real native Pi lifecycle incomplete: {key}")
        passed += 1
    require(len(seen) == len(expected),
            f"{platform}/{shard}: missing materialization cases")
    return passed


def verify_all(paths: list[Path], sources: list[dict], head: str) -> None:
    require(len(paths) == len(PLATFORMS) * SHARDS,
            "required one original report for every OS and shard")
    remaining = {(platform, shard) for platform in PLATFORMS
                 for shard in range(SHARDS)}
    counts = {platform: 0 for platform in PLATFORMS}
    for path in paths:
        report = read_json(path)
        require(isinstance(report, dict), "materialization artifact must be JSON object")
        runner = report.get("runner_os")
        platform = next((key for key, value in PLATFORMS.items() if value == runner), None)
        shard = report.get("shard")
        require(platform is not None and type(shard) is int
                and (platform, shard) in remaining,
                "duplicate or unrecognized original OS/shard materialization artifact")
        counts[platform] += verify_report(
            report, sources, head, platform, shard, SHARDS)
        remaining.remove((platform, shard))
    require(not remaining, "OS/shard materialization evidence missing")
    expected = sum(item["distribution_status"] == "active" for item in sources) * len(SCOPES)
    require(all(count == expected for count in counts.values()),
            f"incomplete positive native Pi source materialization: {counts}, expected {expected}")
    print(f"Native direct-source materialization: {counts} across three OS; "
          "signed saved dependency authority and account authentication NOT tested")


def run_shard(args: argparse.Namespace, sources: list[dict]) -> int:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY")
            == "777genius/universal-agent-plugins-registry"
            and os.environ.get("RUNNER_TEMP")
            and os.environ.get("RUNNER_OS") == PLATFORMS[args.platform],
            "only an identified disposable GitHub Actions runner may run Pi packages")
    binary = shutil.which(args.cli)
    require(binary is not None and Path(binary).is_file(), "released CLI is missing")
    cli = str(Path(binary).resolve(strict=True))
    require_published_cli_version(cli)
    require(not args.report.exists(), "refusing to overwrite a native Pi evidence report")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1, "kind": KIND, "source_head": args.source_head,
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "uap_cli": "public npm 0.1.102",
        "native_pi": "real npm @earendil-works/pi-coding-agent@1.5.0",
        "runner_os": PLATFORMS[args.platform], "shard": args.shard,
        "shards": SHARDS, "source_count": len(sources), "scopes": list(SCOPES),
        "signed_pi_policy_published": False, "saved_dependency_eligibility": False,
        "runtime_claims": False, "account_authentication": "not_tested",
        "results": [],
    }
    with tempfile.TemporaryDirectory(
        prefix="pi-materialization-", dir=os.environ["RUNNER_TEMP"]
    ) as temporary:
        scratch = Path(temporary)
        binary_seed = seed_verified_cli_cache(cli, scratch)
        for index, item in selected_sources(sources, args.shard, SHARDS):
            for scope in SCOPES:
                identity = source_identity(item)
                if item["distribution_status"] == "active":
                    case = case_tuple(item, index)
                    outcome = run_case(cli, args.source_head, scratch, case,
                                       scope, binary_seed)
                    require(outcome.get("scope") == scope
                            and outcome.get("source") == item["source"],
                            "Pi lifecycle executed a different source or scope")
                    result = {**identity, **outcome}
                else:
                    result = {**identity, "scope": scope, "status": "not_eligible"}
                report["results"].append(result)
                # Persist even failed outcomes, so CI failures remain auditable.
                args.report.write_text(json.dumps(report, indent=2) + "\n",
                                       encoding="utf-8")
                print(f"{item['distribution']} / {scope}: {result['status']}",
                      flush=True)
    verify_report(report, sources, args.source_head, args.platform,
                  args.shard, SHARDS)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--platform", choices=tuple(PLATFORMS))
    parser.add_argument("--shard", type=int)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--verify-report", type=Path, action="append")
    parser.add_argument("--cli", default="agentplugins")
    args = parser.parse_args()
    require(SHA.fullmatch(args.source_head) is not None, "source HEAD must be full SHA")
    require_exact_checkout(args.source_head)
    sources = active_sources(args.source_head)
    if args.verify_report:
        require(args.shard is None and args.platform is None and args.report is None,
                "verification cannot execute native packages")
        verify_all(args.verify_report, sources, args.source_head)
        return 0
    require(args.platform is not None and args.shard is not None
            and args.report is not None, "materialization requires OS/shard/report")
    return run_shard(args, sources)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, TypeError) as error:
        print(f"Pi native catalog materialization FAILED: {error}", file=sys.stderr)
        sys.exit(1)
