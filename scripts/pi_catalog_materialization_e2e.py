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
# This root has mandatory signed saved dependencies. The immutable public CLI
# must refuse a direct --no-save install; it needs a distinct managed signed E2E.
MANAGED_ROOT = "777genius/marketing-kit"
UPSTREAM_REVIEW_IDS = frozenset({"github/github", "upstash/context7"})
MANAGED_NO_SAVE_DIAGNOSTIC = (
    "package marketing-kit declares UAP requirements; use a managed saved "
    "add/install workflow instead of --no-save or local/manual installation"
)
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
        "manifest_name", "revision", "tree_digest", "manifest_digest", "source"
    )}


def pinned_add_argv(argv: object, item: dict, scope: str) -> bool:
    """Validate the exact immutable --no-save Pi request even when it is denied."""
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
        return False
    if len(argv) < 10 or not argv[0] or argv[1:3] != ["add", item["source"]]:
        return False
    expected = ["--no-save", "--target", "pi", "--scope", scope, "--format", "json"]
    if argv[3:10] != expected:
        return False
    if scope == "user":
        return len(argv) == 10
    return (scope == "project" and len(argv) == 12
            and argv[10] == "--project-root" and bool(argv[11])
            and not argv[11].startswith("-"))


def require_managed_refusal(result: dict, item: dict, scope: str) -> None:
    """Count only a real refusal of this pinned Pi --no-save request."""
    operations = result.get("operations")
    require(result.get("status") == "failed"
            and isinstance(result.get("error"), str)
            and MANAGED_NO_SAVE_DIAGNOSTIC in result["error"]
            and isinstance(operations, list) and len(operations) == 1
            and isinstance(operations[0], dict)
            and pinned_add_argv(operations[0].get("argv"), item, scope)
            and type(operations[0].get("exit")) is int
            and operations[0]["exit"] != 0
            and isinstance(operations[0].get("error_tail"), str)
            and MANAGED_NO_SAVE_DIAGNOSTIC in operations[0]["error_tail"],
            "Marketing Kit direct-source denial was not the expected managed-dependency gate")


def real_pinned_add(op: dict, item: dict, scope: str) -> bool:
    """Require the pinned Pi --no-save request and its successful exit code."""
    return (isinstance(op, dict) and type(op.get("exit")) is int
            and op["exit"] == 0 and pinned_add_argv(op.get("argv"), item, scope))



def real_pinned_lifecycle(operations: object, identity: object, item: dict,
                          scope: str) -> bool:
    """Require the complete ordered native journey in each positive E2E receipt."""
    if not isinstance(operations, list) or len(operations) != 10:
        return False
    if not all(isinstance(op, dict) and isinstance(op.get("argv"), list)
               and all(isinstance(arg, str) for arg in op["argv"])
               and len(op["argv"]) >= 2 for op in operations):
        return False
    commands = [op["argv"] for op in operations]
    binary = commands[0][0]
    if not binary or not real_pinned_add(operations[0], item, scope) or (
        not real_pinned_add(operations[2], item, scope)
    ):
        return False
    flags = ["--target", "pi", "--scope", scope, "--format", "json"]
    if scope == "project":
        flags.extend(commands[0][10:])
    elif scope != "user":
        return False
    # This identity comes from the real public list and was cross-checked
    # against the persisted scoped Pi binding before the runner emitted it.
    # Do not allow all four maintenance verbs to select the same foreign ID.
    fields = {"installation_id", "name", "source", "client_id", "scope",
              "resolved_revision", "tree_digest", "manifest_digest"}
    if not isinstance(identity, dict) or set(identity) != fields:
        return False
    install_id = identity["installation_id"]
    if (not isinstance(install_id, str) or not 0 < len(install_id) <= 256
            or install_id.startswith("-")
            or identity["name"] != item["manifest_name"]
            or identity["source"] != item["source"]
            or identity["client_id"] != "pi" or identity["scope"] != scope
            or identity["resolved_revision"] != item["revision"]
            or identity["tree_digest"] != item["tree_digest"]
            or identity["manifest_digest"] != item["manifest_digest"]
            or not isinstance(identity["manifest_digest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", identity["manifest_digest"]) is None):
        return False
    expected = [
        [binary, "add", item["source"], "--no-save", *flags],
        [binary, "list", *flags],
        [binary, "add", item["source"], "--no-save", *flags],
        [binary, "list", *flags],
        [binary, "info", install_id, *flags],
        [binary, "update", install_id, *flags],
        [binary, "repair", install_id, *flags],
        [binary, "list", *flags],
        [binary, "remove", install_id, *flags],
        [binary, "list", *flags],
    ]
    if commands != expected:
        return False
    for index, op in enumerate(operations):
        if type(op.get("exit")) is not int:
            return False
        if index == 5:
            if op["exit"] == 0 or not isinstance(op.get("error_tail"), str) or (
                "direct full-SHA installations require explicit switch"
                not in op["error_tail"]
            ):
                return False
        elif op["exit"] != 0:
            return False
    return True


def selected_sources(sources: list[dict], shard: int, shards: int) -> list[tuple[int, dict]]:
    require(shards == SHARDS and 0 <= shard < shards, "invalid catalog shard")
    return [(index, item) for index, item in enumerate(sources)
            if index % shards == shard]


def github_run_identity() -> tuple[int, int]:
    """Only derive provenance from the actual Actions run, never a report."""
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY")
            == "777genius/universal-agent-plugins-registry",
            "review packet requires a trusted GitHub Actions run")
    values = (os.environ.get("GITHUB_RUN_ID", ""),
              os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    require(all(value.isascii() and value.isdecimal() and int(value) > 0
                for value in values),
            "missing valid GitHub Actions run id/attempt")
    return int(values[0]), int(values[1])


def verify_report(report: dict, sources: list[dict], head: str,
                  platform: str, shard: int, shards: int) -> int:
    """Fail closed on omitted, repeated, unpinned or non-materialized cases."""
    require(isinstance(report, dict) and type(report.get("schema_version")) is int
            and report["schema_version"] == 1
            and type(report.get("shard")) is int and report["shard"] == shard
            and type(report.get("shards")) is int and report["shards"] == shards
            and type(report.get("github_run_id")) is int
            and report["github_run_id"] > 0
            and type(report.get("github_run_attempt")) is int
            and report["github_run_attempt"] > 0
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
        if item["distribution"] == MANAGED_ROOT:
            require(case.get("status") == "requires_managed_saved_install",
                    f"{platform}/{shard}: Marketing Kit was misreported as native evidence")
            require_managed_refusal({**case, "status": "failed"}, item, key[2])
            require(case.get("verification") is None
                    and case.get("verified_public_installation") is None
                    and case.get("runtime_claims") is None,
                    f"{platform}/{shard}: a denied install gained positive native evidence")
            continue
        require(case.get("status") == "passed"
                and case.get("verification") == "native-files-and-receipt-only"
                and case.get("runtime_claims") is False
                and case.get("account_oauth_qualified") is False
                and real_pinned_lifecycle(
                    case.get("operations"), case.get("verified_public_installation"),
                    item, key[2]),
                f"{platform}/{shard}: real native Pi lifecycle incomplete: {key}")
        passed += 1
    require(len(seen) == len(expected),
            f"{platform}/{shard}: missing materialization cases")
    return passed


def verify_all(paths: list[Path], sources: list[dict], head: str) -> list[dict]:
    require(len(paths) == len(PLATFORMS) * SHARDS,
            "required one original report for every OS and shard")
    remaining = {(platform, shard) for platform in PLATFORMS
                 for shard in range(SHARDS)}
    counts = {platform: 0 for platform in PLATFORMS}
    upstream_cases: list[dict] = []
    original_run: tuple[int, int] | None = None
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
        provenance = (report["github_run_id"], report["github_run_attempt"])
        require(original_run is None or original_run == provenance,
                "original native reports come from different workflow runs/attempts")
        original_run = provenance
        # Only export validated public immutable identities. Never serialize
        # executable commands, credentials, installation IDs or native paths.
        for case in report["results"]:
            if case["distribution"] not in UPSTREAM_REVIEW_IDS:
                continue
            require(case["status"] == "passed"
                    and case["verification"] == "native-files-and-receipt-only",
                    "upstream source has no positive native Pi materialization")
            upstream_cases.append({
                "distribution": case["distribution"],
                "release_sequence": case["release_sequence"],
                "runner_os": report["runner_os"],
                "scope": case["scope"],
                "source": case["source"],
                "revision": case["revision"],
                "tree_digest": case["tree_digest"],
                "manifest_digest": case["manifest_digest"],
                "original_artifact": f"pi-materialization-{platform}-{shard}",
                "original_run_id": report["github_run_id"],
                "original_run_attempt": report["github_run_attempt"],
                "result": "direct-source-no-save-native-lifecycle",
            })
        remaining.remove((platform, shard))
    require(not remaining, "OS/shard materialization evidence missing")
    expected = sum(
        item["distribution_status"] == "active"
        and item["distribution"] != MANAGED_ROOT for item in sources
    ) * len(SCOPES)
    require(all(count == expected for count in counts.values()),
            f"incomplete positive no-save Pi materialization: {counts}, expected {expected}")
    require(any(item["distribution_status"] == "active"
                and item["distribution"] == MANAGED_ROOT for item in sources),
            "mandatory managed-only root absent from source inventory")
    print(f"Real pinned --no-save Pi lifecycle: {counts} across three OS; "
          "Marketing Kit user/project explicitly refused by managed-dependency gate "
          "(NOT materialized; requires separate signed saved E2E); "
          "72/72 signed eligibility and account authentication NOT tested")
    return upstream_cases


def build_upstream_review_pack(paths: list[Path], sources: list[dict],
                               head: str, expected_run: tuple[int, int]) -> dict:
    """Aggregate upstream Pi native receipts for review, NOT signing authority."""
    reviewed = {item["distribution"] for item in sources
                if item["distribution"] in UPSTREAM_REVIEW_IDS
                and item["distribution_status"] == "active"}
    require(reviewed == UPSTREAM_REVIEW_IDS,
            "upstream review requires both active immutable source releases")
    require(type(expected_run) is tuple and len(expected_run) == 2
            and all(type(value) is int and value > 0 for value in expected_run),
            "invalid trusted workflow provenance")
    cases = verify_all(paths, sources, head)
    require(all((case["original_run_id"], case["original_run_attempt"])
                == expected_run for case in cases),
            "native receipts do not belong to this GitHub Actions run/attempt")
    expected = {(runner, distribution, scope)
                for runner in PLATFORMS.values()
                for distribution in UPSTREAM_REVIEW_IDS
                for scope in SCOPES}
    observed = {(case["runner_os"], case["distribution"], case["scope"])
                for case in cases}
    require(len(cases) == len(expected) and observed == expected,
            "incomplete or repeated upstream native Pi review receipts")
    return {
        "schema_version": 1, "kind": "pi-upstream-native-review-only",
        "source_head": head, "published_cli": "0.1.102", "native_pi": "1.5.0",
        "original_workflow_run": {"id": expected_run[0], "attempt": expected_run[1]},
        "unsigned": True, "production_published": False,
        "signed_managed_eligibility": False,
        "managed_saved_installation": False, "oauth_or_tool_call_qualified": False,
        "cases": sorted(cases, key=lambda case: (
            case["runner_os"], case["distribution"], case["scope"])),
    }


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
        "github_run_id": github_run_identity()[0],
        "github_run_attempt": github_run_identity()[1],
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
                    if item["distribution"] == MANAGED_ROOT:
                        require_managed_refusal(outcome, item, scope)
                        # This is a verified refusal, NOT a positive install.
                        outcome["status"] = "requires_managed_saved_install"
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
    parser.add_argument("--upstream-review-output", type=Path)
    parser.add_argument("--cli", default="agentplugins")
    args = parser.parse_args()
    require(SHA.fullmatch(args.source_head) is not None, "source HEAD must be full SHA")
    require_exact_checkout(args.source_head)
    sources = active_sources(args.source_head)
    if args.verify_report:
        require(args.shard is None and args.platform is None and args.report is None,
                "verification cannot execute native packages")
        if args.upstream_review_output is not None:
            pack = build_upstream_review_pack(
                args.verify_report, sources, args.source_head,
                github_run_identity())
            with args.upstream_review_output.open("x", encoding="utf-8") as output:
                json.dump(pack, output, indent=2)
                output.write("\n")
        else:
            verify_all(args.verify_report, sources, args.source_head)
        return 0
    require(args.upstream_review_output is None,
            "upstream review output requires nine independently verified reports")
    require(args.platform is not None and args.shard is not None
            and args.report is not None, "materialization requires OS/shard/report")
    return run_shard(args, sources)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, TypeError) as error:
        print(f"Pi native catalog materialization FAILED: {error}", file=sys.stderr)
        sys.exit(1)
