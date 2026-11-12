#!/usr/bin/env python3
"""Prepare an UNSIGNED, isolated Directory v1 Pi source candidate for review.

This is not a signing, approval, feed promotion, or evidence of signed Pi installs.
The existing registry/directory.json and historical signed feed stay untouched.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import os
import stat
import tempfile
import json
from pathlib import Path
import re
import subprocess
import sys

from directory_publication import PublicationError, read_json
from pi_catalog_inventory_e2e import ROOT, SHA, active_sources, require, require_exact_checkout

REVIEW_FIELDS = {"distribution", "release_sequence", "tree_digest", "transport",
                 "authentication", "evidence_url"}
TRANSPORTS = {"stdio", "streamable-http", "skills"}
AUTHENTICATION = {"required", "not_required", "unknown"}
RUNNER_OS = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}
PLATFORMS = set(RUNNER_OS)
SCOPES = ("user", "project")
MARKETING_KIT = "777genius/marketing-kit"
# Exact published CLI 0.1.102 stderr confirmed on Linux, macOS and Windows.
# Any different nonzero exit is an unexpected failure, not the known policy block.
KNOWN_MARKETING_REFUSAL = (
    "agentplugins: dependency conflict for directory:777genius/hubspot-crm: "
    "marketing-kit version 0.1.0"
)


def read_evidence_object(path: Path) -> dict:
    """Reject ambiguous JSON before interpreting source, reviews or CI reports."""
    value = read_json(path)
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


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
            require(isinstance(case.get("diagnostic"), str)
                    and case["diagnostic"].strip() == KNOWN_MARKETING_REFUSAL,
                    f"{platform}: refusal is not the verified signed HubSpot policy conflict")
            refused += 1
    require(len(seen) == len(expected), f"{platform}: incomplete evidence")
    eligible = sum(source["distribution_status"] == "active" for source in sources) * 2
    require(planned + refused == eligible and refused in {0, 2},
            f"{platform}: invalid eligibility totals")
    return planned, refused


def require_complete_source_eligibility(counts: dict[str, tuple[int, int]], expected_eligible: int) -> None:
    """Block staging when any OS still refuses a real saved dependency plan."""
    # This helper is also callable outside main(), so independently require
    # all three OS with identical positive counts; an empty/partial report or
    # bool masquerading as an integer must never qualify a candidate.
    require(type(expected_eligible) is int and expected_eligible > 0
            and expected_eligible % len(SCOPES) == 0
            and set(counts) == PLATFORMS and len(set(counts.values())) == 1
            and all(type(planned) is int and planned > 0
                    and type(refused) is int and refused == 0
                    and planned + refused == expected_eligible
                    for planned, refused in counts.values()),
            "modern Pi candidate requires complete identical 3-OS source plans "
            "with zero refused saved dependency plans")


def require_unsigned_preproduction_eligibility(counts: dict[str, tuple[int, int]], expected_eligible: int) -> None:
    """Only permit a REVIEW candidate from complete, consistently classified 3-OS plans.

    A historically Pi-free signed feed may refuse Marketing Kit's HubSpot child.
    That genuine refusal is never a successful install or permission to sign.
    """
    require(type(expected_eligible) is int and expected_eligible > 0
            and expected_eligible % len(SCOPES) == 0
            and set(counts) == PLATFORMS and len(set(counts.values())) == 1
            and all(type(planned) is int and planned > 0
                    and type(refused) is int and refused in {0, 2}
                    and planned + refused == expected_eligible
                    for planned, refused in counts.values()),
            "preproduction requires complete consistent 3-OS source plans with only known refusals")


def proposed_source(source: dict, sources: list[dict], reviews: dict) -> dict:
    """Add reviewed Pi targets to a separate, unsigned modern-feed proposal.

    Keep v1 signed grants User-scoped on both feeds. Released CLI 0.1.102
    selects a signed v1 User source for explicit local Project placement,
    while independently checking the native Project client policy.
    """
    require(isinstance(reviews, dict) and set(reviews) == {"schema_version", "source_commit", "reviews"}
            and type(reviews["schema_version"]) is int and reviews["schema_version"] == 1
            and isinstance(reviews["reviews"], list),
            "review document contract is invalid")
    source_map = {(item["distribution"], item["release_sequence"]): item
                  for item in sources if item["distribution_status"] == "active"}
    review_map: dict[tuple[str, int], dict] = {}
    for record in reviews["reviews"]:
        require(isinstance(record, dict) and set(record) == REVIEW_FIELDS,
                "Pi transport/auth review has missing or extra fields")
        require(type(record["release_sequence"]) is int,
                "Pi review release sequence must be an integer, never bool")
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
        # "unknown" is valid registry metadata but not reviewed Pi signing authority.
        require(record["authentication"] != "unknown",
                "Pi authentication is unresolved; do not propose a signed Pi target")
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
            # Project placement is independently qualified by the CLI's
            # native client policy, not by a fabricated v1 project grant.
            policy["targets"].append({
                "client": "pi", "scopes": ["user"], "delivery": "managed",
                "authentication": review_map[key]["authentication"],
            })
            version = tuple(int(part) for part in policy["minimum_installer_version"].split("."))
            require(len(version) == 3, "invalid installer version")
            if version < (0, 1, 102):
                policy["minimum_installer_version"] = "0.1.102"
    return result


def require_committed_directory_source(source_head: str, actual: bytes) -> None:
    """Derive the unsigned candidate only from the committed v1 source bytes."""
    committed = subprocess.run(
        ["git", "show", f"{source_head}:registry/directory.json"],
        cwd=ROOT, capture_output=True, check=True, timeout=30,
    ).stdout
    require(actual == committed,
            "working Directory source differs from requested source HEAD")


def open_windows_exclusive_nofollow(path: Path):
    """Atomically create a Windows file without following a final symlink.

    Python's regular open("x") can follow a dangling NTFS symlink. CREATE_NEW
    plus FILE_FLAG_OPEN_REPARSE_POINT instead refuses the existing link itself.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        str(path), 0x40000000, 0, None, 1, 0x80 | 0x00200000, None,
    )  # GENERIC_WRITE, no sharing, CREATE_NEW, NORMAL | OPEN_REPARSE_POINT
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    except BaseException:
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle(handle)
        raise
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


def write_unsigned_candidate(path: Path, candidate: dict) -> None:
    """Create an unsigned review file exclusively in an isolated output directory.

    POSIX pins the verified private parent by directory descriptor: replacing
    its pathname with a symlink cannot redirect the final file creation.
    Windows is restricted to the current user's home/temporary output roots.
    This is local preproduction staging, never a signed publication path.
    """
    content = json.dumps(candidate, ensure_ascii=False, indent=2) + "\n"
    root = ROOT.resolve()
    require(not path.resolve().is_relative_to(root),
            "unsigned candidate must stay outside the repository")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.parent.is_symlink(),
            "unsigned candidate output parent must not be a symlink")
    parent = path.parent.resolve(strict=True)
    require(not parent.is_relative_to(root),
            "unsigned candidate output parent must stay outside the repository")

    if os.name == "posix":
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent_fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and (stat.S_IMODE(info.st_mode) & 0o077) == 0,
                    "unsigned candidate requires an owner-private output directory")
            current = os.stat(path.parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)
                    and not path.parent.resolve(strict=True).is_relative_to(root),
                    "unsigned candidate output parent changed during verification")
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                output.write(content)
        finally:
            os.close(parent_fd)
    else:
        # Windows has no portable Python dir_fd. Stay within the user's
        # private profile/temp tree, not an arbitrary shared or repo path.
        trusted = (Path.home().resolve(), Path(tempfile.gettempdir()).resolve())
        require(any(parent.is_relative_to(base) for base in trusted),
                "Windows unsigned candidate output must be in the user home/temp directory")
        with open_windows_exclusive_nofollow(path) as output:
            output.write(content)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-head", required=True)
    parser.add_argument(
        "--preproduction-only", action="store_true",
        help="prepare an UNSIGNED review candidate with known legacy Marketing Kit refusals; never sign-ready",
    )
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--report", required=True, action="append", help="linux=PATH, macos=PATH or windows=PATH")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    # The only supported inputs are historical direct-source *plans*. Even
    # 72 successful dry-runs are not saved-install receipts, so this tool can
    # never emit a sign-ready or production candidate from these reports.
    require(args.preproduction_only,
            "source plans are not managed saved-install receipts; "
            "use --preproduction-only for isolated unsigned review staging")
    require(SHA.fullmatch(args.source_head) is not None, "source HEAD must be a full SHA")
    require_exact_checkout(args.source_head)
    require(not args.output.resolve().is_relative_to(ROOT.resolve()),
            "unsigned candidate must stay outside the repository and publication tree")

    source_path = ROOT / "registry/directory.json"
    original = source_path.read_bytes()
    require_committed_directory_source(args.source_head, original)
    sources = active_sources(args.source_head)
    reports = {}
    for value in args.report:
        label, sep, name = value.partition("=")
        require(sep and label in PLATFORMS and label not in reports, "duplicate or invalid OS report")
        reports[label] = read_evidence_object(Path(name))
    require(set(reports) == PLATFORMS, "all three independent OS reports required")
    counts = {platform: validate_platform_report(data, platform, args.source_head, sources)
              for platform, data in reports.items()}
    expected_eligible = sum(source["distribution_status"] == "active" for source in sources) * len(SCOPES)
    require(len(set(counts.values())) == 1, "cross-OS outcomes differ")
    require_unsigned_preproduction_eligibility(counts, expected_eligible)

    reviews = read_evidence_object(args.review)
    require(reviews.get("source_commit") == args.source_head, "review source HEAD differs")
    candidate = proposed_source(read_evidence_object(source_path), sources, reviews)
    # The ordinary v1 validator also enforces canonical client order, signed
    # source constraints and positive upstream materialization evidence.
    # Never emit an apparently ready modern feed when those checks fail.
    from build_registry import validate_directory
    validate_directory(
        candidate, verify_packages=False,
        allow_unsigned_pi_review_only=True,
    )
    require(source_path.read_bytes() == original, "legacy Directory source changed")
    write_unsigned_candidate(args.output, candidate)
    print(f"PREPRODUCTION UNSIGNED REVIEW modern v1 candidate only: "
          f"OS source-plan coverage={counts}; "
          "not actual saved installs, not sign-ready, no Ed25519 signature, approval, "
          "production feed or 72/72 signed eligibility")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, RuntimeError, PublicationError) as error:
        print(f"Pi modern candidate refused: {error}", file=sys.stderr)
        sys.exit(1)
