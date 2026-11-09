#!/usr/bin/env python3
"""Exact-source Pi planning coverage for every active reviewed Directory release.

This is installer/package eligibility evidence only, not signed target authority,
OAuth, native tool execution, or an account connection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def native_files(profile: Path) -> list[tuple[str, str]]:
    return sorted(
        (file.relative_to(profile).as_posix(), hashlib.sha256(file.read_bytes()).hexdigest())
        for file in profile.rglob("*")
        if file.is_file() and not file.is_symlink()
    )


def active_sources(head: str) -> list[dict]:
    directory = json.loads((ROOT / "registry/directory.json").read_text(encoding="utf-8"))
    sources = []
    for distribution in directory["distributions"]:
        # A release policy can remain active while its distribution is suspended.
        # Inventory it for completeness, but never qualify it for installation.
        releases = {release["sequence"]: release for release in distribution["releases"]}
        for policy in distribution["release_policies"]:
            if policy["status"] != "active":
                continue
            release = releases[policy["release_sequence"]]
            source = release["package_source"]
            repo = source["repository"]
            revision = source["revision"] or head
            require(REPOSITORY.fullmatch(repo) is not None and SHA.fullmatch(revision) is not None,
                    "reviewed package source must be exact GitHub revision")
            require(source["revision"] is not None or
                    repo == "777genius/universal-agent-plugins-registry",
                    "null package revision must be in this checkout")
            require("pi" not in [target["client"] for target in policy["targets"]],
                    "Pi policy was published: update the old-reader migration proof first")
            require(set(release["components"]) <= {"skills", "mcp", "extensions"},
                    "unqualified portable component in active release")
            sources.append({
                "distribution": distribution["id"],
                "distribution_status": distribution["status"],
                "release_sequence": release["sequence"],
                "components": release["components"],
                "source": f"github:{repo}@{revision}//{source['path']}",
            })
    require(bool(sources), "no active release policies were inventoried")
    return sources


def run_case(cli: str, item: dict, number: int, scratch: Path, scope: str) -> dict:
    require(scope in {"user", "project"}, "unsupported scope")
    root = scratch / f"source-{number:02d}-{scope}"
    home = root / "home"
    profile = home / ".pi" / "agent"
    project = root / "project"
    for path in (profile, project, root / "data", root / "config", root / "cache"):
        path.mkdir(parents=True, exist_ok=True)
        require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
                "disposable profile path is redirected")
    marker = profile / "foreign-neighbor.txt"
    marker.write_text("unowned Pi profile\n", encoding="utf-8")
    project_marker = project / "foreign-neighbor.txt"
    project_marker.write_text("unowned Pi project\n", encoding="utf-8")
    env = dict(os.environ)
    for key in list(env):
        if key in {"GH_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN", "OPENAI_API_KEY",
                   "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"}:
            env.pop(key, None)
    env.update({
        "HOME": str(home), "USERPROFILE": str(home), "PI_CODING_AGENT_DIR": str(profile),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "APPDATA": str(root / "config"), "LOCALAPPDATA": str(root / "data"),
        "GIT_TERMINAL_PROMPT": "0", "CI": "true",
    })
    if scope == "project":
        subprocess.run(["git", "init", "-q"], cwd=project, env=env,
                       capture_output=True, timeout=20, check=True)
    baseline = native_files(profile)
    project_baseline = native_files(project)
    result = {key: item[key] for key in ("distribution", "distribution_status", "release_sequence", "components", "source")}
    result["scope"] = scope
    result["status"] = "unverified"
    try:
        argv = [cli, "add", item["source"], "--target", "pi", "--scope", scope,
                "--dry-run", "--format", "json"]
        if scope == "project":
            argv.extend(["--project-root", str(project)])
        proc = subprocess.run(argv, cwd=project, env=env,
                              text=True, encoding="utf-8", errors="replace",
                              capture_output=True, timeout=240, check=False)
        result["exit_code"] = proc.returncode
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            require(isinstance(data, dict) and data.get("command") == "add" and
                    data.get("result") == "success" and
                    isinstance(data.get("data"), dict),
                    "successful CLI dry-run must return a structured add envelope")
            result["status"] = "planned"
        else:
            result["status"] = "refused"
            result["diagnostic"] = (proc.stderr or proc.stdout)[-600:]
        require(native_files(profile) == baseline and
                marker.read_text(encoding="utf-8") == "unowned Pi profile\n",
                "dry-run changed native Pi profile")
        require(native_files(project) == project_baseline and
                project_marker.read_text(encoding="utf-8") == "unowned Pi project\n",
                "dry-run changed project files or Pi native state")
        require(not (project / "uap.toml").exists() and
                not (project / "uap.lock").exists(),
                "dry-run changed portable project dependency state")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
        result["status"] = "failed"
        result["diagnostic"] = str(error)[-600:]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--cli", default="agentplugins")
    args = parser.parse_args()
    require(SHA.fullmatch(args.source_head) is not None, "source head must be exact SHA")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_REPOSITORY") == "777genius/universal-agent-plugins-registry"
            and os.environ.get("RUNNER_TEMP"), "requires a disposable GitHub Actions runner")
    binary = shutil.which(args.cli)
    require(binary is not None and Path(binary).is_file(), "published CLI not installed")
    sources = active_sources(args.source_head)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    evidence = {
        "schema_version": 1, "kind": "pi-direct-source-planning",
        "source_commit": args.source_head, "cli_version": "0.1.102",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "signed_pi_policy_published": False, "runtime_claims": False,
        "account_authentication": "not_tested",
        "scopes": ["user", "project"], "active_policy_count": len(sources),
        "results": [],
    }
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"],
                                     prefix="pi-catalog-planning-") as temp:
        for number, source in enumerate(sources):
            for scope in ("user", "project"):
                if source["distribution_status"] != "active":
                    result = {**source, "scope": scope, "status": "not_eligible",
                              "diagnostic": "suspended distribution; active policy is not install authority"}
                else:
                    result = run_case(str(Path(binary).resolve()), source, number, Path(temp), scope)
                evidence["results"].append(result)
                args.report.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
                print(f"{number + 1}/{len(sources)} {source['distribution']}/{scope}: {result['status']}",
                      flush=True)
    eligible = sum(x["distribution_status"] == "active" for x in sources) * 2
    planned = sum(x["status"] == "planned" for x in evidence["results"])
    excluded = sum(x["status"] == "not_eligible" for x in evidence["results"])
    print(f"Pi exact-source planning: {planned}/{eligible} eligible scope plans, "
          f"{excluded} suspended scope exclusions across {len(sources)} active policies")
    return 0 if planned == eligible and excluded == 2 * len(sources) - eligible else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Pi catalog E2E setup error: {exc}", file=sys.stderr)
        sys.exit(1)
