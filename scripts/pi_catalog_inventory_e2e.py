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


def require_exact_checkout(source_head: str) -> None:
    """Refuse provenance reports when the script and package sources use different trees."""
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, timeout=15, check=True,
    )
    require(result.stdout.strip() == source_head,
            "actual checkout HEAD differs from requested source HEAD")


def require_published_cli_version(binary: str) -> None:
    """The evidence must come from the released CLI, not a silently substituted version."""
    result = subprocess.run(
        [binary, "version"], capture_output=True, text=True, timeout=15, check=True,
    )
    require(result.stdout.strip() == "agentplugins 0.1.102",
            "installed CLI is not the qualified public 0.1.102 release")



# Only carry native launcher/toolchain inputs into untrusted source previews.
# Do not forward arbitrary Actions, npm, cloud, model or Git credential variables.
SAFE_RUNNER_ENV_KEYS = (
    "PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA",
    "LANG", "LC_ALL", "LC_CTYPE", "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO",
)


def isolated_cli_env(root: Path) -> dict[str, str]:
    env = {key: os.environ[key] for key in SAFE_RUNNER_ENV_KEYS if key in os.environ}
    scratch = root / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    env.update({
        "TMP": str(scratch), "TEMP": str(scratch), "TMPDIR": str(scratch),
        "CI": "true", "GIT_TERMINAL_PROMPT": "0",
    })
    return env



def seed_verified_cli_cache(cli: str, scratch: Path) -> Path:
    """Download and verify the released CLI once, then clone its cache per case."""
    seed = scratch / "cli-seed"
    home = seed / "home"
    home.mkdir(parents=True)
    cache = seed / "binary-cache"
    env = isolated_cli_env(seed)
    # Windows npm .cmd + the released Node launcher expect a user profile
    # and application-data homes even when the binary cache is overridden.
    # Keep these inside the disposable seed; never inherit host profile paths.
    env.update({
        "HOME": str(home), "USERPROFILE": str(home),
        "APPDATA": str(seed / "config"), "LOCALAPPDATA": str(seed / "data"),
        "XDG_CONFIG_HOME": str(seed / "config"),
        "XDG_DATA_HOME": str(seed / "data"),
        "XDG_CACHE_HOME": str(seed / "cache"),
        "AGENTPLUGINS_HOME": str(seed / "state"),
        "AGENTPLUGINS_CACHE_DIR": str(cache),
    })
    for name in ("config", "data", "cache", "state"):
        (seed / name).mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([cli, "version"], cwd=seed, env=env,
                          capture_output=True, text=True, timeout=180, check=False)
    if proc.returncode != 0:
        # Never echo the launcher stderr or inherited environment into CI.
        kind = ("bootstrap" if "agentplugins npm launcher:" in proc.stderr
                else "native-command")
        raise RuntimeError(
            f"isolated public CLI launcher failed: {kind}, exit={proc.returncode}")
    require(proc.stdout.strip() == "agentplugins 0.1.102",
            "isolated launcher did not resolve public CLI 0.1.102")
    require(cache.is_dir() and
            any(p.is_file() for p in cache.rglob("*")) and
            all(not p.is_symlink() for p in cache.rglob("*")),
            "verified published CLI cache missing or contains symlinks")
    return cache


def clone_verified_cli_cache(seed: Path, destination: Path) -> None:
    """Use separate verified launcher bytes without giving packages a shared cache."""
    require(not destination.exists(), "case launcher cache unexpectedly exists")
    shutil.copytree(seed, destination)


def native_files(profile: Path) -> list[tuple[str, str, str]]:
    """Snapshot file bytes, directories and symlink targets without dereferencing links."""
    entries = []
    for path in profile.rglob("*"):
        relative = path.relative_to(profile).as_posix()
        if path.is_symlink():
            entries.append((relative, "symlink", os.readlink(path)))
        elif path.is_file():
            entries.append((relative, "file", hashlib.sha256(path.read_bytes()).hexdigest()))
        elif path.is_dir():
            entries.append((relative, "directory", ""))
        else:
            entries.append((relative, "other", ""))
    return sorted(entries)


def require_saved_pi_receipt(data: dict, scope: str, manifest_name: str,
                             revision: str, tree_digest: str) -> None:
    """Validate the published 0.1.102 saved-source dry-run contract."""
    require(data.get("dry_run") is True and data.get("scope") == scope and
            data.get("result") == "success",
            "CLI response did not attest a saved dry-run for the requested scope")
    environment = data.get("environment")
    require(isinstance(environment, dict) and
            environment.get("saved") is True and
            environment.get("scope") == scope and
            environment.get("selected_targets") == ["pi"],
            "CLI did not plan exactly Pi in the saved dependency environment")
    actions = data.get("actions")
    require(isinstance(actions, list) and len(actions) > 0 and
            all(isinstance(action, dict) and
                action.get("client_id") == "pi" and
                isinstance(action.get("alias"), str) and action["alias"] and
                action.get("action") in {"install", "unchanged"}
                for action in actions),
            "CLI saved dry-run did not report valid Pi dependency actions")
    # Every case has a fresh, isolated state. A success containing only no-op
    # actions would not demonstrate that this package is actually installable.
    installs = [action for action in actions if action["action"] == "install"]
    require(bool(installs), "fresh saved Pi dry-run planned no installations")
    require(all(isinstance(action.get("package_digest"), str) and
                re.fullmatch(r"sha256:[0-9a-f]{64}", action["package_digest"])
                for action in installs),
            "Pi install plan lacks immutable package digests")
    # An arbitrary dependency install is not proof that the reviewed root
    # package was resolved. Match its immutable source identity exactly.
    require(bool(manifest_name) and SHA.fullmatch(revision) is not None and
            re.fullmatch(r"sha256:[0-9a-f]{64}", tree_digest) is not None,
            "invalid reviewed root package identity")
    require(any(action.get("alias") == manifest_name and
                action.get("revision") == revision and
                action.get("package_digest") == tree_digest for action in installs),
            "saved Pi plan omitted or replaced the reviewed root installation")


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
            require(bool(release["manifest_name"]) and
                    re.fullmatch(r"sha256:[0-9a-f]{64}", release["tree_digest"]) is not None
                    and re.fullmatch(r"sha256:[0-9a-f]{64}",
                                     release["manifest_digest"]) is not None,
                    "active release lacks immutable root package identity")
            sources.append({
                "distribution": distribution["id"],
                "distribution_status": distribution["status"],
                "release_sequence": release["sequence"],
                "components": release["components"],
                "manifest_name": release["manifest_name"],
                "revision": revision,
                "tree_digest": release["tree_digest"],
                "manifest_digest": release["manifest_digest"],
                "source": f"github:{repo}@{revision}//{source['path']}",
            })
    require(bool(sources), "no active release policies were inventoried")
    return sources


def run_case(cli: str, item: dict, number: int, scratch: Path, scope: str, binary_seed: Path) -> dict:
    require(scope in {"user", "project"}, "unsupported scope")
    root = scratch / f"source-{number:02d}-{scope}"
    home = root / "home"
    profile = home / ".pi" / "agent"
    project = root / "project"
    for path in (profile, project, root / "data", root / "config", root / "cache", root / "state"):
        path.mkdir(parents=True, exist_ok=True)
        require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
                "disposable profile path is redirected")
    clone_verified_cli_cache(binary_seed, root / "binary-cache")
    marker = profile / "foreign-neighbor.txt"
    marker.write_text("unowned Pi profile\n", encoding="utf-8")
    project_marker = project / "foreign-neighbor.txt"
    project_marker.write_text("unowned Pi project\n", encoding="utf-8")
    env = isolated_cli_env(root)
    env.update({
        "HOME": str(home), "USERPROFILE": str(home), "PI_CODING_AGENT_DIR": str(profile),
        "AGENTPLUGINS_HOME": str(root / "state"),
        "AGENTPLUGINS_CACHE_DIR": str(root / "binary-cache"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "APPDATA": str(root / "config"), "LOCALAPPDATA": str(root / "data"),
    })
    if scope == "project":
        subprocess.run(["git", "init", "-q"], cwd=project, env=env,
                       capture_output=True, timeout=20, check=True)
    baseline = native_files(profile)
    project_baseline = native_files(project)
    state_baseline = native_files(root / "state")
    result = {key: item[key] for key in (
        "distribution", "distribution_status", "release_sequence", "components",
        "manifest_name", "revision", "tree_digest", "manifest_digest", "source"
    )}
    result["scope"] = scope
    result["status"] = "unverified"
    try:
        # Ordinary remote add uses the published saved dependency planner;
        # --no-save bypasses its signed dependency closure and is not equivalent.
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
            require_saved_pi_receipt(data["data"], scope, item["manifest_name"],
                                     item["revision"], item["tree_digest"])
            # Store only reviewed, non-sensitive plan fields; never echo the CLI
            # environment, transport credentials or arbitrary stderr on success.
            result["planned_actions"] = [
                {key: action[key] for key in (
                    "alias", "client_id", "action", "package_digest", "revision"
                ) if key in action}
                for action in data["data"]["actions"]
            ]
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
        state_after = native_files(root / "state")
        if state_after != state_baseline:
            before, after = set(state_baseline), set(state_after)
            added = [(path, kind) for path, kind, _ in sorted(after - before)][:8]
            removed = [(path, kind) for path, kind, _ in sorted(before - after)][:8]
            raise RuntimeError(
                f"dry-run changed managed state; added={added}; removed={removed}")
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
    require_exact_checkout(args.source_head)
    require_published_cli_version(str(Path(binary).resolve()))
    sources = active_sources(args.source_head)
    require(os.environ.get("RUNNER_OS") in {"Linux", "macOS", "Windows"},
            "Pi catalog evidence requires an identified native Actions OS")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    evidence = {
        "schema_version": 1, "kind": "pi-direct-source-planning",
        "source_commit": args.source_head, "cli_version": "0.1.102",
        "runner_os": os.environ["RUNNER_OS"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "signed_pi_policy_published": False, "runtime_claims": False,
        "account_authentication": "not_tested",
        "scopes": ["user", "project"], "active_policy_count": len(sources),
        "results": [],
    }
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"],
                                     prefix="pi-catalog-planning-") as temp:
        binary_seed = seed_verified_cli_cache(str(Path(binary).resolve()), Path(temp))
        for number, source in enumerate(sources):
            for scope in ("user", "project"):
                if source["distribution_status"] != "active":
                    result = {**source, "scope": scope, "status": "not_eligible",
                              "diagnostic": "suspended distribution; active policy is not install authority"}
                else:
                    result = run_case(str(Path(binary).resolve()), source, number, Path(temp), scope, binary_seed)
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
