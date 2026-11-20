#!/usr/bin/env python3
"""Production-default signed Pi saved Marketing Kit E2E on an isolated runner.

This is one real four-package User/Project slice, not 72/72 acceptance, a
publisher authorization, or proof of remote OAuth/MCP tool execution.
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

EXPECTED = {
    "marketing-kit": "777genius/marketing-kit",
    "notion": "777genius/notion",
    "hubspot-crm": "777genius/hubspot-crm",
    "playwright": "777genius/playwright-bridge",
}
CHILD_VERSIONS = {"notion": "0.1.0", "hubspot-crm": "0.1.0", "playwright": "0.0.80"}
RELEASE_VERSIONS = {"marketing-kit": "0.1.0", **CHILD_VERSIONS}
SAFE_ENV = ("PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC",
            "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA",
            "LANG", "LC_ALL", "LC_CTYPE", "SSL_CERT_FILE", "GIT_SSL_CAINFO")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def json_object(body: str, stage: str) -> dict:
    try:
        value = json.loads(body)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError(f"{stage}: CLI returned no valid JSON") from error
    require(isinstance(value, dict) and value.get("result") == "success"
            and value.get("outcome") in (None, "completed"),
            f"{stage}: CLI did not report completed success")
    return value


def check_lock(path: Path, policy: dict | None = None) -> str:
    require(path.is_file() and not path.is_symlink(), "signed saved lock missing")
    data = json.loads(path.read_text(encoding="utf-8"))
    packages = data.get("packages")
    require(isinstance(packages, list) and len(packages) == len(EXPECTED),
            "signed saved lock has incomplete four-package closure")
    aliases = set()
    for package in packages:
        require(isinstance(package, dict), "signed lock has malformed package")
        alias = package.get("alias")
        require(alias in EXPECTED and alias not in aliases
                and package.get("source_key") == "directory:" + EXPECTED[alias]
                and package.get("targets") == ["pi"]
                and all(isinstance(package.get(key), str)
                        and DIGEST.fullmatch(package[key])
                        for key in ("tree_digest", "manifest_digest")),
                "signed lock has missing/unsigned Pi package pin")
        source = package.get("source")
        require(isinstance(source, dict)
                and isinstance(source.get("registry"), dict)
                and source["registry"].get("distribution") == EXPECTED[alias],
                "signed lock package has no matching Directory identity")
        if policy is not None:
            release = policy["releases"][EXPECTED[alias]]
            require(all(package[key] == release[key]
                        for key in ("tree_digest", "manifest_digest")),
                    "saved lock digests differ from authenticated signed release")
        edges = package.get("required_by", [])
        require(isinstance(edges, list), "signed lock dependency edges malformed")
        if alias == "marketing-kit":
            require(not edges, "signed Marketing Kit root has unexpected parents")
        else:
            require(len(edges) == 1 and isinstance(edges[0], dict)
                    and edges[0].get("alias") == "marketing-kit"
                    and edges[0].get("selector") ==
                    {"kind": "version", "value": CHILD_VERSIONS[alias]},
                    "signed Marketing Kit dependency closure changed")
        aliases.add(alias)
    require(aliases == set(EXPECTED), "signed Marketing Kit child missing")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def check_installations(document: dict, scope: str, policy: dict | None = None) -> dict[str, str]:
    data = document.get("data")
    require(isinstance(data, dict) and isinstance(data.get("installations"), list),
            "native saved inventory missing")
    installations = data["installations"]
    require(len(installations) == len(EXPECTED), "native signed Pi closure incomplete")
    identities: dict[str, str] = {}
    for record in installations:
        require(isinstance(record, dict), "malformed installed record")
        signed = record.get("directory")
        require(isinstance(signed, dict), "installed record has no signed Directory identity")
        distribution = signed.get("recorded_distribution")
        instance = record.get("installation_id")
        bindings = record.get("clients")
        if isinstance(bindings, dict):
            bindings = list(bindings.values())
        require(distribution in EXPECTED.values() and distribution not in identities
                and isinstance(instance, str) and bool(instance)
                and isinstance(bindings, list) and len(bindings) == 1
                and isinstance(bindings[0], dict),
                "native inventory has duplicate/unknown/unowned Pi installation")
        binding = bindings[0]
        require(binding.get("client_id") == "pi" and binding.get("scope") == scope
                and binding.get("materialization") == "materialized"
                and binding.get("verification") == "installation_verified"
                and isinstance(binding.get("package_revision"), dict)
                and binding["package_revision"].get("distribution_id") == distribution
                and type(binding["package_revision"].get("release_sequence")) is int
                and binding["package_revision"]["release_sequence"] > 0
                and signed.get("recorded_release_sequence") ==
                    binding["package_revision"]["release_sequence"]
                and isinstance(signed.get("recorded_revision"), str)
                and re.fullmatch(r"[0-9a-f]{40}", signed["recorded_revision"]),
                "native Pi installation does not bind materialized signed release")
        if policy is not None:
            release = policy["releases"][distribution]
            revision = binding["package_revision"]
            require(revision["release_sequence"] == release["release_sequence"]
                    and signed["recorded_revision"] == release["resolved_revision"]
                    and all(revision.get(key) == release[key]
                            for key in ("version", "tree_digest", "manifest_digest"))
                    and revision.get("resolved_revision") == release["resolved_revision"],
                    "native saved receipt differs from authenticated signed release")
        identities[distribution] = instance
    require(len(set(identities.values())) == 4, "duplicate installed ownership IDs")
    return identities


def native_root(env: dict[str, str], project: Path, scope: str) -> Path:
    return (Path(env["PI_CODING_AGENT_DIR"]) if scope == "user"
            else project / ".pi")


def check_native(env: dict[str, str], project: Path, scope: str,
                 *, removed: bool = False) -> None:
    """Inspect real Pi discovery files; a saved receipt alone is insufficient."""
    root = native_root(env, project, scope)
    skill = root / "skills" / "campaign-planning" / "SKILL.md"
    config = root / "mcp.json"
    required_mcp = {"notion", "hubspot-crm", "playwright"}
    if removed:
        require(not skill.exists() and not skill.is_symlink(),
                "removed Pi profile retains Marketing Kit Skill")
    else:
        require(skill.is_file() and not skill.is_symlink()
                and 0 < skill.stat().st_size < 1024 * 1024,
                "real Pi Marketing Kit Skill was not materialized")
    if not config.exists() and not config.is_symlink():
        require(removed, "Pi MCP configuration absent after signed install")
        return
    require(config.is_file() and not config.is_symlink(),
            "unsafe Pi MCP configuration path")
    document = json.loads(config.read_text(encoding="utf-8"))
    servers = document.get("mcpServers")
    require(isinstance(servers, dict) and
            all(isinstance(name, str) and isinstance(data, dict)
                for name, data in servers.items()),
            "Pi MCP configuration is malformed")
    if removed:
        require(not required_mcp.intersection(servers),
                "removed Pi profile retains signed MCP server")
    else:
        require(required_mcp.issubset(servers),
                "real signed Pi child MCP configuration is incomplete")


def fresh_case(root: Path, name: str, scope: str) -> tuple[dict[str, str], Path, Path, Path]:
    case = root / name
    case.mkdir(mode=0o700)
    home, project, state, native = (case / "home", case / "project",
                                    case / "state", case / "home" / ".pi" / "agent")
    for path in (home, project, state, native, case / "data", case / "config",
                 case / "cache", case / "temp"):
        path.mkdir(parents=True, exist_ok=True)
        require(not path.is_symlink() and path.resolve().is_relative_to(case.resolve()),
                "isolated test path is redirected")
    for marker in (home / "foreign-do-not-change.txt",
                   project / "foreign-do-not-change.txt",
                   native / "foreign-do-not-change.txt"):
        marker.write_text("foreign and unchanged\n", encoding="utf-8")
    env = {key: os.environ[key] for key in SAFE_ENV if key in os.environ}
    env.update({
        "HOME": str(home), "USERPROFILE": str(home),
        "PI_CODING_AGENT_DIR": str(native), "AGENTPLUGINS_HOME": str(state),
        "AGENTPLUGINS_CACHE_DIR": str(case / "cache"),
        "XDG_CONFIG_HOME": str(case / "config"), "XDG_DATA_HOME": str(case / "data"),
        "XDG_CACHE_HOME": str(case / "cache"), "APPDATA": str(case / "config"),
        "LOCALAPPDATA": str(case / "data"), "TMP": str(case / "temp"),
        "TEMP": str(case / "temp"), "TMPDIR": str(case / "temp"),
        "CI": "true", "GIT_TERMINAL_PROMPT": "0",
    })
    # No origin override, private token, npm/GitHub credentials, shell hook or
    # source selector reaches the signed-production CLI.
    if scope == "project":
        subprocess.run(["git", "init", "-q"], cwd=project, env=env,
                       capture_output=True, check=True, timeout=20)
    return env, project, state, native


def assert_foreign(root: Path, scope: str) -> None:
    require(scope in ("user", "project"), "unexpected test scope")
    for suffix in ("A", "B"):
        case = root / (scope + "-" + suffix)
        for relative in ("home/foreign-do-not-change.txt",
                         "project/foreign-do-not-change.txt",
                         "home/.pi/agent/foreign-do-not-change.txt"):
            marker = case / relative
            require(marker.is_file() and not marker.is_symlink()
                    and marker.read_text(encoding="utf-8") == "foreign and unchanged\n",
                    "foreign Pi/User/Project content changed")


def invoke(cli: str, env: dict[str, str], project: Path, stage: str,
           *args: str) -> dict:
    proc = subprocess.run([cli, *args, "--format", "json"], cwd=project, env=env,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=300, check=False)
    require(proc.returncode == 0, f"{stage}: public CLI refused (exit={proc.returncode})")
    return json_object(proc.stdout, stage)


def observe_signed_policy(cli: str, env: dict[str, str], project: Path) -> dict:
    """Read the authentic release and Pi authorization from the public CLI."""
    baseline = None
    releases: dict[str, dict] = {}
    for alias, distribution in EXPECTED.items():
        envelope = invoke(cli, env, project, "signed info", "info",
                          distribution, "--target", "pi", "--scope", "user")
        data = envelope.get("data")
        require(envelope.get("command") == "info" and isinstance(data, dict)
                and data.get("selected_distribution") == distribution,
                "signed Directory info has wrong selected distribution")
        seq, digest = data.get("snapshot_sequence"), data.get("snapshot_digest")
        require(type(seq) is int and seq > 0
                and isinstance(digest, str) and DIGEST.fullmatch(digest),
                "signed Directory info has no authenticated snapshot identity")
        identity = (seq, digest)
        require(baseline is None or baseline == identity,
                "signed Directory snapshot changed across Marketing Kit graph")
        baseline = identity
        release = data.get("selected_release")
        require(isinstance(release, dict) and release.get("id") == distribution
                and release.get("release_status") == "active"
                and type(release.get("release_sequence")) is int
                and release["release_sequence"] > 0
                and release.get("package_version") == RELEASE_VERSIONS[alias]
                and isinstance(release.get("resolved_revision"), str)
                and re.fullmatch(r"[0-9a-f]{40}", release["resolved_revision"])
                and all(isinstance(release.get(key), str)
                        and DIGEST.fullmatch(release[key])
                        for key in ("tree_digest", "manifest_digest")),
                "signed Pi release identity/version/digest is invalid")
        targets = release.get("target_compatibility")
        require(isinstance(targets, list) and any(
            isinstance(target, dict) and target.get("client") == "pi"
            and target.get("delivery") == "managed"
            and target.get("scopes") == ["user"]
            for target in targets), "signed Pi target is missing for required package")
        releases[distribution] = {
            key: release[key] for key in (
                "release_sequence", "resolved_revision", "tree_digest",
                "manifest_digest")
        }
        releases[distribution]["version"] = release["package_version"]
    require(baseline is not None, "signed Pi policy has no snapshot")
    return {"snapshot_sequence": baseline[0], "snapshot_digest": baseline[1],
            "releases": releases}


def run_scope(cli: str, root: Path, scope: str, report: list[dict]) -> None:
    env_a, project_a, state_a, _ = fresh_case(root, scope + "-A", scope)
    env_b, project_b, state_b, _ = fresh_case(root, scope + "-B", scope)
    args_a = ("--scope", scope) + (
        ("--project-root", str(project_a)) if scope == "project" else ())
    args_b = ("--scope", scope) + (
        ("--project-root", str(project_b)) if scope == "project" else ())
    portable_a = project_a if scope == "project" else state_a
    portable_b = project_b if scope == "project" else state_b

    policy = observe_signed_policy(cli, env_a, project_a)
    invoke(cli, env_a, project_a, "signed add", "add", "marketing-kit",
           "--target", "pi", *args_a)
    original = check_installations(
        invoke(cli, env_a, project_a, "signed list", "list", "--target", "pi", *args_a),
        scope, policy)
    check_native(env_a, project_a, scope)
    lock_digest = check_lock(portable_a / "uap.lock", policy)
    require((portable_a / "uap.toml").is_file(), "saved source agreement missing")
    report.append({"scope": scope, "stage": "signed-add", "result": "passed",
                   "installed": len(original), "lock_digest": lock_digest,
                   "snapshot_sequence": policy["snapshot_sequence"]})

    invoke(cli, env_a, project_a, "repeat signed add", "add", "marketing-kit",
           "--target", "pi", *args_a)
    require(original == check_installations(
        invoke(cli, env_a, project_a, "repeat list", "list", "--target", "pi", *args_a),
        scope, policy), "repeat add changed signed owners")
    invoke(cli, env_a, project_a, "signed update", "update", "marketing-kit", *args_a)
    invoke(cli, env_a, project_a, "signed repair", "repair", "marketing-kit",
           "--target", "pi", *args_a)
    require(lock_digest == check_lock(portable_a / "uap.lock", policy),
            "unchanged signed saved lifecycle rewrote lock")
    require(original == check_installations(
        invoke(cli, env_a, project_a, "post-repair list", "list",
               "--target", "pi", *args_a), scope, policy),
            "signed update/repair lost installed owner")
    report.append({"scope": scope, "stage": "repeat-update-repair", "result": "passed"})

    for filename in ("uap.toml", "uap.lock"):
        shutil.copyfile(portable_a / filename, portable_b / filename)
    require(observe_signed_policy(cli, env_b, project_b) == policy,
            "cold restore changed authenticated Pi Directory snapshot")
    invoke(cli, env_b, project_b, "cold locked restore", "install",
           "--locked", "--yes", *args_b)
    restored = check_installations(
        invoke(cli, env_b, project_b, "restored list", "list",
               "--target", "pi", *args_b), scope, policy)
    require(lock_digest == check_lock(portable_b / "uap.lock", policy)
            and not set(original.values()) & set(restored.values()),
            "cold restore changed signed pins or reused installation IDs")
    check_native(env_b, project_b, scope)
    report.append({"scope": scope, "stage": "cold-locked-restore", "result": "passed"})

    for env, project, args in ((env_b, project_b, args_b), (env_a, project_a, args_a)):
        invoke(cli, env, project, "signed remove", "remove", "marketing-kit", *args)
        listing = invoke(cli, env, project, "removed list", "list", "--target", "pi", *args)
        data = listing.get("data")
        require(isinstance(data, dict) and data.get("installations") == [],
                "removed Pi profile retains signed installations")
        check_native(env, project, scope, removed=True)
    assert_foreign(root, scope)
    report.append({"scope": scope, "stage": "signed-removal-foreign", "result": "passed"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", default="agentplugins")
    parser.add_argument("--cli-version", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") ==
            "777genius/universal-agent-plugins-registry"
            and os.environ.get("RUNNER_OS") in ("Linux", "macOS", "Windows")
            and os.environ.get("RUNNER_TEMP"),
            "signed saved acceptance requires isolated GitHub-hosted OS")
    require(re.fullmatch(r"0\.1\.[1-9][0-9]*", args.cli_version) is not None,
            "CLI version must be explicitly selected")
    binary = shutil.which(args.cli)
    require(binary is not None, "published CLI executable missing")
    version = subprocess.run([binary, "version"], capture_output=True, text=True,
                             timeout=30, check=True)
    require(version.stdout.strip() == "agentplugins " + args.cli_version,
            "wrong published CLI version")
    report = {"kind": "pi-signed-marketing-kit-saved-production-e2e",
              "os": os.environ["RUNNER_OS"], "cli_version": args.cli_version,
              "production_feed": True, "synthetic_signed_feed": False,
              "scope_coverage": "marketing-kit-only-not-72/72",
              "status": "failed", "stages": []}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="pi-signed-saved-",
                                         dir=os.environ["RUNNER_TEMP"]) as temp:
            for scope in ("user", "project"):
                run_scope(str(Path(binary).resolve()), Path(temp), scope, report["stages"])
        report["status"] = "passed"
        return 0
    except Exception as error:
        # Do not attach untrusted command output, paths, tokens or native config.
        report["failure_kind"] = type(error).__name__
        report["failure_stage"] = str(error).split(":")[0][:100]
        return 1
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
