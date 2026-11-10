#!/usr/bin/env python3
"""Public 0.1.102 direct-source Pi lifecycle, independent of signed Directory eligibility."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from pi_catalog_inventory_e2e import (
    isolated_cli_env, native_files, require_exact_checkout,
    require_published_cli_version,
)

PINNED_UPSTREAM = "769c6cd22c3d95462d1f55d789e9532cabefa5a9"
CASES = (
    ("context7-stdio", "context7", "plugins/context7", None, "mcp"),
    ("context7-http", "context7", "plugins/agent-plugins/context7", PINNED_UPSTREAM, "mcp"),
    ("navigator-skills", "agent-code-navigator", "plugins/agent-code-navigator", None, "skill"),
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def strict_json(data: str) -> dict:
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise ValueError("duplicate JSON object key")
            obj[k] = v
        return obj
    result = json.loads(data, object_pairs_hook=pairs)
    require(isinstance(result, dict), "CLI did not emit a JSON object")
    return result


def command(argv: list[str], cwd: Path, env: dict, *, timeout: int = 180) -> dict:
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                            text=True, encoding="utf-8", errors="replace",
                            timeout=timeout, check=False)
    # CLI output is untrusted. Store short bounded diagnostics, never raw
    # executable package content or credentials from the host environment.
    entry = {"argv": [Path(argv[0]).name, argv[1], *argv[2:]],
             "exit": result.returncode}
    if result.returncode == 0:
        value = strict_json(result.stdout)
        require(value.get("result") == "success" and
                isinstance(value.get("data"), dict),
                "CLI returned success exit without the success envelope")
        entry["data"] = value["data"]
    else:
        entry["error_tail"] = (result.stderr or result.stdout)[-800:]
    return entry


def plugin_record(envelope: dict, name: str, revision: str) -> dict:
    require(envelope["exit"] == 0, "cannot inspect failed CLI list")
    installations = envelope["data"].get("installations")
    require(isinstance(installations, list), "CLI list installations missing")
    matching = []
    for item in installations:
        if not isinstance(item, dict) or item.get("name") != name:
            continue
        clients = item.get("clients", [])
        if not isinstance(clients, list):
            continue
        installed = [
            client for client in clients
            if isinstance(client, dict) and client.get("client_id") == "pi"
            and isinstance(client.get("package_revision"), dict)
            and client["package_revision"].get("resolved_revision") == revision
            and (client.get("verification") == "installation_verified" or
                 (client.get("materialization") == "materialized" and
                  client.get("verification") == "package_validated" and
                  client.get("activation") == "manual_activation_required"))
        ]
        if installed and isinstance(item.get("installation_id"), str):
            matching.append(item)
    require(len(matching) == 1, "expected one pinned Pi installation with a real materialization receipt")
    return matching[0]


def run_case(cli: str, source_head: str, temp: Path, case: tuple,
             scope: str) -> dict:
    case_id, name, source_path, revision, kind = case
    if revision is None:
        revision = source_head
        repository = "777genius/universal-agent-plugins-registry"
    else:
        repository = "upstash/context7"
    selector = f"github:{repository}@{revision}//{source_path}"
    case_root = temp / f"{case_id}-{scope}"
    home = case_root / "home"
    project = case_root / "project"
    pi_profile = home / ".pi" / "agent"
    for directory in (home, project, pi_profile, case_root / "data",
                      case_root / "config", case_root / "cache",
                      case_root / "state", case_root / "binary-cache"):
        directory.mkdir(parents=True, exist_ok=True)
        require(not directory.is_symlink() and
                directory.resolve().is_relative_to(case_root.resolve()),
                "disposable path crossed case boundary")
    original_user = pi_profile / "foreign-neighbor.txt"
    original_project = project / "foreign-neighbor.txt"
    original_user.write_text("unowned pi profile bytes\n")
    original_project.write_text("unowned project bytes\n")
    env = isolated_cli_env(case_root)
    env.update({
        "HOME": str(home), "USERPROFILE": str(home),
        "PI_CODING_AGENT_DIR": str(pi_profile),
        "AGENTPLUGINS_HOME": str(case_root / "state"),
        "AGENTPLUGINS_CACHE_DIR": str(case_root / "binary-cache"),
        "XDG_DATA_HOME": str(case_root / "data"),
        "XDG_CONFIG_HOME": str(case_root / "config"),
        "XDG_CACHE_HOME": str(case_root / "cache"),
        "APPDATA": str(case_root / "config"),
        "LOCALAPPDATA": str(case_root / "data"),
    })
    args = ["--target", "pi", "--scope", scope, "--format", "json"]
    if scope == "project":
        subprocess.run(["git", "init", "-q"], cwd=project, env=env,
                       timeout=20, check=True)
        args += ["--project-root", str(project)]
    report = {"case": case_id, "scope": scope, "source": selector,
              "status": "failed", "operations": []}
    def call(*verb: str, timeout: int = 180) -> dict:
        outcome = command([cli, *verb, *args], project, env, timeout=timeout)
        report["operations"].append({k: v for k, v in outcome.items() if k != "data"})
        require(outcome["exit"] == 0, f"{case_id}/{scope}: {verb[0]} failed: {outcome.get('error_tail', '')}")
        return outcome
    try:
        add = call("add", selector, "--no-save", timeout=240)
        listed = call("list")
        first = plugin_record(listed, name, revision)
        again = call("add", selector, "--no-save", timeout=240)
        repeated = plugin_record(call("list"), name, revision)
        require(first["installation_id"] == repeated["installation_id"],
                "duplicate or switched installation identity")
        # An exact full-SHA source is immutable. The CLI must refuse update
        # with explicit switch guidance *before changing native Pi files*.
        call("info", first["installation_id"])
        native_root = pi_profile if scope == "user" else project / ".pi"
        # A denied immutable-source update must not create directories or
        # symlinks either: comparing file bytes alone misses these mutations.
        before_update = native_files(native_root)
        # The immutable-source refusal must not mutate the installer's own
        # persisted receipt or fetch cache, not only Pi's native files.
        before_installer_state = native_files(case_root / "state")
        before_installer_cache = native_files(case_root / "binary-cache")
        refused = command([cli, "update", first["installation_id"], *args],
                          project, env, timeout=240)
        report["operations"].append({k: v for k, v in refused.items()
                                     if k != "data"})
        require(refused["exit"] != 0 and
                "direct full-SHA installations require explicit switch"
                in refused.get("error_tail", ""),
                "pinned Git update must refuse with explicit switch guidance")
        require(native_files(native_root) == before_update,
                "refused immutable source update changed Pi native files")
        require(native_files(case_root / "state") == before_installer_state and
                native_files(case_root / "binary-cache") == before_installer_cache,
                "refused immutable source update changed installer state or cache")
        call("repair", first["installation_id"], timeout=240)
        maintained = plugin_record(call("list"), name, revision)
        require(maintained["installation_id"] == first["installation_id"],
                "maintenance switched or duplicated the pinned Pi installation")
        if kind == "skill":
            require(any(native_root.joinpath("skills").rglob("SKILL.md")),
                    "Pi native skills not installed")
        else:
            config = native_root / "mcp.json"
            require(config.is_file(), "Pi native MCP configuration absent")
            server_entries = strict_json(config.read_text(encoding="utf-8")).get("mcpServers")
            require(isinstance(server_entries, dict) and server_entries,
                    "Pi native MCP server registration absent")
        call("remove", first["installation_id"], timeout=120)
        require(not any(isinstance(x, dict) and x.get("installation_id") ==
                        first["installation_id"]
                        for x in call("list")["data"].get("installations", [])),
                "removed Pi registration still active")
        require(original_user.read_text() == "unowned pi profile bytes\n" and
                original_project.read_text() == "unowned project bytes\n",
                "installer changed unowned sentinels")
        require(not (project / "uap.toml").exists() and
                not (project / "uap.lock").exists(),
                "imperative --no-save created portable dependency state")
        report["verification"] = "native-files-and-receipt-only"
        report["runtime_claims"] = False
        report["account_oauth_qualified"] = False
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)[-800:]
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--cli", default="agentplugins")
    args = parser.parse_args()
    # npm installs a .cmd launcher on Windows. subprocess does not reliably
    # apply PATHEXT when given the bare command name; resolve the trusted
    # published CLI executable before entering disposable child profiles.
    cli_path = shutil.which(args.cli)
    require(cli_path is not None and Path(cli_path).is_file(),
            "published agentplugins executable not found in PATH")
    args.cli = str(Path(cli_path).resolve(strict=True))
    require(re.fullmatch(r"[a-f0-9]{40}", args.source_head) is not None,
            "source SHA must be immutable")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_REPOSITORY") ==
            "777genius/universal-agent-plugins-registry" and
            os.environ.get("RUNNER_TEMP"), "only disposable GitHub-hosted E2E")
    # Self-attest the exact source tree and public CLI, even outside the workflow.
    require_exact_checkout(args.source_head)
    require_published_cli_version(args.cli)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "tested_at": datetime.now(timezone.utc).isoformat(),
              "uap_cli": "public npm 0.1.102", "source_head": args.source_head,
              "native_pi": "real npm @earendil-works/pi-coding-agent@1.5.0",
              "runtime_claims": False, "account_oauth_qualified": False,
              "results": []}
    with tempfile.TemporaryDirectory(prefix="pi-direct-e2e-",
                                     dir=os.environ["RUNNER_TEMP"]) as temporary:
        for case in CASES:
            for scope in ("user", "project"):
                result = run_case(args.cli, args.source_head, Path(temporary),
                                  case, scope)
                report["results"].append(result)
                args.report.write_text(json.dumps(report, indent=2) + "\n")
                print(f"{result['case']}/{scope}: {result['status']}", flush=True)
    require(len(report["results"]) == 6 and
            all(x["status"] == "passed" for x in report["results"]),
            "Pi direct source lifecycle incomplete: review exact case JSON")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Pi E2E setup/coverage error: {exc}", file=sys.stderr)
        sys.exit(1)
