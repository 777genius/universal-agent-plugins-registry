#!/usr/bin/env python3
"""Public 0.1.102 direct-source Pi lifecycle, independent of signed Directory eligibility."""
from __future__ import annotations

import argparse
import hashlib
from functools import lru_cache
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
from datetime import datetime, timezone

from pi_catalog_inventory_e2e import (
    isolated_cli_env, native_files, require_exact_checkout,
    require_published_cli_version, seed_verified_cli_cache, clone_verified_cli_cache,
)

PINNED_UPSTREAM = "769c6cd22c3d95462d1f55d789e9532cabefa5a9"
PINNED_HUBSPOT = "2ddbb99dd190c1792b79904f9875e6322bccd243"
CASES = (
    ("context7-stdio", "context7", "plugins/context7", None, "mcp",
     "777genius/universal-agent-plugins-registry"),
    ("context7-http", "context7", "plugins/agent-plugins/context7", PINNED_UPSTREAM, "mixed",
     "upstash/context7"),
    ("navigator-skills", "agent-code-navigator", "plugins/agent-code-navigator", None, "skill",
     "777genius/universal-agent-plugins-registry"),
    # Real Marketing Kit dependency source, but no signed Pi eligibility yet.
    ("hubspot-crm-http", "hubspot-crm", "plugins/hubspot-crm", PINNED_HUBSPOT, "mcp",
     "777genius/universal-agent-plugins"),
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



def verified_private_pi_binding(state_path: Path, public_installation: dict,
                                declared_name: str, revision: str, repository: str,
                                source_path: str, scope: str) -> dict:
    """Bind public list evidence to the CLI's exact persisted Pi ownership.

    Published CLI 0.1.102 deliberately omits private target locators from
    list JSON. Never infer those paths from a copied manifest or public view.
    """
    require(state_path.parent.is_dir() and not state_path.parent.is_symlink()
            and state_path.is_file() and not state_path.is_symlink(),
            "persisted Pi ownership state is absent or redirected")
    raw = state_path.read_bytes()
    require(0 < len(raw) <= 8 * 1024 * 1024,
            "persisted Pi ownership state exceeds the bounded fixture")
    state = strict_json(raw.decode("utf-8"))
    require(type(state.get("schema_version")) is int
            and state["schema_version"] == 5,
            "persisted Pi ownership state has an unexpected schema")
    installations = state.get("installations")
    require(isinstance(installations, list),
            "persisted Pi ownership installations are missing")
    matching = [item for item in installations
                if isinstance(item, dict) and
                item.get("installation_id") == public_installation.get("installation_id")]
    require(len(matching) == 1 and matching[0].get("declared_name") == declared_name,
            "private Pi installation does not match public receipt")
    installed = matching[0]
    source = installed.get("source")
    require(isinstance(source, dict)
            and source.get("repository") == repository
            and source.get("package_subpath") == source_path
            and source.get("resolved_revision") == revision,
            "private Pi source differs from the pinned public request")
    public_clients = [item for item in public_installation.get("clients", [])
                      if isinstance(item, dict) and item.get("client_id") == "pi"
                      and item.get("scope") == scope]
    require(len(public_clients) == 1
            and isinstance(public_clients[0].get("package_revision"), dict),
            "public Pi receipt has no unique scoped revision")
    clients = installed.get("clients")
    require(isinstance(clients, dict), "private Pi binding map is absent")
    bindings = [item for item in clients.values()
                if isinstance(item, dict)
                and item.get("client_id") == "pi"
                and item.get("scope") == scope]
    require(len(bindings) == 1,
            "private Pi receipt has no unique selected scope binding")
    binding = bindings[0]
    public = public_clients[0]
    private_revision = binding.get("package_revision")
    public_revision = public["package_revision"]
    package = installed.get("package")
    require(isinstance(private_revision, dict) and isinstance(package, dict)
            and all(isinstance(public_revision.get(key), str)
                    and public_revision[key] == private_revision.get(key)
                    for key in ("resolved_revision", "tree_digest", "manifest_digest"))
            and private_revision.get("resolved_revision") == revision
            and package.get("manifest_digest") == private_revision.get("manifest_digest")
            and binding.get("materialization") == public.get("materialization")
            and binding.get("verification") == public.get("verification")
            and binding.get("client_binding_id") in clients,
            "private Pi ownership does not match the public pinned receipt")
    require(clients[binding["client_binding_id"]] == binding,
            "private Pi binding key differs from recorded ownership")
    return binding



ROOT = Path(__file__).resolve().parents[1]
PINNED_SOURCE_LIMIT = 16 * 1024 * 1024


@lru_cache(maxsize=512)
def pinned_source_bytes(repository: str, revision: str,
                        package_subpath: str, relative: str) -> bytes:
    """Independently read source bytes at the exact reviewed Git commit.

    Never use the installed package (or its mutable state receipts) as its
    own integrity reference. No authentication, source execution, or tags.
    """
    posix = PurePosixPath(relative)
    subpath = PurePosixPath(package_subpath)
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None
            and re.fullmatch(r"[0-9a-f]{40}", revision) is not None
            and all(p not in ("", ".", "..") for p in (*posix.parts, *subpath.parts))
            and relative == posix.as_posix() and package_subpath == subpath.as_posix()
            and not posix.is_absolute() and not subpath.is_absolute()
            and all("\\" not in p and ":" not in p for p in (*posix.parts, *subpath.parts)),
            "immutable source contains an unsafe repository or package path")
    fullpath = f"{package_subpath}/{relative}"
    if repository == "777genius/universal-agent-plugins-registry":
        # The runner already has the exact Git objects for this checkout.
        # For older shallow revisions fall through to the pinned HTTPS source.
        result = subprocess.run(["git", "show", f"{revision}:{fullpath}"],
                                cwd=ROOT, capture_output=True, timeout=30, check=False)
        if result.returncode == 0:
            require(0 < len(result.stdout) <= PINNED_SOURCE_LIMIT,
                    "pinned Git source file exceeds the integrity bound")
            return result.stdout
    url = (f"https://raw.githubusercontent.com/{repository}/{revision}/"
           f"{quote(fullpath, safe='/')}")
    request = Request(url, headers={"User-Agent": "uap-pi-source-e2e/1"})
    with urlopen(request, timeout=45) as response:
        require(response.status == 200
                and urlparse(response.geturl()).scheme == "https"
                and urlparse(response.geturl()).hostname == "raw.githubusercontent.com",
                "pinned source response left the immutable GitHub origin")
        data = response.read(PINNED_SOURCE_LIMIT + 1)
    require(0 < len(data) <= PINNED_SOURCE_LIMIT,
            "pinned HTTPS source file missing or exceeds integrity bound")
    return data


def require_source_file(package: Path, relative: str,
                        source_read: Callable[[str], bytes]) -> None:
    """Compare bound installed bytes with independently pinned source bytes."""
    path = package / relative
    require(path.is_file() and not path.is_symlink()
            and path.resolve(strict=True).is_relative_to(package.resolve(strict=True))
            and path.read_bytes() == source_read(relative),
            f"bound package file differs from immutable pinned source: {relative}")


def native_skill_markers(skills_root: Path) -> set[str]:
    """Enumerate real SKILL.md files, never marker directories or symlinks."""
    if not skills_root.is_dir() or skills_root.is_symlink():
        return set()
    return {
        path.relative_to(skills_root).as_posix()
        for path in skills_root.rglob("SKILL.md")
        if path.is_file() and not path.is_symlink()
    }


def expected_package_native_names(root: Path, installation: dict,
                                  declared_name: str, kind: str, *,
                                  source_read: Callable[[str], bytes]) -> tuple[set[str], dict, tuple[Path, ...]]:
    """Read source-declared component identities from the verified active package.

    The published CLI's pinned revision and manifest digest select the package;
    arbitrary unrelated native entries cannot satisfy this assertion.
    """
    clients = [client for client in installation.get("clients", [])
               if isinstance(client, dict) and client.get("client_id") == "pi"]
    require(len(clients) == 1 and isinstance(clients[0].get("package_revision"), dict),
            "pinned Pi client has no package identity")
    manifest_digest = clients[0]["package_revision"].get("manifest_digest")
    require(isinstance(manifest_digest, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest) is not None,
            "pinned Pi client has no verified manifest digest")
    # Anchor verified component discovery to the selected Pi binding. A
    # duplicate plugin.json and MCP declaration elsewhere in the disposable
    # checkout cannot establish ownership of that other directory.
    binding = clients[0]
    locator = binding.get("target_locator")
    artifact = binding.get("physical_artifact_id")
    require(isinstance(locator, str) and Path(locator).is_absolute()
            and isinstance(artifact, str) and artifact not in ("", ".", "..")
            and Path(artifact).name == artifact,
            "pinned Pi client has no physical extension binding")
    extensions = root / "extensions"
    package = extensions / artifact
    require(isinstance(binding.get("native_profile_root"), str)
            and Path(binding["native_profile_root"]).resolve(strict=True)
            == root.resolve(strict=True)
            and not extensions.is_symlink()
            and not package.is_symlink() and package.is_dir()
            and Path(locator).resolve(strict=True) == package.resolve(strict=True)
            and package.resolve(strict=True).parent == extensions.resolve(strict=True),
            "pinned Pi extension binding differs from selected native scope")
    manifest_path = package / "plugin.json"
    require(manifest_path.is_file() and not manifest_path.is_symlink()
            and "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            == manifest_digest,
            "verified pinned package native source unavailable")
    require_source_file(package, "plugin.json", source_read)
    manifest = strict_json(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("name") == declared_name,
            "verified package manifest differs from requested package")
    skills = native_skill_markers(package / "skills")
    for skill in skills:
        require_source_file(package, f"skills/{skill}", source_read)
    mcp = package / "mcp.json"
    servers = {}
    if mcp.exists():
        require(mcp.is_file() and not mcp.is_symlink(),
                "verified package MCP declaration is not regular")
        require_source_file(package, "mcp.json", source_read)
        raw = strict_json(mcp.read_text(encoding="utf-8")).get("mcpServers")
        require(isinstance(raw, dict), "verified package MCP declaration invalid")
        require(all(isinstance(name, str) and name and isinstance(value, dict)
                    for name, value in raw.items()),
                "verified package MCP server definitions invalid")
        servers = raw
        for definition in servers.values():
            args = definition.get("args", [])
            require(isinstance(args, list), "verified package MCP args malformed")
            for arg in args:
                if isinstance(arg, str) and arg.startswith("${PLUGIN_ROOT}/"):
                    relative = arg[len("${PLUGIN_ROOT}/"):]
                    posix = PurePosixPath(relative)
                    require(relative == posix.as_posix() and not posix.is_absolute()
                            and all(part not in ("", ".", "..") for part in posix.parts),
                            "verified package MCP launcher path is unsafe")
                    require_source_file(package, relative, source_read)
    require((kind not in {"skill", "mixed"} or bool(skills))
            and (kind not in {"mcp", "mixed"} or bool(servers)),
            "verified package omitted its expected native components")
    return skills, servers, (package,)

def require_removed_native_payload(native_root: Path, kind: str, *,
                                   surviving_skills: list[tuple[str, str, str]] | None = None,
                                   surviving_servers: dict | None = None) -> None:
    """Removal must clean the owned Pi payload without destroying pre-existing registrations."""
    if kind == "skill":
        skills = native_root / "skills"
        require(not skills.is_symlink(), "Pi skills root became a symlink")
        require(native_files(skills) == (surviving_skills or []),
                "removed Pi skill payload remains or foreign skill tree changed")
    elif kind == "mcp":
        config = native_root / "mcp.json"
        require(not config.is_symlink(), "removed Pi MCP configuration became a symlink")
        servers = {}
        if config.exists():
            servers = strict_json(config.read_text(encoding="utf-8")).get("mcpServers", {})
        require(isinstance(servers, dict) and servers == (surviving_servers or {}),
                "removed Pi MCP registration remains or a foreign server was changed")
    else:
        raise RuntimeError("unsupported Pi materialization kind")

def require_expected_mcp_definitions(actual: dict, expected: dict,
                                     verified_package_roots: tuple[Path, ...]) -> None:
    """Match source-verified MCP command/args or URL, not just server keys."""
    for name, declared in expected.items():
        installed = actual.get(name)
        require(isinstance(declared, dict) and isinstance(installed, dict),
                "native Pi MCP definition is missing or malformed")
        if isinstance(declared.get("url"), str) and declared["url"]:
            require(installed.get("url") == declared["url"],
                    "native Pi MCP URL differs from pinned package")
            continue
        command = declared.get("command")
        args = declared.get("args", [])
        require(isinstance(command, str) and command
                and installed.get("command") == command
                and isinstance(args, list) and isinstance(installed.get("args"), list)
                and len(args) == len(installed["args"]),
                "native Pi MCP command or argument structure differs from pinned package")
        for source_arg, native_arg in zip(args, installed["args"]):
            require(isinstance(source_arg, str) and isinstance(native_arg, str),
                    "native Pi MCP arguments must be strings")
            if source_arg.startswith("${PLUGIN_ROOT}/"):
                suffix = Path(source_arg[len("${PLUGIN_ROOT}/"):])
                require(bool(suffix.parts) and not suffix.is_absolute()
                        and all(part not in ("", ".", "..") for part in suffix.parts),
                        "verified package declares unsafe MCP runtime argument")
                native = Path(native_arg)
                require(native.is_absolute() and native.is_file() and not native.is_symlink()
                        and any((package / suffix).is_file()
                                and not (package / suffix).is_symlink()
                                and native.resolve(strict=True) ==
                                (package / suffix).resolve(strict=True)
                                and (package / suffix).resolve(strict=True).is_relative_to(
                                    package.resolve(strict=True))
                                for package in verified_package_roots),
                        "native Pi MCP runtime argument is not pinned to verified package")
            else:
                require(native_arg == source_arg,
                        "native Pi MCP argument differs from pinned package")


def require_unchanged_native_scope(root: Path, existed: bool,
                                   baseline: list[tuple[str, str, str]]) -> None:
    """A scoped Pi install must never materialize in the other Pi scope."""
    require(not root.is_symlink() and root.exists() == existed
            and native_files(root) == baseline,
            "Pi native installation modified the unselected scope")


def run_case(cli: str, source_head: str, temp: Path, case: tuple,
             scope: str, binary_seed: Path) -> dict:
    case_id, name, source_path, revision, kind, repository = case
    require(kind in {"skill", "mcp", "mixed"}, "unsupported Pi materialization kind")
    if revision is None:
        revision = source_head
    selector = f"github:{repository}@{revision}//{source_path}"
    case_root = temp / f"{case_id}-{scope}"
    home = case_root / "home"
    project = case_root / "project"
    pi_profile = home / ".pi" / "agent"
    for directory in (home, project, pi_profile, case_root / "data",
                      case_root / "config", case_root / "cache",
                      case_root / "state"):
        directory.mkdir(parents=True, exist_ok=True)
        require(not directory.is_symlink() and
                directory.resolve().is_relative_to(case_root.resolve()),
                "disposable path crossed case boundary")
    clone_verified_cli_cache(binary_seed, case_root / "binary-cache")
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
    # Unowned native Pi registrations must survive add, repair and remove.
    # This is stronger than preserving only unrelated sentinel text files.
    native_root = pi_profile if scope == "user" else project / ".pi"
    untouched_root = project / ".pi" if scope == "user" else pi_profile
    untouched_exists = untouched_root.exists()
    untouched_baseline = native_files(untouched_root)
    native_root.mkdir(parents=True, exist_ok=True)
    def assert_scope_isolation() -> None:
        require_unchanged_native_scope(
            untouched_root, untouched_exists, untouched_baseline)
    foreign_skill = native_root / "skills" / "foreign-neighbor" / "SKILL.md"
    foreign_skill_text = ("---\nname: foreign-neighbor\n"
                          "description: Existing unowned Pi skill\n---\n\nKeep intact.\n")
    foreign_server = {"command": "node", "args": ["--version"]}
    if kind in {"skill", "mixed"}:
        foreign_skill.parent.mkdir(parents=True, exist_ok=True)
        foreign_skill.write_text(foreign_skill_text, encoding="utf-8")
    if kind in {"mcp", "mixed"}:
        (native_root / "mcp.json").write_text(
            json.dumps({"mcpServers": {"foreign-neighbor": foreign_server}}) + "\n",
            encoding="utf-8")

    surviving_skill_tree = (native_files(native_root / "skills")
                            if kind in {"skill", "mixed"} else [])
    def require_native_payload_present() -> None:
        # Require materialization immediately after add. A later repair must
        # not mask a missing native file or MCP entry at initial install.
        if kind in {"skill", "mixed"}:
            skills = native_root / "skills"
            installed = native_skill_markers(skills)
            require("foreign-neighbor/SKILL.md" in installed and len(installed) > 1
                    and foreign_skill.read_text(encoding="utf-8") == foreign_skill_text,
                    "Pi native skill absent or pre-existing Pi skill was changed")
        if kind in {"mcp", "mixed"}:
            config = native_root / "mcp.json"
            require(config.is_file(), "Pi native MCP configuration absent")
            server_entries = strict_json(config.read_text(encoding="utf-8")).get("mcpServers")
            require(isinstance(server_entries, dict)
                    and server_entries.get("foreign-neighbor") == foreign_server
                    and any(name != "foreign-neighbor" for name in server_entries),
                    "Pi native MCP registration absent or foreign server was changed")

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
        assert_scope_isolation()
        require_native_payload_present()
        listed = call("list")
        first = plugin_record(listed, name, revision)
        state_path = (case_root / "state" / "state-v2.json" if scope == "user"
                      else project / ".uap" / "state-v2.json")
        private_binding = verified_private_pi_binding(
            state_path, first, name, revision, repository, source_path, scope)
        expected_skills, expected_servers, verified_package_roots = expected_package_native_names(
            native_root, {"clients": [private_binding]}, name, kind,
            source_read=lambda relative: pinned_source_bytes(
                repository, revision, source_path, relative))

        def require_expected_identity() -> None:
            if kind in {"skill", "mixed"}:
                skills = native_root / "skills"
                found = native_skill_markers(skills)
                require(found == expected_skills | {"foreign-neighbor/SKILL.md"},
                        "native Pi Skills differ from verified package identities")
            if kind in {"mcp", "mixed"}:
                servers = strict_json((native_root / "mcp.json").read_text(
                    encoding="utf-8")).get("mcpServers")
                require(isinstance(servers, dict)
                        and set(servers) == set(expected_servers) | {"foreign-neighbor"},
                        "native Pi MCP keys differ from verified package identities")
                require_expected_mcp_definitions(
                    servers, expected_servers, verified_package_roots)

        require_expected_identity()
        again = call("add", selector, "--no-save", timeout=240)
        assert_scope_isolation()
        repeated = plugin_record(call("list"), name, revision)
        require(first["installation_id"] == repeated["installation_id"],
                "duplicate or switched installation identity")
        # An exact full-SHA source is immutable. The CLI must refuse update
        # with explicit switch guidance *before changing native Pi files*.
        call("info", first["installation_id"])
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
        assert_scope_isolation()
        require(native_files(native_root) == before_update,
                "refused immutable source update changed Pi native files")
        require(native_files(case_root / "state") == before_installer_state and
                native_files(case_root / "binary-cache") == before_installer_cache,
                "refused immutable source update changed installer state or cache")
        call("repair", first["installation_id"], timeout=240)
        assert_scope_isolation()
        maintained = plugin_record(call("list"), name, revision)
        require(maintained["installation_id"] == first["installation_id"],
                "maintenance switched or duplicated the pinned Pi installation")
        require_native_payload_present()
        require_expected_identity()
        call("remove", first["installation_id"], timeout=120)
        assert_scope_isolation()
        if kind in {"skill", "mixed"}:
            require_removed_native_payload(
                native_root, "skill", surviving_skills=surviving_skill_tree)
            require(foreign_skill.read_text(encoding="utf-8") == foreign_skill_text,
                    "remove changed pre-existing Pi skill bytes")
        if kind in {"mcp", "mixed"}:
            require_removed_native_payload(
                native_root, "mcp", surviving_servers={"foreign-neighbor": foreign_server})
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
        binary_seed = seed_verified_cli_cache(args.cli, Path(temporary))
        for case in CASES:
            for scope in ("user", "project"):
                result = run_case(args.cli, args.source_head, Path(temporary),
                                  case, scope, binary_seed)
                report["results"].append(result)
                args.report.write_text(json.dumps(report, indent=2) + "\n")
                print(f"{result['case']}/{scope}: {result['status']}", flush=True)
    require(len(report["results"]) == 2 * len(CASES) and
            all(x["status"] == "passed" for x in report["results"]),
            "Pi direct source lifecycle incomplete: review exact case JSON")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Pi E2E setup/coverage error: {exc}", file=sys.stderr)
        sys.exit(1)
