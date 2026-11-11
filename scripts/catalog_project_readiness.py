"""Marketing Kit Project placement from signed v1 User-qualified sources.

This module owns the fixed reviewed User/Project release identity. It never accepts
a caller-selected installer identity, downloads an unpinned installer or grants a target.
Project native configuration is evidence of installed resources, not a claim
about account authentication, trust approval or successful MCP execution.
"""
from __future__ import annotations

import copy
import base64
import re
from pathlib import Path
import tomllib

import catalog_managed_readiness as managed

require = managed.require
# Remains unset until the actual release commit and all three authenticated
# release asset digests have been reviewed. No development or guessed pin.
RELEASE = None
# Evidence-source identity only: grants are read from the authenticated feed.
# The materialized commit has the signed commit as its direct parent, and both
# contain the same immutable snapshot/envelope bytes.
REFUSAL_SOURCE = {
    "signed_ledger_sha": "3f9c30e8b76a51ae3a83f3232cbbb0129fecd468",
    "materialized_ledger_sha": "3509baaac8e4f7ee3d565440f8c0d0bd1f928fba",
    "sequence": 45,
    "snapshot_digest": "sha256:2aba9b0d97556ac0756dff5f974aa7377914e0d8d1d9b735b46c5bc804b81f50",
}
CLIENTS = managed.CLIENTS
SKILL_ROOTS = {"codex": ".agents/skills", "cursor": ".cursor/skills",
               "copilot": ".github/skills", "claude": ".claude/skills",
               "gemini": ".gemini/skills", "opencode": ".opencode/skills"}
MCP_PATHS = {"codex": ".codex/config.toml", "cursor": ".cursor/mcp.json",
             "copilot": ".github/mcp.json", "claude": None,
             "gemini": ".gemini/settings.json", "opencode": "opencode.json"}


def validate_cli(cli):
    require(isinstance(cli, dict) and set(cli) == {"version", "tag", "commit", "binary_digest"},
            "Project CLI identity fields")
    require(isinstance(cli["version"], str) and re.fullmatch(r"0\.1\.[0-9]+", cli["version"])
            and int(cli["version"].rsplit(".", 1)[1]) >= 103,
            "Project requires a corrected released CLI")
    require(cli["tag"] == "agentplugins-v" + cli["version"]
            and isinstance(cli["commit"], str) and re.fullmatch(r"[0-9a-f]{40}", cli["commit"])
            and isinstance(cli["binary_digest"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", cli["binary_digest"]),
            "Project released CLI identity")


def reviewed_release():
    require(RELEASE is not None, "reviewed Project CLI release identity is unset")
    require(isinstance(RELEASE, dict) and set(RELEASE) == {"cli", "checksums_digest", "manifest_digest"},
            "Project release identity fields")
    validate_cli(RELEASE["cli"])
    require(all(isinstance(RELEASE[key], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", RELEASE[key])
                for key in ("checksums_digest", "manifest_digest")), "Project release asset digests")
    return copy.deepcopy(RELEASE)


def refusal_source_identity():
    return copy.deepcopy(REFUSAL_SOURCE)


def needs_refusal_source(snapshot, select):
    case = managed.expected(snapshot, select)
    return case is not None and tuple(target["client"] for target in case["closure"][0]["policy"]["targets"]) == managed.COPILOT_AUTHORIZED_CLIENTS


def validate_refusal_context(ctx):
    import catalog_publication_readiness as gate
    require(isinstance(ctx, dict) and set(ctx) == set(gate.CONTEXT_FIELDS), "refusal context fields")
    require(all(ctx.get(key) == value for key, value in REFUSAL_SOURCE.items()), "refusal source identity changed")
    expected_origin = f"https://raw.githubusercontent.com/{gate.active_registry_repository()}/{REFUSAL_SOURCE['materialized_ledger_sha']}/registry/schemas/1/"
    require(ctx.get("directory_origin") == expected_origin, "refusal origin changed")


def validate_refusal_pair(case, refusal_source, select):
    """Compare signed source facts without granting or resolving another target."""
    import argparse
    import catalog_publication_readiness as gate
    require(isinstance(refusal_source, tuple) and len(refusal_source) == 2, "fixed refusal source required")
    snapshot, ctx = refusal_source
    validate_refusal_context(ctx)
    identity = {"sequence": snapshot["sequence"], "snapshot_digest": gate.digest(gate.publication.canonical_json(snapshot))}
    require(identity == {key: REFUSAL_SOURCE[key] for key in ("sequence", "snapshot_digest")}, "refusal snapshot changed")
    gate.context(argparse.Namespace(**ctx), snapshot, identity)
    negative = expected(snapshot, select)
    require(negative is not None and negative["cli"] == case["cli"], "refusal released CLI differs")
    require(managed.immutable_closure(case) == managed.immutable_closure(negative), "positive/refusal immutable closure differs")
    for positive, prior in zip(case["closure"], negative["closure"]):
        policy = copy.deepcopy(positive["policy"])
        if positive["distribution_id"] == managed.ROOT:
            policy["targets"] = [target for target in policy["targets"] if target["client"] != "vscode"]
        require(policy == prior["policy"], "positive/refusal policy delta exceeds prepared VSCode grant")
    return negative


def expected(snapshot, select, *, refusal_source=None):
    """Construct the exact Project contract only for the reviewed six-source root."""
    base = managed.expected(snapshot, select)
    if base is None:
        return None
    root = base["closure"][0]
    source_clients = tuple(target["client"] for target in root["policy"]["targets"])
    if source_clients == managed.LEGACY_CLIENTS:
        return None
    paired = source_clients == managed.COPILOT_AUTHORIZED_CLIENTS
    require(not paired or refusal_source is not None,
            "seven-grant policy requires separate fixed signed45 refusal source")
    require(source_clients in (CLIENTS, managed.COPILOT_AUTHORIZED_CLIENTS), "unqualified Project source targets")
    cli = reviewed_release()["cli"]
    closure = [select(snapshot, selector, CLIENTS, cli=cli) for selector in managed.PINS]
    require(all(item["package_version"] == managed.PINS[item["selector"]] for item in closure),
            "Project immutable closure changed")
    require(all(target["scopes"] == ["user"] for item in closure
                for target in item["policy"]["targets"] if target["client"] in CLIENTS),
            "Project requires the unchanged User-qualified source scope")
    # Same immutable source releases as the historical User dependency case.
    for before, after in zip(base["closure"], closure):
        require(all(before[key] == after[key] for key in
                    ("distribution_id", "release_sequence", "package_version", "package_source", "tree_digest", "manifest_digest")),
                "Project changed signed source identity")
    proof = copy.deepcopy(base["proof"])
    proof.pop("native_plugin_listing")
    proof.update(native_project_resources={client: "passed_exact_resources" for client in CLIENTS},
                 repeat_add="passed_no_change", repair="passed_same_signed_identity",
                 user_native_and_durable_state_unchanged=True,
                 native_client_discovery="not_qualified_by_this_case", client_tools_call="not_tested",
                 native_project_cleanup="passed_exact_absence")
    case = {"cli": copy.deepcopy(cli), "root": managed.ROOT,
            "placement_scope": "project", "signed_source_scope": "user",
            "targets": list(CLIENTS), "native_removal_targets": [],
            "client_tools": {"codex": "pinned_public_cli", "cursor": "version_only_detection_fixture",
                             "copilot": "pinned_public_cli", "claude": "pinned_public_cli",
                             "gemini": "configuration_directory_detection",
                             "opencode": "version_only_native_executable_fixture"},
            "closure": closure, "edges": base["edges"],
            "associations": [{"distribution_id": item["distribution_id"],
                              "release_sequence": item["release_sequence"], "client": client}
                             for item in closure for client in CLIENTS],
            "proof": proof}
    if paired:
        validate_refusal_pair(case, refusal_source, select)
    return case


def expected_user_refusal(case, *, context=None):
    """A separate explicit VSCode request cannot borrow Copilot's source grant."""
    if case is None:
        return None
    require(all("vscode" not in {target["client"] for target in item["policy"]["targets"]}
                for item in case["closure"] if item["distribution_id"] == managed.ROOT), "VSCode refusal source grant changed")
    result = {"cli": copy.deepcopy(case["cli"]), "root": managed.ROOT,
            "target": "vscode", "placement_scope": "user", "outcome": "refused",
            "reason": "missing_vscode_signed_target_grant",
            "native_and_portable_state_unchanged": True,
            "authenticated_directory_cache": "warmed_unchanged"}
    if context is not None:
        validate_refusal_context(context)
        result["context"] = copy.deepcopy(context)
    return result


def source_coverage(case):
    """Signed source qualification; this must never be counted as positive User placement."""
    return set() if case is None else {
        (item["distribution_id"], item["release_sequence"], item["client"], case["signed_source_scope"])
        for item in case["associations"]}


def confined(path, project):
    require(path.is_absolute() and path.resolve().is_relative_to(project.resolve())
            and path != project and not path.is_symlink(), "Project resource escaped or substituted")
    for parent in path.parents:
        if parent == project:
            break
        require(not parent.is_symlink(), "Project resource ancestor substituted")


def config_servers(path, client):
    import catalog_publication_readiness as gate
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= gate.LIMIT,
            "Project native config missing or invalid")
    document = tomllib.loads(path.read_text()) if client == "codex" else gate.read_json(path)
    require(isinstance(document, dict), "Project native config shape")
    key = "mcp_servers" if client == "codex" else "mcp" if client == "opencode" else "mcpServers"
    servers = document.get(key, {})
    require(isinstance(servers, dict) and all(isinstance(name, str) and name and isinstance(value, dict)
                                           for name, value in servers.items()), "Project native MCP member shape")
    return servers


def package_components(package):
    import catalog_publication_readiness as gate
    skills_root = package / "skills"
    skills = {path.name: path for path in skills_root.iterdir() if path.is_dir()} if skills_root.exists() else {}
    paths = [path for path in (package / "mcp.json", package / ".mcp.json") if path.exists()]
    require(len(paths) <= 1, "ambiguous immutable MCP source")
    document = gate.read_json(paths[0]) if paths else {}
    servers = document.get("mcpServers", {})
    require(isinstance(servers, dict), "immutable MCP source shape")
    return skills, servers


def validate_server(entry, source, package_root, *, cli_digest=None, project_root=None, data_root=None):
    # Account and runtime remain untested. Bind the actual persisted endpoint
    # or pinned executable arguments; installed[] cannot establish this.
    require(isinstance(entry, dict) and bool(entry), "Project native MCP entry missing")
    if source.get("url"):
        require(entry.get("url", entry.get("httpUrl")) == source["url"] and not entry.get("command")
                and entry.get("headers", entry.get("http_headers", {})) == source.get("headers", {}),
                "Project MCP endpoint or transport metadata changed")
    else:
        command = entry.get("command")
        native_args = entry.get("args", [])
        if isinstance(command, list):
            require(bool(command), "Project MCP command missing")
            command, native_args = command[0], command[1:]
        expected_args = [arg.replace("${PLUGIN_ROOT}", str(package_root)) for arg in source.get("args", [])]
        require(isinstance(command, str) and command and isinstance(native_args, list), "Project MCP executable missing")
        if Path(command).name == "agentplugins":
            import catalog_publication_readiness as gate
            launcher = package_root / "io.github.777genius.agentplugins/managed-stdio-v1/agentplugins"
            require(command == str(launcher) and launcher.is_file() and not launcher.is_symlink()
                    and cli_digest is not None and gate.digest(launcher.read_bytes()) == cli_digest,
                    "Project MCP launcher is not the pinned released CLI")
            require(len(native_args) >= 7 and native_args[:2] == ["--internal-stdio-v1", str(package_root)]
                    and native_args[3:5] == [str(package_root), "plugin"]
                    and project_root is not None and data_root is not None and native_args[2] == str(data_root)
                    and native_args[5] in ("--", "--argv-base64-v1"), "Project MCP launcher context changed")
            confined(data_root, project_root)
            child_args = native_args[6:]
            if native_args[5] == "--argv-base64-v1":
                decoded = [base64.b64decode(arg, validate=True) for arg in child_args]
                require([base64.b64encode(arg).decode() for arg in decoded] == child_args, "noncanonical Project MCP argument encoding")
                child_args = [arg.decode("utf-8") for arg in decoded]
            require(child_args == [source.get("command"), *expected_args], "Project MCP wrapped command or arguments changed")
        else:
            require(command == source.get("command") and native_args == expected_args,
                    "Project MCP executable or arguments changed")


def validate_native_resources(installations, case, project, store):
    import catalog_publication_readiness as gate
    require(case.get("placement_scope") == "project" and tuple(case["targets"]) == CLIENTS,
            "Project native proof scope or targets")
    for selected in case["closure"]:
        package = store / "packages" / "agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
        skills, servers = package_components(package)
        bindings = list(installations[selected["distribution_id"]]["clients"].values())
        for client in CLIENTS:
            matches = [binding for binding in bindings if binding.get("client_id") == client]
            require(len(matches) == 1, "Project native client binding missing or ambiguous")
            binding = matches[0]
            require(binding.get("scope") == "project" and binding.get("verification") == "installation_verified"
                    and binding.get("affected_surfaces") == [client], "Project native binding scope or siblings")
            target = Path(binding["target_locator"])
            confined(target, project)
            backend = binding.get("physical_artifact_id")
            require(isinstance(backend, str) and backend not in ("", ".", "..") and Path(backend).name == backend,
                    "Project physical artifact identity missing or invalid")
            data_root = project / ".uap/plugin-data" / backend
            if client == "claude":
                require(target.parent == project / SKILL_ROOTS[client], "Claude Project package path")
                manifest_path = target / ".claude-plugin/plugin.json"
                confined(manifest_path, project)
                manifest = gate.read_json(manifest_path)
                portable = gate.read_json(package / "plugin.json")
                require(isinstance(manifest, dict) and manifest.get("name") == portable.get("name")
                        and manifest.get("version") == selected["package_version"]
                        and manifest.get("skills") == ("./.agentplugins-runtime/skills/" if skills else None)
                        and manifest.get("mcpServers") == ("./.mcp.json" if servers else None),
                        "Claude Project manifest identity or component references changed")
                for name, source in skills.items():
                    path = target / ".agentplugins-runtime/skills" / name
                    confined(path, project)
                    require(gate.registry.directory_tree_digest(path) == gate.registry.directory_tree_digest(source),
                            "Claude Project Skill bytes changed")
                native_servers = gate.read_json(target / ".mcp.json") if servers else {}
                require(isinstance(native_servers, dict), "Claude Project MCP resource shape")
                require(set(native_servers) == set(servers), "Claude Project MCP resource set")
                for name, source in servers.items():
                    validate_server(native_servers[name], source, target / ".agentplugins-runtime",
                                    cli_digest=case["cli"]["binary_digest"], project_root=project, data_root=data_root)
                continue
            objects = binding.get("native_objects", [])
            for name, source in skills.items():
                path = project / SKILL_ROOTS[client] / name
                confined(path, project)
                matches = [item for item in objects if item.get("logical_name") == name and "skill" in item.get("kind", "")]
                require(len(matches) == 1 and matches[0].get("path") == str(path) and path.is_dir()
                        and gate.registry.directory_tree_digest(path) == gate.registry.directory_tree_digest(source),
                        "Project native Skill receipt or bytes changed")
            if servers:
                path = project / MCP_PATHS[client]
                if client == "copilot" and (project / ".mcp.json").exists():
                    path = project / ".mcp.json"
                confined(path, project)
                native_servers = config_servers(path, client)
                for name, source in servers.items():
                    matches = [item for item in objects if item.get("logical_name") == name and "mcp" in item.get("kind", "")]
                    require(len(matches) == 1 and matches[0].get("path") == str(path), "Project native MCP receipt changed")
                    validate_server(native_servers.get(name), source, target,
                                    cli_digest=case["cli"]["binary_digest"], project_root=project, data_root=data_root)


def validate_native_cleanup(installations, project):
    """Inspect exact recorded Project native members, including both Copilot locations."""
    for installation in installations.values():
        for binding in installation["clients"].values():
            client = binding["client_id"]
            target = Path(binding["target_locator"])
            confined(target, project)
            require(not target.exists(), "Project owned package remains")
            for item in binding.get("native_objects", []):
                if item.get("kind") == "managed_package_directory":
                    continue
                path = Path(item.get("path", ""))
                confined(path, project)
                if "skill" in item.get("kind", ""):
                    require(not path.exists(), "Project native Skill remains")
                elif "mcp" in item.get("kind", ""):
                    paths = (project / ".github/mcp.json", project / ".mcp.json") if client == "copilot" else (path,)
                    for candidate in paths:
                        confined(candidate, project)
                        require(not candidate.exists() or item["logical_name"] not in config_servers(candidate, client),
                                "Project native MCP member remains")
                else:
                    raise ValueError("unrecognized Project native resource")


def user_paths(roots):
    paths = {"home": roots["home"], "config": roots["config"]}
    paths.update({"state-" + name: roots["state"] / name for name in
                  ("state-v2.json", "uap.toml", "uap.lock", "managed", "plugin-data",
                   "operations-v2", "installer-tmp", "mutation.lock", "environment.lock")})
    return paths


def validate_user_isolation(before, roots):
    require(managed.snapshot_paths(user_paths(roots)) == before, "Project operation changed User native or durable state")


def refusal_snapshot(roots):
    result = managed.snapshot_paths({"home": roots["home"], "config": roots["config"],
                                     "project": roots["workspace"], "state": roots["state"]})
    allowed = {"directory-v1-cache.json", "directory-v1-cache.json.lock"}
    result["state"] = [entry for entry in result["state"] if entry[0] not in allowed]
    return result


def validate_directory_cache(path, keys, ctx, *, required=False):
    import catalog_publication_readiness as gate
    lock = path.with_name(path.name + ".lock")
    require(not lock.is_symlink() and (not lock.exists() or lock.is_file() and lock.stat().st_size == 0
                                      and lock.stat().st_mode & 0o077 == 0), "Directory cache lock substituted")
    if not path.exists():
        require(not required, "authenticated Directory cache missing")
        require(not path.is_symlink(), "Directory cache substituted")
        return
    require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0,
            "Directory cache is not a restrictive regular file")
    record = gate.read_json(path, limit=12 * 1024 * 1024)
    require(set(record) == {"schema_version", "sequence", "snapshot", "envelope"}
            and type(record["schema_version"]) is int and record["schema_version"] == 1
            and type(record["sequence"]) is int and record["sequence"] == ctx["sequence"], "Directory cache identity")
    snapshot = base64.b64decode(record["snapshot"], validate=True)
    envelope_bytes = base64.b64decode(record["envelope"], validate=True)
    require(gate.digest(snapshot) == ctx["snapshot_digest"], "Directory cache publication differs")
    envelope = gate.publication.parse_json_bytes(envelope_bytes, "Directory cache envelope", max_bytes=gate.publication.MAX_ENVELOPE_BYTES)
    gate.publication.verify_envelope(snapshot, envelope, gate.publication.load_public_keys(keys),
                                     signature_verifier=gate.verify_signature)


def validate_operation(value, aliases, clients, *, operation, expected_scope, installations=None):
    """Bind actual dependency actions/results to one explicitly selected scope."""
    require(expected_scope in ("user", "project") and value.get("scope") == expected_scope
            and value.get("outcome") == "completed", "dependency operation scope or outcome")
    expected = {(alias, client) for alias in aliases.values() for client in clients}
    if operation == "repair":
        expected = {(aliases[managed.ROOT], client) for client in clients}
    actions, results = value.get("actions"), value.get("results")
    require(isinstance(actions, list) and isinstance(results, list) and len(actions) == len(expected)
            and {(item.get("alias"), item.get("client_id")) for item in actions} == expected,
            "Project operation target or alias closure")
    active = []
    for action in actions:
        allowed = {"install", "repair", "unchanged"} if operation == "add" else {"repair"} if operation == "repair" else {"unchanged"}
        require(action.get("action") in allowed, "Project operation action")
        if action["action"] != "unchanged":
            active.append(action)
    require(len(results) == len(active), "Project operation applied receipts")
    by_alias = {alias: distribution for distribution, alias in aliases.items()}
    for action, result in zip(active, results):
        require(result.get("outcome") in ("completed", "unchanged") and result.get("operation") == action["action"]
                and result.get("client_id") == action["client_id"] and isinstance(result.get("installation_id"), str)
                and bool(result["installation_id"]), "Project operation receipt identity")
        if installations is not None:
            require(result["installation_id"] == installations[by_alias[action["alias"]]]["installation_id"],
                    "Project operation changed installation identity")


def run_user_refusal(args, root, case, ctx):
    import catalog_publication_readiness as gate
    require(case["outcome"] == "refused", "VSCode User refusal mislabeled as success")
    if "context" in case:
        validate_refusal_context(ctx)
        require(case["context"] == ctx, "refusal runtime context differs")
        require(case["cli"] == reviewed_release()["cli"], "wrong refusal corrected CLI authority")
    binary = args.project_binary.resolve(strict=True)
    require(gate.digest(binary.read_bytes()) == case["cli"]["binary_digest"], "wrong Project released binary")
    root.mkdir(mode=0o700)
    roots, env = gate.isolated_environment(root, ctx["directory_origin"], (args.codex, args.claude, args.copilot, args.opencode))
    managed.seed_runtime(root / "bin", env, args.codex)
    args.failure_phase = "vscode:warm_directory"
    initial = refusal_snapshot(roots)
    readonly = (*gate.tool_paths(args), binary.parent)
    warmed = gate.child([str(binary), "info", "marketing-kit", "--target", "codex", "--scope", "user", "--format", "json"],
                        root=root, readonly=readonly, env=env, cwd=roots["workspace"], timeout=600)
    require(warmed.returncode == 0 and warmed.stderr == "", "VSCode refusal Directory warmup failed")
    info = gate.publication.parse_json_bytes(warmed.stdout.encode(), "Directory warmup", max_bytes=gate.LIMIT)
    require(isinstance(info, dict) and info.get("command") == "info" and info.get("result") == "success"
            and info.get("data", {}).get("snapshot_sequence") == ctx["sequence"]
            and info["data"].get("snapshot_digest") == ctx["snapshot_digest"], "VSCode refusal warmed wrong signed publication")
    validate_directory_cache(roots["state"] / "directory-v1-cache.json", args.trusted_keys, ctx, required=True)
    require(refusal_snapshot(roots) == initial, "Directory warmup changed non-cache state")
    before = managed.snapshot_paths({name: roots[name] for name in ("home", "config", "workspace", "state")})
    args.failure_phase = "vscode:user_refusal"
    result = gate.child([str(binary), "add", "marketing-kit", "--target", "vscode", "--scope", "user", "--no-save", "--yes", "--format", "json"],
                        root=root, readonly=(*gate.tool_paths(args), binary.parent), env=env,
                        cwd=roots["workspace"], timeout=600)
    reason = ('Resolving and validating one Agent Plugin package for every selected target...\n'
              'agentplugins: no eligible directory release for "marketing-kit": '
              '777genius/marketing-kit: release does not support complete target set; missing vscode')
    # The genuine Linux CLI emits these two complete lines and one terminal LF.
    # Whitespace, padding or another diagnostic must not count as signed refusal.
    require(result.returncode == 1 and result.stdout == "" and result.stderr == reason + "\n",
            "VSCode User did not receive exact signed-target refusal")
    require(managed.snapshot_paths({name: roots[name] for name in ("home", "config", "workspace", "state")}) == before,
            "VSCode User refusal mutated native, portable or durable state")
    validate_directory_cache(roots["state"] / "directory-v1-cache.json", args.trusted_keys, ctx, required=True)
