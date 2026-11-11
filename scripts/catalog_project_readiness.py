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
# Historical point-in-time evidence identity; never a recurring runtime feed.
# Grants are read only from authenticated feed data.
# The materialized commit has the signed commit as its direct parent, and both
# contain the same immutable snapshot/envelope bytes.
REFUSAL_SOURCE = {
    "signed_ledger_sha": "3f9c30e8b76a51ae3a83f3232cbbb0129fecd468",
    "materialized_ledger_sha": "3509baaac8e4f7ee3d565440f8c0d0bd1f928fba",
    "sequence": 45,
    "snapshot_digest": "sha256:2aba9b0d97556ac0756dff5f974aa7377914e0d8d1d9b735b46c5bc804b81f50",
}
# Reviewed nonexpiring package facts from the independently authenticated signed45
# closure (also unchanged in signed46). These are not target grants or a feed:
# every runtime authorization, signature, expiry and floor remains current.
REVIEWED_SOURCE_CLOSURE = [
    {
        "product_id": "marketing-kit",
        "distribution_id": "777genius/marketing-kit",
        "release_sequence": 1,
        "package_version": "0.1.0",
        "package_source": {
            "path": "plugins/marketing-kit",
            "repository": "777genius/universal-agent-plugins-registry",
            "revision": "c5bcedd4ecf12585a8a50401852e57a44891ebec"
        },
        "tree_digest": "sha256:8918c0f0222bd735fd0eef3cacf90b5a9351fb213483d1558a65b9911624e68a",
        "manifest_digest": "sha256:40b18a6b33c6392134aff7beafb9a91eaeecf46ce765e0e888cdc743dd284ea2"
    },
    {
        "product_id": "hubspot-crm",
        "distribution_id": "777genius/hubspot-crm",
        "release_sequence": 1,
        "package_version": "0.1.0",
        "package_source": {
            "path": "plugins/hubspot-crm",
            "repository": "777genius/universal-agent-plugins",
            "revision": "2ddbb99dd190c1792b79904f9875e6322bccd243"
        },
        "tree_digest": "sha256:09a0b151c384235c3d7b3929398695d24cd7b07c75993a0a73f1a218198ededd",
        "manifest_digest": "sha256:20334e86a1b599d2759e04bfaef37dc2ddb7f6b0f3994b5d66d4eca12fbec941"
    },
    {
        "product_id": "notion",
        "distribution_id": "777genius/notion",
        "release_sequence": 1,
        "package_version": "0.1.0",
        "package_source": {
            "path": "plugins/notion",
            "repository": "777genius/universal-agent-plugins",
            "revision": "2ddbb99dd190c1792b79904f9875e6322bccd243"
        },
        "tree_digest": "sha256:860fa6dd1830d0da2b8fed38195fa6ad6307082ac12d708118e5eb1c5d10f9b7",
        "manifest_digest": "sha256:bbab30a4f062218d7a5fce2f6c818680d3c7adfaebdbaa3e523e15942a2f57e5"
    },
    {
        "product_id": "playwright",
        "distribution_id": "777genius/playwright-bridge",
        "release_sequence": 2,
        "package_version": "0.0.80",
        "package_source": {
            "path": "plugins/playwright",
            "repository": "777genius/universal-agent-plugins-registry",
            "revision": "d9c8d778200d51ae941d86bb69af23534cd1c8f7"
        },
        "tree_digest": "sha256:ff3c74bb5760fea47003130f3984d48234892330325a7cad35a7bc973acc9cf6",
        "manifest_digest": "sha256:8419b5c9e67894c2312048c4fe30e3ea920d00101d02641230183dd7ab4d3b31"
    }
]
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


def validate_source_anchor(case):
    import catalog_publication_readiness as gate
    require(gate.publication.canonical_json(managed.immutable_closure(case)) ==
            gate.publication.canonical_json(REVIEWED_SOURCE_CLOSURE), "reviewed immutable source anchor differs")


def current_boundary(case):
    """A closed oracle choice from the authenticated, already validated policy."""
    root = next(item for item in case["closure"] if item["distribution_id"] == managed.ROOT)
    clients = tuple(target["client"] for target in root["policy"]["targets"])
    require(clients in (CLIENTS, managed.COPILOT_AUTHORIZED_CLIENTS), "unqualified current VSCode boundary")
    return {"source": "current_authenticated_feed", "target": "vscode", "placement_scope": "user",
            "kind": "missing_signed_target" if clients == CLIENTS else "prepared_target_saved_management"}


def validate_refusal_context(ctx):
    import catalog_publication_readiness as gate
    require(isinstance(ctx, dict) and set(ctx) == set(gate.CONTEXT_FIELDS), "refusal context fields")
    require(all(ctx.get(key) == value for key, value in REFUSAL_SOURCE.items()), "refusal source identity changed")
    expected_origin = f"https://raw.githubusercontent.com/{gate.active_registry_repository()}/{REFUSAL_SOURCE['materialized_ledger_sha']}/registry/schemas/1/"
    require(ctx.get("directory_origin") == expected_origin, "refusal origin changed")


def validate_refusal_pair(case, refusal_source, select):
    """Historical point-in-time comparison; never a recurring authorization input."""
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


def expected(snapshot, select):
    """Construct the exact Project contract only for the reviewed six-source root."""
    base = managed.expected(snapshot, select)
    if base is None:
        return None
    root = base["closure"][0]
    source_clients = tuple(target["client"] for target in root["policy"]["targets"])
    if source_clients == managed.LEGACY_CLIENTS:
        return None
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
    validate_source_anchor(case)
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



def expected_user_saved_management(case, ctx):
    """Current signed preparation grant does not grant saved-target capability."""
    if case is None:
        return None
    root = next(item for item in case["closure"] if item["distribution_id"] == managed.ROOT)
    if tuple(target["client"] for target in root["policy"]["targets"]) != managed.COPILOT_AUTHORIZED_CLIENTS:
        return None
    require(case["cli"] == reviewed_release()["cli"], "saved-management corrected CLI differs")
    return {"cli": copy.deepcopy(case["cli"]), "context": copy.deepcopy(ctx),
            "root": managed.ROOT, "target": "vscode", "placement_scope": "user",
            "signed_delivery": "prepared", "outcome": "refused",
            "reason": "unsupported_saved_management", "request_route": "saved_add_without_no_save",
            "dependency_intent": "unchanged",
            "source_binding": "same_four_immutable_packages_as_project_dependencies",
            "authenticated_directory_cache": "warmed_unchanged",
            "native_portable_durable_and_foreign_state_unchanged": True,
            "signed_target_refusal": False, "prepared_native_absence": "not_claimed",
            "standalone_editor_lifecycle": "not_tested"}


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
    if "context" not in case:
        _, canonical = gate.canonical_inputs(args)
        require("vscode_user_refusal" in canonical, "current signed-refusal contract missing")
        gate.validate_artifact(case, canonical["vscode_user_refusal"])
        gate.validate_artifact(ctx, canonical["context"])
    else:
        # Explicit historical audit calls still authenticate the original feed
        # with normal expiry. An archived context is not runtime permission.
        historical, historical_ctx = gate.load_refusal_source(args, ctx)
        gate.validate_artifact(ctx, historical_ctx)
        historical_case = expected(historical, gate.selected)
        gate.validate_artifact(case, expected_user_refusal(historical_case, context=historical_ctx))
    binary = args.project_binary.resolve(strict=True)
    require(gate.digest(binary.read_bytes()) == case["cli"]["binary_digest"], "wrong Project released binary")
    root.mkdir(mode=0o700)
    roots, env = gate.isolated_environment(root, ctx["directory_origin"], (args.codex, args.claude, args.copilot, args.opencode))
    managed.seed_runtime(root / "bin", env, args.codex)
    initial = refusal_snapshot(roots)
    readonly = (*gate.tool_paths(args), binary.parent)
    before = None
    try:
        args.failure_phase = "vscode:warm_directory"
        warmed = gate.child([str(binary), "info", "marketing-kit", "--target", "codex", "--scope", "user", "--format", "json"],
                            root=root, readonly=readonly, env=env, cwd=roots["workspace"], timeout=600)
        require(type(warmed.returncode) is int and warmed.returncode == 0 and warmed.stderr == "", "VSCode refusal Directory warmup failed")
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
        require(type(result.returncode) is int and result.returncode == 1 and result.stdout == "" and result.stderr == reason + "\n",
                "VSCode User did not receive exact signed-target refusal")
    finally:
        try:
            require((refusal_snapshot(roots) == initial) if before is None else
                    managed.snapshot_paths({name: roots[name] for name in ("home", "config", "workspace", "state")}) == before,
                    "VSCode User refusal mutated native, portable or durable state")
        finally:
            validate_directory_cache(roots["state"] / "directory-v1-cache.json", args.trusted_keys, ctx, required=before is not None)


def run_user_saved_management(args, root, case, ctx, source_case):
    """Probe only the explicit saved route; no standalone Editor lifecycle claim."""
    import catalog_publication_readiness as gate
    # A direct helper call has the same authenticated whole-input boundary as
    # the producer. Caller-supplied contexts/cases cannot select another feed.
    _, canonical = gate.canonical_inputs(args)
    require("vscode_user_saved_management" in canonical, "saved-management source contract missing")
    gate.validate_artifact(case, canonical["vscode_user_saved_management"])
    gate.validate_artifact(ctx, canonical["context"])
    gate.validate_artifact(source_case, canonical["project_dependencies"])
    binary = args.project_binary.resolve(strict=True)
    require(gate.digest(binary.read_bytes()) == case["cli"]["binary_digest"], "wrong saved-management released binary")
    root.mkdir(mode=0o700)
    roots, env = gate.isolated_environment(root, ctx["directory_origin"], (args.codex, args.claude, args.copilot, args.opencode))
    managed.seed_runtime(root / "bin", env, args.codex)
    foreign_paths, foreign_configs = managed.seed_foreign_state(roots)
    foreign_before = managed.snapshot_paths(foreign_paths)
    initial = refusal_snapshot(roots)
    readonly = (*gate.tool_paths(args), binary.parent)
    before = None
    try:
        args.failure_phase = "vscode:saved_management_warm_directory"
        for selection in source_case["closure"]:
            warmed = gate.child([str(binary), "info", selection["distribution_id"], "--target", "vscode", "--scope", "user", "--format", "json"],
                                root=root, readonly=readonly, env=env, cwd=roots["workspace"], timeout=600)
            require(type(warmed.returncode) is int and warmed.returncode == 0 and warmed.stderr == "", "saved-management Directory warmup failed")
            info = gate.publication.parse_json_bytes(warmed.stdout.encode(), "Directory warmup", max_bytes=gate.LIMIT)
            require(isinstance(info, dict) and info.get("command") == "info" and info.get("result") == "success"
                    and isinstance(info.get("data"), dict), "saved-management warmup envelope")
            data = info["data"]
            require(type(data.get("snapshot_sequence")) is int and data["snapshot_sequence"] == ctx["sequence"] and data.get("snapshot_digest") == ctx["snapshot_digest"],
                    "saved-management warmed wrong signed publication")
            release = data.get("selected_release", {})
            require(isinstance(release, dict) and type(release.get("release_sequence")) is int
                    and release.get("release_status") == "active", "saved-management release shape or status")
            require(data.get("product_id") == selection["product_id"] and data.get("selected_distribution") == selection["distribution_id"]
                    and all(release.get(key) == value for key, value in {
                        "id": selection["distribution_id"], "release_sequence": selection["release_sequence"],
                        "package_version": selection["package_version"], "resolved_revision": selection["package_source"]["revision"],
                        "repository": selection["package_source"]["repository"], "package_path": selection["package_source"]["path"],
                        "tree_digest": selection["tree_digest"], "manifest_digest": selection["manifest_digest"]}.items()),
                    "saved-management warmup immutable source differs")
            for targets in (data.get("target_compatibility", []), release.get("target_compatibility", [])):
                require(isinstance(targets, list) and all(isinstance(target, dict) for target in targets)
                        and [target for target in targets if target.get("client") == "vscode"] ==
                        [{"client": "vscode", "scopes": ["user"], "delivery": "prepared"}], "saved-management signed preparation differs")
            validate_directory_cache(roots["state"] / "directory-v1-cache.json", args.trusted_keys, ctx, required=True)
            require(refusal_snapshot(roots) == initial, "saved-management warmup changed non-cache state")
        before = managed.snapshot_paths({name: roots[name] for name in ("home", "config", "workspace", "state")})
        args.failure_phase = "vscode:user_saved_management"
        # Deliberately omit --no-save: this is the unsupported dependency-intent
        # route, not a signed-target refusal or a claim about native preparation.
        result = gate.child([str(binary), "add", "marketing-kit", "--target", "vscode", "--scope", "user", "--yes", "--format", "json"],
                            root=root, readonly=readonly, env=env, cwd=roots["workspace"], timeout=600)
        reason = ('agentplugins: target vscode cannot be saved; retry '
                  'agentplugins add marketing-kit --target vscode --no-save\n')
        require(type(result.returncode) is int and result.returncode == 1 and result.stdout == "" and result.stderr == reason,
                "VSCode User did not receive exact unsupported-saved-management refusal")
    finally:
        # These guards also run for malformed output, rejected diagnostics and
        # child failures. Freeze the full profile only after all four warmups.
        try:
            if before is None:
                require(refusal_snapshot(roots) == initial, "saved-management warmup changed non-cache state")
            else:
                require(managed.snapshot_paths({name: roots[name] for name in ("home", "config", "workspace", "state")}) == before,
                        "saved-management refusal mutated native, portable or durable state")
        finally:
            try:
                managed.validate_foreign_state(foreign_paths, foreign_before, foreign_configs)
            finally:
                validate_directory_cache(roots["state"] / "directory-v1-cache.json", args.trusted_keys, ctx, required=before is not None)
