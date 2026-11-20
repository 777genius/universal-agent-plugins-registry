"""Marketing Kit Project placement from signed v1 User-qualified sources.

It uses the one pinned released CLI identity (catalog_managed_readiness.CLI). It
never accepts a caller-selected installer identity or grants a target.
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
# Reviewed nonexpiring immutable package facts of the Marketing Kit closure.
# These are not target grants or a feed: every runtime authorization,
# signature, expiry and floor remains current.
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


def validate_source_anchor(case):
    import catalog_publication_readiness as gate
    require(gate.publication.canonical_json(managed.immutable_closure(case)) ==
            gate.publication.canonical_json(REVIEWED_SOURCE_CLOSURE), "reviewed immutable source anchor differs")


def current_boundary(case):
    """A closed oracle choice from the authenticated, already validated policy."""
    root = next(item for item in case["closure"] if item["distribution_id"] == managed.ROOT)
    require("vscode" in {target["client"] for target in root["policy"]["targets"]}, "unqualified current VSCode boundary")
    return {"source": "current_authenticated_feed", "target": "vscode", "placement_scope": "user",
            "kind": "prepared_target_saved_management"}


def expected(snapshot, select):
    """Construct the exact Project contract only for the reviewed six-source root."""
    base = managed.expected(snapshot, select)
    if base is None:
        return None
    cli = managed.CLI
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
                 user_native_and_durable_state="unchanged_except_exact_project_trust_claude_project_registry_and_native_runtime_caches",
                 claude_profile_setup="native_first_start_then_fixed_unchanged_control_before_uap",
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


def expected_user_saved_management(case, ctx):
    """Current signed preparation grant does not grant saved-target capability."""
    if case is None:
        return None
    current_boundary(case)
    require(case["cli"] == managed.CLI, "saved-management released CLI differs")
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
                # The owned package is a local Claude marketplace; Claude Code
                # installs the plugin below it into its own project cache.
                plugin_root = target / ".agentplugins-plugin"
                caches = [item for item in binding.get("native_objects", []) if item.get("kind") == "claude_project_plugin_cache"]
                require(len(caches) == 1 and caches[0].get("path") == str(plugin_root) and plugin_root.is_dir(),
                        "Claude Project plugin cache receipt changed")
                confined(target / ".claude-plugin/marketplace.json", project)
                require((target / ".claude-plugin/marketplace.json").is_file(), "Claude Project marketplace missing")
                target = plugin_root
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
                if item.get("kind") == "claude_project_plugin_cache":
                    require(not path.exists(), "Claude Project plugin cache remains")
                elif "skill" in item.get("kind", ""):
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


# The released CLI places Project resources through the clients' native
# project flows. By design they record exact trust for the selected project in
# these native files of record, and Claude Code keeps its project-scoped plugin
# registry under HOME. Each change is validated by content below.
PROJECT_TRUST_FILES = (".gemini/trustedFolders.json", ".copilot/config.json", ".codex/config.toml", ".claude/.claude.json")
CLAUDE_REGISTRY_FILES = (".claude/plugins/installed_plugins.json", ".claude/plugins/known_marketplaces.json")
RECORD_FILES = PROJECT_TRUST_FILES + CLAUDE_REGISTRY_FILES
CLAUDE_MARKETPLACE = re.compile(r"agentplugins-[0-9a-f]{12}")
# Exact native runtime outputs observed with the pinned CLI: Claude Code's MCP
# health probe (logs, needs-auth and OAuth discovery state, its own lock),
# Codex runtime databases and bundled system Skills, and Claude's project
# plugin store whose registry entries are validated above.
NATIVE_RUNTIME = re.compile(
    r"\.cache|\.cache/claude-cli-nodejs(/.*)?|\.claude/mcp-needs-auth-cache\.json|\.claude/\.credentials\.json"
    r"|\.claude/\.claude\.json\.lock|\.codex/installation_id|\.codex/[a-z]+_[0-9]+\.sqlite(-shm|-wal)?"
    r"|\.codex/skills|\.codex/skills/\.system(/.*)?|\.codex/(\.tmp|tmp)(/.*)?"
    r"|\.claude/plugins|\.claude/plugins/(cache|data|marketplaces)"
    r"|\.claude/plugins/cache/agentplugins-[0-9a-f]{12}(/.*)?|\.claude/plugins/data/[a-z0-9._-]+-agentplugins-[0-9a-f]{12}(/.*)?")
EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def record_bytes(home):
    """Baseline bytes of the native files of record, captured before UAP runs."""
    result = {}
    for name in RECORD_FILES:
        path = home / name
        require(not path.is_symlink() and (not path.exists() or path.is_file() and path.stat().st_size <= 1024 * 1024),
                "native file of record is not an ordinary bounded file")
        result[name] = path.read_bytes() if path.exists() else None
    return result


def validate_record(name, before, path, workspace, home):
    """Allow only exact trust for the selected project and its Claude registry entries."""
    import catalog_publication_readiness as gate
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024, "native file of record substituted")
    body = path.read_bytes()
    if name == ".codex/config.toml":
        after, prior = tomllib.loads(body.decode()), tomllib.loads(before.decode()) if before else {}
    else:
        after = gate.publication.parse_json_bytes(body, name, max_bytes=1024 * 1024)
        prior = gate.publication.parse_json_bytes(before, name, max_bytes=1024 * 1024) if before else {}
    require(isinstance(after, dict) and isinstance(prior, dict), "native file of record shape")
    rest = copy.deepcopy(after)
    if name == ".gemini/trustedFolders.json":
        require(rest.pop(workspace, None) == "TRUST_FOLDER", "Gemini trust is not the exact project")
    elif name == ".copilot/config.json":
        folders = rest.get("trustedFolders")
        require(isinstance(folders, list) and folders.count(workspace) == 1, "Copilot trust is not the exact project")
        rest["trustedFolders"] = [item for item in folders if item != workspace]
        if "trustedFolders" not in prior and not rest["trustedFolders"]:
            rest.pop("trustedFolders")
    elif name in (".codex/config.toml", ".claude/.claude.json"):
        expected = {"trust_level": "trusted"} if name == ".codex/config.toml" else {"hasTrustDialogAccepted": True}
        projects = rest.get("projects")
        require(isinstance(projects, dict) and projects.pop(workspace, None) == expected, "native trust is not the exact project")
        if "projects" not in prior and not projects:
            rest.pop("projects")
        if name == ".claude/.claude.json" and "userID" not in prior:
            # Claude Code assigns its own anonymous installation ID on first use.
            require(isinstance(rest.pop("userID", ""), str), "Claude user ID shape")
    elif name == ".claude/plugins/installed_plugins.json":
        plugins, old = rest.pop("plugins", None), prior.pop("plugins", {})
        require(rest.get("version") == 2 and isinstance(plugins, dict) and isinstance(old, dict), "Claude plugin registry shape")
        if "version" not in prior:
            rest.pop("version")
        cache = home / ".claude/plugins/cache"
        for key, records in plugins.items():
            if old.get(key) == records:
                continue
            marketplace = key.split("@", 1)[1] if isinstance(key, str) and "@" in key else ""
            require(CLAUDE_MARKETPLACE.fullmatch(marketplace) is not None and isinstance(records, list) and bool(records)
                    and all(isinstance(item, dict) and item.get("scope") == "project" and item.get("projectPath") == workspace
                            and isinstance(item.get("installPath"), str) and Path(item["installPath"]).is_relative_to(cache / marketplace)
                            for item in records),
                    "Claude plugin registry changed outside the selected project")
        require(all(plugins.get(key) == value for key, value in old.items()), "Claude plugin registry rewrote foreign entries")
    else:
        skills = Path(workspace) / SKILL_ROOTS["claude"]
        for key, value in rest.items():
            if prior.get(key) == value:
                continue
            source = value.get("source") if isinstance(value, dict) else None
            require(CLAUDE_MARKETPLACE.fullmatch(key) is not None and isinstance(source, dict)
                    and set(value) <= {"source", "installLocation", "lastUpdated"}
                    and source == {"source": "directory", "path": value.get("installLocation")}
                    and isinstance(source["path"], str) and Path(source["path"]).parent == skills,
                    "Claude marketplace registry changed outside the selected project")
        rest = {key: value for key, value in rest.items() if key in prior}
    require(rest == prior, "native file of record changed beyond exact project trust")


def validate_user_isolation(before, roots):
    after = managed.snapshot_paths(user_paths(roots))
    message = "Project operation changed User native or durable state"
    require(all(after[key] == before[key] for key in after if key != "home"), message)
    old = {entry[0]: entry[1:] for entry in before["home"]}
    new = {entry[0]: entry[1:] for entry in after["home"]}
    records = before.get("records", {})
    for name in sorted(set(old) | set(new)):
        if old.get(name) == new.get(name) or NATIVE_RUNTIME.fullmatch(name):
            continue
        if name.removesuffix(".agentplugins.lock") in RECORD_FILES and name.endswith(".agentplugins.lock"):
            entry = new.get(name, ())
            require(len(entry) == 3 and entry[1:] == ("file", EMPTY_DIGEST) and entry[0] & 0o077 == 0, message)
            continue
        require(name in RECORD_FILES and new.get(name, ("absent",))[1:2] == ("file",), message)
        validate_record(name, records.get(name), roots["home"] / name, str(roots["workspace"]), roots["home"])


def initialize_user_profile(args, root, roots, env, readonly):
    """Initialize only native first-start metadata, then freeze it before UAP.

    The real selected Claude profile is required for User precedence and Project
    suppression. Exactly two native empty-list controls establish one baseline;
    no installer operation or later native call can replace that baseline.
    """
    import catalog_publication_readiness as gate
    profile_root = roots["home"] / ".claude"
    profile = profile_root / ".claude.json"
    backups = profile_root / "backups"
    def require_profile_anchor():
        require(not root.is_symlink() and root.is_dir() and root.resolve() == root
                and roots["home"] == root / "home" and not roots["home"].is_symlink()
                and roots["home"].is_dir() and roots["home"].resolve() == roots["home"],
                "Claude initialization substituted the case or HOME anchor")
    require_profile_anchor()
    require(not profile.exists() and not profile.is_symlink()
            and not backups.exists() and not backups.is_symlink(),
            "Claude profile initialization requires a fresh disposable profile")
    require(not profile_root.is_symlink()
            and (not profile_root.exists() or profile_root.is_dir()),
            "Claude profile root is not an ordinary directory")
    paths = {**user_paths(roots), "workspace": roots["workspace"],
             "all-state": roots["state"], "cache": roots["cache"]}
    before = managed.snapshot_paths(paths)
    old_home = {entry[0]: entry[1:] for entry in before["home"]}
    # Exact environment selected by public .104's bounded Claude list probe
    # from isolated_environment(); do not pass XDG, Directory, auth or CI flags.
    native_env = {key: env[key] for key in ("HOME", "USERPROFILE", "PATH", "TMPDIR", "LANG")}
    native_env.update(CLAUDE_CONFIG_DIR=str(profile_root), DISABLE_AUTOUPDATER="1",
                      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")

    def empty_list(stage):
        args.failure_phase = "project:claude_profile:" + stage
        completed = gate.child([str(args.claude), "plugin", "list", "--json"],
                               root=root, readonly=readonly, cwd=roots["workspace"],
                               env=native_env, timeout=60)
        require(type(completed.returncode) is int and completed.returncode == 0
                and completed.stderr == "", "Claude empty profile control failed")
        value = gate.publication.parse_json_bytes(completed.stdout.encode(),
                                                "Claude empty profile control", max_bytes=65536)
        require(type(value) is list and value == [], "Claude initial profile is not empty")

    def admitted_profile():
        # Check new native objects before the whole-tree hash reads their bytes.
        require_profile_anchor()
        require(profile_root.is_dir() and not profile_root.is_symlink(), "Claude profile root substituted")
        files, seen = [], 0
        limit = sum(name == ".claude" or name.startswith(".claude/") for name in old_home) + 11
        for path in profile_root.rglob("*"):
            seen += 1
            require(seen <= limit, "Claude initialization profile object count")
            name = path.relative_to(roots["home"]).as_posix()
            if name in old_home:
                continue  # Existing objects remain under the exact snapshot guard.
            require(not path.is_symlink(), "Claude initialization substituted a profile object")
            if path == backups:
                require(path.is_dir(), "Claude backup root substituted")
                continue
            require((path == profile or re.fullmatch(r"\.claude/backups/\.claude\.json\.backup\.[0-9]+", name))
                    and path.is_file() and path.stat().st_size <= 65536,
                    "Claude initialization created unexpected or oversized User state")
            files.append(path)
            require(len(files) <= 6, "Claude initialization profile or backup count")
        require(profile in files, "Claude initialization profile missing")
        metadata = {"firstStartTime", "firstStartVersion", "machineID"}
        migrations = {"opusProMigrationComplete": True, "sonnet1m45MigrationComplete": True,
                      "hasResetAutoModeOptInForDefaultOffer": True, "seenNotifications": {},
                      "migrationVersion": 13}
        documents = {}
        for path in files:
            value = gate.read_json(path, limit=65536)
            require(type(value) is dict and set(value) <= metadata | migrations.keys()
                    and all(type(value[key]) is str and 0 < len(value[key]) <= 256
                            for key in metadata & value.keys())
                    and all(type(value[key]) is type(expected) and value[key] == expected
                            for key, expected in migrations.items() if key in value),
                    "Claude initialization exceeded first-start metadata")
            if path == profile:
                require(metadata <= value.keys(), "Claude first-start metadata is incomplete")
            documents[path] = value
        require(all(all(documents[profile].get(key) == value for key, value in document.items())
                    for document in documents.values()), "Claude backup metadata differs from initialized profile")

    empty_list("initialize")
    admitted_profile()
    after = managed.snapshot_paths(paths)
    require(all(after[key] == value for key, value in before.items() if key != "home"),
            "Claude initialization changed non-profile fixture state")
    new_home = {entry[0]: entry[1:] for entry in after["home"]}
    require(all(new_home.get(name) == entry for name, entry in old_home.items()),
            "Claude initialization changed existing User state")
    require(all(name in old_home or name == ".claude" or name.startswith(".claude/") for name in new_home),
            "Claude initialization created state outside its profile")
    # This is the only accepted User baseline. The second control and the
    # public installer both compare to these exact bytes, types and modes.
    protected_user = {key: after[key] for key in user_paths(roots)}
    protected_user["records"] = record_bytes(roots["home"])
    empty_list("stable")
    admitted_profile()
    require(managed.snapshot_paths(paths) == after, "Claude native profile did not stabilize before UAP")
    return protected_user


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
    binary = args.binary.resolve(strict=True)
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
