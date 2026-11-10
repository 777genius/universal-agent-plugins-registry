"""Bounded saved-dependency proof for Marketing Kit; no account/runtime claim.

The legacy catalog matrix stays pinned independently. This case exercises the
released saved-environment protocol, including the transitive MCP closure.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import os
import stat
from pathlib import Path
import tomllib

CLI = {"version": "0.1.91", "tag": "agentplugins-v0.1.91",
       "commit": "4555aa53844ee0078e9036cd82638afd67f77c16",
       "binary_digest": "sha256:7cabae845789bff8691ddfc3888e43a2b66918a6606b2d9b68965c1df58a4626"}
# Historical signed v1 snapshots retain five clients; only the reviewed
# new root policy may add Copilot. Never relabel a legacy snapshot as six.
CLIENTS = ("codex", "cursor", "copilot", "claude", "gemini", "opencode")
LEGACY_CLIENTS = tuple(client for client in CLIENTS if client != "copilot")
NATIVE_TARGETS = ("codex", "claude")
PINS = {"777genius/marketing-kit": "0.1.0", "777genius/hubspot-crm": "0.1.0",
        "777genius/notion": "0.1.0", "777genius/playwright-bridge": "0.0.80"}
ROOT = "777genius/marketing-kit"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expected(snapshot, select):
    roots = [item for item in snapshot["distributions"] if item["id"] == ROOT and item["status"] == "active"]
    if not roots:
        return None
    policies = [policy for policy in roots[0]["release_policies"]
                if policy["release_sequence"] == 1 and policy["status"] == "active"]
    require(len(roots) == 1 and len(policies) == 1, "ambiguous managed root policy")
    source_clients = tuple(target["client"] for target in policies[0]["targets"])
    require(source_clients in (LEGACY_CLIENTS, CLIENTS), "unqualified managed target expansion")
    # Preserve the five-positive historical 0.1.91 case independently of the
    # corrected release used by the separate six-positive User/Project cases.
    clients = LEGACY_CLIENTS
    require(all(target["scopes"] == ["user"] and target["authentication"] == "required"
                and target["delivery"] == "managed" for target in policies[0]["targets"]),
            "unqualified managed target authority")
    closure = [select(snapshot, selector, clients, cli=CLI) for selector in PINS]
    root = closure[0]
    require(root["policy"]["minimum_installer_version"] == CLI["version"], "managed installer floor changed")
    require({item["client"] for item in root["policy"]["targets"]} == set(source_clients), "managed target policy changed")
    require(all(item["package_version"] == PINS[item["selector"]] for item in closure), "managed package version changed")
    require(root["release_sequence"] == 1, "unqualified managed release")
    proof = {"saved_add": "passed", "info": "passed", "status": "passed",
             "locked_replay": "passed_no_change", "update": "passed_no_change",
             "state_bytes_unchanged": True, "owned_artifacts_unchanged": True,
             "remove": "passed_orphan_cleanup", "retained_store_and_data": True,
             "doctor": "passed_read_only", "installation_count": 0,
             "retained_installation_count": 4, "active_binding_count": 0,
             "receipt_count": 0, "open_operation_count": 0,
             "native_plugin_listing": {client: "passed" if client in ("claude", "copilot") else "not_tested" for client in clients},
             "account_runtime": "not_tested", "oauth": "not_tested"}
    return {"cli": CLI, "root": ROOT, "targets": list(clients), "closure": closure,
            "edges": [{"parent": ROOT, "dependency": key, "version": value} for key, value in PINS.items() if key != ROOT],
            "associations": [{"distribution_id": item["distribution_id"], "release_sequence": item["release_sequence"], "client": client}
                             for item in closure for client in clients], "proof": proof}


def release_expected(snapshot, select):
    """Six positive User targets on the one reviewed corrected release."""
    import copy
    import catalog_project_readiness as project
    project_case = project.expected(snapshot, select)
    if project_case is None:
        return None
    case = copy.deepcopy(expected(snapshot, select))
    case.update(cli=copy.deepcopy(project_case["cli"]), placement_scope="user",
                targets=list(CLIENTS), closure=copy.deepcopy(project_case["closure"]),
                associations=copy.deepcopy(project_case["associations"]))
    case["proof"].update(
        native_plugin_listing={client: "passed" if client in ("claude", "copilot") else "not_tested" for client in CLIENTS},
        repeat_add="passed_no_change", repair="passed_same_signed_identity",
        locked_restore="passed_same_signed_closure", list="passed_exact_closure",
        foreign_state_unchanged=True, copilot_shared_surfaces=["copilot", "vscode"],
        vscode_qualification="not_granted")
    return case


def coverage(case):
    return set() if case is None else {(item["distribution_id"], item["release_sequence"], item["client"], "user") for item in case["associations"]}


def validate_lock(lock, case):
    require(lock.get("lock_version") == 1, "managed lock version")
    packages = lock.get("packages", [])
    require(len(packages) == len(case["closure"]) == 4, "managed lock closure")
    by_source = {item.get("source_key"): item for item in packages}
    require(len(by_source) == 4, "managed lock duplicate source")
    aliases = {}
    for selected in case["closure"]:
        package = by_source.get("directory:" + selected["distribution_id"], {})
        source = selected["package_source"]
        registry = package.get("source", {}).get("registry", {})
        require(package.get("version") == selected["package_version"] and
                package.get("tree_digest") == selected["tree_digest"] and
                package.get("manifest_digest") == selected["manifest_digest"] and
                package.get("digest_algorithm") == "agentplugins-tree-sha256-v1", "managed lock package identity")
        require(registry.get("distribution_id") == selected["distribution_id"] and
                registry.get("release_sequence") == selected["release_sequence"] and
                registry.get("product_id") == selected["product_id"] and
                registry.get("repository") == source["repository"] and registry.get("path", "") == source["path"] and
                registry.get("commit") == source["revision"], "managed lock source identity")
        require(len(package.get("targets", [])) == len(case["targets"]) and set(package["targets"]) == set(case["targets"]), "managed lock target closure")
        alias = package.get("alias")
        require(isinstance(alias, str) and bool(alias) and alias not in aliases.values(), "managed lock alias")
        aliases[selected["distribution_id"]] = alias
    root_alias = aliases[ROOT]
    for selected in case["closure"]:
        package = by_source["directory:" + selected["distribution_id"]]
        parents = package.get("required_by", [])
        expected_parents = [] if selected["distribution_id"] == ROOT else [{"alias": root_alias, "selector": {"kind": "version", "value": selected["package_version"]}}]
        require(parents == expected_parents, "managed lock dependency edges")
    return aliases


def validate_state(state, case, ctx, root, aliases, *, clients=None):
    clients = tuple(case["targets"]) if clients is None else tuple(clients)
    installations = state.get("installations", [])
    require(len(installations) == 4, "managed installation count")
    by_distribution = {item.get("directory", {}).get("distribution_id"): item for item in installations}
    require(len(by_distribution) == 4, "managed installation duplicate")
    receipts = state.get("environment_receipts", [])
    receipt_count = len(case["closure"]) * len(clients)
    require(len(receipts) == receipt_count and len({item.get("receipt_id") for item in receipts}) == receipt_count, "managed receipt count")
    expected_receipts, owned = set(), []
    for selected in case["closure"]:
        installation = by_distribution.get(selected["distribution_id"], {})
        directory, source = installation.get("directory", {}), installation.get("source", {})
        require(installation.get("origin_mode") == "directory" and installation.get("package", {}).get("version") == selected["package_version"] and
                installation.get("package", {}).get("manifest_digest") == selected["manifest_digest"], "managed installation package")
        require(source.get("repository") == selected["package_source"]["repository"] and
                source.get("package_subpath", "") == selected["package_source"]["path"] and
                source.get("resolved_revision") == selected["package_source"]["revision"] and
                source.get("tree_digest") == selected["tree_digest"], "managed installation source")
        require(directory.get("desired_release_sequence") == selected["release_sequence"] and
                directory.get("snapshot_sequence") == ctx["sequence"] and directory.get("snapshot_digest") == ctx["snapshot_digest"], "managed installation Directory identity")
        bindings = list(installation.get("clients", {}).values())
        require(len(bindings) == len(clients) and {binding.get("client_id") for binding in bindings} == set(clients), "managed bindings")
        for binding in bindings:
            require(binding.get("scope") == case.get("placement_scope", "user") and binding.get("materialization") == "materialized" and
                    binding.get("verification") in ("installation_verified", "package_validated"), "managed binding not materialized")
            revision = binding.get("package_revision", {})
            require(all(revision.get(key) == value for key, value in {
                "version": selected["package_version"], "resolved_revision": selected["package_source"]["revision"],
                "tree_digest": selected["tree_digest"], "manifest_digest": selected["manifest_digest"]}.items()), "managed binding revision")
            path = Path(binding["target_locator"])
            require(path.is_absolute() and path.resolve().is_relative_to(root.resolve()) and path.exists(), "managed owned path missing or escaped")
            owned.append(path)
            for native in binding.get("native_objects", []):
                if not native.get("path"):
                    continue
                path = Path(native["path"])
                require(path.is_absolute() and path.resolve().is_relative_to(root.resolve()) and path.exists(), "managed native path missing or escaped")
                owned.append(path)
            expected_receipts.add((aliases[selected["distribution_id"]], binding["client_id"], installation["installation_id"],
                                   binding["client_binding_id"], "directory:" + selected["distribution_id"], selected["tree_digest"]))
    actual_receipts = set()
    for receipt in receipts:
        require(receipt.get("environment_id") == case.get("placement_scope", "user") + "-default" and receipt.get("phase") == "committed", "managed receipt owner or phase")
        actual_receipts.add(tuple(receipt.get(key) for key in ("alias", "client_id", "installation_id", "client_binding_id", "source_key", "package_digest")))
    require(actual_receipts == expected_receipts, "managed receipt identity")
    return by_distribution, owned


def snapshot_paths(paths):
    """Snapshot owned files/directories without following symlink objects."""
    result = {}
    for name, root in sorted(paths.items()):
        members = [root]
        if root.is_dir() and not root.is_symlink():
            members.extend(sorted(root.rglob("*")))
        entries = []
        for path in members:
            relative = "." if path == root else path.relative_to(root).as_posix()
            try:
                info = path.lstat()
            except FileNotFoundError:
                entries.append((relative, "absent"))
                continue
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                entries.append((relative, mode, "symlink", os.readlink(path)))
            elif stat.S_ISREG(info.st_mode):
                entries.append((relative, mode, "file", hashlib.sha256(path.read_bytes()).hexdigest()))
            else:
                require(stat.S_ISDIR(info.st_mode), "unsupported managed snapshot object")
                entries.append((relative, mode, "directory"))
        result[name] = entries
    return result


def retained_state_summary(state):
    """Only fixed field names, JSON types and counts; no identifiers or data."""
    def field(value):
        kind = {type(None): "null", list: "array", dict: "object", bool: "boolean",
                int: "integer", float: "number", str: "string"}.get(type(value), "other")
        return {"type": kind, "count": len(value) if type(value) in (list, dict) else None}
    installations = state.get("installations")
    records = installations if isinstance(installations, list) else []
    return json.dumps({"installations": field(installations),
        "environment_receipts": field(state.get("environment_receipts")),
        "client_bindings": [field(item.get("clients")) for item in records if isinstance(item, dict)],
        "retained_installation_count": sum(item.get("data_retained") is True for item in records if isinstance(item, dict))}, sort_keys=True)


def validate_retained_state(state, case, ctx, root, aliases, initial):
    # Plain remove retains four data-owning installation records. Public list
    # and doctor count only installations with active bindings (read.go).
    summary = retained_state_summary(state)
    receipts = state.get("environment_receipts")
    require(receipts is None or (type(receipts) is list and receipts == []), "managed retained receipts remain: " + summary)
    retained, _ = validate_state({**state, "environment_receipts": []}, case, ctx, root, aliases, clients=())
    additions = set()
    for distribution, installation in retained.items():
        before = initial[distribution]
        require(installation.get("installation_id") == before["installation_id"] and
                all(installation.get(key) == before.get(key) for key in ("package", "source", "directory")) and
                installation.get("data_retained") is True and installation.get("clients") == {} and
                isinstance(installation.get("data_receipts"), dict) and bool(installation["data_receipts"]), "managed retained state identity: " + summary)
        old_data = before.get("data_receipts", {})
        if old_data:
            require(installation["data_receipts"] == old_data, "managed retained data receipts changed: " + summary)
            continue
        # finalizeLastBindingState creates data only when the installation had
        # none. It uses precisely the bindings removed in the last operation.
        backends = {(binding["physical_artifact_id"], binding["scope"]) for binding in before["clients"].values()
                    if binding["client_id"] not in case.get("native_removal_targets", NATIVE_TARGETS)}
        expected_ids = set()
        for backend, scope in backends:
            require(isinstance(backend, str) and backend not in ("", ".", "..") and Path(backend).name == backend and scope == case.get("placement_scope", "user"), "managed retained data backend")
            receipt_id = "data_" + hashlib.sha256((before["installation_id"] + "\0" + backend + "\0" + scope).encode()).hexdigest()[:24]
            locator = (root / "workspace" / ".uap" if case.get("placement_scope") == "project" else root / "state") / "plugin-data" / backend
            ownership = "sha256:" + hashlib.sha256(("agentplugins-plugin-data-v1\0" + receipt_id + "\0" + str(locator)).encode()).hexdigest()
            receipt = installation["data_receipts"].get(receipt_id, {})
            require(isinstance(receipt, dict) and set(receipt) <= {"data_receipt_id", "physical_backend_id", "scope", "locator", "ownership_digest", "state", "created_at", "updated_at"} and
                    all(receipt.get(key) == value for key, value in {"data_receipt_id": receipt_id,
                    "physical_backend_id": backend, "scope": scope, "locator": str(locator),
                    "ownership_digest": ownership, "state": "owned"}.items()), "managed new retained data identity")
            marker = locator / ".agentplugins-data-owner.json"
            require(locator.resolve().is_relative_to(root.resolve()) and locator.is_dir() and not locator.is_symlink() and stat.S_IMODE(locator.stat().st_mode) == 0o700 and
                    marker.is_file() and not marker.is_symlink() and stat.S_IMODE(marker.stat().st_mode) == 0o600 and
                    json.loads(marker.read_text()) == receipt and set(locator.iterdir()) == {marker}, "managed new retained data ownership")
            expected_ids.add(receipt_id)
            additions.update((backend, backend + "/.agentplugins-data-owner.json"))
        require(set(installation["data_receipts"]) == expected_ids, "managed new retained data receipt closure")
    return additions


def validate_retained_paths(before, after, additions):
    require(after["store"] == before["store"], "managed removal changed retained store")
    old, new = dict((item[0], item[1:]) for item in before["plugin-data"]), dict((item[0], item[1:]) for item in after["plugin-data"])
    if old.get(".") == ("absent",) and additions:
        require(new.get(".") == (0o700, "directory"), "managed retained data root")
        old.pop(".")
    require(all(new.get(path) == value for path, value in old.items()), "managed removal changed existing plugin data")
    require(set(new) - set(old) <= additions | ({"."} if additions else set()), "managed removal created unrelated plugin data")


def seed_runtime(tool_bin, env, codex):
    # Saved installs require a real Codex activation backend in the released
    # installer. Only expose the explicitly pinned tool, never an ambient CLI.
    require(codex.is_absolute(), "managed Codex path must be absolute")
    expected_codex = codex.resolve(strict=True)
    for name in ("node", "npm", "npx"):
        runtime = shutil.which(name)
        require(runtime is not None, "managed runtime tool missing")
        path = tool_bin / name
        require(not path.exists() and not path.is_symlink(), "managed runtime fixture collision")
        path.symlink_to(Path(runtime).resolve(strict=True))
    env["PATH"] = str(tool_bin) + ":/usr/bin:/bin"
    linked_codex = tool_bin / "codex"
    require(linked_codex.is_symlink() and linked_codex.resolve(strict=True) == expected_codex,
            "managed pinned Codex link missing or substituted")
    detected_codex = shutil.which("codex", path=env["PATH"])
    require(detected_codex is not None and Path(detected_codex).resolve(strict=True) == expected_codex,
            "managed pinned Codex is not executable")
    # Released saved-install preflight requires an executable for Cursor too,
    # but its adapter only prepares files and never invokes a native backend.
    # This fixture answers version detection and cannot fake native operations.
    cursor = tool_bin / "cursor"
    require(not cursor.exists() and not cursor.is_symlink(), "managed Cursor fixture collision")
    cursor.write_text('#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = --version ] || exit 1\necho 0.0.0\n')
    cursor.chmod(0o700)
    detected_cursor = shutil.which("cursor", path=env["PATH"])
    require(detected_cursor is not None and Path(detected_cursor).resolve(strict=True) == cursor.resolve(strict=True),
            "managed Cursor preparation fixture missing or substituted")


def failure_diagnostics(command, result):
    # Persist only fixed categories/client IDs, never response text, paths,
    # URLs, credentials or native logs. Useful even for credential-free smoke.
    body = (result.stdout + "\n" + result.stderr).lower()
    categories = {
        "client_missing": ("not detected", "client missing"),
        "activation_failed": ("activation", "marketplace", "plugin add"),
        "runtime_failed": ("npm", "node", "npx", "executable"),
        "directory_refused": ("directory", "snapshot", "installer version"),
        "network_failed": ("timeout", "timed out", "download", "http status"),
        "ownership_refused": ("ownership", "permission", "drift"),
        "transaction_failed": ("receipt", "transaction"),
    }
    return json.dumps({"command": command, "exit_code": result.returncode,
        "categories": sorted(key for key, patterns in categories.items() if any(value in body for value in patterns)),
        "clients": [name for name in CLIENTS if re.search(r"\b" + re.escape(name) + r"\b", body)]}, sort_keys=True)


def validate_codex_listing(value, identities, *, absent=False):
    """Recognize the released Codex installed[] contract, never text markers."""
    require(isinstance(value, dict) and isinstance(value.get("installed"), list), "managed Codex listing shape")
    expected = {name + "@" + marketplace for name, marketplace in identities}
    found = set()
    for entry in value["installed"]:
        require(isinstance(entry, dict) and all(isinstance(entry.get(key), str) and entry[key]
                for key in ("pluginId", "name", "marketplaceName")) and
                type(entry.get("installed")) is bool and type(entry.get("enabled")) is bool,
                "managed Codex listing entry")
        identity = entry["pluginId"]
        require(identity == entry["name"] + "@" + entry["marketplaceName"] and
                identity in expected and identity not in found, "managed Codex listing identity")
        found.add(identity)
    require(not absent or not found, "managed Codex external removal incomplete")


def remove_codex_plugins(command, identities):
    # These identities come from the four validated saved bindings. The fresh
    # profile may contain an inactive/absent plugin; both cases still require
    # exact native cleanup before attesting external removal to UAP.
    require(len(identities) == 4 and len({name for name, _ in identities}) == 4 and
            len({marketplace for _, marketplace in identities}) == 4 and
            all(re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) and
                re.fullmatch(r"agentplugins-[0-9a-f]{12}", marketplace)
                for name, marketplace in identities), "managed Codex removal identities")
    validate_codex_listing(command("plugin", "list", "--json"), identities)
    for name, marketplace in identities:
        command("plugin", "remove", name + "@" + marketplace, "--json", allow_absent=True)
        command("plugin", "marketplace", "remove", marketplace, "--json", allow_absent=True)
    validate_codex_listing(command("plugin", "list", "--json"), identities, absent=True)


def seed_foreign_state(roots):
    """Seed unrelated User Skills, native members and Project bytes for preservation."""
    paths = {"project": roots["workspace"]}
    for client, profile in {"codex": roots["home"] / ".codex", "cursor": roots["home"] / ".cursor",
                            "copilot": roots["home"] / ".copilot", "claude": roots["home"] / ".claude",
                            "gemini": roots["home"] / ".gemini", "opencode": roots["config"] / "opencode"}.items():
        path = profile / "skills/foreign-readiness-sentinel/SKILL.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Foreign Skill; preserve these exact bytes.\n")
        paths[client] = path.parent
    (roots["workspace"] / "foreign.txt").write_text("Foreign Project bytes.\n")
    configs = {}
    for path, key in ((roots["home"] / ".gemini/settings.json", "mcpServers"),
                      (roots["config"] / "opencode/opencode.json", "mcp")):
        member = {"type": "remote", "url": "https://foreign.invalid/mcp"} if key == "mcp" else {"url": "https://foreign.invalid/mcp"}
        path.write_text(json.dumps({key: {"foreign-readiness-sentinel": member}}))
        configs[path] = (key, member)
    return paths, configs


def validate_foreign_state(paths, before, configs):
    require(snapshot_paths(paths) == before, "managed operation changed foreign Skill or Project bytes")
    import catalog_publication_readiness as gate
    for path, (key, member) in configs.items():
        require(not path.is_symlink() and gate.read_json(path).get(key, {}).get("foreign-readiness-sentinel") == member,
                "managed operation changed foreign native member")


def validate_release_user_bindings(installations, case, root):
    """Check actual saved bindings, committed mutation receipts and shared effects."""
    import catalog_publication_readiness as gate
    import catalog_project_readiness as project
    require(case["placement_scope"] == "user" and tuple(case["targets"]) == CLIENTS,
            "release User binding contract")
    for selected in case["closure"]:
        bindings = installations[selected["distribution_id"]]["clients"]
        package = root / "state/store/packages/agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
        skills, servers = project.package_components(package)
        for client in CLIENTS:
            matches = [binding for binding in bindings.values() if binding["client_id"] == client]
            require(len(matches) == 1, "release User native binding missing or ambiguous")
            binding = matches[0]
            expected_surfaces = ["copilot", "vscode"] if client == "copilot" else [client]
            require(binding.get("scope") == "user" and binding.get("affected_surfaces") == expected_surfaces,
                    "release User native binding scope or surfaces")
            backend = binding.get("physical_artifact_id")
            require(isinstance(backend, str) and backend not in ("", ".", "..") and Path(backend).name == backend,
                    "release User physical backend identity invalid")
            target = Path(binding["target_locator"])
            project.confined(target, root)
            skill_root = target / (".agentplugins-runtime/skills" if client == "claude" else "skills")
            for name, source in skills.items():
                path = skill_root / name
                project.confined(path, root)
                require(gate.registry.directory_tree_digest(path) == gate.registry.directory_tree_digest(source),
                        "release User projected Skill bytes changed")
            if client in ("gemini", "opencode"):
                objects = binding.get("native_objects", [])
                for name, source in skills.items():
                    matches = [item for item in objects if item.get("logical_name") == name and "skill" in item.get("kind", "")]
                    require(len(matches) == 1, "release User native Skill receipt missing or ambiguous")
                    path = Path(matches[0].get("path", ""))
                    project.confined(path, root)
                    require(gate.registry.directory_tree_digest(path) == gate.registry.directory_tree_digest(source),
                            "release User native Skill bytes changed")
                for name, source in servers.items():
                    matches = [item for item in objects if item.get("logical_name") == name and "mcp" in item.get("kind", "")]
                    require(len(matches) == 1, "release User native MCP receipt missing or ambiguous")
                    path = Path(matches[0].get("path", ""))
                    project.confined(path, root)
                    native = project.config_servers(path, client)
                    project.validate_server(native.get(name), source, target, cli_digest=case["cli"]["binary_digest"],
                                            project_root=root, data_root=root / "state/plugin-data" / binding["physical_artifact_id"])
            receipts = binding.get("receipts", [])
            require(isinstance(receipts, list) and bool(receipts) and all(
                receipt.get("client_binding_id") == binding["client_binding_id"]
                and receipt.get("phase") == "committed" and receipt.get("active_path") == str(target)
                and isinstance(receipt.get("operation_id"), str) and bool(receipt["operation_id"])
                for receipt in receipts), "release User committed mutation receipt missing or substituted")
            if client == "copilot":
                gate.native_binding(list(bindings.values()), client)
                marketplace = gate.read_json(target / ".github/plugin/marketplace.json")
                require(marketplace.get("name") == gate.managed_marketplace(binding["physical_artifact_id"])
                        and len(marketplace.get("plugins", [])) == 1
                        and marketplace["plugins"][0].get("name") == selected["product_id"]
                        and marketplace["plugins"][0].get("version") == selected["package_version"]
                        and marketplace["plugins"][0].get("source") == ".",
                        "release User Copilot marketplace identity")


def seed_retained_data(state, root):
    """Put test application bytes only in already authenticated owned data slots."""
    from contextlib import ExitStack
    import catalog_project_readiness as project
    import catalog_publication_readiness as gate
    require(len(state.get("installations", [])) == 4, "User retained data closure")
    require(root.is_absolute() and root.resolve(strict=True) == root and not root.is_symlink(),
            "User retained data disposable root substituted")
    data_root = root / "state/plugin-data"
    project.confined(data_root, root)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    sentinel_name = "readiness-retained-data.txt"
    with ExitStack() as descriptors:
        def directory(path, parent=None):
            descriptor = os.open(path, directory_flags, dir_fd=parent)
            descriptors.callback(os.close, descriptor)
            return descriptor

        root_fd = directory(root)
        state_fd = directory("state", root_fd)
        data_fd = directory("plugin-data", state_fd)
        prepared, identities = [], set()
        # Preflight every owner before creating any fixture. Open directory
        # descriptors stay anchored to the fresh root if pathnames are swapped.
        for installation in state["installations"]:
            require(installation.get("data_retained") is True and installation.get("clients") == {}
                    and bool(installation.get("data_receipts")), "User retained data owner missing")
            for receipt in installation["data_receipts"].values():
                locator = Path(receipt["locator"])
                project.confined(locator, root)
                require(locator.parent == data_root and receipt.get("scope") == "user",
                        "User retained data locator differs from owned User data root")
                marker = locator / ".agentplugins-data-owner.json"
                project.confined(marker, root)
                locator_fd = directory(locator.name, data_fd)
                info = os.fstat(locator_fd)
                identity = (info.st_dev, info.st_ino)
                require(identity not in identities, "User retained data owner duplicated")
                identities.add(identity)
                marker_fd = os.open(marker.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                    dir_fd=locator_fd)
                with os.fdopen(marker_fd, "rb") as source:
                    require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "User retained data marker is not a regular file")
                    body = source.read(gate.LIMIT + 1)
                require(gate.publication.parse_json_bytes(body, "retained data owner", max_bytes=gate.LIMIT) == receipt,
                        "User retained data ownership marker differs")
                try:
                    os.stat(sentinel_name, dir_fd=locator_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("User retained data fixture collision")
                prepared.append(locator_fd)
        for locator_fd in prepared:
            descriptor = os.open(sentinel_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=locator_fd)
            with os.fdopen(descriptor, "wb") as target:
                target.write(b"Credential-free retained application data.\n")


def run(args, root, case, ctx):
    # The composition owner provides confinement and the legacy native-listing
    # parser; no third client engine or portable semantics are introduced here.
    import catalog_publication_readiness as gate
    clients = tuple(case["targets"])
    scope = case.get("placement_scope", "user")
    release_user = scope == "user" and clients == CLIENTS
    require((scope == "user" and clients in (LEGACY_CLIENTS, CLIENTS)) or
            (scope == "project" and clients == CLIENTS and case.get("signed_source_scope") == "user"),
            "unqualified managed lifecycle targets or scope")
    if release_user:
        import catalog_project_readiness as project
        require(case["cli"] == project.reviewed_release()["cli"], "wrong six-target User release authority")
    binary_arg = getattr(args, "project_binary" if scope == "project" or release_user else "managed_binary", None)
    require(binary_arg is not None, "missing managed released binary")
    binary = binary_arg.resolve(strict=True)
    require(gate.digest(binary.read_bytes()) == case["cli"]["binary_digest"], "wrong managed released binary")
    codex = getattr(args, "codex", None)
    require(isinstance(codex, Path) and codex.is_absolute(), "managed Codex path must be absolute")
    require(codex.resolve(strict=True).is_file(), "managed Codex executable missing")
    prefix = "project" if scope == "project" else "release_user" if release_user else "managed"
    args.failure_phase = prefix + ":prepare"
    root.mkdir(mode=0o700)
    roots, env = gate.isolated_environment(root, ctx["directory_origin"], (codex, args.claude, args.copilot, args.opencode))
    readonly = (*gate.tool_paths(args), binary.parent)
    seed_runtime(root / "bin", env, codex)
    state_root = roots["workspace"] / ".uap" if scope == "project" else roots["state"]
    intent_root = roots["workspace"] if scope == "project" else state_root
    scope_args = ["--scope", "project", "--project-root", str(roots["workspace"])] if scope == "project" else ["--scope", "user"] if release_user else []
    if release_user:
        foreign_paths, foreign_configs = seed_foreign_state(roots)
        foreign_before = snapshot_paths(foreign_paths)
    if scope == "project":
        import catalog_project_readiness as project
        protected_user = snapshot_paths(project.user_paths(roots))

    def command(*argv):
        args.failure_phase = prefix + ":" + argv[0]
        result = gate.child([str(binary), *argv, *scope_args, "--format", "json"], root=root, readonly=readonly,
                            env=env, cwd=roots["workspace"], timeout=600)
        if result.returncode != 0:
            if callable(getattr(args, "on_failure", None)):
                args.on_failure(result)
            print("managed CLI failure: " + failure_diagnostics(argv[0], result), file=sys.stderr, flush=True)
            raise ValueError("managed CLI command failed")
        value = gate.publication.parse_json_bytes(result.stdout.encode(), "managed CLI", max_bytes=gate.LIMIT)
        require(isinstance(value, dict), "managed CLI JSON shape")
        if release_user:
            validate_foreign_state(foreign_paths, foreign_before, foreign_configs)
        if scope == "project":
            project.validate_user_isolation(protected_user, roots)
        if argv[0] in ("add", "info", "list", "doctor"):
            require(value.get("command") == argv[0] and value.get("result") == "success" and isinstance(value.get("data"), dict), "managed CLI envelope")
            return value["data"]
        return value

    added = command("add", "marketing-kit", "--target", ",".join(clients))
    require(added.get("environment", {}).get("saved") is True and added.get("outcome") == "completed" and len(added.get("actions", [])) == len(PINS) * len(clients), "managed saved add incomplete")
    require(scope != "project" or added.get("scope") == "project", "managed placement scope")
    state_file = state_root / "state-v2.json"
    manifest, lock_path = intent_root / "uap.toml", intent_root / "uap.lock"
    # Dependency file location is a released output, but must remain confined to
    # the new state root rather than trusting arbitrary JSON paths.
    environment = added["environment"]
    require(Path(environment["manifest_path"]).resolve() == manifest.resolve() and
            Path(environment["lock_path"]).resolve() == lock_path.resolve(), "managed environment paths")
    lock = gate.read_json(lock_path)
    aliases = validate_lock(lock, case)
    if scope == "project" or release_user:
        import catalog_project_readiness as project
        project.validate_operation(added, aliases, clients, operation="add", expected_scope=scope)
    requirements = tomllib.loads(manifest.read_text())
    require(set(requirements.get("dependencies", {})) == {aliases[ROOT]} and
            requirements.get("targets") == {client: [aliases[ROOT]] for client in clients}, "managed root intent")
    installations, owned = validate_state(gate.read_json(state_file), case, ctx, root, aliases)
    if scope == "project" or release_user:
        import catalog_project_readiness as project
        project.validate_operation(added, aliases, clients, operation="add", expected_scope=scope, installations=installations)
    # Immutable package acquisition uses the shared cache store in released CLI.
    store = roots["state"] / "store"
    for selected in case["closure"]:
        package = store / "packages" / "agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
        require(gate.registry.directory_tree_digest(package) == selected["tree_digest"] and
                gate.digest((package / "plugin.json").read_bytes()) == selected["manifest_digest"], "managed immutable package bytes")
        if selected["distribution_id"] == ROOT:
            require(tomllib.loads((package / "uap.toml").read_text()) == {"schema_version": 1, "dependencies": {key: version for key, version in PINS.items() if key != ROOT}}, "managed declared dependency closure")
        info = command("info", aliases[selected["distribution_id"]])
        require(info.get("installation_id") == installations[selected["distribution_id"]]["installation_id"] and
                {item["client_id"] for item in info.get("clients", [])} == set(clients) and
                (not release_user or len(info["clients"]) == len(clients)), "managed info identity")

    def native(client, installed):
        # Verify the actual client-owned registry for each immutable package.
        # A prepared Skills file alone cannot qualify Copilot native delivery.
        tool = args.claude if client == "claude" else args.copilot
        for selected in case["closure"]:
            binding = gate.native_binding(list(installations[selected["distribution_id"]]["clients"].values()), client)
            gate.native_listing(tool, env, roots["workspace"], selected["product_id"], installed, root=root, readonly=readonly,
                                expected_marketplace=gate.managed_marketplace(binding["physical_artifact_id"]),
                                expected_version=selected["package_version"], expected_path=Path(binding["target_locator"]))
    if scope == "project":
        import catalog_project_readiness as project
        project.validate_native_resources(installations, case, roots["workspace"], store)
    else:
        native("claude", True)
        if release_user:
            native("copilot", True)
            validate_release_user_bindings(installations, case, root)
            listed = command("list")
            require({item.get("installation_id") for item in listed.get("installations", [])} ==
                    {item["installation_id"] for item in installations.values()} and len(listed["installations"]) == 4,
                    "managed installed list closure")
    status = command("deps", "status")
    require(status.get("scope") == scope and status.get("pending_recovery") is False and len(status.get("facts", [])) == len(PINS) * len(clients), "managed status incomplete")
    require({(item.get("alias"), item.get("client_id")) for item in status["facts"]} == {(alias, client) for alias in aliases.values() for client in clients}, "managed status identities")
    require(all(item.get("owner") == scope + "-default" and set(item.get("facts", [])) <= {"auth_unverified", "auth_pending", "activation_manual", "activation_prepared"} for item in status["facts"]), "managed status drift")
    immutable = {"manifest": manifest, "lock": lock_path, "state": state_file, "store": store,
                 **{f"owned-{index}": path for index, path in enumerate(owned)}}
    replays = (("add", "marketing-kit", "--target", ",".join(clients)),) if scope == "project" or release_user else ()
    for argv in (*replays, ("install", "--locked", "--yes"), ("update", "marketing-kit")):
        before = snapshot_paths(immutable)
        result = command(*argv)
        require(result.get("outcome") == "completed" and result.get("results") == [] and
                len(result.get("actions", [])) == len(PINS) * len(clients) and all(item.get("action") == "unchanged" for item in result["actions"]), "managed replay changed plan")
        if scope == "project" or release_user:
            project.validate_operation(result, aliases, clients, operation="unchanged", expected_scope=scope)
        require(snapshot_paths(immutable) == before, "managed replay mutated state or artifacts")
    if scope == "project" or release_user:
        portable_before = snapshot_paths({"manifest": manifest, "lock": lock_path})
        repaired = command("repair", "marketing-kit", "--target", ",".join(clients), "--yes")
        project.validate_operation(repaired, aliases, clients, operation="repair", expected_scope=scope, installations=installations)
        repaired_installations, repaired_owned = validate_state(gate.read_json(state_file), case, ctx, root, aliases)
        require({key: item["installation_id"] for key, item in repaired_installations.items()} ==
                {key: item["installation_id"] for key, item in installations.items()}, "Project repair changed closure identity")
        require(snapshot_paths({"manifest": manifest, "lock": lock_path}) == portable_before, "Project repair changed portable pins")
        if scope == "project":
            project.validate_native_resources(repaired_installations, case, roots["workspace"], store)
        else:
            validate_release_user_bindings(repaired_installations, case, root)
        installations, owned = repaired_installations, repaired_owned
        if release_user:
            native("claude", True)
            native("copilot", True)
    saved_intent = (manifest.read_bytes(), lock_path.read_bytes()) if release_user else None
    retained = {"store": store, "plugin-data": state_root / "plugin-data"}
    def remove_closure():
        retained_before = snapshot_paths(retained)
        if scope == "user":
            require(command("remove", "marketing-kit", "--target", "claude").get("outcome") == "completed", "managed Claude removal")
            native("claude", False)
            if "copilot" in clients:
                native("copilot", True)

            def codex_command(*argv, allow_absent=False):
                args.failure_phase = "managed:codex_external_remove"
                result = gate.child([str(codex), *argv], root=root, readonly=readonly,
                                    env={**env, "CODEX_HOME": str(roots["home"] / ".codex")},
                                    cwd=roots["workspace"], timeout=60)
                if result.returncode != 0:
                    # This is the same idempotent negative recognized by the released
                    # adapter. Every removal is followed by a strict absence listing.
                    if allow_absent and "not configured or installed" in result.stdout + result.stderr:
                        return None
                    if callable(getattr(args, "on_failure", None)):
                        args.on_failure(result)
                    print("managed CLI failure: " + failure_diagnostics("remove", result), file=sys.stderr, flush=True)
                    raise ValueError("managed Codex external command failed")
                if argv[:2] == ("plugin", "list"):
                    return gate.publication.parse_json_bytes(result.stdout.encode(), "managed Codex listing", max_bytes=gate.LIMIT)
                return None

            identities = [(selected["product_id"], gate.managed_marketplace(next(binding for binding in
                installations[selected["distribution_id"]]["clients"].values() if binding["client_id"] == "codex")["physical_artifact_id"]))
                for selected in case["closure"]]
            remove_codex_plugins(codex_command, identities)
            require(command("remove", "marketing-kit", "--target", "codex", "--external-uninstalled").get("outcome") == "completed", "managed Codex removal")
            partial = gate.read_json(state_file)
            remaining = tuple(client for client in clients if client not in NATIVE_TARGETS)
            validate_state(partial, case, ctx, root, aliases, clients=remaining)
        require(command("remove", "marketing-kit").get("outcome") == "completed", "managed orphan removal")
        state = gate.read_json(state_file)
        try:
            data_additions = validate_retained_state(state, case, ctx, root, aliases, installations)
        except (ValueError, OSError) as error:
            reason = str(error) if type(error) is ValueError else type(error).__name__
            raise ValueError("managed final state invalid: " + reason + "; " + retained_state_summary(state)) from None
        require(gate.read_json(lock_path).get("packages") == [], "managed orphan lock remains")
        # Native objects can be shared registries retained for an empty profile;
        # the per-binding target locators must all have disappeared.
        require(all(not Path(binding["target_locator"]).exists() and not Path(binding["target_locator"]).is_symlink()
                    for installation in installations.values() for binding in installation["clients"].values()), "managed owned package remains")
        validate_retained_paths(retained_before, snapshot_paths(retained), data_additions)
        require(command("list").get("installations") == [], "managed list not empty")
        if scope == "project":
            project.validate_native_cleanup(installations, roots["workspace"])
            # The authenticated Directory cache may be populated. Native User
            # configuration, portable intent and durable User state stay unchanged.
            project.validate_user_isolation(protected_user, roots)
        else:
            native("claude", False)
            if release_user:
                project.validate_native_cleanup(installations, root)
                native("copilot", False)
    remove_closure()
    if release_user:
        seed_retained_data(gate.read_json(state_file), root)
        removed_data = snapshot_paths(retained)
        original_ids = {key: item["installation_id"] for key, item in installations.items()}
        manifest.write_bytes(saved_intent[0])
        lock_path.write_bytes(saved_intent[1])
        restored = command("install", "--locked", "--yes")
        project.validate_operation(restored, aliases, clients, operation="add", expected_scope=scope)
        require(validate_lock(gate.read_json(lock_path), case) == aliases, "User restore changed locked closure")
        installations, owned = validate_state(gate.read_json(state_file), case, ctx, root, aliases)
        project.validate_operation(restored, aliases, clients, operation="add", expected_scope=scope, installations=installations)
        require({key: item["installation_id"] for key, item in installations.items()} == original_ids,
                "User locked restore changed retained installation identity")
        require(snapshot_paths(retained) == removed_data, "User locked restore changed retained store or data")
        validate_release_user_bindings(installations, case, root)
        native("claude", True)
        native("copilot", True)
        remove_closure()
    before = gate.snapshot_roots(roots)
    doctor = command("doctor")
    gate.validate_doctor({"command": "doctor", "result": "success", "data": doctor}, post_remove=True)
    require(doctor.get("read_only") is True and doctor.get("installation_count") == 0 and doctor.get("open_operation_count") == 0 and
            gate.snapshot_roots(roots) == before, "managed doctor not clean/read-only")
    args.failure_phase = prefix + ":complete"
