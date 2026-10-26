"""Bounded saved-dependency proof for Marketing Kit; no account/runtime claim.

The legacy catalog matrix stays pinned independently. This case exercises the
released saved-environment protocol, including the transitive MCP closure.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
import tomllib

CLI = {"version": "0.1.91", "tag": "agentplugins-v0.1.91",
       "commit": "4555aa53844ee0078e9036cd82638afd67f77c16",
       "binary_digest": "sha256:7cabae845789bff8691ddfc3888e43a2b66918a6606b2d9b68965c1df58a4626"}
PROJECT_CLI = {"version": "0.1.93", "tag": "agentplugins-v0.1.93",
               "commit": "d5c16856cef67a1457704971d46765739141ab08",
               "binary_digest": "sha256:af9b9519fa66ff5705f94c6cff20adb3c921acdcc41ed8087ef40f7327a07b50"}
CLIENTS = ("codex", "cursor", "claude", "gemini", "opencode")
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
    closure = [select(snapshot, selector, CLIENTS, cli=CLI) for selector in PINS]
    root = closure[0]
    require(root["policy"]["minimum_installer_version"] == CLI["version"], "managed installer floor changed")
    require({item["client"] for item in root["policy"]["targets"]} == set(CLIENTS), "managed target policy changed")
    require(all(item["package_version"] == PINS[item["selector"]] for item in closure), "managed package version changed")
    require(root["release_sequence"] == 1, "unqualified managed release")
    proof = {"saved_add": "passed", "info": "passed", "status": "passed",
             "locked_replay": "passed_no_change", "update": "passed_no_change",
             "state_bytes_unchanged": True, "owned_artifacts_unchanged": True,
             "remove": "passed_orphan_cleanup", "retained_store_and_data": True,
             "doctor": "passed_read_only", "installation_count": 0,
             "receipt_count": 0, "open_operation_count": 0,
             "native_plugin_listing": {client: "passed" if client == "claude" else "not_tested" for client in CLIENTS},
             "account_runtime": "not_tested", "oauth": "not_tested"}
    result = {"cli": CLI, "scope": "user", "root": ROOT, "targets": list(CLIENTS), "closure": closure,
            "edges": [{"parent": ROOT, "dependency": key, "version": value} for key, value in PINS.items() if key != ROOT],
            "associations": [{"distribution_id": item["distribution_id"], "release_sequence": item["release_sequence"], "client": client}
                             for item in closure for client in CLIENTS], "proof": proof}
    qualified = [target for item in closure for target in item["policy"]["targets"] if target["client"] in CLIENTS]
    require(len(qualified) == 20 and all("user" in target["scopes"] and set(target["scopes"]) <= {"user", "project"} for target in qualified), "managed scope policy changed")
    if any("project" in target["scopes"] for target in qualified):
        require(all(set(target["scopes"]) == {"user", "project"} for target in qualified), "incomplete managed project policy")
        project_proof = {**proof, "native_plugin_listing": {client: "not_tested" for client in CLIENTS},
                         "user_owned_paths_unchanged": True, "shared_immutable_cache": True}
        result["project"] = {**result, "cli": PROJECT_CLI, "scope": "project", "proof": project_proof}
    return result


def coverage(case):
    return set() if case is None else {(item["distribution_id"], item["release_sequence"], item["client"]) for item in case["associations"]}


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
        require(len(package.get("targets", [])) == 5 and set(package["targets"]) == set(CLIENTS), "managed lock target closure")
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


def validate_state(state, case, ctx, root, aliases):
    scope = case.get("scope", "user")
    environment_id = "project-default" if scope == "project" else "user-default"
    installations = state.get("installations", [])
    require(len(installations) == 4, "managed installation count")
    by_distribution = {item.get("directory", {}).get("distribution_id"): item for item in installations}
    require(len(by_distribution) == 4, "managed installation duplicate")
    receipts = state.get("environment_receipts", [])
    require(len(receipts) == 20 and len({item.get("receipt_id") for item in receipts}) == 20, "managed receipt count")
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
        require(len(bindings) == 5 and {binding.get("client_id") for binding in bindings} == set(CLIENTS), "managed bindings")
        for binding in bindings:
            require(binding.get("scope") == scope and binding.get("materialization") == "materialized" and
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
        require(receipt.get("environment_id") == environment_id and receipt.get("phase") == "committed", "managed receipt owner or phase")
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


def run(args, root, case, ctx):
    root.mkdir(mode=0o700)
    run_case(args, root / "user", case, ctx)
    if "project" in case:
        run_case(args, root / "project", case["project"], ctx)


def run_case(args, root, case, ctx):
    # The composition owner provides confinement and the legacy native-listing
    # parser; no third client engine or portable semantics are introduced here.
    import catalog_publication_readiness as gate
    scope = case.get("scope", "user")
    environment_id = "project-default" if scope == "project" else "user-default"
    binary = getattr(args, "project_binary" if scope == "project" else "managed_binary", None)
    require(binary is not None and gate.digest(binary.read_bytes()) == case["cli"]["binary_digest"], "wrong managed released binary")
    args.failure_phase = "managed:" + scope + ":prepare"
    root.mkdir(mode=0o700)
    roots, env = gate.isolated_environment(root, ctx["directory_origin"], (args.claude, args.copilot, args.opencode))
    readonly = (*gate.tool_paths(args), binary.absolute().parent)
    for name in ("codex", "cursor"):
        stub = root / "bin" / name
        require(not stub.exists() and not stub.is_symlink(), "managed fixture collision")
        stub.write_text('#!/bin/sh\n[ "$1" = --version ] || exit 1\necho 0.0.0\n')
        stub.chmod(0o700)

    protected = {name: roots["state"] / name for name in ("state-v2.json", "uap.toml", "uap.lock", "managed", "plugin-data", "operations-v2", "mutation.lock", "environment.lock")}
    protected["user-home"] = roots["home"]
    protected["user-config"] = roots["config"]
    protected_before = snapshot_paths(protected)
    env["NPM_CONFIG_CACHE"] = str(roots["tmp"] / "npm-cache")

    def command(*argv):
        args.failure_phase = "managed:" + scope + ":" + argv[0]
        scoped = (*argv, "--scope", "project") if scope == "project" else argv
        result = gate.child([str(binary), *scoped, "--format", "json"], root=root, readonly=readonly,
                            env=env, cwd=roots["workspace"], timeout=600)
        require(result.returncode == 0, "managed CLI failed: " + argv[0])
        if scope == "project":
            require(snapshot_paths(protected) == protected_before, "project operation changed user owned paths")
        value = gate.publication.parse_json_bytes(result.stdout.encode(), "managed CLI", max_bytes=gate.LIMIT)
        require(isinstance(value, dict), "managed CLI JSON shape")
        if argv[0] in ("add", "info", "list", "doctor"):
            require(value.get("command") == argv[0] and value.get("result") == "success" and isinstance(value.get("data"), dict), "managed CLI envelope")
            return value["data"]
        return value

    added = command("add", "marketing-kit", "--target", ",".join(CLIENTS))
    require(added.get("environment", {}).get("saved") is True and added.get("outcome") == "completed" and len(added.get("actions", [])) == 20, "managed saved add incomplete")
    namespace = roots["workspace"] / ".uap" if scope == "project" else roots["state"]
    intent_root = roots["workspace"] if scope == "project" else roots["state"]
    state_file = namespace / "state-v2.json"
    manifest, lock_path = intent_root / "uap.toml", intent_root / "uap.lock"
    # Dependency file location is a released output, but must remain confined to
    # the new state root rather than trusting arbitrary JSON paths.
    environment = added["environment"]
    require(Path(environment["manifest_path"]).resolve() == manifest.resolve() and
            Path(environment["lock_path"]).resolve() == lock_path.resolve(), "managed environment paths")
    lock = gate.read_json(lock_path)
    aliases = validate_lock(lock, case)
    requirements = tomllib.loads(manifest.read_text())
    require(set(requirements.get("dependencies", {})) == {aliases[ROOT]} and
            requirements.get("targets") == {client: [aliases[ROOT]] for client in CLIENTS}, "managed root intent")
    installations, owned = validate_state(gate.read_json(state_file), case, ctx, roots["workspace"] if scope == "project" else root, aliases)
    store = roots["state"] / "store"
    for selected in case["closure"]:
        package = store / "packages" / "agentplugins-tree-sha256-v1" / selected["tree_digest"].removeprefix("sha256:") / "package"
        require(gate.registry.directory_tree_digest(package) == selected["tree_digest"] and
                gate.digest((package / "plugin.json").read_bytes()) == selected["manifest_digest"], "managed immutable package bytes")
        if selected["distribution_id"] == ROOT:
            require(tomllib.loads((package / "uap.toml").read_text()) == {"schema_version": 1, "dependencies": {key: version for key, version in PINS.items() if key != ROOT}}, "managed declared dependency closure")
        info = command("info", aliases[selected["distribution_id"]])
        require(info.get("installation_id") == installations[selected["distribution_id"]]["installation_id"] and
                {item["client_id"] for item in info.get("clients", [])} == set(CLIENTS), "managed info identity")

    def native(installed):
        if scope == "project":
            return
        for selected in case["closure"]:
            binding = gate.native_binding(list(installations[selected["distribution_id"]]["clients"].values()), "claude")
            gate.native_listing(args.claude, env, roots["workspace"], selected["product_id"], installed, root=root, readonly=readonly,
                                expected_marketplace=gate.managed_marketplace(binding["physical_artifact_id"]),
                                expected_version=selected["package_version"], expected_path=Path(binding["target_locator"]))
    native(True)
    status = command("deps", "status")
    require(status.get("scope") == scope and status.get("pending_recovery") is False and len(status.get("facts", [])) == 20, "managed status incomplete")
    require({(item.get("alias"), item.get("client_id")) for item in status["facts"]} == {(alias, client) for alias in aliases.values() for client in CLIENTS}, "managed status identities")
    require(all(item.get("owner") == environment_id and set(item.get("facts", [])) <= {"auth_unverified", "auth_pending", "activation_manual", "activation_prepared"} for item in status["facts"]), "managed status drift")
    immutable = {"manifest": manifest, "lock": lock_path, "state": state_file, "store": store,
                 **{f"owned-{index}": path for index, path in enumerate(owned)}}
    for argv in (("install", "--locked", "--yes"), ("update", "marketing-kit")):
        before = snapshot_paths(immutable)
        result = command(*argv)
        require(result.get("outcome") == "completed" and result.get("results") == [] and
                len(result.get("actions", [])) == 20 and all(item.get("action") == "unchanged" for item in result["actions"]), "managed replay changed plan")
        require(snapshot_paths(immutable) == before, "managed replay mutated state or artifacts")
    retained = {"store": store, "plugin-data": namespace / "plugin-data"}
    retained_before = snapshot_paths(retained)
    require(command("remove", "marketing-kit", "--target", "claude").get("outcome") == "completed", "managed native removal")
    native(False)
    partial = gate.read_json(state_file)
    require(len(partial.get("environment_receipts", [])) == 16 and
            all("claude" not in {binding["client_id"] for binding in item["clients"].values()} for item in partial["installations"]), "managed partial removal")
    require(command("remove", "marketing-kit", "--external-uninstalled").get("outcome") == "completed", "managed orphan removal")
    state = gate.read_json(state_file)
    require(state.get("installations") == [] and state.get("environment_receipts", []) == [], "managed orphan state remains")
    require(gate.read_json(lock_path).get("packages") == [], "managed orphan lock remains")
    # Native objects can be shared registries retained for an empty profile;
    # the per-binding target locators must all have disappeared.
    require(all(not Path(binding["target_locator"]).exists() and not Path(binding["target_locator"]).is_symlink()
                for installation in installations.values() for binding in installation["clients"].values()), "managed owned package remains")
    require(snapshot_paths(retained) == retained_before, "managed removal changed retained store/data")
    require(command("list").get("installations") == [], "managed list not empty")
    native(False)
    before = gate.snapshot_roots(roots)
    doctor = command("doctor")
    gate.validate_doctor({"command": "doctor", "result": "success", "data": doctor}, post_remove=True)
    require(doctor.get("read_only") is True and doctor.get("installation_count") == 0 and doctor.get("open_operation_count") == 0 and
            gate.snapshot_roots(roots) == before, "managed doctor not clean/read-only")
    if scope == "project":
        require(snapshot_paths(protected) == protected_before, "project lifecycle changed user owned paths")
        require(not (namespace / "store").exists(), "project unexpectedly copied shared content store")
    args.failure_phase = "managed:" + scope + ":complete"
