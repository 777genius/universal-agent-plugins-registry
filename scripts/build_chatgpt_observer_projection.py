#!/usr/bin/env python3
"""Build the observer's ChatGPT app binding and projection receipt.

The two output files are projections of already authenticated inputs.  This
command does not register an app, resolve a package, or invent release
metadata: the app identity comes from the signed Directory target, package and
source identity come from the selected signed release, and the native files
must be the exact projection retained by released agentplugins state.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from directory_publication import (  # noqa: E402
    MAX_ENVELOPE_BYTES,
    MAX_LATEST_BYTES,
    MAX_SNAPSHOT_BYTES,
    PublicationError,
    canonical_json as directory_json,
    load_public_keys,
    parse_json_bytes,
    parse_timestamp,
    read_bytes_bounded,
    require,
    sha256_digest,
    validate_latest,
    validate_snapshot_semantics,
    verify_envelope,
)
from observe_launch_scenario import (  # noqa: E402
    strict_state_json_loads,
    validate_released_state_v4,
)


MAX_EVIDENCE_BYTES = 8 << 20
MAX_PROJECTION_BYTES = 64 << 10
MAX_BINARY_BYTES = 256 << 20
APP_ID = re.compile(r"plugin_asdk_app_[a-f0-9]{32}")
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def exact_object(value: Any, required: set[str], optional: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(required <= set(value) <= required | optional, f"{label} fields are invalid")
    return value


def one(values: list[dict[str, Any]], label: str) -> dict[str, Any]:
    require(len(values) == 1, f"expected exactly one {label}, found {len(values)}")
    return values[0]


def semver(value: Any, label: str) -> tuple[int, int, int]:
    require(isinstance(value, str) and SEMVER.fullmatch(value) is not None, f"{label} is invalid")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def canonical_output(value: Any) -> bytes:
    """Match the official package JSON profile consumed by the observer."""
    body = directory_json(value)
    return body[:-1]


def read_regular_bounded(path: Path, limit: int, label: str) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} must be a one-link regular file")
    body = read_bytes_bounded(path, limit)
    after = path.lstat()
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        f"{label} changed while reading",
    )
    return body


def load_object(path: Path, limit: int, label: str) -> tuple[dict[str, Any], bytes]:
    body = read_regular_bounded(path, limit, label)
    value = parse_json_bytes(body, label, max_bytes=limit)
    require(isinstance(value, dict), f"{label} must be an object")
    return value, body


def verified_snapshot(feed: Path, trusted_keys: Path, now: str, minimum_sequence: int) -> tuple[dict[str, Any], str]:
    latest, latest_body = load_object(feed / "latest.json", MAX_LATEST_BYTES, "latest pointer")
    require(directory_json(latest) == latest_body, "latest pointer is not canonical JSON")
    validate_latest(latest)
    require(latest["sequence"] >= minimum_sequence, "Directory snapshot is below the requested sequence floor")
    limits = latest["fetch_contract"]
    snapshot_body = read_regular_bounded(feed / latest["snapshot_path"], limits["snapshot_max_bytes"], "snapshot")
    require(len(snapshot_body) <= MAX_SNAPSHOT_BYTES, "snapshot exceeds the implementation limit")
    envelope, envelope_body = load_object(feed / latest["envelope_path"], limits["envelope_max_bytes"], "signature envelope")
    require(len(envelope_body) <= MAX_ENVELOPE_BYTES, "signature envelope exceeds the implementation limit")
    require(directory_json(envelope) == envelope_body, "signature envelope is not canonical JSON")
    verify_envelope(snapshot_body, envelope, load_public_keys(trusted_keys))
    snapshot = parse_json_bytes(snapshot_body, "snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    require(isinstance(snapshot, dict), "snapshot must be an object")
    validate_snapshot_semantics(snapshot)
    require(snapshot["sequence"] == envelope["sequence"] == latest["sequence"], "Directory artifact sequence mismatch")
    moment = parse_timestamp(now, "now")
    require(moment >= parse_timestamp(snapshot["generated_at"], "generated_at"), "Directory snapshot is not yet valid")
    require(moment < parse_timestamp(snapshot["expires_at"], "expires_at"), "Directory snapshot is expired")
    return snapshot, sha256_digest(snapshot_body)


def selected_identity(
    snapshot: dict[str, Any], *, product_id: str, distribution_id: str,
    release_sequence: int, installer_version: str, app_key: str, app_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    product = one([item for item in snapshot["products"] if item["id"] == product_id], f"product {product_id!r}")
    require(product["default_distribution"] == distribution_id, "requested distribution is not the product default")
    require(distribution_id in product["distributions"], "requested distribution is not declared by the product")
    distribution = one([item for item in snapshot["distributions"] if item["id"] == distribution_id], f"distribution {distribution_id!r}")
    require(distribution["product_id"] == product_id and distribution["status"] == "active", "requested distribution is not active for the product")
    require([item for item in snapshot["revocations"] if item["distribution_id"] == distribution_id and item["release_sequence"] == release_sequence] == [], "requested release is revoked")
    eligible: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for policy in distribution["release_policies"]:
        targets = [target for target in policy["targets"] if target["client"] == "chatgpt"]
        require(len(targets) <= 1, "release policy has ambiguous ChatGPT targets")
        if (
            policy["status"] == "active" and targets
            and semver(policy["minimum_installer_version"], "minimum installer version") <= semver(installer_version, "installer version")
        ):
            eligible.append((policy, targets[0]))
    selected = one(
        [{"policy": policy, "target": target} for policy, target in eligible],
        "eligible active ChatGPT release policy",
    )
    policy, target = selected["policy"], selected["target"]
    require(policy["release_sequence"] == release_sequence, "requested release is not the eligible ChatGPT release")
    binding = target.get("app_binding")
    exact_object(binding, {"app_key", "id", "mcp_server"}, set(), "signed ChatGPT app binding")
    require(binding["app_key"] == app_key, "requested app key differs from the signed target")
    require(binding["id"] == app_id, "requested app ID differs from the signed target")
    release = one([item for item in distribution["releases"] if item["sequence"] == release_sequence], f"release {release_sequence}")
    return distribution, release, binding


def validate_add(
    add: dict[str, Any], *, product_id: str, distribution: dict[str, Any], release: dict[str, Any],
    snapshot: dict[str, Any], snapshot_digest: str, binding: dict[str, Any],
) -> str:
    exact_object(add, {"schema_version", "command", "result", "data"}, set(), "CLI add evidence")
    require(isinstance(add["schema_version"], int) and not isinstance(add["schema_version"], bool) and add["schema_version"] == 1, "CLI add schema is invalid")
    require(add["command"] == "add" and add["result"] == "success", "CLI add did not succeed")
    data = exact_object(
        add["data"],
        {
            "operation_id", "batch", "status", "succeeded", "failed", "plugin", "version",
            "source", "revision", "tree_digest", "manifest_digest", "dry_run", "targets",
            "acquisition", "target_outcomes", "directory",
        },
        set(),
        "CLI add data",
    )
    source = release["package_source"]
    expected = {
        "plugin": product_id, "version": release["package_version"],
        "source": f"{source['repository']}//{source['path']}", "revision": source["revision"],
        "tree_digest": release["tree_digest"], "manifest_digest": release["manifest_digest"],
    }
    require(data["dry_run"] is False, "CLI add evidence must be a real isolated materialization")
    for field, value in expected.items():
        require(isinstance(data.get(field), str) and data.get(field) == value, f"CLI add {field} differs from the signed release")
    operation_id = data.get("operation_id")
    require(isinstance(operation_id, str) and operation_id != "", "CLI add operation ID is invalid")
    require(
        data.get("batch") is True and data.get("status") == "completed"
        and isinstance(data.get("succeeded"), int) and not isinstance(data["succeeded"], bool) and data["succeeded"] == 1
        and isinstance(data.get("failed"), int) and not isinstance(data["failed"], bool) and data["failed"] == 0,
        "CLI add completion summary is invalid",
    )
    acquisition = exact_object(
        data["acquisition"],
        {"acquisition_id", "acquisition_count", "tree_digest", "manifest_digest", "closure_digest", "source_kind", "fetched", "validated"},
        set(), "CLI acquisition",
    )
    require(
        isinstance(acquisition["acquisition_id"], str) and acquisition["acquisition_id"] != ""
        and isinstance(acquisition["acquisition_count"], int) and not isinstance(acquisition["acquisition_count"], bool)
        and acquisition["acquisition_count"] == 1
        and acquisition["tree_digest"] == release["tree_digest"]
        and acquisition["manifest_digest"] == release["manifest_digest"]
        and isinstance(acquisition["closure_digest"], str) and re.fullmatch(r"sha256:[a-f0-9]{64}", acquisition["closure_digest"])
        and acquisition["source_kind"] in {"github", "directory"}
        and acquisition["fetched"] is True and acquisition["validated"] is True,
        "CLI acquisition identity differs from the signed release",
    )
    outcomes = exact_object(data["target_outcomes"], {"chatgpt"}, set(), "CLI target outcomes")
    outcome = exact_object(
        outcomes["chatgpt"],
        {"outcome", "acquisition_id", "tree_digest", "manifest_digest", "closure_digest"},
        set(), "CLI ChatGPT target outcome",
    )
    require(
        outcome == {
            "outcome": "passed", "acquisition_id": acquisition["acquisition_id"],
            "tree_digest": acquisition["tree_digest"], "manifest_digest": acquisition["manifest_digest"],
            "closure_digest": acquisition["closure_digest"],
        },
        "CLI ChatGPT target outcome differs from the single acquisition",
    )
    directory = exact_object(
        data["directory"],
        {"product_id", "distribution_id", "distribution_kind", "desired_release_sequence", "snapshot_schema", "snapshot_sequence", "snapshot_digest"},
        set(), "CLI add Directory evidence",
    )
    expected_directory = {
        "product_id": product_id, "distribution_id": distribution["id"], "distribution_kind": distribution["kind"],
        "desired_release_sequence": release["sequence"], "snapshot_schema": snapshot["snapshot_schema_version"],
        "snapshot_sequence": snapshot["sequence"], "snapshot_digest": snapshot_digest,
    }
    require(directory == expected_directory, "CLI add Directory identity differs from the signed snapshot")
    require(isinstance(data["targets"], list), "CLI add targets must be a list")
    target = one([item for item in data["targets"] if isinstance(item, dict) and item.get("target") == "chatgpt"], "ChatGPT add target")
    require(len(data["targets"]) == 1, "CLI add evidence contains ambiguous targets")
    exact_object(target, {"target", "status", "next_action", "output"}, set(), "CLI ChatGPT target")
    require(target["status"] == "external_completed" and isinstance(target["next_action"], str) and target["next_action"] != "", "CLI ChatGPT target did not complete external preparation")
    output = exact_object(
        target["output"],
        {"operation_id", "plugin", "version", "source", "revision", "tree_digest", "manifest_digest", "dry_run", "result", "next_action"},
        set(), "CLI ChatGPT output",
    )
    for field, value in expected.items():
        require(isinstance(output.get(field), str) and output.get(field) == value, f"CLI ChatGPT output {field} differs from the signed release")
    require(output["dry_run"] is False, "CLI ChatGPT output is a dry run")
    require(output["next_action"] == target["next_action"], "CLI ChatGPT next action is inconsistent")
    require(output["operation_id"] == operation_id, "CLI ChatGPT operation ID differs")
    result = exact_object(
        output["result"], {"installation_id", "plan", "activation", "requires_confirmation", "mutated", "group_phase"}, set(),
        "CLI ChatGPT result",
    )
    require(result["mutated"] is True, "CLI ChatGPT add did not materialize the package")
    require(isinstance(result["installation_id"], str) and result["installation_id"] != "", "CLI ChatGPT installation ID is invalid")
    require(result["requires_confirmation"] is False and result["group_phase"] == "external_completed", "CLI ChatGPT group completion is invalid")
    plan = exact_object(
        result["plan"],
        {"client_id", "scope", "status", "package_mode", "activation", "authentication", "policy", "verification", "physical_artifact_id", "components", "user_actions", "warnings"},
        set(), "CLI ChatGPT plan",
    )
    require(
        plan["client_id"] == "chatgpt" and plan["scope"] == "user"
        and plan["status"] == "manual_activation_required"
        and plan["package_mode"] == "compatibility_projection"
        and plan["activation"] == "manual_activation_required"
        and plan["policy"] == "allowed" and plan["verification"] == "package_validated",
        "CLI ChatGPT plan selected another client or lifecycle",
    )
    components = plan.get("components")
    require(isinstance(components, list), "CLI ChatGPT plan components are invalid")
    require(all(isinstance(item, dict) and set(item) == {"kind", "name", "support"} for item in components), "CLI ChatGPT plan component fields are invalid")
    require(
        {(item["kind"], item["name"], item["support"]) for item in components}
        == {("app", binding["app_key"], "projected"), ("mcp_server", binding["mcp_server"], "projected")}
        and len(components) == 2,
        "CLI ChatGPT plan did not project the exact signed app and MCP components",
    )
    activation = exact_object(
        result["activation"], {"activation", "authentication", "policy", "verification", "user_actions"}, set(),
        "CLI ChatGPT activation",
    )
    require(
        activation["activation"] == "manual_activation_required"
        and activation["policy"] == "allowed" and activation["verification"] == "package_validated",
        "CLI ChatGPT activation state is invalid",
    )
    return result["installation_id"]


def validate_state(
    state: dict[str, Any], projection_root: Path, *, product_id: str,
    distribution: dict[str, Any], release: dict[str, Any], snapshot: dict[str, Any], snapshot_digest: str,
    binding: dict[str, Any], installation_id: str,
) -> None:
    require(validate_released_state_v4(state), "released CLI State v4 is invalid")
    matches = [item for item in state["installations"] if item.get("declared_name") == product_id]
    installation = one(matches, f"State v4 installation {product_id!r}")
    require(installation.get("installation_id") == installation_id, "State v4 installation ID differs from the add result")
    require(installation.get("origin_mode") == "directory", "State v4 installation did not originate from Directory")
    expected_directory = {
        "product_id": product_id, "distribution_id": distribution["id"], "distribution_kind": distribution["kind"],
        "desired_release_sequence": release["sequence"], "snapshot_schema": snapshot["snapshot_schema_version"],
        "snapshot_sequence": snapshot["sequence"], "snapshot_digest": snapshot_digest,
    }
    require(installation.get("directory") == expected_directory, "State v4 Directory identity differs")
    source = installation.get("source")
    package_source = release["package_source"]
    require(isinstance(source, dict), "State v4 source is invalid")
    expected_source = {
        "repository": package_source["repository"], "package_subpath": package_source["path"],
        "resolved_revision": package_source["revision"], "tree_digest": release["tree_digest"],
    }
    for field, value in expected_source.items():
        require(source.get(field) == value, f"State v4 source {field} differs from the signed release")
    package = installation.get("package")
    require(isinstance(package, dict), "State v4 package is invalid")
    require(package.get("version") == release["package_version"] and package.get("manifest_digest") == release["manifest_digest"], "State v4 package identity differs")
    clients = installation.get("clients")
    require(isinstance(clients, dict), "State v4 clients are invalid")
    client = one([item for item in clients.values() if isinstance(item, dict) and item.get("client_id") == "chatgpt"], "State v4 ChatGPT client")
    require(len(clients) == 1, "State v4 installation contains ambiguous clients")
    require(Path(client.get("target_locator", "")).resolve() == projection_root.resolve(), "State v4 target locator differs from the supplied projection")
    revision = client.get("package_revision")
    require(isinstance(revision, dict), "State v4 ChatGPT package revision is missing")
    expected_revision = {
        "version": release["package_version"], "resolved_revision": package_source["revision"],
        "tree_digest": release["tree_digest"], "manifest_digest": release["manifest_digest"],
        "distribution_id": distribution["id"], "release_sequence": release["sequence"],
    }
    for field, value in expected_revision.items():
        require(revision.get(field) == value, f"State v4 ChatGPT revision {field} differs")
    catalog = revision.get("catalog_evidence")
    if catalog is not None:
        require(isinstance(catalog, dict) and catalog.get("schema_version") == 2, "State v4 catalog evidence is invalid")
        compatibility = catalog.get("compatibility")
        require(isinstance(compatibility, dict), "State v4 compatibility evidence is invalid")
        chat = compatibility.get("chatgpt")
        require(isinstance(chat, dict), "State v4 ChatGPT catalog evidence is missing")
        app = chat.get("app_binding")
        require(isinstance(app, dict), "State v4 app binding evidence is missing")
        for field in ("app_key", "id", "mcp_server"):
            require(app.get(field) == binding[field], f"State v4 app binding {field} differs from the signed target")


def validate_projection(root: Path, binding: dict[str, Any], product_id: str) -> str:
    metadata = root.lstat()
    require(stat.S_ISDIR(metadata.st_mode), "ChatGPT projection root must be a directory, not a link")
    manifest, _ = load_object(root / ".codex-plugin/plugin.json", MAX_PROJECTION_BYTES, "ChatGPT official manifest")
    require(
        manifest.get("name") == product_id
        and manifest.get("apps") == "./.app.json"
        and manifest.get("mcpServers") == "./.mcp.json"
        and "hooks" not in manifest,
        "ChatGPT official manifest does not bind the exact app and MCP projection",
    )
    app, _ = load_object(root / ".app.json", MAX_PROJECTION_BYTES, "ChatGPT .app.json")
    expected_app = {"apps": {binding["app_key"]: {"id": binding["id"]}}}
    require(app == expected_app, "ChatGPT .app.json differs from the signed target")
    mcp, _ = load_object(root / ".mcp.json", MAX_PROJECTION_BYTES, "ChatGPT .mcp.json")
    servers = exact_object(mcp, {"mcpServers"}, set(), "ChatGPT .mcp.json")["mcpServers"]
    require(isinstance(servers, dict) and set(servers) == {binding["mcp_server"]}, "ChatGPT .mcp.json has ambiguous MCP servers")
    server = exact_object(servers[binding["mcp_server"]], {"url", "type"}, set(), "ChatGPT MCP server")
    require(server["type"] == "http" and isinstance(server["url"], str), "ChatGPT MCP projection is invalid")
    parsed = urlsplit(server["url"])
    require(parsed.scheme == "https" and parsed.hostname is not None and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment, "ChatGPT MCP URL is unsafe")
    require(parsed.hostname == parsed.hostname.lower() and parsed.port in (None, 443), "ChatGPT MCP endpoint is not canonical HTTPS")
    return parsed.hostname


def binary_snapshot(path: Path) -> tuple[str, tuple[int, int, int, int, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "released CLI binary must be a one-link regular file")
        require(before.st_mode & 0o111 != 0, "released CLI binary is not executable")
        require(0 < before.st_size <= MAX_BINARY_BYTES, "released CLI binary size is invalid")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1 << 20, remaining))
            require(bool(block), "released CLI binary was truncated")
            digest.update(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "released CLI binary changed while hashing")
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        return "sha256:" + digest.hexdigest(), identity
    finally:
        os.close(descriptor)


def validate_binary(path: Path, installer_version: str) -> str:
    digest, identity = binary_snapshot(path)
    try:
        completed = subprocess.run(
            [str(path.resolve()), "version"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=path.parent, env={"HOME": "/nonexistent", "PATH": "/usr/bin:/bin"},
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PublicationError(f"released CLI version check failed: {error}") from error
    require(
        completed.returncode == 0
        and completed.stdout == f"agentplugins {installer_version}\n"
        and completed.stderr == "",
        "released CLI version output differs from the requested installer version",
    )
    after_digest, after_identity = binary_snapshot(path)
    require((after_digest, after_identity) == (digest, identity), "released CLI binary changed during version verification")
    return digest


def write_outputs(output: Path, app: dict[str, Any], receipt: dict[str, Any]) -> None:
    require(not output.exists(), "output directory already exists; refusing to overwrite approved inputs")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    require(not stage.exists(), "temporary output directory already exists")
    stage.mkdir(mode=0o700)
    try:
        for name, value in (("app-binding.json", app), ("projection-receipt.json", receipt)):
            path = stage / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o640)
            try:
                body = canonical_output(value)
                os.write(descriptor, body)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        descriptor = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(stage, output)
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def build(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    require(NAME.fullmatch(args.product_id) is not None, "product ID is invalid")
    require(NAME.fullmatch(args.app_key) is not None, "app key is invalid")
    require(APP_ID.fullmatch(args.app_id) is not None, "app ID is invalid")
    require(isinstance(args.release_sequence, int) and not isinstance(args.release_sequence, bool) and 1 <= args.release_sequence <= 9007199254740991, "release sequence is invalid")
    require(isinstance(args.minimum_sequence, int) and not isinstance(args.minimum_sequence, bool) and 1 <= args.minimum_sequence <= 9007199254740991, "minimum sequence is invalid")
    semver(args.installer_version, "installer version")
    require(TIMESTAMP.fullmatch(args.observed_at) is not None, "observed-at must be canonical UTC seconds")
    observed = parse_timestamp(args.observed_at, "observed-at")
    require(observed.tzinfo == timezone.utc, "observed-at must be UTC")
    require(args.now == args.observed_at, "now and observed-at must identify the same deterministic observation")
    snapshot, snapshot_digest = verified_snapshot(args.feed, args.trusted_keys, args.now, args.minimum_sequence)
    distribution, release, binding = selected_identity(
        snapshot, product_id=args.product_id, distribution_id=args.distribution_id,
        release_sequence=args.release_sequence, installer_version=args.installer_version,
        app_key=args.app_key, app_id=args.app_id,
    )
    add, _ = load_object(args.add_evidence, MAX_EVIDENCE_BYTES, "CLI add evidence")
    installation_id = validate_add(
        add, product_id=args.product_id, distribution=distribution, release=release,
        snapshot=snapshot, snapshot_digest=snapshot_digest, binding=binding,
    )
    state_body = read_regular_bounded(args.state, MAX_EVIDENCE_BYTES, "released CLI state")
    state = strict_state_json_loads(state_body)
    require(isinstance(state, dict), "released CLI state must be an object")
    validate_state(
        state, args.projection_root, product_id=args.product_id, distribution=distribution,
        release=release, snapshot=snapshot, snapshot_digest=snapshot_digest,
        binding=binding, installation_id=installation_id,
    )
    endpoint_host = validate_projection(args.projection_root, binding, args.product_id)
    binary_digest = validate_binary(args.cli_binary, args.installer_version)
    source = release["package_source"]
    receipt = {
        "application_id": args.app_id,
        "product_id": args.product_id,
        "tuple": {
            "adapter_version": args.installer_version,
            "architecture": "amd64",
            "binary_digest": binary_digest,
            "client_version": None,
            "dependency_identity": f"remote-mcp:{endpoint_host}",
            "distribution_id": distribution["id"],
            "distribution_kind": distribution["kind"],
            "installer_version": args.installer_version,
            "manifest_digest": release["manifest_digest"],
            "observed_at": args.observed_at,
            "os": "linux",
            "package_version": release["package_version"],
            "product_id": args.product_id,
            "release_sequence": release["sequence"],
            "snapshot_digest": snapshot_digest,
            "snapshot_sequence": snapshot["sequence"],
            "source_path": source["path"],
            "source_repository": source["repository"],
            "source_revision": source["revision"],
            "tree_digest": release["tree_digest"],
        },
    }
    app = {"apps": {args.app_key: {"id": args.app_id}}}
    return app, receipt


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--feed", type=Path, required=True)
    value.add_argument("--trusted-keys", type=Path, required=True)
    value.add_argument("--now", required=True)
    value.add_argument("--minimum-sequence", type=int, default=1)
    value.add_argument("--add-evidence", type=Path, required=True)
    value.add_argument("--state", type=Path, required=True)
    value.add_argument("--projection-root", type=Path, required=True)
    value.add_argument("--cli-binary", type=Path, required=True)
    value.add_argument("--installer-version", required=True)
    value.add_argument("--product-id", required=True)
    value.add_argument("--distribution-id", required=True)
    value.add_argument("--release-sequence", type=int, required=True)
    value.add_argument("--app-key", required=True)
    value.add_argument("--app-id", required=True)
    value.add_argument("--observed-at", required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        app, receipt = build(args)
        write_outputs(args.output, app, receipt)
        print(f"wrote canonical ChatGPT observer projection to {args.output}")
        return 0
    except (OSError, ValueError, PublicationError, KeyError, TypeError) as error:
        print(f"build-chatgpt-observer-projection: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
