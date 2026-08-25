#!/usr/bin/env python3
"""Repository-owned stable-launch command and native-state observer.

This program does not accept scenario implementation code or claimed outcomes.
It executes only the immutable plans below, records a challenge-correlated trace,
and derives results from independent before/after state digests. Scenarios that
need a client/runtime capability not present on the native runner fail closed.
"""

from __future__ import annotations

import argparse
import base64
import copy
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from directory_publication import canonical_json, sha256_digest, signature_message, validate_snapshot_semantics, verify_envelope
from build_registry import directory_tree_digest


_CONFIG = json.loads((Path(__file__).resolve().parents[1] / "tests/e2e/launch-scenarios.json").read_text())
EXPECTED_SCENARIOS = frozenset(
    _CONFIG["acceptance_postconditions"] +
    _CONFIG["fault_scenarios"] + _CONFIG["adapter_repair_faults"] +
    _CONFIG["advanced_scenarios"] + [item for item in _CONFIG["journeys"] if item != "direct_external_package"] +
    ["context7_grouped_lifecycle", "shared_copilot_vscode_backend"] +
    [f"hero_lifecycle_{plugin}_{client}" for plugin in _CONFIG["heroes"] for client in _CONFIG["runtime_clients"]]
)
NATIVE_ROOTS = (".codex", ".cursor", ".kiro", ".copilot", ".config/Code/User")
EXTERNAL_PACKAGE = Path(__file__).resolve().parents[1] / "tests/e2e/fixtures/external-package"
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures"
JOURNEY_VALIDATOR = Path(__file__).resolve().parent / "validate_review_journey.py"
CONFORMANCE_KEY_ID = "launch-conformance-only"
CONFORMANCE_SEED = hashlib.sha256(b"UAP launch evidence conformance key; never production").digest()
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)
GITHUB_SOURCE_PATH = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GITHUB_WORKFLOW = re.compile(
    r"^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9._-]*/\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$"
)
GITHUB_BRANCH_REF = re.compile(r"^refs/heads/[A-Za-z0-9._/-]+$")
LEAF_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
WINDOWS_RESERVED_LEAF_IDS = frozenset({
    "CON", "PRN", "AUX", "NUL", "CLOCK$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
})
GO_UNICODE_WHITE_SPACE = frozenset(
    "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


class DuplicateKeyError(ValueError):
    """Raised before raw JSON object pairs can collapse into a dictionary."""


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON object key: {key}")
        value[key] = child
    return value


def strict_json_loads(raw: str | bytes) -> Any:
    """Decode evidence JSON without allowing duplicate keys or non-JSON numbers."""
    return json.loads(
        raw, object_pairs_hook=unique_json_object,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON number: {value}")),
    )


def _exact_int(value: Any, expected: int | None = None) -> bool:
    return type(value) is int and (expected is None or value == expected)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _keys(value: Any, required: set[str], optional: set[str] = set()) -> bool:
    return isinstance(value, dict) and required <= set(value) <= required | optional


def _digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _go_trim_space(value: str) -> str:
    """Match Go strings.TrimSpace's Unicode White_Space predicate exactly."""
    start, end = 0, len(value)
    while start < end and value[start] in GO_UNICODE_WHITE_SPACE:
        start += 1
    while end > start and value[end - 1] in GO_UNICODE_WHITE_SPACE:
        end -= 1
    return value[start:end]


def _go_nonempty(value: Any) -> bool:
    """The released Go State-v4 validator's strings.TrimSpace check."""
    return isinstance(value, str) and bool(_go_trim_space(value))


def _valid_leaf_id(value: Any) -> bool:
    """Exact portable leaf-ID rule used by released agentplugins 0.1.14."""
    if not isinstance(value, str):
        return False
    value = _go_trim_space(value)
    if not value or len(value.encode()) > 64:
        return False
    if not LEAF_ID.fullmatch(value) or value in {".", ".."} or value.endswith(".") or ".." in value:
        return False
    return value.split(".", 1)[0].upper() not in WINDOWS_RESERVED_LEAF_IDS


def _directory_snapshot_coherent(value: dict[str, Any]) -> bool:
    fields = ("snapshot_schema", "snapshot_sequence", "snapshot_digest")
    present = any(value.get(name) not in (None, "", 0) for name in fields)
    return not present or bool(
        _exact_int(value.get("snapshot_schema")) and value["snapshot_schema"] > 0
        and _exact_int(value.get("snapshot_sequence")) and value["snapshot_sequence"] > 0
        and _digest(value.get("snapshot_digest"))
    )


def _released_directory_snapshot_coherent(value: dict[str, Any]) -> bool:
    """The weaker, exact snapshot rule in released State.Validate."""
    schema = value.get("snapshot_schema", 0)
    sequence = value.get("snapshot_sequence", 0)
    digest = value.get("snapshot_digest", "")
    if type(schema) is not int or type(sequence) is not int or not isinstance(digest, str) or sequence < 0:
        return False
    present = sequence > 0 or schema > 0 or digest != ""
    return not present or (sequence >= 1 and schema >= 1 and _go_nonempty(digest))


def validate_released_state_v4(value: Any) -> bool:
    """Exact acceptance semantics of agentplugins 0.1.14 statev2.Validate.

    The evidence reader applies additional path/digest authority constraints
    after this check; those constraints are not represented as State.Validate
    parity.
    """
    if not isinstance(value, dict) or value.get("schema_version") != 4 or type(value.get("schema_version")) is not int:
        return False
    installations = value.get("installations")
    if installations is None:
        installations = []
    if not isinstance(installations, list):
        return False
    installation_ids: set[str] = set()
    source_ids: set[str] = set()
    client_ids: set[str] = set()
    operation_ids: set[str] = set()
    for installation in installations:
        if not isinstance(installation, dict):
            return False
        installation_id = installation.get("installation_id")
        package = installation.get("package")
        source = installation.get("source")
        clients = installation.get("clients")
        receipts = installation.get("data_receipts", {})
        clients = {} if clients is None else clients
        receipts = {} if receipts is None else receipts
        if (
            not _valid_leaf_id(installation_id) or installation_id in installation_ids
            or not isinstance(package, dict) or not isinstance(source, dict)
            or not isinstance(clients, dict) or not isinstance(receipts, dict)
            or not _go_nonempty(installation.get("declared_name"))
            or installation.get("declared_name") != package.get("declared_name")
        ):
            return False
        installation_ids.add(installation_id)
        group_id = installation.get("operation_group_id", "")
        if group_id != "" and not _valid_leaf_id(group_id):
            return False
        origin = installation.get("origin_mode", "")
        directory = installation.get("directory")
        if origin == "direct":
            if directory is not None:
                return False
        elif origin == "directory":
            if not isinstance(directory, dict) or not (
                _go_nonempty(directory.get("product_id")) and _go_nonempty(directory.get("distribution_id"))
                and type(directory.get("desired_release_sequence")) is int
                and directory["desired_release_sequence"] >= 1
                and directory.get("distribution_kind") in {"upstream", "community_bridge", "community"}
                and FULL_SHA.fullmatch(str(source.get("resolved_revision", ""))) is not None
                and _released_directory_snapshot_coherent(directory)
            ):
                return False
        else:
            return False
        retained = installation.get("data_retained", False)
        if type(retained) is not bool or (retained and (clients or not receipts)):
            return False
        for receipt_key, receipt in receipts.items():
            if not isinstance(receipt, dict) or receipt_key == "" or receipt_key != receipt.get("data_receipt_id"):
                return False
            if not _valid_leaf_id(receipt.get("data_receipt_id")) or not all(
                _go_nonempty(receipt.get(field)) for field in ("physical_backend_id", "scope", "locator", "ownership_digest")
            ) or receipt.get("state") not in {"owned", "unknown", "stale"}:
                return False
        source_id = source.get("source_binding_id")
        if not _go_nonempty(source_id) or source_id in source_ids:
            return False
        source_ids.add(source_id)
        if package.get("loader_kind") == "agent_plugins" and not (
            _go_nonempty(package.get("format_id")) and _go_nonempty(source.get("tree_digest"))
            and _go_nonempty(package.get("manifest_digest"))
            and (package.get("format_id") != "agent-plugins/1.0.0" or _go_nonempty(package.get("schema_uri")))
        ):
            return False
        for map_key, client in clients.items():
            if not isinstance(client, dict) or map_key == "" or map_key != client.get("client_binding_id"):
                return False
            binding_id = client.get("client_binding_id")
            if not _valid_leaf_id(binding_id) or binding_id in client_ids:
                return False
            client_ids.add(binding_id)
            if not _go_nonempty(client.get("client_id")) or not _go_nonempty(client.get("target_locator")) or not _valid_leaf_id(client.get("physical_artifact_id")):
                return False
            if (
                client.get("materialization") not in {"absent", "staged", "materialized", "degraded"}
                or client.get("activation") not in {"not_required", "prepared", "manual_activation_required", "active", "failed"}
                or client.get("authentication") not in {"not_required", "not_checked", "auth_pending", "authenticated", "failed"}
                or client.get("policy") not in {"allowed", "blocked", "approval_required"}
                or client.get("verification") not in {"not_run", "package_validated", "installation_verified", "runtime_verified", "failed"}
            ):
                return False
            revision = client.get("package_revision")
            if revision is not None and (not isinstance(revision, dict) or not _go_nonempty(revision.get("tree_digest")) or not _go_nonempty(revision.get("manifest_digest"))):
                return False
            if origin == "directory" and not (
                isinstance(revision, dict) and revision.get("distribution_id") == directory.get("distribution_id")
                and type(revision.get("release_sequence")) is int
                and 1 <= revision["release_sequence"] <= directory["desired_release_sequence"]
                and FULL_SHA.fullmatch(str(revision.get("resolved_revision", ""))) is not None
            ):
                return False
            data_receipt_id = client.get("data_receipt_id", "")
            if data_receipt_id != "" and data_receipt_id not in receipts:
                return False
            object_ids: set[str] = set()
            native_objects = client.get("native_objects", [])
            native_objects = [] if native_objects is None else native_objects
            if not isinstance(native_objects, list):
                return False
            for native_object in native_objects:
                if not isinstance(native_object, dict) or not _go_nonempty(native_object.get("object_id")) or not _go_nonempty(native_object.get("kind")) or native_object["object_id"] in object_ids:
                    return False
                object_ids.add(native_object["object_id"])
            mutations = client.get("receipts", [])
            mutations = [] if mutations is None else mutations
            if not isinstance(mutations, list):
                return False
            for mutation in mutations:
                if not isinstance(mutation, dict) or not _valid_leaf_id(mutation.get("operation_id")):
                    return False
                if mutation.get("client_binding_id") != binding_id or type(mutation.get("sequence")) is not int or mutation["sequence"] < 1 or mutation.get("phase", "") == "":
                    return False
                mutation_group = mutation.get("operation_group_id", "")
                if mutation_group != "" and not _valid_leaf_id(mutation_group):
                    return False
                if mutation["operation_id"] in operation_ids:
                    return False
                operation_ids.add(mutation["operation_id"])
    return True


def _validate_package_revision(value: Any, *, revision: str | None, tree: str, manifest: str) -> bool:
    required = {"tree_digest", "manifest_digest"}
    optional = {"version", "resolved_revision", "distribution_id", "release_sequence", "catalog_evidence"}
    return bool(
        _keys(value, required, optional)
        and ("version" not in value or _nonempty(value["version"]))
        and _nonempty(value["tree_digest"]) and _nonempty(value["manifest_digest"])
        and value["tree_digest"] == tree and value["manifest_digest"] == manifest
        and (not revision or value.get("resolved_revision") == revision)
        and (not revision or FULL_SHA.fullmatch(value.get("resolved_revision", "")) is not None)
    )


MATERIALIZATIONS = {"materialized"}
ACTIVATIONS = {"active", "manual_activation_required", "not_required"}
AUTHENTICATIONS = {"not_checked", "not_required"}
POLICIES = {"allowed"}
VERIFICATIONS = {"package_validated", "installation_verified"}
PACKAGE_MODES = {"native", "compatibility_projection"}


def _string_list(value: Any, *, nonempty: bool = False) -> bool:
    return isinstance(value, list) and (not nonempty or bool(value)) and all(_nonempty(item) for item in value)


def _validate_plan(value: Any, target: str) -> bool:
    required = {
        "client_id", "scope", "status", "package_mode", "activation", "authentication",
        "policy", "verification", "physical_artifact_id", "components", "user_actions", "warnings",
    }
    if not _keys(value, required):
        return False
    components = value["components"]
    if not isinstance(components, list) or not components:
        return False
    for component in components:
        if not (
            _keys(component, {"kind", "name", "support"})
            and component["kind"] in {"skill", "mcp_server"}
            and _nonempty(component["name"])
            and component["support"] in {"native", "projected"}
        ):
            return False
    return bool(
        value["client_id"] == target and value["scope"] == "user"
        and value["status"] == "manual_activation_required"
        and value["package_mode"] in PACKAGE_MODES
        and value["activation"] == "manual_activation_required"
        and value["authentication"] in AUTHENTICATIONS and value["policy"] in POLICIES
        and value["verification"] == "package_validated"
        and _nonempty(value["physical_artifact_id"])
        and _string_list(value["user_actions"], nonempty=True) and _string_list(value["warnings"])
    )


def _validate_activation(value: Any) -> bool:
    if not _keys(value, {"activation", "authentication", "policy", "verification"}, {"user_actions"}):
        return False
    return bool(
        value["activation"] in ACTIVATIONS and value["authentication"] in AUTHENTICATIONS
        and value["policy"] in POLICIES and value["verification"] in VERIFICATIONS
        and ("user_actions" not in value or _string_list(value["user_actions"], nonempty=True))
        and ((value["activation"] == "active") == (value["verification"] == "installation_verified"))
    )


def _requested_source_matches(requested: str, data: dict[str, Any], command: str) -> bool:
    if command != "add":
        return requested == data["plugin"]
    if requested in {data["plugin"], data["source"]}:
        return True
    if data["source"] == "direct local source":
        path = PurePosixPath(requested.removeprefix("./"))
        return bool(requested.startswith("./") and path.parts and ".." not in path.parts)
    try:
        repository_revision, package_path = requested.split("//", 1)
        repository, revision = repository_revision.split("@", 1)
    except ValueError:
        return False
    return bool(
        data.get("source") == repository + "//" + package_path
        and data.get("revision") == revision and GITHUB_REPOSITORY.fullmatch(repository)
        and FULL_SHA.fullmatch(revision) and GITHUB_SOURCE_PATH.fullmatch(package_path)
    )


def _optional_string(value: dict[str, Any], name: str) -> bool:
    return name not in value or _nonempty(value[name])


def _validate_directory_evidence(value: Any) -> bool:
    required = {
        "id", "distribution_id", "release_sequence", "level", "outcome",
        "package_tree_digest", "artifact", "trusted_for_eligibility",
    }
    optional = {
        "client", "client_version", "installer_version", "os", "architecture",
        "dependency_identity", "observed_at", "trust",
    }
    if not _keys(value, required, optional):
        return False
    artifact = value["artifact"]
    if not (
        _keys(artifact, {"repository", "revision", "path", "digest"})
        and GITHUB_REPOSITORY.fullmatch(str(artifact["repository"])) is not None
        and FULL_SHA.fullmatch(str(artifact["revision"])) is not None
        and GITHUB_SOURCE_PATH.fullmatch(str(artifact["path"])) is not None
        and _digest(artifact["digest"])
        and _exact_int(value["release_sequence"]) and value["release_sequence"] > 0
        and _digest(value["package_tree_digest"])
        and type(value["trusted_for_eligibility"]) is bool
        and all(_nonempty(value[name]) for name in ("id", "distribution_id", "level", "outcome"))
        and all(_optional_string(value, name) for name in optional - {"trust"})
    ):
        return False
    trusted = False
    if "trust" in value:
        trust = value["trust"]
        if not isinstance(trust, dict) or not _nonempty(trust.get("kind")):
            return False
        if trust["kind"] == "github_actions":
            if not _keys(trust, {"kind", "workflow", "source_ref", "source_digest"}):
                return False
            if not (
                GITHUB_WORKFLOW.fullmatch(str(trust["workflow"]))
                and GITHUB_BRANCH_REF.fullmatch(str(trust["source_ref"]))
                and FULL_SHA.fullmatch(str(trust["source_digest"]))
                and trust["workflow"].startswith(artifact["repository"] + "/.github/workflows/")
                and artifact["revision"] == trust["source_digest"]
            ):
                return False
            trusted = True
        elif trust["kind"] == "reviewed_external":
            if set(trust) != {"kind"}:
                return False
            trusted = True
        else:
            return False
    eligible = trusted and value["level"] in {"discovery", "runtime", "oauth"}
    if trusted and value["level"] in {"schema", "materialization"}:
        eligible = value["trust"]["kind"] == "github_actions"
    return value["trusted_for_eligibility"] is eligible


def _validate_installed_directory(value: Any) -> bool:
    required = {"product_id", "recorded_distribution", "recorded_revision", "recorded_release_sequence"}
    optional = {
        "current_distribution", "reviewed_default_distribution", "current_revision",
        "current_repository", "current_package_path", "current_release_sequence",
        "recorded_snapshot_sequence", "current_snapshot_sequence", "current_immutable_evidence",
    }
    if not _keys(value, required, optional):
        return False
    if not (
        all(_nonempty(value[name]) for name in ("product_id", "recorded_distribution", "recorded_revision"))
        and _exact_int(value["recorded_release_sequence"]) and value["recorded_release_sequence"] > 0
        and all(_optional_string(value, name) for name in (
            "current_distribution", "reviewed_default_distribution", "current_revision",
            "current_repository", "current_package_path",
        ))
        and all(name not in value or (_exact_int(value[name]) and value[name] > 0) for name in (
            "current_release_sequence", "recorded_snapshot_sequence", "current_snapshot_sequence",
        ))
    ):
        return False
    evidence = value.get("current_immutable_evidence", [])
    return isinstance(evidence, list) and all(_validate_directory_evidence(item) for item in evidence)


def _validate_safety_warning(value: Any) -> bool:
    if not _keys(value, {"code", "message"}, {"action", "distribution_id", "release_sequence", "clients"}):
        return False
    return bool(
        _nonempty(value["code"]) and _nonempty(value["message"])
        and all(_optional_string(value, name) for name in ("action", "distribution_id"))
        and ("release_sequence" not in value or (_exact_int(value["release_sequence"]) and value["release_sequence"] > 0))
        and ("clients" not in value or _string_list(value["clients"], nonempty=True))
    )


def _managed_native_product_id(name: str, physical_artifact_id: str) -> str:
    name = _go_trim_space(name)
    return name + "@agentplugins-" + hashlib.sha256(_go_trim_space(physical_artifact_id).encode()).hexdigest()[:12]


def _validate_native_discovery(
    value: Any, client_id: str, client_version: Any, *, name: str, installation_id: str,
) -> bool:
    if not _keys(value, {"basis", "version_operation", "discovery_operation"}) or value["basis"] != "native_client_command":
        return False
    version = value["version_operation"]
    discovery = value["discovery_operation"]
    if client_id not in {"copilot", "vscode"}:
        return False
    return bool(
        _keys(version, {"argv"}, {"observed_client_version"})
        and version["argv"] == ["copilot", "--version"]
        and _optional_string(version, "observed_client_version")
        and ("observed_client_version" not in version or version["observed_client_version"] == client_version)
        and _keys(discovery, {"argv", "discovered", "product_id"})
        and discovery["argv"] == ["copilot", "plugin", "list"]
        and type(discovery["discovered"]) is bool and _nonempty(discovery["product_id"])
        # The released info surface omits physical_artifact_id. Exact managed
        # identity is therefore bound later, where State-v4 is also available.
        and re.fullmatch(re.escape(_go_trim_space(name)) + r"@agentplugins-[0-9a-f]{12}", discovery["product_id"]) is not None
    )


def _validate_inventory(value: Any) -> bool:
    required = {"mcp_present", "mcp_enabled"}
    list_fields = {"mcp_servers", "invalid_mcp_servers", "app_bindings", "skills", "invalid_skills", "extensions"}
    bool_fields = {"app_present", "invalid_skills_root"}
    return bool(
        _keys(value, required, list_fields | bool_fields)
        and all(type(value[name]) is bool for name in required)
        and all(name not in value or _string_list(value[name]) for name in list_fields)
        and all(name not in value or type(value[name]) is bool for name in bool_fields)
    )


def _validate_group_target(
    item: Any, *, command: str, data: dict[str, Any], installation_ids: set[str],
) -> str | None:
    optional_item = {"next_action"} | ({"selected"} if command == "update" else set())
    if not _keys(item, {"target", "status", "output"}, optional_item):
        return None
    target = item["target"]
    output = item["output"]
    if not _nonempty(target) or item["status"] != "external_completed" or not isinstance(output, dict):
        return None
    required_output = {"operation_id", "plugin", "version", "source", "tree_digest", "manifest_digest", "dry_run", "result"}
    optional_output = {"revision", "next_action"}
    if not _keys(output, required_output, optional_output):
        return None
    if not (
        output["operation_id"] == data["operation_id"]
        and output["plugin"] == data["plugin"]
        and _nonempty(output["version"])
        and output["version"] == data.get("version", output["version"])
        and _nonempty(output["source"])
        and output["source"] == data.get("source", output["source"])
        and output["tree_digest"] == data.get("tree_digest", output["tree_digest"])
        and _digest(output["tree_digest"])
        and _digest(output["manifest_digest"])
        and output["manifest_digest"] == data.get("manifest_digest", output["manifest_digest"])
        and output["dry_run"] is False
        and ("revision" not in output or FULL_SHA.fullmatch(output["revision"]) is not None)
        and ("revision" not in data or "revision" in output)
        and ("revision" not in data or output.get("revision") == data["revision"])
        and ("next_action" not in item or _nonempty(item["next_action"]))
        and ("next_action" not in output or _nonempty(output["next_action"]))
        and (item.get("next_action") == output.get("next_action"))
    ):
        return None
    result = output["result"]
    common = {"installation_id", "requires_confirmation", "mutated", "group_phase"}
    if command in {"add", "update", "repair"}:
        if not _keys(result, common | {"plan"}, {"activation", "no_change"}):
            return None
        plan = result["plan"]
        if not _validate_plan(plan, target):
            return None
        if "activation" in result and not _validate_activation(result["activation"]):
            return None
    elif command == "remove":
        if not _keys(result, common | {"plugin", "client_id", "deactivation", "affected_surfaces"}):
            return None
        deactivation = result["deactivation"]
        if not _keys(deactivation, {"activation", "artifact_removal_allowed", "external_removal_complete"}):
            return None
        if (
            result["plugin"] != data["plugin"] or result["client_id"] != target
            or deactivation["activation"] != "not_required"
            or type(deactivation["artifact_removal_allowed"]) is not bool
            or type(deactivation["external_removal_complete"]) is not bool
            or result["affected_surfaces"] != [target]
        ):
            return None
    else:
        return None
    mutated = result.get("mutated")
    if (
        not _nonempty(result.get("installation_id"))
        or result.get("requires_confirmation") is not False
        or result.get("group_phase") != "external_completed"
        or type(mutated) is not bool
    ):
        return None
    if command == "update":
        if item.get("selected") is not True or (mutated is False) != (result.get("no_change") is True):
            return None
    elif mutated is not True or "no_change" in result:
        return None
    installation_ids.add(result["installation_id"])
    return target


def _validate_grouped(value: dict[str, Any], command: str, *, verify_acquisition: bool = True) -> bool:
    data = value["data"]
    required = {"operation_id", "batch", "status", "succeeded", "failed", "plugin", "dry_run", "targets"}
    optional = {"version", "source", "revision", "tree_digest", "manifest_digest", "directory"}
    if command == "add":
        required |= {"version", "source", "tree_digest", "manifest_digest", "acquisition", "target_outcomes"}
    elif command == "update":
        required |= {"version", "source", "tree_digest"}
    elif command == "remove":
        required |= {"plugin_data_preserved", "data_retained", "retained_data", "retained_data_action"}
    if not _keys(data, required, optional):
        return False
    if not (
        _nonempty(data["operation_id"]) and data["batch"] is True
        and data["status"] in ({"completed"} if command != "remove" else {"completed", "data_retained"})
        and _exact_int(data["succeeded"]) and data["succeeded"] > 0
        and _exact_int(data["failed"], 0) and _nonempty(data["plugin"])
        and ("version" not in data or _nonempty(data["version"]))
        and ("source" not in data or _nonempty(data["source"]))
        and data["dry_run"] is False and isinstance(data["targets"], list) and data["targets"]
        and ("tree_digest" not in data or _digest(data["tree_digest"]))
        and ("manifest_digest" not in data or _digest(data["manifest_digest"]))
        and ("revision" not in data or FULL_SHA.fullmatch(data["revision"]) is not None)
    ):
        return False
    if "directory" in data:
        directory = data["directory"]
        if not (
            _keys(directory, {"product_id", "distribution_id", "distribution_kind", "desired_release_sequence"},
                  {"snapshot_schema", "snapshot_sequence", "snapshot_digest"})
            and directory["product_id"] == data["plugin"]
            and _nonempty(directory["distribution_id"])
            and directory["distribution_kind"] in {"upstream", "community_bridge", "community"}
            and _exact_int(directory["desired_release_sequence"])
            and directory["desired_release_sequence"] > 0
            and _directory_snapshot_coherent(directory)
            and FULL_SHA.fullmatch(str(data.get("revision", ""))) is not None
        ):
            return False
    installations: set[str] = set()
    targets = [_validate_group_target(item, command=command, data=data, installation_ids=installations) for item in data["targets"]]
    identities = {
        (
            item["output"]["source"], item["output"].get("revision"),
            item["output"]["tree_digest"], item["output"]["manifest_digest"],
        )
        for item in data["targets"] if isinstance(item, dict) and isinstance(item.get("output"), dict)
    }
    if (
        None in targets or len(targets) != len(set(targets)) or data["succeeded"] != len(targets)
        or len(installations) != 1 or len(identities) != 1
    ):
        return False
    if command == "remove":
        receipts = data["retained_data"]
        if not (
            data["status"] == "data_retained" and data["plugin_data_preserved"] is True
            and data["data_retained"] is True and isinstance(receipts, list) and receipts
            and len({item.get("data_receipt_id") for item in receipts if isinstance(item, dict)}) == len(receipts)
            and all(
                _keys(item, {"data_receipt_id", "physical_backend_id", "scope", "state"})
                and all(_nonempty(item[key]) for key in item)
                and item["scope"] in {"user", "project"} and item["state"] in {"owned", "unknown", "stale"}
                for item in receipts
            )
            and _nonempty(data["retained_data_action"])
        ):
            return False
    return command != "add" or not verify_acquisition or command_acquisition_proof(value, tuple(targets), command="add") is not None


def validate_cli_envelope(
    value: Any, command: str, *, requested_argv: list[str] | tuple[str, ...] | None = None,
) -> bool:
    """Validate public agentplugins 0.1.14 JSON, without accepting invented shapes."""
    if requested_argv is not None:
        normalized_argv = list(requested_argv)
        try:
            command_index = normalized_argv.index(command)
        except ValueError:
            return False
        requested_argv = normalized_argv[command_index:]
    if not (
        _keys(value, {"schema_version", "command", "result", "data"})
        and _exact_int(value.get("schema_version"), 1)
        and value.get("command") == command and value.get("result") == "success"
        and isinstance(value.get("data"), dict)
    ):
        return False
    data = value["data"]
    if command in {"add", "update", "repair", "remove"}:
        valid = _validate_grouped(value, command)
        if valid and requested_argv is not None:
            argv = list(requested_argv)
            try:
                command_index = argv.index(command)
                requested_source = argv[command_index + 1]
                requested_targets = argv[argv.index("--target") + 1].split(",")
            except (ValueError, IndexError):
                return False
            expected_argv = [command, requested_source, "--target", ",".join(requested_targets), "--format", "json"]
            valid = bool(
                argv == expected_argv
                and
                requested_targets == [item["target"] for item in data["targets"]]
                and _requested_source_matches(requested_source, data, command)
            )
        return valid
    if command == "info":
        required_info = {"installation_id", "name", "source", "clients", "mixed_version"}
        optional_info = {"version", "needs_rebind", "directory", "warnings", "convergence_action"}
        if not _keys(data, required_info, optional_info):
            return False
        clients = data["clients"]
        seen: set[tuple[str, str]] = set()
        for client in clients if isinstance(clients, list) else ():
            required = {
                "client_id", "scope", "materialization", "activation", "authentication", "policy",
                "verification",
            }
            optional = {
                "package_revision", "affected_surfaces", "receipt_reconciled",
                "native_discovery_reconciled", "native_identity_state", "client_version",
                "native_discovery_evidence",
            }
            client_id = client.get("client_id") if _keys(client, required, optional) else None
            revision = client.get("package_revision") if isinstance(client, dict) else None
            if (
                not _nonempty(client_id) or (client_id, client.get("scope")) in seen or not _nonempty(client["scope"])
                or client["materialization"] not in {"absent", "staged", "materialized", "degraded"}
                or client["activation"] not in {"not_required", "prepared", "manual_activation_required", "active", "failed"}
                or client["authentication"] not in {"not_required", "not_checked", "auth_pending", "authenticated", "failed"}
                or client["policy"] not in {"allowed", "blocked", "approval_required"}
                or client["verification"] not in {"not_run", "package_validated", "installation_verified", "runtime_verified", "failed"}
                or ("affected_surfaces" in client and not _string_list(client["affected_surfaces"], nonempty=True))
                or ("receipt_reconciled" in client and type(client["receipt_reconciled"]) is not bool)
                or ("native_discovery_reconciled" in client and type(client["native_discovery_reconciled"]) is not bool)
                or ("native_identity_state" in client and client["native_identity_state"] not in {"absent", "managed", "unmanaged", "indeterminate"})
                or ("client_version" in client and not _nonempty(client["client_version"]))
            ):
                return False
            if revision is not None:
                revision_required = {"tree_digest", "manifest_digest"}
                revision_optional = {"version", "resolved_revision", "distribution_id", "release_sequence", "evidence"}
                if not (
                    _keys(revision, revision_required, revision_optional)
                    and _digest(revision["tree_digest"]) and _digest(revision["manifest_digest"])
                    and all(_optional_string(revision, name) for name in ("version", "resolved_revision", "distribution_id"))
                    and ("release_sequence" not in revision or (_exact_int(revision["release_sequence"]) and revision["release_sequence"] > 0))
                    and ("evidence" not in revision or (
                        isinstance(revision["evidence"], list)
                        and all(_validate_directory_evidence(item) for item in revision["evidence"])
                    ))
                    and ("version" not in revision or revision["version"] == data.get("version"))
                    and (("distribution_id" in revision) == ("release_sequence" in revision))
                ):
                    return False
            native_evidence = client.get("native_discovery_evidence")
            if native_evidence is not None and not _validate_native_discovery(
                native_evidence, client_id, client.get("client_version"),
                name=data["name"], installation_id=data["installation_id"],
            ):
                return False
            seen.add((client_id, client["scope"]))
        valid = bool(
            _nonempty(data["installation_id"]) and _nonempty(data["name"])
            and _nonempty(data["source"]) and isinstance(clients, list) and seen
            and _optional_string(data, "version")
            and type(data["mixed_version"]) is bool
            and ("needs_rebind" not in data or type(data["needs_rebind"]) is bool)
            and ("directory" not in data or _validate_installed_directory(data["directory"]))
            and ("warnings" not in data or (
                isinstance(data["warnings"], list) and data["warnings"]
                and all(_validate_safety_warning(item) for item in data["warnings"])
            ))
            and ("convergence_action" not in data or _nonempty(data["convergence_action"]))
            and (data["mixed_version"] == ("convergence_action" in data))
        )
        if valid and requested_argv is not None:
            argv = list(requested_argv)
            try:
                valid = (
                    argv == ["info", data["name"], "--target", ",".join(item["client_id"] for item in clients), "--format", "json"]
                    and
                    argv[argv.index("info") + 1] == data["name"]
                    and argv[argv.index("--target") + 1].split(",") == [item["client_id"] for item in clients]
                )
            except (ValueError, IndexError):
                return False
        return valid
    if command == "migrate-state":
        if not _keys(data, {"dry_run", "source_schema", "installations", "needs_rebind", "migrated", "backup_created"}):
            return False
        if not (
            type(data["dry_run"]) is bool and data["source_schema"] in {2, 3}
            and _exact_int(data["installations"]) and data["installations"] >= 1
            and _exact_int(data["needs_rebind"]) and 0 <= data["needs_rebind"] <= data["installations"]
            and _exact_int(data["migrated"]) and 0 <= data["migrated"] <= data["installations"]
            and type(data["backup_created"]) is bool
        ):
            return False
        valid = (data["migrated"], data["backup_created"]) == ((0, False) if data["dry_run"] else (data["installations"], True))
        if valid and requested_argv is not None:
            valid = list(requested_argv) == (
                ["migrate-state", "--dry-run", "--format", "json"]
                if data["dry_run"] else ["migrate-state", "--format", "json"]
            )
        return valid
    return False


FULL_SHA_UPDATE_STDERR = (
    "Resolving and validating one updated Agent Plugin package for every selected target...\n"
    "agentplugins: group update preflight failed; no target was changed: "
    "direct full-SHA installations require explicit switch\n"
)


def validate_full_sha_update_failure(
    value: Any, stderr: str, *, plugin: str, source: str, revision: str,
    tree_digest: str, expected_targets: tuple[str, ...], requested_argv: list[str] | tuple[str, ...] | None = None,
) -> bool:
    """Validate the complete public 0.1.14 preflight-refusal contract."""
    if not (
        _keys(value, {"schema_version", "command", "result", "data"})
        and _exact_int(value.get("schema_version"), 1) and value.get("command") == "update"
        and value.get("result") == "failure" and stderr == FULL_SHA_UPDATE_STDERR
    ):
        return False
    data = value["data"]
    required = {
        "operation_id", "batch", "status", "succeeded", "failed", "plugin", "version",
        "source", "revision", "tree_digest", "dry_run", "targets",
    }
    if not (
        _keys(data, required) and _nonempty(data["operation_id"]) and data["batch"] is True
        and data["status"] == "preflight_failed" and _exact_int(data["succeeded"], 0)
        and _exact_int(data["failed"], len(expected_targets)) and data["targets"] == []
        and data["plugin"] == plugin and _nonempty(data["version"]) and data["source"] == source
        and data["revision"] == revision and FULL_SHA.fullmatch(revision)
        and data["tree_digest"] == tree_digest and _digest(tree_digest) and data["dry_run"] is False
        and len(expected_targets) == len(set(expected_targets)) and bool(expected_targets)
    ):
        return False
    if requested_argv is None:
        return True
    argv = list(requested_argv)
    return argv == ["update", plugin, "--target", ",".join(expected_targets), "--format", "json"]


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stable_tree_snapshot(root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    """Read one tree through a descriptor-bound parent/child graph.

    Each child binding is checked again after its descendants have been read.
    This detects name swaps even when the replacement has identical bytes and
    metadata.  Hosted Linux must provide ``O_NOFOLLOW`` and dir-fd operations;
    callers fail closed when those guarantees are unavailable.
    """
    if not hasattr(os, "O_NOFOLLOW") or not all(function in os.supports_dir_fd for function in (os.open, os.stat, os.unlink)):
        raise ValueError("descriptor-bound no-follow snapshots are unavailable")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, flags)
    except FileNotFoundError:
        return {}, {}
    snapshot: dict[str, dict[str, Any]] = {}
    bodies: dict[str, bytes] = {}
    try:
        opened_root = os.fstat(root_fd)
        current_root = root.lstat()
        if not stat.S_ISDIR(opened_root.st_mode) or (opened_root.st_dev, opened_root.st_ino) != (current_root.st_dev, current_root.st_ino):
            raise ValueError("snapshot root changed during observation")
        def metadata_identity(metadata: os.stat_result) -> dict[str, int]:
            return {
                "device": metadata.st_dev, "inode": metadata.st_ino,
                "ctime_ns": metadata.st_ctime_ns, "mtime_ns": metadata.st_mtime_ns,
                "mode": stat.S_IMODE(metadata.st_mode),
            }

        snapshot["."] = {"kind": "directory", **metadata_identity(opened_root)}
        def walk(directory_fd: int, relative_directory: str) -> None:
            before = os.fstat(directory_fd)
            names = sorted(os.listdir(directory_fd))
            for name in names:
                if name in {".", ".."} or "/" in name:
                    raise ValueError("invalid directory entry during observation")
                relative = name if relative_directory == "." else relative_directory + "/" + name
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                common = metadata_identity(metadata)
                if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                    raise ValueError(f"unsupported filesystem object during observation: {relative}")
                if stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        identity = (opened.st_dev, opened.st_ino)
                        if identity != (metadata.st_dev, metadata.st_ino) or identity != (current.st_dev, current.st_ino):
                            raise ValueError(f"directory changed during observation: {relative}")
                        snapshot[relative] = {**common, "kind": "directory"}
                        walk(child_fd, relative)
                        rebound = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        after_child = os.fstat(child_fd)
                        if identity != (rebound.st_dev, rebound.st_ino) or identity != (after_child.st_dev, after_child.st_ino):
                            raise ValueError(f"directory binding changed during descendant observation: {relative}")
                    finally:
                        os.close(child_fd)
                    continue
                file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                try:
                    opened = os.fstat(file_fd)
                    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise ValueError(f"file changed during observation: {relative}")
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(file_fd, 1 << 20)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    after = os.fstat(file_fd)
                    stable = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stable(opened) != stable(after) or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
                        raise ValueError(f"file changed during observation: {relative}")
                    bodies[relative] = body
                    snapshot[relative] = {
                        **common, "kind": "file", "size": len(body),
                        "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                    }
                finally:
                    os.close(file_fd)
            after = os.fstat(directory_fd)
            if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError(f"directory changed during observation: {relative_directory}")
        walk(root_fd, ".")
        # Directory digests deliberately exclude filesystem identity.  The
        # identity fields above make local before/after mutation comparisons
        # replacement-sensitive; these closure digests remain portable.
        for relative in sorted(
            (name for name, item in snapshot.items() if item["kind"] == "directory"),
            key=lambda name: len(PurePosixPath(name).parts), reverse=True,
        ):
            prefix = "" if relative == "." else relative + "/"
            children = []
            for name, item in snapshot.items():
                if name == relative or not name.startswith(prefix):
                    continue
                remainder = name[len(prefix):]
                if "/" in remainder:
                    continue
                children.append([remainder, item["kind"], item.get("digest", ""), item["mode"]])
            framed = canonical_json(children)
            snapshot[relative]["digest"] = "sha256:" + hashlib.sha256(framed).hexdigest()
        current_root = root.lstat()
        if (opened_root.st_dev, opened_root.st_ino) != (current_root.st_dev, current_root.st_ino):
            raise ValueError("snapshot root was replaced during observation")
        return snapshot, bodies
    finally:
        try:
            os.close(root_fd)
        except OSError:
            pass


def tree_digest(root: Path) -> str:
    snapshot, bodies = _stable_tree_snapshot(root)
    framed = bytearray(b"uap-native-observation-v1\0")
    for relative in sorted(bodies):
        name = relative.encode()
        body = bodies[relative]
        framed.extend(len(name).to_bytes(8, "big") + name)
        framed.extend(len(body).to_bytes(8, "big") + body)
    return "sha256:" + hashlib.sha256(framed).hexdigest()


def observe(home: Path, manager: Path) -> dict[str, Any]:
    manager_snapshot = filesystem_snapshot(manager)
    native_snapshots = {name: filesystem_snapshot(home / name) for name in NATIVE_ROOTS}
    return {
        "manager": manager_snapshot,
        "native": native_snapshots,
        "portable_digests": {
            "manager": manager_snapshot.get(".", {}).get("digest"),
            "native": {name: snapshot.get(".", {}).get("digest") for name, snapshot in native_snapshots.items()},
        },
    }


def file_digests(root: Path) -> dict[str, str]:
    """Digest every regular, non-symlink file for an exact mutation allowlist."""
    snapshot, _ = _stable_tree_snapshot(root)
    return {path: item["digest"] for path, item in snapshot.items() if item["kind"] == "file"}


def filesystem_snapshot(root: Path) -> dict[str, dict[str, Any]]:
    """Capture a complete stable no-follow proof, including empty directories."""
    snapshot, _ = _stable_tree_snapshot(root)
    return snapshot


def find_value(value: Any, names: set[str]) -> Any:
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
        for child in value.values():
            found = find_value(child, names)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_value(child, names)
            if found is not None:
                return found
    return None


def find_values(value: Any, names: set[str]) -> list[Any]:
    """Return every explicitly named value without treating a state mention as proof."""
    found: list[Any] = []
    if isinstance(value, dict):
        for name, child in value.items():
            if name in names:
                found.append(child)
            found.extend(find_values(child, names))
    elif isinstance(value, list):
        for child in value:
            found.extend(find_values(child, names))
    return found


def grouped_acquisition_closure_digest(
    source_kind: str, repository: str, package_subpath: str, resolved_revision: str,
    tree_digest: str, manifest_digest: str,
) -> str:
    """Reproduce agentplugins/grouped-acquisition-closure/v1 exactly."""
    digest = hashlib.sha256()
    for field in (
        "agentplugins/grouped-acquisition-closure/v1", source_kind, repository,
        package_subpath, resolved_revision, tree_digest, manifest_digest,
    ):
        body = field.strip().encode()
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return "sha256:" + digest.hexdigest()


def command_acquisition_proof(
    value: Any, clients: tuple[str, ...], *, command: str,
) -> dict[str, Any] | None:
    """Validate the exact grouped-add JSON envelope and return its proof.

    Installed state and package identity fields intentionally do not satisfy this
    contract: the command output must expose the acquisition event itself.
    """
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("command") != command
        or value.get("result") != "success"
        or not isinstance(value.get("data"), dict)
        or "acquisition" in value
        or "acquisitions" in value
        or "target_outcomes" in value
        or len(clients) != len(set(clients))
    ):
        return None
    if not _validate_grouped(value, command, verify_acquisition=False):
        return None
    data = value["data"]
    if (
        "acquisition" not in data
        or "target_outcomes" not in data
        or not isinstance(data["acquisition"], dict)
        or len(find_values(value, {"acquisition"})) != 1
        or len(find_values(value, {"target_outcomes"})) != 1
        or find_values(value, {"acquisitions"})
    ):
        return None
    acquisition = data["acquisition"]
    if set(acquisition) != {
        "acquisition_id", "acquisition_count", "tree_digest", "manifest_digest",
        "closure_digest", "source_kind", "fetched", "validated",
    }:
        return None
    identity = acquisition.get("acquisition_id")
    count = acquisition.get("acquisition_count")
    tree_digest = acquisition.get("tree_digest")
    manifest_digest = acquisition.get("manifest_digest")
    closure_digest = acquisition.get("closure_digest")
    source_kind = acquisition.get("source_kind")
    fetched = acquisition.get("fetched")
    validated = acquisition.get("validated")
    if not (
        isinstance(identity, str) and identity.strip()
        and type(count) is int and count == 1
        and isinstance(tree_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", tree_digest)
        and isinstance(manifest_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest)
        and isinstance(closure_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", closure_digest)
        and source_kind in {"github", "local", "directory"}
        and fetched is (source_kind != "local") and validated is True
    ):
        return None

    target_values = data["target_outcomes"]
    raw_targets = data.get("targets")
    if command == "add":
        if not isinstance(raw_targets, list) or len(raw_targets) != len(clients):
            return None
        target_names = [item.get("target") if isinstance(item, dict) else None for item in raw_targets]
        if target_names != list(clients) or len(target_names) != len(set(target_names)):
            return None
        installation_ids: set[str] = set()
        for item, client in zip(raw_targets, clients):
            output = item.get("output") if isinstance(item, dict) else None
            result = output.get("result") if isinstance(output, dict) else None
            plan = result.get("plan") if isinstance(result, dict) else None
            if not (
                item.get("status") == "external_completed"
                and output.get("operation_id") == data["operation_id"]
                and output.get("plugin") == data["plugin"]
                and output.get("version") == data["version"]
                and output.get("source") == data["source"]
                and output.get("revision") == data.get("revision")
                and output.get("tree_digest") == tree_digest
                and output.get("manifest_digest") == manifest_digest
                and output.get("dry_run") is False
                and isinstance(plan, dict) and plan.get("client_id") == client
                and isinstance(result.get("installation_id"), str) and result["installation_id"]
            ):
                return None
            installation_ids.add(result["installation_id"])
        if len(installation_ids) != 1 or data["succeeded"] != len(raw_targets):
            return None
    if (
        not isinstance(target_values, dict)
        or set(target_values) != set(clients)
        or not all(isinstance(item, dict) for item in target_values.values())
    ):
        return None
    outcomes = copy.deepcopy(target_values)
    expected_binding = {
        "outcome": "passed",
        "acquisition_id": identity,
        "tree_digest": tree_digest,
        "manifest_digest": manifest_digest,
        "closure_digest": closure_digest,
    }
    if any(outcome != expected_binding for outcome in outcomes.values()):
        return None
    repository = package_path = revision = ""
    if source_kind in {"github", "directory"}:
        try:
            repository, package_path = data["source"].split("//", 1)
        except ValueError:
            return None
        revision = data.get("revision", "")
        if not (
            GITHUB_REPOSITORY.fullmatch(repository) and GITHUB_SOURCE_PATH.fullmatch(package_path)
            and not package_path.startswith("/") and not package_path.endswith("/")
            and all(part not in {"", ".", ".."} for part in package_path.split("/"))
            and FULL_SHA.fullmatch(revision)
        ):
            return None
    elif data.get("source") != "direct local source" or "revision" in data:
        return None
    expected_closure = grouped_acquisition_closure_digest(
        source_kind, repository, package_path, revision, tree_digest, manifest_digest,
    )
    if (
        closure_digest != expected_closure
        or data["tree_digest"] != tree_digest or data["manifest_digest"] != manifest_digest
    ):
        return None
    return {
        "acquisition_id": identity,
        "acquisition_count": count,
        "tree_digest": tree_digest,
        "manifest_digest": manifest_digest,
        "closure_digest": closure_digest,
        "source_kind": source_kind,
        "fetched": fetched,
        "validated": validated,
        "source_repository": repository,
        "source_revision": revision,
        "source_path": package_path,
        "targets": copy.deepcopy(raw_targets),
        "target_outcomes": outcomes,
    }


def grouped_acquisition_proof(value: Any, clients: tuple[str, ...]) -> dict[str, Any] | None:
    return command_acquisition_proof(value, clients, command="add")


def json_output(completed: subprocess.CompletedProcess[str], command: str | None = None) -> dict[str, Any] | None:
    if completed.returncode:
        return None
    try:
        value = strict_json_loads(completed.stdout)
    except (json.JSONDecodeError, DuplicateKeyError, ValueError):
        return None
    requested = completed.args if isinstance(completed.args, (list, tuple)) else None
    return value if isinstance(value, dict) and (
        command is None or validate_cli_envelope(value, command, requested_argv=requested)
    ) else None


def parse_canonical_github_source(value: Any) -> dict[str, str] | None:
    """Normalize documented and production GitHub canonical source identities."""
    if not isinstance(value, str) or any(character in value for character in "?#\\%"):
        return None
    repository_locator = value.removeprefix("https://github.com/")
    try:
        repository, locator = repository_locator.split("@", 1)
        revision, package_path = locator.split("//", 1)
    except ValueError:
        return None
    path = PurePosixPath(package_path)
    if (
        not GITHUB_REPOSITORY.fullmatch(repository)
        or not FULL_SHA.fullmatch(revision)
        or not GITHUB_SOURCE_PATH.fullmatch(package_path)
        or not package_path
        or package_path.startswith("/")
        or package_path.endswith("/")
        or "//" in package_path
        or any(part in {"", ".", ".."} for part in package_path.split("/"))
        or path.as_posix() != package_path
    ):
        return None
    return {
        "source_repository": repository,
        "source_revision": revision,
        "source_path": package_path,
    }


def source_identities_match(expected: Any, observed: Any) -> bool:
    """Compare source identities structurally while preserving the observed spelling."""
    if not isinstance(expected, dict) or not isinstance(observed, dict) or set(expected) != set(observed):
        return False
    expected_canonical = parse_canonical_github_source(expected.get("canonical_source"))
    observed_canonical = parse_canonical_github_source(observed.get("canonical_source"))
    return bool(
        expected_canonical
        and expected_canonical == observed_canonical
        and all(
            observed.get(field) == expected.get(field)
            for field in expected
            if field != "canonical_source"
        )
    )


def manager_facts(manager: Path, product: str) -> dict[str, Any]:
    state = manager_state(manager)
    installations = state.get("installations", []) if state else []
    matches = [item for item in installations if isinstance(item, dict) and item.get("declared_name") == product]
    receipts = installation_receipts(manager, product) or []
    digests = sorted({
        child for child in find_values(matches, {"tree_digest", "manifest_digest", "after_digest", "managed_digest"})
        if isinstance(child, str) and DIGEST.fullmatch(child)
    })
    return {
        "json_files": 1 if state else 0,
        "committed_receipts": len(receipts),
        "product_mentions": len(matches),
        "installation_records": len(matches),
        "digests": digests,
    }


def manager_state(
    manager: Path, *, removal_authority: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Read only the State-v4 contract file, without following a link."""
    try:
        _, bodies = _stable_tree_snapshot(manager)
        value = strict_json_loads(bodies["state-v2.json"])
    except (OSError, KeyError, UnicodeError, json.JSONDecodeError, DuplicateKeyError, ValueError):
        return None
    if (
        not isinstance(value, dict) or not {"schema_version", "installations"} <= set(value) <= {"schema_version", "installations", "transaction_receipts"}
        or not _exact_int(value.get("schema_version"), 4)
        or not isinstance(value.get("installations"), list)
        or not validate_released_state_v4(value)
    ):
        return None
    installation_ids: set[str] = set()
    source_binding_ids: set[str] = set()
    global_binding_ids: set[str] = set()
    global_receipt_ids: set[str] = set()
    global_operation_ids: set[str] = set()
    global_paths: dict[str, str] = {}
    binding_authority: dict[str, dict[str, Any]] = {}

    def owned_path(value: Any, owner: str) -> bool:
        if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
            return False
        path = PurePosixPath(value)
        if any(part in {"", ".", ".."} for part in path.parts[1:]) or str(path) != value:
            return False
        for existing, previous in global_paths.items():
            if previous == owner:
                continue
            existing_path = PurePosixPath(existing)
            if path == existing_path or path in existing_path.parents or existing_path in path.parents:
                return False
        global_paths[value] = owner
        return True
    for installation in value["installations"]:
        required = {"installation_id", "declared_name", "source", "package", "clients", "created_at", "updated_at"}
        optional = {"origin_mode", "directory", "operation_group_id", "data_receipts", "data_retained", "needs_rebind"}
        if not _keys(installation, required, optional):
            return None
        installation_id = installation["installation_id"]
        name = installation["declared_name"]
        if not _valid_leaf_id(installation_id) or not _nonempty(name) or installation_id in installation_ids:
            return None
        installation_ids.add(installation_id)
        origin_mode = installation.get("origin_mode")
        directory = installation.get("directory")
        if origin_mode not in {"direct", "directory"}:
            return None
        if origin_mode == "direct" and directory is not None:
            return None
        if origin_mode == "directory" and not (
            _keys(directory, {"product_id", "distribution_id", "distribution_kind", "desired_release_sequence"},
                  {"snapshot_schema", "snapshot_sequence", "snapshot_digest"})
            and _nonempty(directory["product_id"])
            and _nonempty(directory["distribution_id"])
            and directory["distribution_kind"] in {"upstream", "community_bridge", "community"}
            and _exact_int(directory["desired_release_sequence"]) and directory["desired_release_sequence"] > 0
            and _directory_snapshot_coherent(directory)
            # Evidence-only strengthening: released State.Validate does not
            # bind this product ID to the enclosing installation identity.
            and directory["product_id"] == name
        ):
            return None
        if "operation_group_id" in installation:
            if not _valid_leaf_id(installation["operation_group_id"]):
                return None
        source = installation["source"]
        package = installation["package"]
        if not (
            _keys(source, {"source_binding_id", "requested_source", "canonical_source", "resolved_revision", "tree_digest"}, {"repository", "package_subpath", "publisher"})
            and all(_nonempty(source[key]) for key in ("source_binding_id", "requested_source", "canonical_source", "tree_digest"))
            and source["source_binding_id"] not in source_binding_ids
            and isinstance(source["resolved_revision"], str)
            and _digest(source["tree_digest"])
            and (not source.get("repository") or (
                GITHUB_REPOSITORY.fullmatch(source["repository"]) is not None
                and FULL_SHA.fullmatch(source["resolved_revision"]) is not None
                and GITHUB_SOURCE_PATH.fullmatch(source.get("package_subpath", "")) is not None
            ))
            and _keys(package, {"loader_kind", "format_id", "schema_uri", "declared_name", "manifest_digest", "inventory"}, {"version"})
            and package["loader_kind"] == "agent_plugins" and package["format_id"] == "agent-plugins/1.0.0"
            and package["schema_uri"] == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
            and package["declared_name"] == name and _validate_inventory(package["inventory"]) and _digest(package["manifest_digest"])
            and ("version" not in package or _nonempty(package["version"]))
        ):
            return None
        source_binding_ids.add(source["source_binding_id"])
        if origin_mode == "directory" and FULL_SHA.fullmatch(source["resolved_revision"]) is None:
            return None
        clients = installation["clients"]
        if not isinstance(clients, dict):
            return None
        client_ids: set[tuple[str, str]] = set()
        for binding_id, binding in clients.items():
            required_binding = {
                "client_binding_id", "client_id", "scope", "target_locator", "physical_artifact_id",
                "materialization", "activation", "authentication", "policy", "verification", "updated_at",
            }
            optional_binding = {"package_revision", "data_receipt_id", "affected_surfaces", "native_objects", "receipts"}
            if (
                not _keys(binding, required_binding, optional_binding)
                or binding.get("client_binding_id") != binding_id or not _valid_leaf_id(binding_id)
                or binding_id in global_binding_ids
            ):
                return None
            global_binding_ids.add(binding_id)
            client_id = binding.get("client_id")
            client_identity = (client_id, binding.get("scope"))
            if not _nonempty(client_id) or client_identity in client_ids or binding.get("scope") not in {"user", "project"}:
                return None
            client_ids.add(client_identity)
            if not (
                binding["materialization"] in {"absent", "staged", "materialized", "degraded"}
                and binding["activation"] in {"not_required", "prepared", "manual_activation_required", "active", "failed"}
                and binding["authentication"] in {"not_required", "not_checked", "auth_pending", "authenticated", "failed"}
                and binding["policy"] in {"allowed", "blocked", "approval_required"}
                and binding["verification"] in {"not_run", "package_validated", "installation_verified", "runtime_verified", "failed"}
                and _valid_leaf_id(binding["physical_artifact_id"])
                and owned_path(binding["target_locator"], binding_id)
                and ("affected_surfaces" not in binding or _string_list(binding["affected_surfaces"], nonempty=True))
            ):
                return None
            if "native_objects" in binding and not isinstance(binding["native_objects"], list):
                return None
            if "receipts" in binding and not isinstance(binding["receipts"], list):
                return None
            revision = binding.get("package_revision")
            if revision is not None and not _validate_package_revision(
                revision, revision=None, tree=revision.get("tree_digest", ""), manifest=revision.get("manifest_digest", ""),
            ):
                return None
            if origin_mode == "directory" and not (
                isinstance(revision, dict)
                and revision.get("distribution_id") == directory["distribution_id"]
                and _exact_int(revision.get("release_sequence"))
                and 1 <= revision["release_sequence"] <= directory["desired_release_sequence"]
                and FULL_SHA.fullmatch(str(revision.get("resolved_revision", ""))) is not None
            ):
                return None
            native_objects = binding.get("native_objects", [])
            object_ids: set[str] = set()
            for native_object in native_objects:
                if not (
                    _keys(native_object, {"object_id", "kind", "protection_class"},
                          {"logical_name", "path", "before_digest", "managed_digest", "user_modified"})
                    and all(_nonempty(native_object[key]) for key in ("object_id", "kind", "protection_class"))
                    and all(_optional_string(native_object, key) for key in ("logical_name", "path"))
                    and all(key not in native_object or _digest(native_object[key]) for key in ("before_digest", "managed_digest"))
                    and ("user_modified" not in native_object or type(native_object["user_modified"]) is bool)
                    and native_object["object_id"] not in object_ids
                    and ("path" not in native_object or owned_path(native_object["path"], binding_id))
                ):
                    return None
                object_ids.add(native_object["object_id"])
            for receipt in binding.get("receipts", []):
                if not (
                    _keys(receipt, {"operation_id", "operation_group_id", "sequence", "mutation_type", "client_binding_id", "active_path", "staging_path", "backup_path", "after_digest", "phase"}, {"before_digest"})
                    and _valid_leaf_id(receipt["operation_id"]) and receipt["operation_id"] not in global_operation_ids
                    and _valid_leaf_id(receipt["operation_group_id"])
                    and receipt["operation_group_id"] == installation.get("operation_group_id")
                    and receipt["client_binding_id"] == binding_id and _exact_int(receipt["sequence"])
                    and receipt["sequence"] >= 1 and receipt["mutation_type"] == "directory_swap"
                    and receipt["phase"] == "committed" and receipt["active_path"] == binding["target_locator"]
                    and PurePosixPath(receipt["staging_path"]).parent == PurePosixPath(binding["target_locator"]).parent
                    and PurePosixPath(receipt["backup_path"]).parent == PurePosixPath(binding["target_locator"]).parent
                    and owned_path(receipt["staging_path"], receipt["operation_id"])
                    and owned_path(receipt["backup_path"], receipt["operation_id"])
                    and _digest(receipt["after_digest"])
                    and len([
                        item for item in native_objects
                        if item.get("path") == receipt["active_path"]
                        and item.get("managed_digest") == receipt["after_digest"]
                    ]) == 1
                    and ("before_digest" not in receipt or _digest(receipt["before_digest"]))
                ):
                    return None
                global_operation_ids.add(receipt["operation_id"])
            binding_authority[binding_id] = {
                "client_binding_id": binding_id,
                "client_id": client_id,
                "active_path": binding["target_locator"],
                "physical_artifact_id": binding["physical_artifact_id"],
                "before_digest": next(iter({item["managed_digest"] for item in native_objects}), None),
                "operation_group_id": installation.get("operation_group_id"),
            }
        data_receipts = installation.get("data_receipts", {})
        if not isinstance(data_receipts, dict):
            return None
        if installation.get("data_retained") is True and (clients or not data_receipts):
            return None
        for receipt_id, receipt in data_receipts.items():
            if not (
                _keys(receipt, {"data_receipt_id", "physical_backend_id", "scope", "locator", "ownership_digest", "state"}, {"created_at", "updated_at"})
                and receipt.get("data_receipt_id") == receipt_id and _valid_leaf_id(receipt_id)
                and receipt.get("scope") in {"user", "project"}
                and receipt.get("state") in {"owned", "unknown", "stale"} and _digest(receipt.get("ownership_digest"))
                and receipt_id not in global_receipt_ids and _nonempty(receipt.get("physical_backend_id"))
                and owned_path(receipt.get("locator"), receipt_id)
            ):
                return None
            global_receipt_ids.add(receipt_id)
        if any(
            "data_receipt_id" in binding and (
                binding["data_receipt_id"] not in data_receipts
                or data_receipts[binding["data_receipt_id"]]["physical_backend_id"] != binding["physical_artifact_id"]
            ) for binding in clients.values()
        ):
            return None
    transaction_receipts = value.get("transaction_receipts", [])
    if not isinstance(transaction_receipts, list):
        return None
    for receipt in transaction_receipts:
        if not (
            _keys(receipt, {"operation_id", "sequence", "mutation_type", "client_binding_id", "phase"}, {"operation_group_id", "active_path", "staging_path", "backup_path", "before_digest", "after_digest"})
            and _valid_leaf_id(receipt["operation_id"]) and _exact_int(receipt["sequence"])
            and receipt["sequence"] >= 1 and _nonempty(receipt["client_binding_id"])
            and receipt["phase"] == "committed"
            and receipt["operation_id"] not in global_operation_ids
        ):
            return None
        if receipt["mutation_type"] == "directory_remove":
            removed = removal_authority.get(receipt["client_binding_id"]) if removal_authority else None
            if not (
                set(receipt) == {"operation_id", "operation_group_id", "sequence", "mutation_type", "client_binding_id", "active_path", "backup_path", "before_digest", "phase"}
                and _valid_leaf_id(receipt["operation_group_id"])
                and owned_path(receipt["active_path"], receipt["client_binding_id"])
                and owned_path(receipt["backup_path"], receipt["operation_id"])
                and PurePosixPath(receipt["active_path"]).parent == PurePosixPath(receipt["backup_path"]).parent
                and _digest(receipt["before_digest"])
                and (removed is None or (
                    receipt["active_path"] == removed.get("active_path")
                    and receipt["before_digest"] == removed.get("before_digest")
                ))
            ):
                return None
        elif receipt["mutation_type"] == "directory_swap":
            authority = binding_authority.get(receipt["client_binding_id"])
            if not (
                set(receipt) == {"operation_id", "operation_group_id", "sequence", "mutation_type", "client_binding_id", "active_path", "staging_path", "backup_path", "before_digest", "after_digest", "phase"}
                and authority is not None
                and receipt["operation_group_id"] == authority["operation_group_id"]
                and receipt["active_path"] == authority["active_path"]
                and _digest(receipt["before_digest"]) and _digest(receipt["after_digest"])
                and owned_path(receipt["staging_path"], receipt["operation_id"])
                and owned_path(receipt["backup_path"], receipt["operation_id"])
                and PurePosixPath(receipt["staging_path"]).parent == PurePosixPath(receipt["active_path"]).parent
                and PurePosixPath(receipt["backup_path"]).parent == PurePosixPath(receipt["active_path"]).parent
                and receipt["after_digest"] == authority["before_digest"]
            ):
                return None
        else:
            return None
        global_operation_ids.add(receipt["operation_id"])
    if global_paths:
        try:
            authority_root = Path(os.path.commonpath(tuple(global_paths)))
            manager_root = manager.resolve(strict=True)
        except (OSError, ValueError):
            return None
        if authority_root == Path("/") or not (
            authority_root == manager_root or manager_root in authority_root.parents
        ):
            return None
    return value


def selected_manager_installation(manager: Path, product: str) -> dict[str, Any] | None:
    """Select one installation without combining authority across files/records."""
    state = manager_state(manager)
    if state is None or len(state["installations"]) != 1:
        return None
    installation = state["installations"][0]
    return copy.deepcopy(installation) if installation.get("declared_name") == product else None


def removal_authority_from_installation(installation: Any) -> dict[str, dict[str, Any]] | None:
    if not isinstance(installation, dict) or not _nonempty(installation.get("installation_id")):
        return None
    authority: dict[str, dict[str, Any]] = {}
    for binding_id, binding in installation.get("clients", {}).items():
        native = binding.get("native_objects") if isinstance(binding, dict) else None
        digests = {
            item.get("managed_digest") for item in native or []
            if isinstance(item, dict) and _digest(item.get("managed_digest"))
        }
        if not isinstance(binding_id, str) or len(digests) != 1:
            return None
        authority[binding_id] = {
            "client_binding_id": binding_id, "client_id": binding.get("client_id"),
            "physical_artifact_id": binding.get("physical_artifact_id"),
            "active_path": binding.get("target_locator"), "before_digest": next(iter(digests)),
            "installation_id": installation["installation_id"],
            "data_receipt_id": binding.get("data_receipt_id"),
        }
        if not all(_nonempty(value) for value in authority[binding_id].values()):
            return None
    return authority or None


def frozen_data_receipt_map(installation: Any) -> dict[str, dict[str, Any]] | None:
    """Freeze every persistent-data authority field before a non-purge remove.

    ``updated_at`` is the sole documented mutable field; removal may refresh
    that timestamp but may not redirect authority or alter ownership state.
    ``created_at`` remains immutable when present.
    """
    receipts = installation.get("data_receipts") if isinstance(installation, dict) else None
    if not isinstance(receipts, dict) or not receipts:
        return None
    frozen: dict[str, dict[str, Any]] = {}
    for receipt_id, receipt in receipts.items():
        if not (
            isinstance(receipt, dict) and receipt.get("data_receipt_id") == receipt_id
            and _valid_leaf_id(receipt_id) and _nonempty(receipt.get("physical_backend_id"))
            and receipt.get("scope") in {"user", "project"} and _nonempty(receipt.get("locator"))
            and _digest(receipt.get("ownership_digest"))
            and receipt.get("state") in {"owned", "unknown", "stale"}
        ):
            return None
        frozen[receipt_id] = {
            key: copy.deepcopy(receipt.get(key))
            for key in (
                "data_receipt_id", "physical_backend_id", "scope", "locator",
                "ownership_digest", "state", "created_at",
            )
        }
    return frozen


def public_receipts_bind_frozen_authority(value: Any, frozen: Any) -> bool:
    if not isinstance(value, list) or not isinstance(frozen, dict):
        return False
    public = {
        receipt_id: {
            "data_receipt_id": receipt_id,
            "physical_backend_id": receipt["physical_backend_id"],
            "scope": receipt["scope"], "state": receipt["state"],
        }
        for receipt_id, receipt in frozen.items()
    }
    observed = {
        item.get("data_receipt_id"): item for item in value if isinstance(item, dict)
    }
    return len(observed) == len(value) and observed == public


def removal_receipts_bind_command(
    before_state: Any, after_state: Any, authority: Any, operation_group_id: Any,
    clients: tuple[str, ...], retained_installation: Any,
) -> bool:
    """Bind released removal receipts to pre-operation binding/native authority."""
    if not isinstance(before_state, dict) or not isinstance(after_state, dict) or not isinstance(authority, dict):
        return False
    before = before_state.get("transaction_receipts", [])
    after = after_state.get("transaction_receipts", [])
    if not isinstance(before, list) or not isinstance(after, list) or after[:len(before)] != before:
        return False
    delta = after[len(before):]
    if len(delta) != len(clients) or not _nonempty(operation_group_id):
        return False
    by_client = {item["client_id"]: item for item in authority.values()}
    if set(by_client) != set(clients):
        return False
    seen: set[str] = set()
    for receipt in delta:
        binding = authority.get(receipt.get("client_binding_id")) if isinstance(receipt, dict) else None
        if not isinstance(binding, dict) or binding["client_id"] in seen:
            return False
        if not (
            set(receipt) == {"operation_id", "operation_group_id", "sequence", "mutation_type", "client_binding_id", "active_path", "backup_path", "before_digest", "phase"}
            and receipt["operation_group_id"] == operation_group_id
            and receipt["mutation_type"] == "directory_remove" and receipt["phase"] == "committed"
            and receipt["active_path"] == binding["active_path"]
            and receipt["before_digest"] == binding["before_digest"]
            and PurePosixPath(receipt["backup_path"]).parent == PurePosixPath(binding["active_path"]).parent
        ):
            return False
        seen.add(binding["client_id"])
    if not isinstance(retained_installation, dict) or retained_installation.get("installation_id") != next(iter(authority.values()))["installation_id"]:
        return False
    return retained_installation.get("clients") == {} and all(
        receipt_id in retained_installation.get("data_receipts", {})
        for receipt_id in {binding["data_receipt_id"] for binding in authority.values()}
    )


def installation_receipts(manager: Path, product: str) -> list[dict[str, Any]] | None:
    """Return committed receipts only from the uniquely selected installation."""
    installation = selected_manager_installation(manager, product)
    if installation is None:
        return None
    entries: list[dict[str, Any]] = []
    bindings = installation.get("clients")
    if not isinstance(bindings, dict) or not bindings:
        return None
    client_ids: set[str] = set()
    for binding_key, binding in bindings.items():
        if not isinstance(binding_key, str) or not isinstance(binding, dict):
            return None
        binding_id = binding.get("client_binding_id")
        client_id = binding.get("client_id")
        raw = binding.get("receipts")
        native_objects = binding.get("native_objects")
        if (
            binding_id != binding_key or not isinstance(client_id, str) or not client_id
            or client_id in client_ids or not isinstance(raw, list) or not raw
            or not isinstance(native_objects, list) or not native_objects
        ):
            return None
        client_ids.add(client_id)
        managed_digests = {
            item.get("managed_digest") for item in native_objects
            if isinstance(item, dict) and isinstance(item.get("managed_digest"), str)
            and DIGEST.fullmatch(item["managed_digest"])
        }
        if not managed_digests:
            return None
        sequences: list[int] = []
        for receipt in raw:
            if not isinstance(receipt, dict) or not (
                isinstance(receipt.get("operation_id"), str) and receipt["operation_id"]
                and _nonempty(receipt.get("operation_group_id"))
                and receipt.get("client_binding_id") == binding_id
                and _exact_int(receipt.get("sequence")) and receipt["sequence"] >= 1
                and receipt.get("phase") == "committed"
                and isinstance(receipt.get("after_digest"), str) and DIGEST.fullmatch(receipt["after_digest"])
                and receipt["after_digest"] in managed_digests
            ):
                return None
            sequences.append(receipt["sequence"])
            entries.append({
                "receipt": copy.deepcopy(receipt), "binding_client": client_id,
                "client_binding_id": binding_id, "operation_group_id": receipt["operation_group_id"],
                "installation_id": installation["installation_id"],
                "physical_artifact_id": binding.get("physical_artifact_id"),
                "active_path": binding.get("target_locator"),
                "native_object_ids": sorted(
                    item["object_id"] for item in native_objects if isinstance(item, dict) and _nonempty(item.get("object_id"))
                ),
            })
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            return None
    return entries


def receipts_bind_command(
    before: list[dict[str, Any]], after: list[dict[str, Any]], operation: str, clients: tuple[str, ...],
    *, operation_group_id: str | None = None,
) -> bool:
    """Bind the exact receipt delta while leaving historical operation groups intact."""
    if operation not in {"add", "repair"} or len(clients) != len(set(clients)) or not after:
        return False
    before_by_id = {entry["receipt"].get("operation_id"): entry for entry in before}
    after_by_id = {entry["receipt"].get("operation_id"): entry for entry in after}
    if len(before_by_id) != len(before) or len(after_by_id) != len(after):
        return False
    if any(after_by_id.get(key) != entry for key, entry in before_by_id.items()):
        return False
    delta = [entry for key, entry in after_by_id.items() if key not in before_by_id]
    previous_by_binding: dict[str, dict[str, Any]] = {}
    for entry in before:
        current = previous_by_binding.get(entry["client_binding_id"])
        if current is None or entry["receipt"]["sequence"] > current["receipt"]["sequence"]:
            previous_by_binding[entry["client_binding_id"]] = entry
    groups = {entry.get("operation_group_id") for entry in delta}
    covered = [entry.get("binding_client") for entry in delta]
    return bool(
        len(delta) == len(clients) and len(groups) == 1
        and (operation_group_id is None or groups == {operation_group_id})
        and set(covered) == set(clients) and len(covered) == len(clients)
        and all(
            entry["receipt"].get("mutation_type") == "directory_swap"
            and entry["receipt"].get("active_path") == entry["active_path"]
            and entry["receipt"].get("after_digest")
            and _nonempty(entry["physical_artifact_id"])
            and entry["native_object_ids"]
            and (
                operation != "repair" or (
                    entry["client_binding_id"] in previous_by_binding
                    and entry["receipt"].get("before_digest")
                    == previous_by_binding[entry["client_binding_id"]]["receipt"].get("after_digest")
                )
            )
            for entry in delta
        )
    )


def materialized_product_mentions(home: Path, manager: Path, product: str, clients: tuple[str, ...]) -> dict[str, int]:
    """Descriptor-read only receipt-owned targets; name mentions are not evidence."""
    result = {client: 0 for client in clients}
    installation = selected_manager_installation(manager, product)
    if installation is None:
        return result
    allowed_roots = tuple(path.resolve(strict=True) for path in (home, manager) if path.exists())
    for binding in installation.get("clients", {}).values():
        if not isinstance(binding, dict) or binding.get("client_id") not in result:
            continue
        target = Path(str(binding.get("target_locator", "")))
        native = [
            item for item in binding.get("native_objects", [])
            if isinstance(item, dict) and item.get("kind") == "managed_package_directory"
            and item.get("path") == str(target)
        ]
        receipts = [
            item for item in binding.get("receipts", [])
            if isinstance(item, dict) and item.get("active_path") == str(target)
            and item.get("after_digest") in {entry.get("managed_digest") for entry in native}
            and item.get("phase") == "committed"
        ]
        try:
            resolved = target.resolve(strict=True)
            contained = any(resolved == root or root in resolved.parents for root in allowed_roots)
            snapshot, bodies = _stable_tree_snapshot(target)
            identity = package_identity(target, observed=(snapshot, bodies))
            manifest = strict_json_loads(bodies["plugin.json"])
        except (OSError, ValueError, json.JSONDecodeError, DuplicateKeyError):
            continue
        if (
            contained and len(native) == 1 and receipts
            and identity["tree_digest"] == native[0]["managed_digest"]
            and isinstance(manifest, dict) and manifest.get("name") == product
        ):
            result[binding["client_id"]] += 1
    return result


def evidence_tuple(context: dict[str, Any], value: dict[str, Any], dependency: str, *, client_identity: str | None = None) -> dict[str, Any]:
    release = context["release"]
    return {
        "product_id": release["product_id"], "tree_digest": release["tree_digest"],
        "manifest_digest": release["manifest_digest"], "distribution_id": release["distribution_id"],
        "distribution_kind": release["distribution_kind"], "release_sequence": release["release_sequence"],
        "package_version": release["package_version"], "snapshot_sequence": context["snapshot_sequence"],
        "source_repository": release.get("source_repository"),
        "source_revision": release.get("source_revision"),
        "source_path": release.get("source_path"),
        "snapshot_digest": context["directory_digest"], "binary_digest": context["binary_digest"],
        "dependency_identity": dependency, "installer_version": context["expected_version"],
        "adapter_version": context["expected_version"],
        "client_version": client_identity or find_value(value, {"client_version"}),
        "os": platform.system() or "unknown", "architecture": platform.machine() or "unknown",
        "observed_at": now(),
    }


def identity_matches_release(identity: dict[str, Any], context: dict[str, Any]) -> bool:
    release = context["release"]
    canonical = parse_canonical_github_source(identity.get("canonical_source"))
    if not all(release.get(field) for field in ("source_repository", "source_revision", "source_path")):
        return False
    expected = {
        "product_id": release["product_id"],
        "tree_digest": release["tree_digest"],
        "manifest_digest": release["manifest_digest"],
        "resolved_revision": release["source_revision"],
        "origin_mode": "directory",
        "distribution_id": release["distribution_id"],
        "distribution_kind": release["distribution_kind"],
        "desired_release_sequence": release["release_sequence"],
        "snapshot_schema": 1,
        "snapshot_sequence": context["snapshot_sequence"],
        "snapshot_digest": context["directory_digest"],
    }
    expected_source = {
        "source_repository": release["source_repository"],
        "source_revision": release["source_revision"],
        "source_path": release["source_path"],
    }
    return bool(canonical == expected_source and all(identity.get(field) == value for field, value in expected.items()))


def traced(binary: Path, argv: list[str], cwd: Path, challenge: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    started = now()
    completed = subprocess.run([str(binary), *argv], cwd=cwd, env=os.environ.copy(), text=True, capture_output=True, check=False, timeout=180)
    ended = now()
    trace = {
        "challenge": challenge, "argv": argv, "started_at": started, "ended_at": ended,
        "exit_code": completed.returncode,
        "stdout_digest": "sha256:" + hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_digest": "sha256:" + hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    return completed, trace


def traced_with_environment(
    binary: Path, argv: list[str], cwd: Path, challenge: str, environment: dict[str, str],
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    original = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(environment)
        return traced(binary, argv, cwd, challenge)
    finally:
        os.environ.clear()
        os.environ.update(original)


def conformance_directory(
    root: Path, context: dict[str, Any], *, sequence: int,
    default_alternate: bool = False, revoked: bool = False,
    safe_successor: bool = False, sequence_over_semver: bool = False,
    generated_offset: timedelta = timedelta(0), lifetime: timedelta = timedelta(hours=2),
    target_delivery: str = "managed",
) -> tuple[dict[str, str], str]:
    """Create a visibly non-production signed policy fixture from authenticated release bytes."""
    product = copy.deepcopy(context["directory_product"])
    source_distribution = copy.deepcopy(context["directory_distribution"])
    selected_sequence = context["release"]["release_sequence"]
    release = copy.deepcopy(next(item for item in source_distribution["releases"] if item["sequence"] == selected_sequence))
    policy = copy.deepcopy(next(item for item in source_distribution["release_policies"] if item["release_sequence"] == selected_sequence))
    authentication_by_client = {
        target["client"]: target.get("authentication", "unknown")
        for target in policy["targets"]
    }
    release["sequence"] = 1
    release["published_at"] = now()
    policy["release_sequence"] = 1
    policy["minimum_installer_version"] = "0.1.14"
    policy["targets"] = [
        {
            "client": client,
            "delivery": target_delivery,
            "scopes": ["user"],
            "authentication": authentication_by_client.get(client, "unknown"),
        }
        for client in ("codex", "cursor", "kiro")
    ]
    policy["current_evidence"] = []
    policy["status"] = "revoked" if revoked else "active"
    source_distribution["releases"] = [release]
    source_distribution["release_policies"] = [policy]
    source_distribution["status"] = "active"
    distributions = [source_distribution]
    revocations = [{"distribution_id": source_distribution["id"], "release_sequence": 1}] if revoked else []
    if safe_successor or sequence_over_semver:
        successor = copy.deepcopy(release)
        successor["sequence"] = 2
        successor["package_version"] = "1.0.0" if sequence_over_semver else release["package_version"]
        if sequence_over_semver:
            release["package_version"] = "9.0.0"
        successor_policy = copy.deepcopy(policy)
        successor_policy["release_sequence"] = 2
        successor_policy["status"] = "active"
        source_distribution["releases"].append(successor)
        source_distribution["release_policies"].append(successor_policy)
    if default_alternate:
        alternate = copy.deepcopy(source_distribution)
        alternate["id"] = "fixture/context7-alternate"
        alternate["kind"] = "community"
        alternate["packager"] = "fixture"
        product["default_distribution"] = alternate["id"]
        product["distributions"] = [source_distribution["id"], alternate["id"]]
        distributions.append(alternate)
    else:
        product["default_distribution"] = source_distribution["id"]
        product["distributions"] = [source_distribution["id"]]
    generated = datetime.now(timezone.utc).replace(microsecond=0) + generated_offset
    snapshot = {
        "snapshot_schema_version": 1, "sequence": sequence,
        "publication_id": f"launch-conformance-{sequence}", "source_commit": context["github_sha"],
        "generated_at": generated.isoformat().replace("+00:00", "Z"),
        "expires_at": (generated + lifetime).isoformat().replace("+00:00", "Z"),
        "products": [product], "distributions": distributions, "evidence": [], "revocations": revocations,
    }
    validate_snapshot_semantics(snapshot)
    snapshot_body = canonical_json(snapshot)
    private_key = Ed25519PrivateKey.from_private_bytes(CONFORMANCE_SEED)
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    envelope = {
        "algorithm": "Ed25519", "envelope_schema_version": 1, "key_id": CONFORMANCE_KEY_ID,
        "sequence": sequence, "signature": base64.b64encode(private_key.sign(signature_message(snapshot_body))).decode(),
        "signature_domain": "UAP-DIRECTORY-SNAPSHOT-ED25519-V1",
        "snapshot_digest": sha256_digest(snapshot_body), "snapshot_schema_version": 1,
    }
    verify_envelope(snapshot_body, envelope, {CONFORMANCE_KEY_ID: public_key})
    directory = root / f"conformance-directory-{sequence}"
    directory.mkdir()
    snapshot_path, envelope_path, trust_path = directory / "snapshot.json", directory / "envelope.json", directory / "trusted-keys.json"
    snapshot_path.write_bytes(snapshot_body)
    envelope_path.write_bytes(canonical_json(envelope))
    trust_path.write_bytes(canonical_json({"schema_version": 1, "keys": [{"key_id": CONFORMANCE_KEY_ID, "public_key": base64.b64encode(public_key).decode()}]}))
    environment = os.environ.copy()
    environment.update({
        "AGENTPLUGINS_DIRECTORY_ORIGIN": "https://conformance.invalid/registry/schemas/1/",
        "AGENTPLUGINS_DIRECTORY_SNAPSHOT": str(snapshot_path),
        "AGENTPLUGINS_DIRECTORY_ENVELOPE": str(envelope_path),
        "AGENTPLUGINS_DIRECTORY_TRUST": str(trust_path),
        "AGENTPLUGINS_DIRECTORY_CONFORMANCE_ONLY": "1",
        "AGENTPLUGINS_DIRECTORY_CACHE": str(root / "directory-cache"),
    })
    return environment, envelope["snapshot_digest"]


def directory_fault_scenario(
    binary: Path, scenario: str, root: Path, challenge: str, context: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    base_sequence = int(context["snapshot_sequence"]) + 2000
    traces: list[dict[str, Any]] = []
    before = observe(home, manager)

    def execute(argv: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        completed, trace = traced_with_environment(binary, argv, root, challenge, environment)
        traces.append(trace)
        return completed

    if scenario == "directory_expired":
        environment, fixture_digest = conformance_directory(
            root, context, sequence=base_sequence, generated_offset=timedelta(hours=-4), lifetime=timedelta(hours=1),
        )
        rejected = execute(["add", "context7", "--target", "cursor", "--format", "json"], environment)
        after = observe(home, manager)
        proof = {"expired_snapshot_rejected": rejected.returncode != 0, "zero_mutation": before == after}
    elif scenario == "directory_tampered":
        environment, fixture_digest = conformance_directory(root, context, sequence=base_sequence)
        snapshot_path = Path(environment["AGENTPLUGINS_DIRECTORY_SNAPSHOT"])
        snapshot_path.write_bytes(snapshot_path.read_bytes() + b"\n")
        rejected = execute(["add", "context7", "--target", "cursor", "--format", "json"], environment)
        after = observe(home, manager)
        proof = {"tampered_snapshot_rejected": rejected.returncode != 0, "zero_mutation": before == after}
    elif scenario == "directory_sequence_rollback":
        high, _ = conformance_directory(root, context, sequence=base_sequence + 1)
        low, fixture_digest = conformance_directory(root, context, sequence=base_sequence)
        installed = execute(["add", "context7", "--target", "cursor", "--format", "json"], high)
        before_rejected = observe(home, manager)
        rejected = execute(["update", "context7", "--target", "cursor", "--format", "json"], low)
        after_rejected = observe(home, manager)
        cleanup = execute(["remove", "context7", "--target", "cursor", "--format", "json"], high)
        after = observe(home, manager)
        proof = {"lower_sequence_rejected": installed.returncode == 0 and rejected.returncode != 0 and cleanup.returncode == 0, "zero_mutation": before_rejected == after_rejected}
    elif scenario == "directory_offline":
        online, fixture_digest = conformance_directory(root, context, sequence=base_sequence)
        installed = execute(["add", "context7", "--target", "cursor", "--format", "json"], online)
        offline = dict(online)
        offline["AGENTPLUGINS_DIRECTORY_ORIGIN"] = "https://offline.invalid/registry/schemas/1/"
        for key in ("AGENTPLUGINS_DIRECTORY_SNAPSHOT", "AGENTPLUGINS_DIRECTORY_ENVELOPE", "AGENTPLUGINS_DIRECTORY_TRUST"):
            offline.pop(key, None)
        updated = execute(["update", "context7", "--target", "cursor", "--format", "json"], offline)
        cleanup = execute(["remove", "context7", "--target", "cursor", "--format", "json"], online)
        after = observe(home, manager)
        proof = {"offline_cache_used": installed.returncode == updated.returncode == cleanup.returncode == 0, "signature_verified": Path(online["AGENTPLUGINS_DIRECTORY_CACHE"]).exists()}
    else:
        raise ValueError("unsupported Directory fault scenario")
    return all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, **proof, "fixture_digest": fixture_digest}


def lifecycle(
    binary: Path, product: str, clients: tuple[str, ...], root: Path,
    challenge: str, context: dict[str, Any], *, include_repair: bool,
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    target = ",".join(clients)
    operations = ["add", "update"] + (["repair"] if include_repair else []) + ["info", "remove"]
    traces: list[dict[str, Any]] = []
    values: dict[str, dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []
    outcomes: dict[str, str] = {}
    identities: dict[str, dict[str, Any]] = {}
    previous_receipts = installation_receipts(manager, product) or []
    for operation in operations:
        before_installation = selected_manager_installation(manager, product)
        before_manager_state = manager_state(manager)
        before_receipts = installation_receipts(manager, product) or []
        before = {"state": observe(home, manager), "manager": manager_facts(manager, product), "installation_receipts": before_receipts, "materialized_mentions": materialized_product_mentions(home, manager, product, clients)}
        argv = [operation, product, "--target", target, "--format", "json"]
        completed, trace = traced(binary, argv, root, challenge)
        traces.append(trace)
        value = json_output(completed, operation)
        after_receipts = installation_receipts(manager, product) or []
        after = {"state": observe(home, manager), "manager": manager_facts(manager, product), "installation_receipts": after_receipts, "materialized_mentions": materialized_product_mentions(home, manager, product, clients)}
        identity = manager_identity(manager, product)
        identities[operation] = identity
        observations.append({"operation": operation, "command": argv, "before": before, "after": after})
        passed = value is not None
        if value is not None and operation in {"add", "update", "repair", "remove"}:
            passed = passed and [item.get("target") for item in value["data"]["targets"]] == list(clients)
            installation = selected_manager_installation(manager, product)
            state_clients = installation.get("clients", {}) if installation else {}
            if operation != "remove":
                passed = passed and {
                    binding.get("client_id") for binding in state_clients.values() if isinstance(binding, dict)
                } == set(clients) and len(state_clients) == len(clients)
                stdout_installations = {
                    item["output"]["result"]["installation_id"] for item in value["data"]["targets"]
                }
                passed = passed and installation is not None and stdout_installations == {installation["installation_id"]}
        if operation in {"add", "repair"}:
            operation_group_id = value.get("data", {}).get("operation_id") if value else None
            passed = passed and isinstance(operation_group_id, str) and receipts_bind_command(
                previous_receipts, after_receipts, operation, clients,
                operation_group_id=operation_group_id,
            )
            previous_receipts = after_receipts
        elif operation == "remove":
            operation_group_id = value.get("data", {}).get("operation_id") if value else None
            removal_authority = removal_authority_from_installation(before_installation)
            state = manager_state(manager, removal_authority=removal_authority)
            matches = [
                item for item in state.get("installations", [])
                if isinstance(item, dict) and item.get("declared_name") == product
            ] if state else []
            installation = matches[0] if len(matches) == 1 else None
            transactions = state.get("transaction_receipts", []) if state else []
            identity = installation_identity(installation)
            identities[operation] = identity
            before_data = frozen_data_receipt_map(before_installation)
            after_data = frozen_data_receipt_map(installation)
            passed = passed and bool(
                installation and installation.get("clients") == {} and installation.get("data_retained") is True
                and before_data is not None and before_data == after_data
                and public_receipts_bind_frozen_authority(value["data"].get("retained_data"), before_data)
                and isinstance(operation_group_id, str)
                and removal_receipts_bind_command(
                    before_manager_state, state, removal_authority, operation_group_id, clients, installation,
                )
            )
        elif operation == "update":
            # This fixture contains exactly one release. A truthful update is a
            # successful no-op: it must neither recommit that release nor alter
            # manager/client materialization.
            passed = (
                passed
                and find_value(value, {"mutated"}) is False
                and after == before
                and after_receipts == previous_receipts
            )
        passed = passed and identity_matches_release(identity, context)
        if operation == "add":
            passed = passed and all(after["materialized_mentions"][client] > 0 for client in clients)
        elif operation == "info":
            # Files and receipts prove fixture materialization only. They do
            # not prove native client discovery.
            passed = passed and bool(after_receipts) and {
                item.get("client_id") for item in value["data"]["clients"]
            } == set(clients) and len(value["data"]["clients"]) == len(clients)
        elif operation == "remove":
            passed = passed and all(after["materialized_mentions"][client] == 0 for client in clients)
        # The info command is part of the receipt-backed lifecycle assertion.
        # It is deliberately not named or exported as native discovery proof.
        outcomes[operation] = "passed" if passed else "failed"
        if value is not None:
            values[operation] = value
    representative = values.get("info") or values.get("add") or {}
    tuple_value = evidence_tuple(context, representative, "fixture-manager-receipts-and-materialized-files")
    tuple_value["client_version"] = None
    materialization_passed = all(value == "passed" for value in outcomes.values())
    passed = materialization_passed
    return passed, {
        "command_traces": traces, "operation_observations": observations,
        "operation_outcomes": outcomes, "values": values, "identities": identities, "tuple": tuple_value,
        "evidence_basis": "repository_owned_disposable_observer", "runtime_proof": False,
        "native_discovery_proof": False,
        "no_newer_release_update_noop": outcomes.get("update") == "passed",
    }


def shared_backend_lifecycle(
    binary: Path, root: Path, challenge: str, context: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    traces: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    values: dict[str, dict[str, Any]] = {}
    mutations: dict[str, int] = {}
    shared_identity: dict[str, Any] = {}
    previous_receipts = manager_facts(manager, "context7")["committed_receipts"]
    for operation in ("add", "info", "remove"):
        before = {"state": observe(home, manager), "manager": manager_facts(manager, "context7")}
        completed, trace = traced(binary, [operation, "context7", "--target", "copilot,vscode", "--format", "json"], root, challenge)
        traces.append(trace)
        value = json_output(completed, operation)
        after = {"state": observe(home, manager), "manager": manager_facts(manager, "context7")}
        observations.append({"operation": operation, "before": before, "after": after})
        if value is not None:
            values[operation] = value
        if operation in {"add", "remove"}:
            mutations[operation] = sum(
                before["state"]["native"][name] != after["state"]["native"][name]
                for name in before["state"]["native"]
            )
            if after["manager"]["committed_receipts"] <= previous_receipts:
                mutations[operation] = 0
            previous_receipts = after["manager"]["committed_receipts"]
        if operation == "add":
            shared_identity = manager_identity(manager, "context7")
    info = values.get("info", {})
    surfaces = find_value(info, {"affected_surfaces", "resolved_surfaces", "clients"})
    surfaces = sorted(surfaces) if isinstance(surfaces, list) and all(isinstance(item, str) for item in surfaces) else []
    if not surfaces and isinstance(shared_identity.get("affected_surfaces"), list):
        surfaces = sorted(shared_identity["affected_surfaces"])
    tuple_value = evidence_tuple(context, info or values.get("add", {}), "fixture-shared-backend-and-manager-receipts")
    tuple_value["client_version"] = None
    passed = (
        set(values) == {"add", "info", "remove"}
        and surfaces == ["copilot", "vscode"] and mutations == {"add": 1, "remove": 1}
        and identity_matches_release(shared_identity, context)
        and next(item for item in observations if item["operation"] == "info")["after"]["manager"]["committed_receipts"] > 0
    )
    return passed, {
        "command_traces": traces, "operation_observations": observations,
        "affected_surfaces": surfaces, "physical_mutations": mutations, "tuple": tuple_value,
        "evidence_basis": "repository_owned_disposable_observer", "runtime_proof": False,
        "native_discovery_proof": False,
    }


def schema_scenario(
    binary: Path, scenario: str, root: Path, challenge: str,
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    package = root / ("package-" + scenario)
    shutil.copytree(EXTERNAL_PACKAGE, package)
    manifest_path = package / "plugin.json"
    manifest = json.loads(manifest_path.read_text())
    exact = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
    if scenario == "schema_draft_rejected":
        manifest["$schema"] = "https://agent-plugins.org/schemas/draft/plugin.schema.json"
    elif scenario == "schema_unknown_rejected":
        manifest["$schema"] = "https://agent-plugins.org/schemas/2.0.0/plugin.schema.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))
    before = observe(home, manager)
    argv = ["add", "./" + package.name, "--target", "cursor", "--format", "json"]
    completed, trace = traced(binary, argv, root, challenge)
    after_add = observe(home, manager)
    traces = [trace]
    if scenario == "schema_1_0_0_accepted":
        accepted = completed.returncode == 0 and before != after_add and manifest["$schema"] == exact
        removed, remove_trace = traced(binary, ["remove", manifest["name"], "--target", "cursor", "--format", "json"], root, challenge)
        traces.append(remove_trace)
        after = observe(home, manager)
        proof = {"exact_schema": manifest["$schema"], "accepted": accepted and removed.returncode == 0}
        return all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof}
    rejected = completed.returncode != 0 and before == after_add
    key = "draft_rejected" if scenario == "schema_draft_rejected" else "unknown_rejected"
    proof = {key: rejected, "zero_mutation": before == after_add}
    return all(proof.values()), {"command_traces": traces, "before": before, "after": after_add, "proof": proof}


def project_scope_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    completed, trace = traced(binary, ["add", "context7", "--target", "cursor", "--scope", "project", "--format", "json"], root, challenge)
    after = observe(home, manager)
    diagnostic = (completed.stdout + "\n" + completed.stderr).lower()
    proof = {
        "project_scope_rejected": completed.returncode != 0 and "project" in diagnostic and ("unsupported" in diagnostic or "user scope" in diagnostic),
        "manager_unchanged": before["manager"] == after["manager"],
        "native_unchanged": before["native"] == after["native"],
    }
    return all(proof.values()), {"command_traces": [trace], "before": before, "after": after, "proof": proof}


def no_hidden_yes_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    """Prove the removed option is rejected by mutating parsers before any write."""
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    commands = (
        ["add", "context7", "--target", "cursor", "--yes", "--format", "json"],
        ["update", "context7", "--target", "cursor", "--yes", "--format", "json"],
        ["remove", "context7", "--target", "cursor", "--yes", "--format", "json"],
    )
    for argv in commands:
        completed, trace = traced(binary, argv, root, challenge)
        traces.append(trace)
        diagnostic = (completed.stdout + "\n" + completed.stderr).lower()
        attempts.append({
            "command": argv[0], "rejected": completed.returncode != 0,
            "unknown_option": "--yes" in diagnostic and any(word in diagnostic for word in ("unknown", "unrecognized", "invalid option", "flag provided but not defined")),
        })
    after = observe(home, manager)
    help_result, help_trace = traced(binary, ["--help"], root, challenge)
    traces.append(help_trace)
    help_text = help_result.stdout + "\n" + help_result.stderr
    proof = {
        "help_exit_zero": help_result.returncode == 0,
        "hidden_yes_absent": "--yes" not in help_text,
        "mutating_commands_rejected": all(item["rejected"] for item in attempts),
        "unknown_option_reported": all(item["unknown_option"] for item in attempts),
        "manager_unchanged": before["manager"] == after["manager"],
        "native_unchanged": before["native"] == after["native"],
    }
    return all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, "attempts": attempts}


def manager_identity(manager: Path, product: str) -> dict[str, Any]:
    """Return identity fields from exactly one owned installation record."""
    return installation_identity(selected_manager_installation(manager, product))


def installation_identity(installation: Any) -> dict[str, Any]:
    """Extract identity only after the caller has validated one State-v4 record."""
    if installation is None:
        return {}
    directory = installation.get("directory") if isinstance(installation.get("directory"), dict) else {}
    source = installation.get("source") if isinstance(installation.get("source"), dict) else {}
    package = installation.get("package") if isinstance(installation.get("package"), dict) else {}
    candidates = {
        "origin_mode": (installation.get("origin_mode"),),
        "product_id": (installation.get("product_id"), installation.get("declared_name")),
        "resolved_revision": (installation.get("resolved_revision"), source.get("resolved_revision"), source.get("revision")),
        "canonical_source": (installation.get("canonical_source"), source.get("canonical_source"), source.get("locator")),
        "source_repository": (installation.get("source_repository"), source.get("source_repository"), source.get("repository")),
        "source_revision": (installation.get("source_revision"), source.get("source_revision"), source.get("resolved_revision"), source.get("revision")),
        "source_path": (installation.get("source_path"), source.get("source_path"), source.get("path"), source.get("package_subpath")),
        "tree_digest": (installation.get("tree_digest"), source.get("tree_digest"), package.get("tree_digest"), package.get("package_tree_digest")),
        "manifest_digest": (installation.get("manifest_digest"), package.get("manifest_digest")),
        "distribution_id": (installation.get("distribution_id"), directory.get("distribution_id")),
        "distribution_kind": (installation.get("distribution_kind"), directory.get("distribution_kind")),
        "desired_release_sequence": (installation.get("desired_release_sequence"), directory.get("desired_release_sequence")),
        "snapshot_schema": (directory.get("snapshot_schema"),),
        "snapshot_sequence": (directory.get("snapshot_sequence"),),
        "snapshot_digest": (directory.get("snapshot_digest"),),
        "data_locator": (installation.get("data_locator"),),
        "data_root": (installation.get("data_root"),),
        "affected_surfaces": (installation.get("affected_surfaces"),),
    }
    identity: dict[str, Any] = {}
    for key, raw_values in candidates.items():
        values = [value for value in raw_values if value not in (None, "")]
        distinct = {json.dumps(value, sort_keys=True, separators=(",", ":")) for value in values}
        if len(distinct) > 1:
            return {}
        if values:
            identity[key] = copy.deepcopy(values[0])
    return identity


def manager_has_flag(manager: Path, product: str, key: str, expected: Any) -> bool:
    installation = selected_manager_installation(manager, product)
    stack = [installation] if installation else []
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if item.get(key) == expected:
                return True
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def installation_record(value: Any, product: str) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("installations"), list):
        return None
    matches = [
        item for item in value["installations"]
        if isinstance(item, dict) and product in {
            item.get("declared_name"), item.get("manifest_name"), find_value(item, {"product_id"}),
        }
    ]
    return matches[0] if len(matches) == 1 else None


def _one_semantic(record: dict[str, Any], names: set[str]) -> Any:
    values = find_values(record, names)
    distinct = {json.dumps(item, sort_keys=True, separators=(",", ":")) for item in values}
    return values[0] if len(distinct) == 1 and values else None


def migration_provenance(record: dict[str, Any] | None, *, legacy: bool) -> dict[str, Any] | None:
    """Normalize fields schema 2/3 migration promises to preserve."""
    if not isinstance(record, dict):
        return None
    source = record.get("source", {})
    package = record.get("package", {})
    clients = record.get("clients")
    if not isinstance(clients, dict) or not clients:
        return None
    bindings: dict[str, Any] = {}
    for binding_id, binding in clients.items():
        if not isinstance(binding_id, str) or not isinstance(binding, dict):
            return None
        revision = binding.get("package_revision", {})
        bindings[binding_id] = {
            key: copy.deepcopy(binding.get(key)) for key in (
                "client_binding_id", "client_id", "scope", "target_locator", "physical_artifact_id",
                "materialization", "activation", "authentication", "policy", "verification", "updated_at",
            )
        }
        bindings[binding_id]["package_revision"] = {
            key: copy.deepcopy(revision.get(key)) for key in ("resolved_revision", "tree_digest", "manifest_digest")
        }
    normalized = {
        "installation_id": record.get("installation_id"), "declared_name": record.get("declared_name"),
        "source": {key: copy.deepcopy(source.get(key)) for key in (
            "source_binding_id", "requested_source", "canonical_source", "repository",
            "package_subpath", "resolved_revision", "tree_digest",
        )},
        "package": {key: copy.deepcopy(package.get(key)) for key in (
            "loader_kind", "format_id", "schema_uri", "declared_name", "manifest_digest",
        )},
        "bindings": bindings,
        "created_at": record.get("created_at"), "updated_at": record.get("updated_at"),
    }
    del legacy
    required_values: list[Any] = [
        normalized["installation_id"], normalized["declared_name"], normalized["created_at"], normalized["updated_at"],
        *normalized["source"].values(), *normalized["package"].values(),
    ]
    for binding in bindings.values():
        required_values.extend(value for key, value in binding.items() if key != "package_revision")
        required_values.extend(binding["package_revision"].values())
    return normalized if all(child not in (None, "") for child in required_values) else None


SANITIZED_PATH_FIELDS = frozenset({
    "target_locator", "active_path", "staging_path", "backup_path", "locator", "path",
})


def transform_sanitized_placeholders(
    value: Any, *, original_raw: bytes | None = None, trusted_input_digest: str | None = None,
    mappings: tuple[tuple[str, Path], ...],
) -> tuple[Any, dict[str, Any]]:
    """Rehome explicitly sanitized path placeholders into one sandbox.

    The record binds the exact input digest, ordered mapping, output digest and
    algorithm.  Only known path-valued fields are rewritten and every absolute
    placeholder must match exactly one mapping, so this cannot become a live
    path-authority exception.
    """
    if (original_raw is None) == (trusted_input_digest is None):
        raise ValueError("supply exactly one independent migration input authority")
    input_digest = (
        "sha256:" + hashlib.sha256(original_raw).hexdigest()
        if original_raw is not None else trusted_input_digest
    )
    if original_raw is not None:
        try:
            if strict_json_loads(original_raw) != value:
                raise ValueError("migration value does not match independently supplied raw bytes")
        except (json.JSONDecodeError, DuplicateKeyError) as error:
            raise ValueError("migration raw bytes are not strict JSON") from error
    if not _digest(input_digest) or not mappings:
        raise ValueError("invalid sanitized fixture transformation authority")
    ordered = sorted((placeholder, str(destination.resolve(strict=True))) for placeholder, destination in mappings)
    placeholders = [item[0] for item in ordered]
    destinations = [item[1] for item in ordered]
    if (
        len(set(placeholders)) != len(placeholders) or len(set(destinations)) != len(destinations)
        or any(not PurePosixPath(item).is_absolute() or item == "/" for item in placeholders + destinations)
    ):
        raise ValueError("ambiguous sanitized fixture transformation")

    def rewrite(child: Any, key: str | None = None) -> Any:
        if isinstance(child, dict):
            return {name: rewrite(item, name) for name, item in child.items()}
        if isinstance(child, list):
            return [rewrite(item, key) for item in child]
        if key not in SANITIZED_PATH_FIELDS:
            return copy.deepcopy(child)
        if not isinstance(child, str) or not PurePosixPath(child).is_absolute():
            raise ValueError("sanitized fixture contains an invalid path field")
        matches = [
            (placeholder, destination) for placeholder, destination in ordered
            if child == placeholder or child.startswith(placeholder + "/")
        ]
        if len(matches) != 1:
            raise ValueError("sanitized fixture path has no unique sandbox mapping")
        placeholder, destination = matches[0]
        suffix = child[len(placeholder):].lstrip("/")
        return str(PurePosixPath(destination) / suffix) if suffix else destination

    transformed = rewrite(value)
    output_digest = sha256_digest(canonical_json(transformed))
    record: dict[str, Any] = {
        "schema_version": 1,
        "algorithm": "agentplugins-sanitized-placeholder-to-sandbox-v1",
        "input_digest": input_digest,
        "mappings": [{"placeholder": source, "sandbox": target} for source, target in ordered],
        "output_digest": output_digest,
    }
    record["record_digest"] = sha256_digest(canonical_json(record))
    return transformed, record


def validate_placeholder_transformation(
    original: Any, transformed: Any, record: Any, *, original_raw: bytes | None = None,
    trusted_input_digest: str | None = None,
) -> bool:
    if not _keys(record, {"schema_version", "algorithm", "input_digest", "mappings", "output_digest", "record_digest"}):
        return False
    unsigned = {key: copy.deepcopy(value) for key, value in record.items() if key != "record_digest"}
    if not (
        _exact_int(record["schema_version"], 1)
        and record["algorithm"] == "agentplugins-sanitized-placeholder-to-sandbox-v1"
        and _digest(record["input_digest"])
        and record["output_digest"] == sha256_digest(canonical_json(transformed))
        and record["record_digest"] == sha256_digest(canonical_json(unsigned))
        and isinstance(record["mappings"], list) and record["mappings"]
    ):
        return False
    if (original_raw is None) == (trusted_input_digest is None):
        return False
    independently_expected = (
        "sha256:" + hashlib.sha256(original_raw).hexdigest()
        if original_raw is not None else trusted_input_digest
    )
    if record["input_digest"] != independently_expected:
        return False
    if original_raw is not None:
        try:
            raw_value = strict_json_loads(original_raw)
        except (json.JSONDecodeError, DuplicateKeyError, ValueError):
            return False
        if raw_value != original:
            return False
    try:
        mappings = tuple((item["placeholder"], Path(item["sandbox"])) for item in record["mappings"] if set(item) == {"placeholder", "sandbox"})
        replayed, replay_record = transform_sanitized_placeholders(
            original, original_raw=original_raw, trusted_input_digest=None if original_raw is not None else independently_expected,
            mappings=mappings,
        )
    except (KeyError, OSError, TypeError, ValueError):
        return False
    return replayed == transformed and replay_record == record


def normalized_migration_provenance(
    record: dict[str, Any] | None, *, inverse_mappings: tuple[tuple[Path, str], ...], legacy: bool,
) -> dict[str, Any] | None:
    provenance = migration_provenance(record, legacy=legacy)
    if provenance is None:
        return None
    normalized = copy.deepcopy(provenance)
    for binding in normalized["bindings"].values():
        path = binding["target_locator"]
        matches = []
        for sandbox, placeholder in inverse_mappings:
            root = str(sandbox.resolve(strict=True))
            if path == root or path.startswith(root + "/"):
                matches.append((root, placeholder))
        if len(matches) != 1:
            return None
        root, placeholder = matches[0]
        suffix = path[len(root):].lstrip("/")
        binding["target_locator"] = str(PurePosixPath(placeholder) / suffix) if suffix else placeholder
    return normalized


def validate_schema_2_state(value: Any) -> bool:
    """Validate the sanitized genuine schema-2 capture before executing a CLI."""
    if not _keys(value, {"schema_version", "installations"}) or not _exact_int(value["schema_version"], 2):
        return False
    if not isinstance(value["installations"], list) or len(value["installations"]) != 1:
        return False
    record = value["installations"][0]
    if not _keys(record, {"installation_id", "declared_name", "source", "package", "clients", "created_at", "updated_at"}):
        return False
    source, package, clients = record["source"], record["package"], record["clients"]
    if not (
        _nonempty(record["installation_id"]) and _nonempty(record["declared_name"])
        and _keys(source, {"source_binding_id", "requested_source", "canonical_source", "repository", "package_subpath", "resolved_revision", "tree_digest"})
        and GITHUB_REPOSITORY.fullmatch(source["repository"]) and GITHUB_SOURCE_PATH.fullmatch(source["package_subpath"])
        and FULL_SHA.fullmatch(source["resolved_revision"]) and _digest(source["tree_digest"])
        and source["canonical_source"] == "https://github.com/" + source["repository"]
        and _keys(package, {"loader_kind", "format_id", "schema_uri", "declared_name", "manifest_digest", "inventory"})
        and package["loader_kind"] == "agent_plugins" and package["format_id"] == "agent-plugins/1.0.0"
        and package["schema_uri"] == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
        and package["declared_name"] == record["declared_name"] and _digest(package["manifest_digest"])
        and isinstance(package["inventory"], dict) and isinstance(clients, dict) and bool(clients)
    ):
        return False
    seen_clients: set[str] = set()
    for binding_id, binding in clients.items():
        if not (
            _keys(binding, {"client_binding_id", "client_id", "scope", "target_locator", "physical_artifact_id", "materialization", "activation", "authentication", "policy", "verification", "package_revision", "updated_at"})
            and binding["client_binding_id"] == binding_id and _nonempty(binding["client_id"])
            and binding["client_id"] not in seen_clients and binding["scope"] == "user"
            and PurePosixPath(binding["target_locator"]).is_absolute() and ".." not in PurePosixPath(binding["target_locator"]).parts
            and binding["materialization"] in MATERIALIZATIONS and binding["activation"] in ACTIVATIONS
            and binding["authentication"] in AUTHENTICATIONS and binding["policy"] in POLICIES
            and binding["verification"] in VERIFICATIONS
            and _keys(binding["package_revision"], {"resolved_revision", "tree_digest", "manifest_digest"})
            and binding["package_revision"] == {
                "resolved_revision": source["resolved_revision"], "tree_digest": source["tree_digest"],
                "manifest_digest": package["manifest_digest"],
            }
        ):
            return False
        seen_clients.add(binding["client_id"])
    return migration_provenance(record, legacy=True) is not None


def copy_ready_migration_guidance(text: str) -> bool:
    return all(
        command in text
        for command in (
            "agentplugins migrate-state --dry-run",
            "agentplugins migrate-state",
        )
    ) and "--expected-digest" not in text


def direct_package_identity_matches(
    identity: dict[str, Any], *, repository: str, revision: str, package_path: str,
) -> bool:
    canonical = parse_canonical_github_source(identity.get("canonical_source"))
    expected_source = {
        "source_repository": repository,
        "source_revision": revision,
        "source_path": package_path,
    }
    return bool(
        canonical == expected_source
        and identity.get("product_id") == "e2e-external-package"
        and identity.get("resolved_revision") == revision
        and identity.get("source_repository") == repository
        and identity.get("source_revision") == revision
        and identity.get("source_path") == package_path
        and isinstance(identity.get("tree_digest"), str) and DIGEST.fullmatch(identity["tree_digest"])
        and isinstance(identity.get("manifest_digest"), str) and DIGEST.fullmatch(identity["manifest_digest"])
    )


def direct_full_sha_scenario(
    binary: Path, root: Path, challenge: str, context: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    revision = context["github_sha"]
    repository = context["catalog_repository"]
    package_path = "tests/e2e/fixtures/external-package"
    selector = f"{repository}@{revision}//{package_path}"
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    add, trace = traced(binary, ["add", selector, "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    add_value = json_output(add, "add")
    installed_identity = manager_identity(manager, "e2e-external-package")
    stable_root = Path(os.path.commonpath((home, manager, root)))
    before_update = filesystem_snapshot(stable_root)
    update, trace = traced(binary, ["update", "e2e-external-package", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    after_update = filesystem_snapshot(stable_root)
    try:
        update_failure = strict_json_loads(update.stdout)
    except (json.JSONDecodeError, DuplicateKeyError, ValueError):
        update_failure = None
    updated_identity = manager_identity(manager, "e2e-external-package")
    remove, trace = traced(binary, ["remove", "e2e-external-package", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    after = observe(home, manager)
    required_identity_fields = (
        "product_id", "resolved_revision", "canonical_source", "source_repository",
        "source_revision", "source_path", "tree_digest", "manifest_digest",
    )
    installed_exact = direct_package_identity_matches(
        installed_identity, repository=repository, revision=revision, package_path=package_path,
    )
    updated_exact = direct_package_identity_matches(
        updated_identity, repository=repository, revision=revision, package_path=package_path,
    )
    identity_stable = bool(
        installed_exact and updated_exact
        and all(installed_identity.get(field) == updated_identity.get(field) for field in required_identity_fields)
    )
    add_acquisition = command_acquisition_proof(add_value, ("cursor",), command="add")
    acquisition_bound = bool(
        add_acquisition
        and add_acquisition["tree_digest"] == installed_identity.get("tree_digest")
        and add_acquisition["manifest_digest"] == installed_identity.get("manifest_digest")
        and add_acquisition["source_kind"] == "github"
        and add_acquisition["fetched"] is True and add_acquisition["validated"] is True
    )
    failure_valid = validate_full_sha_update_failure(
        update_failure, update.stderr, plugin="e2e-external-package",
        source=installed_identity.get("canonical_source", "").removeprefix("https://github.com/").split("@", 1)[0] + "//" + package_path,
        revision=revision, tree_digest=installed_identity.get("tree_digest", ""), expected_targets=("cursor",),
        requested_argv=["update", "e2e-external-package", "--target", "cursor", "--format", "json"],
    )
    proof = {
        "full_sha": installed_exact and updated_exact,
        "direct_update_refused_requires_switch": bool(
            add.returncode == 0 and update.returncode != 0 and failure_valid
            and before_update == after_update and identity_stable and acquisition_bound
        ),
        "mutable_ref_followed": False if identity_stable else True,
    }
    return all((proof["full_sha"], proof["direct_update_refused_requires_switch"], not proof["mutable_ref_followed"], remove.returncode == 0)), {"command_traces": traces, "before": before, "after": after, "before_update": before_update, "after_update": after_update, "proof": proof, "installed_identity": installed_identity, "updated_identity": updated_identity, "update_failure": update_failure, "add_acquisition": add_acquisition}


def missing_runtime_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    package = root / "package-missing-runtime"
    shutil.copytree(EXTERNAL_PACKAGE, package)
    command = "uap-runtime-that-does-not-exist"
    (package / "mcp.json").write_text(json.dumps({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"demo": {"type": "stdio", "command": command}},
    }, sort_keys=True))
    before = observe(home, manager)
    completed, trace = traced(binary, ["add", "./" + package.name, "--target", "cursor", "--format", "json"], root, challenge)
    after = observe(home, manager)
    diagnostic = completed.stdout + "\n" + completed.stderr
    proof = {
        "zero_mutation": before == after,
        "dependency_installed": shutil.which(command, path=os.environ.get("PATH")) is not None,
        "guidance_exact": all(text in diagnostic for text in (f'requires executable "{command}" on PATH', "install it explicitly", "never installs runtimes")),
    }
    return completed.returncode != 0 and proof["zero_mutation"] and not proof["dependency_installed"] and proof["guidance_exact"], {"command_traces": [trace], "before": before, "after": after, "proof": proof}


def repair_fault_scenario(binary: Path, client: str, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    add, trace = traced(binary, ["add", "context7", "--target", client, "--format", "json"], root, challenge)
    traces.append(trace)
    roots = {"codex": home / ".codex", "cursor": home / ".cursor", "kiro": home / ".kiro"}
    fault_injected = False
    for path in sorted(roots[client].rglob("*"), reverse=True) if roots[client].exists() else ():
        if path.is_file() and not path.is_symlink() and "context7" in (path.as_posix() + path.read_text(errors="ignore")):
            path.unlink()
            fault_injected = True
    repair, trace = traced(binary, ["repair", "context7", "--target", client, "--format", "json"], root, challenge)
    traces.append(trace)
    repaired = materialized_product_mentions(home, manager, "context7", (client,))[client] > 0
    remove, trace = traced(binary, ["remove", "context7", "--target", client, "--format", "json"], root, challenge)
    traces.append(trace)
    after = observe(home, manager)
    proof = {"fault_injected_once": fault_injected, "repair_succeeded": add.returncode == repair.returncode == remove.returncode == 0 and repaired, "client": client}
    return all((proof["fault_injected_once"], proof["repair_succeeded"])), {"command_traces": traces, "before": before, "after": after, "proof": proof, **proof}


def managed_tamper_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    add, trace = traced(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    tampered = False
    for path in sorted((home / ".cursor").rglob("*")) if (home / ".cursor").exists() else ():
        if path.is_file() and not path.is_symlink() and "context7" in (path.as_posix() + path.read_text(errors="ignore")):
            path.write_bytes(path.read_bytes() + b"\nlaunch-tamper")
            tampered = True
            break
    info, trace = traced(binary, ["info", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    diagnostic = (info.stdout + "\n" + info.stderr).lower()
    detected = tampered and any(word in diagnostic for word in ("tamper", "digest", "drift", "repair"))
    repair_required = "repair" in diagnostic
    repair, trace = traced(binary, ["repair", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    remove, trace = traced(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    after = observe(home, manager)
    proof = {"tamper_detected": add.returncode == 0 and detected, "repair_required": repair_required and repair.returncode == 0 and remove.returncode == 0}
    return all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, **proof}


def migration_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    manager.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).resolve().parents[1] / "tests/e2e/fixtures/state-schema-2.json"
    state_path = manager / "state-v2.json"
    fixture_bytes = fixture.read_bytes()
    legacy_state = strict_json_loads(fixture_bytes)
    if not validate_schema_2_state(legacy_state):
        raise ValueError("migration fixture is not a valid sanitized schema-2 capture")
    fixture_digest = "sha256:" + hashlib.sha256(fixture_bytes).hexdigest()
    migrated_fixture_root = manager / "sanitized-schema2-root"
    migrated_fixture_root.mkdir()
    transformed_state, transformation = transform_sanitized_placeholders(
        legacy_state, original_raw=fixture_bytes, mappings=(("/fixture/home", migrated_fixture_root),),
    )
    if not validate_placeholder_transformation(
        legacy_state, transformed_state, transformation, original_raw=fixture_bytes,
    ):
        raise ValueError("migration fixture sandbox transformation is invalid")
    transformed_bytes = canonical_json(transformed_state)
    state_path.write_bytes(transformed_bytes)
    product = legacy_state["installations"][0]["declared_name"]
    legacy_record = installation_record(legacy_state, product)
    expected_provenance = migration_provenance(legacy_record, legacy=True)
    input_digest = "sha256:" + hashlib.sha256(transformed_bytes).hexdigest()
    state_fd = os.open(state_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    state_identity = os.fstat(state_fd)

    def original_handle_unchanged() -> bool:
        try:
            opened = os.fstat(state_fd)
            current = state_path.lstat()
            os.lseek(state_fd, 0, os.SEEK_SET)
            body = b""
            while True:
                chunk = os.read(state_fd, 1 << 20)
                if not chunk:
                    break
                body += chunk
            return bool(
                (opened.st_dev, opened.st_ino) == (state_identity.st_dev, state_identity.st_ino)
                and (current.st_dev, current.st_ino) == (state_identity.st_dev, state_identity.st_ino)
                and body == transformed_bytes
            )
        except OSError:
            return False

    isolated_root = Path(os.path.commonpath((home, manager, root)))
    manager_relative = manager.relative_to(isolated_root).as_posix()
    before = filesystem_snapshot(isolated_root)
    traces: list[dict[str, Any]] = []
    read, trace = traced(binary, ["info", product, "--target", "codex", "--format", "json"], root, challenge)
    traces.append(trace)
    read_value = json_output(read, "info")
    after_read = filesystem_snapshot(isolated_root)
    before_hidden = filesystem_snapshot(isolated_root)
    hidden, trace = traced(binary, ["add", product, "--target", "codex", "--format", "json"], root, challenge)
    traces.append(trace)
    after_hidden = filesystem_snapshot(isolated_root)
    hidden_diagnostic = hidden.stdout + "\n" + hidden.stderr
    unchanged_after_hidden = original_handle_unchanged()
    before_dry = filesystem_snapshot(isolated_root)
    dry, trace = traced(binary, ["migrate-state", "--dry-run", "--format", "json"], root, challenge)
    traces.append(trace)
    after_dry = filesystem_snapshot(isolated_root)
    dry_value = json_output(dry, "migrate-state")
    unchanged_after_dry = original_handle_unchanged()
    before_apply_files = filesystem_snapshot(manager)
    before_apply_all = filesystem_snapshot(isolated_root)
    apply, trace = traced(binary, ["migrate-state", "--format", "json"], root, challenge)
    traces.append(trace)
    apply_value = json_output(apply, "migrate-state")
    after = filesystem_snapshot(isolated_root)
    after_apply_files = filesystem_snapshot(manager)
    backups = [
        manager / relative for relative, item in after_apply_files.items()
        if relative != "." and item["kind"] == "file" and relative.startswith("state-v2.json.schema2.backup-agentplugins-")
    ]
    migrated_schema = None
    migrated_state: dict[str, Any] | None = None
    try:
        _, manager_bodies = _stable_tree_snapshot(manager)
        migrated_state = strict_json_loads(manager_bodies["state-v2.json"])
        migrated_schema = migrated_state.get("schema_version")
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        pass
    migrated_record = installation_record(migrated_state, product) if migrated_state else None
    observed_provenance = normalized_migration_provenance(
        migrated_record, inverse_mappings=((migrated_fixture_root, "/fixture/home"),), legacy=False,
    )
    changed_manager_files = {
        path for path in set(before_apply_files) | set(after_apply_files)
        if before_apply_files.get(path) != after_apply_files.get(path)
    }
    changed_backups = [path for path in changed_manager_files if path not in {".", "state-v2.json", "mutation.lock"}]
    changed_all = {
        path for path in set(before_apply_all) | set(after)
        if before_apply_all.get(path) != after.get(path)
    }
    allowed_global_changes = {
        ".", manager_relative,
        f"{manager_relative}/state-v2.json", f"{manager_relative}/mutation.lock",
        *(f"{manager_relative}/{path}" for path in changed_backups),
    }
    allowed_apply_mutation = bool(
        changed_manager_files <= {".", "state-v2.json", "mutation.lock", *changed_backups}
        and "state-v2.json" in changed_manager_files
        and len(changed_backups) == 1
        and Path(changed_backups[0]).name.startswith("state-v2.json.schema2.backup-agentplugins-")
        and changed_backups[0] not in before_apply_files
        and after_apply_files.get(changed_backups[0], {}).get("digest") == input_digest
        and changed_all <= allowed_global_changes
    )
    proof = {
        "pre_migration_read_only": read.returncode == 0 and after_read[f"{manager_relative}/state-v2.json"]["digest"] == input_digest,
        "pre_migration_mutation_refused_without_state_mutation": hidden.returncode != 0 and unchanged_after_hidden and after_hidden[f"{manager_relative}/state-v2.json"]["digest"] == input_digest,
        "dry_run_bound_exact_bytes": bool(
            dry.returncode == 0 and dry_value and validate_cli_envelope(dry_value, "migrate-state")
            and dry_value["data"] == {
                "dry_run": True, "source_schema": transformed_state["schema_version"],
                "installations": len(legacy_state["installations"]), "needs_rebind": 0,
                "migrated": 0, "backup_created": False,
            }
            and before_dry == after_dry and unchanged_after_dry
        ),
        "migration_applied": bool(
            apply.returncode == 0
            and type(migrated_schema) is int and migrated_schema == 4
            and manager_state(manager) is not None
            and len(manager_state(manager)["installations"]) == 1
            and apply_value and validate_cli_envelope(apply_value, "migrate-state")
            and apply_value["data"] == {
                "dry_run": False, "source_schema": transformed_state["schema_version"],
                "installations": len(legacy_state["installations"]), "needs_rebind": 0,
                "migrated": len(legacy_state["installations"]), "backup_created": True,
            }
            and allowed_apply_mutation
        ),
        "provenance_preserved": expected_provenance is not None and expected_provenance == observed_provenance,
        "backup_verified": len(backups) == 1 and after_apply_files[backups[0].name]["digest"] == input_digest,
    }
    os.close(state_fd)
    return all(proof.values()), {
        "command_traces": traces, "before": before, "after": after, "proof": proof, **proof,
        "input_digest": input_digest,
        "sanitized_fixture_digest": fixture_digest, "sandbox_transformation": transformation,
        "expected_provenance": expected_provenance, "observed_provenance": observed_provenance,
    }


def crash_recovery_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    started = now()
    process = subprocess.Popen(
        [str(binary), "add", "context7", "--target", "cursor", "--format", "json"],
        cwd=root, env=os.environ.copy(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    killed = False
    baseline = before["manager"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and process.poll() is None:
        if tree_digest(manager) != baseline:
            process.kill()
            killed = True
            break
        time.sleep(0.01)
    stdout, stderr = process.communicate(timeout=10)
    crash_trace = {
        "challenge": challenge, "argv": ["add", "context7", "--target", "cursor", "--format", "json"],
        "started_at": started, "ended_at": now(), "exit_code": process.returncode,
        "stdout_digest": "sha256:" + hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_digest": "sha256:" + hashlib.sha256(stderr.encode()).hexdigest(),
    }
    retry, retry_trace = traced(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    identity = manager_identity(manager, "context7")
    reconciled = retry.returncode == 0 and bool(identity) and materialized_product_mentions(home, manager, "context7", ("cursor",))["cursor"] > 0
    remove, remove_trace = traced(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    after = observe(home, manager)
    proof = {"crash_injected": killed and process.returncode != 0, "journal_recovered": reconciled, "ownership_reconciled": reconciled and remove.returncode == 0}
    return all(proof.values()), {"command_traces": [crash_trace, retry_trace, remove_trace], "before": before, "after": after, "proof": proof, **proof}


def managed_rollback_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    started = now()
    argv = ["add", "context7", "--target", "codex,cursor,kiro", "--format", "json"]
    process = subprocess.Popen([str(binary), *argv], cwd=root, env=os.environ.copy(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    injected = False
    kiro = home / ".kiro"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and process.poll() is None:
        if materialized_product_mentions(home, manager, "context7", ("codex",))["codex"] > 0:
            try:
                if kiro.is_dir() and not any(kiro.iterdir()):
                    kiro.rmdir()
                    kiro.write_text("mid-commit fault")
                    injected = True
                    break
            except OSError:
                pass
        time.sleep(0.005)
    stdout, stderr = process.communicate(timeout=30)
    trace = {
        "challenge": challenge, "argv": argv, "started_at": started, "ended_at": now(), "exit_code": process.returncode,
        "stdout_digest": "sha256:" + hashlib.sha256(stdout.encode()).hexdigest(), "stderr_digest": "sha256:" + hashlib.sha256(stderr.encode()).hexdigest(),
    }
    if kiro.is_file():
        kiro.unlink()
        kiro.mkdir()
    rolled_back = all(materialized_product_mentions(home, manager, "context7", (client,))[client] == 0 for client in ("codex", "cursor", "kiro"))
    state_restored = manager_facts(manager, "context7")["installation_records"] == 0
    if process.returncode == 0:
        cleanup, cleanup_trace = traced(binary, ["remove", "context7", "--target", "codex,cursor,kiro", "--format", "json"], root, challenge)
        trace_list = [trace, cleanup_trace]
    else:
        trace_list = [trace]
    after = observe(home, manager)
    proof = {"failure_injected": injected and process.returncode != 0, "managed_state_restored": rolled_back and state_restored}
    return all(proof.values()), {"command_traces": trace_list, "before": before, "after": after, "proof": proof, **proof}


def sticky_scenario(
    binary: Path, scenario: str, root: Path, challenge: str,
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    add, trace = traced(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    original = manager_identity(manager, "context7")
    if scenario == "readd_sticky_distribution":
        middle, trace = traced(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge)
        traces.append(trace)
        final, trace = traced(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge)
        traces.append(trace)
    else:
        cursor = Path(os.environ["HOME"]) / ".cursor"
        for path in sorted(cursor.rglob("*"), reverse=True) if cursor.exists() else ():
            if path.is_file() and not path.is_symlink() and "context7" in (path.as_posix() + path.read_text(errors="ignore")):
                path.unlink()
        middle = subprocess.CompletedProcess([], 0)
        final, trace = traced(binary, ["repair", "context7", "--target", "cursor", "--format", "json"], root, challenge)
        traces.append(trace)
    observed = manager_identity(manager, "context7")
    remove, trace = traced(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge)
    traces.append(trace)
    after = observe(home, manager)
    proof = {
        "recorded_distribution_retained": bool(original.get("distribution_id")) and original.get("distribution_id") == observed.get("distribution_id"),
        "recorded_revision_retained": bool(original.get("resolved_revision")) and original.get("resolved_revision") == observed.get("resolved_revision"),
    }
    return add.returncode == middle.returncode == final.returncode == remove.returncode == 0 and all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, "original_identity": original, "observed_identity": observed}


def data_receipt(manager: Path, product: str) -> dict[str, Any] | None:
    installation = selected_manager_installation(manager, product)
    if installation is None:
        return None
    receipts = installation.get("data_receipts")
    if not isinstance(receipts, dict) or len(receipts) != 1:
        return None
    receipt_id, receipt = next(iter(receipts.items()))
    if not (
        isinstance(receipt, dict)
        and receipt.get("data_receipt_id") == receipt_id
        and isinstance(receipt.get("locator"), str)
        and isinstance(receipt.get("ownership_digest"), str)
        and DIGEST.fullmatch(receipt["ownership_digest"])
    ):
        return None
    return copy.deepcopy(receipt)


def data_locator(manager: Path, product: str) -> Path | None:
    receipt = data_receipt(manager, product)
    return Path(receipt["locator"]) if receipt else None


def canonical_allowed_locator(locator: Path | None, allowed_roots: tuple[Path, ...]) -> Path | None:
    """Resolve roots/locator and reject lexical traversal or symlink escapes."""
    if locator is None or not locator.is_absolute() or ".." in locator.parts:
        return None
    try:
        canonical_roots = tuple(root.resolve(strict=True) for root in allowed_roots)
        canonical_locator = locator.resolve(strict=True)
    except OSError:
        return None
    if any(root == canonical_locator or root in canonical_locator.parents for root in canonical_roots):
        return canonical_locator
    return None


class RetainedMarker:
    """An inode-bound marker plus its descriptor-bound allowed-root ancestry."""

    def __init__(self, path: Path, ancestry: list[tuple[int, Path, int | None, str | None, tuple[int, int]]], marker_fd: int, marker_identity: tuple[int, int], body: bytes, mode: int):
        self.path = path
        self.ancestry = ancestry
        self.directory_fd = ancestry[-1][0]
        self.marker_fd = marker_fd
        self.marker_identity = marker_identity
        self.locator_identity = ancestry[-1][4]
        self.body = body
        self.mode = mode

    def verify(self) -> bool:
        try:
            for descriptor, absolute, parent_fd, name, identity in self.ancestry:
                opened = os.fstat(descriptor)
                if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != identity:
                    return False
                current = absolute.lstat() if parent_fd is None else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != identity:
                    return False
            opened_directory = os.fstat(self.directory_fd)
            opened_marker = os.fstat(self.marker_fd)
            current_marker = os.stat(self.path.name, dir_fd=self.directory_fd, follow_symlinks=False)
            os.lseek(self.marker_fd, 0, os.SEEK_SET)
            observed = b""
            while len(observed) <= len(self.body):
                chunk = os.read(self.marker_fd, len(self.body) + 1 - len(observed))
                if not chunk:
                    break
                observed += chunk
            return bool(
                stat.S_ISDIR(opened_directory.st_mode) and stat.S_ISREG(opened_marker.st_mode)
                and (opened_marker.st_dev, opened_marker.st_ino) == self.marker_identity
                and (current_marker.st_dev, current_marker.st_ino) == self.marker_identity
                and stat.S_IMODE(opened_marker.st_mode) == self.mode
                and stat.S_IMODE(current_marker.st_mode) == self.mode
                and observed == self.body
            )
        except OSError:
            return False

    def purged(
        self, allowed_roots: tuple[Path, ...], *, max_entries: int = 10000, max_depth: int = 32,
    ) -> bool:
        """Prove unlink of both the exact marker and its owned locator."""
        try:
            opened = os.fstat(self.marker_fd)
            if (opened.st_dev, opened.st_ino) != self.marker_identity or opened.st_nlink != 0:
                return False
            opened_locator = os.fstat(self.directory_fd)
            if (opened_locator.st_dev, opened_locator.st_ino) != self.locator_identity or opened_locator.st_nlink != 0:
                return False
            if len(self.ancestry) < 2 or self.ancestry[-1][2] != self.ancestry[-2][0]:
                return False
            try:
                os.stat(self.ancestry[-1][3], dir_fd=self.ancestry[-2][0], follow_symlinks=False)
                return False
            except FileNotFoundError:
                pass
            visited = 0
            for root in allowed_roots:
                anchor = root.resolve(strict=True)
                for directory, names, files in os.walk(anchor, followlinks=False):
                    relative = Path(directory).relative_to(anchor)
                    if len(relative.parts) > max_depth:
                        return False
                    names[:] = sorted(names)
                    for name in sorted([*names, *files]):
                        visited += 1
                        if visited > max_entries:
                            return False
                        metadata = os.lstat(Path(directory) / name)
                        if (metadata.st_dev, metadata.st_ino) == self.marker_identity:
                            return False
            return True
        except (OSError, ValueError):
            return False

    def close(self) -> None:
        for descriptor in [self.marker_fd, *(item[0] for item in reversed(self.ancestry))]:
            try:
                os.close(descriptor)
            except OSError:
                pass


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_nsec", ctypes.c_uint32), ("reserved", ctypes.c_int32)]


class _Statx(ctypes.Structure):
    _fields_ = [
        ("mask", ctypes.c_uint32), ("blksize", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64), ("nlink", ctypes.c_uint32),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16), ("spare0", ctypes.c_uint16),
        ("ino", ctypes.c_uint64), ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64), ("attributes_mask", ctypes.c_uint64),
        ("atime", _StatxTimestamp), ("btime", _StatxTimestamp),
        ("ctime", _StatxTimestamp), ("mtime", _StatxTimestamp),
        ("rdev_major", ctypes.c_uint32), ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32), ("dev_minor", ctypes.c_uint32),
        ("mnt_id", ctypes.c_uint64), ("dio_mem_align", ctypes.c_uint32),
        ("dio_offset_align", ctypes.c_uint32), ("spare3", ctypes.c_uint64 * 12),
    ]


_LIBC = ctypes.CDLL(None, use_errno=True)
_STATX_MNT_ID = 0x1000
_AT_EMPTY_PATH = 0x1000
_AT_SYMLINK_NOFOLLOW = 0x100
_INOTIFY_EVENT_MASK = 0x00000004 | 0x00000008 | 0x00000100 | 0x00000200 | 0x00000040 | 0x00000080
_INOTIFY_SELF_MASK = 0x00000400 | 0x00000800 | 0x00002000 | 0x00008000
_IN_Q_OVERFLOW = 0x00004000


def _statx_mount_id(directory_fd: int, name: str = "") -> int:
    """Return Linux's mount ID, failing if statx cannot make that binding."""
    statx = getattr(_LIBC, "statx", None)
    if statx is None:
        raise OSError(errno.ENOSYS, "statx is unavailable")
    result = _Statx()
    flags = _AT_EMPTY_PATH if not name else _AT_SYMLINK_NOFOLLOW
    if statx(directory_fd, os.fsencode(name), flags, _STATX_MNT_ID, ctypes.byref(result)) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    if result.mask & _STATX_MNT_ID == 0 or result.mnt_id == 0:
        raise OSError(errno.ENOTSUP, "statx mount identity is unavailable")
    return int(result.mnt_id)


class _LinuxAncestryLifetimeProof:
    """One fail-closed inotify stream plus statx mount bindings for ancestry edges."""

    def __init__(self):
        init = getattr(_LIBC, "inotify_init1", None)
        add = getattr(_LIBC, "inotify_add_watch", None)
        if init is None or add is None:
            raise OSError(errno.ENOSYS, "inotify is unavailable")
        self.fd = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if self.fd < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        self._add = add
        self._names: dict[int, set[bytes]] = {}
        self._edges: list[tuple[int, str, int, int]] = []
        self._failed = False
        self._roots: list[tuple[int, int]] = []

    def bind_root(self, root_fd: int) -> None:
        self._roots.append((root_fd, _statx_mount_id(root_fd)))

    def watch_parent(self, parent_fd: int, name: str) -> int:
        path = os.fsencode(f"/proc/self/fd/{parent_fd}")
        wd = self._add(self.fd, path, _INOTIFY_EVENT_MASK | _INOTIFY_SELF_MASK)
        if wd < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        self._names.setdefault(wd, set()).add(os.fsencode(name))
        return wd

    def ignore_name(self, wd: int, name: str) -> None:
        """Stop treating an existing final authority leaf as an ancestry edge."""
        wanted = os.fsencode(name)
        self._names.get(wd, set()).discard(wanted)

    def bind_existing_edge(self, parent_fd: int, name: str, child_fd: int) -> None:
        child_mount = _statx_mount_id(child_fd)
        if _statx_mount_id(parent_fd, name) != child_mount:
            raise OSError(errno.ESTALE, "ancestry mount changed while freezing")
        self._edges.append((parent_fd, name, child_fd, child_mount))

    def _record_event(self, wd: int, mask: int, raw_name: bytes) -> None:
        """Latch relevant churn and overflow; a later clean state cannot erase it."""
        if mask & _IN_Q_OVERFLOW or mask & _INOTIFY_SELF_MASK:
            self._failed = True
        if mask & _INOTIFY_EVENT_MASK and raw_name in self._names.get(wd, set()):
            self._failed = True

    def verify(self) -> bool:
        if self._failed:
            return False
        try:
            while True:
                try:
                    body = os.read(self.fd, 65536)
                except BlockingIOError:
                    break
                if not body:
                    self._failed = True
                    break
                offset = 0
                while offset + 16 <= len(body):
                    wd = int.from_bytes(body[offset:offset + 4], sys.byteorder, signed=True)
                    mask = int.from_bytes(body[offset + 4:offset + 8], sys.byteorder)
                    length = int.from_bytes(body[offset + 12:offset + 16], sys.byteorder)
                    raw_name = body[offset + 16:offset + 16 + length].split(b"\0", 1)[0]
                    offset += 16 + length
                    self._record_event(wd, mask, raw_name)
                if offset != len(body):
                    self._failed = True
            for root_fd, root_mount in self._roots:
                fresh_root = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
                try:
                    if _statx_mount_id(root_fd) != root_mount or _statx_mount_id(fresh_root) != root_mount:
                        self._failed = True
                finally:
                    os.close(fresh_root)
            for parent_fd, name, child_fd, mount_id in self._edges:
                if _statx_mount_id(child_fd) != mount_id or _statx_mount_id(parent_fd, name) != mount_id:
                    self._failed = True
        except OSError:
            self._failed = True
        return not self._failed

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


class FrozenAuthoritySet:
    """Descriptor-bound path authority with every lexical component pinned."""

    def __init__(self, records: dict[str, tuple[str, int, tuple[int, int], str, list[tuple[int, int | None, str | None, tuple[int, int]]]]], lifetime: _LinuxAncestryLifetimeProof):
        self.records = records
        self.lifetime = lifetime

    def _ancestry_bound(self, ancestry: list[tuple[int, int | None, str | None, tuple[int, int]]]) -> bool:
        if not ancestry or not self.lifetime.verify():
            return False
        try:
            fresh_root = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                fresh = os.fstat(fresh_root)
                if (fresh.st_dev, fresh.st_ino) != ancestry[0][3]:
                    return False
            finally:
                os.close(fresh_root)
            for descriptor, parent_fd, name, identity in ancestry:
                opened = os.fstat(descriptor)
                if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != identity:
                    return False
                if parent_fd is not None:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != identity:
                        return False
            return True
        except OSError:
            return False

    def retained(self, paths: set[str]) -> bool:
        try:
            for path in paths:
                kind, descriptor, identity, name, ancestry = self.records[path]
                if kind != "existing" or not self._ancestry_bound(ancestry):
                    return False
                opened = os.fstat(descriptor)
                current = os.stat(name, dir_fd=ancestry[-1][0], follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != identity or (current.st_dev, current.st_ino) != identity:
                    return False
            return True
        except (KeyError, OSError):
            return False

    def absent_and_unlinked(self) -> bool:
        try:
            for _path, (kind, descriptor, identity, name, ancestry) in self.records.items():
                if not self._ancestry_bound(ancestry):
                    return False
                opened = os.fstat(descriptor)
                if kind == "existing":
                    if (opened.st_dev, opened.st_ino) != identity or opened.st_nlink != 0:
                        return False
                else:
                    if (opened.st_dev, opened.st_ino) != identity:
                        return False
                try:
                    os.stat(name, dir_fd=ancestry[-1][0], follow_symlinks=False)
                    return False
                except FileNotFoundError:
                    pass
            return True
        except OSError:
            return False

    def partitioned(self, retained_paths: set[str]) -> bool:
        try:
            for path, (kind, descriptor, identity, name, ancestry) in self.records.items():
                if not self._ancestry_bound(ancestry):
                    return False
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != identity:
                    return False
                if path in retained_paths:
                    if kind != "existing":
                        return False
                    current = os.stat(name, dir_fd=ancestry[-1][0], follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != identity:
                        return False
                elif kind == "existing":
                    if opened.st_nlink != 0:
                        return False
                    try:
                        os.stat(name, dir_fd=ancestry[-1][0], follow_symlinks=False)
                        return False
                    except FileNotFoundError:
                        pass
                else:
                    try:
                        os.stat(name, dir_fd=ancestry[-1][0], follow_symlinks=False)
                        return False
                    except FileNotFoundError:
                        pass
            return True
        except OSError:
            return False

    def close(self) -> None:
        self.lifetime.close()
        closed: set[int] = set()
        for _, descriptor, _, _, ancestry in self.records.values():
            for child in [descriptor, *(item[0] for item in ancestry)]:
                if child not in closed:
                    try:
                        os.close(child)
                    except OSError:
                        pass
                    closed.add(child)


def freeze_path_authority(paths: set[str], allowed_roots: tuple[Path, ...]) -> FrozenAuthoritySet | None:
    """Open an absolute path component-by-component and retain its lexical binding."""
    records: dict[str, tuple[str, int, tuple[int, int], str, list[tuple[int, int | None, str | None, tuple[int, int]]]]] = {}
    opened_descriptors: list[int] = []
    lifetime: _LinuxAncestryLifetimeProof | None = None
    try:
        roots = tuple(root.resolve(strict=True) for root in allowed_roots)
        lifetime = _LinuxAncestryLifetimeProof()
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        for value in sorted(paths):
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts or str(path) != value:
                raise ValueError("authority path is not absolute and lexical")
            if not any(root == path or root in path.parents for root in roots):
                raise ValueError("authority path is outside the allowed roots")
            root_fd = os.open("/", directory_flags)
            opened_descriptors.append(root_fd)
            lifetime.bind_root(root_fd)
            root_metadata = os.fstat(root_fd)
            ancestry = [(root_fd, None, None, (root_metadata.st_dev, root_metadata.st_ino))]
            parent_fd = root_fd
            parts = path.parts[1:]
            if not parts:
                raise ValueError("filesystem root cannot be purge authority")
            for index, name in enumerate(parts):
                final = index == len(parts) - 1
                watch = lifetime.watch_parent(parent_fd, name)
                try:
                    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    opened_parent = os.fstat(parent_fd)
                    records[value] = (
                        "absent", parent_fd, (opened_parent.st_dev, opened_parent.st_ino), name, ancestry,
                    )
                    break
                if stat.S_ISLNK(metadata.st_mode) or (not final and not stat.S_ISDIR(metadata.st_mode)):
                    raise ValueError("authority path has a non-directory or symbolic ancestor")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                if not final:
                    flags |= getattr(os, "O_DIRECTORY", 0)
                descriptor = os.open(name, flags, dir_fd=parent_fd)
                opened_descriptors.append(descriptor)
                opened = os.fstat(descriptor)
                identity = (opened.st_dev, opened.st_ino)
                if identity != (metadata.st_dev, metadata.st_ino):
                    os.close(descriptor)
                    raise ValueError("authority component changed while freezing")
                if final:
                    lifetime.ignore_name(watch, name)
                    records[value] = ("existing", descriptor, identity, name, ancestry)
                else:
                    lifetime.bind_existing_edge(parent_fd, name, descriptor)
                    ancestry.append((descriptor, parent_fd, name, identity))
                    parent_fd = descriptor
            else:
                if value not in records:
                    raise ValueError("authority path was not frozen")
        frozen = FrozenAuthoritySet(records, lifetime)
        if set(records) != paths:
            raise ValueError("authority set is incomplete")
        return frozen
    except (OSError, ValueError):
        if lifetime is not None:
            lifetime.close()
        for descriptor in set(opened_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        return None


def freeze_complete_authority(
    installation: Any, allowed_roots: tuple[Path, ...], public_receipts: Any,
    transaction_receipts: Any = (), *, extra_paths: frozenset[str] = frozenset(),
) -> tuple[FrozenAuthoritySet, set[str]] | None:
    """Freeze every state/public-receipt authorized locator exactly once."""
    data = frozen_data_receipt_map(installation)
    if data is None or not public_receipts_bind_frozen_authority(public_receipts, data):
        return None
    data_paths = {receipt["locator"] for receipt in data.values()}
    paths = set(data_paths)
    paths.update(extra_paths)
    clients = installation.get("clients") if isinstance(installation, dict) else None
    if not isinstance(clients, dict):
        return None
    for binding in clients.values():
        if not isinstance(binding, dict) or not _nonempty(binding.get("target_locator")):
            return None
        paths.add(binding["target_locator"])
        for native in binding.get("native_objects", []):
            if isinstance(native, dict) and "path" in native:
                paths.add(native["path"])
        for receipt in binding.get("receipts", []):
            if isinstance(receipt, dict):
                for field in ("active_path", "staging_path", "backup_path"):
                    if _nonempty(receipt.get(field)):
                        paths.add(receipt[field])
    if not isinstance(transaction_receipts, (list, tuple)):
        return None
    for receipt in transaction_receipts:
        if not isinstance(receipt, dict):
            return None
        for field in ("active_path", "staging_path", "backup_path"):
            if _nonempty(receipt.get(field)):
                paths.add(receipt[field])
    frozen = freeze_path_authority(paths, allowed_roots)
    return (frozen, data_paths) if frozen is not None else None


def create_contained_marker(
    locator: Path | None, allowed_roots: tuple[Path, ...], leaf: str, body: bytes,
) -> RetainedMarker | None:
    """Create a new evidence leaf relative to the validated opened directory."""
    canonical = canonical_allowed_locator(locator, allowed_roots)
    if canonical is None or not leaf or leaf in {".", ".."} or "/" in leaf or "\\" in leaf:
        return None
    ancestry: list[tuple[int, Path, int | None, str | None, tuple[int, int]]] = []
    marker_fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        expected_locator = canonical.lstat()
        probe_fd = os.open(canonical, flags)
        try:
            probed = os.fstat(probe_fd)
            if (probed.st_dev, probed.st_ino) != (expected_locator.st_dev, expected_locator.st_ino):
                return None
        finally:
            os.close(probe_fd)
        anchors = [root.resolve(strict=True) for root in allowed_roots]
        matches = [anchor for anchor in anchors if anchor == canonical or anchor in canonical.parents]
        if len(matches) != 1:
            return None
        anchor = matches[0]
        anchor_fd = os.open(anchor, flags)
        anchor_stat = os.fstat(anchor_fd)
        ancestry.append((anchor_fd, anchor, None, None, (anchor_stat.st_dev, anchor_stat.st_ino)))
        current_path = anchor
        for part in canonical.relative_to(anchor).parts:
            parent_fd = ancestry[-1][0]
            child_fd = os.open(part, flags, dir_fd=parent_fd)
            child_stat = os.fstat(child_fd)
            current_path /= part
            ancestry.append((child_fd, current_path, parent_fd, part, (child_stat.st_dev, child_stat.st_ino)))
        directory_fd = ancestry[-1][0]
        opened = os.fstat(directory_fd)
        if canonical_allowed_locator(locator, allowed_roots) != canonical:
            return None
        marker_fd = os.open(
            leaf,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        current = canonical.lstat()
        if (
            (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or canonical_allowed_locator(locator, allowed_roots) != canonical
        ):
            os.close(marker_fd)
            marker_fd = None
            os.unlink(leaf, dir_fd=directory_fd)
            return None
        written = 0
        while written < len(body):
            written += os.write(marker_fd, body[written:])
        os.fsync(marker_fd)
        marker_metadata = os.fstat(marker_fd)
        retained = RetainedMarker(
            canonical / leaf, ancestry, marker_fd, (marker_metadata.st_dev, marker_metadata.st_ino),
            body, stat.S_IMODE(marker_metadata.st_mode),
        )
        if not retained.verify():
            return None
        ancestry = []
        marker_fd = None
        return retained
    except (FileExistsError, NotADirectoryError, OSError):
        return None
    finally:
        if marker_fd is not None:
            os.close(marker_fd)
        for descriptor, *_ in reversed(ancestry):
            os.close(descriptor)


def package_identity(
    package: Path, *, observed: tuple[dict[str, dict[str, Any]], dict[str, bytes]] | None = None,
) -> dict[str, str]:
    """Calculate the canonical tree and manifest identities from package bytes."""
    snapshot, bodies = observed if observed is not None else _stable_tree_snapshot(package)
    if "." not in snapshot or "plugin.json" not in bodies:
        raise ValueError("package snapshot has no regular plugin.json")
    entries: list[tuple[bytes, bytes, bytes, bytes, bytes]] = []
    for relative, item in snapshot.items():
        if relative == ".":
            continue
        kind = item["kind"].encode()
        mode = ("100755" if item["kind"] == "file" and item["mode"] & 0o111 else "100644" if item["kind"] == "file" else "040000").encode()
        entries.append((relative.encode(), kind, mode, b"", bodies.get(relative, b"")))
    ordered = sorted(entries, key=lambda entry: entry[0])
    digest = hashlib.sha256()
    domain = b"agentplugins.package-tree\x00sha256\x00v1"
    digest.update(len(domain).to_bytes(8, "big"))
    digest.update(domain)
    for relative, kind, mode, target, content in ordered:
        for field in (b"entry", relative, kind, mode, target):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
        digest.update(len(content).to_bytes(8, "big"))
        if kind == b"file":
            digest.update(content)
    return {
        "tree_digest": "sha256:" + digest.hexdigest(),
        "manifest_digest": "sha256:" + hashlib.sha256(bodies["plugin.json"]).hexdigest(),
    }


def plugin_data_update_proof(
    initial_identity: dict[str, Any], updated_identity: dict[str, Any],
    initial_receipt: dict[str, Any] | None, updated_receipt: dict[str, Any] | None,
    expected_initial: dict[str, str], expected_updated: dict[str, str],
) -> tuple[bool, bool]:
    changed_package = bool(
        initial_identity.get("tree_digest") == expected_initial["tree_digest"]
        and initial_identity.get("manifest_digest") == expected_initial["manifest_digest"]
        and updated_identity.get("tree_digest") == expected_updated["tree_digest"]
        and updated_identity.get("manifest_digest") == expected_updated["manifest_digest"]
        and expected_initial["tree_digest"] != expected_updated["tree_digest"]
        and expected_initial["manifest_digest"] != expected_updated["manifest_digest"]
    )
    preserved_receipt = initial_receipt is not None and initial_receipt == updated_receipt
    return changed_package, preserved_receipt


def plugin_data_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    package = root / "package-plugin-data"
    alternate = root / "package-plugin-data-alternate"
    shutil.copytree(EXTERNAL_PACKAGE, package)
    shutil.copytree(EXTERNAL_PACKAGE, alternate)
    mcp = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"demo": {"type": "stdio", "command": "sh", "args": ["-c", "echo ${PLUGIN_DATA}"], "env": {"DATA": "${PLUGIN_DATA}/state"}}},
    }
    (package / "mcp.json").write_text(json.dumps(mcp, sort_keys=True))
    (alternate / "mcp.json").write_text(json.dumps(mcp, sort_keys=True))
    initial_manifest = json.loads((package / "plugin.json").read_text())
    initial_manifest["version"] = "1.0.0"
    initial_manifest["description"] = "Deterministic PLUGIN_DATA lifecycle fixture revision one."
    (package / "plugin.json").write_text(json.dumps(initial_manifest, sort_keys=True))
    (package / "fixture-revision.txt").write_text("revision-one\n")
    expected_initial_identity = package_identity(package)
    alternate_manifest = json.loads((alternate / "plugin.json").read_text())
    alternate_manifest["description"] = "Alternate exact source for PLUGIN_DATA switch evidence."
    (alternate / "plugin.json").write_text(json.dumps(alternate_manifest, sort_keys=True))
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []

    def execute(argv: list[str]) -> subprocess.CompletedProcess[str]:
        completed, trace = traced(binary, argv, root, challenge)
        traces.append(trace)
        return completed

    add = execute(["add", "./" + package.name, "--target", "cursor", "--format", "json"])
    initial_identity = manager_identity(manager, "e2e-external-package")
    initial_installation = selected_manager_installation(manager, "e2e-external-package")
    initial_receipt = data_receipt(manager, "e2e-external-package")
    locator = data_locator(manager, "e2e-external-package")
    canonical_locator = canonical_allowed_locator(locator, (root, manager))
    safe_locator = canonical_locator is not None
    marker = create_contained_marker(locator, (root, manager), "launch-marker.txt", b"stable-launch-marker")
    safe_locator = marker is not None and marker.verify()
    info = execute(["info", "e2e-external-package", "--target", "cursor", "--format", "json"])
    info_preserved = marker is not None and marker.verify()
    update_manifest = json.loads((package / "plugin.json").read_text())
    update_manifest["version"] = "2.0.0"
    update_manifest["description"] = "Deterministic PLUGIN_DATA lifecycle fixture revision two."
    (package / "plugin.json").write_text(json.dumps(update_manifest, sort_keys=True))
    (package / "fixture-revision.txt").write_text("revision-two\n")
    expected_updated_identity = package_identity(package)
    update = execute(["update", "e2e-external-package", "--target", "cursor", "--format", "json"])
    updated_identity = manager_identity(manager, "e2e-external-package")
    updated_receipt = data_receipt(manager, "e2e-external-package")
    update_preserved = marker is not None and marker.verify()
    update_changed_package, update_preserved_receipt = plugin_data_update_proof(
        initial_identity, updated_identity, initial_receipt, updated_receipt,
        expected_initial_identity, expected_updated_identity,
    )
    cursor = home / ".cursor"
    for path in sorted(cursor.rglob("*"), reverse=True) if cursor.exists() else ():
        if path.is_file() and not path.is_symlink() and "e2e-external-package" in (path.as_posix() + path.read_text(errors="ignore")):
            path.unlink()
    repair = execute(["repair", "e2e-external-package", "--target", "cursor", "--format", "json"])
    repair_preserved = marker is not None and marker.verify()
    switch = execute(["switch", "e2e-external-package", "--to", "./" + alternate.name, "--format", "json"])
    switch_preserved = marker is not None and marker.verify()
    pre_remove_state = manager_state(manager)
    pre_remove_installation = selected_manager_installation(manager, "e2e-external-package")
    pre_remove_data = frozen_data_receipt_map(pre_remove_installation)
    projected_public_receipts = [
        {
            "data_receipt_id": receipt_id, "physical_backend_id": receipt["physical_backend_id"],
            "scope": receipt["scope"], "state": receipt["state"],
        }
        for receipt_id, receipt in (pre_remove_data or {}).items()
    ]
    removal_frozen_result = freeze_complete_authority(
        pre_remove_installation, (root, manager), projected_public_receipts,
        pre_remove_state.get("transaction_receipts", []) if pre_remove_state else None,
    )
    removal_authority, frozen_data_paths = removal_frozen_result if removal_frozen_result is not None else (None, set())
    remove = execute(["remove", "e2e-external-package", "--target", "cursor", "--format", "json"])
    try:
        remove_value = strict_json_loads(remove.stdout)
    except (json.JSONDecodeError, DuplicateKeyError, ValueError):
        remove_value = None
    retained_state = manager_state(manager)
    retained_installation = selected_manager_installation(manager, "e2e-external-package")
    remove_checks = {
        "marker_retained": marker is not None and marker.verify(),
        "authority_partitioned": removal_authority is not None and removal_authority.partitioned(frozen_data_paths),
        "data_map_unchanged": pre_remove_data == frozen_data_receipt_map(retained_installation),
        "stdout_bound": isinstance(remove_value, dict) and isinstance(remove_value.get("data"), dict)
        and public_receipts_bind_frozen_authority(
            remove_value["data"].get("retained_data"), pre_remove_data,
        ),
    }
    remove_preserved = all(remove_checks.values())
    if removal_authority is not None:
        removal_authority.close()
        removal_authority = None
    purge_public_receipts = remove_value.get("data", {}).get("retained_data") if isinstance(remove_value, dict) else None
    purge_state_path = str(manager / "state-v2.json")
    purge_frozen_result = freeze_complete_authority(
        retained_installation, (root, manager), purge_public_receipts,
        retained_state.get("transaction_receipts", []) if retained_state else None,
        extra_paths=frozenset({purge_state_path}),
    )
    purge_authority, purge_data_paths = purge_frozen_result if purge_frozen_result is not None else (None, set())
    purge = execute(["remove", "e2e-external-package", "--purge-data", "--format", "json"])
    purge_state = manager_state(manager)
    remaining = [
        item for item in purge_state.get("installations", [])
        if isinstance(item, dict) and item.get("installation_id") == (initial_installation or {}).get("installation_id")
    ] if purge_state else []
    valid_absent_state = purge_state is not None and not remaining
    purge_authority_valid = bool(
        purge_authority is not None and (
            (valid_absent_state and purge_authority.partitioned({purge_state_path}))
            or (purge_state is None and purge_authority.absent_and_unlinked())
        )
    )
    authority_consumed = purge_authority_valid
    purge_deleted = bool(
        marker is not None and marker.purged((root, manager)) and authority_consumed
        and purge_authority is not None and purge_data_paths == frozen_data_paths
    )
    after = observe(home, manager)
    proof = {
        "info_preserved": info_preserved,
        "update_changed_package_digest": update_changed_package,
        "update_preserved": update_preserved, "update_preserved_data_receipt": update_preserved_receipt,
        "repair_preserved": repair_preserved,
        "switch_preserved": switch_preserved, "remove_preserved": remove_preserved,
        "explicit_owned_purge_deleted": purge_deleted,
    }
    exits = (add, info, update, repair, switch, remove, purge)
    if marker is not None:
        marker.close()
    if removal_authority is not None:
        removal_authority.close()
    if purge_authority is not None:
        purge_authority.close()
    return safe_locator and all(item.returncode == 0 for item in exits) and all(proof.values()), {
        "command_traces": traces, "before": before, "after": after, "proof": proof,
        "data_receipt_observed": safe_locator, "initial_identity": initial_identity,
        "updated_identity": updated_identity, "initial_data_receipt": initial_receipt,
        "updated_data_receipt": updated_receipt,
        "remove_authority_checks": remove_checks,
        "purge_authority_consumed": authority_consumed,
        "expected_initial_identity": expected_initial_identity,
        "expected_updated_identity": expected_updated_identity,
    }


def explicit_switch_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    first, second = root / "switch-first", root / "switch-second"
    shutil.copytree(EXTERNAL_PACKAGE, first)
    shutil.copytree(EXTERNAL_PACKAGE, second)
    manifest = json.loads((second / "plugin.json").read_text())
    manifest["description"] = "Second immutable source used for switch rollback evidence."
    (second / "plugin.json").write_text(json.dumps(manifest, sort_keys=True))
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []

    def execute(argv: list[str]) -> subprocess.CompletedProcess[str]:
        completed, trace = traced(binary, argv, root, challenge)
        traces.append(trace)
        return completed

    add = execute(["add", "./switch-first", "--target", "cursor", "--format", "json"])
    initial = manager_identity(manager, "e2e-external-package")
    switched = execute(["switch", "e2e-external-package", "--to", "./switch-second", "--format", "json"])
    alternate = manager_identity(manager, "e2e-external-package")
    rolled_back = execute(["switch", "e2e-external-package", "--to", "./switch-first", "--format", "json"])
    restored = manager_identity(manager, "e2e-external-package")
    remove = execute(["remove", "e2e-external-package", "--target", "cursor", "--format", "json"])
    after = observe(home, manager)
    proof = {
        "switch_applied": switched.returncode == 0 and initial.get("tree_digest") != alternate.get("tree_digest"),
        "rollback_verified": rolled_back.returncode == 0 and initial.get("tree_digest") == restored.get("tree_digest") and add.returncode == remove.returncode == 0,
    }
    return all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, **proof}


def sticky_update_scenario(binary: Path, root: Path, challenge: str, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    sequence = int(context["snapshot_sequence"]) + 3000
    initial_env, _ = conformance_directory(root, context, sequence=sequence)
    update_env, fixture_digest = conformance_directory(root, context, sequence=sequence + 1, safe_successor=True)
    before = observe(home, manager)
    add, add_trace = traced_with_environment(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge, initial_env)
    initial = manager_identity(manager, "context7")
    update, update_trace = traced_with_environment(binary, ["update", "context7", "--target", "cursor", "--format", "json"], root, challenge, update_env)
    update_value = json_output(update, "update")
    updated = manager_identity(manager, "context7")
    remove, remove_trace = traced_with_environment(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge, update_env)
    after = observe(home, manager)
    proof = {
        "distribution_unchanged": bool(initial.get("distribution_id")) and initial.get("distribution_id") == updated.get("distribution_id"),
        "release_advanced": initial.get("desired_release_sequence") == 1 and updated.get("desired_release_sequence") == 2 and find_value(update_value, {"mutated"}) is True,
        "trusted_two_release_fixture": True,
        "update_advanced_from_sequence": initial.get("desired_release_sequence"),
        "update_advanced_to_sequence": updated.get("desired_release_sequence"),
    }
    return add.returncode == update.returncode == remove.returncode == 0 and all(proof.values()), {"command_traces": [add_trace, update_trace, remove_trace], "before": before, "after": after, "proof": proof, **proof, "fixture_digest": fixture_digest}


def source_kind_scenario(binary: Path, kind: str, root: Path, challenge: str, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    environment, fixture_digest = conformance_directory(root, context, sequence=int(context["snapshot_sequence"]) + 3200)
    product = context["release"]["product_id"]
    before = observe(home, manager)
    add, add_trace = traced_with_environment(binary, ["add", product, "--target", "cursor", "--format", "json"], root, challenge, environment)
    identity = manager_identity(manager, product)
    remove, remove_trace = traced_with_environment(binary, ["remove", product, "--target", "cursor", "--format", "json"], root, challenge, environment)
    after = observe(home, manager)
    canonical = parse_canonical_github_source(identity.get("canonical_source")) or {}
    source_identity = {
        "product_id": identity.get("product_id"),
        "distribution_id": identity.get("distribution_id"), "distribution_kind": identity.get("distribution_kind"),
        "release_sequence": identity.get("desired_release_sequence"), "source_revision": identity.get("resolved_revision"),
        "source_repository": canonical.get("source_repository"), "source_path": canonical.get("source_path"),
        "canonical_source": identity.get("canonical_source"),
        "tree_digest": identity.get("tree_digest"), "manifest_digest": identity.get("manifest_digest"),
    }
    revision = source_identity["source_revision"]
    proof = {
        "source_kind": source_identity["distribution_kind"],
        "immutable_revision": bool(FULL_SHA.fullmatch(str(revision))) and canonical.get("source_revision") == revision,
        "exact_source_identity": source_identities_match(context["source_identity"], source_identity),
    }
    passed = add.returncode == remove.returncode == 0 and proof == {"source_kind": kind, "immutable_revision": True, "exact_source_identity": True}
    return passed, {"command_traces": [add_trace, remove_trace], "before": before, "after": after, "proof": proof, **proof, "source_identity": source_identity, "fixture_digest": fixture_digest}


def fixture_git(repository: Path, *arguments: str, environment: dict[str, str] | None = None) -> str:
    env = os.environ.copy()
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"})
    if environment:
        env.update(environment)
    completed = subprocess.run(["git", *arguments], cwd=repository, env=env, text=True, capture_output=True, check=False, timeout=60)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"git {arguments[0]} failed")
    return completed.stdout.strip()


def fixture_commit(repository: Path, message: str, timestamp: str) -> str:
    fixture_git(repository, "add", ".")
    identity = {
        "GIT_AUTHOR_NAME": "Journey Fixture", "GIT_AUTHOR_EMAIL": "journey@example.invalid",
        "GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_NAME": "Journey Fixture",
        "GIT_COMMITTER_EMAIL": "journey@example.invalid", "GIT_COMMITTER_DATE": timestamp,
    }
    fixture_git(repository, "commit", "-qm", message, environment=identity)
    return fixture_git(repository, "rev-parse", "HEAD")


def command_artifact(name: str, argv: list[str], cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(argv, cwd=cwd, env=os.environ.copy(), text=True, capture_output=True, check=False, timeout=180)
    return {"name": name, "exit_code": completed.returncode, "stdout_digest": "sha256:" + hashlib.sha256(completed.stdout.encode()).hexdigest()}


def promotion_scenario(binary: Path, scenario: str, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    repository = root / "upstream-repository"
    package = repository / "packages" / "fixture-bridge"
    package.parent.mkdir(parents=True)
    shutil.copytree(FIXTURE_ROOT / "plugins" / "fixture-bridge", package)
    fixture_git(repository, "init", "-q", "-b", "main")
    reviewed_revision = fixture_commit(repository, "reviewed package", "2026-01-01T00:00:00Z")
    reviewed_tree = __import__("build_registry").directory_tree_digest(package)
    reviewed_manifest = "sha256:" + hashlib.sha256((package / "plugin.json").read_bytes()).hexdigest()
    if scenario == "promotion_gate_digest_mismatch":
        manifest = json.loads((package / "plugin.json").read_text())
        manifest["description"] = "Community package for changed maintainer bytes."
        (package / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n")
    else:
        (repository / "MERGE-NOTE.md").write_text("Docs outside the reviewed package.\n")
    candidate_revision = fixture_commit(repository, "merged candidate", "2026-01-02T00:00:00Z")
    evidence = sorted([
        command_artifact("package-validation", [sys.executable, str(Path(__file__).resolve().parent / "validate_catalog.py")], Path(__file__).resolve().parents[1]),
        command_artifact("registry-policy", [sys.executable, str(Path(__file__).resolve().parent / "build_registry.py"), "--check"], Path(__file__).resolve().parents[1]),
    ], key=lambda item: item["name"])
    review_record = root / "promotion-review.json"
    review_record.write_text(json.dumps({
        "schema_version": 1, "repository": "fixture/upstream", "path": "packages/fixture-bridge",
        "reviewed_revision": reviewed_revision, "reviewed_tree_digest": reviewed_tree,
        "reviewed_manifest_digest": reviewed_manifest, "product_id": "fixture-bridge",
        "distribution_id": "fixture/fixture-bridge", "required_components": ["skills"],
        "required_targets": ["codex"], "policy_status": "active", "evidence_artifacts": evidence,
    }, sort_keys=True))
    candidate_output = root / "promotion-candidate.json"
    before = observe(Path(os.environ["HOME"]), Path(os.environ["AGENTPLUGINS_HOME"]))
    before_repository = tree_digest(repository)
    argv = [str(JOURNEY_VALIDATOR), "promotion", "--repository", str(repository), "--repository-id", "fixture/upstream", "--reviewed-revision", reviewed_revision, "--candidate-revision", candidate_revision, "--path", "packages/fixture-bridge", "--review-record", str(review_record), "--candidate-output", str(candidate_output)]
    completed, trace = traced(Path(sys.executable), argv, root, challenge)
    trace["argv"] = ["validate-review-journey", "promotion", "--repository", "disposable-upstream", "--reviewed-revision", reviewed_revision, "--candidate-revision", candidate_revision, "--path", "packages/fixture-bridge"]
    result = json.loads(completed.stdout)
    after_repository = tree_digest(repository)
    after = observe(Path(os.environ["HOME"]), Path(os.environ["AGENTPLUGINS_HOME"]))
    gate_names = [item["name"] for item in result.get("gates", [])]
    if scenario == "promotion_gate_digest_match":
        deterministic = candidate_output.is_file() and hashlib.sha256(candidate_output.read_bytes()).hexdigest() == result.get("candidate_digest", "").removeprefix("sha256:")
        proof = {"digest_match": result.get("exact_match") is True, "promotion_simulated": completed.returncode == 0 and deterministic, "identity_gates_complete": gate_names == list(__import__("validate_review_journey").REQUIRED_PROMOTION_GATES), "repository_unchanged": before_repository == after_repository}
    else:
        proof = {"digest_mismatch": result.get("outcome") == "rejected" and "bytes differ" in result.get("reason", ""), "promotion_refused": completed.returncode == 2 and not candidate_output.exists(), "zero_mutation": before == after and before_repository == after_repository}
    return all(proof.values()), {"command_traces": [trace], "before": before, "after": after, "proof": proof, **proof, "validator_artifact": result, "reviewed_revision": reviewed_revision, "candidate_revision": candidate_revision}


def fork_submission_scenario(scenario: str, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    upstream = root / "bridge-upstream"
    shutil.copytree(FIXTURE_ROOT / "bridge_upstream", upstream)
    fixture_git(upstream, "init", "-q", "-b", "main")
    upstream_revision = fixture_commit(upstream, "fixture", "2026-01-01T00:00:00Z")
    mirror = root / "upstream-mirror" / "fixture"
    mirror.mkdir(parents=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(upstream), str(mirror / "upstream.git")], check=True, timeout=60)

    source = root / "contribution-source"
    source.mkdir()
    shutil.copytree(FIXTURE_ROOT / "bridges", source / "bridges")
    shutil.copytree(FIXTURE_ROOT / "plugins", source / "plugins")
    for recipe in (source / "bridges").glob("*/bridge.yaml"):
        recipe.write_text(recipe.read_text().replace("9ec238505ab95b2e07222e69a893f0bbac201ae6", upstream_revision))
    fixture_git(source, "init", "-q", "-b", "main")
    base_revision = fixture_commit(source, "base contribution repository", "2026-01-03T00:00:00Z")
    fork = root / "disposable-fork"
    subprocess.run(["git", "clone", "-q", str(source), str(fork)], check=True, timeout=60)
    fixture_git(fork, "checkout", "-qb", "contribution/fixture-bridge")
    readme = fork / "bridges" / "fixture-bridge" / "overlay" / "README.md"
    readme.write_text(readme.read_text() + "\nValidated through the disposable contributor journey.\n")
    build = subprocess.run([
        sys.executable, str(Path(__file__).resolve().parent / "build_bridges.py"),
        "--root", str(fork), "--upstream-mirror", str(root / "upstream-mirror"), "build", "fixture-bridge",
    ], cwd=fork, text=True, capture_output=True, check=False, timeout=180)
    if build.returncode:
        raise RuntimeError(build.stderr or build.stdout)
    if scenario == "fork_submission_rejected":
        manifest = json.loads((fork / "plugins" / "fixture-bridge" / "plugin.json").read_text())
        manifest["$schema"] = "https://example.invalid/unreviewed.schema.json"
        (fork / "plugins" / "fixture-bridge" / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n")
    branch_revision = fixture_commit(fork, "contribute fixture bridge", "2026-01-04T00:00:00Z")
    record = root / "submission.json"
    record.write_text(json.dumps({
        "schema_version": 1, "fork_repository": "contributor/fixture-fork",
        "base_revision": base_revision, "branch": "contribution/fixture-bridge",
        "branch_revision": branch_revision, "package_path": "plugins/fixture-bridge",
        "bridge_root": ".", "bridge_id": "fixture-bridge", "product_id": "fixture-bridge",
        "distribution_id": "contributor/fixture-bridge",
    }, sort_keys=True))
    before = observe(Path(os.environ["HOME"]), Path(os.environ["AGENTPLUGINS_HOME"]))
    before_repository = tree_digest(fork)
    argv = [str(JOURNEY_VALIDATOR), "submission", "--repository", str(fork), "--submission-record", str(record), "--upstream-mirror", str(root / "upstream-mirror")]
    completed, trace = traced(Path(sys.executable), argv, root, challenge)
    trace["argv"] = ["validate-review-journey", "submission", "--repository", "disposable-fork", "--branch-revision", branch_revision, "--upstream-mirror", "disposable-upstream-mirror"]
    result = json.loads(completed.stdout)
    after = observe(Path(os.environ["HOME"]), Path(os.environ["AGENTPLUGINS_HOME"]))
    after_repository = tree_digest(fork)
    if scenario == "fork_submission":
        gate_names = [item["name"] for item in result.get("gates", [])]
        side_effects = result.get("side_effects", {})
        proof = {
            "fork_created": (fork / ".git").is_dir(), "branch_submission": result.get("branch") == "contribution/fixture-bridge",
            "submission_validated": completed.returncode == 0 and gate_names == list(__import__("validate_review_journey").REQUIRED_SUBMISSION_GATES),
            "publication_performed": side_effects.get("publication_created") != 0,
            "pr_created": side_effects.get("pr_created") != 0, "network_performed": side_effects.get("network_commands") != 0,
            "repository_unchanged": before_repository == after_repository, "manager_unchanged": before == after,
        }
        passed = all((proof["fork_created"], proof["branch_submission"], proof["submission_validated"], not proof["publication_performed"], not proof["pr_created"], not proof["network_performed"], proof["repository_unchanged"], proof["manager_unchanged"]))
    else:
        proof = {
            "fork_created": (fork / ".git").is_dir(), "submission_rejected": completed.returncode == 2 and result.get("outcome") == "rejected",
            "no_side_effect": before == after and before_repository == after_repository,
            "no_candidate": not any(root.glob("*publication*")) and not any(root.glob("*pull-request*")),
        }
        passed = all(proof.values())
    return passed, {"command_traces": [trace], "before": before, "after": after, "proof": proof, **proof, "validator_artifact": result, "base_revision": base_revision, "branch_revision": branch_revision, "upstream_revision": upstream_revision}


def external_activation_scenario(binary: Path, root: Path, challenge: str, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    environment, fixture_digest = conformance_directory(
        root, context, sequence=int(context["snapshot_sequence"]) + 3400, target_delivery="manual_activation",
    )
    before = observe(home, manager)
    add, add_trace = traced_with_environment(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge, environment)
    combined = add.stdout + "\n" + add.stderr
    try:
        candidate = strict_json_loads(add.stdout)
        result = candidate if validate_cli_envelope(candidate, "add") else {}
    except (json.JSONDecodeError, ValueError):
        result = {}
    rendered = json.dumps(result, sort_keys=True).lower() + combined.lower()
    identity = manager_identity(manager, "context7")
    materialized = bool(identity) and materialized_product_mentions(home, manager, "context7", ("cursor",))["cursor"] > 0
    activation_visible = "activation" in rendered and any(word in rendered for word in ("pending", "manual", "failed", "repair"))
    repair_action = "repair" in rendered or "activation" in rendered
    remove, remove_trace = traced_with_environment(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge, environment)
    after = observe(home, manager)
    proof = {"materialization_retained": add.returncode == 0 and materialized and activation_visible, "repair_action_recorded": repair_action and remove.returncode == 0}
    return all(proof.values()), {"command_traces": [add_trace, remove_trace], "before": before, "after": after, "proof": proof, **proof, "fixture_digest": fixture_digest}


def stdio_containment_scenario(binary: Path, root: Path, challenge: str) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    package = root / "stdio-containment-package"
    shutil.copytree(EXTERNAL_PACKAGE, package)
    (package / "mcp.json").write_text(json.dumps({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"demo": {"type": "stdio", "command": "sh", "args": ["${PLUGIN_ROOT}/run.sh"], "env": {"DATA": "${PLUGIN_DATA}/state"}}},
    }, sort_keys=True))
    (package / "run.sh").write_text("#!/bin/sh\nexit 0\n")
    (package / "run.sh").chmod(0o700)
    before = observe(home, manager)
    add, add_trace = traced(binary, ["add", "./stdio-containment-package", "--target", "cursor", "--format", "json"], root, challenge)
    locator = data_locator(manager, "e2e-external-package")
    projected = []
    for path in (home / ".cursor").rglob("*") if (home / ".cursor").exists() else ():
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= (1 << 20):
            projected.append(path.read_text(errors="ignore"))
    projection = "\n".join(projected)
    managed_root_visible = str(manager) in projection
    data_visible = locator is not None and str(locator) in projection
    writable = False
    if locator is not None and locator.is_absolute() and (root in locator.parents or manager in locator.parents):
        locator.mkdir(parents=True, exist_ok=True)
        marker = locator / "stdio-write-proof"
        marker.write_text("ok")
        writable = marker.read_text() == "ok"
    contained = managed_root_visible and data_visible and "${PLUGIN_ROOT}" not in projection and "${PLUGIN_DATA}" not in projection
    remove, remove_trace = traced(binary, ["remove", "e2e-external-package", "--target", "cursor", "--format", "json"], root, challenge)
    after = observe(home, manager)
    proof = {"plugin_root_verified": add.returncode == 0 and managed_root_visible, "plugin_data_verified": data_visible, "writable": writable, "contained": contained and remove.returncode == 0}
    return all(proof.values()), {"command_traces": [add_trace, remove_trace], "before": before, "after": after, "proof": proof, **proof}


def retained_default_scenario(
    binary: Path, root: Path, challenge: str, context: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    sequence = int(context["snapshot_sequence"]) + 1000
    initial_env, initial_digest = conformance_directory(root, context, sequence=sequence)
    changed_env, changed_digest = conformance_directory(root, context, sequence=sequence + 1, default_alternate=True)
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    add, trace = traced_with_environment(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge, initial_env)
    traces.append(trace)
    original = manager_identity(manager, "context7")
    remove, trace = traced_with_environment(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge, initial_env)
    traces.append(trace)
    retained = manager_has_flag(manager, "context7", "data_retained", True)
    readd, trace = traced_with_environment(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge, changed_env)
    traces.append(trace)
    observed = manager_identity(manager, "context7")
    cleanup, trace = traced_with_environment(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge, changed_env)
    traces.append(trace)
    after = observe(home, manager)
    proof = {
        "data_retained_found_before_resolution": retained,
        "changed_default_ignored": bool(original.get("distribution_id")) and original.get("distribution_id") == observed.get("distribution_id") and observed.get("distribution_id") != "fixture/context7-alternate",
    }
    exits = (add, remove, readd, cleanup)
    return all(item.returncode == 0 for item in exits) and all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, "initial_fixture_digest": initial_digest, "changed_default_fixture_digest": changed_digest, "original_identity": original, "observed_identity": observed}


def signed_sequence_scenario(
    binary: Path, root: Path, challenge: str, context: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    environment, fixture_digest = conformance_directory(root, context, sequence=int(context["snapshot_sequence"]) + 1100, sequence_over_semver=True)
    before = observe(home, manager)
    add, add_trace = traced_with_environment(binary, ["add", "context7", "--target", "cursor", "--format", "json"], root, challenge, environment)
    identity = manager_identity(manager, "context7")
    remove, remove_trace = traced_with_environment(binary, ["remove", "context7", "--target", "cursor", "--format", "json"], root, challenge, environment)
    after = observe(home, manager)
    proof = {"higher_sequence_selected": identity.get("desired_release_sequence") == 2, "semver_order_ignored": identity.get("desired_release_sequence") == 2}
    return add.returncode == remove.returncode == 0 and all(proof.values()), {"command_traces": [add_trace, remove_trace], "before": before, "after": after, "proof": proof, "fixture_digest": fixture_digest, "observed_identity": identity}


def revoked_boundary_scenario(
    binary: Path, root: Path, challenge: str, context: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    sequence = int(context["snapshot_sequence"]) + 1200
    active_env, _ = conformance_directory(root, context, sequence=sequence)
    revoked_env, revoked_digest = conformance_directory(root, context, sequence=sequence + 1, revoked=True)
    safe_env, safe_digest = conformance_directory(root, context, sequence=sequence + 2, revoked=True, safe_successor=True)
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []

    def execute(argv: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        completed, trace = traced_with_environment(binary, argv, root, challenge, environment)
        traces.append(trace)
        return completed

    installed = execute(["add", "context7", "--target", "cursor", "--format", "json"], active_env)
    identity_before = manager_identity(manager, "context7")
    new_target = execute(["add", "context7", "--target", "codex", "--format", "json"], revoked_env)
    repair = execute(["repair", "context7", "--target", "cursor", "--format", "json"], revoked_env)
    identity_after_blocks = manager_identity(manager, "context7")
    update = execute(["update", "context7", "--target", "cursor", "--format", "json"], safe_env)
    update_value = json_output(update, "update")
    identity_after_update = manager_identity(manager, "context7")
    remove = execute(["remove", "context7", "--target", "cursor", "--format", "json"], safe_env)

    fresh = root / "revoked-fresh-install"
    fresh_home, fresh_manager, fresh_workspace = fresh / "home", fresh / "manager", fresh / "workspace"
    fresh_workspace.mkdir(parents=True)
    fresh_env = dict(revoked_env)
    fresh_env.update({"HOME": str(fresh_home), "USERPROFILE": str(fresh_home), "XDG_CONFIG_HOME": str(fresh / "config"), "XDG_CACHE_HOME": str(fresh / "cache"), "AGENTPLUGINS_HOME": str(fresh_manager), "AGENTPLUGINS_EVIDENCE_ROOT": str(fresh / "evidence")})
    blocked_install, trace = traced_with_environment(binary, ["add", "context7", "--target", "cursor", "--format", "json"], fresh_workspace, challenge, fresh_env)
    traces.append(trace)
    after = observe(home, manager)
    identity_unchanged = all(identity_before.get(field) == identity_after_blocks.get(field) for field in ("distribution_id", "resolved_revision", "desired_release_sequence"))
    proof = {
        "install_blocked": blocked_install.returncode != 0 and manager_facts(fresh_manager, "context7")["installation_records"] == 0 and materialized_product_mentions(fresh_home, fresh_manager, "context7", ("cursor",))["cursor"] == 0,
        "new_target_blocked": new_target.returncode != 0 and identity_unchanged,
        "repair_blocked": repair.returncode != 0 and identity_unchanged,
        "remove_available": remove.returncode == 0,
        "safe_update_available": update.returncode == 0 and identity_after_update.get("desired_release_sequence") == 2 and find_value(update_value, {"mutated"}) is True,
        "trusted_two_release_fixture": True,
        "update_advanced_from_sequence": identity_before.get("desired_release_sequence"),
        "update_advanced_to_sequence": identity_after_update.get("desired_release_sequence"),
        "same_release_recommit_avoided": True,
    }
    return installed.returncode == 0 and all(proof.values()), {"command_traces": traces, "before": before, "after": after, "proof": proof, "revoked_fixture_digest": revoked_digest, "safe_successor_fixture_digest": safe_digest}


def run(binary: Path, scenario: str, root: Path, challenge_context: dict[str, str]) -> dict[str, Any]:
    if scenario not in EXPECTED_SCENARIOS:
        raise ValueError("scenario is not in the immutable acceptance postcondition set")
    challenge = challenge_context["value"]
    home = Path(os.environ["HOME"])
    manager = Path(os.environ["AGENTPLUGINS_HOME"])
    before = observe(home, manager)
    traces: list[dict[str, Any]] = []
    proof: dict[str, Any] = {}
    validator_artifact: dict[str, Any] | None = None
    reason = "repository-owned observer could not establish the postcondition"

    if scenario in {"schema_1_0_0_accepted", "schema_draft_rejected", "schema_unknown_rejected"}:
        passed, schema_value = schema_scenario(binary, scenario, root, challenge)
        traces.extend(schema_value["command_traces"])
        proof = schema_value["proof"]
        before, after = schema_value["before"], schema_value["after"]
        reason = "exact schema behavior was derived from isolated package execution" if passed else "schema behavior or zero-mutation boundary was not observed"
    elif scenario == "project_scope_zero_mutation":
        passed, scope_value = project_scope_scenario(binary, root, challenge)
        traces.extend(scope_value["command_traces"])
        proof = scope_value["proof"]
        before, after = scope_value["before"], scope_value["after"]
        reason = "unsupported project scope failed before manager/native mutation" if passed else "project scope rejection or zero-mutation boundary was not observed"
    elif scenario == "direct_full_sha_immutable":
        passed, direct_value = direct_full_sha_scenario(binary, root, challenge, challenge_context)
        traces.extend(direct_value["command_traces"])
        proof = direct_value["proof"]
        before, after = direct_value["before"], direct_value["after"]
        reason = "direct source retained its exact full SHA and package identity" if passed else "direct full-SHA identity changed or could not be observed"
    elif scenario == "missing_runtime_exact_guidance":
        passed, runtime_value = missing_runtime_scenario(binary, root, challenge)
        traces.extend(runtime_value["command_traces"])
        proof = runtime_value["proof"]
        before, after = runtime_value["before"], runtime_value["after"]
        reason = "missing runtime failed before mutation with exact non-installing guidance" if passed else "missing-runtime boundary or exact guidance was not observed"
    elif scenario in {"readd_sticky_distribution", "repair_sticky_distribution"}:
        passed, sticky_value = sticky_scenario(binary, scenario, root, challenge)
        traces.extend(sticky_value["command_traces"])
        proof = sticky_value["proof"]
        before, after = sticky_value["before"], sticky_value["after"]
        reason = "recorded distribution and revision remained sticky" if passed else "recorded distribution/revision changed or was not observable"
    elif scenario == "plugin_data_lifecycle_boundary":
        passed, data_value = plugin_data_scenario(binary, root, challenge)
        traces.extend(data_value["command_traces"])
        proof = data_value["proof"]
        before, after = data_value["before"], data_value["after"]
        reason = "owned PLUGIN_DATA marker survived lifecycle and explicit purge removed it" if passed else "PLUGIN_DATA receipt/preservation/purge boundary was not observed"
    elif scenario == "retained_data_readd_before_changed_default":
        passed, retained_value = retained_default_scenario(binary, root, challenge, challenge_context)
        traces.extend(retained_value["command_traces"])
        proof = retained_value["proof"]
        before, after = retained_value["before"], retained_value["after"]
        reason = "data-retained state won before a changed signed default" if passed else "retained-data/changed-default ordering was not observed"
    elif scenario == "signed_sequence_not_semver":
        passed, sequence_value = signed_sequence_scenario(binary, root, challenge, challenge_context)
        traces.extend(sequence_value["command_traces"])
        proof = sequence_value["proof"]
        before, after = sequence_value["before"], sequence_value["after"]
        reason = "higher signed release sequence won over higher SemVer" if passed else "signed sequence selection was not observed"
    elif scenario == "revoked_operations_boundary":
        passed, revoked_value = revoked_boundary_scenario(binary, root, challenge, challenge_context)
        traces.extend(revoked_value["command_traces"])
        proof = revoked_value["proof"]
        before, after = revoked_value["before"], revoked_value["after"]
        reason = "revoked exposure/repair blocked while safe update/removal remained" if passed else "revocation operation boundary was not observed"
    elif scenario.startswith("hero_lifecycle_"):
        product, client = scenario.removeprefix("hero_lifecycle_").rsplit("_", 1)
        passed, lifecycle_value = lifecycle(binary, product, (client,), root, challenge, challenge_context, include_repair=False)
        traces.extend(lifecycle_value["command_traces"])
        proof = lifecycle_value
        reason = "disposable lifecycle and materialization postconditions passed; native discovery was not claimed" if passed else "disposable lifecycle materialization was incomplete"
    elif scenario == "context7_grouped_lifecycle":
        clients = ("codex", "cursor", "kiro")
        passed, lifecycle_value = lifecycle(binary, "context7", clients, root, challenge, challenge_context, include_repair=True)
        traces.extend(lifecycle_value["command_traces"])
        values = lifecycle_value["values"]
        acquisition = grouped_acquisition_proof(values.get("add"), clients)
        expected_tree_digest = challenge_context["release"]["tree_digest"]
        expected_manifest_digest = challenge_context["release"]["manifest_digest"]
        passed = bool(
            passed and acquisition
            and acquisition["tree_digest"] == expected_tree_digest
            and acquisition["manifest_digest"] == expected_manifest_digest
            and acquisition["source_repository"] == challenge_context["release"]["source_repository"]
            and acquisition["source_revision"] == challenge_context["release"]["source_revision"]
            and acquisition["source_path"] == challenge_context["release"]["source_path"]
        )
        proof = {
            **lifecycle_value,
            "commands": [
                observation["command"] for observation in lifecycle_value["operation_observations"]
                if observation["operation"] != "info"
            ],
            "acquisition": acquisition,
            "acquisition_digests": [acquisition["tree_digest"]] if acquisition else [],
            "target_outcomes": {
                client: outcome["outcome"] for client, outcome in acquisition["target_outcomes"].items()
            } if acquisition else {},
        }
        reason = "one disposable acquisition and three materializations observed; native discovery was not claimed" if passed else "grouped disposable lifecycle did not prove one acquisition and every target materialization"
    elif scenario == "shared_copilot_vscode_backend":
        passed, shared_value = shared_backend_lifecycle(binary, root, challenge, challenge_context)
        traces.extend(shared_value["command_traces"])
        proof = shared_value
        reason = "Copilot CLI and VS Code resolved to one receipt-backed physical mutation" if passed else "shared backend did not produce one independently observed physical mutation"
    elif scenario == "public_help_no_hidden_yes":
        passed, yes_value = no_hidden_yes_scenario(binary, root, challenge)
        traces.extend(yes_value["command_traces"])
        proof = yes_value["proof"]
        before, after = yes_value["before"], yes_value["after"]
        reason = "mutating parsers reject --yes as unknown before all manager/native mutation" if passed else "--yes was accepted, was not reported unknown, or caused mutation"
    elif scenario in {"fork_submission", "fork_submission_rejected"}:
        passed, fork_value = fork_submission_scenario(scenario, root, challenge)
        traces.extend(fork_value["command_traces"])
        proof = fork_value["proof"]
        before, after = fork_value["before"], fork_value["after"]
        validator_artifact = fork_value["validator_artifact"]
        reason = "local fork branch command artifacts passed contribution CI validators without side effects" if passed else "fork submission validator boundary was not observed"
    elif scenario in {"directory_offline", "directory_expired", "directory_tampered", "directory_sequence_rollback"}:
        passed, fault_value = directory_fault_scenario(binary, scenario, root, challenge, challenge_context)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "Directory fault was independently injected and the exact boundary observed" if passed else "Directory fault boundary was not observed"
    elif scenario == "managed_package_tamper":
        passed, fault_value = managed_tamper_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "managed package tamper was detected and required repair" if passed else "managed package tamper boundary was not observed"
    elif scenario.startswith("repair_"):
        passed, fault_value = repair_fault_scenario(binary, scenario.removeprefix("repair_"), root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "one native client fault was injected and repaired" if passed else "adapter repair fault boundary was not observed"
    elif scenario == "state_schema_2_migration":
        passed, fault_value = migration_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "explicit digest-checked migration preserved provenance and backup" if passed else "explicit migration/backup boundary was not observed"
    elif scenario == "crash_journal_recovery":
        passed, fault_value = crash_recovery_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "mid-operation process crash recovered through journal/ownership reconciliation" if passed else "crash recovery boundary was not observed"
    elif scenario == "missing_runtime_zero_mutation":
        passed, fault_value = missing_runtime_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        before, after = fault_value["before"], fault_value["after"]
        source = fault_value["proof"]
        proof = {"zero_mutation": source["zero_mutation"], "copy_ready_requirement": source["guidance_exact"], "dependency_installed": source["dependency_installed"]}
        passed = passed and all((proof["zero_mutation"], proof["copy_ready_requirement"], not proof["dependency_installed"]))
        reason = "missing runtime failed with copy-ready guidance and zero mutation" if passed else "missing runtime fault boundary was not observed"
    elif scenario == "plugin_data_update_repair_switch_remove_purge":
        passed, fault_value = plugin_data_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        before, after = fault_value["before"], fault_value["after"]
        source = fault_value["proof"]
        proof = {"marker_preserved": all(source[key] for key in ("update_preserved", "repair_preserved", "switch_preserved", "remove_preserved")), "explicit_purge_deleted": source["explicit_owned_purge_deleted"]}
        passed = passed and all(proof.values())
        reason = "PLUGIN_DATA preservation and explicit purge were observed" if passed else "PLUGIN_DATA lifecycle fault boundary was not observed"
    elif scenario == "explicit_source_switch":
        passed, fault_value = explicit_switch_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "explicit source switch and reverse switch restored the original digest" if passed else "explicit switch rollback boundary was not observed"
    elif scenario == "distribution_sticky_update":
        passed, fault_value = sticky_update_scenario(binary, root, challenge, challenge_context)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "update advanced release sequence without switching distribution" if passed else "distribution-sticky update boundary was not observed"
    elif scenario in {"promotion_gate_digest_match", "promotion_gate_digest_mismatch"}:
        passed, fault_value = promotion_scenario(binary, scenario, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        validator_artifact = fault_value["validator_artifact"]
        reason = "immutable promotion fixture digest gate produced the required decision" if passed else "promotion digest gate decision was not observed"
    elif scenario in {"upstream_owned_short_name", "community_bridge_short_name"}:
        kind = "upstream" if scenario == "upstream_owned_short_name" else "community_bridge"
        passed, fault_value = source_kind_scenario(binary, kind, root, challenge, challenge_context)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "short name selected the signed immutable source kind" if passed else "short-name source kind/immutable revision was not observed"
    elif scenario == "external_activation_failure":
        passed, fault_value = external_activation_scenario(binary, root, challenge, challenge_context)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "manual/external activation failure retained materialization and exposed repair action" if passed else "external activation failure boundary was not observed"
    elif scenario == "stdio_environment_and_containment":
        passed, fault_value = stdio_containment_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "stdio PLUGIN_ROOT/PLUGIN_DATA projection was writable and contained" if passed else "stdio environment/containment boundary was not observed"
    elif scenario == "managed_rollback":
        passed, fault_value = managed_rollback_scenario(binary, root, challenge)
        traces.extend(fault_value["command_traces"])
        proof = fault_value["proof"]
        before, after = fault_value["before"], fault_value["after"]
        reason = "mid-commit client fault rolled back every managed mutation" if passed else "managed rollback boundary was not observed"
    elif scenario in set(_CONFIG["fault_scenarios"] + _CONFIG["adapter_repair_faults"] + _CONFIG["advanced_scenarios"]):
        raise ValueError("required fault/advanced scenario has no repository-owned execution plan")
    else:
        raise ValueError("repository observer has no exact execution plan for this scenario")

    if scenario not in {"schema_1_0_0_accepted", "schema_draft_rejected", "schema_unknown_rejected", "project_scope_zero_mutation", "direct_full_sha_immutable", "missing_runtime_exact_guidance", "readd_sticky_distribution", "repair_sticky_distribution", "plugin_data_lifecycle_boundary", "retained_data_readd_before_changed_default", "signed_sequence_not_semver", "revoked_operations_boundary"}:
        after = observe(home, manager)
    result = {
        "schema_version": 1, "scenario_id": scenario, "challenge": challenge,
        "started_at": traces[0]["started_at"] if traces else now(), "observed_at": now(),
        # This repository-owned runner proves only disposable lifecycle,
        # materialization, fault, and postcondition behavior. Native discovery
        # and runtime claims remain exclusive to the protected observer input.
        "outcome": "passed" if passed else "failed", "reason": reason,
        "command_traces": traces, "before": before, "after": after, "proof": proof,
        "client_version": None,
        "evidence_basis": "repository_owned_disposable_observer", "runtime_proof": False,
        "native_discovery_proof": False,
        "manager_observer": "agentplugins-state-tree-v1", "native_observer": "native-client-tree-v1",
    }
    if validator_artifact is not None:
        result["validator_artifact"] = validator_artifact
    result.update(proof)
    if scenario.startswith("hero_lifecycle_") or scenario in {"context7_grouped_lifecycle", "shared_copilot_vscode_backend"}:
        result.update({key: value for key, value in proof.items() if key not in {"command_traces"}})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--scenario", choices=sorted(EXPECTED_SCENARIOS), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--challenge-context", type=Path, required=True)
    args = parser.parse_args()
    value = run(args.binary.resolve(), args.scenario, args.root.resolve(), json.loads(args.challenge_context.read_text()))
    print(json.dumps(value, sort_keys=True))
    return 0 if value["outcome"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
