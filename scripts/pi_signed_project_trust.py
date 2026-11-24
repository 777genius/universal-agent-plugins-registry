"""Frozen public CLI 0.1.114 Pi project trust acceptance oracle.

Test-only: verify local machine receipts and exact native bytes without
granting trust, writing configuration, or exposing private state in reports.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat
import struct

from pi_signed_marketing_kit_e2e import require

# Exact piTrustHookMarker + piTrustHookSource raw string at the published
# 0.1.114 producer eb75218c574472169d37a898af65952080d15c99.
HOOK_SHA256 = "eb4fa44cb880e1df05e42356f7e4bef9efef4abad82495cdfc87867b76b90a73"
HOOK = "extensions/agentplugins-project-trust/"
HOOK_ENTRY = HOOK + "index.ts"
HOOK_RECORD = HOOK + "projects.json"
HOOK_LOCKS = {HOOK_ENTRY + ".agentplugins.lock", HOOK_RECORD + ".agentplugins.lock"}
MCP_LOCK = "mcp.json.agentplugins.lock"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def plain_info(path: Path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400,
            "Pi trust oracle encountered a link or reparse point")
    return info


def plain_bytes(path: Path, limit: int) -> bytes:
    before = plain_info(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= limit, "Pi trust oracle expected a bounded plain file")
    with path.open("rb") as file:
        opened = os.fstat(file.fileno())
        require(os.path.samestat(before, opened) and opened.st_nlink == 1,
                "Pi trust input identity changed")
        data = file.read(limit + 1)
    require(len(data) == before.st_size, "Pi trust input size changed")
    return data


def strict_document(path: Path, limit: int, *, numeric_float: bool = False) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate key in Pi trust input")
            result[key] = value
        return result

    def invalid_constant(_):
        raise RuntimeError("nonfinite Pi trust JSON value")

    parsed = json.loads(plain_bytes(path, limit).decode("utf-8-sig"),
                        object_pairs_hook=unique, parse_constant=invalid_constant,
                        parse_int=float if numeric_float else int)
    require(isinstance(parsed, dict), "Pi trust input is not an object")
    return parsed


def trust_tree_digest(root: Path) -> str:
    """Match the producer's depth-first bytewise d/f NUL-framed digest."""
    require(stat.S_ISDIR(plain_info(root).st_mode), "Pi trust resource is not a directory")
    digest = hashlib.sha256()
    entries, size = 0, 0

    def walk(directory: Path, prefix: str):
        nonlocal entries, size
        for child in sorted(directory.iterdir(), key=lambda p: p.name.encode("utf-8")):
            entries += 1
            require(entries <= 16384, "Pi trust tree entry limit exceeded")
            rel = prefix + child.name
            info = plain_info(child)
            if stat.S_ISDIR(info.st_mode):
                digest.update(b"d\0" + rel.encode("utf-8") + b"\0")
                walk(child, rel + "/")
            else:
                data = plain_bytes(child, (64 << 20) - size)
                size += len(data)
                digest.update(b"f\0" + rel.encode("utf-8") + b"\0"
                              + hashlib.sha256(data).hexdigest().encode("ascii") + b"\0")

    walk(root, "")
    return "sha256:" + digest.hexdigest()


def trust_value_digest(value: object) -> str:
    """Match the producer's typed JSON framing, not JSON serialization."""
    def frame(item):
        if item is None:
            return b"n"
        if isinstance(item, bool):
            return b"t" if item else b"f"
        if type(item) in (int, float):
            require(math.isfinite(float(item)), "nonfinite Pi trust number")
            return b"d" + struct.pack(">d", float(item)).hex().encode("ascii")
        if isinstance(item, str):
            data = item.encode("utf-8")
            return b"s" + str(len(data)).encode("ascii") + b":" + data
        if isinstance(item, list):
            return b"a" + str(len(item)).encode("ascii") + b":" + b"".join(map(frame, item))
        require(isinstance(item, dict), "invalid Pi trust value")
        keys = sorted(item, key=lambda key: key.encode("utf-8"))
        return (b"o" + str(len(keys)).encode("ascii") + b":"
                + b"".join(frame(key) + frame(item[key]) for key in keys))

    return "sha256:" + hashlib.sha256(frame(value)).hexdigest()


def leaf(name: object) -> bool:
    return (isinstance(name, str) and bool(name) and name not in (".", "..")
            and not any(c in name for c in ("/", "\\", ":", "\0"))
            and all(ord(c) >= 32 for c in name))


def verify_project_trust(user: Path, project: Path, packages: dict,
                         owners: dict, snapshot: tuple[int, str]) -> None:
    """Reconcile the isolated project's private state with public lock/owners."""
    root = project.resolve(strict=True)
    native = root / ".pi"
    state = strict_document(root / ".uap" / "state-v2.json", 16 << 20)
    installations = state.get("installations")
    receipts = state.get("environment_receipts")
    require(type(state.get("schema_version")) is int and state["schema_version"] == 5
            and isinstance(installations, list) and len(installations) == len(packages)
            and isinstance(receipts, list) and len(receipts) == len(packages),
            "Pi private project state differs from locked inventory")
    by_id = {record["installation_id"]: record for record in installations}
    by_alias = {receipt["alias"]: receipt for receipt in receipts}
    require(len(by_id) == len(installations) and len(by_alias) == len(receipts)
            and set(by_id) == set(owners.values()) and set(by_alias) == set(packages),
            "Pi private project owner identities differ from public inventory")
    expected = {}
    owned_skills, owned_servers = set(), set()
    mcp_path = native / "mcp.json"
    mcp_document = strict_document(mcp_path, 4 << 20, numeric_float=True) if mcp_path.exists() else {}
    require(set(mcp_document) <= {"mcpServers"}, "Pi project MCP document has unexpected fields")
    servers = mcp_document.get("mcpServers", {})
    require(isinstance(servers, dict), "Pi project MCP collection invalid")

    for alias, package in packages.items():
        registry = package["source"]["registry"]
        dist = registry["distribution_id"]
        installation_id = owners[dist]
        installation = by_id[installation_id]
        origin = installation.get("directory", {})
        source = installation.get("source", {})
        require(installation.get("origin_mode") == "directory"
                and origin.get("distribution_id") == dist
                and origin.get("desired_release_sequence") == registry["release_sequence"]
                and origin.get("snapshot_sequence") == snapshot[0]
                and origin.get("snapshot_digest") == snapshot[1]
                and source.get("resolved_revision") == registry["commit"]
                and source.get("tree_digest") == package["tree_digest"]
                and installation.get("package", {}).get("manifest_digest") == package["manifest_digest"],
                "Pi private project source identity differs from signed lock")
        bindings = installation.get("clients", {})
        require(isinstance(bindings, dict) and len(bindings) == 1, "Pi project binding inventory invalid")
        binding_id, binding = next(iter(bindings.items()))
        receipt = by_alias[alias]
        require(receipt.get("client_id") == "pi" and receipt.get("installation_id") == installation_id
                and receipt.get("client_binding_id") == binding_id
                and receipt.get("source_key") == package["source_key"]
                and receipt.get("package_digest") == package["tree_digest"]
                and binding.get("client_binding_id") == binding_id
                and binding.get("client_id") == "pi" and binding.get("scope") == "project",
                "Pi private environment receipt differs from locked project binding")
        artifact = binding.get("physical_artifact_id")
        require(leaf(artifact) and artifact not in expected
                and Path(binding["target_locator"]) == native / "extensions" / artifact,
                "Pi project physical artifact ownership invalid")
        record = {"extensions": {artifact: trust_tree_digest(native / "extensions" / artifact)},
                  "skills": {}, "mcp_servers": {}}
        for obj in binding.get("native_objects", []):
            kind, name = obj.get("kind"), obj.get("logical_name")
            require(kind not in ("pi_user_skill_directory", "pi_user_mcp_server"),
                    "Pi project receipt contains user resources")
            if kind == "pi_project_skill_directory":
                require(leaf(name) and name not in owned_skills
                        and Path(obj["path"]) == native / "skills" / name,
                        "Pi project Skill ownership invalid")
                owned_skills.add(name)
                record["skills"][name] = trust_tree_digest(native / "skills" / name)
            elif kind == "pi_project_mcp_server":
                require(isinstance(name, str) and name in servers and name not in owned_servers
                        and Path(obj["path"]) == mcp_path, "Pi project MCP ownership invalid")
                owned_servers.add(name)
                record["mcp_servers"][name] = trust_value_digest(servers[name])
        expected[artifact] = record

    # A trust record alone is not authority to ignore unrelated native resources.
    require(set(servers) == owned_servers, "Pi project has unowned MCP resources")
    for surface, names in (("extensions", set(expected)), ("skills", owned_skills),
                           ("prompts", set()), ("themes", set())):
        directory = native / surface
        if directory.exists():
            require(stat.S_ISDIR(plain_info(directory).st_mode)
                    and {p.name for p in directory.iterdir()} == names,
                    "Pi project has unowned native resources")
        else:
            require(not names, "Pi project owned resource directory missing")
    require(set(p.name for p in native.iterdir()) <=
            {"extensions", "skills", "prompts", "themes", "mcp.json", MCP_LOCK},
            "Pi project has unexpected native settings")
    require(hashlib.sha256(plain_bytes(user / HOOK_ENTRY, 16 << 10)).hexdigest() == HOOK_SHA256,
            "Pi project trust hook differs from pinned published CLI")
    record = strict_document(user / HOOK_RECORD, 1 << 20)
    require(type(record.get("schema_version")) is int and record["schema_version"] == 1
            and record == {"schema_version": 1, "projects": {str(root): expected}},
            "Pi project trust record differs from exact owned project resources")


def check_opposite_after_project(root: Path, before: dict, after: dict) -> None:
    """Only the exact verified trust files may change the otherwise isolated user profile."""
    remaining = dict(after)
    for name in (HOOK_ENTRY, HOOK_RECORD):
        require(name not in before and name in remaining, "Pi project trust files missing or preexisting")
        remaining.pop(name)
    for name in HOOK_LOCKS:
        if name in remaining and name not in before:
            require(remaining[name] == EMPTY_SHA256 and plain_bytes(root / name, 0) == b"",
                    "Pi project trust writer lock is not empty")
            remaining.pop(name)
    require(remaining == before, "Pi project changed unrelated user native resources")


def check_removed(root: Path, before: dict, after: dict, *,
                  had_mcp: bool, project_user: bool = False) -> None:
    """No native payload may survive; only known empty writer scaffolding may remain.

    0.1.114 nativeconfig keeps the empty MCP collection and regular writer
    lock files, on POSIX and Windows. Never remove or mask existing files.
    """
    remaining = dict(after)
    if had_mcp and "mcp.json" not in before and "mcp.json" in remaining:
        require(strict_document(root / "mcp.json", 4 << 20) == {"mcpServers": {}},
                "Pi native MCP configuration still contains payload")
        remaining.pop("mcp.json")
    allowed = ({MCP_LOCK} if had_mcp else set()) | (HOOK_LOCKS if project_user else set())
    for name in allowed:
        if name in remaining and name not in before:
            require(remaining[name] == EMPTY_SHA256 and plain_bytes(root / name, 0) == b"",
                    "Pi native writer lock is not empty")
            remaining.pop(name)
    require(remaining == before, "Pi native projection remains or other scope was modified")
