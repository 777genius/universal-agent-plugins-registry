"""Read the reviewed, immutable released UAP client contract without network I/O.

Client identity is installer capability metadata, never a package policy grant.
The historical publisher applies its own frozen compatibility boundary.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "777genius/universal-agent-plugins"
SOURCE_PATH = "landing/data/clientCapabilities.generated.json"
CONTRACT_PATH = Path("registry/client-capabilities.json")
LOCK_PATH = Path("registry/client-capabilities.lock.json")
RELEASE_RE = re.compile(r"agentplugins-v[0-9]+\.[0-9]+\.[0-9]+")
CLIENT_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
MAX_CONTRACT_BYTES = 256 << 10


class ClientContractError(ValueError):
    """The checked-in client contract or its immutable provenance is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClientContractError(message)


def parse_json(body: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ClientContractError(f"{label}: invalid JSON constant {value}")

    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ClientContractError(f"{label}: invalid UTF-8 JSON") from error


def contract_client_ids(body: bytes) -> tuple[str, ...]:
    require(len(body) <= MAX_CONTRACT_BYTES, "client contract exceeds size limit")
    rows = parse_json(body, "client contract")
    require(isinstance(rows, list) and bool(rows), "client contract must be a nonempty array")
    clients: list[str] = []
    for row in rows:
        require(isinstance(row, dict), "client contract row must be an object")
        client = row.get("id")
        require(isinstance(client, str) and CLIENT_RE.fullmatch(client) is not None,
                "client contract contains an invalid client ID")
        require(client not in clients, f"client contract contains duplicate client {client}")
        clients.append(client)
    return tuple(clients)


def load_client_ids(root: Path = ROOT) -> tuple[str, ...]:
    try:
        lock_body = (root / LOCK_PATH).read_bytes()
        require(len(lock_body) <= 4096, "client contract pin exceeds size limit")
        lock = parse_json(lock_body, "client contract pin")
        require(isinstance(lock, dict) and set(lock) == {
            "schema_version", "repository", "release", "revision", "path", "digest",
        }, "client contract pin fields are invalid")
        require(type(lock["schema_version"]) is int and lock["schema_version"] == 1,
                "client contract pin version is invalid")
        require(lock["repository"] == REPOSITORY and lock["path"] == SOURCE_PATH,
                "client contract must name the canonical UAP generator output")
        require(isinstance(lock["release"], str) and RELEASE_RE.fullmatch(lock["release"]) is not None,
                "client contract pin must name an exact released CLI tag")
        require(isinstance(lock["revision"], str) and re.fullmatch(r"[0-9a-f]{40}", lock["revision"]) is not None,
                "client contract pin must use an immutable full commit")
        body = (root / CONTRACT_PATH).read_bytes()
    except OSError as error:
        raise ClientContractError(f"cannot read pinned client contract: {error}") from error
    require(lock["digest"] == "sha256:" + hashlib.sha256(body).hexdigest(),
            "client contract digest differs from its reviewed pin")
    return contract_client_ids(body)
