#!/usr/bin/env python3
"""Synchronize Directory client enums from the pinned released UAP contract.

Normal --check/--write operation is offline. An explicit --from-uap update reads
only the named release's committed artifact, never its checkout's working tree.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

if __package__:
    from .client_contract import (
        CONTRACT_PATH, LOCK_PATH, REPOSITORY, RELEASE_RE, ROOT, SOURCE_PATH,
        ClientContractError, contract_client_ids, load_client_ids, parse_json, require,
    )
else:
    from client_contract import (
        CONTRACT_PATH, LOCK_PATH, REPOSITORY, RELEASE_RE, ROOT, SOURCE_PATH,
        ClientContractError, contract_client_ids, load_client_ids, parse_json, require,
    )

SCHEMA_CLIENT_ENUMS = {
    "directory-distribution": ("$defs/target/properties/client/enum",),
    "directory-evidence-artifact": ("properties/client/enum",),
    "directory-evidence": ("properties/client/enum",),
    "directory-preview": ("$defs/eligibleTarget/properties/client/enum",),
    "directory-publication-candidate": (
        "$defs/target/properties/client/enum",
        "$defs/wireEvidence/properties/client/enum",
        "$defs/legacyEvidence/properties/client/enum",
    ),
    "promotion-candidate": ("$defs/target/properties/client/enum",),
    "registry-index": ("$defs/clientSupport/properties/clients/items/enum",),
}
ENUM_RE = re.compile(r'"enum"\s*:\s*(\[[^\[\]]*\])')


def generated_schema(body: bytes, pointers: tuple[str, ...], clients: tuple[str, ...]) -> bytes:
    document = parse_json(body, "client schema")
    expected = copy.deepcopy(document)
    previous: list[list[str]] = []
    for pointer in pointers:
        node = expected
        try:
            for part in pointer.split("/")[:-1]:
                node = node[part]
            values = node["enum"]
        except (KeyError, TypeError) as error:
            raise ClientContractError(f"client schema pointer is absent: {pointer}") from error
        require(isinstance(values, list) and all(isinstance(value, str) for value in values),
                f"client schema enum is invalid: {pointer}")
        previous.append(values)
        node["enum"] = list(clients)

    def replace(match: re.Match[str]) -> str:
        if json.loads(match.group(1)) not in previous:
            return match.group(0)
        prefix = match.group(0)[:match.start(1) - match.start()]
        return prefix + json.dumps(clients)

    generated = ENUM_RE.sub(replace, body.decode("utf-8")).encode("utf-8")
    require(parse_json(generated, "generated client schema") == expected,
            "client enum generation changed an unexpected schema field")
    return generated


def sync_schemas(root: Path, *, write: bool = False) -> list[str]:
    clients = load_client_ids(root)
    changes: dict[Path, bytes] = {}
    for name, pointers in SCHEMA_CLIENT_ENUMS.items():
        path = root / "schemas" / f"{name}.schema.json"
        body = path.read_bytes()
        generated = generated_schema(body, pointers, clients)
        if generated != body:
            changes[path] = generated
    if write:
        for path, generated in changes.items():
            path.write_bytes(generated)
    return [str(path.relative_to(root)) for path in changes]


def update_pin(root: Path, checkout: Path, release: str, reviewed_revision: str) -> None:
    require(RELEASE_RE.fullmatch(release) is not None, "update requires an exact CLI release tag")
    require(re.fullmatch(r"[0-9a-f]{40}", reviewed_revision) is not None,
            "update requires the independently reviewed full release commit")

    def git(*args: str) -> bytes:
        result = subprocess.run(["git", "-C", str(checkout), *args], capture_output=True, check=False)
        require(result.returncode == 0, "cannot read the requested release from the UAP checkout")
        return result.stdout

    revision = git("rev-parse", "--verify", f"refs/tags/{release}^{{commit}}").decode("ascii").strip()
    require(revision == reviewed_revision, "local release tag differs from the reviewed release commit")
    body = git("show", f"{revision}:{SOURCE_PATH}")
    contract_client_ids(body)
    lock = {
        "schema_version": 1, "repository": REPOSITORY, "release": release,
        "revision": revision, "path": SOURCE_PATH,
        "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
    }
    (root / CONTRACT_PATH).write_bytes(body)
    (root / LOCK_PATH).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--from-uap", type=Path, metavar="CHECKOUT")
    parser.add_argument("--release", help="exact published CLI tag; required with --from-uap")
    parser.add_argument("--revision", help="independently reviewed full release commit; required with --from-uap")
    args = parser.parse_args()
    try:
        require(bool(args.from_uap) == bool(args.release) == bool(args.revision),
                "--from-uap, --release and --revision must be used together")
        if args.from_uap:
            update_pin(ROOT, args.from_uap, args.release, args.revision)
        changes = sync_schemas(ROOT, write=args.write or bool(args.from_uap))
        if args.check and changes:
            raise ClientContractError("client contract/schema drift: " + ", ".join(changes))
        print(f"Pinned released client contract: {len(load_client_ids())} IDs; schemas {'updated' if changes else 'consistent'}")
        return 0
    except (ClientContractError, OSError) as error:
        print(f"client contract refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
