"""Isolated Directory schema-2 signature boundary (not a publication action).

The existing v1 signer and public feed are unchanged. An authenticated
schema-2 bootstrap must never be verifiable in the schema-1 domain.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from directory_publication import (
    MAX_ENVELOPE_BYTES, MAX_SNAPSHOT_BYTES, PublicationError, ROOT,
    canonical_json, ed25519_sign, ed25519_verify, parse_json_bytes,
    require, validate_with_schema,
)
from directory_v2_contract import require_unique_scoped_grants


SIGNATURE_DOMAIN_V2 = b"UAP-DIRECTORY-SNAPSHOT-ED25519-V2\x00"
SNAPSHOT_SCHEMA_V2 = ROOT / "schemas/directory-snapshot-v2.schema.json"
ENVELOPE_SCHEMA_V2 = ROOT / "schemas/directory-envelope-v2.schema.json"


def v2_signature_message(snapshot_bytes: bytes) -> bytes:
    require(0 < len(snapshot_bytes) <= MAX_SNAPSHOT_BYTES,
            "v2 snapshot exceeds signed size limit")
    return SIGNATURE_DOMAIN_V2 + len(snapshot_bytes).to_bytes(8, "big") + snapshot_bytes


def validate_v2_snapshot(snapshot: dict) -> None:
    validate_with_schema(snapshot, SNAPSHOT_SCHEMA_V2)
    for distribution in snapshot["distributions"]:
        for policy in distribution["release_policies"]:
            require_unique_scoped_grants(policy)


def sign_v2_snapshot(snapshot: dict, key_id: str, private_seed: bytes) -> tuple[bytes, bytes]:
    """Build a detached envelope over exact canonical bytes using existing crypto."""
    validate_v2_snapshot(snapshot)
    body = canonical_json(snapshot)
    require(len(body) <= MAX_SNAPSHOT_BYTES, "v2 snapshot exceeds size limit")
    require(isinstance(key_id, str) and key_id != "", "v2 key ID is required")
    signature = ed25519_sign(private_seed, v2_signature_message(body))
    envelope = {
        "envelope_schema_version": 2,
        "snapshot_schema_version": 2,
        "sequence": snapshot["sequence"],
        "key_id": key_id,
        "algorithm": "Ed25519",
        "signature_domain": "UAP-DIRECTORY-SNAPSHOT-ED25519-V2",
        "snapshot_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    validate_with_schema(envelope, ENVELOPE_SCHEMA_V2)
    encoded = canonical_json(envelope)
    require(len(encoded) <= MAX_ENVELOPE_BYTES, "v2 envelope exceeds size limit")
    return body, encoded


def verify_v2_snapshot(snapshot_bytes: bytes, envelope_bytes: bytes,
                       public_keys: dict[str, bytes]) -> dict:
    """Validate exact signed bytes; callers still enforce ledger and time policy."""
    snapshot = parse_json_bytes(snapshot_bytes, "v2 snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    envelope = parse_json_bytes(envelope_bytes, "v2 envelope", max_bytes=MAX_ENVELOPE_BYTES)
    require(isinstance(snapshot, dict) and isinstance(envelope, dict),
            "v2 signed inputs must be objects")
    validate_v2_snapshot(snapshot)
    validate_with_schema(envelope, ENVELOPE_SCHEMA_V2)
    require(canonical_json(snapshot) == snapshot_bytes and canonical_json(envelope) == envelope_bytes,
            "v2 signed bytes must be canonical JSON")
    require(envelope["sequence"] == snapshot["sequence"],
            "v2 signed snapshot sequence mismatch")
    require(envelope["snapshot_digest"] == "sha256:" + hashlib.sha256(snapshot_bytes).hexdigest(),
            "v2 signed snapshot digest mismatch")
    key = public_keys.get(envelope["key_id"])
    require(isinstance(key, bytes) and len(key) == 32, "untrusted v2 signing key")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except ValueError as error:
        raise PublicationError("malformed v2 signature") from error
    require(len(signature) == 64, "malformed v2 signature length")
    ed25519_verify(key, v2_signature_message(snapshot_bytes), signature)
    return snapshot
