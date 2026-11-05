"""Offline signed Directory v2 bootstrap: exact-byte verification, no publication.

V1 signer, ledger and latest pointer are deliberately unchanged. Release
promotion uses its existing review/CAS authority after a verified v2 consumer
and actual native qualifications exist.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from datetime import timedelta
from typing import Any

from directory_publication import (
    PublicationError, b64decode_exact, canonical_json, ed25519_sign,
    ed25519_verify, format_timestamp, parse_json_bytes, parse_timestamp,
    require, validate_with_schema, ROOT, MAX_SNAPSHOT_BYTES, MAX_ENVELOPE_BYTES,
)
from directory_v2_contract import require_unique_scoped_grants

DOMAIN = b"UAP-DIRECTORY-SNAPSHOT-ED25519-V2\x00"
ENVELOPE_SCHEMA = ROOT / "schemas" / "directory-envelope-v2.schema.json"
SNAPSHOT_SCHEMA = ROOT / "schemas" / "directory-snapshot-v2.schema.json"


def signature_message_v2(snapshot: bytes) -> bytes:
    require(0 < len(snapshot) <= MAX_SNAPSHOT_BYTES, "invalid v2 snapshot size")
    return DOMAIN + len(snapshot).to_bytes(8, "big") + snapshot


def validate_v2_product_ownership(snapshot: dict[str, Any]) -> None:
    """Reject selector hijacking and cross-product distribution references."""
    products = snapshot["products"]
    distributions = {item["id"]: item for item in snapshot["distributions"]}
    selectors: dict[str, str] = {}
    for product in products:
        product_id = product["id"]
        names = [product_id, product["manifest_name"], *product["aliases"],
                 *product["reserved_aliases"]]
        for name in names:
            owner = selectors.setdefault(name, product_id)
            require(owner == product_id,
                    f"v2 selector {name!r} belongs to both {owner} and {product_id}")
        require(product["default_distribution"] in product["distributions"],
                "v2 default distribution is not owned by product")
        for distribution_id in product["distributions"]:
            target = distributions.get(distribution_id)
            require(target is not None and target["product_id"] == product_id,
                    "v2 product claims a foreign distribution")


def validate_snapshot_v2(snapshot: dict[str, Any]) -> None:
    """Check scoped identity and referenced evidence after structural schema."""
    validate_with_schema(snapshot, SNAPSHOT_SCHEMA)
    generated = parse_timestamp(snapshot["generated_at"], "generated_at")
    expires = parse_timestamp(snapshot["expires_at"], "expires_at")
    require(generated < expires <= generated + timedelta(days=30), "invalid v2 snapshot lifetime")
    require(snapshot["sequence"] >= 1, "invalid v2 sequence")
    products = {item["id"]: item for item in snapshot["products"]}
    require(len(products) == len(snapshot["products"]), "duplicate v2 products")
    distributions = {item["id"]: item for item in snapshot["distributions"]}
    require(len(distributions) == len(snapshot["distributions"]), "duplicate v2 distributions")
    validate_v2_product_ownership(snapshot)
    evidence = {item["id"]: item for item in snapshot["evidence"]}
    require(len(evidence) == len(snapshot["evidence"]), "duplicate v2 evidence")
    selected: set[str] = set()
    releases: set[tuple[str, int]] = set()
    for distribution in snapshot["distributions"]:
        require(distribution["product_id"] in products, "v2 distribution has missing product")
        product = products[distribution["product_id"]]
        require(distribution["id"] in product["distributions"], "v2 product/distribution mismatch")
        found = {release["sequence"]: release for release in distribution["releases"]}
        require(len(found) == len(distribution["releases"]), "duplicate v2 release")
        policies = {policy["release_sequence"]: policy for policy in distribution["release_policies"]}
        require(len(policies) == len(distribution["release_policies"]) and set(found) == set(policies),
                "v2 release/policy mapping differs")
        for sequence, policy in policies.items():
            release = found[sequence]
            releases.add((distribution["id"], sequence))
            require(release["manifest_name"] == product["manifest_name"],
                    "v2 manifest identity mismatch")
            require_unique_scoped_grants(policy)
            policy_floor = tuple(map(int, policy["minimum_installer_version"].split(".")))
            ids = set(policy["current_evidence"])
            for grant in policy["targets"]:
                floor = tuple(map(int, grant["minimum_installer_version"].split(".")))
                require(floor >= policy_floor, "v2 grant lowered release installer floor")
                closure = grant.get("canonical_closure")
                if closure is not None and closure["eligible"]:
                    closure_floor = tuple(map(int, closure["minimum_installer_version"].split(".")))
                    require(closure_floor >= floor, "v2 closure lowered grant installer floor")
                ids.update(grant["current_evidence"])
                if grant["scope"] == "project":
                    require(grant["client"] != "chatgpt", "ChatGPT project grant is not qualified")
                    closure = grant.get("canonical_closure")
                    # A new signed project compatibility claim needs proof for
                    # this exact client and scope, not borrowed user evidence.
                    qualified = any(
                        evidence.get(evidence_id, {}).get("client") == grant["client"]
                        and evidence[evidence_id].get("scope") == "project"
                        and evidence[evidence_id].get("level") == "runtime"
                        and evidence[evidence_id].get("outcome") == "passed"
                        and (
                            (closure is None and not evidence[evidence_id].get("closure_digest"))
                            or (closure is not None and closure["eligible"]
                                and evidence[evidence_id].get("closure_digest")
                                == closure["closure_digest"])
                        )
                        for evidence_id in grant["current_evidence"]
                    )
                    require(qualified, "v2 project grant lacks qualified scoped runtime evidence")
                    for evidence_id in grant["current_evidence"]:
                        record = evidence.get(evidence_id)
                        if record is not None and record["level"] != "schema":
                            require(record.get("client") == grant["client"]
                                    and record.get("scope") == "project",
                                    "v2 project grant borrows evidence from another client or scope")
            for item in ids:
                require(item in evidence, "v2 grant references missing evidence")
                record = evidence[item]
                require(record["distribution_id"] == distribution["id"] and
                        record["release_sequence"] == sequence and
                        record["package_tree_digest"] == release["tree_digest"],
                        "v2 grant evidence references another immutable release")
            selected.update(ids)
    require(selected == set(evidence), "v2 signed evidence is not selected by a release policy")
    for product in snapshot["products"]:
        require(set(product["distributions"]).issubset(distributions),
                "v2 product references missing distribution")
    for revoked in snapshot["revocations"]:
        require((revoked["distribution_id"], revoked["release_sequence"]) in releases,
                "v2 revocation references missing release")


def sign_snapshot_v2(snapshot: dict[str, Any], key_id: str, seed: bytes) -> tuple[bytes, bytes]:
    """Return canonical immutable bytes and detached envelope for review only."""
    validate_snapshot_v2(snapshot)
    body = canonical_json(snapshot)
    signature = ed25519_sign(seed, signature_message_v2(body))
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
    validate_with_schema(envelope, ENVELOPE_SCHEMA)
    return body, canonical_json(envelope)


def verify_snapshot_v2(
    snapshot_body: bytes, envelope_body: bytes, trusted_keys: dict[str, bytes],
) -> dict[str, Any]:
    require(0 < len(snapshot_body) <= MAX_SNAPSHOT_BYTES, "invalid v2 snapshot size")
    require(0 < len(envelope_body) <= MAX_ENVELOPE_BYTES, "invalid v2 envelope size")
    snapshot = parse_json_bytes(snapshot_body, "v2 snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    envelope = parse_json_bytes(envelope_body, "v2 envelope", max_bytes=MAX_ENVELOPE_BYTES)
    require(isinstance(snapshot, dict) and canonical_json(snapshot) == snapshot_body,
            "v2 snapshot is not canonical JSON")
    require(isinstance(envelope, dict) and canonical_json(envelope) == envelope_body,
            "v2 envelope is not canonical JSON")
    validate_snapshot_v2(snapshot)
    validate_with_schema(envelope, ENVELOPE_SCHEMA)
    require(snapshot["sequence"] == envelope["sequence"], "v2 sequence mismatch")
    digest = "sha256:" + hashlib.sha256(snapshot_body).hexdigest()
    require(digest == envelope["snapshot_digest"], "v2 snapshot digest mismatch")
    key_id = envelope["key_id"]
    require(key_id in trusted_keys, "v2 signing key is unknown")
    signature = b64decode_exact(envelope["signature"], 64, "v2 signature")
    try:
        ed25519_verify(trusted_keys[key_id], signature_message_v2(snapshot_body), signature)
    except PublicationError as error:
        raise PublicationError("invalid v2 Ed25519 signature") from error
    return copy.deepcopy(snapshot)
