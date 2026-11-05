#!/usr/bin/env python3
"""Separate Ed25519 contract for an eligible nine-source static-analysis release.

A signature is not an installation approval. The production signer MUST acquire
fresh source evidence through the existing signed Community/Directory readers
and must publish only via a separately guarded main-only CAS workflow.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from scripts import skillspector_candidate_signature as candidate_signature
from scripts import skillspector_candidate_cohort as candidate
from scripts import skillspector_reports as scanner
from scripts.build_registry import RegistryError
from scripts.directory_publication import (
    ID_RE, PublicationError, b64decode_exact, canonical_json,
    ed25519_public_bytes, ed25519_sign, ed25519_verify, parse_timestamp,
    require, sha256_digest,
)

DOMAIN_NAME = "UAP-SKILLSPECTOR-COHORT-RELEASE-ED25519-V1"
DOMAIN = DOMAIN_NAME.encode("ascii") + b"\x00"
RELEASE_KIND = "skillspector-cohort-release-v1"
ENVELOPE_KIND = "skillspector-cohort-release-envelope-v1"
SOURCE_KIND = "skillspector-signed-community-cohort-preflight"
MAX_RELEASE_BYTES = 2 << 20
MAX_ENVELOPE_BYTES = 4096
MAX_LIFETIME = timedelta(hours=24)
SHA = candidate.admission.SHA
DIGEST = candidate.admission.DIGEST
SNAPSHOT_FIELDS = {
    "schema_version", "kind", "source_commit", "generated_at",
    "expires_at", "candidate", "signed_sources",
}
ENVELOPE_FIELDS = {
    "schema_version", "kind", "algorithm", "signature_domain",
    "snapshot_digest", "key_id", "signature",
}
SOURCE_FIELDS = {
    "schema_version", "kind", "base_report_commit", "base_manifest_digest",
    "community", "directory", "source_pins_verified_against_fresh_signed_feeds",
    "provider_listing_verified", "candidate_scan_verified",
    "publication_authorized", "sources",
}


def validate_signed_source_join(proof: dict, signed_sources: dict) -> None:
    """Join every measured source to a separately authenticated live feed.

    This function validates the *shape and exact join*, not the Ed25519 feed
    itself. The main-only signer must compute signed_sources by calling the
    current signed-feed verifier, never accept a PR artifact as live authority.
    """
    require(isinstance(signed_sources, dict) and set(signed_sources) == SOURCE_FIELDS
            and type(signed_sources["schema_version"]) is int
            and signed_sources["schema_version"] == 1
            and signed_sources["kind"] == SOURCE_KIND
            and signed_sources["source_pins_verified_against_fresh_signed_feeds"] is True
            and signed_sources["provider_listing_verified"] is False
            and signed_sources["candidate_scan_verified"] is False
            and signed_sources["publication_authorized"] is False,
            "unverified source-pin evidence cannot qualify a release")
    require(signed_sources["base_report_commit"] == proof["base_report_commit"]
            and signed_sources["base_manifest_digest"] == proof["base_manifest_digest"],
            "candidate and live source evidence were built on different reports")
    for name in ("community", "directory"):
        identity = signed_sources[name]
        require(isinstance(identity, dict) and set(identity) ==
                {"sequence", "source_commit", "snapshot_digest"}
                and type(identity["sequence"]) is int and identity["sequence"] > 0
                and isinstance(identity["source_commit"], str)
                and SHA.fullmatch(identity["source_commit"]) is not None
                and isinstance(identity["snapshot_digest"], str)
                and DIGEST.fullmatch(identity["snapshot_digest"]) is not None,
                "signed source provenance is malformed")
    rows, pins = proof["records"], signed_sources["sources"]
    require(isinstance(rows, list) and isinstance(pins, list)
            and len(rows) == len(pins) == 9,
            "the release must contain exactly nine current source pins")
    keyed = {}
    for pin in pins:
        require(isinstance(pin, dict) and set(pin) == {
            "id", "repository", "revision", "path", "plugin_path",
            "content_digest", "signed_package_id",
            "signed_package_tree_digest", "signed_package_manifest_digest",
        }, "invalid live source-pin shape")
        require(isinstance(pin["id"], str) and pin["id"] not in keyed
                and all(isinstance(pin[k], str) for k in (
                    "repository", "revision", "path", "plugin_path",
                    "content_digest", "signed_package_id"))
                and SHA.fullmatch(pin["revision"]) is not None
                and DIGEST.fullmatch(pin["content_digest"]) is not None
                and all(DIGEST.fullmatch(pin[k]) is not None
                        for k in ("signed_package_tree_digest", "signed_package_manifest_digest")),
                "duplicate or malformed signed source pin")
        keyed[pin["id"]] = pin
    require({row["id"] for row in rows} == set(keyed),
            "release includes a source outside signed Community evidence")
    for record in rows:
        pin = keyed[record["id"]]
        source = record["source"]
        require(all(source[key] == pin[key] for key in (
                    "repository", "revision", "path", "content_digest"))
                and record["plugin_path"] == pin["plugin_path"]
                and record["id"].startswith("plugin:" + pin["signed_package_id"] + "/"),
                "release record differs from its exact signed package identity")


def build_release(
    proof: dict, signed_sources: dict, previous_dir: Path,
    source_commit: str, generated_at: str, expires_at: str,
    *, now: datetime | None = None,
) -> dict:
    """Admit an actual scanner result; do not write or sign any public feed."""
    require(isinstance(source_commit, str) and SHA.fullmatch(source_commit) is not None,
            "release source commit must be immutable")
    require(isinstance(proof, dict) and isinstance(signed_sources, dict),
            "release evidence must be JSON objects")
    candidate_signature.validate_candidate_proof(
        proof, previous_dir, proof.get("base_report_commit"))
    try:
        validate_signed_source_join(proof, signed_sources)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise PublicationError("release source identity is invalid") from error
    created = parse_timestamp(generated_at, "cohort generated_at")
    expires = parse_timestamp(expires_at, "cohort expires_at")
    current = datetime.now(timezone.utc) if now is None else now
    require(current.tzinfo is not None and created <= current + timedelta(minutes=5)
            and current < expires and timedelta(0) < expires - created <= MAX_LIFETIME,
            "release time or validity window is invalid")
    value = {
        "schema_version": 1, "kind": RELEASE_KIND,
        "source_commit": source_commit,
        "generated_at": generated_at, "expires_at": expires_at,
        "candidate": proof, "signed_sources": signed_sources,
    }
    require(len(scanner.report_json(value)) <= MAX_RELEASE_BYTES,
            "release bytes exceed the bounded signed evidence size")
    return value


def signing_message(body: bytes) -> bytes:
    """Domain-separated, length-prefixed *display JSON* bytes (floats retained)."""
    require(type(body) is bytes and len(body) <= MAX_RELEASE_BYTES,
            "release body exceeds its bound")
    return DOMAIN + len(body).to_bytes(8, "big") + body


def sign_release(
    release: dict, trusted_keys: dict[str, bytes],
    key_id: str, private_seed: bytes, previous_dir: Path,
    fresh_source_loader: Callable[[], dict] | None = None,
    *, now: datetime | None = None,
) -> dict[str, Any]:
    """Requalify all nine records *before* using the independent signer key."""
    require(isinstance(key_id, str) and ID_RE.fullmatch(key_id) is not None
            and key_id in trusted_keys
            and type(private_seed) is bytes and len(private_seed) == 32
            and type(trusted_keys[key_id]) is bytes and len(trusted_keys[key_id]) == 32
            and ed25519_public_bytes(private_seed) == trusted_keys[key_id],
            "cohort signer is not registered under the independent trust key")
    require(isinstance(release, dict) and set(release) == SNAPSHOT_FIELDS,
            "unsigned release is not an exact cohort snapshot")
    try:
        expected = build_release(
            release["candidate"], release["signed_sources"], previous_dir,
            release["source_commit"], release["generated_at"],
            release["expires_at"], now=now)
    except (KeyError, TypeError, ValueError, IndexError) as error:
        raise PublicationError("unverified cohort evidence cannot be signed") from error
    require(expected == release,
            "cohort signer refuses unverified or altered source evidence")
    # The on-disk source witness can be copied or fabricated. A privileged
    # signer must fetch and authenticate both signed feeds immediately before
    # signing and compare their exact normalized current-pins proof.
    require(callable(fresh_source_loader),
            "production cohort signing needs a fresh signed-feed verifier")
    fresh_sources = fresh_source_loader()
    require(isinstance(fresh_sources, dict)
            and len(scanner.report_json(fresh_sources)) <= MAX_RELEASE_BYTES
            and scanner.report_json(fresh_sources) ==
                scanner.report_json(release["signed_sources"]),
            "fresh signed Community/Directory pin readback differs")
    body = scanner.report_json(release)
    require(len(body) <= MAX_RELEASE_BYTES, "release exceeds signing limit")
    return {
        "schema_version": 1, "kind": ENVELOPE_KIND,
        "algorithm": "Ed25519", "signature_domain": DOMAIN_NAME,
        "snapshot_digest": sha256_digest(body), "key_id": key_id,
        "signature": base64.b64encode(
            ed25519_sign(private_seed, signing_message(body))).decode("ascii"),
    }


def verify_release(
    body: bytes, envelope_bytes: bytes,
    trusted_keys: dict[str, bytes], previous_dir: Path,
    *, now: datetime | None = None,
) -> dict:
    """Verify signed exact bytes and recompute all nine old/current joins."""
    require(type(body) is bytes and len(body) <= MAX_RELEASE_BYTES
            and type(envelope_bytes) is bytes and len(envelope_bytes) <= MAX_ENVELOPE_BYTES,
            "cohort release or envelope exceeds bounds")
    try:
        release = scanner.parse_scanner_json(body, "cohort release")
        envelope = scanner.parse_scanner_json(envelope_bytes, "cohort envelope")
    except (RegistryError, ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise PublicationError("invalid cohort JSON") from error
    require(isinstance(release, dict) and set(release) == SNAPSHOT_FIELDS
            and isinstance(envelope, dict) and set(envelope) == ENVELOPE_FIELDS,
            "cohort release or envelope contract differs")
    require(scanner.report_json(release) == body
            and canonical_json(envelope) == envelope_bytes,
            "noncanonical signed cohort JSON")
    require(type(envelope["schema_version"]) is int and envelope["schema_version"] == 1
            and envelope["kind"] == ENVELOPE_KIND
            and envelope["signature_domain"] == DOMAIN_NAME
            and envelope["algorithm"] == "Ed25519"
            and envelope["snapshot_digest"] == sha256_digest(body),
            "cohort signature protocol or digest differs")
    key_id = envelope["key_id"]
    require(isinstance(key_id, str) and ID_RE.fullmatch(key_id) is not None
            and key_id in trusted_keys
            and type(trusted_keys[key_id]) is bytes
            and len(trusted_keys[key_id]) == 32,
            "untrusted cohort publication key")
    ed25519_verify(trusted_keys[key_id], signing_message(body),
                   b64decode_exact(envelope["signature"], 64, "cohort signature"))
    require(type(release["schema_version"]) is int and release["schema_version"] == 1
            and release["kind"] == RELEASE_KIND,
            "wrong cohort release protocol")
    expected = build_release(
        release["candidate"], release["signed_sources"], previous_dir,
        release["source_commit"], release["generated_at"],
        release["expires_at"], now=now)
    require(expected == release, "signed cohort evidence was altered")
    return release
