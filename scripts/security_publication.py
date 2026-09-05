#!/usr/bin/env python3
"""Fail-closed publication contracts for automated package security checks."""

from __future__ import annotations

import base64
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.directory_publication import (
    PublicationError, atomic_write, b64decode_exact, canonical_json, ed25519_sign, ed25519_verify,
    load_public_keys, parse_json_bytes, parse_timestamp, read_bytes_bounded, require,
    require_integer_const, sha256_digest, validate_with_schema,
)
from scripts.sequence_boundaries import next_public_sequence


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_SCHEMA = ROOT / "schemas" / "security-snapshot.schema.json"
ENVELOPE_SCHEMA = ROOT / "schemas" / "security-envelope.schema.json"
LATEST_SCHEMA = ROOT / "schemas" / "security-latest.schema.json"
SIGNATURE_DOMAIN = b"UAP-SECURITY-INDEX-ED25519-V1\x00"
MAX_SNAPSHOT_BYTES = 8 << 20
MAX_ENVELOPE_BYTES = 16 << 10
MAX_LATEST_BYTES = 16 << 10

SignatureVerifier = Callable[[bytes, bytes, bytes], None]


def signature_message(snapshot: bytes) -> bytes:
    return SIGNATURE_DOMAIN + len(snapshot).to_bytes(8, "big") + snapshot


def validate_records(snapshot: dict[str, Any]) -> None:
    records = snapshot["records"]
    expected = sorted(records, key=lambda item: (
        item["subject"]["tree_digest"], item["subject"]["manifest_digest"],
    ))
    require(records == expected, "Security records are not canonically ordered")
    identities: set[tuple[str, str]] = set()
    checked = 0
    for record in records:
        identity = (record["subject"]["tree_digest"], record["subject"]["manifest_digest"])
        require(identity not in identities, "duplicate Security package subject")
        identities.add(identity)
        counts = record["counts"]
        require(counts["total"] == counts["blocking"] + counts["warnings"], "Security counts are inconsistent")
        if record["outcome"] == "check_unavailable":
            require(counts == {"blocking": 0, "warnings": 0, "total": 0} and record["findings"] == [],
                    "unavailable Security record contains findings")
            continue
        checked += 1
        expected_outcome = "blocking_findings" if counts["blocking"] else "warnings" if counts["warnings"] else "no_blocking_findings"
        require(record["outcome"] == expected_outcome, "Security outcome does not match counts")
        finding_order = sorted(record["findings"], key=lambda item: (
            item["disposition"], item["code"], item["path"], item.get("line", 0), item["message"],
        ))
        require(record["findings"] == finding_order, "Security findings are not canonically ordered")
        require(sum(item["disposition"] == "blocking" for item in record["findings"]) <= counts["blocking"],
                "Security blocking finding projection exceeds its count")
        require(sum(item["disposition"] == "warning" for item in record["findings"]) <= counts["warnings"],
                "Security warning finding projection exceeds its count")
    coverage = snapshot["coverage"]
    require(coverage["subjects"] == len(records), "Security coverage subject count is inconsistent")
    require(coverage["checked"] == checked, "Security coverage checked count is inconsistent")
    require(coverage["unavailable"] == len(records) - checked, "Security coverage unavailable count is inconsistent")


def validate_envelope(envelope: dict[str, Any]) -> None:
    validate_with_schema(envelope, ENVELOPE_SCHEMA)
    require_integer_const(envelope.get("envelope_schema_version"), 1, "Security envelope version is invalid")
    require(envelope.get("signature_domain") == "UAP-SECURITY-INDEX-ED25519-V1", "Security signature domain is invalid")
    b64decode_exact(envelope.get("signature"), 64, "Security signature")


def verify_bundle(snapshot_body: bytes, envelope_body: bytes, trusted_keys: Path,
                  *, signature_verifier: SignatureVerifier | None = None) -> dict[str, Any]:
    require(len(snapshot_body) <= MAX_SNAPSHOT_BYTES, "Security snapshot exceeds size limit")
    require(len(envelope_body) <= MAX_ENVELOPE_BYTES, "Security envelope exceeds size limit")
    snapshot = parse_json_bytes(snapshot_body, "Security snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    envelope = parse_json_bytes(envelope_body, "Security envelope", max_bytes=MAX_ENVELOPE_BYTES)
    require(canonical_json(snapshot) == snapshot_body, "Security snapshot is not canonical JSON")
    require(canonical_json(envelope) == envelope_body, "Security envelope is not canonical JSON")
    validate_with_schema(snapshot, SNAPSHOT_SCHEMA)
    validate_envelope(envelope)
    require(snapshot["complete"] is True, "partial Security snapshot cannot be published")
    generated = parse_timestamp(snapshot["generated_at"], "Security generated_at")
    expires = parse_timestamp(snapshot["expires_at"], "Security expires_at")
    require(generated < expires <= generated + timedelta(days=31), "Security validity interval is invalid")
    validate_records(snapshot)
    require(envelope["sequence"] == snapshot["sequence"], "Security envelope sequence mismatch")
    require(envelope["snapshot_digest"] == sha256_digest(snapshot_body), "Security snapshot digest mismatch")
    trusted = load_public_keys(trusted_keys)
    require(envelope["key_id"] in trusted, "unknown Security signing key")
    verifier = ed25519_verify if signature_verifier is None else signature_verifier
    try:
        verifier(trusted[envelope["key_id"]], signature_message(snapshot_body),
                 b64decode_exact(envelope["signature"], 64, "Security signature"))
    except PublicationError as error:
        raise PublicationError("invalid Security snapshot signature") from error
    return snapshot


def load_latest(feed: Path, trusted_keys: Path, *, signature_verifier: SignatureVerifier | None = None) -> tuple[dict[str, Any], dict[str, Any]] | None:
    latest_path = feed / "latest.json"
    if not latest_path.exists():
        return None
    latest_body = read_bytes_bounded(latest_path, MAX_LATEST_BYTES)
    latest = parse_json_bytes(latest_body, "Security latest pointer", max_bytes=MAX_LATEST_BYTES)
    require(canonical_json(latest) == latest_body, "Security latest pointer is not canonical JSON")
    validate_with_schema(latest, LATEST_SCHEMA)
    snapshot = verify_bundle(
        read_bytes_bounded(feed / latest["snapshot_path"], latest["fetch_contract"]["snapshot_max_bytes"]),
        read_bytes_bounded(feed / latest["envelope_path"], latest["fetch_contract"]["envelope_max_bytes"]),
        trusted_keys, signature_verifier=signature_verifier,
    )
    require(snapshot["sequence"] == latest["sequence"], "Security latest sequence mismatch")
    return snapshot, latest


def publish(candidate_path: Path, feed: Path, trusted_keys: Path, private_seed: bytes, key_id: str,
            publication_id: str, source_commit: str, lifetime_days: int = 30) -> dict[str, Any]:
    require(len(private_seed) == 32, "Security signing seed must be 32 bytes")
    require(1 <= lifetime_days <= 31, "Security lifetime must be between 1 and 31 days")
    candidate_body = read_bytes_bounded(candidate_path, MAX_SNAPSHOT_BYTES)
    candidate = parse_json_bytes(candidate_body, "Security candidate", max_bytes=MAX_SNAPSHOT_BYTES)
    require(canonical_json(candidate) == candidate_body, "Security candidate is not canonical JSON")
    require(set(candidate) == {"candidate_schema_version", "generated_at", "complete", "discovery", "scanner", "policy", "coverage", "records"},
            "Security candidate fields are invalid")
    require(candidate["candidate_schema_version"] == 1 and candidate["complete"] is True,
            "partial Security candidate cannot replace last-known-good")
    previous = load_latest(feed, trusted_keys)
    sequence = next_public_sequence(None if previous is None else previous[0]["sequence"])
    generated = parse_timestamp(candidate["generated_at"], "Security generated_at")
    snapshot = {
        "security_schema_version": 1,
        "sequence": sequence,
        "publication_id": publication_id,
        "source_commit": source_commit,
        "generated_at": candidate["generated_at"],
        "expires_at": (generated + timedelta(days=lifetime_days)).isoformat().replace("+00:00", "Z"),
        "complete": True,
        "discovery": candidate["discovery"],
        "scanner": candidate["scanner"],
        "policy": candidate["policy"],
        "coverage": candidate["coverage"],
        "records": candidate["records"],
    }
    snapshot_body = canonical_json(snapshot)
    validate_with_schema(snapshot, SNAPSHOT_SCHEMA)
    validate_records(snapshot)
    signature = ed25519_sign(private_seed, signature_message(snapshot_body))
    envelope = {
        "envelope_schema_version": 1, "snapshot_schema_version": 1, "sequence": sequence,
        "key_id": key_id, "algorithm": "Ed25519", "signature_domain": "UAP-SECURITY-INDEX-ED25519-V1",
        "snapshot_digest": sha256_digest(snapshot_body), "signature": base64.b64encode(signature).decode("ascii"),
    }
    envelope_body = canonical_json(envelope)
    validate_envelope(envelope)
    stem = f"{sequence:020d}"
    snapshot_path = f"snapshots/{stem}.json"
    envelope_path = f"snapshots/{stem}.envelope.json"
    latest = {
        "pointer_schema_version": 1, "snapshot_schema_version": 1, "sequence": sequence,
        "snapshot_path": snapshot_path, "envelope_path": envelope_path,
        "fetch_contract": {"max_redirects": 0, "latest_max_bytes": MAX_LATEST_BYTES,
                           "snapshot_max_bytes": MAX_SNAPSHOT_BYTES, "envelope_max_bytes": MAX_ENVELOPE_BYTES,
                           "retry_attempts": 3},
    }
    validate_with_schema(latest, LATEST_SCHEMA)
    require(not (feed / snapshot_path).exists() and not (feed / envelope_path).exists(), "Security sequence already exists")
    verify_bundle(snapshot_body, envelope_body, trusted_keys)
    atomic_write(feed / snapshot_path, snapshot_body)
    atomic_write(feed / envelope_path, envelope_body)
    atomic_write(feed / "latest.json", canonical_json(latest))
    return {"sequence": sequence, "snapshot_digest": envelope["snapshot_digest"], "record_count": len(snapshot["records"])}
