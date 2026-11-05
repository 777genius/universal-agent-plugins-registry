#!/usr/bin/env python3
"""Authenticate unpublished nine-source candidate evidence with a separate key.

This is NOT a publication pathway. A valid signature attests to candidate
measurements only: live selection, production authorization, and old-v3 CAS
remain separate mandatory gates. Never replace a v3 record on this basis.
"""
from __future__ import annotations

import base64
from typing import Any

from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_candidate_cohort as candidate
from scripts import skillspector_reports as scanner
from scripts.build_registry import RegistryError
from scripts.directory_publication import (
    ID_RE, PublicationError, b64decode_exact, canonical_json,
    ed25519_sign, ed25519_verify, require, sha256_digest,
)

DOMAIN_NAME = "UAP-SKILLSPECTOR-UNPUBLISHED-CANDIDATE-ED25519-V1"
DOMAIN = DOMAIN_NAME.encode("ascii") + b"\x00"
MAX_PROOF_BYTES = candidate.MAX_PROOF_BYTES
MAX_ENVELOPE_BYTES = 4096
ENVELOPE_FIELDS = {
    "schema_version", "kind", "algorithm", "signature_domain",
    "candidate_digest", "key_id", "signature",
}


def validate_candidate_proof(proof: dict, previous: dict, report_commit: str) -> None:
    """Bind every newly measured record to an immutable old Partial witness."""
    require(isinstance(proof, dict) and set(proof) == {
        "schema_version", "kind", "base_report_commit", "base_manifest_digest",
        "scanner", "profile", "profile_policy_digest", "candidate_status",
        "live_selection_verified", "publication_authorized", "comparisons", "records",
    }, "candidate proof shape differs")
    require(type(proof["schema_version"]) is int and proof["schema_version"] == 1
            and proof["kind"] == "skillspector-2.13.3-nine-source-candidate",
            "candidate proof version differs")
    require(proof["base_report_commit"] == report_commit
            and proof["base_manifest_digest"] == admission.digest(previous["manifest"]),
            "candidate base report identity differs")
    require(proof["scanner"] == candidate.NEW_SCANNER
            and proof["profile"] == candidate.PROFILE
            and proof["profile_policy_digest"] == candidate.PROFILE["digest"],
            "candidate scanner or versioned profile differs")
    require(proof["candidate_status"] == "measured_complete_unpublished"
            and proof["live_selection_verified"] is False
            and proof["publication_authorized"] is False,
            "candidate proof falsely claims deployment or live selection")
    require(not scanner.has_public_credentials(proof), "candidate proof contains credential-shaped data")
    try:
        plan = admission.build_plan(previous, previous["selection"], report_commit)
        selected = plan["selection"]["sources"]
        rows, comparisons = proof["records"], proof["comparisons"]
        require(isinstance(rows, list) and isinstance(comparisons, list)
                and len(rows) == len(comparisons) == len(selected) == 9,
                "candidate proof does not contain nine records")
        for item, record, comparison in zip(selected, rows, comparisons, strict=True):
            require(isinstance(record, dict) and isinstance(comparison, dict),
                    "invalid candidate evidence entry")
            old = previous["records"][item["id"]]
            require(record["id"] == item["id"] and comparison ==
                    candidate.verify_candidate(item, old, record),
                    "candidate comparison or immutable selection differs")
    except (admission.CohortRejected, KeyError, TypeError, IndexError) as error:
        raise PublicationError("candidate evidence or prior witness differs") from error


def candidate_bytes(proof: dict, previous: dict, report_commit: str) -> bytes:
    validate_candidate_proof(proof, previous, report_commit)
    body = scanner.report_json(proof)
    require(len(body) <= MAX_PROOF_BYTES, "candidate evidence exceeds bound")
    return body


def signature_message(body: bytes) -> bytes:
    require(len(body) <= MAX_PROOF_BYTES, "candidate evidence exceeds bound")
    return DOMAIN + len(body).to_bytes(8, "big") + body


def sign_unpublished_candidate(proof: dict, previous: dict, report_commit: str,
                               key_id: str, private_seed: bytes) -> dict[str, Any]:
    """Use only in a separately authorized signer; never set a live flag."""
    require(isinstance(key_id, str) and ID_RE.fullmatch(key_id) is not None,
            "invalid candidate signing key ID")
    body = candidate_bytes(proof, previous, report_commit)
    return {
        "schema_version": 1,
        "kind": "skillspector-unpublished-candidate-envelope",
        "algorithm": "Ed25519",
        "signature_domain": DOMAIN_NAME,
        "candidate_digest": sha256_digest(body),
        "key_id": key_id,
        "signature": base64.b64encode(ed25519_sign(private_seed, signature_message(body))).decode("ascii"),
    }


def verify_signed_candidate(body: bytes, envelope_bytes: bytes, trusted_keys: dict[str, bytes],
                            previous: dict, report_commit: str) -> dict:
    """Verify exact bytes, dedicated Ed25519 trust and every old/current witness.

    The result is still unpublished evidence, never an authorized status overlay.
    """
    require(isinstance(body, bytes) and len(body) <= MAX_PROOF_BYTES,
            "candidate body exceeds bound")
    require(isinstance(envelope_bytes, bytes) and len(envelope_bytes) <= MAX_ENVELOPE_BYTES,
            "candidate envelope exceeds bound")
    try:
        proof = scanner.parse_scanner_json(body, "candidate proof")
        envelope = scanner.parse_scanner_json(envelope_bytes, "candidate signature")
    except (RegistryError, ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise PublicationError("invalid candidate JSON") from error
    require(isinstance(proof, dict) and isinstance(envelope, dict),
            "candidate proof or envelope is not an object")
    require(scanner.report_json(proof) == body,
            "candidate proof is not in canonical display JSON encoding")
    require(canonical_json(envelope) == envelope_bytes
            and set(envelope) == ENVELOPE_FIELDS,
            "candidate signature envelope differs from canonical contract")
    require(type(envelope["schema_version"]) is int and envelope["schema_version"] == 1
            and envelope["kind"] == "skillspector-unpublished-candidate-envelope"
            and envelope["algorithm"] == "Ed25519"
            and envelope["signature_domain"] == DOMAIN_NAME,
            "candidate signature protocol differs")
    require(envelope["candidate_digest"] == sha256_digest(body),
            "candidate signature digest differs")
    key_id = envelope["key_id"]
    require(isinstance(key_id, str) and ID_RE.fullmatch(key_id) is not None
            and key_id in trusted_keys and type(trusted_keys[key_id]) is bytes
            and len(trusted_keys[key_id]) == 32,
            "untrusted candidate signing key")
    signature = b64decode_exact(envelope["signature"], 64, "candidate signature")
    ed25519_verify(trusted_keys[key_id], signature_message(body), signature)
    validate_candidate_proof(proof, previous, report_commit)
    return proof
