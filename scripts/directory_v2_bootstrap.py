"""Prepare a signed-v1-derived user-only Directory v2 bootstrap in memory.

This preview has no feed, signing-key or CAS side effects. An actual v2
publication still requires the existing reviewed publisher's ledger authority.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

from directory_publication import (
    MAX_ENVELOPE_BYTES, MAX_SNAPSHOT_BYTES, PublicationError, canonical_json,
    format_timestamp, parse_json_bytes, parse_timestamp, require,
    validate_snapshot_semantics, verify_envelope,
)
from directory_v2_contract import legacy_user_v2_distribution
from directory_v2_signing import validate_snapshot_v2


def prepare_v2_user_bootstrap(
    snapshot_bytes: bytes,
    envelope_bytes: bytes,
    keys: dict[str, bytes],
    *,
    at: datetime,
    installer_version: str,
    publication_id: str,
    source_commit: str,
) -> dict[str, Any]:
    """Rebind reviewed v1 immutable releases to a fresh v2 user-only sequence 1.

    This does not publish or sign anything and may never mint project grants.
    Caller must separately authorize a signed v2 ledger initialization.
    """
    source = parse_json_bytes(snapshot_bytes, "v1 snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    envelope = parse_json_bytes(envelope_bytes, "v1 envelope", max_bytes=MAX_ENVELOPE_BYTES)
    require(isinstance(source, dict) and isinstance(envelope, dict),
            "v1 signed inputs must be JSON objects")
    require(canonical_json(envelope) == envelope_bytes, "v1 envelope must be canonical")
    verify_envelope(snapshot_bytes, envelope, keys)
    validate_snapshot_semantics(source)
    require(source["sequence"] == envelope["sequence"], "v1 signed sequence differs")
    require(at.tzinfo is not None and at.utcoffset() == timedelta(0),
            "reviewed v2 bootstrap time must be UTC")
    current = at.astimezone(timezone.utc).replace(microsecond=0)
    require(parse_timestamp(source["generated_at"], "v1 generated_at") <= current <
            parse_timestamp(source["expires_at"], "v1 expires_at"),
            "v2 bootstrap cannot borrow expired or future-dated v1 grants")

    projected = copy.deepcopy(source)
    projected["snapshot_schema_version"] = 2
    projected["sequence"] = 1  # Independent protocol high-water domain.
    projected["publication_id"] = publication_id
    projected["source_commit"] = source_commit
    projected["generated_at"] = format_timestamp(current)
    projected["expires_at"] = format_timestamp(current + timedelta(days=30))
    projected["distributions"] = [
        legacy_user_v2_distribution(item, installer_version)
        for item in source["distributions"]
    ]
    validate_snapshot_v2(projected)
    return projected
