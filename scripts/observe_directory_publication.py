#!/usr/bin/env python3
"""Reacquire and verify one bounded production Directory publication."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.directory_publication import (
    MAX_ENVELOPE_BYTES,
    MAX_LATEST_BYTES,
    MAX_SNAPSHOT_BYTES,
    PublicationError,
    canonical_json,
    format_timestamp,
    load_public_keys,
    parse_json_bytes,
    parse_timestamp,
    read_bytes_bounded,
    require,
    sha256_digest,
    validate_latest,
    validate_snapshot_semantics,
    verify_envelope,
)
from scripts.sequence_boundaries import parse_public_sequence, require_public_sequence


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise PublicationError(f"Directory origin returned forbidden redirect HTTP {code}")


def cryptography_ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise PublicationError("cryptography is required for portable Directory verification") from error
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError) as error:
        raise PublicationError("Ed25519 signature verification failed") from error


def fetch(opener: urllib.request.OpenerDirector, url: str, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        "User-Agent": "universal-agent-plugins-directory-observer/1",
    })
    try:
        with opener.open(request, timeout=20) as response:
            if response.status != 200:
                raise PublicationError(f"Directory origin returned HTTP {response.status}")
            body = response.read(maximum + 1)
    except PublicationError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise PublicationError(f"Directory origin fetch failed: {error}") from error
    if len(body) > maximum:
        raise PublicationError(f"Directory origin response exceeds {maximum} bytes")
    return body


def observe_once(origin: str, trusted_keys: Path, minimum_sequence: int) -> dict[str, object]:
    minimum_sequence = require_public_sequence(minimum_sequence, "minimum sequence")
    opener = urllib.request.build_opener(NoRedirect())
    origin = origin.rstrip("/")
    latest_body = fetch(opener, origin + "/latest.json", MAX_LATEST_BYTES)
    latest = parse_json_bytes(latest_body, "Directory latest pointer", max_bytes=MAX_LATEST_BYTES)
    require(isinstance(latest, dict), "Directory latest pointer must be an object")
    require(canonical_json(latest) == latest_body, "Directory latest pointer is not canonical JSON")
    validate_latest(latest)
    require(latest["sequence"] >= minimum_sequence, "Directory production sequence is below the required floor")

    with tempfile.TemporaryDirectory(prefix="uap-directory-observe-") as temporary:
        feed = Path(temporary)
        snapshot_path = feed / latest["snapshot_path"]
        envelope_path = feed / latest["envelope_path"]
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_body = fetch(
            opener, origin + "/" + latest["snapshot_path"],
            latest["fetch_contract"]["snapshot_max_bytes"],
        )
        envelope_body = fetch(
            opener, origin + "/" + latest["envelope_path"],
            latest["fetch_contract"]["envelope_max_bytes"],
        )
        snapshot_path.write_bytes(snapshot_body)
        envelope_path.write_bytes(envelope_body)
        envelope = parse_json_bytes(envelope_body, "Directory envelope", max_bytes=MAX_ENVELOPE_BYTES)
        require(isinstance(envelope, dict), "Directory envelope must be an object")
        verify_envelope(
            snapshot_body, envelope, load_public_keys(trusted_keys),
            signature_verifier=cryptography_ed25519_verify,
        )
        snapshot = parse_json_bytes(snapshot_body, "Directory snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
        require(isinstance(snapshot, dict), "Directory snapshot must be an object")
        validate_snapshot_semantics(snapshot)
        require(snapshot["sequence"] == envelope["sequence"] == latest["sequence"], "Directory artifact sequence mismatch")
        now = datetime.now(timezone.utc)
        require(now >= parse_timestamp(snapshot["generated_at"], "generated_at"), "Directory snapshot is not active yet")
        require(now < parse_timestamp(snapshot["expires_at"], "expires_at"), "Directory snapshot is expired")
        return {
            "observation_schema_version": 2,
            "feed": "directory",
            "origin": origin,
            "sequence": snapshot["sequence"],
            "publication_id": snapshot["publication_id"],
            "source_commit": snapshot["source_commit"],
            "snapshot_digest": envelope["snapshot_digest"],
            "expires_at": snapshot["expires_at"],
            "observed_at": format_timestamp(now),
            "latest_digest": sha256_digest(latest_body),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--trusted-keys", required=True, type=Path)
    parser.add_argument("--minimum-sequence", required=True, type=parse_public_sequence)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--attempts", type=int, default=6)
    args = parser.parse_args()
    if not args.origin.startswith("https://") or not 1 <= args.attempts <= 6:
        print("Directory observation failed: invalid observer arguments", file=sys.stderr)
        return 2
    error: Exception | None = None
    for attempt in range(args.attempts):
        try:
            observation = observe_once(args.origin, args.trusted_keys, args.minimum_sequence)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical_json(observation))
            print(f"observed Directory sequence {observation['sequence']}")
            return 0
        except (PublicationError, OSError, ValueError, json.JSONDecodeError) as current:
            error = current
            if attempt + 1 < args.attempts:
                time.sleep(5)
    print(f"Directory observation failed after {args.attempts} attempts: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
