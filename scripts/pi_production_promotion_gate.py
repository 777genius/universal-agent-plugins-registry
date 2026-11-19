#!/usr/bin/env python3
"""Fail closed on Pi production promotion until a signed saved E2E gate exists.

This is a temporary *denial* boundary, not a production acceptance harness.
No candidate-supplied claims or environment variables can authorize Pi here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
PI_GATE_REASON = (
    "Pi-bearing Directory promotion is not authorized: missing independently "
    "authenticated 72/72 production signed saved User/Project lifecycle E2E "
    "on Linux/macOS/Windows and protected owner approval (issue #479)"
)


class PromotionDenied(ValueError):
    pass


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PromotionDenied("duplicate JSON object key")
        result[key] = value
    return result


def require_pi_free_snapshot(snapshot: object, expected_sequence: int) -> None:
    if not isinstance(snapshot, dict) or type(snapshot.get("sequence")) is not int:
        raise PromotionDenied("signed snapshot is not a valid sequence-bearing object")
    if snapshot["sequence"] != expected_sequence:
        raise PromotionDenied("signed snapshot sequence differs from exact staged publication")
    distributions, evidence = snapshot.get("distributions"), snapshot.get("evidence")
    if not isinstance(distributions, list) or not isinstance(evidence, list):
        raise PromotionDenied("signed snapshot lacks distribution or evidence arrays")
    for distribution in distributions:
        if not isinstance(distribution, dict) or not isinstance(distribution.get("release_policies"), list):
            raise PromotionDenied("malformed signed release policies")
        for policy in distribution["release_policies"]:
            if not isinstance(policy, dict) or not isinstance(policy.get("targets"), list):
                raise PromotionDenied("malformed signed release targets")
            for target in policy["targets"]:
                if not isinstance(target, dict) or not isinstance(target.get("client"), str):
                    raise PromotionDenied("malformed signed target client")
                if target["client"] == "pi":
                    raise PromotionDenied(PI_GATE_REASON)
    for record in evidence:
        if not isinstance(record, dict) or not isinstance(record.get("client"), str):
            raise PromotionDenied("malformed signed evidence client")
        if record["client"] == "pi":
            raise PromotionDenied(PI_GATE_REASON)


def require_pi_free_ledger(ledger: Path, sequence_arg: str) -> None:
    if re.fullmatch(r"[1-9][0-9]{0,19}", sequence_arg) is None:
        raise PromotionDenied("expected sequence must be a nonzero 20-digit maximum integer")
    sequence = int(sequence_arg)
    if sequence >= 10**20:
        raise PromotionDenied("expected sequence exceeds fixed publication width")
    if ledger.is_symlink():
        raise PromotionDenied("staged ledger path is a symlink")
    path = ledger
    for component in ("registry", "schemas", "1", "snapshots", f"{sequence:020d}.json"):
        path = path / component
        if path.is_symlink():
            raise PromotionDenied("staged signed snapshot path contains a symlink")
    if not path.is_file():
        raise PromotionDenied("exact staged signed snapshot is missing")
    data = path.read_bytes()
    if not 0 < len(data) <= MAX_SNAPSHOT_BYTES:
        raise PromotionDenied("exact staged signed snapshot size is invalid")
    try:
        snapshot = json.loads(
            data,
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PromotionDenied("non-JSON numeric constant")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PromotionDenied("exact staged signed snapshot is invalid JSON") from error
    require_pi_free_snapshot(snapshot, sequence)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--sequence", required=True)
    args = parser.parse_args()
    try:
        require_pi_free_ledger(args.ledger, args.sequence)
    except (OSError, PromotionDenied) as error:
        print(f"production promotion denied: {error}", file=sys.stderr)
        return 1
    print("verified: staged signed Directory contains no Pi targets or Pi evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
