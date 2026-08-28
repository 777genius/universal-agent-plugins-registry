#!/usr/bin/env python3
"""Build or replay the canonical two-lane readiness envelope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from two_lane_evidence import (
    UAP_COMMIT, build_readiness_envelope, canonical_json, sha256_file,
    validate_completed_readiness,
)


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "tests/e2e/launch-scenarios.json"
HARNESS = ROOT / "tests/e2e/source-policy-tests.json"
OVERLAY = ROOT / "tests/e2e/source-policy-overlay.json"


def identities(uap_sha: str) -> dict[str, str]:
    return {
        "scenario_digest": sha256_file(SCENARIOS),
        "harness_digest": sha256_file(HARNESS),
        "overlay_digest": sha256_file(OVERLAY),
        "uap_sha": uap_sha,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--completed", type=Path)
    parser.add_argument("--uap-sha", default=UAP_COMMIT)
    args = parser.parse_args()
    runtime = json.loads(args.runtime.read_text())
    policy = json.loads(args.policy.read_text())
    if bool(args.output) == bool(args.completed):
        raise ValueError("select exactly one of --output or --completed")
    if args.completed:
        validate_completed_readiness(json.loads(args.completed.read_text()), runtime, policy, **identities(args.uap_sha))
    else:
        value = build_readiness_envelope(runtime, policy, **identities(args.uap_sha))
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("readiness output must not already exist")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
