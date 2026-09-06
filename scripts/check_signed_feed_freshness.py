#!/usr/bin/env python3
"""Fail when an authenticated production feed is close to expiry."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.directory_publication import PublicationError, parse_timestamp, read_json, require


EXPECTED_FEEDS = frozenset({"directory", "discovery", "security"})


def check_observations(observations: list[dict[str, object]], now: datetime, minimum_remaining: timedelta) -> list[str]:
    require(now.tzinfo is not None, "current time must include a timezone")
    require(minimum_remaining > timedelta(), "minimum remaining lifetime must be positive")
    feeds = {item.get("feed") for item in observations}
    require(feeds == EXPECTED_FEEDS and len(observations) == len(EXPECTED_FEEDS), "exactly one observation per signed feed is required")
    results: list[str] = []
    for observation in sorted(observations, key=lambda item: str(item["feed"])):
        feed = str(observation["feed"])
        require(observation.get("observation_schema_version") == 2, f"{feed} observation schema is unsupported")
        observed_at = parse_timestamp(observation["observed_at"], f"{feed}.observed_at")
        expires_at = parse_timestamp(observation["expires_at"], f"{feed}.expires_at")
        require(observed_at <= now + timedelta(minutes=5), f"{feed} observation is from the future")
        remaining = expires_at - now
        require(remaining > minimum_remaining, f"{feed} expires in {remaining}; required margin is greater than {minimum_remaining}")
        results.append(f"{feed}: sequence {observation['sequence']}, expires {expires_at.isoformat()}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", action="append", required=True, type=Path)
    parser.add_argument("--minimum-hours", type=int, default=48)
    parser.add_argument("--now", help="RFC3339 time for deterministic tests")
    args = parser.parse_args()
    try:
        require(1 <= args.minimum_hours <= 168, "minimum hours must be between 1 and 168")
        now = datetime.now(timezone.utc) if args.now is None else parse_timestamp(args.now, "now")
        observations = [read_json(path, max_bytes=64 << 10) for path in args.observation]
        require(all(isinstance(item, dict) for item in observations), "observations must be JSON objects")
        for line in check_observations(observations, now, timedelta(hours=args.minimum_hours)):
            print(line)
        return 0
    except (KeyError, OSError, PublicationError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"signed-feed-freshness: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
