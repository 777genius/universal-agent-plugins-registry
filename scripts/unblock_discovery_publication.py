#!/usr/bin/env python3
"""Unblock expiring Discovery when an unsigned Directory approval is abandoned."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


PRESIGN_JOB = "Authenticate staged publication or append a signed sequence"


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def select_unsigned_blocker(
    runs: list[dict],
    jobs_for_run: Callable[[int], list[dict]],
    *,
    now: datetime,
    expires_at: datetime,
    minimum_remaining: timedelta = timedelta(hours=60),
    approval_grace: timedelta = timedelta(hours=6),
) -> int | None:
    """Return only an old, first-attempt, still-waiting pre-sign Directory run.

    Discovery expires after 72 hours and refreshes every 6 hours. The 60-hour
    threshold leaves room for one grace period and one subsequent scan.
    """
    if expires_at - now > minimum_remaining:
        return None
    candidates = sorted(
        (
            run for run in runs
            if run.get("status") == "waiting" and run.get("run_attempt") == 1
        ),
        key=lambda run: (run["created_at"], run["id"]),
    )
    for run in candidates:
        run_id = run["id"]
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
            raise ValueError("invalid Directory run ID")
        if now - timestamp(run["created_at"]) < approval_grace:
            continue
        jobs = jobs_for_run(run_id)
        presign = [job for job in jobs if job.get("name") == PRESIGN_JOB]
        if len(presign) == 1 and presign[0].get("status") == "waiting":
            return run_id
    return None


def gh_json(endpoint: str) -> dict:
    result = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True, text=True)
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"GitHub response for {endpoint} was not an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--feed", required=True, type=Path)
    args = parser.parse_args()
    if args.repo != os.environ.get("GITHUB_REPOSITORY"):
        raise ValueError("repository must match the running workflow")

    feed = args.feed.resolve()
    latest = json.loads((feed / "latest.json").read_text())
    snapshot_path = latest["snapshot_path"]
    if not isinstance(snapshot_path, str) or not re.fullmatch(r"snapshots/[0-9]{20}\.json", snapshot_path):
        raise ValueError("invalid Discovery snapshot path")
    snapshot = json.loads((feed / snapshot_path).read_text())
    now = datetime.now(timezone.utc)
    expires_at = timestamp(snapshot["expires_at"])
    if expires_at - now > timedelta(hours=60):
        print(f"Discovery is fresh until {expires_at.isoformat()}; no recovery needed")
        return 0

    repo = args.repo
    runs = gh_json(f"repos/{repo}/actions/workflows/directory-publication.yml/runs?status=waiting&per_page=100")["workflow_runs"]
    if not isinstance(runs, list):
        raise ValueError("Directory workflow runs response is invalid")

    def jobs_for_run(run_id: int) -> list[dict]:
        jobs = gh_json(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]
        if not isinstance(jobs, list):
            raise ValueError("Directory jobs response is invalid")
        return jobs

    candidate = select_unsigned_blocker(runs, jobs_for_run, now=now, expires_at=expires_at)
    if candidate is None:
        print("Discovery needs refresh; no old unsigned Directory approval blocks publication")
        return 0

    # An approval may have arrived between listing and cancellation. Re-read
    # both the run and its job immediately before touching the workflow.
    current = gh_json(f"repos/{repo}/actions/runs/{candidate}")
    if select_unsigned_blocker([current], jobs_for_run, now=now, expires_at=expires_at) != candidate:
        print(f"Directory run {candidate} advanced; leaving it untouched")
        return 0
    subprocess.run(["gh", "run", "cancel", str(candidate), "--repo", repo], check=True)
    print(f"Canceled unsigned Directory approval {candidate}; the next scheduled Discovery refresh can run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
