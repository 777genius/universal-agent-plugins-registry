#!/usr/bin/env python3
"""Flag a stale Directory approval before it can silently expire Discovery.

This check is read-only. Directory approvals protect signing and publication;
an operator must review any flagged run before changing its state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Callable


REPOSITORY = "777genius/universal-agent-plugins-registry"
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
    """Select only an old first-attempt schedule/push waiting before signing."""
    if expires_at - now > minimum_remaining:
        return None
    candidates = sorted(
        (
            run for run in runs
            if run.get("status") == "waiting"
            and run.get("run_attempt") == 1
            and run.get("event") in {"schedule", "push"}
            and run.get("head_branch") == "main"
        ),
        key=lambda run: (run["created_at"], run["id"]),
    )
    for run in candidates:
        run_id = run["id"]
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
            raise ValueError("invalid Directory run ID")
        presign = [job for job in jobs_for_run(run_id) if job.get("name") == PRESIGN_JOB]
        if len(presign) != 1 or presign[0].get("status") != "waiting":
            continue
        if now - timestamp(presign[0]["created_at"]) >= approval_grace:
            return run_id
    return None


def gh_value(endpoint: str, *, raw: bool = False) -> object:
    command = ["gh", "api"]
    if raw:
        command += ["-H", "Accept: application/vnd.github.raw+json"]
    result = subprocess.run(command + [endpoint], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def gh_json(endpoint: str, *, raw: bool = False) -> dict:
    value = gh_value(endpoint, raw=raw)
    if not isinstance(value, dict):
        raise ValueError(f"GitHub response for {endpoint} was not an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=REPOSITORY)
    args = parser.parse_args()
    if args.repo != REPOSITORY or (os.environ.get("GITHUB_REPOSITORY") not in {None, args.repo}):
        raise ValueError("unexpected repository identity")

    base = f"repos/{args.repo}"
    latest = gh_json(f"{base}/contents/discovery/latest.json?ref=directory-publication-ledger", raw=True)
    snapshot_path = latest["snapshot_path"]
    if not isinstance(snapshot_path, str) or not re.fullmatch(r"snapshots/[0-9]{20}\.json", snapshot_path):
        raise ValueError("invalid Discovery snapshot path")
    snapshot = gh_json(f"{base}/contents/discovery/{snapshot_path}?ref=directory-publication-ledger", raw=True)
    now = datetime.now(timezone.utc)
    expires_at = timestamp(snapshot["expires_at"])
    if expires_at - now > timedelta(hours=60):
        print(f"Discovery is fresh until {expires_at.isoformat()}; no recovery needed")
        return 0

    runs = gh_json(f"{base}/actions/workflows/directory-publication.yml/runs?status=waiting&per_page=100")["workflow_runs"]
    if not isinstance(runs, list):
        raise ValueError("Directory workflow runs response is invalid")

    def jobs_for_run(run_id: int) -> list[dict]:
        jobs = gh_json(f"{base}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]
        if not isinstance(jobs, list):
            raise ValueError("Directory jobs response is invalid")
        return jobs

    candidate = select_unsigned_blocker(runs, jobs_for_run, now=now, expires_at=expires_at)
    if candidate is not None:
        print(f"Directory run {candidate} blocks Discovery before signing; review this pending approval now")
        return 1
    if expires_at <= now:
        print(f"Discovery expired at {expires_at.isoformat()}; no safely identifiable Directory blocker found")
        return 1
    print(f"Discovery expires at {expires_at.isoformat()}; no stale Directory approval found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
