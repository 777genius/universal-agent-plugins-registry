from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.recover_discovery_publication import PRESIGN_JOB, pending_directory_environment, select_unsigned_blocker


NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def run(run_id: int, *, event: str = "schedule", attempt: int = 1, status: str = "waiting") -> dict:
    return {
        "id": run_id,
        "status": status,
        "event": event,
        "run_attempt": attempt,
        "head_branch": "main",
        "created_at": (NOW - timedelta(days=1)).isoformat(),
    }


def approval(*, hours_old: int = 7, status: str = "waiting") -> list[dict]:
    return [{"name": PRESIGN_JOB, "status": status, "created_at": (NOW - timedelta(hours=hours_old)).isoformat()}]


class DiscoveryPublicationLivenessTests(unittest.TestCase):
    def test_expiring_feed_selects_only_old_unsigned_approval(self) -> None:
        runs = [run(11), run(12), run(13)]
        jobs = {11: approval(hours_old=2), 12: approval(), 13: [{"name": "Gate staged publication", "status": "waiting"}]}
        self.assertEqual(
            select_unsigned_blocker(runs, jobs.__getitem__, now=NOW, expires_at=NOW + timedelta(hours=30)),
            12,
        )

    def test_fresh_feed_never_inspects_workflow_jobs(self) -> None:
        def unexpected_jobs(_run_id: int) -> list[dict]:
            self.fail("jobs should not be fetched while Discovery is fresh")

        self.assertIsNone(
            select_unsigned_blocker([run(12)], unexpected_jobs, now=NOW, expires_at=NOW + timedelta(hours=61)),
        )

    def test_signed_resume_or_advanced_run_is_never_selected(self) -> None:
        for candidate in (run(12, event="workflow_dispatch"), run(12, attempt=2), run(12, status="in_progress")):
            with self.subTest(candidate=candidate):
                self.assertIsNone(select_unsigned_blocker([candidate], lambda _: approval(), now=NOW, expires_at=NOW))
        self.assertIsNone(
            select_unsigned_blocker([run(12)], lambda _: approval(status="completed"), now=NOW, expires_at=NOW),
        )

    def test_grace_starts_when_job_waits_not_when_workflow_was_created(self) -> None:
        self.assertIsNone(
            select_unsigned_blocker([run(12)], lambda _: approval(hours_old=1), now=NOW, expires_at=NOW),
        )

    def test_only_exact_pending_directory_environment_can_be_rejected(self) -> None:
        self.assertEqual(
            pending_directory_environment([
                {"environment": {"name": "github-pages", "id": 1}},
                {"environment": {"name": "directory-publication", "id": 42}},
            ]),
            42,
        )
        self.assertIsNone(pending_directory_environment([{"environment": {"name": "github-pages", "id": 1}}]))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            pending_directory_environment([
                {"environment": {"name": "directory-publication", "id": 42}},
                {"environment": {"name": "directory-publication", "id": 43}},
            ])
        with self.assertRaisesRegex(ValueError, "invalid"):
            pending_directory_environment([{"environment": {"name": "directory-publication", "id": True}}])

    def test_ci_is_read_only_and_outside_shared_publication_lock(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/discovery-publication-liveness.yml").read_text()
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("actions: write", workflow)
        self.assertNotIn("directory-publication-schema-1", workflow)
        self.assertIn("actions: read", workflow)


if __name__ == "__main__":
    unittest.main()
