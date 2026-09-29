from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from scripts.unblock_discovery_publication import PRESIGN_JOB, select_unsigned_blocker


NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def run(run_id: int, *, hours_old: int = 30, status: str = "waiting", attempt: int = 1) -> dict:
    return {
        "id": run_id,
        "status": status,
        "run_attempt": attempt,
        "created_at": (NOW - timedelta(hours=hours_old)).isoformat(),
    }


class DiscoveryPublicationLivenessTests(unittest.TestCase):
    def test_expiring_feed_releases_only_old_unsigned_approval(self) -> None:
        runs = [run(11, hours_old=2), run(12), run(13, hours_old=40)]
        jobs = {
            11: [{"name": PRESIGN_JOB, "status": "waiting"}],
            12: [{"name": PRESIGN_JOB, "status": "waiting"}],
            13: [{"name": "Gate the exact staged publication identity", "status": "waiting"}],
        }
        self.assertEqual(
            select_unsigned_blocker(runs, jobs.__getitem__, now=NOW, expires_at=NOW + timedelta(hours=30)),
            12,
        )

    def test_fresh_feed_does_not_inspect_or_cancel_directory(self) -> None:
        def unexpected_jobs(_run_id: int) -> list[dict]:
            self.fail("jobs should not be fetched while Discovery is fresh")

        self.assertIsNone(
            select_unsigned_blocker([run(12)], unexpected_jobs, now=NOW, expires_at=NOW + timedelta(hours=61)),
        )

    def test_signed_or_advanced_publication_is_never_canceled(self) -> None:
        for status in ("in_progress", "completed", "queued"):
            with self.subTest(status=status):
                self.assertIsNone(
                    select_unsigned_blocker(
                        [run(12, status=status)],
                        lambda _: [{"name": PRESIGN_JOB, "status": "waiting"}],
                        now=NOW,
                        expires_at=NOW,
                    )
                )
        self.assertIsNone(
            select_unsigned_blocker(
                [run(12)],
                lambda _: [{"name": PRESIGN_JOB, "status": "completed"}, {"name": "Gate the exact staged publication identity", "status": "waiting"}],
                now=NOW,
                expires_at=NOW,
            )
        )
        self.assertIsNone(
            select_unsigned_blocker(
                [run(12, attempt=2)],
                lambda _: [{"name": PRESIGN_JOB, "status": "waiting"}],
                now=NOW,
                expires_at=NOW,
            )
        )

    def test_workflow_is_schedule_only_and_outside_shared_publication_lock(self) -> None:
        from pathlib import Path

        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/discovery-publication-liveness.yml").read_text()
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("directory-publication-schema-1", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("--feed _publication-ledger/discovery", workflow)


if __name__ == "__main__":
    unittest.main()
