from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from scripts.check_signed_feed_freshness import check_observations
from scripts.directory_publication import PublicationError


NOW = datetime(2026, 9, 6, 0, 0, tzinfo=timezone.utc)


def observations(hours: int = 72) -> list[dict[str, object]]:
    expires = (NOW + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    observed = NOW.isoformat().replace("+00:00", "Z")
    return [
        {"observation_schema_version": 2, "feed": feed, "sequence": index, "observed_at": observed, "expires_at": expires}
        for index, feed in enumerate(("directory", "discovery", "security"), start=1)
    ]


class SignedFeedFreshnessTests(unittest.TestCase):
    def test_accepts_all_three_feeds_above_margin(self) -> None:
        self.assertEqual(len(check_observations(observations(), NOW, timedelta(hours=48))), 3)

    def test_rejects_feed_at_margin(self) -> None:
        with self.assertRaisesRegex(PublicationError, "expires in"):
            check_observations(observations(48), NOW, timedelta(hours=48))

    def test_rejects_missing_or_duplicate_feed(self) -> None:
        with self.assertRaisesRegex(PublicationError, "exactly one"):
            check_observations(observations()[:2], NOW, timedelta(hours=48))
        duplicate = observations()
        duplicate[2]["feed"] = "directory"
        with self.assertRaisesRegex(PublicationError, "exactly one"):
            check_observations(duplicate, NOW, timedelta(hours=48))


if __name__ == "__main__":
    unittest.main()
