"""Early stale-main rejection before signing work, without weakening final CAS."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from scripts import skillspector_cohort_publish_cli as cli
from scripts.directory_publication import PublicationError

EXPECTED_MAIN = "a" * 40
ADVANCED_MAIN = "b" * 40


def github_at(sha: str | None) -> mock.Mock:
    github = mock.Mock()
    github.request.return_value = (
        {"object": {"sha": sha}} if sha is not None else None
    )
    return github


class CohortSignerMainLeaseTests(unittest.TestCase):
    def test_exact_main_accepted_read_only(self):
        github = github_at(EXPECTED_MAIN)
        cli.require_fresh_main(github, EXPECTED_MAIN)
        github.request.assert_called_once_with("GET", "git/ref/heads/main")

    def test_stale_or_missing_main_is_rejected(self):
        for live in (ADVANCED_MAIN, None, "not-a-commit"):
            with self.subTest(live=live):
                github = github_at(live)
                with self.assertRaises(PublicationError):
                    cli.require_fresh_main(github, EXPECTED_MAIN)
                github.request.assert_called_once_with("GET", "git/ref/heads/main")

    def test_invalid_expected_commit_rejected_before_github_call(self):
        github = github_at(EXPECTED_MAIN)
        for bad in ("", "0" * 39, "z" * 40, None):
            with self.subTest(bad=bad), self.assertRaises(PublicationError):
                cli.require_fresh_main(github, bad)
        github.request.assert_not_called()

    def test_obsolete_run_never_loads_signing_key_or_published_sources(self):
        github = github_at(ADVANCED_MAIN)
        with (
            mock.patch.object(cli, "GitHub", return_value=github),
            mock.patch.object(cli, "load_public_keys", return_value={"reviewed": b"k"}),
            mock.patch.object(cli, "ed25519_private_key") as parse_seed,
            mock.patch.object(cli.old_publisher, "previous") as previous,
            mock.patch.object(cli, "authenticated_fresh_sources") as live_sources,
            mock.patch.object(cli.protocol, "sign_release") as sign,
            mock.patch.object(cli.publisher, "publish") as publish,
        ):
            with self.assertRaisesRegex(
                PublicationError, "main advanced since signed cohort qualification"
            ):
                cli.publish_one(Path("nonexistent-candidate.json"), "token", "seed",
                                "reviewed", EXPECTED_MAIN)
        parse_seed.assert_not_called()
        previous.assert_not_called()
        live_sources.assert_not_called()
        sign.assert_not_called()
        publish.assert_not_called()
        github.request.assert_called_once_with("GET", "git/ref/heads/main")


if __name__ == "__main__":
    unittest.main()
