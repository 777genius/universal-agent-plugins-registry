"""Fail-closed coverage of unversioned, same-source retry lineage (#470)."""

from __future__ import annotations

import copy
import unittest

from scripts import skillspector_contract as contract
from scripts import skillspector_coverage_v3 as coverage
from scripts.directory_publication import PublicationError
from tests.test_skillspector_coverage_v3 import record
from tests.test_skillspector_reports import item


class RetryEpochGuardTests(unittest.TestCase):
    def setUp(self):
        self.subject = item()
        self.selection = {"schema_version": 1, "sources": [self.subject]}
        self.prior = record(self.subject, status="error")
        # Bare scanner failure fixtures have no persisted retry summary.
        # Construct the same six-field shape as retry_summary() explicitly.
        self.prior["retry"] = {
            "attempt_count": 4,
            "disposition": "exhausted",
            "reason": "transient_retry_limit",
            "next_attempt_at": None,
            "next_profile": None,
            "latest_status": "error",
        }
        self.prior["attempt_history"] = [
            {"old_signed_event": index} for index in range(8)
        ]

    def previous(self, *, policy=None):
        policy = policy or contract.LEGACY_POLICY["digest"]
        return {
            "manifest": {
                "schema_version": 3,
                "repository_aliases": [],
            },
            "selection": copy.deepcopy(self.selection),
            "records": {self.subject["id"]: copy.deepcopy(self.prior)},
            "attempts": {
                self.subject["id"]: {
                    "source_digest": coverage.source_digest(self.subject),
                    "scanner": copy.deepcopy(coverage.SCANNER),
                    "policy_digest": policy,
                    "attempt_count": 4,
                    "disposition": "exhausted",
                    "last_attempted_at": "2026-11-14T00:00:00Z",
                },
            },
            "queue_cursor": 0,
        }

    def test_same_pin_exhausted_error_cannot_be_implicitly_replayed(self):
        old = self.previous()
        self.assertNotEqual(contract.LEGACY_POLICY["digest"], coverage.PROFILE["digest"])
        self.assertEqual(coverage.compatible_attempts(old, self.selection), {})
        self.assertTrue(coverage.requires_versioned_retry_epoch(self.subject, None, self.prior))
        before = copy.deepcopy(self.prior)
        # Fail visibly instead of silently skipping an exhausted old source.
        with self.assertRaisesRegex(PublicationError, "explicit versioned epoch"):
            coverage.plan_attempts(self.selection, old, 0, 1, 1)
        with self.assertRaisesRegex(PublicationError, "explicit versioned epoch"):
            coverage.make_attempt(
                self.subject, record(self.subject, status="partial"),
                previous_attempt=None, previous_record=self.prior,
            )
        self.assertEqual(self.prior, before)
        self.assertEqual(len(self.prior["attempt_history"]), 8)

    def test_any_existing_same_pin_attempt_requires_explicit_migration(self):
        prior = copy.deepcopy(self.prior)
        prior["retry"].update(attempt_count=3, disposition="scheduled")
        self.assertTrue(coverage.requires_versioned_retry_epoch(self.subject, None, prior))
        with self.assertRaisesRegex(PublicationError, "explicit versioned epoch"):
            coverage.make_attempt(self.subject, record(self.subject), previous_record=prior)

    def test_existing_compatible_attempt_keeps_original_limit(self):
        old = self.previous(policy=coverage.PROFILE["digest"])
        attempts = coverage.compatible_attempts(old, self.selection)
        self.assertIn(self.subject["id"], attempts)
        existing = attempts[self.subject["id"]]
        self.assertFalse(coverage.requires_versioned_retry_epoch(self.subject, existing, self.prior))
        self.assertEqual(coverage.plan_attempts(self.selection, old, 0, 1, 1), [])
        with self.assertRaisesRegex(PublicationError, "attempt limit exhausted"):
            coverage.make_attempt(
                self.subject, record(self.subject),
                previous_attempt=existing, previous_record=self.prior,
            )

    def test_changed_immutable_revision_is_a_distinct_scan_identity(self):
        changed = copy.deepcopy(self.subject)
        changed["revision"] = "d" * 40
        selection = {"schema_version": 1, "sources": [changed]}
        self.assertFalse(coverage.requires_versioned_retry_epoch(changed, None, self.prior))
        self.assertEqual(
            [source["id"] for source in coverage.plan_attempts(selection, self.previous(), 0, 1, 1)],
            [changed["id"]],
        )

    def test_first_attempt_and_zero_history_are_not_blocked(self):
        self.assertFalse(coverage.requires_versioned_retry_epoch(self.subject, None, None))
        self.assertEqual(
            [source["id"] for source in coverage.plan_attempts(self.selection, None, 0, 1, 1)],
            [self.subject["id"]],
        )
        new_attempt = coverage.make_attempt(self.subject, record(self.subject))
        self.assertEqual(new_attempt["attempt_count"], 1)
        old = copy.deepcopy(self.prior)
        old["retry"]["attempt_count"] = 0
        self.assertFalse(coverage.requires_versioned_retry_epoch(self.subject, None, old))

    def test_verified_repository_alias_must_not_reset_old_attempts(self):
        # previous_records may rebind a verified renamed repository. Never
        # allow an unchanged revision and root to bypass the epoch boundary.
        aliased = copy.deepcopy(self.prior)
        aliased["source"]["repository"] = "renamed-owner/renamed-repository"
        self.assertTrue(coverage.requires_versioned_retry_epoch(self.subject, None, aliased))

    def test_changed_immutable_pin_or_source_type_is_not_blocked(self):
        for field, value in (("revision", "e" * 40), ("path", "other/SKILL.md")):
            previous = copy.deepcopy(self.prior)
            previous["source"][field] = value
            with self.subTest(field=field):
                self.assertFalse(coverage.requires_versioned_retry_epoch(
                    self.subject, None, previous
                ))
        changed = copy.deepcopy(self.prior)
        changed["kind"] = "different_kind"
        self.assertFalse(coverage.requires_versioned_retry_epoch(self.subject, None, changed))


if __name__ == "__main__":
    unittest.main()
