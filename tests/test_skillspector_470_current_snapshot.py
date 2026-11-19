"""Fail-closed regression tests for current-vs-historical Error qualification."""
from __future__ import annotations

import copy
import unittest

from scripts.skillspector_470_current_snapshot import (
    ORIGINAL_PINS, SCANNER_REVISION, classify, git_blob_sha,
)


def fixture():
    source_id, (repo, revision, path) = next(iter(ORIGINAL_PINS.items()))
    state = {"id": source_id, "repository": repo, "path": path,
             "current": True, "selected_ids": [source_id], "state": "resolved",
             "revision": revision}
    record = {
        "id": source_id, "freshness": "current", "status": "error",
        "source": {"repository": repo, "revision": revision,
                   "path": path, "content_digest": None},
        "target_revision": revision,
        "scanner": {"revision": SCANNER_REVISION},
        "errors": [{"code": "acquisition_failed"}],
        "coverage": {"reasons": [{"code": "acquisition_failed"}]},
        "retry": {"attempt_count": 4, "disposition": "exhausted",
                  "reason": "transient_retry_limit", "next_attempt_at": None},
        "attempt_history": [{"status": "error"}] * 8,
    }
    return source_id, state, record


class CurrentAdmissionTests(unittest.TestCase):
    def test_git_blob_header_is_exact(self):
        self.assertEqual(git_blob_sha(b"hello world\n"),
                         "3b18e512dba79e4c8300dd08aeb37f8e728b8dad")

    def test_same_pin_exhausted_is_review_only(self):
        source_id, state, record = fixture()
        actual = classify(identifier=source_id, state=state, record=record)
        self.assertEqual(actual["outcome"], "same_pin_exhausted")
        self.assertTrue(actual["eligible_for_future_review"])
        self.assertFalse(actual["migration_authorized"])
        self.assertFalse(actual["safe_for_automatic_publication"])
        self.assertEqual(actual["production_error_reduction"], 0)

    def test_new_revision_partial_is_not_old_error_requalified(self):
        source_id, state, record = fixture()
        state["revision"] = "a" * 40
        record["target_revision"] = state["revision"]
        record["source"]["revision"] = state["revision"]
        record["source"]["content_digest"] = "sha256:" + "f" * 64
        record["status"] = "partial"
        actual = classify(identifier=source_id, state=state, record=record)
        self.assertEqual(actual["outcome"], "superseded_qualification")
        self.assertFalse(actual["eligible_for_future_review"])
        self.assertFalse(actual["migration_authorized"])

    def test_malformed_selection_or_record_identity_fails(self):
        source_id, state, record = fixture()
        cases = [
            ("state", "revision", "b" * 40),
            ("state", "current", False),
            ("state", "selected_ids", []),
            ("state", "state", "unresolved"),
            ("record", "freshness", "historical"),
            ("record", "target_revision", "0" * 40),
            ("record", "scanner", {"revision": "0" * 40}),
            ("record", "status", "complete"),
        ]
        for where, field, value in cases:
            with self.subTest(where=where, field=field):
                a, b = copy.deepcopy((state, record))
                {"state": a, "record": b}[where][field] = value
                with self.assertRaises(ValueError):
                    classify(identifier=source_id, state=a, record=b)

    def test_not_exhausted_or_missing_evidence_fails(self):
        source_id, state, record = fixture()
        cases = [
            ("retry", "attempt_count", 1),
            ("retry", "disposition", "scheduled"),
            ("retry", "reason", "other"),
            ("retry", "next_attempt_at", "2026-11-19T00:00:00Z"),
            ("record", "errors", []),
            ("record", "attempt_history", []),
            ("record", "coverage", {"reasons": []}),
            ("record", "source", {"repository": "imposter", "revision": state["revision"]}),
        ]
        for where, field, value in cases:
            with self.subTest(where=where, field=field):
                a = copy.deepcopy(record)
                (a["retry"] if where == "retry" else a)[field] = value
                with self.assertRaises(ValueError):
                    classify(identifier=source_id, state=state, record=a)

    def test_drift_cannot_certify_complete(self):
        source_id, state, record = fixture()
        state["revision"] = "a" * 40
        record["target_revision"] = state["revision"]
        record["source"]["revision"] = state["revision"]
        record["source"]["content_digest"] = "sha256:" + "f" * 64
        record["status"] = "complete"
        with self.assertRaisesRegex(ValueError, "must not be certified"):
            classify(identifier=source_id, state=state, record=record)


if __name__ == "__main__":
    unittest.main()
