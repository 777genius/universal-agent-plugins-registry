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
        "findings": [], "findings_truncated": False,
        "finding_group_count": 0, "finding_count": 0,
    }
    return source_id, state, record


def change_to_current_partial(state, record):
    """Distinct current revision with eight separately attested occurrences."""
    state["revision"] = "a" * 40
    record["target_revision"] = state["revision"]
    record["source"]["revision"] = state["revision"]
    record["source"]["content_digest"] = "sha256:" + "f" * 64
    record["status"] = "partial"
    record["retry"]["reason"] = "reference_missing"
    ids = [f"finding-{i:032x}" for i in range(8)]
    record["finding_count"] = 8
    record["finding_group_count"] = 1
    record["findings"] = [{
        "id": "sha256:" + "b" * 64, "rule": "RP1", "severity": "MEDIUM",
        "raw_count": 8, "finding_ids": ids,
        "occurrences": [{"finding_id": x, "path": "README.md", "line": i}
                        for i, x in enumerate(ids, 1)],
    }]


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
        change_to_current_partial(state, record)
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

    def test_security_groups_are_not_silently_dropped_or_rebound(self):
        source_id, state, record = fixture()
        change_to_current_partial(state, record)
        accepted = classify(identifier=source_id, state=state, record=record)
        self.assertEqual(accepted["original_security"]["finding_group_count"], 1)
        self.assertEqual(accepted["original_security"]["finding_occurrences"], 8)
        self.assertTrue(accepted["original_security"]["original_findings_sha256"].startswith("sha256:"))
        tampered = []
        for field, value in [
            ("findings_truncated", True),
            ("finding_count", 7),
            ("finding_group_count", 0),
            ("findings", []),
        ]:
            modified = copy.deepcopy(record)
            modified[field] = value
            tampered.append(modified)
        for change in ["duplicate", "foreign", "missing", "extra"]:
            modified = copy.deepcopy(record)
            group = modified["findings"][0]
            if change == "duplicate":
                group["occurrences"][1]["finding_id"] = group["occurrences"][0]["finding_id"]
            elif change == "foreign":
                group["finding_ids"][0] = "finding-" + "f" * 32
            elif change == "missing":
                group["occurrences"].pop()
            else:
                modified["findings"].append(copy.deepcopy(group))
                modified["finding_group_count"] = 2
                modified["finding_count"] = 16
            tampered.append(modified)
        for index, modified in enumerate(tampered):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                classify(identifier=source_id, state=state, record=modified)

    def test_drift_cannot_certify_complete(self):
        source_id, state, record = fixture()
        change_to_current_partial(state, record)
        record["status"] = "complete"
        with self.assertRaisesRegex(ValueError, "must not be certified"):
            classify(identifier=source_id, state=state, record=record)


if __name__ == "__main__":
    unittest.main()
