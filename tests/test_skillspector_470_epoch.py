"""No production retry: adversarial tests for shadow policy epoch #470."""
from __future__ import annotations

import copy
import unittest

from scripts.skillspector_470_epoch import (
    BASELINE_REPORT_COMMIT, BASELINE_SOURCE_COMMIT, OLD_POLICY_DIGEST,
    OLD_SCANNER_REVISION, PINS, digest, start_epoch, record_shadow_observation,
)


def fixture():
    source_id, (repository, revision, path) = next(iter(PINS.items()))
    history = [{"status": "error", "reason": "transient_source_failure", "seq": i}
               for i in range(7)]
    history.append({"status": "error", "reason": "transient_retry_limit", "seq": 7})
    original = {
        "id": source_id, "status": "error", "freshness": "current",
        "source": {"repository": repository, "revision": revision, "path": path,
                   "content_digest": None},
        "target_revision": revision, "errors": [{"code": "acquisition_failed"}],
        "coverage": {"reasons": [{"code": "acquisition_failed"}]},
        "retry": {"attempt_count": 4, "disposition": "exhausted",
                  "reason": "transient_retry_limit", "latest_status": "error",
                  "next_attempt_at": None, "next_profile": None},
        "attempt_history": history, "findings": [],
        "scanner": {"revision": OLD_SCANNER_REVISION},
        "profile": {"id": "static-extended-v3"},
    }
    manifest = {"schema_version": 3, "source_commit": BASELINE_SOURCE_COMMIT,
                "profile": {"digest": OLD_POLICY_DIGEST},
                "scanner": {"revision": OLD_SCANNER_REVISION}}
    qualified = {"repository": repository, "revision": revision, "selected_root": path,
                 "status": "complete_acquisition", "tree_digest": "sha256:" + "a" * 64,
                 "file_count": 12, "scan_status": "partial"}
    return source_id, original, manifest, qualified


def epoch():
    source_id, original, manifest, qualified = fixture()
    return start_epoch(source_id=source_id, published_record=original,
                       signed_manifest=manifest, qualification=qualified,
                       report_commit=BASELINE_REPORT_COMMIT)


class EpochTests(unittest.TestCase):
    def test_old_history_is_separate_and_immutable(self):
        source_id, original, _, _ = fixture()
        receipt = epoch()
        self.assertEqual(receipt["original_history_digest"],
                         digest(original["attempt_history"]))
        self.assertEqual(len(receipt["original_record"]["attempt_history"]), 8)
        self.assertNotEqual(receipt["new_policy_digest"], receipt["old_policy_digest"])
        self.assertEqual(receipt["new_epoch_attempts"], [])
        self.assertEqual(receipt["production_error_reduction"], 0)
        self.assertFalse(receipt["migration_authorized"])
        original["attempt_history"].clear()
        self.assertEqual(len(receipt["original_record"]["attempt_history"]), 8)

    def test_exactly_one_shadow_observation_without_certification(self):
        receipt = epoch()
        actual = {"analysis_completeness": {"status": "partial", "is_complete": False},
                  "execution_successful": True, "issues": [{"id": "E1"}]}
        observed = record_shadow_observation(
            receipt, source_id=receipt["source_id"],
            revision=receipt["source_revision"],
            tree_digest=receipt["qualified_tree_digest"], scan=actual)
        self.assertEqual(observed["new_epoch_attempts"][0]["actual_scanner_status"], "partial")
        self.assertFalse(observed["new_epoch_attempts"][0]["certified_complete"])
        self.assertEqual(receipt["new_epoch_attempts"], [])
        with self.assertRaisesRegex(ValueError, "already consumed"):
            record_shadow_observation(
                observed, source_id=receipt["source_id"],
                revision=receipt["source_revision"],
                tree_digest=receipt["qualified_tree_digest"], scan=actual)

    def test_forgeries_of_source_policy_budget_and_old_lineage_fail(self):
        source_id, original, manifest, qualified = fixture()
        mutations = [
            ("original", {"status": "complete"}),
            ("original", {"freshness": "historical"}),
            ("original", {"target_revision": "f" * 40}),
            ("original", {"retry": {"attempt_count": 1}}),
            ("original", {"attempt_history": []}),
            ("original", {"source": {"revision": "0" * 40}}),
            ("original", {"scanner": {"revision": "0" * 40}}),
            ("manifest", {"profile": {"digest": "sha256:" + "f" * 64}}),
            ("manifest", {"source_commit": "0" * 40}),
            ("qualification", {"status": "failed"}),
            ("qualification", {"tree_digest": None}),
        ]
        for where, change in mutations:
            with self.subTest(where=where, change=change):
                a, b, c = copy.deepcopy((original, manifest, qualified))
                {"original": a, "manifest": b, "qualification": c}[where].update(change)
                with self.assertRaises(ValueError):
                    start_epoch(source_id=source_id, published_record=a,
                                signed_manifest=b, qualification=c,
                                report_commit=BASELINE_REPORT_COMMIT)

    def test_unapproved_source_and_wrong_report_fail(self):
        source_id, original, manifest, qualified = fixture()
        for supplied_id, commit in [
            ("other/unreviewed", BASELINE_REPORT_COMMIT),
            (source_id, "f" * 40),
        ]:
            with self.assertRaises(ValueError):
                start_epoch(source_id=supplied_id, published_record=original,
                            signed_manifest=manifest, qualification=qualified,
                            report_commit=commit)

    def test_shadow_tampering_or_new_tree_drift_fails(self):
        receipt = epoch()
        actual = {"analysis_completeness": {"status": "complete", "is_complete": True},
                  "execution_successful": True, "issues": []}
        for key, value in [
            ("new_policy_digest", "sha256:" + "0" * 64),
            ("original_record_digest", "sha256:" + "0" * 64),
            ("production_error_reduction", 1),
            ("migration_authorized", True),
            ("max_new_epoch_attempts", 2),
        ]:
            changed = copy.deepcopy(receipt)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                record_shadow_observation(
                    changed, source_id=receipt["source_id"],
                    revision=receipt["source_revision"],
                    tree_digest=receipt["qualified_tree_digest"], scan=actual)
        with self.assertRaisesRegex(ValueError, "source or acquired tree"):
            record_shadow_observation(
                receipt, source_id=receipt["source_id"],
                revision=receipt["source_revision"],
                tree_digest="sha256:" + "f" * 64, scan=actual)

    def test_failed_acquisition_consumes_budget_and_retains_error(self):
        receipt = epoch()
        failure = {"source_id": receipt["source_id"],
                   "source_revision": receipt["source_revision"],
                   "status": "error", "reason_code": "acquisition_failed",
                   "message": "pinned source could not be fetched"}
        observed = record_shadow_observation(
            receipt, source_id=receipt["source_id"],
            revision=receipt["source_revision"],
            tree_digest=receipt["qualified_tree_digest"],
            failed_acquisition=failure)
        self.assertEqual(observed["new_epoch_attempts"][0]["actual_scanner_status"], "error")
        self.assertFalse(observed["new_epoch_attempts"][0]["certified_complete"])
        self.assertEqual(observed["production_error_reduction"], 0)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            record_shadow_observation(
                observed, source_id=receipt["source_id"],
                revision=receipt["source_revision"],
                tree_digest=receipt["qualified_tree_digest"], failed_acquisition=failure)

    def test_forged_failed_acquisition_does_not_consume_or_certify(self):
        receipt = epoch()
        valid = {"source_id": receipt["source_id"],
                 "source_revision": receipt["source_revision"],
                 "status": "error", "reason_code": "acquisition_failed"}
        for key, value in [("source_revision", "0" * 40),
                           ("status", "complete"), ("reason_code", "complete")]:
            forged = copy.deepcopy(valid)
            forged[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "invalid failed-acquisition"
            ):
                record_shadow_observation(
                    receipt, source_id=receipt["source_id"],
                    revision=receipt["source_revision"],
                    tree_digest=receipt["qualified_tree_digest"], failed_acquisition=forged)
        with self.assertRaisesRegex(ValueError, "invalid failed-acquisition"):
            record_shadow_observation(
                receipt, source_id=receipt["source_id"],
                revision=receipt["source_revision"],
                tree_digest=receipt["qualified_tree_digest"],
                failed_acquisition=valid, scan={})

    def test_failed_or_inconsistent_scans_never_claim_success(self):
        receipt = epoch()
        for status, is_complete, executed in [
            ("error", False, False), ("complete", False, True),
            ("partial", True, True), ("complete_with_caveats", False, True),
        ]:
            actual = {"analysis_completeness": {"status": status,
                                                 "is_complete": is_complete},
                      "execution_successful": executed, "issues": []}
            with self.subTest(status=status), self.assertRaisesRegex(
                ValueError, "real successful"
            ):
                record_shadow_observation(
                    receipt, source_id=receipt["source_id"],
                    revision=receipt["source_revision"],
                    tree_digest=receipt["qualified_tree_digest"], scan=actual)


if __name__ == "__main__":
    unittest.main()
