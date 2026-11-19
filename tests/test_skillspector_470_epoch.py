"""No production retry: adversarial tests for shadow policy epoch #470."""
from __future__ import annotations

import copy
import json
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
                "scanner": {"revision": OLD_SCANNER_REVISION},
                "profiles": [copy.deepcopy(original["profile"])]}
    qualified = {"repository": repository, "revision": revision, "selected_root": path,
                 "status": "complete_acquisition", "tree_digest": "sha256:" + "a" * 64,
                 "file_count": 12, "scan_status": "partial"}
    return source_id, original, manifest, qualified


def epoch():
    source_id, original, manifest, qualified = fixture()
    return start_epoch(source_id=source_id, published_record=original,
                       signed_manifest=manifest, qualification=qualified,
                       report_commit=BASELINE_REPORT_COMMIT)


def cli_metadata():
    return {"skillspector_version": "2.13.1", "llm_requested": False, "inference_usage": []}


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
        actual = {"analysis_completeness": {"status": "partial", "is_complete": False,
                                            "execution_successful": True,
                                            "findings_before_filtering": 1,
                                            "findings_after_filtering": 1},
                  "metadata": cli_metadata(), "execution_successful": True,
                  "issues": [{"id": "E1"}], "suppressed": [], "suppressed_count": 0}
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
            ("original", {"profile": {"id": "unreviewed-profile"}}),
            ("manifest", {"profiles": []}),
            ("manifest", {"profile": {"digest": "sha256:" + "f" * 64}}),
            ("manifest", {"source_commit": "0" * 40}),
            ("qualification", {"status": "failed"}),
            ("qualification", {"tree_digest": None}),
            ("qualification", {"tree_digest": "sha256:" + "g" * 64}),
            ("qualification", {"tree_digest": "sha256:" + "A" * 64}),
            ("qualification", {"tree_digest": "sha256:" + "a" * 63 + "/"}),
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
        actual = {"analysis_completeness": {"status": "complete", "is_complete": True,
                                            "execution_successful": True,
                                            "findings_before_filtering": 0,
                                            "findings_after_filtering": 0},
                  "metadata": cli_metadata(), "execution_successful": True,
                  "issues": [], "suppressed": [], "suppressed_count": 0}
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

    def test_llm_or_unpinned_scanner_cannot_supply_shadow_observation(self):
        receipt = epoch()
        valid = {"analysis_completeness": {"status": "partial", "is_complete": False,
                                            "execution_successful": True,
                                            "findings_before_filtering": 0,
                                            "findings_after_filtering": 0},
                 "metadata": cli_metadata(), "execution_successful": True,
                 "issues": [], "suppressed": [], "suppressed_count": 0}
        for key, value in [
            ("llm_requested", True),
            ("inference_usage", [{"model": "unverified"}]),
            ("skillspector_version", "2.13.4"),
        ]:
            forged = copy.deepcopy(valid)
            forged["metadata"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "real successful"):
                record_shadow_observation(
                    receipt, source_id=receipt["source_id"],
                    revision=receipt["source_revision"],
                    tree_digest=receipt["qualified_tree_digest"], scan=forged)

    def test_security_findings_and_coverage_cannot_disappear_from_shadow_ledger(self):
        receipt = epoch()
        valid = {
            "analysis_completeness": {
                "status": "partial", "is_complete": False, "execution_successful": True,
                "findings_before_filtering": 2, "findings_after_filtering": 1,
                "ledger_exceptions": [{"reason_code": "reference_missing"}],
            },
            "metadata": cli_metadata(), "execution_successful": True,
            "issues": [{"id": "E1"}], "suppressed": [{"id": "S1"}],
            "suppressed_count": 1,
        }
        args = dict(source_id=receipt["source_id"], revision=receipt["source_revision"],
                    tree_digest=receipt["qualified_tree_digest"])
        observed = record_shadow_observation(receipt, scan=valid, **args)
        attempt = observed["new_epoch_attempts"][0]
        self.assertEqual(attempt["observed_security_issues"], valid["issues"])
        self.assertEqual(attempt["observed_suppressed_issues"], valid["suppressed"])
        self.assertEqual(attempt["observed_analysis_completeness"],
                         valid["analysis_completeness"])
        self.assertFalse(attempt["certified_complete"])
        for field, value in (
            ("issues", []), ("suppressed", []), ("suppressed_count", 0),
            ("suppressed_count", True), ("suppressed", None),
        ):
            tampered = copy.deepcopy(valid)
            tampered[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                ValueError, "inconsistent scanner finding accounting"
            ):
                record_shadow_observation(receipt, scan=tampered, **args)
        for field, value in (
            ("findings_before_filtering", 1), ("findings_before_filtering", True),
            ("findings_after_filtering", 0), ("findings_after_filtering", 2),
        ):
            tampered = copy.deepcopy(valid)
            tampered["analysis_completeness"][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                ValueError, "inconsistent scanner finding accounting"
            ):
                record_shadow_observation(receipt, scan=tampered, **args)

    def test_failed_or_inconsistent_scans_never_claim_success(self):
        receipt = epoch()
        for status, is_complete, executed in [
            ("error", False, False), ("complete", False, True),
            ("partial", True, True), ("complete_with_caveats", False, True),
        ]:
            actual = {"analysis_completeness": {"status": status,
                                                 "is_complete": is_complete,
                                                 "execution_successful": executed},
                      "metadata": cli_metadata(), "execution_successful": executed, "issues": []}
            with self.subTest(status=status), self.assertRaisesRegex(
                ValueError, "real successful"
            ):
                record_shadow_observation(
                    receipt, source_id=receipt["source_id"],
                    revision=receipt["source_revision"],
                    tree_digest=receipt["qualified_tree_digest"], scan=actual)


    def test_original_expired_artifact_log_proof_requires_all_pinned_sources(self):
        # The 7-day Actions ZIP now gives HTTP 410. Historical proof can be
        # rechecked only against the exact *successful* GitHub job log, never
        # by skipping source evidence or treating an expired ZIP as verified.
        from scripts.skillspector_470_pinned_replay_e2e import (
            EXPECTED_LOG_SOURCES, parse_original_job_log,
        )

        def make_lines(entries):
            return (
                "2026-11-12T14:37:19.4200433Z "
                + json.dumps(entries, sort_keys=True)
                + "\n"
            ).encode("utf-8")

        entries = [
            {
                "repository": repo, "revision": sha, "selected_root": root,
                "status": "complete_acquisition", "file_count": metadata[0],
                "total_bytes": metadata[1], "unicode_files": metadata[2],
                "tree_digest": metadata[3], "scan_status": metadata[4],
                "scan_issue_count": metadata[5],
            }
            for (repo, sha, root), metadata in EXPECTED_LOG_SOURCES.items()
        ]
        self.assertEqual(len(entries), 5)
        verified = parse_original_job_log(make_lines(entries))
        self.assertEqual(verified["status"], "passed")
        self.assertFalse(verified["expired_artifact_zip_reverified"])
        for name, mutation in (
            ("missing", lambda items: items.pop()),
            ("duplicate", lambda items: items.__setitem__(1, copy.deepcopy(items[0]))),
            ("source_revision", lambda items: items[0].update(revision="0" * 40)),
            ("tree_digest", lambda items: items[0].update(tree_digest="sha256:" + "0" * 64)),
            ("security_issues", lambda items: items[0].update(scan_issue_count=0)),
            ("partial_to_complete", lambda items: items[0].update(scan_status="complete")),
            ("wrong_bytes", lambda items: items[0].update(total_bytes=2)),
            ("unverified_status", lambda items: items[0].update(status="failed")),
        ):
            with self.subTest(name=name):
                changed = copy.deepcopy(entries)
                mutation(changed)
                with self.assertRaises(ValueError):
                    parse_original_job_log(make_lines(changed))
        with self.assertRaises(ValueError):
            parse_original_job_log(make_lines(entries) * 2)
        with self.assertRaises(ValueError):
            parse_original_job_log(b"2026-11-12T14:37:19Z PASSED\n")


if __name__ == "__main__":
    unittest.main()
