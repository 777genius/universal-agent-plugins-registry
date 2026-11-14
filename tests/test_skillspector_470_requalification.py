"""Negative proof that #470's read-only cohort boundary cannot silently retry."""
from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import skillspector_470_requalification as proof
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_contract as contract
from scripts.directory_publication import PublicationError


class RequalificationBoundary(unittest.TestCase):
    def fixture(self):
        sources = [
            {"id": r + "/" + p, "kind": "standalone_skill", "repository": r,
             "revision": s, "path": p, "plugin_path": None}
            for r, s, p in proof.COHORT
        ]
        records, attempts = {}, {}
        for source in sources:
            history = [{"at": "2026-11-13T00:00:00Z", "profile": {}, "status": "error",
                        "fingerprint": "a", "reason": "transient_source_failure"}] * 3 + [
                       {"at": "2026-11-14T00:00:00Z", "profile": {}, "status": "error",
                        "fingerprint": "b", "reason": "transient_retry_limit"}]
            attempt = {
                "id": source["id"], "source_digest": coverage.source_digest(source),
                "scanner": copy.deepcopy(coverage.SCANNER),
                "policy_digest": contract.PROFILE["digest"], "profile": {"id": "standard"},
                "status": "error", "attempt_count": 4, "disposition": "exhausted",
                "reason": "transient_retry_limit", "next_attempt_at": None,
                "next_profile": None, "history": history,
            }
            record = {
                "id": source["id"], "freshness": "current", "status": "error",
                "source": {"repository": source["repository"], "revision": source["revision"],
                           "path": source["path"], "content_digest": None},
                "target_revision": source["revision"], "scanner": copy.deepcopy(coverage.SCANNER),
                "profile": copy.deepcopy(attempt["profile"]),
                "errors": [{"code": "acquisition_failed"}], "coverage": {"reasons": []},
                "attempt_history": copy.deepcopy(history), "retry": coverage.retry_summary(attempt),
                "report_digest": "sha256:" + "a" * 64,
                "findings": [], "finding_count": 0, "findings_truncated": False,
            }
            records[source["id"]] = record
            attempts[source["id"]] = attempt
        return {
            "manifest": {"schema_version": 3, "source_commit": proof.BASELINE_SOURCE_COMMIT,
                         "scanner": copy.deepcopy(coverage.SCANNER),
                         "profile": copy.deepcopy(coverage.PROFILE),
                         "profiles": [{"id": "standard"}]},
            "selection": {"sources": sources}, "records": records, "attempts": attempts,
        }

    def test_checkout_must_be_clean_and_exact_immutable_git_head(self):
        from scripts.directory_publication import PublicationError
        good = type("Proc", (), {"stdout": proof.BASELINE_REPORT_COMMIT + "\n"})()
        clean = type("Proc", (), {"stdout": ""})()
        wrong = type("Proc", (), {"stdout": "f" * 40})()
        dirty = type("Proc", (), {"stdout": " M reports/skillspector/v3/index.json"})()
        with patch.object(proof.subprocess, "run", side_effect=[good, clean]) as run:
            proof.verify_checkout(Path("/checked-out-report"))
            self.assertEqual(run.call_count, 2)
        with patch.object(proof.subprocess, "run", return_value=wrong):
            with self.assertRaises(PublicationError):
                proof.verify_checkout(Path("/checked-out-report"))
        with patch.object(proof.subprocess, "run", side_effect=[good, dirty]):
            with self.assertRaises(PublicationError):
                proof.verify_checkout(Path("/checked-out-report"))

    def test_proof_preserves_original_evidence_and_never_authorizes_retry(self):
        bundle = self.fixture()
        unchanged = copy.deepcopy(bundle)
        result = proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)
        self.assertEqual(result["cohort_size"], 2)
        self.assertEqual(result["production_error_reduction"], 0)
        self.assertFalse(result["ready_for_auto_promotion"])
        self.assertTrue(all(not x["new_attempt_authorized"] and not x["candidate_complete"]
                            for x in result["receipts"]))
        self.assertEqual(bundle, unchanged)

    def test_wrong_report_commit_scanner_or_policy_fails_closed(self):
        with self.assertRaises(PublicationError):
            proof.qualify(self.fixture(), report_commit="f" * 40)
        for field in ("source_commit", "profile", "scanner"):
            with self.subTest(field=field):
                bundle = self.fixture()
                bundle["manifest"][field] = "unreviewed"
                with self.assertRaises(PublicationError):
                    proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)

    def test_selection_source_freshness_and_error_provenance_must_match(self):
        for location, field, value in (
            ("selection", "revision", "f" * 40),
            ("record", "status", "partial"),
            ("record", "freshness", "historical"),
            ("record_source", "content_digest", "sha256:" + "f" * 64),
            ("record_source", "path", "different"),
        ):
            with self.subTest(location=location, field=field):
                bundle = self.fixture()
                source = bundle["selection"]["sources"][0]
                target = (source if location == "selection" else
                          bundle["records"][source["id"]] if location == "record" else
                          bundle["records"][source["id"]]["source"])
                target[field] = value
                with self.assertRaises(PublicationError):
                    proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)

    def test_malformed_old_attempt_never_qualifies(self):
        for field, value in (
            ("attempt_count", 1),
            ("disposition", "scheduled"),
            ("reason", "recovery_conflict_attempt_limit"),
            ("policy_digest", "sha256:" + "1" * 64),
            ("source_digest", "sha256:" + "2" * 64),
            ("next_attempt_at", "2026-11-14T00:00:00Z"),
        ):
            with self.subTest(field=field):
                bundle = self.fixture()
                identifier = bundle["selection"]["sources"][0]["id"]
                bundle["attempts"][identifier][field] = value
                with self.assertRaises(PublicationError):
                    proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)
        bundle = self.fixture()
        identifier = bundle["selection"]["sources"][0]["id"]
        bundle["records"][identifier]["errors"] = [{"code": "input_limit_exceeded"}]
        with self.assertRaises(PublicationError):
            proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)

    def test_missing_or_conflicting_history_and_duplicate_pin_fail(self):
        bundle = self.fixture()
        identifier = bundle["selection"]["sources"][0]["id"]
        bundle["attempts"][identifier]["history"].pop()
        with self.assertRaises(PublicationError):
            proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)
        bundle = self.fixture()
        del bundle["attempts"][identifier]
        with self.assertRaises(PublicationError):
            proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)
        bundle = self.fixture()
        bundle["selection"]["sources"].append(copy.deepcopy(bundle["selection"]["sources"][0]))
        with self.assertRaises(PublicationError):
            proof.qualify(bundle, report_commit=proof.BASELINE_REPORT_COMMIT)


if __name__ == "__main__":
    unittest.main()
