"""Separate scanner identity and immutable result admission tests."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts import skillspector_candidate_cohort as candidate
from scripts import skillspector_reports as scanner
from tests.test_bounded_cohort import BoundedCohortTests
from tests.test_skillspector_reports import upstream_report
from scripts.directory_publication import PublicationError


class CandidateCohortTests(unittest.TestCase):
    def fixture(self):
        previous, selection = BoundedCohortTests.fixture()
        item = selection["sources"][0]
        old = previous["records"][item["id"]]
        # The stage-one historical witness fixture intentionally uses only its
        # admission fields; stage-two tests require full v3 selection identity.
        old["kind"] = item["kind"]
        old["plugin_path"] = item["plugin_path"]
        old["finding_count"] = 0
        old["findings"] = []
        new = {
            "id": old["id"], "kind": item["kind"], "plugin_path": item["plugin_path"],
            "source": copy.deepcopy(old["source"]),
            "scanner": copy.deepcopy(candidate.NEW_SCANNER),
            "profile": copy.deepcopy(candidate.PROFILE),
            "status": "complete", "errors": [], "findings_truncated": False,
            "raw_finding_count": 0, "finding_count": 0, "finding_group_count": 0,
            "findings": [],
            "execution": {"state": "completed", "exit_code": 0},
            "coverage": {"status": "complete", "fully_inspected_files": 1,
                         "partially_inspected_files": 0, "entirely_uninspected_files": 0,
                         "grouping_complete": True, "reference_evidence_truncated": False,
                         "references_total": 0, "references": [], "reasons": [],
                         "ledger_exceptions_total": 0,
                         "ledger_exceptions": []},
        }
        return item, old, new

    def test_new_profile_identity_is_separate_from_current_v3(self):
        self.assertNotEqual(candidate.NEW_SCANNER, scanner.SCANNER)
        self.assertNotIn(candidate.PROFILE["id"], scanner.PROFILES)
        self.assertNotEqual(candidate.PROFILE, scanner.STANDARD_PROFILE)
        self.assertIsNone(candidate.PROFILE_DOCUMENT["exception_set_digest"])

    def test_measured_complete_preserves_content_findings(self):
        item, old, new = self.fixture()
        proof = candidate.verify_candidate(item, old, new)
        self.assertEqual(proof["candidate_exit_code"], 0)
        self.assertFalse(proof["findings_changed"])
        self.assertEqual(proof["source_digest"], old["source"]["content_digest"])

    def test_risk_exit_one_does_not_hide_findings(self):
        item, old, new = self.fixture()
        finding = {"rule": "E4", "severity": "HIGH", "path": "SKILL.md", "line": 7}
        old.update(findings=[finding], finding_count=1)
        new.update(findings=[finding], finding_count=1, raw_finding_count=1,
                   finding_group_count=1)
        new["execution"]["exit_code"] = 1
        proof = candidate.verify_candidate(item, old, new)
        self.assertFalse(proof["findings_changed"])
        self.assertEqual(new["findings"], [finding])

    def test_changed_source_and_uninspected_files_fail(self):
        item, old, new = self.fixture()
        new["source"]["content_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)
        item, old, new = self.fixture()
        new["coverage"]["partially_inspected_files"] = 1
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)

    def test_nonempty_incomplete_reason_and_truncated_reference_totals_fail(self):
        item, old, new = self.fixture()
        new["coverage"]["reasons"] = [{"code": "osv_timeout", "message": "incomplete"}]
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)
        item, old, new = self.fixture()
        new["coverage"]["references_total"] = 1
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)

    def test_unresolved_link_and_ledger_fail(self):
        item, old, new = self.fixture()
        new["coverage"]["references"] = [{"status": "rejected", "disposition": "partial"}]
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)
        item, old, new = self.fixture()
        new["coverage"]["ledger_exceptions_total"] = 1
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)

    def test_changed_findings_are_reported_not_suppressed(self):
        item, old, new = self.fixture()
        new.update(findings=[{"rule": "MP3", "severity": "HIGH", "path": "SKILL.md"}],
                   finding_count=1, raw_finding_count=1, finding_group_count=1)
        proof = candidate.verify_candidate(item, old, new)
        self.assertTrue(proof["findings_changed"])
        self.assertEqual(new["findings"][0]["rule"], "MP3")

    def test_pinned_new_version_requires_explicit_identity(self):
        raw = upstream_report()
        raw["metadata"]["skillspector_version"] = "2.13.3"
        record = scanner.empty_record_v3(BoundedCohortTests.fixture()[1]["sources"][0])
        record["scanner"] = copy.deepcopy(candidate.NEW_SCANNER)
        record["profile"] = copy.deepcopy(candidate.PROFILE)
        record["source"]["content_digest"] = "sha256:" + "a" * 64
        record["scanned_at"] = scanner.now()
        body = json.dumps(raw).encode()
        with self.assertRaises(PublicationError):
            scanner.normalize_report_v3(copy.deepcopy(record), body, 0, Path("/tmp/content"))
        normalized = scanner.normalize_report_v3(
            record, body, 0, Path("/tmp/content"), scanner_identity=candidate.NEW_SCANNER,
        )
        self.assertEqual(normalized["scanner"], candidate.NEW_SCANNER)
        self.assertEqual(normalized["profile"], candidate.PROFILE)
        self.assertEqual(normalized["coverage"]["status"], "complete")


if __name__ == "__main__":
    unittest.main()
