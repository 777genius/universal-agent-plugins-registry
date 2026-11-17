"""Fail-closed no-loss contract tests for SQL API source-bound qualification."""
from __future__ import annotations

import copy
import unittest

from scripts.skillspector_2134_sql_api_e2e import TARGET_LINE, compare, published_source_risks, PUBLISHED_RECORD_ID, SOURCE_COMMIT, SOURCE_ROOT, PUBLISHED_SOURCE_DIGEST


def report(references, issues=()):
    return {
        "analysis_completeness": {
            "status": "partial", "is_complete": False,
            "references": references, "partially_inspected_files": 0,
            "entirely_uninspected_files": 0,
        },
        "issues": list(issues),
    }


TARGET = {
    "source_path": "SKILL.md", "line": 38, "target_path": None,
    "status": "missing", "reference_kind": "quoted_or_code",
    "evidence": TARGET_LINE, "disposition": "partial",
}
OTHER = {
    "source_path": "SKILL.md", "line": 12, "target_path": None,
    "status": "missing", "reference_kind": "markdown_link",
    "evidence": "Load [real file](required.json)", "disposition": "partial",
}
SECURITY = {"id": "P2", "tags": ["security"], "location": {"file": "SKILL.md", "start_line": 20}}


class SqlSourceEvidenceTests(unittest.TestCase):
    def test_only_exact_nonsecurity_row_removed(self):
        proof = compare(report([TARGET, OTHER], [SECURITY]), report([OTHER], [SECURITY]))
        self.assertEqual(proof["false_sql_reference_removed"], 1)
        self.assertFalse(proof["safe_for_automatic_publication"])
        self.assertEqual(proof["production_partial_reduction"], 0)

    def test_removal_of_other_real_reference_fails(self):
        with self.assertRaisesRegex(ValueError, "one-row"):
            compare(report([TARGET, OTHER]), report([]))

    def test_any_missing_security_finding_fails(self):
        with self.assertRaisesRegex(ValueError, "security"):
            compare(report([TARGET], [SECURITY]), report([]))

    def test_extra_reference_fails(self):
        with self.assertRaisesRegex(ValueError, "one-row"):
            compare(report([TARGET]), report([OTHER]))

    def test_missing_target_from_original_fails(self):
        with self.assertRaisesRegex(ValueError, "one-row"):
            compare(report([OTHER]), report([OTHER]))

    def test_unsafe_promotion_fails(self):
        new = report([])
        new["analysis_completeness"].update(status="complete", is_complete=True)
        with self.assertRaisesRegex(ValueError, "Partial/Complete"):
            compare(report([TARGET]), new)

    def test_incomplete_file_count_drift_fails(self):
        new = report([])
        new["analysis_completeness"]["entirely_uninspected_files"] = 1
        with self.assertRaisesRegex(ValueError, "inspection"):
            compare(report([TARGET]), new)

    def test_incomplete_risk_location_change_fails(self):
        different = copy.deepcopy(SECURITY)
        different["location"]["start_line"] = 21
        with self.assertRaisesRegex(ValueError, "security"):
            compare(report([TARGET], [SECURITY]), report([], [different]))

    def test_original_signed_finding_absence_fails(self):
        original = {
            "id": PUBLISHED_RECORD_ID, "status": "partial", "freshness": "current",
            "findings_truncated": False, "coverage": {"grouping_complete": True},
            "source": {"revision": SOURCE_COMMIT, "path": SOURCE_ROOT,
                       "content_digest": PUBLISHED_SOURCE_DIGEST},
            "findings": [{"rule": "RP1", "severity": "MEDIUM", "path": "references/testing.md",
                          "line": 253, "raw_count": 2, "match_fingerprint": "a" * 64}],
            "raw_finding_count": 3,
        }
        report_issues = [{
            "id": "RP1", "severity": "MEDIUM",
            "location": {"file": "references/testing.md", "start_line": 253},
            "match_fingerprint": "a" * 64, "tags": ["security"],
        }]
        with self.assertRaisesRegex(ValueError, "lost a source-bound"):
            published_source_risks(original, {"issues": report_issues})
        good = published_source_risks(original, {"issues": report_issues * 2})
        self.assertEqual(good["published_signed_grouped_occurrences_preserved"], 2)
        self.assertEqual(good["published_unattributed_raw_count"], 1)



if __name__ == "__main__":
    unittest.main()
