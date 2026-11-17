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

    def test_actual_2134_status_transition_is_only_readonly_observation(self):
        old = report([TARGET, OTHER], [copy.deepcopy(SECURITY)])
        new = report([OTHER], [copy.deepcopy(SECURITY)])
        old["analysis_completeness"].update(
            status="complete_with_caveats", is_complete=True,
            ledger_exceptions=[{
                "reason_code": "reference_missing", "path": "SKILL.md",
                "start_line": 38, "phase": "reference_resolution",
            }],
        )
        new["analysis_completeness"].update(
            status="complete", is_complete=True, ledger_exceptions=[]
        )
        for raw, stamp in ((old, "2026-11-17T21:00:22Z"), (new, "2026-11-17T21:00:25Z")):
            raw["skill"] = {"scanned_at": stamp}
            raw["issues"][0]["finding_id"] = "finding-" + ("a" if raw is old else "b") * 32
        proof = compare(old, new)
        self.assertTrue(proof["candidate_scanner_complete_is_not_certification"])
        self.assertFalse(proof["safe_for_automatic_publication"])
        self.assertEqual(proof["production_partial_reduction"], 0)
        changed = copy.deepcopy(new)
        changed["issues"][0]["severity"] = "CRITICAL"
        with self.assertRaisesRegex(ValueError, "security"):
            compare(old, changed)
        changed = copy.deepcopy(new)
        changed["analysis_completeness"]["coverage_percent"] = 80
        with self.assertRaisesRegex(ValueError, "evidence drift"):
            compare(old, changed)
        changed = copy.deepcopy(new)
        changed["analysis_completeness"]["ledger_exceptions"] = [{
            "reason_code": "static_parse_limit",
        }]
        with self.assertRaisesRegex(ValueError, "exception ledger"):
            compare(old, changed)

    def test_remaining_partial_rejects_unrelated_analyzer_drift(self):
        old = report([TARGET, OTHER], [SECURITY])
        new = report([OTHER], [SECURITY])
        new["analysis_completeness"]["analyzer_statuses"] = [
            {"analyzer_id": "static_parse", "status": "skipped"}
        ]
        with self.assertRaisesRegex(ValueError, "evidence drift"):
            compare(old, new)

    def test_remaining_partial_rejects_new_source_limitation(self):
        old = report([TARGET, OTHER], [SECURITY])
        new = report([OTHER], [SECURITY])
        new["analysis_completeness"]["ledger_exceptions"] = [
            {"reason_code": "static_parse_limit", "path": "SKILL.md"}
        ]
        with self.assertRaisesRegex(ValueError, "evidence drift"):
            compare(old, new)

    def test_incomplete_file_count_drift_fails(self):
        new = report([])
        new["analysis_completeness"]["entirely_uninspected_files"] = 1
        with self.assertRaisesRegex(ValueError, "inspected-file count drift"):
            compare(report([TARGET]), new)

    def test_incomplete_risk_location_change_fails(self):
        different = copy.deepcopy(SECURITY)
        different["location"]["start_line"] = 21
        with self.assertRaisesRegex(ValueError, "security"):
            compare(report([TARGET], [SECURITY]), report([], [different]))

    def test_original_signed_finding_absence_fails(self):
        original = {
            "id": PUBLISHED_RECORD_ID, "status": "partial", "freshness": "current",
            "findings_truncated": False, "coverage": {
                "grouping_complete": True,
                "status": "partial",
                "ledger_exceptions": [
                    {"reason_code": "reference_missing", "path": "SKILL.md"},
                    {"reason_code": "static_parse_limit", "path": "references/workers.md"},
                ],
                "original_findings": [{"id": "AE1"}],
            },
            "source": {"revision": SOURCE_COMMIT, "path": SOURCE_ROOT,
                       "content_digest": PUBLISHED_SOURCE_DIGEST},
            "findings": [{"rule": "RP1", "severity": "MEDIUM", "path": "references/testing.md",
                          "line": 253, "raw_count": 2, "match_fingerprint": "a" * 64,
                          "occurrences": [
                              {"path": "references/testing.md", "line": 253},
                              {"path": "references/testing.md", "line": 254},
                          ]}],
            "raw_finding_count": 3,
        }
        report_issues = [{
            "id": "RP1", "severity": "MEDIUM",
            "location": {"file": "references/testing.md", "start_line": 253},
            "match_fingerprint": "a" * 64, "tags": ["security"],
        }]
        with self.assertRaisesRegex(ValueError, "lost a source-bound"):
            published_source_risks(original, {"issues": report_issues})
        wrong_line = copy.deepcopy(report_issues[0])
        wrong_line["location"]["start_line"] = 254
        good = published_source_risks(original, {"issues": report_issues + [wrong_line]})
        with self.assertRaisesRegex(ValueError, "lost a source-bound"):
            published_source_risks(original, {"issues": report_issues * 2})
        incomplete = copy.deepcopy(original)
        incomplete["findings"][0].pop("occurrences")
        with self.assertRaisesRegex(ValueError, "occurrence list"):
            published_source_risks(incomplete, {"issues": report_issues + [wrong_line]})
        self.assertEqual(good["published_signed_grouped_occurrences_preserved"], 2)
        self.assertEqual(good["published_unattributed_raw_count"], 1)



if __name__ == "__main__":
    unittest.main()
