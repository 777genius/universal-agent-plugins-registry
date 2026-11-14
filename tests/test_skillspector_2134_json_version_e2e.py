"""Negative tests for the read-only exact-source JSON VERSION comparator."""
from __future__ import annotations

import copy
import unittest

from scripts import skillspector_2134_json_version_e2e as proof


class ExactReferenceDifferenceTests(unittest.TestCase):
    def fixtures(self):
        meta = {"source_path": "SKILL.md", "line": 153, "column": 12,
                "status": "missing", "reference_kind": "quoted_or_code",
                "target_path": None, "disposition": "partial",
                "evidence": '"VERSION": "1.0.0",'}
        real = {"source_path": "SKILL.md", "line": 154, "column": 12,
                "status": "missing", "reference_kind": "inline_command",
                "target_path": None, "disposition": "partial",
                "evidence": "Run python3 scripts/required.sh"}
        issue = {"id": "AE2", "tags": ["security"], "severity": "HIGH",
                 "location": {"file": "SKILL.md", "start_line": 13}}
        old = {"analysis_completeness": {"status": "partial", "is_complete": False,
                                         "partially_inspected_files": 0,
                                         "ledger_exceptions": [{"reason_code": "referenced_uninspected"}],
                                         "references": [meta, real]},
               "issues": [issue]}
        new = copy.deepcopy(old)
        new["analysis_completeness"]["references"] = [copy.deepcopy(real)]
        return old, new

    def test_one_exact_version_row_removed_without_other_losses(self):
        old, new = self.fixtures()
        result = proof.assert_delta(old, new)
        self.assertEqual(result["fake_version_rows_removed"], 1)
        self.assertEqual(result["retained_reference_rows"], 1)
        self.assertTrue(result["noncoverage_finding_groups_unchanged"])

    def test_real_missing_dependency_cannot_disappear_with_version(self):
        old, new = self.fixtures()
        new["analysis_completeness"]["references"] = []
        with self.assertRaisesRegex(ValueError, "another reference"):
            proof.assert_delta(old, new)

    def test_new_reference_or_changed_security_finding_fails(self):
        old, new = self.fixtures()
        extra = copy.deepcopy(new["analysis_completeness"]["references"][0])
        extra["evidence"] = "another missing dependency"
        new["analysis_completeness"]["references"].append(extra)
        with self.assertRaisesRegex(ValueError, "another reference"):
            proof.assert_delta(old, new)
        old, new = self.fixtures()
        new["issues"][0]["severity"] = "LOW"
        with self.assertRaisesRegex(ValueError, "security findings"):
            proof.assert_delta(old, new)

    def test_wrong_or_multiple_version_rows_fail(self):
        old, new = self.fixtures()
        old["analysis_completeness"]["references"][0]["line"] = 152
        with self.assertRaisesRegex(ValueError, "candidate removed another reference"):
            proof.assert_delta(old, new)
        old, new = self.fixtures()
        old["analysis_completeness"]["references"].append(
            copy.deepcopy(old["analysis_completeness"]["references"][0]))
        with self.assertRaisesRegex(ValueError, "candidate removed another reference"):
            proof.assert_delta(old, new)

    def test_missing_executable_never_qualifies_as_complete_with_caveats(self):
        old, new = self.fixtures()
        new["analysis_completeness"]["status"] = "complete_with_caveats"
        new["analysis_completeness"]["is_complete"] = True
        with self.assertRaisesRegex(ValueError, "missing executable"):
            proof.assert_delta(old, new)
        old, new = self.fixtures()
        new["analysis_completeness"]["ledger_exceptions"] = []
        with self.assertRaisesRegex(ValueError, "missing executable"):
            proof.assert_delta(old, new)

    def test_coverage_tag_does_not_hide_independent_security_finding(self):
        old, new = self.fixtures()
        old["issues"].append({"id": "AE1", "tags": ["coverage", "security"], "severity": "HIGH"})
        with self.assertRaisesRegex(ValueError, "security findings"):
            proof.assert_delta(old, new)

    def test_mixed_coverage_content_or_policy_is_not_suppressed(self):
        for issue_id in ("AE1", "AE7"):
            for extra_tag in ("content", "policy", "unknown"):
                with self.subTest(issue_id=issue_id, extra_tag=extra_tag):
                    old, new = self.fixtures()
                    old["issues"].append({
                        "id": issue_id, "tags": ["coverage", extra_tag],
                        "severity": "HIGH",
                        "location": {"file": "SKILL.md", "start_line": 17},
                    })
                    with self.assertRaisesRegex(ValueError, "security findings"):
                        proof.assert_delta(old, new)

    def test_malformed_issue_evidence_fails_closed(self):
        old, new = self.fixtures()
        new["issues"].append("missing actual issue data")
        with self.assertRaisesRegex(ValueError, "invalid security issue"):
            proof.assert_delta(old, new)

    def test_coverage_only_finding_may_disappear_but_content_may_not(self):
        old, new = self.fixtures()
        evidence = {"id": "AE1", "tags": ["coverage"], "severity": "HIGH"}
        old["issues"].append(evidence)
        proof.assert_delta(old, new)
        old["issues"].append({"id": "AE1", "tags": ["content"], "severity": "HIGH"})
        with self.assertRaisesRegex(ValueError, "security findings"):
            proof.assert_delta(old, new)


if __name__ == "__main__":
    unittest.main()
