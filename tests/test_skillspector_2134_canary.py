"""Negative tests for immutable source-bound 2.13.4 pilot results."""
import copy
import json
import unittest
from pathlib import Path

from scripts import skillspector_2134_canary as pilot


class UpgradeCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "docs/skillspector/upgrade-2.13.4-canary.json"
        cls.baseline = json.loads(path.read_text(encoding="utf-8"))

    def record(self, source=None, status="complete", findings=2):
        source = source or self.baseline["cases"][0]
        return {
            "source": {key: source[key] for key in ("repository", "revision", "path", "content_digest")},
            "scanner": copy.deepcopy(pilot.SCANNER),
            "status": status, "finding_count": findings,
            "execution": {"state": "completed"},
            "coverage": {"status": status, "reasons": [], "fully_inspected_files": 1,
                         "grouping_complete": True, "ledger_exceptions": [],
                         "reference_evidence_truncated": False, "partially_inspected_files": 0,
                         "entirely_uninspected_files": 0},
            "errors": [], "findings_truncated": False,
        }

    def test_curated_corpus_is_bounded_and_well_formed(self):
        cases = pilot.validate_cases(self.baseline)
        self.assertEqual(len(cases), 7)
        self.assertEqual(len({case["id"] for case in cases}), 7)
        self.assertEqual(len({case["reason"] for case in cases}), 5)

    def test_nonportable_or_untrusted_source_rejected(self):
        for changed in ({"path": "../SKILL.md"}, {"revision": "main"}, {"repository": "https://bad.example/a"},
                        {"content_digest": "sha256:" + "0" * 63}, {"status": "complete"}, {"reason": "unreviewed"}):
            with self.subTest(changed=changed):
                cases = copy.deepcopy(self.baseline)
                cases["cases"][0].update(changed)
                with self.assertRaises(ValueError):
                    pilot.validate_cases(cases)

    def test_duplicate_source_rejected(self):
        cases = copy.deepcopy(self.baseline)
        cases["cases"][1]["id"] = cases["cases"][0]["id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pilot.validate_cases(cases)

    def test_complete_is_not_automatically_authorized(self):
        old = self.baseline["cases"][0]
        result = pilot.compare(old, self.record(old, findings=5))
        self.assertTrue(result["candidate_complete"])
        self.assertTrue(result["manual_finding_review_required"])
        self.assertFalse(result["fewer_findings"])
        self.assertEqual(result["old_reason"], "reference_missing")

    def test_decreased_findings_requires_review_even_if_complete(self):
        old = self.baseline["cases"][1]
        result = pilot.compare(old, self.record(old, findings=0))
        self.assertTrue(result["candidate_complete"])
        self.assertTrue(result["fewer_findings"])
        self.assertTrue(result["manual_finding_review_required"])

    def test_source_replay_or_upgrade_identity_mismatch_fails(self):
        old = self.baseline["cases"][0]
        for patch in ({"content_digest": "sha256:" + "0" * 64}, {"revision": "a" * 40}):
            with self.subTest(patch=patch):
                record = self.record(old)
                record["source"].update(patch)
                with self.assertRaisesRegex(ValueError, "immutable baseline"):
                    pilot.compare(old, record)
        record = self.record(old)
        record["scanner"]["version"] = "2.13.1"
        with self.assertRaisesRegex(ValueError, "identity"):
            pilot.compare(old, record)

    def test_false_complete_fails_closed(self):
        old = self.baseline["cases"][0]
        mutations = [
            lambda r: r["coverage"].update(status="partial"),
            lambda r: r["coverage"].update(fully_inspected_files=0),
            lambda r: r["coverage"].update(grouping_complete=False),
            lambda r: r["coverage"].update(ledger_exceptions=[{"reason_code": "missing"}]),
            lambda r: r["execution"].update(state="failed"),
            lambda r: r["coverage"].update(reasons=[{"code": "reference_missing"}]),
            lambda r: r.update(errors=[{"code": "runtime_limit"}]),
            lambda r: r["coverage"].update(partially_inspected_files=1),
            lambda r: r["coverage"].update(entirely_uninspected_files=1),
            lambda r: r.update(findings_truncated=True),
        ]
        for mutate in mutations:
            record = self.record(old)
            mutate(record)
            with self.subTest(record=record), self.assertRaisesRegex(ValueError, "complete evidence"):
                pilot.compare(old, record)

    def test_partial_remains_partial(self):
        old = self.baseline["cases"][0]
        record = self.record(old, status="partial")
        record["coverage"]["reasons"] = [{"code": "reference_missing"}]
        result = pilot.compare(old, record)
        self.assertFalse(result["candidate_complete"])
        self.assertEqual(result["coverage_reasons"], ["reference_missing"])
        self.assertTrue(result["manual_finding_review_required"])


if __name__ == "__main__":
    unittest.main()
