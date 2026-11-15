"""Fail-closed reference/security comparison for exact immutable metadata sources."""
import copy
import unittest
from scripts import skillspector_2134_metadata_e2e as audit


class MetadataE2ETests(unittest.TestCase):
    def fixture(self):
        old = {"analysis_completeness": {"status": "partial", "is_complete": False,
            "references": [{"source_path": "SKILL.md", "line": 4,
                            "status": "missing", "reference_kind": "quoted_or_code",
                            "evidence": 'license: "Apache-2.0"'}]},
               "issues": [{"id": "RP1", "tags": ["content"], "severity": "HIGH",
                           "finding_id": "finding-" + "a" * 32, "message": "retained"}]}
        new = copy.deepcopy(old)
        new["issues"][0]["finding_id"] = "finding-" + "b" * 32
        new["analysis_completeness"]["references"] = []
        new["analysis_completeness"].update(status="complete", is_complete=True)
        return old, new

    def test_high_risk_exit_is_not_a_coverage_failure(self):
        from scripts.skillspector_2134_json_version_e2e import expected_cli_exit
        complete = {"status": "complete", "is_complete": True}
        caveats = {"status": "complete_with_caveats", "is_complete": True}
        partial = {"status": "partial", "is_complete": False}
        self.assertEqual(expected_cli_exit(complete, 51, allow_risk_exit=True), 1)
        self.assertEqual(expected_cli_exit(caveats, 51, allow_risk_exit=True), 1)
        self.assertEqual(expected_cli_exit(complete, 50, allow_risk_exit=True), 0)
        self.assertEqual(expected_cli_exit(partial, 0, allow_risk_exit=True), 1)
        # The original JSON VERSION qualification keeps its stricter default.
        self.assertEqual(expected_cli_exit(complete, 99), 0)
        for coverage, score in (
            (complete, None), (complete, float("nan")), (complete, float("inf")),
            (complete, -1), (complete, 101), (complete, True),
            ({"status": "complete", "is_complete": False}, 60),
            ({"status": "partial", "is_complete": True}, 60),
        ):
            with self.subTest(coverage=coverage, score=score):
                with self.assertRaises(ValueError):
                    expected_cli_exit(coverage, score, allow_risk_exit=True)

    def test_public_risk_score_reads_exact_serialized_schema(self):
        from scripts.skillspector_2134_json_version_e2e import public_risk_score

        report = {"risk_assessment": {"score": 72, "severity": "HIGH",
                                      "recommendation": "CAUTION"}}
        self.assertEqual(public_risk_score(report), 72)
        for bad in (
            {"risk_score": 72},  # internal node field is not public JSON
            {"risk_assessment": None},
            {"risk_assessment": {"score": None}},
            {"risk_assessment": {"score": True}},
            {"risk_assessment": {"score": "72"}},
            {"risk_assessment": {"score": float("nan")}},
            {"risk_assessment": {"score": 101}},
        ):
            with self.subTest(report=bad), self.assertRaises(ValueError):
                public_risk_score(bad)

    def test_only_metadata_is_removed(self):
        a, b = self.fixture()
        self.assertTrue(audit.compare(a, b, audit.CASES[0])["other_security_findings_preserved"])

    def test_real_findings_and_references_cannot_disappear(self):
        for edit in ("severity", "message", "extra", "command"):
            old, new = self.fixture()
            if edit == "severity":
                new["issues"][0]["severity"] = "CRITICAL"
            elif edit == "message":
                new["issues"][0]["message"] = "lost"
            elif edit == "extra":
                old["analysis_completeness"]["references"].append(
                    {"status": "missing", "reference_kind": "plain_path", "evidence": "LICENSE.txt"})
            else:
                command = {"status": "missing", "reference_kind": "inline_command",
                           "evidence": "scripts/run.sh"}
                old["analysis_completeness"]["references"].append(copy.deepcopy(command))
                new["analysis_completeness"]["references"].append(copy.deepcopy(command))
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                audit.compare(old, new, audit.CASES[0])


    def test_nested_security_evidence_is_never_discarded(self):
        old, new = self.fixture()
        old["issues"][0]["evidence"] = {"finding_id": "finding-" + "a" * 32}
        new["issues"][0]["evidence"] = {"finding_id": "finding-" + "b" * 32}
        with self.assertRaisesRegex(ValueError, "content/security"):
            audit.compare(old, new, audit.CASES[0])

    def test_dynamic_external_instructions_remain_unqualified(self):
        old, new = self.fixture()
        original = {
            "source_path": "SKILL.md", "line": 13, "status": "missing",
            "reference_kind": "plain_path",
            "evidence": "generated by scripts/generate-skill-stubs.js",
        }
        old["analysis_completeness"]["references"] = [copy.deepcopy(original)]
        new["analysis_completeness"]["references"] = [copy.deepcopy(original)]
        new["analysis_completeness"].update(status="partial", is_complete=False)
        result = audit.compare(old, new, audit.CASES[1])
        self.assertEqual(result["metadata_rows_removed"], 0)
        self.assertTrue(result["dynamic_primary_instructions_unverified"])
        for change in ("remove_comment", "promote_without_instructions"):
            candidate = copy.deepcopy(new)
            if change == "remove_comment":
                candidate["analysis_completeness"]["references"] = []
            else:
                candidate["analysis_completeness"].update(status="complete", is_complete=True)
            with self.subTest(change=change), self.assertRaisesRegex(
                ValueError, "dynamic primary instructions"
            ):
                audit.compare(old, candidate, audit.CASES[1])

    def test_published_source_risks_must_survive_scanner_upgrade(self):
        signed = {
            "status": "partial", "freshness": "current",
            "findings_truncated": False,
            "coverage": {"grouping_complete": True},
            "findings": [
                {"rule": "PE3", "severity": "HIGH", "path": "SKILL.md",
                 "line": 56, "raw_count": 1, "match_fingerprint": "a" * 64},
            ],
        }
        newer = {"issues": [
            {"id": "PE3", "severity": "HIGH",
             "location": {"file": "SKILL.md", "start_line": 56},
             "match_fingerprint": "a" * 64}
        ]}
        self.assertTrue(audit.source_risks(signed, newer)["no_signed_security_finding_lost"])
        for mutation in (
            lambda row: row["issues"][0].update(id="PE1"),
            lambda row: row["issues"][0].update(severity="MEDIUM"),
            # Same rule and location may have a different security match.
            lambda row: row["issues"][0].update(match_fingerprint="b" * 64),
            lambda row: row["issues"][0]["location"].update(start_line=57),
            lambda row: row["issues"].clear(),
        ):
            candidate = copy.deepcopy(newer)
            mutation(candidate)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                ValueError, "lost source-bound original"
            ):
                audit.source_risks(signed, candidate)
        damaged = copy.deepcopy(signed)
        damaged["findings_truncated"] = True
        with self.assertRaisesRegex(ValueError, "invalid signed source"):
            audit.source_risks(damaged, newer)
        damaged = copy.deepcopy(signed)
        damaged["findings"][0]["match_fingerprint"] = None
        with self.assertRaisesRegex(ValueError, "unqualified signed finding fingerprint"):
            audit.source_risks(damaged, newer)
        candidate = copy.deepcopy(newer)
        candidate["issues"][0].pop("match_fingerprint")
        with self.assertRaisesRegex(ValueError, "candidate missing source-bound fingerprint"):
            audit.source_risks(signed, candidate)

    def test_full_source_digest_binds_original_nested_files_and_modes(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "SKILL.md").write_text("name: demo\n", encoding="utf-8")
            (root / "references").mkdir()
            nested = root / "references" / "nested.md"
            nested.write_text("v1\n", encoding="utf-8")
            expected = "sha256:2c52cf165900a9bf0553f64d49c314d0ac52c2749a728b55afd91dedb66b7c06"
            self.assertEqual(audit.signed_source_tree_digest(root), expected)
            nested.write_text("v2\n", encoding="utf-8")
            self.assertNotEqual(audit.signed_source_tree_digest(root), expected)
            nested.write_text("v1\n", encoding="utf-8")
            nested.chmod(0o755)
            self.assertNotEqual(audit.signed_source_tree_digest(root), expected)
            nested.chmod(0o644)
            self.assertEqual(audit.signed_source_tree_digest(root), expected)
            (root / "unsafe").symlink_to(nested)
            with self.assertRaisesRegex(ValueError, "untrusted or colliding"):
                audit.signed_source_tree_digest(root)

    def test_unknown_finding_identifiers_stay_strict(self):
        self.assertNotEqual(
            audit.canonical({"finding_id": "custom-one"}),
            audit.canonical({"finding_id": "custom-two"}))


if __name__ == "__main__":
    unittest.main()
