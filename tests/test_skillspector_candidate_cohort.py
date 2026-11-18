"""Separate scanner identity and immutable result admission tests."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
        old.update(finding_count=0, raw_finding_count=0, finding_group_count=0,
                   findings=[], findings_truncated=False)
        old["coverage"]["grouping_complete"] = True
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
        self.assertEqual(candidate.PROFILE_DOCUMENT["reference_inventory_patch"], "uap-directory-inventory-v1")
        self.assertEqual(candidate.PROFILE["digest"], "sha256:ad4477fa9f9d61952c5fa929fc6810b0792433a1494102308a1e8e183ba6fe74")

    def test_measured_complete_preserves_content_findings(self):
        item, old, new = self.fixture()
        proof = candidate.verify_candidate(item, old, new)
        self.assertEqual(proof["candidate_exit_code"], 0)
        self.assertFalse(proof["findings_changed"])
        self.assertEqual(proof["source_digest"], old["source"]["content_digest"])

    def test_risk_exit_one_does_not_hide_findings(self):
        item, old, new = self.fixture()
        finding = {"rule": "E4", "severity": "HIGH", "path": "SKILL.md", "line": 7}
        old.update(findings=[finding], finding_count=1, raw_finding_count=1,
                   finding_group_count=1)
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
        new["coverage"]["references_total"] = 1
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)
        item, old, new = self.fixture()
        new["coverage"]["ledger_exceptions_total"] = 1
        with self.assertRaises(candidate.admission.CohortRejected):
            candidate.verify_candidate(item, old, new)

    def test_added_security_finding_requires_independent_review(self):
        item, old, new = self.fixture()
        new.update(findings=[{"rule": "MP3", "severity": "HIGH", "path": "SKILL.md"}],
                   finding_count=1, raw_finding_count=1, finding_group_count=1)
        with self.assertRaisesRegex(candidate.admission.CohortRejected, "security finding"):
            candidate.verify_candidate(item, old, new)

    def test_changed_occurrence_positions_are_reported(self):
        item, old, new = self.fixture()
        group = {"rule": "E4", "severity": "HIGH", "path": "SKILL.md", "line": 7,
                 "occurrences": [{"path": "SKILL.md", "line": 7},
                                 {"path": "SKILL.md", "line": 19}]}
        old.update(findings=[group], finding_count=2, raw_finding_count=2,
                   finding_group_count=1)
        new.update(findings=[copy.deepcopy(group)], finding_count=2, raw_finding_count=2,
                   finding_group_count=1)
        new["findings"][0]["occurrences"].reverse()
        self.assertFalse(candidate.verify_candidate(item, old, new)["findings_changed"])
        new["findings"][0]["occurrences"][0]["line"] = 20
        with self.assertRaisesRegex(candidate.admission.CohortRejected, "security finding"):
            candidate.verify_candidate(item, old, new)

    def test_only_generated_ids_can_differ_between_signed_security_groups(self):
        item, old, new = self.fixture()
        old_group = {
            "id": "sha256:" + "a" * 64,
            "rule": "E2", "severity": "HIGH", "path": "SKILL.md", "line": 8,
            "evidence": {"match": "real credential exposure"},
            "finding_ids": ["finding-" + "a" * 32],
            "occurrences": [
                {"path": "SKILL.md", "line": 8, "start_column": 4,
                 "finding_id": "finding-" + "a" * 32},
            ],
        }
        next_group = copy.deepcopy(old_group)
        next_group["finding_ids"] = ["finding-" + "b" * 32]
        next_group["occurrences"][0]["finding_id"] = "finding-" + "b" * 32
        old.update(findings=[old_group], finding_count=1,
                   raw_finding_count=1, finding_group_count=1)
        new.update(findings=[next_group], finding_count=1,
                   finding_group_count=1, raw_finding_count=1)
        parity = candidate.verify_candidate(item, old, new)
        # The v1 comparison bit remains ID-sensitive even after semantic proof.
        self.assertTrue(parity["findings_changed"])
        self.assertEqual(parity["old_findings"], 1)

        for changed in (
            {"severity": "LOW"},
            {"id": "sha256:" + "f" * 64},
            {"evidence": {"match": "suppressed"}},
        ):
            with self.subTest(changed=changed):
                mutated = copy.deepcopy(new)
                mutated["findings"][0].update(changed)
                with self.assertRaisesRegex(candidate.admission.CohortRejected, "security finding"):
                    candidate.verify_candidate(item, old, mutated)

        mutated = copy.deepcopy(new)
        mutated["findings"][0]["occurrences"][0]["line"] = 9
        with self.assertRaisesRegex(candidate.admission.CohortRejected, "security finding"):
            candidate.verify_candidate(item, old, mutated)

        mutated = copy.deepcopy(new)
        mutated["findings"][0]["finding_ids"] = ["finding-" + "c" * 32]
        with self.assertRaisesRegex(candidate.admission.CohortRejected,
                                    "generated group and occurrence"):
            candidate.verify_candidate(item, old, mutated)

    def test_reused_generated_ids_cannot_launder_distinct_occurrences(self):
        item, old, new = self.fixture()
        original_ids = ["finding-" + "a" * 32, "finding-" + "b" * 32]
        candidate_ids = ["finding-" + "c" * 32, "finding-" + "d" * 32]
        group = {
            "rule": "E2", "severity": "HIGH", "path": "SKILL.md",
            "finding_ids": original_ids,
            "occurrences": [
                {"path": "SKILL.md", "line": 8, "finding_id": original_ids[0]},
                {"path": "SKILL.md", "line": 18, "finding_id": original_ids[1]},
            ],
        }
        replacement_group = copy.deepcopy(group)
        replacement_group["finding_ids"] = candidate_ids
        for row, value in zip(replacement_group["occurrences"], candidate_ids):
            row["finding_id"] = value
        old.update(findings=[group], finding_count=2, raw_finding_count=2,
                   finding_group_count=1)
        new.update(findings=[replacement_group], finding_count=2, raw_finding_count=2,
                   finding_group_count=1)
        # Preserve signed-v1 generated-ID-drift flag; both risk sets still match.
        self.assertTrue(candidate.verify_candidate(item, old, new)["findings_changed"])
        for side in ("original", "candidate"):
            historical, proposed = copy.deepcopy((old, new))
            corrupted = historical if side == "original" else proposed
            one_group = corrupted["findings"][0]
            one_group["finding_ids"][1] = one_group["finding_ids"][0]
            one_group["occurrences"][1]["finding_id"] = one_group["finding_ids"][0]
            with self.subTest(side=side), self.assertRaisesRegex(
                candidate.admission.CohortRejected, "malformed generated finding identities"
            ):
                candidate.verify_candidate(item, historical, proposed)

    def test_old_independent_security_finding_cannot_disappear(self):
        item, old, new = self.fixture()
        old.update(findings=[{"rule": "MP3", "severity": "HIGH",
                              "path": "SKILL.md", "line": 18}], finding_count=1,
                   raw_finding_count=1, finding_group_count=1)
        with self.assertRaisesRegex(candidate.admission.CohortRejected, "security finding"):
            candidate.verify_candidate(item, old, new)

    def test_original_truncated_or_inconsistent_security_ledger_rejected(self):
        item, old, new = self.fixture()
        for mutation in (
            ("findings_truncated", True),
            ("coverage", {**old["coverage"], "grouping_complete": False}),
            ("raw_finding_count", 1),
        ):
            witness = copy.deepcopy(old)
            witness[mutation[0]] = mutation[1]
            with self.subTest(mutation=mutation[0]), self.assertRaises(
                    candidate.admission.CohortRejected):
                candidate.verify_candidate(item, witness, new)

    def test_failed_cohort_preserves_only_safe_verified_progress(self):
        previous, selection = BoundedCohortTests.fixture()
        for item in selection["sources"][:-1]:
            old = previous["records"][item["id"]]
            old.update(kind=item["kind"], plugin_path=item["plugin_path"],
                       finding_count=0, raw_finding_count=0, finding_group_count=0,
                       findings_truncated=False, findings=[])
            old["coverage"]["grouping_complete"] = True
        plan = candidate.admission.build_plan(previous, selection, "b" * 40)
        item, _, verified = self.fixture()
        self.assertEqual(item["id"], plan["selection"]["sources"][0]["id"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with (
                mock.patch.object(candidate, "verify_pinned_scanner", return_value=path / "scanner"),
                mock.patch.object(candidate.subprocess, "run",
                                  return_value=SimpleNamespace(stdout="SkillSpector v2.13.3", stderr="")),
                mock.patch.object(candidate, "PinnedRepository"),
                mock.patch.object(candidate, "scan_one",
                                  side_effect=[verified, candidate.admission.CohortRejected("secret-value")]),
            ):
                with self.assertRaises(candidate.admission.CohortRejected):
                    candidate.run_candidate(plan, previous, path / "scanner", progress_dir=path)
            accepted = json.loads((path / "accepted-01.json").read_text())
            rejected = json.loads((path / "rejected-02.json").read_text())
            self.assertEqual(accepted["record"]["id"], item["id"])
            self.assertFalse(accepted["publication_authorized"])
            self.assertEqual(rejected["completed_records"], 1)
            self.assertFalse(rejected["publication_authorized"])
            self.assertNotIn("secret-value", (path / "rejected-02.json").read_text())

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
