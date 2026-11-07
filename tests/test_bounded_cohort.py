"""Fail-closed tests for the non-publishing nine-source scanner cohort."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import skillspector_contract as contract
from scripts import skillspector_reports as scanner
from scripts.skillspector_bounded_cohort import (
    COHORT, CohortRejected, OLD_SCANNER, build_plan, digest, write_plan_exclusively,
)


class BoundedCohortTests(unittest.TestCase):
    @staticmethod
    def fixture():
        sources, records = [], {}
        for index, ((repo, revision, path), kind) in enumerate(sorted(COHORT.items())):
            item = {"id": f"skill-{index}", "kind": "skill", "repository": repo,
                    "revision": revision, "path": path, "plugin_path": ""}
            evidence = ('methodology-version: "3.1.0"' if kind == "yaml"
                        else '<?xml version="1.0" encoding="UTF-8"?>')
            lines = [5] if kind == "yaml" else [75, 86]
            missing = [
                {"status": "missing", "evidence": evidence, "reference_kind": "quoted_or_code",
                 "source_path": "SKILL.md", "line": line, "target_path": None,
                 "disposition": "partial"} for line in lines
            ]
            ledger = [
                {"path": "SKILL.md", "start_line": line, "end_line": line,
                 "reason_code": "reference_missing", "phase": "reference_resolution",
                 "outcome": "partial", "fatal": False} for line in lines
            ]
            sources.append(item)
            records[item["id"]] = {
                "id": item["id"], "freshness": "current", "target_revision": revision,
                "source": {"repository": repo, "revision": revision, "path": path,
                           "content_digest": "sha256:" + "a" * 64},
                "scanner": copy.deepcopy(OLD_SCANNER), "status": "partial",
                "errors": [{"code": "reference_missing"} for _ in lines],
                "coverage": {"status": "partial", "reasons": [{"code": "reference_missing"}],
                             "references_total": len(missing), "references": missing,
                             "ledger_exceptions_total": len(ledger), "ledger_exceptions": ledger,
                             "reference_evidence_truncated": False},
                "execution": {"state": "completed", "exit_code": 1},
            }
        sources.append({"id": "unrelated", "kind": "skill", "repository": "other/repo",
                        "revision": "f" * 40, "path": "skills/unknown", "plugin_path": ""})
        selection = {"schema_version": 1, "sources": sources}
        manifest = {"schema_version": 3, "scanner": copy.deepcopy(OLD_SCANNER),
                    "profile": copy.deepcopy(contract.LEGACY_POLICY),
                    "profiles": copy.deepcopy(list(scanner.LEGACY_PROFILES.values())),
                    "selection_digest": digest(selection), "source_commit": "c" * 40,
                    "coverage": {"selected": 17947}}
        return {"manifest": manifest, "selection": selection, "records": records}, selection

    def test_bounded_plan_cannot_claim_complete_or_publish(self):
        previous, selection = self.fixture()
        plan = build_plan(previous, selection, "b" * 40)
        self.assertEqual(len(plan["selection"]["sources"]), 9)
        self.assertFalse(plan["publication_authorized"])
        self.assertFalse(plan["live_selection_verified"])
        self.assertEqual(plan["candidate_status"], "not_scanned")
        self.assertEqual(previous["records"]["skill-0"]["status"], "partial")
        self.assertNotEqual(plan["baseline_scanner"], plan["candidate_scanner"])

    def test_cohort_old_evidence_survives_mixed_policy_without_relabeling(self):
        previous, selection = self.fixture()
        previous["manifest"]["profile"] = copy.deepcopy(contract.PROFILE)
        previous["manifest"]["profiles"] = copy.deepcopy(scanner.ALL_PROFILES)
        self.assertEqual(len(build_plan(previous, selection, "b" * 40)["selection"]["sources"]), 9)
        previous["manifest"]["profiles"].append({"id": "other", "digest": "sha256:" + "f" * 64})
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_unrelated_catalog_update_does_not_stale_17k_other_reports(self):
        previous, selection = self.fixture()
        current = copy.deepcopy(selection)
        current["sources"].append({"id": "new", "kind": "skill", "repository": "new/repo",
                                   "revision": "d" * 40, "path": "skills/new", "plugin_path": ""})
        self.assertEqual(len(build_plan(previous, current, "b" * 40)["selection"]["sources"]), 9)

    def test_true_missing_script_must_stay_partial(self):
        previous, selection = self.fixture()
        coverage = previous["records"]["skill-0"]["coverage"]
        coverage["references"].append({"status": "missing", "evidence": "Run scripts/install.sh"})
        coverage["references_total"] = 2
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_uninspected_or_truncated_references_must_stay_partial(self):
        previous, selection = self.fixture()
        coverage = previous["records"]["skill-0"]["coverage"]
        coverage["references"].append({"status": "rejected", "disposition": "partial",
                                       "evidence": "../outside.sh"})
        coverage["references_total"] = len(coverage["references"])
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)
        coverage["references"].pop()
        coverage["references_total"] = len(coverage["references"])
        coverage["reference_evidence_truncated"] = True
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_changed_pin_and_historical_source_fail(self):
        previous, selection = self.fixture()
        current = copy.deepcopy(selection)
        current["sources"][0]["revision"] = "0" * 40
        with self.assertRaises(CohortRejected):
            build_plan(previous, current, "b" * 40)
        previous["records"]["skill-0"]["freshness"] = "historical"
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_other_coverage_limit_and_changed_baseline_scanner_fail(self):
        previous, selection = self.fixture()
        previous["records"]["skill-0"]["coverage"]["reasons"].append({"code": "static_parse_limit"})
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)
        previous, selection = self.fixture()
        previous["manifest"]["scanner"]["revision"] = "0" * 40
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)
        previous, selection = self.fixture()
        previous["manifest"]["profiles"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)


    def test_unrelated_error_or_ledger_must_stay_partial(self):
        previous, selection = self.fixture()
        record = previous["records"]["skill-0"]
        record["errors"].append({"code": "acquisition_failed"})
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

        previous, selection = self.fixture()
        coverage = previous["records"]["skill-0"]["coverage"]
        coverage["ledger_exceptions"].append({
            "path": "SKILL.md", "start_line": 9, "end_line": 9,
            "reason_code": "referenced_uninspected", "phase": "reference_resolution",
            "outcome": "partial", "fatal": False,
        })
        coverage["ledger_exceptions_total"] += 1
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_mismatched_ledger_lines_or_reference_kind_must_fail(self):
        previous, selection = self.fixture()
        coverage = previous["records"]["skill-0"]["coverage"]
        coverage["ledger_exceptions"][0]["start_line"] = 88
        coverage["ledger_exceptions"][0]["end_line"] = 88
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

        previous, selection = self.fixture()
        coverage = previous["records"]["skill-0"]["coverage"]
        coverage["references"][0]["reference_kind"] = "markdown_link"
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_mismatched_error_count_fails_even_with_reference_missing_code(self):
        previous, selection = self.fixture()
        previous["records"]["skill-0"]["errors"].append({"code": "reference_missing"})
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)

    def test_mismatched_metadata_quotes_are_rejected(self):
        for kind in ("yaml", "xml"):
            previous, selection = self.fixture()
            target = next(item for item in selection["sources"] if
                          (item["repository"], item["revision"], item["path"]) in COHORT and
                          COHORT[(item["repository"], item["revision"], item["path"])] == kind)
            evidence = previous["records"][target["id"]]["coverage"]["references"][0]
            evidence["evidence"] = (
                """methodology-version: "3.1.0'""" if kind == "yaml"
                else """<?xml version="1.0' encoding="UTF-8"?>"""
            )
            with self.assertRaises(CohortRejected):
                build_plan(previous, selection, "b" * 40)

    def test_valid_single_quote_pairs_stay_admitted(self):
        previous, selection = self.fixture()
        for item in selection["sources"]:
            key = item["repository"], item["revision"], item["path"]
            if key not in COHORT:
                continue
            evidence = ("""methodology-version: '3.1.0'""" if COHORT[key] == "yaml"
                        else """<?xml version='1.0' encoding='UTF-8'?>""")
            for row in previous["records"][item["id"]]["coverage"]["references"]:
                row["evidence"] = evidence
        self.assertEqual(len(build_plan(previous, selection, "b" * 40)["selection"]["sources"]), 9)

    def test_direct_script_help_resolves_repo_package(self):
        script = Path(__file__).resolve().parents[1] / "scripts/skillspector_bounded_cohort.py"
        result = subprocess.run([sys.executable, str(script), "--help"],
                                cwd=script.parent.parent, text=True,
                                capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--previous-dir", result.stdout)

    def test_cohort_proof_is_exclusive_and_rejects_symlink_locations(self):
        previous, selection = self.fixture()
        plan = build_plan(previous, selection, "b" * 40)
        with tempfile.TemporaryDirectory(prefix="cohort-exclusivity-") as tmp:
            root = Path(tmp).resolve()
            path = root / "out" / "plan.json"
            write_plan_exclusively(path, plan)
            self.assertEqual(json.loads(path.read_text()), plan)
            with self.assertRaises(FileExistsError):
                write_plan_exclusively(path, plan)
            self.assertEqual(json.loads(path.read_text()), plan)

            dangling = root / "dangling.json"
            dangling.symlink_to(root / "missing-target.json")
            with self.assertRaises(CohortRejected):
                write_plan_exclusively(dangling, plan)
            self.assertFalse((root / "missing-target.json").exists())

            linked_dir = root / "linked-output"
            linked_dir.symlink_to(path.parent, target_is_directory=True)
            with self.assertRaises(CohortRejected):
                write_plan_exclusively(linked_dir / "plan2.json", plan)
            self.assertFalse((path.parent / "plan2.json").exists())

            nested = linked_dir / "nested" / "plan3.json"
            with self.assertRaises(CohortRejected):
                write_plan_exclusively(nested, plan)
            self.assertFalse((path.parent / "nested").exists())



if __name__ == "__main__":
    unittest.main()
