"""Fail-closed tests for the non-publishing nine-source scanner cohort."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

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
            evidence = ('metadata.methodology-version: "3.1.0"' if kind == "yaml"
                        else '<?xml version="1.0" encoding="UTF-8"?>')
            sources.append(item)
            records[item["id"]] = {
                "id": item["id"], "freshness": "current", "target_revision": revision,
                "source": {"repository": repo, "revision": revision, "path": path,
                           "content_digest": "sha256:" + "a" * 64},
                "scanner": copy.deepcopy(OLD_SCANNER), "status": "partial", "errors": [],
                "coverage": {"status": "partial", "reasons": [{"code": "reference_missing"}],
                             "references_total": 1, "references": [{"status": "missing", "evidence": evidence}],
                             "ledger_exceptions_total": 0, "ledger_exceptions": [],
                             "reference_evidence_truncated": False},
                "execution": {"state": "completed", "exit_code": 1},
            }
        sources.append({"id": "unrelated", "kind": "skill", "repository": "other/repo",
                        "revision": "f" * 40, "path": "skills/unknown", "plugin_path": ""})
        selection = {"schema_version": 1, "sources": sources}
        manifest = {"schema_version": 3, "scanner": copy.deepcopy(OLD_SCANNER),
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
        coverage["references_total"] = 2
        with self.assertRaises(CohortRejected):
            build_plan(previous, selection, "b" * 40)
        coverage["references"].pop()
        coverage["references_total"] = 1
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


    def test_cohort_proof_is_exclusive_and_rejects_symlink_locations(self):
        previous, selection = self.fixture()
        plan = build_plan(previous, selection, "b" * 40)
        with tempfile.TemporaryDirectory(prefix="cohort-exclusivity-") as tmp:
            root = Path(tmp)
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



if __name__ == "__main__":
    unittest.main()
