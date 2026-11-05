"""Fail-closed nine-source checks against independently authenticated live feeds."""
from __future__ import annotations

import copy
import unittest

from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_live_cohort_preflight as live
from scripts.directory_publication import canonical_json, sha256_digest
from tests.test_bounded_cohort import BoundedCohortTests

REPORT_COMMIT = "b" * 40


def signed_fixture():
    """Model the nine actual community-sourced roots and distinct signed feeds."""
    previous, selection = BoundedCohortTests.fixture()
    package_roots = {}
    records = {}
    for item in selection["sources"]:
        if item["id"] == "unrelated":
            continue
        old_id = item["id"]
        repo, path = item["repository"], item["plugin_path"]
        name = "community:" + sha256_digest(canonical_json([repo, path]))[7:39]
        item.update(id="plugin:" + name + "/" + item["path"].rsplit("/", 1)[-1],
                    kind="plugin_skill")
        record = previous["records"][old_id]
        record["id"] = item["id"]
        records[item["id"]] = record
        entry = package_roots.setdefault((repo, path), {
            "name": name, "components": ["skills"],
            "source": {"repository": repo, "revision": item["revision"], "path": path},
            "expected_skills": 0, "available": True,
            "tree_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
        })
        entry["expected_skills"] += 1
    previous["records"] = records
    previous["manifest"]["selection_digest"] = admission.digest(selection)
    plan = admission.build_plan(previous, selection, REPORT_COMMIT)
    meta = {"state": "resolved", "reason": None, "sequence": 7,
            "source_commit": "c" * 40,
            "snapshot_digest": "sha256:" + "3" * 64}
    other = meta | {"sequence": 10, "snapshot_digest": "sha256:" + "4" * 64}
    return previous, plan, list(package_roots.values()), meta, [], other


class SignedLiveCohortTests(unittest.TestCase):
    def check(self, fixture):
        """Exercise the same admission gate after signed-feed decoding."""
        return live.verify_live_pins(*fixture)

    def test_exact_nine_signed_pins_admit_only_nonpublishing_source_evidence(self):
        value = signed_fixture()
        result = self.check(value)
        self.assertEqual(len(result["sources"]), 9)
        self.assertTrue(result["source_pins_verified_against_fresh_signed_feeds"])
        self.assertFalse(result["provider_listing_verified"])
        self.assertFalse(result["candidate_scan_verified"])
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(len({row["signed_package_id"] for row in result["sources"]}), 3)
        self.assertTrue(all(row["content_digest"].startswith("sha256:") for row in result["sources"]))
        self.assertEqual(value[0]["records"][result["sources"][0]["id"]]["status"], "partial")

    def test_changed_revision_or_unavailable_package_rejected(self):
        for change in ("revision", "available", "name", "path"):
            value = copy.deepcopy(signed_fixture())
            plugin = value[2][0]
            if change == "revision":
                plugin["source"]["revision"] = "f" * 40
            elif change == "available":
                plugin["available"] = False
            elif change == "name":
                plugin["name"] = "community:" + "0" * 32
            else:
                plugin["source"]["path"] = "wrong/path"
            with self.subTest(change=change), self.assertRaises(admission.CohortRejected):
                self.check(value)

    def test_missing_or_duplicate_signed_package_rejected(self):
        value = copy.deepcopy(signed_fixture())
        value[2].pop()
        with self.assertRaises(admission.CohortRejected):
            self.check(value)
        value = copy.deepcopy(signed_fixture())
        value[2].append(copy.deepcopy(value[2][0]))
        with self.assertRaises(admission.CohortRejected):
            self.check(value)

    def test_directory_override_at_different_pin_fails_closed(self):
        value = copy.deepcopy(signed_fixture())
        source = copy.deepcopy(value[2][0]["source"])
        source["revision"] = "f" * 40
        value[4].append({"name": "directory/other", "source": source})
        with self.assertRaises(admission.CohortRejected):
            self.check(value)
        value[4][0]["source"]["revision"] = value[2][0]["source"]["revision"]
        self.assertEqual(len(self.check(value)["sources"]), 9)

    def test_incomplete_signed_inventory_or_digest_rejected(self):
        for change in ("count", "digest", "components"):
            value = copy.deepcopy(signed_fixture())
            plugin = value[2][0]
            if change == "count":
                plugin["expected_skills"] = 0
            elif change == "digest":
                plugin["tree_digest"] = "sha256:" + "g" * 64
            else:
                plugin["components"] = ["mcp"]
            with self.subTest(change=change), self.assertRaises(admission.CohortRejected):
                self.check(value)

    def test_stale_signed_metadata_is_not_live_proof(self):
        for position, key, bad in ((3, "state", "unavailable"),
                                   (3, "sequence", True),
                                   (3, "snapshot_digest", "unverified"),
                                   (5, "source_commit", "latest")):
            value = copy.deepcopy(signed_fixture())
            value[position][key] = bad
            with self.subTest(position=position, key=key), self.assertRaises(admission.CohortRejected):
                self.check(value)

    def test_modified_cohort_plan_or_partial_cannot_be_live(self):
        value = copy.deepcopy(signed_fixture())
        value[1]["publication_authorized"] = True
        with self.assertRaises(admission.CohortRejected):
            self.check(value)
        value = copy.deepcopy(signed_fixture())
        row = value[1]["selection"]["sources"][0]
        value[0]["records"][row["id"]]["coverage"]["reasons"].append(
            {"code": "referenced_uninspected"})
        with self.assertRaises(admission.CohortRejected):
            self.check(value)

    def test_wrong_signed_plugin_identity_and_deleted_prior_digest_rejected(self):
        value = copy.deepcopy(signed_fixture())
        value[1]["selection"]["sources"][0]["id"] = "plugin:community:untrusted/other"
        with self.assertRaises(admission.CohortRejected):
            self.check(value)
        value = copy.deepcopy(signed_fixture())
        row = value[1]["selection"]["sources"][0]
        value[0]["records"][row["id"]]["source"]["content_digest"] = None
        with self.assertRaises(admission.CohortRejected):
            self.check(value)


if __name__ == "__main__":
    unittest.main()
