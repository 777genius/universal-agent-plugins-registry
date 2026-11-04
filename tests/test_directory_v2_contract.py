"""Strict v2 grant shape; does not publish or grant new compatibility."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from directory_v2_contract import legacy_user_v2_distribution, require_unique_scoped_grants


class DirectoryV2GrantContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v1 = json.loads((ROOT / "schemas/directory-distribution.schema.json").read_text())
        cls.v2 = json.loads((ROOT / "schemas/directory-distribution-v2.schema.json").read_text())
        Draft202012Validator.check_schema(cls.v2)
        cls.validator = Draft202012Validator(cls.v2)

    def distribution(self):
        v1 = json.loads((ROOT / "registry/directory.json").read_text())["distributions"][0]
        result = copy.deepcopy(v1)
        result["schema_version"] = 2
        for policy in result["release_policies"]:
            grants = []
            for target in policy["targets"]:
                for scope in target["scopes"]:
                    grant = {key: copy.deepcopy(value) for key, value in target.items() if key != "scopes"}
                    grant["scope"] = scope
                    grant["minimum_installer_version"] = policy["minimum_installer_version"]
                    grant["current_evidence"] = list(policy["current_evidence"])
                    grants.append(grant)
            policy["targets"] = grants
        return result


    def test_legacy_bootstrap_projection_is_user_only_without_mutating_source(self):
        source = json.loads((ROOT / "registry/directory.json").read_text())["distributions"]
        for record in source:
            original = copy.deepcopy(record)
            converted = legacy_user_v2_distribution(record, "0.1.96")
            self.validator.validate(converted)
            self.assertEqual(record, original)
            for policy in converted["release_policies"]:
                require_unique_scoped_grants(policy)
                self.assertTrue(all(g["scope"] == "user" for g in policy["targets"]))
                self.assertTrue(all(tuple(map(int, g["minimum_installer_version"].split("."))) >= (0, 1, 96)
                                    for g in policy["targets"]))
                self.assertTrue(all(g["current_evidence"] == policy["current_evidence"]
                                    for g in policy["targets"]))

    def test_bootstrap_refuses_scope_or_floor_widening(self):
        original = json.loads((ROOT / "registry/directory.json").read_text())["distributions"][0]
        bad = copy.deepcopy(original)
        bad["release_policies"][0]["targets"][0]["scopes"] = ["project"]
        with self.assertRaisesRegex(ValueError, "non-user"):
            legacy_user_v2_distribution(bad, "0.1.96")
        bad = copy.deepcopy(original)
        bad["release_policies"][0]["minimum_installer_version"] = "01.2.3"
        with self.assertRaisesRegex(ValueError, "installer version"):
            legacy_user_v2_distribution(bad, "0.1.96")
        with self.assertRaisesRegex(ValueError, "reviewed v1"):
            legacy_user_v2_distribution({"schema_version": 2}, "0.1.96")
        with self.assertRaisesRegex(ValueError, "installer version"):
            legacy_user_v2_distribution(original, "latest")

    def test_v1_stays_user_only_and_v2_accepts_scoped_policy(self):
        value = self.distribution()
        self.validator.validate(value)
        for policy in value["release_policies"]:
            require_unique_scoped_grants(policy)
        grant = value["release_policies"][0]["targets"][0]
        grant["scope"] = "project"
        self.validator.validate(value)
        old = copy.deepcopy(value)
        old["schema_version"] = 1
        for policy in old["release_policies"]:
            policy["targets"] = [dict({k:v for k,v in grant.items() if k not in ("scope","minimum_installer_version","current_evidence")}, scopes=[grant["scope"]]) for grant in policy["targets"]]
        with self.assertRaises(ValidationError):
            Draft202012Validator(self.v1).validate(old)

    def test_invalid_grant_and_closure_are_rejected(self):
        value = self.distribution()
        grant = value["release_policies"][0]["targets"][0]
        for patch in ({"scope":"workspace"}, {"extra_field":True}, {"canonical_closure":{"eligible":True}}):
            changed = copy.deepcopy(value)
            changed["release_policies"][0]["targets"][0].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValidationError):
                self.validator.validate(changed)
        changed = copy.deepcopy(value)
        del changed["release_policies"][0]["targets"][0]["minimum_installer_version"]
        with self.assertRaises(ValidationError):
            self.validator.validate(changed)

    def test_same_client_distinct_scopes_allowed_but_duplicate_pair_refused(self):
        value = self.distribution()
        policy = value["release_policies"][0]
        grant = copy.deepcopy(policy["targets"][0])
        other = copy.deepcopy(grant)
        other["scope"] = "project" if grant["scope"] == "user" else "user"
        policy["targets"].append(other)
        self.validator.validate(value)
        require_unique_scoped_grants(policy)
        other["scope"] = grant["scope"]
        other["authentication"] = "required" if grant["authentication"] != "required" else "not_required"
        self.validator.validate(value)  # structurally valid; distinct properties
        with self.assertRaisesRegex(ValueError, "duplicate scoped target"):
            require_unique_scoped_grants(policy)


if __name__ == "__main__":
    unittest.main()
