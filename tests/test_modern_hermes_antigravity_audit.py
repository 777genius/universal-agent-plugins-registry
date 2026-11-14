"""Source audit tests. These are NOT signed-grant or native saved E2E tests."""
from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from modern_hermes_antigravity_audit import (AuditError, audit,
                                            committed_inputs)

HEAD = "a" * 40


def fixture(component="mcp", mandatory="mcp", status="active"):
    release = {"sequence": 1, "components": [component], "manifest_name": "pkg",
               "tree_digest": "sha256:" + "b" * 64,
               "manifest_digest": "sha256:" + "c" * 64,
               "package_source": {"repository": "example/source", "revision": "d" * 40,
                                  "path": "plugins/pkg"}}
    source = {"schema_version": 1,
              "products": [{"id": "pkg", "minimum_capabilities": {
                  "skills": "required" if mandatory == "skills" else "optional",
                  "mcp": "required" if mandatory == "mcp" else "optional"}}],
              "distributions": [{"id": "example/pkg", "product_id": "pkg",
                                 "status": status, "releases": [release],
                                 "release_policies": [{"release_sequence": 1, "status": "active",
                                                       "targets": []}]}]}
    contract = [{"id": name, "skill_support": "native",
                 "mcp_transports": {"stdio": "native", "streamable-http": "native", "sse": "unsupported"},
                 "project": {"skill_support": "native", "mcp_transports": {
                     "stdio": "unsupported" if name == "hermes" else "native",
                     "streamable-http": "unsupported" if name == "hermes" else "native",
                     "sse": "unsupported"}}}
                for name in ("hermes", "antigravity")]
    return source, contract


class ModernSourceAuditTests(unittest.TestCase):
    def test_hermes_project_mcp_is_incompatible_even_with_native_user_mcp(self):
        report = audit(*fixture(), HEAD)
        rows = {(r["client"], r["scope"]): r for r in report["rows"]}
        self.assertEqual(rows["hermes", "user"]["status"], "review_required")
        self.assertEqual(rows["hermes", "project"]["status"], "native_incompatible")
        self.assertEqual(rows["antigravity", "user"]["status"], "review_required")
        self.assertEqual(rows["antigravity", "project"]["status"], "review_required")
        self.assertIn("mandatory_mcp_unsupported", rows["hermes", "project"]["blockers"])
        self.assertFalse(report["sign_ready"])
        self.assertFalse(report["verified_signed_grants"])
        self.assertFalse(report["saved_lifecycle_evidence"])
        self.assertTrue(all("targets" not in r for r in report["rows"]))

    def test_hermes_project_skills_only_is_structurally_possible_but_not_granted(self):
        report = audit(*fixture(component="skills", mandatory="skills"), HEAD)
        self.assertEqual(report["summary"]["hermes"]["project"]["review_required"], 1)
        self.assertTrue(all(r["status"] == "review_required" for r in report["rows"]))
        self.assertTrue(all("transitive_dependency_closure_not_verified" in r["blockers"]
                            for r in report["rows"]))

    def test_suspension_excludes_every_scope_even_if_otherwise_compatible(self):
        report = audit(*fixture(status="suspended"), HEAD)
        self.assertTrue(all(r["status"] == "excluded" for r in report["rows"]))

    def test_any_historical_client_grant_fails_closed(self):
        source, contract = fixture()
        source["distributions"][0]["release_policies"][0]["targets"].append({"client": "hermes"})
        with self.assertRaisesRegex(AuditError, "historical Directory already"):
            audit(source, contract, HEAD)

    def test_unpinned_or_tampered_source_cannot_appear_in_report(self):
        source, contract = fixture()
        for patch in ({"tree_digest": "0" * 64},
                      {"manifest_digest": "sha256:unknown"},
                      {"package_source": {"repository": "evil/repo", "revision": None,
                                          "path": "plugins/pkg"}},
                      {"package_source": {"repository": "example/source", "revision": "d" * 40,
                                          "path": "../pkg"}}):
            with self.subTest(patch=patch):
                modified = copy.deepcopy(source)
                modified["distributions"][0]["releases"][0].update(patch)
                with self.assertRaises(AuditError):
                    audit(modified, contract, HEAD)

    def test_policy_source_does_not_expand_from_unsupported_native_transport(self):
        source, contract = fixture()
        contract[1]["project"]["mcp_transports"]["stdio"] = "prepared"
        contract[1]["project"]["mcp_transports"]["streamable-http"] = "unsupported"
        report = audit(source, contract, HEAD)
        row = next(r for r in report["rows"] if r["client"] == "antigravity"
                   and r["scope"] == "project")
        self.assertEqual(row["status"], "native_incompatible")

    def test_actual_committed_catalog_has_no_grants_for_either_client(self):
        # Inspect exact Git blob bytes, not the Windows CRLF working tree.
        # This does not prove transport, native lifecycle, signed entitlement.
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              text=True, capture_output=True, check=True).stdout.strip()
        source, contract = committed_inputs(head)
        report = audit(source, contract, head)
        policies = sum(p["status"] == "active" for d in source["distributions"]
                       for p in d["release_policies"])
        self.assertEqual(len(report["rows"]), 4 * policies)
        self.assertGreater(report["summary"]["hermes"]["project"]["native_incompatible"], 0)
        self.assertTrue(all(r["status"] in {"excluded", "review_required", "native_incompatible"}
                            for r in report["rows"]))
        self.assertFalse(report["sign_ready"])


if __name__ == "__main__":
    unittest.main()
