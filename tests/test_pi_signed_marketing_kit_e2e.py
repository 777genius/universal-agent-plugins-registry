"""Fail-closed parsing of genuine production-default signed Pi saved E2E receipts."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pi_signed_marketing_kit_e2e import (
    EXPECTED, CHILD_VERSIONS, assert_foreign, check_installations, check_lock,
    fresh_case, json_object,
)


def lock_fixture() -> dict:
    packages = []
    for alias, distribution in EXPECTED.items():
        packages.append({
            "alias": alias, "source_key": "directory:" + distribution,
            "targets": ["pi"],
            "source": {"registry": {"distribution": distribution}},
            "tree_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "b" * 64,
            "required_by": [] if alias == "marketing-kit" else [
                {"alias": "marketing-kit",
                 "selector": {"kind": "version", "value": CHILD_VERSIONS[alias]}}],
        })
    return {"schema_version": 1, "packages": packages}


def installed_fixture(scope: str = "user") -> dict:
    return {"result": "success", "data": {"installations": [
        {
            "installation_id": str(number), "directory": {
                "recorded_distribution": distribution,
                "recorded_revision": "c" * 40,
            },
            "clients": [{"client_id": "pi", "scope": scope,
                         "materialization": "materialized",
                         "verification": "installation_verified",
                         "package_revision": {"distribution_id": distribution,
                                              "release_sequence": 1}}],
        } for number, distribution in enumerate(EXPECTED.values(), 1)
    ]}}


class SignedMarketingLockTests(unittest.TestCase):
    def check(self, lock: dict) -> str:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "uap.lock"
            path.write_text(json.dumps(lock), encoding="utf-8")
            return check_lock(path)

    def test_accepts_exact_four_signed_pi_owners_and_edges(self):
        self.assertTrue(self.check(lock_fixture()).startswith("sha256:"))

    def test_rejects_missing_child_or_borrowed_signed_target(self):
        for mutation in (
            lambda p: p.pop(),
            lambda p: p[1].update(targets=["codex"]),
            lambda p: p[2].update(source_key="github:" + EXPECTED["hubspot-crm"]),
            lambda p: p[2].update(alias="notion"),
            lambda p: p[2].update(tree_digest="unverified"),
            lambda p: p[2]["source"]["registry"].update(distribution="other/hubspot"),
            lambda p: p[2].update(required_by=[]),
            lambda p: p[2]["required_by"][0]["selector"].update(value="2.0.0"),
            lambda p: p[0].update(required_by=[{"alias": "notion"}]),
        ):
            data = lock_fixture()
            with self.subTest(mutation=mutation):
                mutation(data["packages"])
                with self.assertRaisesRegex(RuntimeError, "signed|closure|dependency"):
                    self.check(data)


class SignedMarketingInventoryTests(unittest.TestCase):
    def test_requires_four_distinct_materialized_signed_pi_bindings(self):
        for scope in ("user", "project"):
            self.assertEqual(
                len(check_installations(installed_fixture(scope), scope)), 4)

    def test_rejects_incomplete_and_forged_installation_receipts(self):
        cases = {
            "missing": lambda d: d["data"]["installations"].pop(),
            "borrowed-target": lambda d: d["data"]["installations"][0]["clients"][0].update(client_id="codex"),
            "wrong-scope": lambda d: d["data"]["installations"][0]["clients"][0].update(scope="project"),
            "unmaterialized": lambda d: d["data"]["installations"][0]["clients"][0].update(materialization="prepared"),
            "unverified": lambda d: d["data"]["installations"][0]["clients"][0].update(verification="package_validated"),
            "wrong-owner": lambda d: d["data"]["installations"][0]["clients"][0]["package_revision"].update(distribution_id="foo"),
            "unknown-record": lambda d: d["data"]["installations"][0]["directory"].update(recorded_distribution="foreign/package"),
            "reused-id": lambda d: d["data"]["installations"][1].update(installation_id="1"),
            "untrusted-revision": lambda d: d["data"]["installations"][0]["directory"].update(recorded_revision="main"),
            "duplicate-record": lambda d: d["data"]["installations"][1]["directory"].update(
                recorded_distribution=EXPECTED["marketing-kit"]),
        }
        for title, mutate in cases.items():
            data = installed_fixture()
            mutate(data)
            with self.subTest(title=title), self.assertRaises(RuntimeError):
                check_installations(data, "user")

    def test_refuses_success_exit_without_valid_structured_response(self):
        for body in ("", "[]", "{}", '{"result":"failed"}',
                     '{"result":"success","outcome":"partial"}'):
            with self.subTest(body=body), self.assertRaises(RuntimeError):
                json_object(body, "test")


class SignedMarketingIsolationTests(unittest.TestCase):
    def test_profile_environment_excludes_runner_tokens_and_origin_overrides(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
            "pi_signed_marketing_kit_e2e.os.environ",
            {"PATH": "/bin", "GITHUB_TOKEN": "secret",
             "AGENTPLUGINS_DIRECTORY_ORIGIN": "https://evil.example",
             "NODE_OPTIONS": "--require /tmp/hook.js",
             "HOME": "/home/real"}, clear=True,
        ):
            env, project, state, native = fresh_case(Path(temp), "user-A", "user")
            self.assertEqual(env["PATH"], "/bin")
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("AGENTPLUGINS_DIRECTORY_ORIGIN", env)
            self.assertNotIn("NODE_OPTIONS", env)
            self.assertNotEqual(env["HOME"], "/home/real")
            self.assertEqual(env["PI_CODING_AGENT_DIR"], str(native))
            self.assertTrue(state.is_dir() and project.is_dir())

    def test_refuses_mutated_or_missing_foreign_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fresh_case(root, "user-A", "user")
            fresh_case(root, "user-B", "user")
            assert_foreign(root, "user")
            bad = root / "user-A" / "home" / "foreign-do-not-change.txt"
            bad.write_text("changed", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                assert_foreign(root, "user")


if __name__ == "__main__":
    unittest.main()
