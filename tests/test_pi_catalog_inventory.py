"""Regression tests for fail-closed Pi dry-run native-state checks."""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pi_catalog_inventory_e2e import native_files, require_planned_pi_receipt


class PiNativeSnapshotTests(unittest.TestCase):
    def test_detects_new_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            profile.mkdir()
            baseline = native_files(profile)
            (profile / "unexpected").mkdir()
            self.assertNotEqual(native_files(profile), baseline)

    def test_detects_native_file_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            profile.mkdir()
            file = profile / "settings.json"
            file.write_text("original", encoding="utf-8")
            baseline = native_files(profile)
            file.write_text("modified", encoding="utf-8")
            self.assertNotEqual(native_files(profile), baseline)

    def test_detects_new_symlink_without_dereferencing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            profile.mkdir()
            baseline = native_files(profile)
            try:
                (profile / "escape").symlink_to(Path(temp) / "not-present")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"host does not permit symlink creation: {error}")
            entries = native_files(profile)
            self.assertNotEqual(entries, baseline)
            self.assertTrue(any(entry[0] == "escape" and entry[1] == "symlink"
                                for entry in entries))


class PiPlanningEnvelopeTests(unittest.TestCase):
    def test_validates_both_scopes_without_claiming_installation(self) -> None:
        for scope in ("user", "project"):
            receipt = {
                "dry_run": True, "scope": scope,
                "result": {"mutated": False, "plan": {
                    "client_id": "pi", "scope": scope, "status": "ready",
                }},
            }
            with self.subTest(scope=scope):
                require_planned_pi_receipt(receipt, scope)

    def test_rejects_success_envelopes_without_real_pi_plan(self) -> None:
        original = {
            "dry_run": True, "scope": "user",
            "result": {"mutated": False, "plan": {
                "client_id": "pi", "scope": "user", "status": "ready",
            }},
        }
        cases = {
            "not_dry_run": ("dry_run", False),
            "wrong_scope": ("scope", "project"),
            "no_outcome": ("result", None),
        }
        for label, (field, value) in cases.items():
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                changed = copy.deepcopy(original)
                changed[field] = value
                require_planned_pi_receipt(changed, "user")
        for label, key, value in (
            ("mutation", "mutated", True),
            ("no_plan", "plan", None),
        ):
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                changed = copy.deepcopy(original)
                changed["result"][key] = value
                require_planned_pi_receipt(changed, "user")
        for label, field, value in (
            ("wrong_target", "client_id", "codex"),
            ("plan_wrong_scope", "scope", "project"),
            ("unsupported", "status", "unsupported"),
        ):
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                changed = copy.deepcopy(original)
                changed["result"]["plan"][field] = value
                require_planned_pi_receipt(changed, "user")


if __name__ == "__main__":
    unittest.main()
