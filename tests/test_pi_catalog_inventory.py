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


def planned_pi_receipt(scope: str) -> dict:
    # Published CLI 0.1.102 emits addMultiResult even for one --target pi.
    return {
        "dry_run": True, "batch": True, "status": "planned",
        "failed": 0, "succeeded": 1,
        "environment": {"scope": scope},
        "targets": [{"target": "pi", "output": {
            "dry_run": True, "scope": scope, "result": {
                "mutated": False, "plan": {
                    "client_id": "pi", "scope": scope, "status": "ready",
                },
            },
        }}],
    }


class PiPlanningEnvelopeTests(unittest.TestCase):
    def test_validates_one_real_pi_batch_plan_for_both_scopes(self) -> None:
        for scope in ("user", "project"):
            with self.subTest(scope=scope):
                require_planned_pi_receipt(planned_pi_receipt(scope), scope)

    def test_rejects_invalid_batch_or_nested_pi_receipts(self) -> None:
        changes = {
            "not_dry_run": lambda data: data.update(dry_run=False),
            "not_batch": lambda data: data.update(batch=False),
            "not_planned": lambda data: data.update(status="preflight_failed"),
            "failed": lambda data: data.update(failed=1),
            "no_success": lambda data: data.update(succeeded=0),
            "wrong_environment_scope": lambda data: data["environment"].update(scope="project"),
            "two_targets": lambda data: data["targets"].append(copy.deepcopy(data["targets"][0])),
            "wrong_target": lambda data: data["targets"][0].update(target="codex"),
            "not_target_dry_run": lambda data: data["targets"][0]["output"].update(dry_run=False),
            "wrong_output_scope": lambda data: data["targets"][0]["output"].update(scope="project"),
            "mutated": lambda data: data["targets"][0]["output"]["result"].update(mutated=True),
            "no_plan": lambda data: data["targets"][0]["output"]["result"].update(plan=None),
            "wrong_client": lambda data: data["targets"][0]["output"]["result"]["plan"].update(client_id="codex"),
            "wrong_plan_scope": lambda data: data["targets"][0]["output"]["result"]["plan"].update(scope="project"),
            "unsupported": lambda data: data["targets"][0]["output"]["result"]["plan"].update(status="unsupported"),
        }
        for name, change in changes.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                receipt = planned_pi_receipt("user")
                change(receipt)
                require_planned_pi_receipt(receipt, "user")

if __name__ == "__main__":
    unittest.main()
