"""Regression tests for fail-closed Pi dry-run native-state checks."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pi_catalog_inventory_e2e import native_files


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


if __name__ == "__main__":
    unittest.main()
