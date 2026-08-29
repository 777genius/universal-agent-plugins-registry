import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_released_cli_directory_parity",
    ROOT / "scripts" / "verify_released_cli_directory_parity.py",
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ReleasedCliDirectoryParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.revision = "a" * 40
        self.snapshot_source = "b" * 40
        self.snapshot_digest = "sha256:" + "3" * 64
        self.snapshot = {
            "sequence": 19,
            "source_commit": self.snapshot_source,
            "products": [{
                "id": "context7", "default_distribution": "example/context7",
                "distributions": ["example/context7"],
            }],
            "distributions": [{
                "id": "example/context7", "product_id": "context7", "status": "active",
                "release_policies": [{
                    "release_sequence": 2, "status": "active", "minimum_installer_version": "0.1.18",
                    "targets": [{"client": "cursor"}],
                }],
                "releases": [{
                    "sequence": 2, "package_version": "1.2.3",
                    "package_source": {"repository": "example/plugins", "revision": self.revision, "path": "plugins/context7"},
                    "tree_digest": "sha256:" + "1" * 64,
                    "manifest_digest": "sha256:" + "2" * 64,
                }],
            }],
        }
        self.search = {"result": "success", "data": {"snapshot_sequence": 19, "results": [{
            "product_id": "context7", "status": "available", "distribution_id": "example/context7",
            "repository": "example/plugins", "revision": self.revision, "package_path": "plugins/context7",
            "release_sequence": 2,
        }]}}
        identity = {
            "plugin": "context7", "version": "1.2.3", "source": "example/plugins//plugins/context7",
            "revision": self.revision, "distribution_id": "example/context7", "release_sequence": 2,
            "tree_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
            "dry_run": True,
        }
        self.add = {"result": "success", "data": {**identity, "directory": {
            "product_id": "context7", "distribution_id": "example/context7",
            "desired_release_sequence": 2, "snapshot_sequence": 19,
            "snapshot_digest": self.snapshot_digest,
        }, "targets": [{
            "target": "cursor", "output": {**identity, "result": {"mutated": False}},
        }]}}

    def verify(self, snapshot=None, search=None, add=None) -> None:
        verifier.verify(
            snapshot or self.snapshot, search or self.search, add or self.add,
            sequence=19, snapshot_digest=self.snapshot_digest,
            product_id="context7", cli_version="0.1.18",
        )

    def test_selects_default_distribution_among_same_product_results(self) -> None:
        search = copy.deepcopy(self.search)
        selected = search["data"]["results"][0]
        search["data"]["results"] = [
            {**selected, "distribution_id": "community/context7", "repository": "community/plugins"},
            {**selected, "distribution_id": "upstash/context7", "repository": "upstash/context7"},
            {"product_id": "context7", "distribution_id": "discovery/one", "status": "unreviewed"},
            selected,
            {"product_id": "context7", "distribution_id": "discovery/two", "status": "unreviewed"},
        ]
        self.verify(search=search)

    def test_package_revision_is_bound_to_release_not_snapshot_source(self) -> None:
        self.assertNotEqual(self.revision, self.snapshot_source)
        self.verify()
        conflated = copy.deepcopy(self.search)
        conflated["data"]["results"][0]["revision"] = self.snapshot_source
        with self.assertRaisesRegex(ValueError, "revision does not match the selected release"):
            self.verify(search=conflated)

    def test_rejects_tampered_selected_release_identity(self) -> None:
        for field, value in (
            ("distribution_id", "attacker/context7"),
            ("repository", "attacker/plugins"),
            ("revision", "c" * 40),
            ("package_path", "plugins/other"),
        ):
            with self.subTest(field=field):
                search = copy.deepcopy(self.search)
                search["data"]["results"][0][field] = value
                with self.assertRaises(ValueError):
                    self.verify(search=search)

    def test_rejects_mismatched_add_release_identity(self) -> None:
        for location in ("data", "output"):
            for field in ("plugin", "version", "source", "revision", "tree_digest", "manifest_digest", "dry_run"):
                with self.subTest(location=location, field=field):
                    add = copy.deepcopy(self.add)
                    container = add["data"] if location == "data" else add["data"]["targets"][0]["output"]
                    container[field] = "substituted"
                    with self.assertRaisesRegex(ValueError, field):
                        self.verify(add=add)

    def test_fails_closed_on_missing_released_identity_fields(self) -> None:
        for location in ("search", "data", "output", "directory"):
            fields = {
                "search": ("distribution_id", "repository", "revision", "package_path"),
                "data": ("plugin", "version", "source", "revision", "tree_digest", "manifest_digest", "dry_run"),
                "output": ("plugin", "version", "source", "revision", "tree_digest", "manifest_digest", "dry_run"),
                "directory": ("product_id", "distribution_id", "desired_release_sequence", "snapshot_sequence", "snapshot_digest"),
            }[location]
            for field in fields:
                with self.subTest(location=location, field=field):
                    search, add = copy.deepcopy(self.search), copy.deepcopy(self.add)
                    containers = {
                        "search": search["data"]["results"][0],
                        "data": add["data"],
                        "output": add["data"]["targets"][0]["output"],
                        "directory": add["data"]["directory"],
                    }
                    containers[location].pop(field)
                    with self.assertRaises(ValueError):
                        self.verify(search=search, add=add)

    def test_rejects_substituted_directory_identity(self) -> None:
        for field in ("product_id", "distribution_id", "desired_release_sequence", "snapshot_sequence", "snapshot_digest"):
            with self.subTest(field=field):
                add = copy.deepcopy(self.add)
                add["data"]["directory"][field] = "substituted"
                with self.assertRaisesRegex(ValueError, field):
                    self.verify(add=add)

    def test_fails_closed_on_ambiguous_applicable_cursor_policy(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["distributions"][0]["release_policies"].append(copy.deepcopy(
            snapshot["distributions"][0]["release_policies"][0]
        ))
        with self.assertRaisesRegex(ValueError, "exactly one applicable active Cursor policy"):
            self.verify(snapshot=snapshot)

    def test_fails_closed_when_default_distribution_is_not_active(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["distributions"][0]["status"] = "suspended"
        with self.assertRaisesRegex(ValueError, "default distribution is not active"):
            self.verify(snapshot=snapshot)


if __name__ == "__main__":
    unittest.main()
