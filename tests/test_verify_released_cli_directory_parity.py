import copy
import hashlib
import importlib.util
import json
import re
import tempfile
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
        self.snapshot = {
            "sequence": 19,
            "snapshot_schema_version": 1,
            "source_commit": self.snapshot_source,
            "products": [{
                "id": "context7", "default_distribution": "example/context7",
                "distributions": ["example/context7"],
            }],
            "distributions": [{
                "id": "example/context7", "product_id": "context7", "kind": "community", "status": "active",
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
        self.snapshot_bytes = json.dumps(self.snapshot, separators=(",", ":"), sort_keys=True).encode()
        self.snapshot_digest = "sha256:" + hashlib.sha256(self.snapshot_bytes).hexdigest()
        self.search = {"result": "success", "data": {"snapshot_sequence": 19, "results": [{
            "product_id": "context7", "status": "available", "distribution_id": "example/context7",
            "distribution_kind": "community", "package_version": "1.2.3", "install_selector": "context7",
            "repository": "example/plugins", "revision": self.revision, "package_path": "plugins/context7",
            "release_sequence": 2,
        }], "snapshot_digest": self.snapshot_digest}}
        self.add = {"result": "success", "data": {
            "dry_run": True,
            "actions": [{
                "component_support": [{"kind": "mcp_server", "name": "context7", "support": "prepared"}],
                "alias": "context7", "client_id": "cursor", "action": "install",
                "reason": "no matching environment-owned binding",
                "package_digest": "sha256:" + "1" * 64,
                "revision": self.revision,
            }],
            "environment": {
                "alias": "context7", "intent_change": True,
                "lock_path": "/tmp/uap.lock", "manifest_path": "/tmp/uap.toml", "saved": True,
            },
        }}

    def verify(self, snapshot=None, search=None, add=None) -> None:
        verifier.verify(
            snapshot or self.snapshot, search or self.search, add or self.add,
            sequence=19, snapshot_digest=self.snapshot_digest,
            product_id="context7", cli_version="0.1.18",
        )

    def test_add_fixture_matches_released_action_shape(self) -> None:
        self.assertEqual(set(self.add["data"]), {"dry_run", "actions", "environment"})
        self.assertEqual(set(self.add["data"]["actions"][0]), {
            "component_support", "alias", "client_id", "action", "reason", "package_digest", "revision",
        })
        self.assertEqual(set(self.add["data"]["environment"]), {
            "alias", "intent_change", "lock_path", "manifest_path", "saved",
        })
        self.verify()

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
            ("distribution_kind", "upstream"),
            ("package_version", "9.9.9"),
            ("install_selector", "example/context7"),
            ("status", "unavailable"),
            ("repository", "attacker/plugins"),
            ("revision", "c" * 40),
            ("package_path", "plugins/other"),
        ):
            with self.subTest(field=field):
                search = copy.deepcopy(self.search)
                search["data"]["results"][0][field] = value
                with self.assertRaises(ValueError):
                    self.verify(search=search)

    def test_rejects_mismatched_add_action_identity(self) -> None:
        for field, value in (
            ("alias", "attacker"),
            ("revision", "c" * 40),
            ("package_digest", "sha256:" + "0" * 64),
            ("client_id", "codex"),
            ("action", "update"),
        ):
            with self.subTest(field=field):
                add = copy.deepcopy(self.add)
                add["data"]["actions"][0][field] = value
                with self.assertRaisesRegex(ValueError, re.escape(f"add.data.actions[0].{field} ")):
                    self.verify(add=add)

    def test_rejects_mismatched_environment_alias(self) -> None:
        add = copy.deepcopy(self.add)
        add["data"]["environment"]["alias"] = "attacker"
        with self.assertRaisesRegex(ValueError, re.escape("add.data.environment.alias")):
            self.verify(add=add)

    def test_fails_closed_on_missing_released_identity_fields(self) -> None:
        fields_by_location = {
            "search": ("distribution_id", "distribution_kind", "package_version", "install_selector", "status", "repository", "revision", "package_path"),
            "action": ("alias", "client_id", "action", "revision", "package_digest"),
            "data": ("dry_run",),
            "environment": ("environment",),
            "environment_fields": ("alias", "saved"),
        }
        for location, fields in fields_by_location.items():
            for field in fields:
                with self.subTest(location=location, field=field):
                    search, add = copy.deepcopy(self.search), copy.deepcopy(self.add)
                    containers = {
                        "search": search["data"]["results"][0],
                        "action": add["data"]["actions"][0],
                        "data": add["data"],
                        "environment": add["data"],
                        "environment_fields": add["data"]["environment"],
                    }
                    containers[location].pop(field)
                    with self.assertRaises(ValueError):
                        self.verify(search=search, add=add)

    def test_fails_closed_on_empty_or_ambiguous_add_actions(self) -> None:
        for actions in ([], [copy.deepcopy(self.add["data"]["actions"][0]) for _ in range(2)]):
            with self.subTest(actions=len(actions)):
                add = copy.deepcopy(self.add)
                add["data"]["actions"] = actions
                with self.assertRaisesRegex(ValueError, "exactly one add action"):
                    self.verify(add=add)

    def test_rejects_missing_or_substituted_search_snapshot_digest(self) -> None:
        for value in (None, "sha256:" + "0" * 64):
            with self.subTest(value=value):
                search = copy.deepcopy(self.search)
                if value is None:
                    search["data"].pop("snapshot_digest")
                else:
                    search["data"]["snapshot_digest"] = value
                with self.assertRaisesRegex(ValueError, "snapshot digest"):
                    self.verify(search=search)

    def test_rejects_missing_or_substituted_cursor_action_client(self) -> None:
        for value in (None, "codex"):
            with self.subTest(value=value):
                add = copy.deepcopy(self.add)
                action = add["data"]["actions"][0]
                if value is None:
                    action.pop("client_id")
                else:
                    action["client_id"] = value
                with self.assertRaisesRegex(ValueError, "client_id"):
                    self.verify(add=add)

    def test_requires_true_dry_run_and_environment_saved(self) -> None:
        for value in (1, 1.0, 19.0, False, None):
            with self.subTest(dry_run=value):
                add = copy.deepcopy(self.add)
                if value is None:
                    add["data"].pop("dry_run")
                else:
                    add["data"]["dry_run"] = value
                with self.assertRaisesRegex(ValueError, "dry_run"):
                    self.verify(add=add)
        for value in (1, 1.0, "true", False, None):
            with self.subTest(saved=value):
                add = copy.deepcopy(self.add)
                if value is None:
                    add["data"]["environment"].pop("saved")
                else:
                    add["data"]["environment"]["saved"] = value
                with self.assertRaisesRegex(ValueError, "saved"):
                    self.verify(add=add)

    def test_public_sequences_require_exact_positive_json_integers(self) -> None:
        for location, field in (("snapshot", "sequence"), ("search", "snapshot_sequence")):
            for value in (1, 1.0, 19.0, True, False, 0, None):
                with self.subTest(location=location, value=value):
                    snapshot, search = copy.deepcopy(self.snapshot), copy.deepcopy(self.search)
                    containers = {"snapshot": snapshot, "search": search["data"]}
                    if value is None:
                        containers[location].pop(field)
                    else:
                        containers[location][field] = value
                    with self.assertRaises(ValueError):
                        self.verify(snapshot=snapshot, search=search)

    def test_release_sequences_require_exact_positive_json_integers(self) -> None:
        for location, field in (("policy", "release_sequence"), ("release", "sequence")):
            for value in (1, 1.0, 19.0, True, False, 0, None):
                with self.subTest(location=location, value=value):
                    snapshot = copy.deepcopy(self.snapshot)
                    containers = {
                        "policy": snapshot["distributions"][0]["release_policies"][0],
                        "release": snapshot["distributions"][0]["releases"][0],
                    }
                    if value is None:
                        containers[location].pop(field)
                    else:
                        containers[location][field] = value
                    with self.assertRaises(ValueError):
                        self.verify(snapshot=snapshot)

    def test_snapshot_schema_requires_exact_positive_json_integers(self) -> None:
        for value in (1.0, 19.0, True, False, 0, None):
            with self.subTest(value=value):
                snapshot = copy.deepcopy(self.snapshot)
                if value is None:
                    snapshot.pop("snapshot_schema_version")
                else:
                    snapshot["snapshot_schema_version"] = value
                with self.assertRaises(ValueError):
                    self.verify(snapshot=snapshot)

    def test_load_snapshot_rejects_file_level_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_bytes(self.snapshot_bytes)
            self.assertEqual(verifier.load_snapshot(path, self.snapshot_digest), self.snapshot)
            path.write_bytes(self.snapshot_bytes + b"\n")
            with self.assertRaisesRegex(ValueError, "snapshot bytes"):
                verifier.load_snapshot(path, self.snapshot_digest)

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

    def test_fails_closed_when_no_policy_applies_to_the_released_cli(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["distributions"][0]["release_policies"][0]["minimum_installer_version"] = "0.1.19"
        with self.assertRaisesRegex(ValueError, "applicable active Cursor policy"):
            self.verify(snapshot=snapshot)


if __name__ == "__main__":
    unittest.main()
