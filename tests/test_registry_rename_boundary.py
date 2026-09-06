"""The rename changes checkout ownership, never signed source identities."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_directory_publication import prepare, publication, write_valid_package
import build_registry as registry
from repository_identity import (
    CURRENT_REGISTRY_REPOSITORY as CURRENT,
    LEGACY_REGISTRY_REPOSITORY as LEGACY,
    is_checkout_owned_repository,
)


class RegistryRenameBoundaryTests(unittest.TestCase):
    def source(self, root, repository):
        package = root / "plugins/demo"
        write_valid_package(package, repository=repository)
        return {
            "schema_version": 1,
            "products": [{"schema_version": 1, "id": "demo", "display_name": "Demo", "description": "Fixture.", "manifest_name": "demo", "aliases": ["demo"], "reserved_aliases": ["demo"], "categories": ["demo"], "minimum_capabilities": {"mcp": "required", "skills": "optional"}, "default_distribution": "777genius/demo", "distributions": ["777genius/demo"]}],
            "distributions": [{"schema_version": 1, "id": "777genius/demo", "product_id": "demo", "kind": "community", "status": "active", "packager": "777genius", "releases": [{"sequence": 1, "package_version": "1.0.0", "manifest_name": "demo", "agent_plugins_schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "package_source": {"repository": repository, "revision": None, "path": "plugins/demo"}, "tree_digest_algorithm": "agentplugins-tree-sha256-v1", "tree_digest": prepare.package_tree_digest(package), "manifest_digest": prepare.manifest_digest(package), "components": ["mcp"]}], "release_policies": [{"release_sequence": 1, "status": "active", "minimum_installer_version": "0.1.6", "targets": [{"client": "codex", "scopes": ["user"], "delivery": "managed", "authentication": "unknown"}], "current_evidence": []}]}],
            "evidence": [],
        }

    def candidate(self, source, root, previous=None):
        return prepare.build_candidate(source, {"schema_version": 1, "repository": CURRENT, "snapshot_lifetime_days": 30}, "a" * 40, "rename", previous, repository_root=root)

    def test_checkout_classification_is_narrow_and_symmetric(self):
        for configured in (LEGACY, CURRENT):
            for source in (LEGACY, CURRENT):
                self.assertTrue(is_checkout_owned_repository(source, configured))
            for source in ("777genius/other", "example/external"):
                self.assertFalse(is_checkout_owned_repository(source, configured))
                self.assertFalse(is_checkout_owned_repository(configured, source))

    def test_new_placeholder_binds_only_current_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for repository in (LEGACY, "777genius/other", "example/external"):
                source = self.source(root, repository)
                with self.subTest(repository=repository), self.assertRaises(publication.PublicationError):
                    self.candidate(source, root)
            source = self.source(root, CURRENT)
            candidate = self.candidate(source, root)
            self.assertEqual(candidate["distributions"][0]["releases"][0]["package_source"], {"repository": CURRENT, "revision": "a" * 40, "path": "plugins/demo"})

    def test_legacy_placeholder_reuses_exact_signed_tuple_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.source(root, LEGACY)
            previous = copy.deepcopy(source)
            signed = previous["distributions"][0]["releases"][0]
            signed["package_source"]["revision"] = "b" * 40
            signed["published_at"] = "2026-08-20T00:00:00Z"
            with mock.patch.object(prepare, "acquire_external", side_effect=AssertionError("must remain offline")):
                candidate = self.candidate(source, root, previous)
            self.assertEqual(candidate["distributions"][0]["releases"][0], signed)
            source["distributions"][0]["releases"][0]["package_source"]["revision"] = "c" * 40
            with self.assertRaisesRegex(publication.PublicationError, "revision changed"):
                self.candidate(source, root, previous)

    def test_revoked_legacy_release_reuses_authoritative_signed_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.source(root, LEGACY)
            distribution = source["distributions"][0]
            distribution["status"] = "suspended"
            distribution["release_policies"][0]["status"] = "revoked"
            release = distribution["releases"][0]
            release["package_source"]["revision"] = "a" * 40
            previous = copy.deepcopy(source)
            signed = previous["distributions"][0]["releases"][0]
            signed["package_source"]["revision"] = "b" * 40
            signed["published_at"] = "2026-08-20T00:00:00Z"

            with mock.patch.object(prepare, "acquire_external", side_effect=AssertionError("revoked release must remain offline")):
                candidate = self.candidate(source, root, previous)
            actual = candidate["distributions"][0]["releases"][0]
            self.assertEqual(actual["package_source"], signed["package_source"])
            self.assertEqual(actual["published_at"], signed["published_at"])

            distribution["status"] = "active"
            distribution["release_policies"][0]["status"] = "active"
            previous["distributions"][0]["status"] = "active"
            previous["distributions"][0]["release_policies"][0]["status"] = "active"
            with self.assertRaisesRegex(publication.PublicationError, "published source revision changed"):
                self.candidate(source, root, previous)

    def test_broadened_legacy_reacquisition_retains_exact_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.source(root, LEGACY)
            release = source["distributions"][0]["releases"][0]
            release["package_source"]["revision"] = "b" * 40
            release["published_at"] = "2026-08-20T00:00:00Z"
            previous = copy.deepcopy(source)
            previous["products"][0]["minimum_capabilities"]["skills"] = "required"
            with mock.patch.object(prepare, "acquire_external", side_effect=RuntimeError("exact probe")) as acquire:
                with self.assertRaisesRegex(RuntimeError, "exact probe"):
                    self.candidate(source, root, previous)
            acquire.assert_called_once_with(LEGACY, "b" * 40, "plugins/demo", root)
            with mock.patch.object(registry, "validate_release_package"):
                with self.assertRaisesRegex(registry.RegistryError, "exact probe"):
                    registry.validate_changed_local_releases(source, previous, repository=CURRENT, repository_root=root, acquirer=acquire)
            self.assertEqual(acquire.call_args.args, (LEGACY, "b" * 40, "plugins/demo", root))

    def test_manifest_repository_stays_exact_across_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for repository, other in ((LEGACY, CURRENT), (CURRENT, LEGACY)):
                source = self.source(root, repository)
                release = source["distributions"][0]["releases"][0]
                release["package_source"]["repository"] = other
                with self.subTest(repository=repository), self.assertRaisesRegex(registry.RegistryError, "repository"):
                    registry.validate_release_package(root / "plugins/demo", release, allow_unresolved_revision=True)

    def test_both_names_keep_local_recipe_and_package_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for repository in (LEGACY, CURRENT):
                source = self.source(root, repository)
                with self.subTest(repository=repository):
                    self.assertEqual(registry.external_release_map(source, CURRENT), {})
                    with mock.patch.object(registry, "validate_locked_npm_runtime_policy", side_effect=registry.RegistryError("runtime probe")):
                        with self.assertRaisesRegex(registry.RegistryError, "runtime probe"):
                            registry.validate_active_local_runtime_closures(source, repository_root=root, repository=CURRENT)
                    release = source["distributions"][0]["releases"][0]
                    release["tree_digest"] = "sha256:" + "0" * 64
                    with self.assertRaisesRegex(registry.RegistryError, "tree digest"):
                        registry.validate_changed_local_releases(source, repository_root=root, repository=CURRENT)
                    source["distributions"][0]["kind"] = "community_bridge"
                    with self.assertRaisesRegex(registry.RegistryError, "one-for-one"):
                        registry.validate_bridge_bindings(source, repository_root=root, repository=CURRENT)

    def test_mixed_legacy_and_current_placeholders_are_checkout_owned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.source(root, LEGACY)
            second = copy.deepcopy(source["distributions"][0])
            second["id"] = "777genius/new"
            second["releases"][0]["package_source"]["repository"] = CURRENT
            source["distributions"].append(second)
            with mock.patch.object(registry, "validate_release_package") as validate:
                registry.validate_changed_local_releases(source, repository_root=root, repository=CURRENT)
            self.assertEqual(validate.call_count, 2)
            self.assertEqual(registry.external_release_map(source, CURRENT), {})

    def test_mixed_bridge_identities_keep_provenance_and_digest_guards(self):
        source = registry.load_directory_source()
        bridges = [d for d in source["distributions"] if d["kind"] == "community_bridge"]
        for index, distribution in enumerate(bridges):
            if index % 2:
                distribution["releases"][-1]["package_source"]["repository"] = CURRENT
        registry.validate_bridge_bindings(source, repository=CURRENT)
        for selected in bridges[:2]:
            for field in ("tree_digest", "manifest_digest", "build_provenance"):
                changed = copy.deepcopy(source)
                distribution = next(d for d in changed["distributions"] if d["id"] == selected["id"])
                distribution["releases"][-1][field] = {} if field == "build_provenance" else "sha256:" + "0" * 64
                with self.subTest(distribution=selected["id"], field=field), self.assertRaises(registry.RegistryError):
                    registry.validate_bridge_bindings(changed, repository=CURRENT)

    def test_current_relocations_append_without_rewriting_signed_releases(self):
        source = registry.load_directory_source()
        distributions = {item["id"]: item for item in source["distributions"]}
        signed = {
            "777genius/chrome-devtools-bridge": (
                2, "dcd94db0bfafe5ff5c4b1f1154ee1f7c656c19e4",
                "sha256:9ecf4bcd3eff01f3cb23a46838f65e5c9e213a29367514b320dc92aee98689ed",
                "sha256:38c1ccf9c0857300832c140caf1049aaaacaa09594011d45e68b85a416734265",
            ),
            "777genius/cloudflare-docs-bridge": (
                1, "224e4c065c69ff0b4e326e7796283524df9bfd2f",
                "sha256:2b1d984194324b50b756a893a576f3d795262bd7edfec6d7167863ca8be93a2c",
                "sha256:7d1ada5818ced00257f39edd0bea371630ad5167dbfa572fbf01d7504012119c",
            ),
            "777genius/context7": (
                2, "dcd94db0bfafe5ff5c4b1f1154ee1f7c656c19e4",
                "sha256:663f92049d29218aa8a5506a4f40fcc3002583a63730d4584ec12c84d481503d",
                "sha256:6f1cca4322bc7bcca4ef0d7fbf33d3b7b0bf3b132b10b80fe5dd27e58c0ff327",
            ),
            "777genius/firebase": (
                3, "40469d89024e0cdb42f092faa9bd0d03ac41b6aa",
                "sha256:f29d3dffebdc119f57a32b29461863ecde25aaed11aa8e5473d3cc857d3e5eb0",
                "sha256:ae8b10620d67a17a08e8aeb80910a66436b86f26716854b520ad3b414b2af3b2",
            ),
            "777genius/github-bridge": (
                1, "224e4c065c69ff0b4e326e7796283524df9bfd2f",
                "sha256:8b4fa6985607be1f503fc98294b1c0af4d4f2c3c55cf089604a3137deaaa53e8",
                "sha256:90f940c0f656bdf83fa8cccd5515bf4df9211c5a1d9cb095b84c30ee0f4f6efe",
            ),
            "777genius/hubspot-developer": (
                3, "40469d89024e0cdb42f092faa9bd0d03ac41b6aa",
                "sha256:3b3e4ae662d980e425fbf54dc7423c211e6a81fb1593ace561734392f14fb377",
                "sha256:359e99c1974c94248663ad639688755409dafc0751fe31a650602b3984a03d92",
            ),
        }
        for distribution_id, (sequence, revision, tree_digest, manifest_digest) in signed.items():
            with self.subTest(distribution=distribution_id):
                distribution = distributions[distribution_id]
                releases = {item["sequence"]: item for item in distribution["releases"]}
                policies = {item["release_sequence"]: item for item in distribution["release_policies"]}
                historical = releases[sequence]
                self.assertEqual(
                    (
                        historical["package_source"]["repository"],
                        historical["package_source"]["revision"],
                        historical["tree_digest"], historical["manifest_digest"],
                    ),
                    (LEGACY, revision, tree_digest, manifest_digest),
                )
                self.assertEqual(policies[sequence]["status"], "superseded")
                relocation = releases[sequence + 1]
                self.assertEqual(
                    relocation["package_source"]["repository"],
                    CURRENT,
                )
                self.assertEqual(relocation["package_source"]["path"], f"plugins/{distribution['product_id']}")
                current = releases[max(releases)]
                self.assertEqual(
                    current["package_source"],
                    {"repository": CURRENT, "revision": None, "path": f"plugins/{distribution['product_id']}"},
                )
                self.assertEqual(policies[current["sequence"]]["status"], "active")
                package = registry.ROOT / current["package_source"]["path"]
                self.assertEqual(current["package_version"], registry.read_object(package / "plugin.json")["version"])
                self.assertEqual(current["tree_digest"], registry.directory_tree_digest(package))
                self.assertEqual(current["manifest_digest"], registry.digest_bytes((package / "plugin.json").read_bytes()))


if __name__ == "__main__":
    unittest.main()
