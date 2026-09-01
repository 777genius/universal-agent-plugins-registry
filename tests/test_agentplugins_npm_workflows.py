import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/agentplugins-npm-publish.yml"
PROOF = ROOT / ".github/workflows/agentplugins-platform-proof.yml"


def load(path: Path):
    return yaml.safe_load(path.read_text())


class AgentpluginsNpmWorkflowContractTests(unittest.TestCase):
    def test_publish_is_manual_version_serialized_and_verify_only_by_default(self):
        workflow = load(PUBLISH)
        dispatch = workflow[True]["workflow_dispatch"]["inputs"]
        self.assertEqual(dispatch["verify_only"]["default"], True)
        self.assertEqual(
            {"uap_tag", "version", "plugin_kit_tag", "plugin_kit_commit", "verify_only"},
            set(dispatch),
        )
        self.assertIn("inputs.version", workflow["concurrency"]["group"])
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], False)
        self.assertNotIn("push", workflow[True])
        self.assertNotIn("release", workflow[True])

    def test_stage_authenticates_exact_cross_repository_release_and_tarball(self):
        body = PUBLISH.read_text()
        for value in (
            "777genius/plugin-kit-ai",
            "agentplugins-release.yml",
            "--source-digest \"$PLUGIN_KIT_COMMIT\"",
            "--source-ref refs/heads/main",
            "--deny-self-hosted-runners",
            "release-manifest.json",
            "checksums.txt",
            "release.immutable !== true",
            "scripts/release-assets.js verify",
            "assets.repository !== \"777genius/plugin-kit-ai\"",
            "vendored binary",
        ):
            self.assertIn(value, body)
        self.assertRegex(body, r"for asset in \"\$release_root\"/\*; do\s+gh attestation verify")
        self.assertIn('test "$UAP_TAG" = "v$VERSION"', body)
        self.assertIn('test "$PLUGIN_KIT_TAG" = "agentplugins-v$VERSION"', body)
        self.assertIn('test "$GITHUB_REF" = "refs/tags/$UAP_TAG"', body)
        self.assertIn('test "$GITHUB_SHA" = "$(git rev-parse HEAD)"', body)

    def test_publish_is_downstream_of_every_native_gate_and_uses_oidc_provenance(self):
        workflow = load(PUBLISH)
        publish = workflow["jobs"]["publish"]
        self.assertEqual(set(publish["needs"]), {"stage", "six-platform-proof"})
        self.assertEqual(publish["permissions"], {"contents": "read", "id-token": "write"})
        self.assertIn("inputs.verify_only == false", publish["if"])
        body = "\n".join(step.get("run", "") for step in publish["steps"])
        self.assertIn("npm publish", body)
        self.assertIn("--provenance", body)
        self.assertIn('test -z "${NPM_TOKEN:-}"', body)
        self.assertIn("npm view universal-agent-plugins versions", body)
        self.assertIn("npm dist-tag ls universal-agent-plugins", body)

    def test_publish_lock_serializes_all_versions_and_eligibility_is_rechecked_last(self):
        workflow = load(PUBLISH)
        self.assertIn("inputs.version", workflow["concurrency"]["group"])
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], False)
        publish = workflow["jobs"]["publish"]
        self.assertEqual(publish["concurrency"], {
            "group": "agentplugins-npm-publish",
            "cancel-in-progress": False,
        })
        body = "\n".join(step.get("run", "") for step in publish["steps"])
        tarball = body.index('tarball=$(find "$RUNNER_TEMP/npm-tarball"')
        versions = body.index("npm view universal-agent-plugins versions")
        tags = body.index("npm dist-tag ls universal-agent-plugins")
        publication = body.index('npm publish "$tarball"')
        self.assertLess(tarball, versions)
        self.assertLess(versions, tags)
        self.assertLess(tags, publication)
        self.assertRegex(body, r"(?m)^NODE\nnpm publish \"\$tarball\"")

    def test_proof_matrix_is_six_native_hosted_architectures(self):
        workflow = load(PROOF)
        matrix = workflow["jobs"]["native-proof"]["strategy"]["matrix"]["include"]
        self.assertEqual({row["target"] for row in matrix}, {
            "darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64",
            "windows-amd64", "windows-arm64",
        })
        self.assertEqual({row["runner"] for row in matrix}, {
            "macos-15-intel", "macos-15", "ubuntu-24.04", "ubuntu-24.04-arm",
            "windows-2025", "windows-11-arm",
        })
        self.assertTrue(workflow["jobs"]["native-proof"]["strategy"]["fail-fast"] is False)
        self.assertNotRegex(PROOF.read_text(), r"(?i)qemu|docker|virtualbox|vmware")

    def test_public_proof_is_anonymous_isolated_and_exercises_lifecycle(self):
        publish = load(PUBLISH)
        public = publish["jobs"]["public-six-platform-proof"]
        self.assertEqual(public["needs"], "publish")
        self.assertEqual(public["with"]["package_source"], "public_npm")
        proof_body = PROOF.read_text()
        self.assertIn("env -i", proof_body)
        self.assertIn("HOME=", proof_body)
        self.assertIn("XDG_CONFIG_HOME=", proof_body)
        self.assertIn("NPM_CONFIG_CACHE=", proof_body)
        script = (ROOT / "npm/universal-agent-plugins/scripts/platform-proof.js").read_text()
        for command in ('["version"]', '["doctor"]', '["search", "context7"]',
                        '["info", "platform-proof-synthetic"', 'lifecycleCommands(synthetic)'):
            self.assertIn(command, script)
        self.assertIn("isolated_add_info_update_remove", script)

    def test_all_third_party_actions_are_commit_pinned(self):
        for path in (PUBLISH, PROOF):
            for action in re.findall(r"uses:\s*([^\s]+)", path.read_text()):
                if action.startswith("./"):
                    continue
                self.assertRegex(action, r"@[0-9a-f]{40}$", f"unpinned action in {path}: {action}")


if __name__ == "__main__":
    unittest.main()
