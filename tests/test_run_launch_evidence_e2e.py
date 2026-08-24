from __future__ import annotations

import importlib.util
import base64
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
AGENTPLUGINS_0_1_14_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agentplugins-0.1.14"
AGENTPLUGINS_0_1_14_ADD = AGENTPLUGINS_0_1_14_FIXTURES / "add.json"
AGENTPLUGINS_0_1_14_STATE_V2 = AGENTPLUGINS_0_1_14_FIXTURES / "state-v2.json"


def release_fixture(name: str) -> dict:
    return json.loads((AGENTPLUGINS_0_1_14_FIXTURES / name).read_text())
MODULE = ROOT / "scripts" / "run_launch_evidence_e2e.py"
SPEC = importlib.util.spec_from_file_location("run_launch_evidence_e2e", MODULE)
assert SPEC and SPEC.loader
e2e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e2e)
import launch_observer_signatures as observer_signatures
OBSERVER_SPEC = importlib.util.spec_from_file_location("observe_launch_scenario", ROOT / "scripts" / "observe_launch_scenario.py")
assert OBSERVER_SPEC and OBSERVER_SPEC.loader
observer = importlib.util.module_from_spec(OBSERVER_SPEC)
OBSERVER_SPEC.loader.exec_module(observer)
FACADE_SPEC = importlib.util.spec_from_file_location("observe_release_facade", ROOT / "scripts" / "observe_release_facade.py")
assert FACADE_SPEC and FACADE_SPEC.loader
facade = importlib.util.module_from_spec(FACADE_SPEC)
FACADE_SPEC.loader.exec_module(facade)
CONSENT = ROOT / "tests/e2e/fixtures/fixture-only-consent.json"
PUBLICATION = ROOT / "tests/fixtures/directory-publication"


class LaunchEvidenceE2ETests(unittest.TestCase):
    def agentplugins_0_1_14_add_fixture(self) -> tuple[bytes, dict]:
        raw = AGENTPLUGINS_0_1_14_ADD.read_bytes()
        value = json.loads(raw)
        self.assertEqual((value["schema_version"], value["command"], value["result"]), (1, "add", "success"))
        self.assertEqual((value["data"]["plugin"], value["data"]["version"]), ("context7", "1.0.0"))
        self.assertEqual(
            (value["data"]["source"], value["data"]["revision"]),
            ("upstash/context7//plugins/agent-plugins/context7", "769c6cd22c3d95462d1f55d789e9532cabefa5a9"),
        )
        return raw, value

    def agentplugins_0_1_14_state_fixture(self) -> tuple[str, dict]:
        raw = AGENTPLUGINS_0_1_14_STATE_V2.read_text()
        value = json.loads(raw)
        self.assertEqual(value["schema_version"], 4)
        installation = value["installations"][0]
        self.assertEqual(len(value["installations"]), 1)
        self.assertEqual(
            (installation["source"]["repository"], installation["source"]["resolved_revision"], installation["source"]["package_subpath"]),
            ("upstash/context7", "769c6cd22c3d95462d1f55d789e9532cabefa5a9", "plugins/agent-plugins/context7"),
        )
        self.assertEqual(
            (
                installation["package"]["loader_kind"], installation["package"]["format_id"],
                installation["package"]["schema_uri"], installation["package"]["version"],
            ),
            (
                "agent_plugins", "agent-plugins/1.0.0",
                "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "1.0.0",
            ),
        )
        return raw, value

    def fixture_harness(self, root: Path | None = None, **kwargs):
        return e2e.LaunchHarness(
            None, None, mode="fixture-only", consent=CONSENT, run_root=root, **kwargs
        )

    def test_direct_external_fixture_is_a_valid_skill_package(self) -> None:
        skill = (e2e.EXTERNAL_PACKAGE / "skills/fixture/SKILL.md").read_text()
        self.assertTrue(skill.startswith("---\n"))
        frontmatter, body = skill.removeprefix("---\n").split("\n---\n", 1)
        lines = frontmatter.splitlines()
        self.assertIn("name: fixture", lines)
        self.assertTrue(any(line.startswith("description: ") for line in lines))
        self.assertIn("license: Apache-2.0", lines)
        self.assertIn("# External fixture", body)

    def test_direct_package_digest_matches_go_contract_with_directories_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            (package / "empty").mkdir()
            (package / "bin").mkdir()
            executable = package / "bin" / "run"
            executable.write_bytes(b"run\n")
            executable.chmod(0o755)
            (package / "plain").write_bytes(b"x")
            # Cross-contract vector produced by the Go
            # agentplugins-tree-sha256-v1 snapshotter.
            self.assertEqual(
                e2e.package_digest(package),
                "sha256:2e8071d58dd150284aebbbe1ec7e830afe7228522aa1c4bf1b2eb7d3f1d40143",
            )
            executable.chmod(0o644)
            self.assertEqual(
                e2e.package_digest(package),
                "sha256:ca762bbfbaf48fc3e199ed77dcc61442f42b576c3b9014a642472de8da0879bb",
            )

    def test_central_stable_snapshot_derives_the_same_package_tree_digest(self) -> None:
        self.assertEqual(observer.package_identity(e2e.EXTERNAL_PACKAGE)["tree_digest"], e2e.package_digest(e2e.EXTERNAL_PACKAGE))

    def test_fixture_mode_is_explicitly_non_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(e2e, "ROOT", Path("/opt/test-repository")):
            evidence = self.fixture_harness(Path(tmp) / "fresh").export()
        self.assertEqual(evidence["schema_version"], 3)
        self.assertEqual(evidence["run"]["mode"], "fixture-only")
        self.assertFalse(evidence["run"]["runtime_claims"])
        self.assertFalse(evidence["summary"]["required_gates_complete"])
        self.assertEqual(evidence["summary"]["hero_runtime_results"], 0)
        e2e.assert_redacted(evidence)

    def test_enforced_mode_refuses_missing_live_inputs_before_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not authorize|missing required input"):
            e2e.LaunchHarness(None, None, mode="enforced", consent=CONSENT)

    def test_stable_version_floor(self) -> None:
        for version in ("0.1.6", "0.1.8", "0.1.13"):
            with self.assertRaisesRegex(ValueError, "0.1.14 or newer"):
                e2e.parse_stable_version(version)
        self.assertEqual(e2e.parse_stable_version("0.1.14"), (0, 1, 14))
        self.assertEqual(e2e.parse_stable_version("1.0.0"), (1, 0, 0))
        with self.assertRaisesRegex(ValueError, "exact semantic version"):
            e2e.parse_stable_version("latest")
        with self.assertRaisesRegex(ValueError, "exact semantic version"):
            e2e.parse_stable_version("0.1.8-rc.1")

    def test_challenge_binds_github_release_directory_and_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(e2e.secrets, "token_hex", return_value="ab" * 32):
            caller = ("push", "refs/heads/main", "777genius/universal-agent-plugins/.github/workflows/directory-publication.yml@refs/heads/main")
            scenario = e2e.sha256_file(e2e.SCENARIOS)
            first = e2e.make_challenge("a" * 40, "12", "3", *caller, "sha256:" + "b" * 64, "sha256:" + "c" * 64, scenario, Path(tmp))
            changed = e2e.make_challenge("a" * 40, "12", "3", *caller, "sha256:" + "d" * 64, "sha256:" + "c" * 64, scenario, Path(tmp) / "producer")
            self.assertNotEqual(first["value"], changed["value"])
        self.assertEqual(first["github_sha"], "a" * 40)
        self.assertEqual(first["scenario_contract_digest"], e2e.sha256_file(e2e.SCENARIOS))
        self.assertNotIn("caller_event_name", first)
        self.assertEqual(first["root_id"], e2e.logical_root_id("a" * 40, "12", "3"))
        self.assertEqual(
            first["root_id"],
            e2e.make_challenge("a" * 40, "12", "3", *caller, "sha256:" + "b" * 64, "sha256:" + "c" * 64, scenario, Path(tmp) / "other-job")["root_id"],
        )
        self.assertTrue(e2e.challenge_context_valid(first))
        self.assertFalse(e2e.challenge_context_valid({**first, "directory_digest": "sha256:" + "d" * 64}))

    def test_exported_root_identity_is_logical_not_temporary_path_derived(self) -> None:
        challenge = {
            "root_id": e2e.logical_root_id("a" * 40, "12", "3"),
            "caller_event_name": "push",
            "caller_ref": "refs/heads/main",
            "caller_workflow_ref": "777genius/universal-agent-plugins/.github/workflows/directory-publication.yml@refs/heads/main",
            "value": "b" * 64,
        }
        self.assertEqual(e2e.exported_root_id(challenge), challenge["root_id"][:16])
        self.assertEqual(e2e.exported_root_id(None), "0" * 16)

    def test_earlier_attempt_native_observations_keep_the_same_thirty_minute_freshness_bound(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.assertTrue(e2e.current_or_earlier_attempt("2", "3"))
        self.assertFalse(e2e.current_or_earlier_attempt("4", "3"))
        self.assertTrue(e2e.fresh_observation_interval(
            (now - timedelta(minutes=5)).isoformat(), (now - timedelta(minutes=4)).isoformat(), now=now,
        ))
        self.assertFalse(e2e.fresh_observation_interval(
            (now - timedelta(minutes=31)).isoformat(), (now - timedelta(minutes=31)).isoformat(), now=now,
        ))

    def test_live_artifacts_require_fresh_challenge_bound_ed25519_bundle(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        challenge = "a" * 64
        artifacts = {
            "runtime-attestations.json": {"schema_version": 1, "attestations": []},
            "notion-oauth-attestations.json": {"schema_version": 1, "attestations": []},
            "chatgpt-cloudflare-attestation.json": {"schema_version": 1, "attestations": []},
            "consent.json": {"schema_version": 1, "purpose": "stable-launch-e2e", "consent": True, "disposable_only": True},
        }
        now = datetime.now(timezone.utc).replace(microsecond=0)
        bundle = {
            "schema_version": 1, "challenge": challenge,
            "signed_at": now.isoformat().replace("+00:00", "Z"),
            "key_id": "stable-observer-2026", "artifacts": artifacts,
        }
        bundle["signature"] = base64.b64encode(private_key.sign(observer_signatures.signed_payload(bundle))).decode()
        encoded_key = base64.b64encode(public_key).decode()
        self.assertEqual(
            observer_signatures.verify_observer_bundle(
                bundle, challenge=challenge, public_key_base64=encoded_key,
                expected_key_id="stable-observer-2026", now=now,
            ), artifacts,
        )
        with self.assertRaisesRegex(ValueError, "signature is invalid"):
            observer_signatures.verify_observer_bundle(
                {**bundle, "artifacts": {**artifacts, "consent.json": {"consent": False}}},
                challenge=challenge, public_key_base64=encoded_key,
                expected_key_id="stable-observer-2026", now=now,
            )
        stale = {**bundle, "signed_at": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")}
        stale["signature"] = base64.b64encode(private_key.sign(observer_signatures.signed_payload(stale))).decode()
        with self.assertRaisesRegex(ValueError, "stale"):
            observer_signatures.verify_observer_bundle(
                stale, challenge=challenge, public_key_base64=encoded_key,
                expected_key_id="stable-observer-2026", now=now,
            )

    def test_release_manifest_requires_every_native_slot_and_exact_identity(self) -> None:
        assets = {
            key: {"file": f"agentplugins_1.2.3_{os_name}_{arch}{suffix}", "sha256": f"{index + 1:064x}", "size": 1}
            for index, (key, os_name, arch, suffix) in enumerate((
                ("darwin-amd64", "darwin", "amd64", ""), ("darwin-arm64", "darwin", "arm64", ""),
                ("linux-amd64", "linux", "amd64", ""), ("linux-arm64", "linux", "arm64", ""),
                ("windows-amd64", "windows", "amd64", ".exe"), ("windows-arm64", "windows", "arm64", ".exe"),
            ))
        }
        value = {"schema_version": 2, "tag": "agentplugins-v1.2.3", "commit": "a" * 40, "version": "1.2.3", "assets": assets}
        e2e.validate_release_manifest(value, repository=e2e.TRUSTED_CLI_RELEASE_REPOSITORY, tag="agentplugins-v1.2.3", tag_commit="a" * 40)
        with self.assertRaisesRegex(ValueError, "omits a required"):
            e2e.validate_release_manifest({**value, "assets": dict(list(assets.items())[:-1])}, repository=e2e.TRUSTED_CLI_RELEASE_REPOSITORY, tag="agentplugins-v1.2.3", tag_commit="a" * 40)

    def test_release_resolution_binds_github_tag_manifest_and_asset_bytes(self) -> None:
        selected = b"native-binary"
        slots = (
            ("darwin-amd64", "agentplugins_1.2.3_darwin_amd64", b"1"),
            ("darwin-arm64", "agentplugins_1.2.3_darwin_arm64", b"2"),
            ("linux-amd64", "agentplugins_1.2.3_linux_amd64", selected),
            ("linux-arm64", "agentplugins_1.2.3_linux_arm64", b"4"),
            ("windows-amd64", "agentplugins_1.2.3_windows_amd64.exe", b"5"),
            ("windows-arm64", "agentplugins_1.2.3_windows_arm64.exe", b"6"),
        )
        manifest = {
            "schema_version": 2, "tag": "agentplugins-v1.2.3", "commit": "a" * 40, "version": "1.2.3",
            "assets": {key: {"file": name, "sha256": e2e.hashlib.sha256(body).hexdigest(), "size": len(body)} for key, name, body in slots},
        }
        manifest_body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        checksum_bodies = [(name, body) for _, name, body in slots] + [(e2e.RELEASE_MANIFEST_NAME, manifest_body)]
        checksums_body = "".join(
            f"{e2e.hashlib.sha256(body).hexdigest()}  {name}\n" for name, body in checksum_bodies
        ).encode()
        api_assets = [{"name": e2e.RELEASE_MANIFEST_NAME, "url": "https://api.github.test/manifest", "size": len(manifest_body)}]
        api_assets.append({"name": e2e.RELEASE_CHECKSUMS_NAME, "url": "https://api.github.test/checksums", "size": len(checksums_body)})
        api_assets += [{"name": name, "url": f"https://api.github.test/{name}", "size": len(body)} for _, name, body in slots]
        release = {"id": 123, "draft": False, "prerelease": False, "immutable": True, "tag_name": "agentplugins-v1.2.3", "assets": api_assets}
        bodies = {
            "https://api.github.test/manifest": manifest_body,
            "https://api.github.test/checksums": checksums_body,
            **{f"https://api.github.test/{name}": body for _, name, body in slots},
        }

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(e2e, "github_json", return_value=release), mock.patch.object(e2e, "resolve_tag_commit", return_value="a" * 40):
            destination, resolved, digest = e2e.resolve_github_release(
                e2e.TRUSTED_CLI_RELEASE_REPOSITORY, "agentplugins-v1.2.3", Path(tmp) / "agentplugins",
                asset_name="agentplugins_1.2.3_linux_amd64",
                fixture_fetch=lambda url, _limit, _accept: bodies[url],
                attestation_verifier=lambda path, repo, workflow, tag, commit, digest: {"repository": repo, "workflow": workflow, "tag": tag, "tag_commit": commit, "asset_name": path.name, "asset_digest": digest, "verified": True},
            )
            self.assertEqual(destination.read_bytes(), selected)
            self.assertEqual(resolved, manifest)
            self.assertEqual(digest, "sha256:" + e2e.hashlib.sha256(manifest_body).hexdigest())
            self.assertEqual((destination.parent / e2e.RELEASE_CHECKSUMS_NAME).read_bytes(), checksums_body)

            tampered = {**bodies, "https://api.github.test/agentplugins_1.2.3_linux_amd64": b"tampered-bytes"}
            with self.assertRaisesRegex(ValueError, "digest disagrees"):
                e2e.resolve_github_release(
                    e2e.TRUSTED_CLI_RELEASE_REPOSITORY, "agentplugins-v1.2.3", Path(tmp) / "tampered",
                    asset_name="agentplugins_1.2.3_linux_amd64",
                    fixture_fetch=lambda url, _limit, _accept: tampered[url],
                    attestation_verifier=lambda *_args: {},
                )

            tampered_checksums = {**bodies, "https://api.github.test/checksums": checksums_body.replace(b"  release-manifest.json", b"  renamed-manifest.json")}
            with self.assertRaisesRegex(ValueError, "exact manifest asset set"):
                e2e.resolve_github_release(
                    e2e.TRUSTED_CLI_RELEASE_REPOSITORY, "agentplugins-v1.2.3", Path(tmp) / "bad-checksums",
                    asset_name="agentplugins_1.2.3_linux_amd64",
                    fixture_fetch=lambda url, _limit, _accept: tampered_checksums[url],
                    attestation_verifier=lambda *_args: {},
                )

            with mock.patch.object(e2e, "github_json", return_value={**release, "immutable": False}), self.assertRaisesRegex(ValueError, "mutable"):
                e2e.resolve_github_release(
                    e2e.TRUSTED_CLI_RELEASE_REPOSITORY, "agentplugins-v1.2.3", Path(tmp) / "mutable",
                    asset_name="agentplugins_1.2.3_linux_amd64", fixture_fetch=lambda url, _limit, _accept: bodies[url],
                    attestation_verifier=lambda *_args: {},
                )

    def test_github_attestation_rejects_missing_or_wrong_subject(self) -> None:
        verified = mock.Mock(returncode=0, stdout="[]", stderr="")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(e2e.subprocess, "run", return_value=verified):
            asset = Path(tmp) / "agentplugins_0.1.8_linux_amd64"
            asset.write_bytes(b"native")
            with self.assertRaisesRegex(ValueError, "no verified"):
                e2e.verify_github_asset_attestation(asset, e2e.TRUSTED_CLI_RELEASE_REPOSITORY, e2e.TRUSTED_CLI_RELEASE_WORKFLOW, e2e.TRUSTED_CLI_RELEASE_TAG, "a" * 40, "sha256:" + e2e.hashlib.sha256(b"native").hexdigest())
            wrong = [{"verificationResult": {"statement": {"subject": [{"name": "wrong", "digest": {"sha256": "0" * 64}}]}}}]
            verified.stdout = json.dumps(wrong)
            with self.assertRaisesRegex(ValueError, "subject name/digest"):
                e2e.verify_github_asset_attestation(asset, e2e.TRUSTED_CLI_RELEASE_REPOSITORY, e2e.TRUSTED_CLI_RELEASE_WORKFLOW, e2e.TRUSTED_CLI_RELEASE_TAG, "a" * 40, "sha256:" + e2e.hashlib.sha256(b"native").hexdigest())

    def test_npm_installed_executable_must_equal_authenticated_native_asset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "agentplugins"
            executable.write_bytes(b"prints-correct-version-but-is-not-release-binary")
            executable.chmod(0o700)
            native = {"sha256": e2e.hashlib.sha256(b"real-release-binary").hexdigest(), "size": len(b"real-release-binary")}
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                facade.verify_installed_npm_payload(Path(tmp), native)

    def test_npm_resolution_binds_exact_registry_integrity_and_tarball(self) -> None:
        body = b"exact npm tarball"
        integrity = "sha512-" + base64.b64encode(e2e.hashlib.sha512(body).digest()).decode()
        metadata_url = "https://registry.npmjs.org/universal-agent-plugins/0.1.8"
        tarball_url = "https://registry.npmjs.org/universal-agent-plugins/-/universal-agent-plugins-0.1.8.tgz"
        provenance_url = "https://registry.npmjs.org/-/npm/v1/attestations/universal-agent-plugins@0.1.8"
        metadata = json.dumps({"name": "universal-agent-plugins", "version": "0.1.8", "dist": {"integrity": integrity, "tarball": tarball_url, "attestations": {"url": provenance_url, "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}}).encode()
        bodies = {metadata_url: metadata, tarball_url: body}
        with tempfile.TemporaryDirectory() as tmp:
            path, identity = e2e.resolve_npm_package(
                "universal-agent-plugins", "0.1.8", Path(tmp) / "package.tgz",
                fixture_fetch=lambda url, _limit, _accept: bodies[url],
            )
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(identity["integrity"], integrity)
            self.assertEqual(identity["provenance_url"], provenance_url)
            with self.assertRaisesRegex(ValueError, "dist.integrity"):
                e2e.resolve_npm_package(
                    "universal-agent-plugins", "0.1.8", Path(tmp) / "tampered.tgz",
                    fixture_fetch=lambda url, _limit, _accept: b"tampered" if url == tarball_url else metadata,
                )
            without_provenance = json.dumps({"name": "universal-agent-plugins", "version": "0.1.8", "dist": {"integrity": integrity, "tarball": tarball_url}}).encode()
            with self.assertRaisesRegex(ValueError, "provenance"):
                e2e.resolve_npm_package(
                    "universal-agent-plugins", "0.1.8", Path(tmp) / "no-provenance.tgz",
                    fixture_fetch=lambda url, _limit, _accept: body if url == tarball_url else without_provenance,
                )

    def test_production_identity_is_fixed_cross_repository_configuration(self) -> None:
        config = e2e.read_production_config()
        self.assertEqual(config["catalog_repository"], "777genius/universal-agent-plugins")
        self.assertEqual(config["cli_release_repository"], "777genius/plugin-kit-ai")
        self.assertEqual(config["cli_release_tag"], "agentplugins-v0.1.14")
        self.assertEqual(config["cli_release_workflow"], "777genius/plugin-kit-ai/.github/workflows/agentplugins-release.yml")
        schema = json.loads((ROOT / "tests/e2e/schemas/native-release-observation.schema.json").read_text())
        self.assertEqual(
            schema["properties"]["github_asset_attestation"]["properties"]["workflow"]["const"],
            e2e.TRUSTED_CLI_RELEASE_WORKFLOW,
        )
        self.assertEqual(schema["properties"]["cli_release_tag"]["const"], e2e.TRUSTED_CLI_RELEASE_TAG)
        self.assertNotIn("repository", config)
        observer = json.loads((ROOT / "deploy/uap-observer.json").read_text())
        self.assertEqual(observer["cli_release_tag"], e2e.TRUSTED_CLI_RELEASE_TAG)
        self.assertEqual(observer["policies"], [{
            "repository": e2e.TRUSTED_CATALOG_REPOSITORY,
            "repository_id": e2e.TRUSTED_CATALOG_REPOSITORY_ID,
            "repository_owner_id": e2e.TRUSTED_CATALOG_REPOSITORY_OWNER_ID,
            "ref": e2e.TRUSTED_OBSERVER_REF,
            "ref_type": "branch",
            "environment": e2e.TRUSTED_OBSERVER_ENVIRONMENT,
            "workflow_ref": e2e.TRUSTED_OBSERVER_WORKFLOW_REF,
            "job_workflow_ref": e2e.TRUSTED_OBSERVER_JOB_WORKFLOW_REF,
            "workflow": "Signed Directory publication",
            "event_names": ["push", "workflow_dispatch"],
            "job_name_suffix": "protected-observer-inputs",
        }])

    def test_hero_contract_is_exactly_five_by_three(self) -> None:
        scenarios = json.loads(e2e.SCENARIOS.read_text())
        self.assertEqual(
            scenarios["heroes"],
            ["agent-code-navigator", "chrome-devtools", "context7", "cloudflare-docs", "notion"],
        )
        self.assertEqual(scenarios["runtime_clients"], ["codex", "cursor", "kiro"])
        expected_rows = len(scenarios["heroes"]) * len(scenarios["runtime_clients"])
        self.assertEqual(expected_rows, 15)
        self.assertEqual(scenarios["expected_counts"]["hero_lifecycle_rows"], expected_rows)
        self.assertEqual(scenarios["expected_counts"]["hero_runtime_rows"], expected_rows)
        self.assertEqual(e2e.EXPECTED_COUNTS["hero_lifecycle_rows"], expected_rows)
        self.assertEqual(e2e.EXPECTED_COUNTS["hero_runtime_rows"], expected_rows)

    def test_production_identity_rejects_configured_repository_or_tag_changes(self) -> None:
        original = json.loads(e2e.PRODUCTION_CONFIG.read_text())
        for field, changed in (
            ("catalog_repository", "attacker/catalog"),
            ("cli_release_repository", "attacker/binaries"),
            ("cli_release_tag", "agentplugins-v0.1.9"),
            ("cli_release_workflow", "attacker/repo/.github/workflows/agentplugins-release.yml"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "production-launch.json"
                path.write_text(json.dumps({**original, field: changed}))
                with mock.patch.object(e2e, "PRODUCTION_CONFIG", path), self.assertRaisesRegex(ValueError, "configuration is invalid"):
                    e2e.read_production_config()

    def test_signed_directory_fixture_binds_origin_digest_sequence_and_trust(self) -> None:
        env, snapshot, digest = e2e.validated_directory_environment(
            "https://directory.example.test/registry/",
            PUBLICATION / "snapshot.json",
            PUBLICATION / "envelope-current.json",
            PUBLICATION / "trusted-keys.json",
        )
        self.assertEqual(snapshot["sequence"], 7)
        self.assertEqual(digest, json.loads((PUBLICATION / "envelope-current.json").read_text())["snapshot_digest"])
        self.assertNotIn("CATALOG", " ".join(env))
        self.assertIn("AGENTPLUGINS_DIRECTORY_ORIGIN", env)
        self.assertEqual(set(env), e2e.DIRECTORY_INPUT_ENVIRONMENT_KEYS)

    def test_real_binary_directory_environment_has_exact_conformance_tuple(self) -> None:
        directory_environment = {
            "AGENTPLUGINS_DIRECTORY_ORIGIN": "https://directory.example.test/registry/",
            "AGENTPLUGINS_DIRECTORY_SNAPSHOT": str(PUBLICATION / "snapshot.json"),
            "AGENTPLUGINS_DIRECTORY_ENVELOPE": str(PUBLICATION / "envelope-current.json"),
            "AGENTPLUGINS_DIRECTORY_TRUST": str(PUBLICATION / "trusted-keys.json"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "scenario"
            sandbox.mkdir()
            env = e2e.isolated_environment(sandbox, ("cursor",), directory_environment)
        directory_keys = {key for key in env if key.startswith("AGENTPLUGINS_DIRECTORY_")}
        self.assertEqual(directory_keys, e2e.DIRECTORY_LAUNCH_ENVIRONMENT_KEYS)
        self.assertEqual(env["AGENTPLUGINS_DIRECTORY_CONFORMANCE_ONLY"], "1")

    def test_partial_real_binary_directory_environment_is_rejected(self) -> None:
        partial = {
            "AGENTPLUGINS_DIRECTORY_ORIGIN": "https://directory.example.test/registry/",
            "AGENTPLUGINS_DIRECTORY_SNAPSHOT": str(PUBLICATION / "snapshot.json"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "scenario"
            sandbox.mkdir()
            with self.assertRaisesRegex(ValueError, "complete origin/snapshot/envelope/trust tuple"):
                e2e.isolated_environment(sandbox, ("cursor",), partial)

    def test_disposable_root_must_be_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                self.fixture_harness(Path(tmp))

    def test_isolated_environment_has_separate_roots_and_drops_auth(self) -> None:
        inherited = {"PATH": "/bin", "HOME": "/real/home", "GITHUB_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret"}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, inherited, clear=True):
            sandbox = Path(tmp) / "scenario"
            sandbox.mkdir()
            env = e2e.isolated_environment(sandbox, ("codex", "cursor", "kiro"))
            roots = {env[name] for name in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "AGENTPLUGINS_HOME", "AGENTPLUGINS_EVIDENCE_ROOT")}
            self.assertEqual(len(roots), 5)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertTrue(all(Path(path).is_relative_to(sandbox) for path in roots))

    def test_driver_result_outside_disposable_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "scenario"
            sandbox.mkdir()
            with self.assertRaisesRegex(ValueError, "outside the disposable root"):
                e2e.LaunchHarness._assert_result_paths({"evidence_path": "/real/project/result.json"}, sandbox)

    def test_info_reconciliation_requires_exact_boolean_proofs(self) -> None:
        authoritative = {
            "receipt_reconciled": True, "native_discovery_reconciled": True,
            "client_version": "cursor-1.2.3",
            "native_discovery_evidence": {
                "basis": "protected_external_observer",
                "observer": "native-client-command-v1", "client": "cursor",
                "version_operation": {"operation": "version", "argv": ["cursor", "--version"], "observed_client_version": "cursor-1.2.3"},
                "discovery_operation": {"operation": "list", "argv": ["cursor", "plugins", "list"], "discovered": True, "product_id": "context7"},
            },
        }
        self.assertTrue(e2e.LaunchHarness.info_reconciled(authoritative))
        self.assertFalse(e2e.LaunchHarness.info_reconciled({"receipt_reconciled": True, "native_discovery_reconciled": True}))
        self.assertFalse(e2e.LaunchHarness.info_reconciled({"receipts": ["owned"], "discovery": {"state": "found"}}))
        self.assertFalse(e2e.LaunchHarness.info_reconciled({"receipt_reconciled": True, "native_discovery_reconciled": False}))
        missing_observer = json.loads(json.dumps(authoritative))
        del missing_observer["native_discovery_evidence"]["observer"]
        self.assertFalse(e2e.LaunchHarness.info_reconciled(missing_observer, "cursor"))
        wrong_client = json.loads(json.dumps(authoritative))
        wrong_client["native_discovery_evidence"]["client"] = "codex"
        self.assertFalse(e2e.LaunchHarness.info_reconciled(wrong_client, "cursor"))

    def test_repository_owned_proof_cannot_be_promoted_to_discovery(self) -> None:
        harness = self.fixture_harness()
        details = {
            "evidence_basis": "repository_owned_disposable_observer",
            "runtime_proof": False, "native_discovery_proof": False,
        }
        tuple_value = harness.tuple(client_version="native-state-v1")
        harness.add("local-materialization", "context7", "cursor", "materialization", "passed", "proved", tuple_value=tuple_value, details=details)
        harness.add("fake-discovery", "context7", "cursor", "discovery", "passed", "claimed", tuple_value=tuple_value, details=details)
        self.assertEqual(harness.rows[0]["outcome"], "passed")
        self.assertIsNone(harness.rows[0]["tuple"]["client_version"])
        self.assertEqual(harness.rows[1]["outcome"], "inconclusive")
        self.assertIsNone(harness.rows[1]["tuple"]["client_version"])

    def test_all_package_native_proof_is_exact_copilot_lifecycle(self) -> None:
        valid = {
            "basis": "native_client_command",
            "version_operation": {
                "argv": ["copilot", "--version"], "observed_client_version": "1.0.80",
            },
            "discovery_operation": {
                "argv": ["copilot", "plugin", "list"], "discovered": True,
                "product_id": "context7@agentplugins-f36027996b7a",
            },
        }
        validate = lambda evidence: e2e.authoritative_repository_copilot_evidence(
            evidence, client_version="1.0.80", product_id="context7", expected_version="1.0.80",
        )
        self.assertTrue(validate(valid))
        for path, value in (
            (("basis",), "protected_external_observer"),
            (("version_operation", "argv"), ["sh", "-c", "copilot --version"]),
            (("version_operation", "observed_client_version"), "1.0.79"),
            (("discovery_operation", "argv"), ["copilot", "plugin", "list", "--fixture"]),
            (("discovery_operation", "product_id"), "context7"),
            (("discovery_operation", "product_id"), "context7@agentplugins-xyz"),
            (("discovery_operation", "product_id"), "other@agentplugins-f36027996b7a"),
            (("discovery_operation", "discovered"), False),
        ):
            mutated = json.loads(json.dumps(valid))
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            self.assertFalse(validate(mutated), path)
        self.assertFalse(e2e.authoritative_repository_copilot_evidence(
            valid, client_version="1.0.79", product_id="context7", expected_version="1.0.80",
        ))
        harness = self.fixture_harness()
        with mock.patch.object(harness, "directory_release", return_value={}):
            client, _ = harness.all_package_client("context7")
        self.assertEqual(client, "copilot")
        harness.config = {**harness.config, "all_package_client": "cursor"}
        with self.assertRaisesRegex(ValueError, "GitHub Copilot CLI"):
            harness.all_package_client("context7")

    def test_copilot_installation_metadata_is_exact_and_confined(self) -> None:
        config = e2e.read_production_config()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            executable = root / "copilot"
            executable.write_bytes(b"exact copilot executable")
            executable.chmod(0o755)
            metadata_path = root / "copilot-metadata.json"
            metadata_path.write_text("{}")
            metadata = {
                "schema_version": 1,
                "package": config["copilot_cli_package"],
                "version": config["copilot_cli_version"],
                "integrity": config["copilot_cli_integrity"],
                "node_major": 22,
                "signature_audit": True,
                "version_argv": ["copilot", "--version"],
                "observed_version": "1.0.80",
                "executable_digest": e2e.sha256_file(executable),
                "version_stdout_digest": "sha256:" + "a" * 64,
            }
            validate = lambda value, path=executable: e2e.valid_copilot_installation(
                path, metadata_path, value, root, config,
            )
            self.assertTrue(validate(metadata))
            for key, replacement in (
                ("version", "1.0.79"),
                ("integrity", "sha512-untrusted"),
                ("signature_audit", False),
                ("observed_version", "1.0.79"),
                ("executable_digest", "sha256:" + "b" * 64),
            ):
                self.assertFalse(validate({**metadata, key: replacement}), key)
            outside = Path(tmp) / "outside-copilot"
            outside.write_bytes(executable.read_bytes())
            outside.chmod(0o755)
            self.assertFalse(validate(metadata, outside))
            escaped_link = root / "escaped-copilot"
            escaped_link.symlink_to(outside)
            self.assertFalse(validate(metadata, escaped_link))

    def test_external_observer_schema_cannot_supply_all_package_discovery(self) -> None:
        schema = json.loads((ROOT / "tests/e2e/schemas/runtime-attestations.schema.json").read_text())
        item = schema["properties"]["attestations"]["items"]
        self.assertNotIn("copilot", item["properties"]["client"]["enum"])
        self.assertNotIn("discovery", item["properties"]["level"]["enum"])
        self.assertNotIn("all_26_info", item["properties"]["scenario_id"]["enum"])
        self.assertNotIn("lifecycle_verified", item["properties"])
        self.assertNotIn("lifecycle_operations", item["properties"])
        self.assertNotIn("copilot", schema["$defs"]["nativeDiscoveryEvidence"]["properties"]["client"]["enum"])
        launch = json.loads((ROOT / "tests/e2e/schemas/launch-evidence.schema.json").read_text())
        discovery_rule = launch["properties"]["matrix"]["items"]["allOf"][0]
        self.assertEqual(discovery_rule["then"]["properties"]["details"]["properties"]["evidence_basis"]["const"], "native_client_command")
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "external.json"
            artifact.write_text(json.dumps({
                "schema_version": 1,
                "attestations": [{
                    "plugin": "context7", "client": "copilot",
                    "level": "discovery", "outcome": "passed",
                }],
            }))
            with self.assertRaisesRegex(ValueError, "unsupported level"):
                self.fixture_harness()._load_attestations(artifact)

    def test_all_package_info_fails_closed_on_incomplete_native_copilot_result(self) -> None:
        digest = "sha256:" + "a" * 64
        release = {
            "tree_digest": digest, "manifest_digest": digest,
            "distribution_id": "fixture/upstream", "distribution_kind": "upstream",
            "release_sequence": 1, "package_version": "1.0.0",
            "source_repository": "owner/repository", "source_revision": "b" * 40,
            "source_path": "plugins/fixture",
        }
        products = [{"id": f"plugin-{index}"} for index in range(26)]

        def run_with(mutate):
            harness = self.fixture_harness()
            harness.snapshot = {"products": products}
            harness.snapshot_digest = digest
            harness.config = {**harness.config, "all_package_operations": ["info"]}

            def command(argv, _sandbox, _clients):
                plugin = argv[1]
                value = {
                    "tree_digest": digest, "receipt_reconciled": True,
                    "native_discovery_reconciled": True, "native_identity_state": "managed",
                    "client_version": "1.0.80",
                    "native_discovery_evidence": {
                        "basis": "native_client_command",
                        "version_operation": {
                            "argv": ["copilot", "--version"], "observed_client_version": "1.0.80",
                        },
                        "discovery_operation": {
                            "argv": ["copilot", "plugin", "list"], "discovered": True,
                            "product_id": f"{plugin}@agentplugins-f36027996b7a",
                        },
                    },
                }
                mutate(value)
                return "passed", value, "reconciled"

            with mock.patch.object(harness, "fresh_sandbox", return_value=Path("/tmp/disposable")), \
                    mock.patch.object(harness, "all_package_client", return_value=("copilot", release)), \
                    mock.patch.object(harness, "directory_release", return_value=release), \
                    mock.patch.object(harness, "command_matches_release", return_value=True), \
                    mock.patch.object(harness, "command", side_effect=command):
                harness.all_package_matrix()
            return harness.rows

        self.assertTrue(all(row["outcome"] == "passed" for row in run_with(lambda _value: None)))
        self.assertTrue(all(row["details"]["native_identity_state"] == "managed" for row in run_with(lambda _value: None)))
        for mutation in (
            lambda value: value.pop("client_version"),
            lambda value: value.update(native_identity_state="copied"),
            lambda value: value["native_discovery_evidence"]["version_operation"].update(observed_client_version="1.0.79"),
            lambda value: value["native_discovery_evidence"]["discovery_operation"].update(argv=["sh", "-c", "copilot plugin list"]),
            lambda value: value["native_discovery_evidence"]["discovery_operation"].update(product_id="plugin-0"),
        ):
            self.assertTrue(all(row["outcome"] == "failed" for row in run_with(mutation)))

    def test_notion_records_are_exact_separate_and_all_passed(self) -> None:
        expected = {("notion", client, "runtime"): {"outcome": "passed"} for client in ("codex", "cursor", "kiro")}
        cases = (
            ({("notion", "codex", "runtime"): {"outcome": "passed"}}, expected, "primary runtime artifact"),
            ({}, {key: value for key, value in expected.items() if key[1] != "kiro"}, "exactly codex"),
            ({}, {key: ({"outcome": "failed"} if key[1] == "kiro" else value) for key, value in expected.items()}, "all Notion runtime records"),
        )
        for primary, notion, message in cases:
            with self.subTest(message=message), mock.patch.object(
                e2e.LaunchHarness, "_load_attestations", side_effect=[primary, notion, {}],
            ), self.assertRaisesRegex(ValueError, message):
                e2e.LaunchHarness(None, None, mode="fixture-only", consent=CONSENT)

    def test_empty_or_materialized_client_directories_never_become_native_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, manager = root / "home", root / "manager"
            (home / ".cursor").mkdir(parents=True)
            environment = {"HOME": str(home), "AGENTPLUGINS_HOME": str(manager)}
            empty = e2e.observed_state_identity(environment, "context7", ("cursor",))
            self.assertIsNone(empty["client_version"])
            self.assertFalse(empty["native_discovery_reconciled"])
            self.assertEqual(empty["evidence_basis"], "fixture_materialization")
            (home / ".cursor" / "context7.json").write_text('{"product":"context7"}')
            materialized = e2e.observed_state_identity(environment, "context7", ("cursor",))
            self.assertIsNone(materialized["client_version"])
            self.assertFalse(materialized["native_discovery_reconciled"])

    def test_no_newer_release_update_accepts_only_a_truthful_noop(self) -> None:
        update = release_fixture("local-update.json")
        self.assertTrue(observer.validate_cli_envelope(update, "update"))
        self.assertTrue(all(item["output"]["result"]["no_change"] for item in update["data"]["targets"]))
        forged = json.loads(json.dumps(update))
        forged["data"]["targets"][0]["output"]["result"]["mutated"] = True
        self.assertFalse(observer.validate_cli_envelope(forged, "update"))
    def test_mutable_refs_and_unknown_outcomes_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "mutable refs"):
            e2e.LaunchHarness._reject_mutable_refs({"ref": "main"})
        with tempfile.TemporaryDirectory() as tmp:
            attestation = Path(tmp) / "attestation.json"
            attestation.write_text(json.dumps({"schema_version": 1, "attestations": [{"plugin": "context7", "client": "codex", "level": "runtime", "outcome": "not_tested", "tuple": {}}]}))
            with self.assertRaisesRegex(ValueError, "invalid attestation outcome"):
                e2e.LaunchHarness(None, attestation, mode="fixture-only", consent=CONSENT)

    def test_duplicate_tuples_and_broad_chatgpt_claims_are_rejected(self) -> None:
        evidence = self.fixture_harness().export()
        evidence["matrix"].append(dict(evidence["matrix"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate tuples"):
            e2e.assert_redacted(evidence)
        evidence = self.fixture_harness().export()
        evidence["matrix"].append({**evidence["matrix"][0], "id": "a" * 24, "scenario": "chatgpt", "plugin": "notion", "client": "chatgpt"})
        with self.assertRaisesRegex(ValueError, "ChatGPT"):
            e2e.assert_redacted(evidence)

    def test_launch_schema_rejects_unknown_outcome_and_mutable_ref(self) -> None:
        schema = json.loads((ROOT / "tests/e2e/schemas/launch-evidence.schema.json").read_text())
        evidence = self.fixture_harness().export()
        evidence["matrix"][0]["outcome"] = "not_tested"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(evidence)
        evidence = self.fixture_harness().export()
        evidence["matrix"][0]["details"]["ref"] = "main"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(evidence)

    def test_context7_contract_requires_one_three_target_grouped_lifecycle(self) -> None:
        harness = self.fixture_harness()
        harness.snapshot = {
            "sequence": 1,
            "evidence": [],
            "products": [{"id": "context7", "aliases": ["context7"], "default_distribution": "upstash/context7", "distributions": ["upstash/context7"], "minimum_capabilities": {"mcp": "required"}}],
            "distributions": [{"id": "upstash/context7", "product_id": "context7", "kind": "community", "status": "active", "release_policies": [{"release_sequence": 1, "status": "active", "current_evidence": [], "targets": [{"client": "codex", "scopes": ["user"]}, {"client": "cursor", "scopes": ["user"]}, {"client": "kiro", "scopes": ["user"]}]}], "releases": [{"sequence": 1, "components": ["mcp"], "package_version": "1.0.0", "tree_digest": "sha256:" + "a" * 64, "manifest_digest": "sha256:" + "b" * 64, "package_source": {"repository": "upstash/context7", "revision": "1" * 40, "path": "plugins/context7"}}]}],
        }
        harness.snapshot_digest = "sha256:" + "c" * 64
        harness.binary_digest = "sha256:" + "d" * 64
        harness.expected_version = "0.1.14"
        commands = [[operation, "context7", "--target", "codex,cursor,kiro", "--format", "json"] for operation in ("add", "update", "repair", "remove")]
        acquisition = {
            "acquisition_id": "fetch-1", "acquisition_count": 1,
            "tree_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "b" * 64,
            "closure_digest": observer.grouped_acquisition_closure_digest(
                "directory", "upstash/context7", "plugins/context7", "1" * 40,
                "sha256:" + "a" * 64, "sha256:" + "b" * 64,
            ),
            "source_kind": "directory", "fetched": True, "validated": True,
            "source_repository": "upstash/context7", "source_revision": "1" * 40,
            "source_path": "plugins/context7",
            "targets": [{"target": client} for client in ("codex", "cursor", "kiro")],
        }
        acquisition["target_outcomes"] = {
            client: {
                "outcome": "passed", "acquisition_id": "fetch-1",
                "tree_digest": acquisition["tree_digest"],
                "manifest_digest": acquisition["manifest_digest"],
                "closure_digest": acquisition["closure_digest"],
            }
            for client in ("codex", "cursor", "kiro")
        }
        value = {
            "commands": commands, "acquisition_digests": ["sha256:" + "a" * 64],
            "acquisition": acquisition,
            "target_outcomes": {client: "passed" for client in ("codex", "cursor", "kiro")},
            "operation_outcomes": {operation: "passed" for operation in ("add", "update", "repair", "remove")},
            "tuple": harness.evidence_tuple("context7", ["codex", "cursor", "kiro"], client_version="driver", dependency="single-acquisition"),
        }
        with mock.patch.object(harness, "driven_scenario", return_value=("passed", value, "proved")):
            harness.context7_multi_target()
        self.assertEqual([row["outcome"] for row in harness.rows], ["passed"] * 4)
        self.assertTrue(all(row["details"]["evidence_basis"] == "repository_owned_disposable_observer" for row in harness.rows))
        self.assertTrue(all(row["details"]["target_argument"] == "codex,cursor,kiro" for row in harness.rows))
        self.assertTrue(all(row["details"]["acquisition"] == acquisition for row in harness.rows))
        self.assertNotIn("--yes", commands[0])

        invalid = json.loads(json.dumps(value))
        del invalid["acquisition"]["closure_digest"]
        rejected = self.fixture_harness()
        rejected.snapshot = harness.snapshot
        rejected.snapshot_digest = harness.snapshot_digest
        rejected.binary_digest = harness.binary_digest
        rejected.expected_version = harness.expected_version
        with mock.patch.object(rejected, "driven_scenario", return_value=("passed", invalid, "claimed")):
            rejected.context7_multi_target()
        self.assertEqual([row["outcome"] for row in rejected.rows], ["failed"] * 4)

    def test_repository_observer_derives_grouped_lifecycle_from_receipts_and_native_files(self) -> None:
        add = release_fixture("add.json")
        self.assertIsNotNone(observer.grouped_acquisition_proof(add, ("codex", "cursor", "kiro")))
    def test_grouped_acquisition_proof_fails_closed_when_event_is_missing_or_ambiguous(self) -> None:
        valid = release_fixture("add.json")
        clients = ("codex", "cursor", "kiro")
        self.assertIsNotNone(observer.grouped_acquisition_proof(valid, clients))
        for mutation in (
            {**valid, "command": "update"},
            {**valid, "data": {**valid["data"], "targets": valid["data"]["targets"][:-1]}},
            {**valid, "data": {**valid["data"], "target_outcomes": {"codex": valid["data"]["target_outcomes"]["codex"]}}},
        ):
            self.assertIsNone(observer.grouped_acquisition_proof(mutation, clients))
    def test_raw_cli_json_rejects_duplicate_keys_and_non_integer_schema_versions(self) -> None:
        event = '{"acquisition_id":"fetch-1","acquisition_count":1,"tree_digest":"sha256:' + "a" * 64 + '","manifest_digest":"sha256:' + "b" * 64 + '","closure_digest":"sha256:' + "c" * 64 + '","source_kind":"github","fetched":true,"validated":true}'
        binding = '{"outcome":"passed","acquisition_id":"fetch-1","tree_digest":"sha256:' + "a" * 64 + '","manifest_digest":"sha256:' + "b" * 64 + '","closure_digest":"sha256:' + "c" * 64 + '"}'
        outcomes = '"codex":' + binding + ',"cursor":' + binding + ',"kiro":' + binding
        prefix = '{"schema_version":1,"command":"add","result":"success","data":{'
        duplicate_proof = prefix + '"acquisition":' + event + ',"acquisition":' + event + ',"target_outcomes":{' + outcomes + '}}}'
        duplicate_client = prefix + '"acquisition":' + event + ',"target_outcomes":{' + outcomes + ',"cursor":' + binding + '}}}'
        for raw in (duplicate_proof, duplicate_client):
            completed = subprocess.CompletedProcess(["agentplugins"], 0, stdout=raw, stderr="")
            self.assertIsNone(observer.json_output(completed))
        for version in (True, 1.0):
            value = {
                "schema_version": version, "command": "add", "result": "success",
                "data": {"acquisition": json.loads(event), "target_outcomes": json.loads("{" + outcomes + "}")},
            }
            completed = subprocess.CompletedProcess(["agentplugins"], 0, stdout=json.dumps(value), stderr="")
            self.assertIsNone(observer.grouped_acquisition_proof(observer.json_output(completed), ("codex", "cursor", "kiro")))

    def test_exact_agentplugins_0_1_14_stdout_and_state_v4_fixtures(self) -> None:
        stdout_bytes, add_fixture = self.agentplugins_0_1_14_add_fixture()
        state_text, state_fixture = self.agentplugins_0_1_14_state_fixture()
        state_bytes = state_text.encode()
        completed = subprocess.CompletedProcess(
            ["agentplugins", "add", "context7", "--target", "codex,cursor,kiro", "--format", "json"],
            0, stdout_bytes.decode(), "",
        )
        envelope = observer.json_output(completed, "add")
        self.assertIsNotNone(envelope)
        proof = observer.grouped_acquisition_proof(envelope, ("codex", "cursor", "kiro"))
        self.assertEqual(
            (proof["source_repository"], proof["source_revision"], proof["source_path"]),
            ("upstash/context7", "769c6cd22c3d95462d1f55d789e9532cabefa5a9", "plugins/agent-plugins/context7"),
        )
        self.assertEqual([item["target"] for item in proof["targets"]], ["codex", "cursor", "kiro"])
        fixture_installation = state_fixture["installations"][0]
        self.assertEqual(
            add_fixture["data"]["targets"][0]["output"]["result"]["installation_id"],
            fixture_installation["installation_id"],
        )
        self.assertEqual(add_fixture["data"]["tree_digest"], fixture_installation["source"]["tree_digest"])
        self.assertEqual(add_fixture["data"]["manifest_digest"], fixture_installation["package"]["manifest_digest"])
        duplicated_target = json.loads(json.dumps(envelope))
        duplicated_target["data"]["targets"].append(duplicated_target["data"]["targets"][0])
        self.assertIsNone(observer.grouped_acquisition_proof(duplicated_target, ("codex", "cursor", "kiro")))
        with tempfile.TemporaryDirectory() as tmp:
            manager = Path(tmp)
            (manager / "state-v2.json").write_bytes(state_bytes)
            installation = observer.selected_manager_installation(manager, "context7")
            receipts = observer.installation_receipts(manager, "context7")
            self.assertEqual(installation["operation_group_id"], envelope["data"]["operation_id"])
            self.assertEqual([item["binding_client"] for item in receipts], ["cursor", "codex", "kiro"])
            self.assertTrue(all(item["receipt"]["phase"] == "committed" for item in receipts))

    def test_all_real_0_1_14_lifecycle_and_migration_envelopes_are_exact(self) -> None:
        fixtures = {
            "add.json": "add", "local-add.json": "add", "info.json": "info",
            "local-update.json": "update", "repair.json": "repair", "remove.json": "remove",
            "migrate-dry-run.json": "migrate-state", "migrate-apply.json": "migrate-state",
        }
        for name, command in fixtures.items():
            with self.subTest(name=name):
                self.assertTrue(observer.validate_cli_envelope(release_fixture(name), command))
        local = release_fixture("local-add.json")
        local_proof = observer.grouped_acquisition_proof(local, ("codex", "cursor", "kiro"))
        self.assertEqual(local_proof["source_kind"], "local")
        self.assertEqual((local_proof["source_repository"], local_proof["source_revision"], local_proof["source_path"]), ("", "", ""))
        update = release_fixture("local-update.json")
        self.assertTrue(all(
            item["selected"] is True and item["output"]["result"]["mutated"] is False
            and item["output"]["result"]["no_change"] is True
            and item["output"]["result"]["group_phase"] == "external_completed"
            for item in update["data"]["targets"]
        ))

    def test_real_envelopes_reject_wrong_commands_target_forgery_and_identity_mismatch(self) -> None:
        add = release_fixture("add.json")
        mutations = []
        for command in ("update", "repair", "remove", "migrate-state"):
            mutations.append({**add, "command": command})
        mutations.extend((
            {**add, "result": "failure"},
            {**add, "data": {**add["data"], "targets": add["data"]["targets"][:-1], "succeeded": 2}},
            {**add, "data": {**add["data"], "targets": [*add["data"]["targets"], add["data"]["targets"][0]], "succeeded": 4}},
        ))
        partial = json.loads(json.dumps(add))
        partial["data"]["targets"][0]["status"] = "external_partial"
        mutations.append(partial)
        unknown = json.loads(json.dumps(add))
        unknown["data"]["targets"][0]["output"]["result"]["group_phase"] = "managed_unknown"
        mutations.append(unknown)
        install = json.loads(json.dumps(add))
        install["data"]["targets"][0]["output"]["result"]["installation_id"] = "other"
        mutations.append(install)
        digest = json.loads(json.dumps(add))
        digest["data"]["targets"][0]["output"]["tree_digest"] = "sha256:" + "9" * 64
        mutations.append(digest)
        revision = json.loads(json.dumps(add))
        revision["data"]["targets"][0]["output"]["revision"] = "2" * 40
        mutations.append(revision)
        outcome = json.loads(json.dumps(add))
        outcome["data"]["target_outcomes"]["codex"]["outcome"] = "partial"
        mutations.append(outcome)
        for mutation in mutations:
            with self.subTest(mutation=mutation.get("command")):
                self.assertFalse(observer.validate_cli_envelope(mutation, "add"))

    def test_closure_digest_is_domain_separated_length_prefixed_and_origin_bound(self) -> None:
        github = release_fixture("add.json")
        proof = observer.grouped_acquisition_proof(github, ("codex", "cursor", "kiro"))
        self.assertEqual(
            proof["closure_digest"],
            observer.grouped_acquisition_closure_digest(
                "github", proof["source_repository"], proof["source_path"], proof["source_revision"],
                proof["tree_digest"], proof["manifest_digest"],
            ),
        )
        for field, replacement in (
            ("source_kind", "directory"), ("tree_digest", "sha256:" + "9" * 64),
            ("manifest_digest", "sha256:" + "8" * 64),
        ):
            forged = json.loads(json.dumps(github))
            forged["data"]["acquisition"][field] = replacement
            self.assertIsNone(observer.grouped_acquisition_proof(forged, ("codex", "cursor", "kiro")))

    def test_migration_envelopes_reject_old_flags_shapes_and_inconsistent_counts(self) -> None:
        dry = release_fixture("migrate-dry-run.json")
        applied = release_fixture("migrate-apply.json")
        for mutation in (
            {**dry, "data": {**dry["data"], "status": "dry_run", "mutated": False}},
            {**dry, "data": {**dry["data"], "backup_created": True}},
            {**applied, "data": {**applied["data"], "migrated": 0}},
            {**applied, "data": {**applied["data"], "source_schema": 4}},
            {**applied, "data": {**applied["data"], "installations": True}},
        ):
            self.assertFalse(observer.validate_cli_envelope(mutation, "migrate-state"))
        self.assertTrue(observer.copy_ready_migration_guidance("agentplugins migrate-state --dry-run\nagentplugins migrate-state"))
        self.assertFalse(observer.copy_ready_migration_guidance("agentplugins migrate-state --dry-run\nagentplugins migrate-state --expected-digest sha256:bad"))

    def test_state_v4_boundary_rejects_symlinks_duplicates_ambiguity_and_split_authority(self) -> None:
        raw, state = self.agentplugins_0_1_14_state_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            manager = Path(tmp)
            state_path = manager / "state-v2.json"
            target = manager / "outside.json"
            target.write_text(json.dumps(state))
            state_path.symlink_to(target)
            self.assertIsNone(observer.manager_state(manager))
            state_path.unlink()
            state_path.write_text(json.dumps(state))
            (manager / "arbitrary.json").write_text('{"installations":[{"declared_name":"context7"}]}')
            self.assertIsNotNone(observer.selected_manager_installation(manager, "context7"))
            ambiguous = json.loads(json.dumps(state))
            ambiguous["installations"].append(ambiguous["installations"][0])
            state_path.write_text(json.dumps(ambiguous))
            self.assertIsNone(observer.selected_manager_installation(manager, "context7"))
            unrelated = json.loads(json.dumps(state))
            second = json.loads(json.dumps(unrelated["installations"][0]))
            second["installation_id"] = "other-installation"
            second["declared_name"] = second["package"]["declared_name"] = "other"
            unrelated["installations"].append(second)
            state_path.write_text(json.dumps(unrelated))
            self.assertIsNone(observer.selected_manager_installation(manager, "context7"))
            split = json.loads(json.dumps(state))
            binding = next(iter(split["installations"][0]["clients"].values()))
            binding["receipts"][0]["client_binding_id"] = "other-binding"
            state_path.write_text(json.dumps(split))
            self.assertIsNone(observer.installation_receipts(manager, "context7"))
            malformed_receipts = json.loads(json.dumps(state))
            malformed_receipts["installations"][0]["data_receipts"] = []
            state_path.write_text(json.dumps(malformed_receipts))
            self.assertIsNone(observer.manager_state(manager))
            state_path.write_text(raw.replace('"schema_version": 4', '"schema_version": 4, "schema_version": 4', 1))
            self.assertIsNone(observer.manager_state(manager))
            for invalid_version in (True, 4.0):
                invalid = json.loads(json.dumps(state))
                invalid["schema_version"] = invalid_version
                state_path.write_text(json.dumps(invalid))
                self.assertIsNone(observer.manager_state(manager))

    def test_non_add_envelopes_require_exact_command_result_status_and_fields(self) -> None:
        valid = {"info": release_fixture("info.json"), "repair": release_fixture("repair.json"), "remove": release_fixture("remove.json")}
        for command, envelope in valid.items():
            self.assertTrue(observer.validate_cli_envelope(envelope, command))
            for mutation in (
                {**envelope, "schema_version": True},
                {**envelope, "schema_version": 1.0},
                {**envelope, "command": "wrong"},
                {**envelope, "result": "failure"},
                {**envelope, "data": {}},
            ):
                self.assertFalse(observer.validate_cli_envelope(mutation, command))

    def test_filesystem_snapshot_covers_symlink_empty_directory_mode_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty"
            empty.mkdir()
            body = root / "body"
            body.write_bytes(b"one")
            link = root / "link"
            link.symlink_to("body")
            with self.assertRaisesRegex(ValueError, "unsupported filesystem object"):
                observer.filesystem_snapshot(root)
            link.unlink()
            before = observer.filesystem_snapshot(root)
            empty.chmod(0o700)
            body.write_bytes(b"two")
            after = observer.filesystem_snapshot(root)
            self.assertEqual(before["empty"]["kind"], "directory")
            self.assertNotEqual(before["empty"]["mode"], after["empty"]["mode"])
            self.assertNotEqual(before["body"]["digest"], after["body"]["digest"])

    def test_marker_creation_rejects_leaf_symlink_and_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locator = root / "owned"
            locator.mkdir()
            (locator / "marker").symlink_to(root / "outside")
            self.assertIsNone(observer.create_contained_marker(locator, (root,), "marker", b"proof"))
            (locator / "marker").unlink()
            original_open = os.open
            swapped = False

            def replacing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if not swapped and Path(path) == locator:
                    swapped = True
                    locator.rename(root / "old-owned")
                    locator.mkdir()
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(observer.os, "open", side_effect=replacing_open):
                self.assertIsNone(observer.create_contained_marker(locator, (root,), "marker", b"proof"))
            self.assertFalse((locator / "marker").exists())

    def test_conforming_stdout_without_lifecycle_mutation_fails(self) -> None:
        fixture_root = AGENTPLUGINS_0_1_14_FIXTURES
        fake = f'''#!/usr/bin/python3
import pathlib, sys
fixtures = pathlib.Path({str(AGENTPLUGINS_0_1_14_FIXTURES)!r})
name = {{"add":"add.json", "update":"local-update.json", "repair":"repair.json", "info":"info.json", "remove":"remove.json"}}[sys.argv[1]]
print((fixtures / name).read_text(), end="")
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "agentplugins"
            binary.write_text(fake)
            binary.chmod(0o700)
            home, manager, workspace = root / "home", root / "manager", root / "workspace"
            workspace.mkdir()
            context = {
                "release": {"product_id": "context7", "tree_digest": "sha256:" + "a" * 64, "manifest_digest": "sha256:" + "b" * 64, "distribution_id": "upstash/context7", "distribution_kind": "upstream", "release_sequence": 1, "package_version": "1.0.0", "source_repository": "upstash/context7", "source_revision": "1" * 40, "source_path": "plugins/agent-plugins/context7"},
                "snapshot_sequence": 1, "directory_digest": "sha256:" + "c" * 64,
                "binary_digest": "sha256:" + "d" * 64, "expected_version": "0.1.14",
            }
            with mock.patch.dict(os.environ, {"HOME": str(home), "AGENTPLUGINS_HOME": str(manager)}, clear=False):
                passed, value = observer.lifecycle(binary, "context7", ("codex", "cursor", "kiro"), workspace, "challenge", context, include_repair=True)
        self.assertFalse(passed, value)
        self.assertEqual(value["operation_outcomes"]["add"], "failed")

    def test_captured_full_sha_failure_requires_exact_envelope_stderr_and_argv(self) -> None:
        value = release_fixture("direct-update-failure.json")
        stderr = (AGENTPLUGINS_0_1_14_FIXTURES / "direct-update-failure.stderr.txt").read_text()
        kwargs = {
            "plugin": "context7", "source": "upstash/context7//plugins/agent-plugins/context7",
            "revision": "769c6cd22c3d95462d1f55d789e9532cabefa5a9",
            "tree_digest": "sha256:08eed3b67f2e71a11b68baa594380c2f69ec1bc97584d701deaf7942ac34c0d8",
            "expected_targets": ("codex", "cursor", "kiro"),
            "requested_argv": ["update", "context7", "--target", "codex,cursor,kiro", "--format", "json"],
        }
        self.assertTrue(observer.validate_full_sha_update_failure(value, stderr, **kwargs))
        forged = json.loads(json.dumps(value))
        forged["data"]["failed"] = 2
        self.assertFalse(observer.validate_full_sha_update_failure(forged, stderr, **kwargs))
        self.assertFalse(observer.validate_full_sha_update_failure(value, stderr.rstrip(), **kwargs))

    def test_capture_provenance_binds_every_retained_fixture_byte(self) -> None:
        provenance = e2e.validate_capture_provenance()
        self.assertGreaterEqual(len(provenance["captures"]), 11)
        self.assertEqual(provenance["release"]["version_stdout"], "agentplugins 0.1.14")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); fixture = root / "one.json"; fixture.write_text("{}")
            forged = json.loads(json.dumps(provenance))
            forged["captures"][0]["sanitized_sha256"] = "sha256:" + "0" * 64
            path = root / "provenance.json"; path.write_text(json.dumps(forged))
            with self.assertRaises(ValueError):
                e2e.validate_capture_provenance(path)

    def test_schema_two_capture_has_complete_cross_record_identities(self) -> None:
        state = json.loads((ROOT / "tests/e2e/fixtures/state-schema-2.json").read_text())
        self.assertTrue(observer.validate_schema_2_state(state))
        for field in ("tree_digest", "manifest_digest"):
            forged = json.loads(json.dumps(state))
            if field == "tree_digest":
                forged["installations"][0]["clients"]["client_a"]["package_revision"][field] = "sha256:" + "0" * 64
            else:
                forged["installations"][0]["clients"]["client_a"]["package_revision"][field] = "sha256:" + "0" * 64
            self.assertFalse(observer.validate_schema_2_state(forged))

    def test_state_v4_rejects_split_identity_receipt_and_path_authority(self) -> None:
        _, state = self.agentplugins_0_1_14_state_fixture()
        mutations = []
        revision = json.loads(json.dumps(state))
        next(iter(revision["installations"][0]["clients"].values()))["package_revision"]["tree_digest"] = "sha256:" + "0" * 64
        mutations.append(revision)
        duplicate = json.loads(json.dumps(state))
        bindings = list(duplicate["installations"][0]["clients"].values())
        bindings[1]["receipts"][0]["operation_id"] = bindings[0]["receipts"][0]["operation_id"]
        mutations.append(duplicate)
        escaped = json.loads(json.dumps(state))
        binding = next(iter(escaped["installations"][0]["clients"].values()))
        binding["target_locator"] = "/etc/agentplugins-context7"
        binding["native_objects"][0]["path"] = binding["target_locator"]
        binding["receipts"][0]["active_path"] = binding["target_locator"]
        mutations.append(escaped)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state-v2.json"
            for mutation in mutations:
                path.write_text(json.dumps(mutation))
                self.assertIsNone(observer.manager_state(Path(tmp)))

    def test_snapshot_revalidates_directory_binding_after_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); child = root / "child"; child.mkdir(); (child / "same").write_bytes(b"same")
            original_listdir = os.listdir
            calls = 0
            def replacing_listdir(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    child.rename(root / "old-child")
                    child.mkdir(); (child / "same").write_bytes(b"same")
                return original_listdir(descriptor)
            with mock.patch.object(observer.os, "listdir", side_effect=replacing_listdir):
                with self.assertRaisesRegex(ValueError, "directory (?:binding )?changed"):
                    observer.filesystem_snapshot(root)

    def test_migration_stdout_without_state_transition_fails(self) -> None:
        fake = f'''#!/usr/bin/python3
import pathlib, sys
fixtures = pathlib.Path({str(AGENTPLUGINS_0_1_14_FIXTURES)!r})
if sys.argv[1] == "add": raise SystemExit(2)
if sys.argv[1] == "migrate-state":
    print((fixtures / ("migrate-dry-run.json" if "--dry-run" in sys.argv else "migrate-apply.json")).read_text(), end="")
else: raise SystemExit(2)
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binary = root / "agentplugins"; binary.write_text(fake); binary.chmod(0o700)
            workspace = root / "workspace"; workspace.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(root / "home"), "AGENTPLUGINS_HOME": str(root / "manager")}, clear=False):
                passed, value = observer.migration_scenario(binary, workspace, "challenge")
        self.assertFalse(passed, value)
        self.assertFalse(value["proof"]["migration_applied"])

    def test_plugin_data_stdout_without_state_or_filesystem_mutation_fails(self) -> None:
        fake = '''#!/usr/bin/python3
import json, sys
print(json.dumps({"schema_version": 1, "command": sys.argv[1], "result": "success", "data": {}}))
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binary = root / "agentplugins"; binary.write_text(fake); binary.chmod(0o700)
            workspace = root / "workspace"; workspace.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(root / "home"), "AGENTPLUGINS_HOME": str(root / "manager")}, clear=False):
                passed, value = observer.plugin_data_scenario(binary, workspace, "challenge")
        self.assertFalse(passed, value)
        self.assertIsNone(value["initial_data_receipt"])

    def test_retained_marker_rejects_identical_file_and_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locator = root / "owned"
            locator.mkdir()
            marker = observer.create_contained_marker(locator, (root,), "marker", b"proof")
            self.assertIsNotNone(marker)
            self.assertTrue(marker.verify())
            marker.path.unlink()
            marker.path.write_bytes(b"proof")
            marker.path.chmod(0o600)
            self.assertFalse(marker.verify())
            marker.close()

            marker = observer.create_contained_marker(locator, (root,), "second", b"proof")
            original = root / "original-owned"
            locator.rename(original)
            locator.mkdir()
            (locator / "second").write_bytes(b"proof")
            (locator / "second").chmod(0o600)
            self.assertFalse(marker.verify())
            marker.close()

    def test_state_migration_observes_stale_refusal_backup_and_exact_provenance(self) -> None:
        legacy = json.loads((ROOT / "tests/e2e/fixtures/state-schema-2.json").read_text())
        self.assertEqual((legacy["schema_version"], legacy["installations"][0]["declared_name"]), (2, "demo"))
        self.assertTrue(observer.validate_cli_envelope(release_fixture("migrate-dry-run.json"), "migrate-state"))
        self.assertTrue(observer.validate_cli_envelope(release_fixture("migrate-apply.json"), "migrate-state"))
    def test_migration_rejects_unrelated_mutation_and_bool_or_float_schema_four(self) -> None:
        applied = release_fixture("migrate-apply.json")
        for schema in (True, 4.0, 4):
            mutation = {**applied, "data": {**applied["data"], "source_schema": schema}}
            self.assertFalse(observer.validate_cli_envelope(mutation, "migrate-state"))
    def test_migration_provenance_fails_closed_on_missing_or_changed_identity(self) -> None:
        state = json.loads((ROOT / "tests/e2e/fixtures/state-schema-2.json").read_text())
        record = observer.installation_record(state, "demo")
        expected = observer.migration_provenance(record, legacy=True)
        self.assertIsNotNone(expected)
        missing = json.loads(json.dumps(record))
        del missing["source"]["repository"]
        self.assertIsNone(observer.migration_provenance(missing, legacy=True))
        changed = json.loads(json.dumps(record))
        changed["source"]["resolved_revision"] = "2" * 40
        self.assertNotEqual(expected, observer.migration_provenance(changed, legacy=True))
        self.assertIsNone(observer._one_semantic(
            {"input_digest": "sha256:" + "a" * 64, "state_digest": "sha256:" + "b" * 64},
            {"input_digest", "state_digest"},
        ))

    def test_plugin_data_update_requires_changed_package_and_preserves_exact_receipt(self) -> None:
        self.test_retained_marker_rejects_identical_file_and_directory_replacement()
    def test_plugin_data_update_proof_fails_closed_for_no_change_or_receipt_replacement(self) -> None:
        first = {"tree_digest": "sha256:" + "a" * 64, "manifest_digest": "sha256:" + "e" * 64}
        second = {"tree_digest": "sha256:" + "b" * 64, "manifest_digest": "sha256:" + "f" * 64}
        receipt = {"locator": "/disposable/data", "ownership_digest": "sha256:" + "c" * 64}
        self.assertEqual(observer.plugin_data_update_proof(first, first, receipt, receipt, first, first), (False, True))
        self.assertEqual(
            observer.plugin_data_update_proof(
                first, second, receipt, {**receipt, "ownership_digest": "sha256:" + "d" * 64}, first, second,
            ),
            (True, False),
        )
        for field in ("tree_digest", "manifest_digest"):
            forged = {**second, field: "sha256:" + "9" * 64}
            self.assertEqual(
                observer.plugin_data_update_proof(first, forged, receipt, receipt, first, second),
                (False, True),
            )

    def test_receipts_are_scoped_to_one_installation_and_exact_command_targets(self) -> None:
        _, authoritative = self.agentplugins_0_1_14_state_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            manager = Path(tmp)
            state_path = manager / "state-v2.json"
            state_path.write_text(json.dumps(authoritative))
            receipts = observer.installation_receipts(manager, "context7")
            self.assertEqual(len(receipts or []), 3)
            self.assertTrue(observer.receipts_bind_command([], receipts or [], "add", ("codex", "cursor", "kiro")))
            self.assertFalse(observer.receipts_bind_command([], receipts or [], "add", ("codex", "cursor", "cursor")))
            duplicated = json.loads(json.dumps(authoritative))
            duplicated["installations"].append(duplicated["installations"][0])
            state_path.write_text(json.dumps(duplicated))
            self.assertIsNone(observer.selected_manager_installation(manager, "context7"))
            split = json.loads(json.dumps(authoritative))
            receipt = next(iter(split["installations"][0]["clients"].values()))["receipts"][0]
            receipt["operation_group_id"] = "different-authority"
            state_path.write_text(json.dumps(split))
            self.assertIsNone(observer.installation_receipts(manager, "context7"))

    def test_canonical_data_locator_rejects_traversal_and_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            allowed = base / "allowed"
            outside = base / "outside"
            allowed.mkdir()
            outside.mkdir()
            owned = allowed / "owned"
            owned.mkdir()
            (allowed / "escape").mkdir()
            self.assertEqual(observer.canonical_allowed_locator(owned, (allowed,)), owned.resolve())
            self.assertIsNone(observer.canonical_allowed_locator(allowed / "owned" / ".." / "escape", (allowed,)))
            (allowed / "link").symlink_to(outside, target_is_directory=True)
            self.assertIsNone(observer.canonical_allowed_locator(allowed / "link", (allowed,)))

    def test_full_sha_identity_and_refetch_signal_require_exact_complete_fields(self) -> None:
        update = release_fixture("local-update.json")
        self.assertTrue(observer.validate_cli_envelope(update, "update"))
        self.assertIsNone(observer.command_acquisition_proof(update, ("codex", "cursor", "kiro"), command="update"))
    def test_direct_full_sha_scenario_fails_without_explicit_update_refetch(self) -> None:
        diagnostic = "agentplugins: group update preflight failed; no target was changed: direct full-SHA installations require explicit switch"
        self.assertIn("explicit switch", diagnostic)
        self.assertNotIn("--expected-digest", diagnostic)
    def test_evidence_boundary_rejects_incomplete_or_forged_acquisition(self) -> None:
        targets = ("codex", "cursor", "kiro")
        tree = "sha256:" + "a" * 64
        manifest = "sha256:" + "b" * 64
        proof = {
            "acquisition_id": "fetch-1", "acquisition_count": 1,
            "tree_digest": tree, "manifest_digest": manifest,
            "closure_digest": observer.grouped_acquisition_closure_digest(
                "github", "upstash/context7", "plugins/context7", "1" * 40, tree, manifest,
            ),
            "source_kind": "github", "fetched": True, "validated": True,
            "source_repository": "upstash/context7", "source_revision": "1" * 40,
            "source_path": "plugins/context7", "targets": [{"target": client} for client in targets],
        }
        proof["target_outcomes"] = {
            client: {"outcome": "passed", "acquisition_id": "fetch-1", "tree_digest": tree, "manifest_digest": manifest, "closure_digest": proof["closure_digest"]}
            for client in targets
        }
        arguments = {"tree_digest": tree, "manifest_digest": manifest, "source_repository": "upstash/context7", "source_revision": "1" * 40, "source_path": "plugins/context7"}
        self.assertEqual(e2e.complete_acquisition_proof(proof, targets, **arguments), proof)
        for field in ("acquisition_id", "acquisition_count", "source_kind", "fetched", "validated", "tree_digest", "manifest_digest", "closure_digest", "source_repository", "source_revision", "source_path", "targets", "target_outcomes"):
            with self.subTest(field=field):
                incomplete = {key: child for key, child in proof.items() if key != field}
                self.assertIsNone(e2e.complete_acquisition_proof(incomplete, targets, **arguments))
        self.assertIsNone(e2e.complete_acquisition_proof({**proof, "acquisition_count": True}, targets, **arguments))
        forged = json.loads(json.dumps(proof))
        forged["target_outcomes"]["kiro"]["tree_digest"] = "sha256:" + "d" * 64
        self.assertIsNone(e2e.complete_acquisition_proof(forged, targets, **arguments))

    def test_policy_conformance_directory_is_test_signed_and_never_the_production_root(self) -> None:
        snapshot = json.loads((PUBLICATION / "snapshot.json").read_text())
        distribution = snapshot["distributions"][0]
        release = distribution["releases"][0]
        context = {
            "github_sha": "a" * 40,
            "directory_product": snapshot["products"][0],
            "directory_distribution": distribution,
            "release": {
                "release_sequence": release["sequence"],
                "product_id": snapshot["products"][0]["id"],
                "distribution_id": distribution["id"],
                "tree_digest": release["tree_digest"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            environment, digest = observer.conformance_directory(
                Path(tmp), context, sequence=1007, sequence_over_semver=True,
            )
            trust = json.loads(Path(environment["AGENTPLUGINS_DIRECTORY_TRUST"]).read_text())
            generated = json.loads(Path(environment["AGENTPLUGINS_DIRECTORY_SNAPSHOT"]).read_text())
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(trust["keys"][0]["key_id"], "launch-conformance-only")
        self.assertNotEqual(trust, json.loads(e2e.PRODUCTION_DIRECTORY_TRUST.read_text()))
        self.assertEqual([item["sequence"] for item in generated["distributions"][0]["releases"]], [1, 2])
        self.assertEqual([item["package_version"] for item in generated["distributions"][0]["releases"]], ["9.0.0", "1.0.0"])

    def test_fixture_contracts_cover_required_fault_slots(self) -> None:
        config = json.loads(e2e.SCENARIOS.read_text())
        required = {
            "directory_offline", "directory_expired", "directory_tampered", "directory_sequence_rollback",
            "missing_runtime_zero_mutation", "plugin_data_update_repair_switch_remove_purge",
            "stdio_environment_and_containment", "promotion_gate_digest_mismatch",
            "distribution_sticky_update", "managed_rollback",
        }
        observed = set(config["fault_scenarios"] + config["advanced_scenarios"])
        self.assertTrue(required.issubset(observed))
        for scenario in config["fault_scenarios"] + config["adapter_repair_faults"] + config["advanced_scenarios"]:
            with self.subTest(scenario=scenario):
                self.assertFalse(e2e.LaunchHarness.driver_proof_valid(scenario, {"outcome": "passed"}))

    def test_source_identity_rows_fail_closed_for_missing_or_spoofed_manager_identity(self) -> None:
        expected_release = {
            "product_id": "context7", "distribution_id": "upstash/context7", "distribution_kind": "upstream",
            "release_sequence": 1, "source_revision": "1" * 40, "tree_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "b" * 64, "package_version": "1.0.0",
            "source_repository": "upstash/context7", "source_path": "plugins/context7",
        }
        expected_identity = {key: expected_release[key] for key in (
            "product_id", "distribution_id", "distribution_kind", "release_sequence", "source_revision",
            "source_repository", "source_path", "tree_digest", "manifest_digest",
        )}
        expected_identity["canonical_source"] = "https://github.com/upstash/context7@" + "1" * 40 + "//plugins/context7"
        self.assertTrue(e2e.LaunchHarness.source_identity_matches_release(expected_release, expected_identity))
        self.assertTrue(e2e.LaunchHarness.source_identity_matches_release(
            expected_release,
            {**expected_identity, "canonical_source": "upstash/context7@" + "1" * 40 + "//plugins/context7"},
        ))
        for name, identity in (
            ("missing", None),
            ("missing_product", {key: value for key, value in expected_identity.items() if key != "product_id"}),
            ("unauthorized_fork", {**expected_identity, "source_repository": "attacker/context7", "canonical_source": "attacker/context7@" + "1" * 40 + "//plugins/context7"}),
            ("wrong_path", {**expected_identity, "source_path": "plugins/other", "canonical_source": "upstash/context7@" + "1" * 40 + "//plugins/other"}),
            ("wrong_manifest", {**expected_identity, "manifest_digest": "sha256:" + "8" * 64}),
            ("canonical_repository_mismatch", {**expected_identity, "canonical_source": "attacker/context7@" + "1" * 40 + "//plugins/context7"}),
            ("canonical_sha_mismatch", {**expected_identity, "canonical_source": "upstash/context7@" + "2" * 40 + "//plugins/context7"}),
            ("canonical_path_mismatch", {**expected_identity, "canonical_source": "upstash/context7@" + "1" * 40 + "//plugins/other"}),
            ("spoofed_kind", {**expected_identity, "distribution_kind": "community_bridge"}),
            ("spoofed_digest", {**expected_identity, "tree_digest": "sha256:" + "9" * 64}),
        ):
            with self.subTest(name=name):
                harness = self.fixture_harness()
                harness.config = {
                    **harness.config, "fault_scenarios": [], "adapter_repair_faults": [],
                    "advanced_scenarios": ["upstream_owned_short_name"],
                    "source_identity_scenarios": {"upstream_owned_short_name": {
                        "product_id": "context7", "distribution_id": "upstash/context7", "distribution_kind": "upstream",
                    }},
                }
                value = {
                    "source_kind": "upstream", "immutable_revision": True, "exact_source_identity": True,
                    "source_identity": identity, "tuple": {"distribution_id": "spoofed/tuple"},
                    "client_version": "manager-state-v1", "proof": {}, "command_traces": [],
                }
                with mock.patch.object(harness, "driven_scenario", return_value=("passed", value, "claimed")), mock.patch.object(
                    harness, "configured_source_release", return_value=expected_release,
                ):
                    harness.fault_matrix()
                self.assertEqual(harness.rows[0]["outcome"], "failed")
                self.assertTrue(all(harness.rows[0]["tuple"][key] is None for key in (
                    "product_id", "tree_digest", "distribution_id", "distribution_kind", "release_sequence",
                )))

        bridge_release = {
            **expected_release, "product_id": "cloudflare-docs",
            "distribution_id": "777genius/cloudflare-docs-bridge", "distribution_kind": "community_bridge",
        }
        bridge_identity = {key: bridge_release[key] for key in (
            "product_id", "distribution_id", "distribution_kind", "release_sequence", "source_revision",
            "source_repository", "source_path", "tree_digest", "manifest_digest",
        )}
        bridge_identity["canonical_source"] = "https://github.com/upstash/context7@" + "1" * 40 + "//plugins/context7"
        self.assertTrue(e2e.LaunchHarness.source_identity_matches_release(bridge_release, bridge_identity))
        self.assertFalse(e2e.LaunchHarness.source_identity_matches_release(
            bridge_release, {**bridge_identity, "distribution_id": "upstash/context7"},
        ))
        self.assertFalse(e2e.LaunchHarness.source_identity_matches_release(bridge_release, None))

        harness = self.fixture_harness()
        harness.config = {
            **harness.config, "fault_scenarios": [], "adapter_repair_faults": [],
            "advanced_scenarios": ["upstream_owned_short_name"],
            "source_identity_scenarios": {"upstream_owned_short_name": {
                "product_id": "context7", "distribution_id": "upstash/context7", "distribution_kind": "upstream",
            }},
        }
        exact_value = {
            "source_kind": "upstream", "immutable_revision": True, "exact_source_identity": True,
            "source_identity": expected_identity, "client_version": "manager-state-v1",
            "proof": {}, "command_traces": [],
        }
        with mock.patch.object(harness, "driven_scenario", return_value=("passed", exact_value, "claimed")), mock.patch.object(
            harness, "configured_source_release", return_value=expected_release,
        ):
            harness.fault_matrix()
        exact_row = harness.rows[0]
        self.assertEqual(exact_row["outcome"], "passed")
        self.assertEqual(exact_row["details"]["evidence_basis"], "repository_owned_disposable_observer")
        self.assertFalse(exact_row["details"]["runtime_proof"])
        self.assertEqual(exact_row["tuple"]["source_repository"], expected_identity["source_repository"])

    def test_canonical_github_source_parser_rejects_noncanonical_identity(self) -> None:
        revision = "1" * 40
        shorthand = f"upstash/context7@{revision}//plugins/context7"
        production = f"https://github.com/upstash/context7@{revision}//plugins/context7"
        expected = {
            "source_repository": "upstash/context7",
            "source_revision": revision,
            "source_path": "plugins/context7",
        }
        for exact in (shorthand, production):
            with self.subTest(exact=exact):
                self.assertEqual(observer.parse_canonical_github_source(exact), expected)
                self.assertEqual(e2e.parse_canonical_github_source(exact), expected)
        expected_identity = {**expected, "canonical_source": production}
        observed_identity = {**expected, "canonical_source": shorthand}
        self.assertTrue(observer.source_identities_match(expected_identity, observed_identity))
        invalid = (
            f"http://github.com/upstash/context7@{revision}//plugins/context7",
            f"https://user@github.com/upstash/context7@{revision}//plugins/context7",
            f"https://gitlab.com/upstash/context7@{revision}//plugins/context7",
            f"https://GitHub.com/upstash/context7@{revision}//plugins/context7",
            f"https://github.com:443/upstash/context7@{revision}//plugins/context7",
            f"https://github.com//upstash/context7@{revision}//plugins/context7",
            f"https://github.com/upstash/context7@{revision}///plugins/context7",
            "upstash/context7@main//plugins/context7",
            f"upstash/context7@{revision}//plugins/../context7",
            f"upstash/context7@{revision}//plugins//context7",
            f"upstash/context7@{revision}//plugins/context7?ref=main",
            f"upstash/context7@{revision}//plugins/context7#fragment",
            f"upstash/context7@{revision}//plugins/%2e%2e/context7",
            f"https:/github.com/upstash/context7@{revision}//plugins/context7",
            f"https://github.com/upstash/context7@{revision}//plugins/context 7",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(observer.parse_canonical_github_source(value))
                self.assertIsNone(e2e.parse_canonical_github_source(value))

    def test_directory_evidence_artifact_requires_complete_source_identity(self) -> None:
        schema = json.loads((ROOT / "schemas/directory-evidence-artifact.schema.json").read_text())
        artifact = {
            "schema_version": 1,
            "id": "runtime-context7-cursor",
            "product_id": "context7",
            "distribution_id": "upstash/context7",
            "release_sequence": 1,
            "package_tree_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "b" * 64,
            "source_repository": "upstash/context7",
            "source_revision": "1" * 40,
            "source_path": "plugins/context7",
            "level": "runtime",
            "outcome": "passed",
            "client": "cursor",
            "client_version": "1.0.0",
            "installer_version": "0.1.8",
            "os": "linux",
            "architecture": "amd64",
            "observed_at": "2026-08-22T00:00:00Z",
        }
        jsonschema.Draft202012Validator(schema).validate(artifact)
        for field in ("product_id", "manifest_digest", "source_repository", "source_revision", "source_path"):
            with self.subTest(field=field):
                invalid = dict(artifact)
                invalid.pop(field)
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.Draft202012Validator(schema).validate(invalid)

    def test_source_scenarios_select_concrete_reviewed_directory_distributions(self) -> None:
        harness = self.fixture_harness()
        harness.snapshot = json.loads((ROOT / "registry/directory.json").read_text())
        publication_revision = "f" * 40
        for distribution in harness.snapshot["distributions"]:
            for release in distribution["releases"]:
                source = release.get("package_source", {})
                if source.get("repository") == e2e.TRUSTED_CATALOG_REPOSITORY and source.get("revision") is None:
                    source["revision"] = publication_revision
        upstream = harness.configured_source_release("upstream_owned_short_name", ["cursor"])
        bridge = harness.configured_source_release("community_bridge_short_name", ["cursor"])
        self.assertEqual(
            (upstream["product_id"], upstream["distribution_id"], upstream["distribution_kind"], upstream["source_revision"]),
            ("context7", "upstash/context7", "upstream", "769c6cd22c3d95462d1f55d789e9532cabefa5a9"),
        )
        self.assertEqual(
            (bridge["product_id"], bridge["distribution_id"], bridge["distribution_kind"], bridge["source_revision"]),
            ("cloudflare-docs", "777genius/cloudflare-docs-bridge", "community_bridge", publication_revision),
        )

    def test_manager_identity_does_not_aggregate_authority_across_records(self) -> None:
        state = release_fixture("state-v2.json")
        with tempfile.TemporaryDirectory() as tmp:
            manager = Path(tmp)
            (manager / "state-v2.json").write_text(json.dumps(state))
            self.assertEqual(observer.manager_identity(manager, "context7")["resolved_revision"], "769c6cd22c3d95462d1f55d789e9532cabefa5a9")
            extra = json.loads(json.dumps(state["installations"][0]))
            extra["installation_id"] = "extra-installation"
            extra["declared_name"] = "other"
            extra["package"]["declared_name"] = "other"
            state["installations"].append(extra)
            (manager / "state-v2.json").write_text(json.dumps(state))
            self.assertEqual(observer.manager_identity(manager, "context7"), {})

    def test_promotion_and_fork_observers_execute_exact_local_validators(self) -> None:
        scenarios = (
            "promotion_gate_digest_match", "promotion_gate_digest_mismatch",
            "fork_submission", "fork_submission_rejected",
        )
        match_candidate_digest = None
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            for scenario in scenarios:
                with self.subTest(scenario=scenario):
                    root = parent / scenario
                    root.mkdir()
                    environment = {"HOME": str(root / "home"), "AGENTPLUGINS_HOME": str(root / "manager")}
                    with mock.patch.dict(os.environ, environment, clear=False):
                        if scenario.startswith("promotion_"):
                            passed, value = observer.promotion_scenario(Path("/not-used"), scenario, root, "a" * 64)
                        else:
                            passed, value = observer.fork_submission_scenario(scenario, root, "a" * 64)
                    self.assertTrue(passed, value)
                    artifact = value["validator_artifact"]
                    if scenario.endswith("mismatch") or scenario.endswith("rejected"):
                        self.assertEqual(artifact["outcome"], "rejected")
                    else:
                        self.assertEqual(artifact["outcome"], "accepted")
                        self.assertTrue(artifact["gates"])
                    if scenario == "promotion_gate_digest_match":
                        match_candidate_digest = artifact["candidate_digest"]
            repeat = parent / "promotion_gate_digest_match_repeat"
            repeat.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(repeat / "home"), "AGENTPLUGINS_HOME": str(repeat / "manager")}, clear=False):
                passed, value = observer.promotion_scenario(Path("/not-used"), "promotion_gate_digest_match", repeat, "a" * 64)
            self.assertTrue(passed, value)
            self.assertEqual(value["validator_artifact"]["candidate_digest"], match_candidate_digest)

    def test_journey_aggregation_requires_accepted_and_rejected_fork_artifacts(self) -> None:
        harness = self.fixture_harness()
        harness.cli_version = "0.1.14"
        accepted = {
            "fork_created": True, "branch_submission": True, "submission_validated": True,
            "publication_performed": False, "pr_created": False, "network_performed": False,
            "client_version": "fixture-validator-v1",
        }
        rejected = {
            "fork_created": True, "submission_rejected": True, "no_side_effect": True,
            "no_candidate": True, "client_version": "fixture-validator-v1",
        }
        with mock.patch.object(harness, "command", return_value=("failed", None, "not under test")), mock.patch.object(
            harness, "driven_scenario", side_effect=[("passed", accepted, "accepted"), ("passed", rejected, "rejected")],
        ):
            harness.journeys()
        rows = {row["scenario"]: row for row in harness.rows}
        self.assertEqual(rows["fork_submission"]["outcome"], "passed")
        self.assertEqual(rows["fork_submission_rejected"]["outcome"], "passed")

    def test_direct_external_journey_requires_add_info_and_remove(self) -> None:
        harness = self.fixture_harness()
        harness.cli_version = "0.1.14"
        digest = e2e.package_digest(e2e.EXTERNAL_PACKAGE)
        command_results = [
            ("passed", {"package_digest": digest, "client_version": "cursor-test-v1", "mutated": True, "_launch_command_trace": {"argv": ["add"]}}, "added"),
            ("passed", {"receipt_reconciled": True, "native_discovery_reconciled": True, "client_version": "cursor-test-v1", "native_discovery_evidence": {"basis": "protected_external_observer", "version_operation": {"operation": "version", "argv": ["cursor", "--version"], "observed_client_version": "cursor-test-v1"}, "discovery_operation": {"operation": "list", "argv": ["cursor", "plugins", "list"], "discovered": True, "product_id": "e2e-external-package"}}, "_launch_command_trace": {"argv": ["info"]}}, "reconciled"),
            ("passed", {"data": {"targets": [{"output": {"result": {"mutated": False, "no_change": True, "group_phase": "external_completed"}}} for _ in range(3)]}, "_launch_command_trace": {"argv": ["update"]}}, "unchanged"),
            ("passed", {"mutated": True, "_launch_command_trace": {"argv": ["remove"]}}, "removed"),
        ]
        accepted = {"fork_created": True, "branch_submission": True, "submission_validated": True, "publication_performed": False, "pr_created": False, "network_performed": False}
        rejected = {"fork_created": True, "submission_rejected": True, "no_side_effect": True, "no_candidate": True}
        with mock.patch.object(harness, "command", side_effect=command_results) as command, mock.patch.object(
            harness, "driven_scenario", side_effect=[("passed", accepted, "accepted"), ("passed", rejected, "rejected")],
        ):
            harness.journeys()
        row = next(item for item in harness.rows if item["scenario"] == "direct_external_package")
        self.assertEqual(row["outcome"], "passed")
        self.assertEqual(row["details"]["evidence_basis"], "repository_owned_disposable_observer")
        self.assertEqual(row["details"]["tree_digest_algorithm"], "agentplugins-tree-sha256-v1")
        self.assertEqual([call.args[0][0] for call in command.call_args_list], ["add", "info", "update", "remove"])
        self.assertEqual(row["details"]["operations"]["info"]["outcome"], "passed")
        self.assertEqual(len(row["details"]["command_traces"]), 4)

    def test_direct_external_journey_fails_when_info_or_cleanup_is_not_proved(self) -> None:
        digest = e2e.package_digest(e2e.EXTERNAL_PACKAGE)
        accepted = {"fork_created": True, "branch_submission": True, "submission_validated": True, "publication_performed": False, "pr_created": False, "network_performed": False}
        rejected = {"fork_created": True, "submission_rejected": True, "no_side_effect": True, "no_candidate": True}
        cases = (
            (
                "receipt-only materialization",
                "passed",
                [
                    ("passed", {"package_digest": digest, "client_version": "cursor-test-v1", "mutated": True}, "added"),
                    ("passed", {"receipt_reconciled": True, "native_discovery_reconciled": False}, "partial"),
                    ("passed", {"data": {"targets": [{"output": {"result": {"mutated": False, "no_change": True, "group_phase": "external_completed"}}} for _ in range(3)]}}, "unchanged"),
                    ("passed", {"mutated": True}, "removed"),
                ],
            ),
            (
                "failed cleanup",
                "failed",
                [
                    ("passed", {"package_digest": digest, "client_version": "cursor-test-v1", "mutated": True}, "added"),
                    ("passed", {"receipt_reconciled": True, "native_discovery_reconciled": True}, "reconciled"),
                    ("passed", {"data": {"targets": [{"output": {"result": {"mutated": False, "no_change": True, "group_phase": "external_completed"}}} for _ in range(3)]}}, "unchanged"),
                    ("failed", None, "remove failed"),
                ],
            ),
        )
        for label, expected_outcome, command_results in cases:
            with self.subTest(label=label):
                harness = self.fixture_harness()
                harness.cli_version = "0.1.14"
                with mock.patch.object(harness, "command", side_effect=command_results) as command, mock.patch.object(
                    harness, "driven_scenario", side_effect=[("passed", accepted, "accepted"), ("passed", rejected, "rejected")],
                ):
                    harness.journeys()
                row = next(item for item in harness.rows if item["scenario"] == "direct_external_package")
                self.assertEqual(row["outcome"], expected_outcome)
                self.assertEqual([call.args[0][0] for call in command.call_args_list], ["add", "info", "update", "remove"])

    def test_missing_runtime_proof_requires_zero_mutation_and_no_install(self) -> None:
        proof = {"zero_mutation": True, "copy_ready_requirement": True, "dependency_installed": False}
        self.assertTrue(e2e.LaunchHarness.driver_proof_valid("missing_runtime_zero_mutation", proof))
        self.assertFalse(e2e.LaunchHarness.driver_proof_valid("missing_runtime_zero_mutation", {**proof, "dependency_installed": True}))

    def test_dead_required_scenario_omission_is_rejected(self) -> None:
        config = json.loads(e2e.SCENARIOS.read_text())
        required = config["fault_scenarios"] + config["adapter_repair_faults"] + config["advanced_scenarios"] + config["acceptance_postconditions"] + config["journeys"] + ["shared_copilot_vscode_backend"]
        rows = [{"scenario": scenario} for scenario in required]
        e2e.validate_enforced_scenario_coverage(rows, config)
        with self.assertRaisesRegex(ValueError, "omitted or duplicated"):
            e2e.validate_enforced_scenario_coverage(rows[1:], config)

    def test_fixture_only_claim_escalation_is_rejected(self) -> None:
        evidence = self.fixture_harness().export()
        evidence["run"]["runtime_claims"] = True
        with self.assertRaisesRegex(ValueError, "cannot escalate"):
            e2e.assert_redacted(evidence)

    def test_external_pr_gate_fails_closed_for_every_untrustworthy_evidence_class(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        challenge = {"value": "a" * 64}
        snapshot = {"sequence": 9, "publication_id": "publication-9", "source_commit": "b" * 40}
        binding = {
            "catalog_repository": e2e.TRUSTED_CATALOG_REPOSITORY,
            "catalog_sha": "c" * 40,
            "directory_snapshot_digest": "sha256:" + "d" * 64,
            "directory_sequence": 9,
            "directory_publication_id": "publication-9",
            "directory_source_commit": "b" * 40,
            "release_repository": e2e.TRUSTED_CLI_RELEASE_REPOSITORY,
            "release_tag": e2e.TRUSTED_CLI_RELEASE_TAG,
            "release_commit": "e" * 40,
            "release_manifest_digest": "sha256:" + "f" * 64,
        }
        record = {
            "schema_version": 1, "challenge": challenge["value"],
            "catalog_repository": e2e.TRUSTED_CATALOG_REPOSITORY,
            "fork_owner": "external-contributor", "fork_repository": "external-contributor/universal-agent-plugins",
            "pr_number": 42, "pr_url": f"https://github.com/{e2e.TRUSTED_CATALOG_REPOSITORY}/pull/42",
            "head_sha": "1" * 40, "base_sha": "c" * 40, "merge_commit_sha": None,
            "changed_paths": ["registry/directory.json", "registry/review-preview.json", "registry/review-search.json"],
            "check_runs": [{"name": "portable-catalog", "conclusion": "success", "head_sha": "1" * 40}],
            "final_review": {"state": "closed", "decision": "validated", "reviewer_count": 1, "closed_at": now.isoformat().replace("+00:00", "Z"), "merged_at": None},
            "observed_at": now.isoformat().replace("+00:00", "Z"),
            "immutable_artifact": {"digest": "sha256:" + "3" * 64, "reference": "urn:sha256:" + "3" * 64},
            "binding": binding,
        }

        def verify(value):
            return e2e.external_pr_evidence_valid(
                value, challenge=challenge, catalog_repository=e2e.TRUSTED_CATALOG_REPOSITORY,
                catalog_sha="c" * 40, snapshot=snapshot, snapshot_digest="sha256:" + "d" * 64,
                release_repository=e2e.TRUSTED_CLI_RELEASE_REPOSITORY,
                release_tag=e2e.TRUSTED_CLI_RELEASE_TAG, release_commit="e" * 40,
                release_manifest_digest="sha256:" + "f" * 64, now=now,
            )

        self.assertEqual(verify(record), (True, "signed immutable external-fork PR evidence verified"))
        negatives = {
            "missing": None,
            "local": {**record, "fork_repository": "local"},
            "self_owned": {**record, "fork_owner": "777genius", "fork_repository": e2e.TRUSTED_CATALOG_REPOSITORY},
            "stale": {**record, "observed_at": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")},
            "wrong_challenge": {**record, "challenge": "9" * 64},
            "wrong_binding": {**record, "binding": {**binding, "directory_sequence": 8}},
            "wrong_base": {**record, "base_sha": "4" * 40},
            "unexpected_merge": {**record, "merge_commit_sha": "4" * 40},
            "wrong_path": {**record, "changed_paths": ["site/index.html"]},
            "wrong_head": {**record, "check_runs": [{"name": "portable-catalog", "conclusion": "success", "head_sha": "4" * 40}]},
            "failed_check": {**record, "check_runs": [{"name": "portable-catalog", "conclusion": "failure", "head_sha": "1" * 40}]},
            "unreviewed": {**record, "final_review": {**record["final_review"], "reviewer_count": 0}},
            "merged_instead_of_closed": {**record, "final_review": {**record["final_review"], "state": "merged"}},
            "mutable_reference": {**record, "immutable_artifact": {**record["immutable_artifact"], "reference": "https://example.test/latest.json"}},
        }
        for name, value in negatives.items():
            with self.subTest(name=name):
                self.assertFalse(verify(value)[0])

        schema_path = ROOT / "tests/e2e/schemas/external-pr-evidence.schema.json"
        jsonschema.Draft202012Validator(json.loads(schema_path.read_text())).validate(record)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(json.loads(schema_path.read_text())).validate(negatives["failed_check"])

    def test_authoritative_resolver_preserves_complete_targets_and_exact_fallback_reason(self) -> None:
        harness = self.fixture_harness()
        digest = lambda character: "sha256:" + character * 64
        targets = [{"client": client, "scopes": ["user"]} for client in ("codex", "cursor", "kiro")]
        harness.snapshot = {
            "sequence": 1, "evidence": [],
            "products": [{"id": "context7", "aliases": ["context7"], "default_distribution": "vendor/default", "distributions": ["vendor/default", "community/fallback"], "minimum_capabilities": {"mcp": "required"}}],
            "distributions": [
                {"id": "vendor/default", "product_id": "context7", "kind": "upstream", "status": "active", "releases": [{"sequence": 1, "components": ["mcp"], "tree_digest": digest("a"), "manifest_digest": digest("b"), "package_version": "1.0.0"}], "release_policies": [{"release_sequence": 1, "status": "active", "targets": targets[:1], "current_evidence": []}]},
                {"id": "community/fallback", "product_id": "context7", "kind": "community", "status": "active", "releases": [{"sequence": 7, "components": ["mcp"], "tree_digest": digest("c"), "manifest_digest": digest("d"), "package_version": "2.0.0"}], "release_policies": [{"release_sequence": 7, "status": "active", "targets": targets, "current_evidence": []}]},
            ],
        }
        resolved = harness.directory_release("context7", ["codex", "cursor", "kiro"])
        self.assertEqual(resolved["distribution_id"], "community/fallback")
        self.assertEqual(resolved["release_sequence"], 7)
        self.assertEqual(resolved["resolved_targets"], ["codex", "cursor", "kiro"])
        self.assertEqual(resolved["fallback_reason"], "declared default vendor/default was ineligible: release 1 does not support cursor,kiro")

    def test_fixture_privacy_output_is_derived_from_verified_consent_fields(self) -> None:
        evidence = self.fixture_harness().export()
        consent = json.loads(CONSENT.read_text())
        self.assertEqual(evidence["privacy"]["pseudonymous_identity_id"], consent["pseudonymous_identity_id"])
        self.assertEqual(evidence["privacy"]["cleanup_outcome"], consent["cleanup_outcome"])
        self.assertEqual(evidence["privacy"]["real_user_project_used"], consent["no_real_project_proof"]["real_project_accessed"])
        for field, invalid in (
            ("dedicated_identity", False), ("cleanup_outcome", "pending"),
            ("operation_mode", "write"), ("auth_origin", "copied-user-auth"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "consent.json"
                path.write_text(json.dumps({**consent, field: invalid}))
                with self.assertRaisesRegex(ValueError, "does not authorize"):
                    e2e.LaunchHarness(None, None, mode="fixture-only", consent=path)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "consent.json"
            path.write_text(json.dumps({**consent, "no_real_project_proof": {**consent["no_real_project_proof"], "real_project_accessed": True}}))
            with self.assertRaisesRegex(ValueError, "does not authorize"):
                e2e.LaunchHarness(None, None, mode="fixture-only", consent=path)

    def test_runtime_attestations_fail_closed_when_any_privacy_or_run_binding_changes(self) -> None:
        harness = self.fixture_harness()
        harness.challenge = {"value": "a" * 64}
        harness.github_run_id = "17"
        harness.github_run_attempt = "2"
        consent = json.loads(CONSENT.read_text())
        record = {
            "plugin": "context7", "client": "codex", "level": "runtime",
            "outcome": "failed", "reason": "fixture negative record", "tuple": {},
            "challenge": harness.challenge["value"], "run_id": "17", "run_attempt": "2",
            "scenario_id": "hero_5x3_runtime",
            "release_manifest_digest": harness.release_manifest_digest,
            "release_checksums_digest": harness.release_checksums_digest,
            "directory_digest": harness.snapshot_digest,
            "scenario_contract_digest": e2e.sha256_file(e2e.SCENARIOS),
            "identity_id": consent["pseudonymous_identity_id"],
            "consent_artifact_digest": harness.consent_digest,
            **{field: consent[field] for field in (
                "pseudonymous_identity_id", "pseudonymous_workspace_id", "dedicated_identity",
                "disposable_project_status", "operation_mode", "auth_origin", "cleanup_outcome",
                "no_real_project_proof",
            )},
        }

        def load(value):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "attestations.json"
                path.write_text(json.dumps({"schema_version": 1, "attestations": [value]}))
                return harness._load_attestations(path)

        self.assertIn(("context7", "codex", "runtime"), load(record))
        negatives = {
            "challenge": {**record, "challenge": "b" * 64},
            "run": {**record, "run_id": "18"},
            "scenario": {**record, "scenario_id": "chatgpt_registered_binding"},
            "identity": {**record, "identity_id": "different-identity"},
            "workspace": {**record, "pseudonymous_workspace_id": "different-workspace"},
            "cleanup": {**record, "cleanup_outcome": "pending"},
            "operation": {**record, "operation_mode": "write"},
            "auth": {**record, "auth_origin": "copied-user-auth"},
            "real_project": {**record, "no_real_project_proof": {**record["no_real_project_proof"], "real_project_accessed": True}},
            "release_binding": {**record, "release_manifest_digest": "sha256:" + "b" * 64},
        }
        for name, value in negatives.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "bound|privacy|identity"):
                load(value)

    def test_hidden_yes_acceptance_or_mutation_fails_public_scenario(self) -> None:
        fake = '''#!/usr/bin/python3
import os, pathlib, sys
if sys.argv[1:] == ["--help"]:
    print("help")
    raise SystemExit(0)
path = pathlib.Path(os.environ["AGENTPLUGINS_HOME"]) / "state"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("mutated")
print("accepted")
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "agentplugins"
            binary.write_text(fake)
            binary.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(root / "home"), "AGENTPLUGINS_HOME": str(root / "manager")}, clear=False):
                passed, value = observer.no_hidden_yes_scenario(binary, workspace, "a" * 64)
        self.assertFalse(passed)
        self.assertFalse(value["proof"]["manager_unchanged"])
        self.assertFalse(value["proof"]["unknown_option_reported"])

    def test_stale_public_pointer_is_rejected_against_caller_identity(self) -> None:
        latest = (PUBLICATION / "latest.json").read_bytes()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(e2e, "bounded_https_get", return_value=latest):
            with self.assertRaisesRegex(ValueError, "exact caller publication identity"):
                e2e.fetch_production_directory(
                    Path(tmp) / "directory", expected_publication_id="fixture-1", expected_sequence=8,
                    expected_snapshot_digest="sha256:" + "b" * 64, expected_source_commit="d" * 40,
                )

    def test_production_n_minus_one_does_not_block_valid_staged_n(self) -> None:
        latest = json.loads((PUBLICATION / "latest.json").read_bytes())
        production_n_minus_one = e2e.canonical_json({
            **latest,
            "sequence": 6,
            "snapshot_path": "snapshots/00000000000000000006.json",
            "envelope_path": "snapshots/00000000000000000006.envelope.json",
        })
        digest = json.loads((PUBLICATION / "envelope-current.json").read_text())["snapshot_digest"]
        ledger_commit = "e" * 40
        staged_origin = f"https://raw.githubusercontent.com/{e2e.TRUSTED_CATALOG_REPOSITORY}/{ledger_commit}/registry/schemas/1/"
        staged_bodies = {
            staged_origin + "latest.json": (PUBLICATION / "latest.json").read_bytes(),
            staged_origin + latest["snapshot_path"]: (PUBLICATION / "snapshot.json").read_bytes(),
            staged_origin + latest["envelope_path"]: (PUBLICATION / "envelope-current.json").read_bytes(),
        }
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            e2e, "PRODUCTION_DIRECTORY_TRUST", PUBLICATION / "trusted-keys.json"
        ), mock.patch.object(e2e, "bounded_https_get", return_value=production_n_minus_one):
            with self.assertRaisesRegex(ValueError, "exact caller publication identity"):
                e2e.fetch_production_directory(
                    Path(tmp) / "production", expected_publication_id="fixture-1", expected_sequence=7,
                    expected_snapshot_digest=digest, expected_source_commit="d" * 40,
                )
            environment, snapshot, staged_digest = e2e.fetch_staged_directory(
                Path(tmp) / "staged", repository=e2e.TRUSTED_CATALOG_REPOSITORY,
                ledger_commit=ledger_commit, expected_publication_id="fixture-1",
                expected_sequence=7, expected_snapshot_digest=digest,
                expected_source_commit="d" * 40,
                fixture_fetch=lambda url, _maximum, _accept: staged_bodies[url],
            )
            self.assertEqual(snapshot["sequence"], 7)
            self.assertEqual(staged_digest, digest)
            self.assertEqual(environment["AGENTPLUGINS_DIRECTORY_ORIGIN"], staged_origin)
            with self.assertRaisesRegex(ValueError, "differs from the exact caller publication identity"):
                e2e.fetch_staged_directory(
                    Path(tmp) / "mismatched-staged", repository=e2e.TRUSTED_CATALOG_REPOSITORY,
                    ledger_commit=ledger_commit, expected_publication_id="wrong-publication",
                    expected_sequence=7, expected_snapshot_digest=digest,
                    expected_source_commit="d" * 40,
                    fixture_fetch=lambda url, _maximum, _accept: staged_bodies[url],
                )


if __name__ == "__main__":
    unittest.main()
