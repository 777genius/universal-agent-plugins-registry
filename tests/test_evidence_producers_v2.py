from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_two_lane_readiness as readiness
import observe_release_facade as native
import run_source_policy_conformance as policy
import two_lane_evidence as lanes


def digest(character: str) -> str:
    return "sha256:" + character * 64


class SourcePolicyProducerV2Tests(unittest.TestCase):
    def test_v2_producer_emits_exact_0124_identity_and_routes_v2_validation(self) -> None:
        contract = policy.release_contract(2)
        self.assertEqual(contract, {
            "tag": "agentplugins-v0.1.24",
            "commit": "c78c79e44efd5ad07083d63436d9170b107df6cb",
            "version": "0.1.24",
            "production_tree_digest": "sha256:3635457d320bc2c78a86b9b3d8e4937d14ac59848ffae70c6571167204130de8",
            "linux_amd64_digest": "sha256:e79125f7ffabd11c6e211d6b049c2eb2b36eb1aba3a76ce27cac819aeba1e6ca",
            "manifest_digest": "sha256:eb834da8237b13ed36061aeafb4fbb6f4aadeb5a6fbd4a31d43781f456f3d1e2",
            "checksums_digest": "sha256:623fb73d0e2f59da8b01399842b0d82b8f6456c6e43db2251c0ea5f9e32f37e3",
        })
        fake_test = lambda source, package, name, go, **kwargs: {
            "package": package, "name": name, "passed": True,
            "transcript_digest": digest("d"),
        }
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(policy, "validate_source_identity", return_value=contract["production_tree_digest"]), \
             mock.patch.object(policy, "validate_release_identity", return_value=(contract["manifest_digest"], contract["checksums_digest"])), \
             mock.patch.object(policy, "run_test", side_effect=fake_test), \
             mock.patch.object(policy, "validate_source_policy_evidence", return_value=digest("e")) as validate:
            root = Path(temporary)
            value = policy.produce(
                root, root / "manifest.json", root / "checksums.txt", go="go",
                uap_sha="a" * 40, schema_version=2,
            )
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["identities"]["plugin_kit_tag"], contract["tag"])
        self.assertEqual(value["identities"]["plugin_kit_commit"], contract["commit"])
        self.assertEqual(value["identities"]["production_source_tree_before"], contract["production_tree_digest"])
        self.assertEqual(value["identities"]["production_source_tree_after"], contract["production_tree_digest"])
        self.assertEqual(validate.call_args.kwargs["expected_schema_version"], 2)

    def test_v1_contract_remains_frozen(self) -> None:
        self.assertEqual(policy.release_contract(1), {
            "tag": policy.V1_PLUGIN_KIT_TAG,
            "commit": policy.V1_PLUGIN_KIT_COMMIT,
            "version": "0.1.18",
            "production_tree_digest": "sha256:4a64cddbf6680d55270a8bec9b3810673995b7328d8ff62feab8421a65378607",
            "linux_amd64_digest": "sha256:9a294d2d117d6be2042aa28f911999edccf051ccbc3f1c7f0f46920cfd6b5779",
            "manifest_digest": policy.V1_RELEASE_MANIFEST_DIGEST,
            "checksums_digest": policy.V1_RELEASE_CHECKSUMS_DIGEST,
        })


class ReadinessProducerV2Tests(unittest.TestCase):
    def args(self, root: Path, *, schema_version: int) -> argparse.Namespace:
        runtime = {"schema_version": 5 if schema_version == 2 else 4}
        policy_value = {"schema_version": schema_version}
        runtime_path = root / "runtime.json"
        policy_path = root / "policy.json"
        runtime_path.write_bytes(lanes.canonical_json(runtime))
        policy_path.write_bytes(lanes.canonical_json(policy_value))
        return argparse.Namespace(
            runtime=runtime_path, policy=policy_path, output=root / "readiness.json",
            completed=None, uap_sha="a" * 40, directory_ledger_sha="b" * 40,
            publication_id="fixture", publication_sequence=1,
            publication_snapshot_digest=digest("c"), publication_source_commit="d" * 40,
            schema_version=schema_version,
        )

    def test_v2_requires_launch_v5_and_emits_sixteen_runtime_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), schema_version=2)
            envelope = {
                "schema_version": 2, "runtime_results": 16,
                "policy_results": 11, "readiness_gate_complete": True,
            }
            with mock.patch.object(readiness, "build_readiness_envelope", return_value=envelope) as build:
                readiness.process(args)
            self.assertEqual(json.loads(args.output.read_text()), envelope)
            self.assertEqual(build.call_args.kwargs["schema_version"], 2)
            self.assertEqual(build.call_args.kwargs["purpose"], "current")

    def test_v2_rejects_v4_runtime_or_v1_policy_before_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), schema_version=2)
            args.runtime.write_bytes(lanes.canonical_json({"schema_version": 4}))
            with mock.patch.object(readiness, "build_readiness_envelope") as build:
                with self.assertRaisesRegex(ValueError, "requires launch evidence v5"):
                    readiness.process(args)
            build.assert_not_called()

    def test_v1_replay_is_explicitly_historical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), schema_version=1)
            envelope = {"schema_version": 1, "runtime_results": 15}
            with mock.patch.object(readiness, "build_readiness_envelope", return_value=envelope) as build:
                readiness.process(args)
            self.assertEqual(build.call_args.kwargs["schema_version"], 1)
            self.assertEqual(build.call_args.kwargs["purpose"], "historical")


class NativeObservationProducerV2Tests(unittest.TestCase):
    def context(self, asset_name: str, body: bytes) -> dict[str, object]:
        checksum = hashlib.sha256(body).hexdigest()
        return {
            "release_manifest": {
                "tag": native.V2_TAG, "version": native.V2_VERSION,
                "commit": native.V2_COMMIT,
                "assets": {"linux-amd64": {"file": asset_name, "sha256": checksum, "size": len(body)}},
            },
            "catalog_repository": "777genius/universal-agent-plugins",
            "github": {"sha": "a" * 40},
            "cli_release_repository": "777genius/plugin-kit-ai",
            "cli_release_tag": native.V2_TAG,
            "release_manifest_digest": native.V2_MANIFEST_DIGEST,
            "release_checksums_digest": native.V2_CHECKSUMS_DIGEST,
            "github_release_identity": {
                "repository": "777genius/plugin-kit-ai", "tag": native.V2_TAG,
                "tag_commit": native.V2_COMMIT, "release_id": native.V2_RELEASE_ID, "immutable": True,
            },
            "directory": {"digest": digest("a")},
            "github_asset_attestation": {},
            "challenge": {"value": "b" * 64},
        }

    def test_native_v2_emits_exact_0124_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            asset_name = "agentplugins_0.1.24_linux_amd64"
            body = b"fixture-native-binary"
            (root / "release").mkdir()
            (root / "release" / asset_name).write_bytes(body)
            context_path = root / "context.json"
            context_path.write_text(json.dumps(self.context(asset_name, body)))
            output = root / "observation.json"
            argv = [
                "observe_release_facade.py", "--context", str(context_path),
                "--executable", "/fixture/agentplugins", "--asset-name", asset_name,
                "--kind", "binary", "--os", "linux", "--architecture", "amd64",
                "--schema-version", "2", "--output", str(output),
            ]
            completed = subprocess.CompletedProcess(
                ["/fixture/agentplugins", "version"], 0, "agentplugins 0.1.24\n", "",
            )
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(native.subprocess, "run", return_value=completed), \
                 mock.patch.object(native, "now", side_effect=["2026-08-30T00:00:00Z", "2026-08-30T00:00:01Z"]), \
                 mock.patch.object(native.platform, "platform", return_value="fixture-linux"):
                self.assertEqual(native.main(), 0)
            value = json.loads(output.read_text())
        self.assertEqual((value["schema_version"], value["version"]), (2, "0.1.24"))
        self.assertEqual(value["cli_release_tag"], native.V2_TAG)
        self.assertEqual(value["github_release_identity"]["tag_commit"], native.V2_COMMIT)
        self.assertEqual(value["release_manifest_digest"], native.V2_MANIFEST_DIGEST)
        self.assertEqual(value["release_checksums_digest"], native.V2_CHECKSUMS_DIGEST)

    def test_native_v2_rejects_cross_version_context_before_execution(self) -> None:
        context = self.context("agentplugins_0.1.24_linux_amd64", b"fixture")
        context["release_manifest"]["version"] = "0.1.18"
        with self.assertRaisesRegex(RuntimeError, "release identity mismatch"):
            native.validate_v2_context(context)


if __name__ == "__main__":
    unittest.main()
