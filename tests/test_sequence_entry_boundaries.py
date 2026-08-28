from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

from scripts import observe_discovery_index, sequence_boundaries, verify_discovery_index
import verify_directory_publication

OBSERVER_SPEC = importlib.util.spec_from_file_location(
    "sequence_boundary_launch_observer", SCRIPTS / "observe_launch_scenario.py",
)
assert OBSERVER_SPEC and OBSERVER_SPEC.loader
launch_observer = importlib.util.module_from_spec(OBSERVER_SPEC)
OBSERVER_SPEC.loader.exec_module(launch_observer)

MAXIMUM = sequence_boundaries.JSON_SAFE_INTEGER_MAX
ALIASES = (MAXIMUM + 1, MAXIMUM + 2)


def challenge_context(snapshot_sequence: int = MAXIMUM) -> dict[str, object]:
    snapshot = json.loads((ROOT / "tests/fixtures/directory-publication/snapshot.json").read_text())
    product = snapshot["products"][0]
    distribution = next(item for item in snapshot["distributions"] if item["id"] == product["default_distribution"])
    selected = distribution["releases"][0]
    source = selected["package_source"]
    release = {
        "product_id": product["id"], "distribution_id": distribution["id"],
        "distribution_kind": distribution["kind"], "release_sequence": selected["sequence"],
        "package_version": selected["package_version"], "tree_digest": selected["tree_digest"],
        "manifest_digest": selected["manifest_digest"], "source_repository": source["repository"],
        "source_revision": source["revision"], "source_path": source["path"],
        "compatible_clients": ["codex", "cursor"], "resolved_targets": ["cursor"],
        "fallback_reason": None,
    }
    identity = {key: release[key] for key in launch_observer.CHALLENGE_SOURCE_IDENTITY_FIELDS - {"canonical_source"}}
    identity["canonical_source"] = f'https://github.com/{source["repository"]}@{source["revision"]}//{source["path"]}'
    context = {
        "nonce": "b" * 64, "github_sha": "a" * 40, "run_id": "1", "run_attempt": "1",
        "release_manifest_digest": "sha256:" + "c" * 64,
        "directory_digest": "sha256:" + "d" * 64,
        "scenario_contract_digest": "sha256:" + "e" * 64,
        "root_id": "f" * 64, "binary_digest": "sha256:" + "1" * 64,
        "expected_version": "0.1.18", "snapshot_sequence": snapshot_sequence,
        "release": release, "catalog_repository": "777genius/universal-agent-plugins",
        "directory_product": product, "directory_distribution": distribution,
        "source_identity": identity,
    }
    framed = json.dumps({key: context[key] for key in (
        "github_sha", "run_id", "run_attempt", "release_manifest_digest", "directory_digest",
        "scenario_contract_digest", "root_id", "nonce",
    )}, sort_keys=True, separators=(",", ":")).encode()
    context["value"] = hashlib.sha256(launch_observer.CHALLENGE_DOMAIN + framed).hexdigest()
    return context


class ExactSequenceHelperTests(unittest.TestCase):
    def test_exact_values_and_canonical_text(self) -> None:
        self.assertEqual(sequence_boundaries.require_public_sequence(MAXIMUM), MAXIMUM)
        self.assertEqual(sequence_boundaries.parse_public_sequence(str(MAXIMUM)), MAXIMUM)
        for value in (True, False, 0, -1, *ALIASES):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sequence_boundaries.require_public_sequence(value)
        for text in ("0", "+1", "-1", " 1", "1 ", "01", *(str(item) for item in ALIASES)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sequence_boundaries.parse_public_sequence(text)

    def test_successor_initializes_and_fails_closed_at_rollover(self) -> None:
        self.assertEqual(sequence_boundaries.next_public_sequence(None), 1)
        self.assertEqual(sequence_boundaries.next_public_sequence(MAXIMUM - 1), MAXIMUM)
        with self.assertRaises(ValueError):
            sequence_boundaries.next_public_sequence(MAXIMUM)


class FloorBeforeIOTests(unittest.TestCase):
    def test_observer_callable_rejects_before_opener_and_accepts_maximum(self) -> None:
        for value in (True, 0, *ALIASES):
            with self.subTest(value=value), mock.patch.object(observe_discovery_index.urllib.request, "build_opener") as opener:
                with self.assertRaises(ValueError):
                    observe_discovery_index.observe_once("https://example.invalid", Path("keys"), value)
                opener.assert_not_called()
        with mock.patch.object(observe_discovery_index.urllib.request, "build_opener", side_effect=RuntimeError("accepted")) as opener:
            with self.assertRaisesRegex(RuntimeError, "accepted"):
                observe_discovery_index.observe_once("https://example.invalid", Path("keys"), MAXIMUM)
            opener.assert_called_once()

    def test_discovery_verifier_cli_rejects_before_load_and_accepts_maximum(self) -> None:
        base = ["verify", "--feed", "feed", "--trusted-keys", "keys", "--minimum-sequence"]
        for text in ("0", "+1", " 1", str(ALIASES[0]), str(ALIASES[1])):
            with self.subTest(text=text), mock.patch.object(sys, "argv", [*base, text]), mock.patch.object(verify_discovery_index, "load_latest") as load:
                with self.assertRaises(SystemExit):
                    verify_discovery_index.main()
                load.assert_not_called()
        with mock.patch.object(sys, "argv", [*base, str(MAXIMUM)]), mock.patch.object(verify_discovery_index, "load_latest", side_effect=OSError("accepted")) as load:
            self.assertEqual(verify_discovery_index.main(), 1)
            load.assert_called_once()

    def test_directory_verifier_cli_rejects_before_path_read_and_accepts_maximum(self) -> None:
        base = ["verify", "--feed", "feed", "--trusted-keys", "keys", "--now", "2026-08-20T00:00:00Z", "--minimum-sequence"]
        for text in ("0", "-1", "1 ", str(ALIASES[0]), str(ALIASES[1])):
            with self.subTest(text=text), mock.patch.object(sys, "argv", [*base, text]), mock.patch.object(verify_directory_publication, "read_bytes_bounded") as read:
                with self.assertRaises(SystemExit):
                    verify_directory_publication.main()
                read.assert_not_called()
        with mock.patch.object(sys, "argv", [*base, str(MAXIMUM)]), mock.patch.object(verify_directory_publication, "read_bytes_bounded", side_effect=OSError("accepted")) as read:
            self.assertEqual(verify_directory_publication.main(), 1)
            read.assert_called_once()


class LaunchContextBoundaryTests(unittest.TestCase):
    def test_dispatch_accepts_maximum_and_rejects_aliases_without_observation(self) -> None:
        environment = {"HOME": "/tmp/launch-home", "AGENTPLUGINS_HOME": "/tmp/launch-manager"}
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(launch_observer, "observe", return_value={}) as observe, mock.patch.object(
            launch_observer, "directory_fault_scenario",
            return_value=(True, {"command_traces": [], "before": {}, "after": {}, "proof": {}}),
        ) as dispatch:
            result = launch_observer.run(Path("binary"), "directory_offline", Path("root"), challenge_context())
            self.assertEqual(result["outcome"], "passed")
            self.assertEqual(observe.call_count, 2)
            dispatch.assert_called_once()
        for value in ALIASES:
            with self.subTest(value=value), mock.patch.object(launch_observer, "observe") as observe, mock.patch.object(launch_observer, "directory_fault_scenario") as dispatch:
                with self.assertRaises(ValueError):
                    launch_observer.run(Path("binary"), "directory_offline", Path("root"), challenge_context(value))
                observe.assert_not_called()
                dispatch.assert_not_called()

    def test_duplicate_and_extra_context_fields_are_rejected(self) -> None:
        context = challenge_context()
        context["extra"] = "no"
        with self.assertRaises(ValueError):
            launch_observer.validate_challenge_context(context)
        with self.assertRaises(launch_observer.DuplicateKeyError):
            launch_observer.strict_json_loads('{"value":"a","value":"b"}')


class WorkflowSequenceContractTests(unittest.TestCase):
    def test_workflow_uses_reviewed_successor_without_bash_increment(self) -> None:
        workflow = (ROOT / ".github/workflows/discovery-index.yml").read_text()
        self.assertIn("scripts/sequence_boundaries.py successor", workflow)
        self.assertNotIn("$((sequence + 1))", workflow)
        self.assertNotIn("sequence=0", workflow)


if __name__ == "__main__":
    unittest.main()
