from __future__ import annotations

import json
import io
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import build_bridges, build_discovery_index as builder
from scripts.discovery_checkpoint import CheckpointYield, DiscoveryCheckpoint, WorkBudget, atomic_json
from scripts.directory_publication import canonical_json, sha256_digest
from tests.test_discovery_index import FixtureAPI, PartitionAPI, SearchFixtureAPI, candidate_record, create_mirror, git

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc).replace(microsecond=0)
STAMP = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
CONFIG = {"schema_version": 1, "query": "schema filename:plugin.json", "maximum_file_size": 10,
          "maximum_records": 1000, "seeds": []}


class FakeClock:
    seconds = 0

    def __call__(self):
        return self.seconds


def package_fixture(root, paths, invalid=()):
    """Real inert Git packages; every new commit uses the owner's identity."""
    mirror, _ = create_mirror(root, package_path=paths[0])
    source = root / "source"
    manifest = json.loads((source / paths[0] / "plugin.json").read_bytes())
    mcp = json.loads((source / paths[0] / "mcp.json").read_bytes())
    for path in paths:
        atomic_json(source / path / "plugin.json", {**manifest, "description": 42 if path in invalid else path})
        atomic_json(source / path / "mcp.json", mcp)
    git(source, "add", ".")
    git(source, "commit", "--quiet", "-m", "test: add resumable package fixtures")
    revision = git(source, "rev-parse", "HEAD")
    git(mirror / "owner/repo.git", "fetch", "--quiet", str(source), "main")
    config = {**CONFIG, "query": '"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" filename:plugin.json'}
    return dict(api=SearchFixtureAPI(revision, [("owner/repo", path + "/plugin.json" if path else "plugin.json") for path in paths]),
                config=config, mode="discover", generated_at=STAMP, previous_records=[],
                mirror_root=mirror, repository_workers=1)


class DiscoveryCheckpointTests(unittest.TestCase):
    def checkpoint(self, directory, **kwargs):
        return DiscoveryCheckpoint(directory, root=ROOT, config=kwargs.pop("config", CONFIG),
            mode=kwargs.pop("mode", "discover"), generated_at=kwargs.pop("generated_at", STAMP), now=kwargs.pop("now", NOW), **kwargs)

    def test_head_metadata_and_unavailability_are_frozen_across_validation_yield(self):
        # Red if resumed slices re-resolve heads or repeat completed validation.
        names = ["first/repo", "second/repo", "third/repo"]
        class DriftingAPI(SearchFixtureAPI):
            calls = []
            def graphql(self, query, variables):
                names = [variables[f"owner{i}"] + "/" + variables[f"name{i}"] for i in range(len(variables) // 2)]
                self.calls.extend(names)
                return {f"r{i}": None if name == "third/repo" else {
                    **FixtureAPI(self.revision).graphql(query, variables)["r0"],
                    "nameWithOwner": name, "stargazerCount": 42 if self.revision == "a" * 40 else 900,
                } for i, name in enumerate(names)}
        clock = FakeClock()
        scans = []
        def scan(name, state, pending, *args):
            scans.append((name, state["revision"]))
            clock.seconds = 2
            sample = {**candidate_record(state["revision"]), "repository": name, "owner": name.split("/")[0],
                      "slug": "discovery:" + name + "//packages/demo", "stars": state["stars"],
                      "first_seen": STAMP, "last_seen": STAMP}
            return {pending[0][1]: sample}, []
        api = DriftingAPI("a" * 40, [(name, "packages/demo/plugin.json") for name in names])
        arguments = dict(api=api, config=CONFIG, mode="discover", generated_at=STAMP, previous_records=[], repository_workers=1)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(builder, "scan_repository", side_effect=scan):
            expected = builder.build_candidate(**arguments)
            scans.clear()
            api.calls.clear()
            clock.seconds = 0
            with self.assertRaises(CheckpointYield):
                builder.build_candidate(**arguments, checkpoint=self.checkpoint(temporary), work_budget=WorkBudget(1, monotonic=clock))
            self.assertEqual(scans, [("first/repo", "a" * 40)])
            self.assertEqual(api.calls, names)
            api.revision = "b" * 40
            with mock.patch.object(api, "graphql", side_effect=AssertionError("frozen repository re-resolved")):
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(temporary), validation_only=True)
            self.assertEqual(scans, [("first/repo", "a" * 40), ("second/repo", "a" * 40)])
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))

    def test_each_resolved_batch_is_durable_before_state_resolution_yield(self):
        # Red if the first GraphQL batch is lost when the next batch yields.
        names = ["first/repo", "second/repo"]
        clock = FakeClock()
        class BatchAPI(SearchFixtureAPI):
            calls = []
            expiring = True
            def graphql(self, query, variables):
                name = variables["owner0"] + "/" + variables["name0"]
                self.calls.append(name)
                if self.expiring:
                    clock.seconds = 2
                return {"r0": {**super().graphql(query, variables)["r0"], "nameWithOwner": name}}
        api = BatchAPI("a" * 40, [(name, "packages/demo/plugin.json") for name in names])
        arguments = dict(api=api, config=CONFIG, mode="discover", generated_at=STAMP, previous_records=[])
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(builder, "REPOSITORY_GRAPHQL_BATCH", 1):
            with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("validation before all states frozen")):
                with self.assertRaises(CheckpointYield):
                    builder.build_candidate(**arguments, checkpoint=self.checkpoint(temporary), work_budget=WorkBudget(1, monotonic=clock))
            payload = json.loads((Path(temporary) / "validation.json").read_bytes())["payload"]
            self.assertEqual(set(payload["states"]), {"first/repo"})
            self.assertEqual(payload["results"], {})
            api.expiring = False
            api.revision = "b" * 40
            seen = []
            def scan(name, state, pending, *args):
                seen.append((name, state["revision"]))
                return {}, [{"kind": "invalid", "repository": name, "path": "packages/demo", "error": "fixture"}]
            with mock.patch.object(builder, "scan_repository", side_effect=scan):
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(temporary), validation_only=True)
            self.assertEqual(api.calls, names)
            self.assertEqual(sorted(seen), [("first/repo", "a" * 40), ("second/repo", "b" * 40)])
            self.assertTrue(actual[0]["complete"])

    def test_hostile_frozen_states_fail_closed_before_resolution_or_checkpoint_write(self):
        # Digest-correct edits must not become source inputs or discard/rewrite
        # existing checkpoints before the malformed state is rejected.
        arguments = dict(api=FixtureAPI("a" * 40), config=CONFIG, mode="discover", generated_at=STAMP,
                         previous_records=[])
        outcome = [{"kind": "invalid", "repository": "owner/repo", "path": "packages/demo", "error": "fixture"}]
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(builder, "scan_repository", return_value=({}, outcome)):
                builder.build_candidate(**arguments, checkpoint=self.checkpoint(temporary))
            path = Path(temporary) / "validation.json"
            pristine = json.loads(path.read_bytes())
            for mutation in ("unknown", "key_case", "missing_state", "available_type", "canonical", "canonical_case",
                             "revision", "stars", "timestamp", "extra", "unavailable_fields", "unavailable_identity",
                             "unavailable_result", "input_digest", "legacy_payload"):
                with self.subTest(mutation=mutation):
                    value = json.loads(canonical_json(pristine))
                    states = value["payload"]["states"]
                    state = states["owner/repo"]
                    if mutation == "unknown":
                        states["unknown/repo"] = dict(state)
                    elif mutation == "key_case":
                        states["Owner/repo"] = states.pop("owner/repo")
                    elif mutation == "missing_state":
                        states.clear()
                    elif mutation == "available_type":
                        state["available"] = 1
                    elif mutation.startswith("canonical"):
                        state["repository"] = "Owner/Repo" if mutation == "canonical_case" else "owner/repo/extra"
                    elif mutation == "revision":
                        state["revision"] = "a" * 39
                    elif mutation == "stars":
                        state["stars"] = True
                    elif mutation == "timestamp":
                        state["updated_at"] = "not-a-timestamp"
                    elif mutation == "extra":
                        state["untrusted"] = True
                    elif mutation.startswith("unavailable"):
                        state["available"] = False
                        if mutation != "unavailable_fields":
                            states["owner/repo"] = {"repository": "unknown/repo" if mutation == "unavailable_identity" else "owner/repo", "available": False}
                    elif mutation == "input_digest":
                        value["payload"]["results"]["owner/repo"]["input_digest"] = "sha256:" + "f" * 64
                    elif mutation == "legacy_payload":
                        del value["payload"]["states"]
                    value["payload_digest"] = sha256_digest(canonical_json(value["payload"]))
                    atomic_json(path, value)
                    before = {item.name: item.read_bytes() for item in Path(temporary).iterdir()}
                    with mock.patch.object(arguments["api"], "graphql", side_effect=AssertionError("hostile state resolved")) as resolver, \
                         mock.patch.object(builder, "scan_repository", side_effect=AssertionError("hostile state validated")) as scanner:
                        with self.assertRaises((ValueError, builder.DiscoveryError)):
                            builder.build_candidate(**arguments, checkpoint=self.checkpoint(temporary), validation_only=True)
                    resolver.assert_not_called()
                    scanner.assert_not_called()
                    self.assertEqual(before, {item.name: item.read_bytes() for item in Path(temporary).iterdir()})

    def test_failed_state_batch_write_preserves_durable_and_in_memory_inputs(self):
        # Red if failed atomic persistence mutates in-memory frozen inputs or
        # admits a result whose state was never committed.
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = self.checkpoint(temporary)
            builder.acquire_candidate(api=FixtureAPI("a" * 40), config=CONFIG, mode="discover", previous_records=[], checkpoint=checkpoint)
            checkpoint.start_validation({}, lambda records: None, ["owner/repo", "other/repo"])
            state = {"repository": "owner/repo", "revision": "a" * 40, "available": True, "stars": 1, "updated_at": STAMP}
            checkpoint.save_states({"owner/repo": state})
            before = (Path(temporary) / "validation.json").read_bytes()
            with mock.patch("scripts.discovery_checkpoint.atomic_json", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    checkpoint.save_states({"other/repo": {**state, "repository": "other/repo"}})
            self.assertEqual(checkpoint.states, {"owner/repo": state})
            self.assertEqual((Path(temporary) / "validation.json").read_bytes(), before)
            with self.assertRaisesRegex(ValueError, "lacks available frozen state"):
                checkpoint.save_result("other/repo", "sha256:" + "a" * 64, [], [])
            self.assertEqual(checkpoint.results, {})
            with self.assertRaisesRegex(ValueError, "cannot be replaced"):
                checkpoint.save_states({"owner/repo": {**state, "revision": "b" * 40}})
            self.assertEqual((Path(temporary) / "validation.json").read_bytes(), before)

    def test_interrupted_partition_resumes_only_pending_with_identical_bytes(self):
        # Red if a finished partition is re-requested or its coverage/items disappear.
        class Interrupted(PartitionAPI):
            def get(self, path, parameters=None):
                if "size:6..10" in parameters["q"]:
                    raise builder.DiscoveryError("interrupted")
                return super().get(path, parameters)

        class Resume(PartitionAPI):
            def get(self, path, parameters=None):
                if "size:6..10" not in parameters["q"]:
                    raise AssertionError("completed search repeated")
                return super().get(path, parameters)

        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = self.checkpoint(Path(temporary))
            with self.assertRaisesRegex(builder.DiscoveryError, "interrupted"):
                builder.acquire_candidate(api=Interrupted(), config=CONFIG, mode="discover", previous_records=[], checkpoint=checkpoint)
            self.assertFalse(checkpoint.payload["complete"])
            expected = builder.acquire_candidate(api=PartitionAPI(), config=CONFIG, mode="discover", previous_records=[])
            resumed = self.checkpoint(Path(temporary))
            actual = builder.acquire_candidate(api=Resume(), config=CONFIG, mode="discover", previous_records=[], checkpoint=resumed)
            self.assertEqual(expected, actual)
            self.assertTrue(resumed.payload["complete"])

    def test_seed_interruption_does_not_repeat_global_search(self):
        config = {**CONFIG, "seeds": [{"repository": "owner/repo", "paths": ["packages"]}]}
        class SeedAPI(FixtureAPI):
            fail = True
            calls = []
            def get(self, path, parameters=None):
                self.calls.append(parameters["q"])
                if " repo:" in parameters["q"] and self.fail:
                    raise builder.DiscoveryError("seed interruption")
                return super().get(path, parameters)
        with tempfile.TemporaryDirectory() as temporary:
            api = SeedAPI("a" * 40)
            checkpoint = self.checkpoint(temporary, config=config)
            with self.assertRaises(builder.DiscoveryError):
                builder.acquire_candidate(api=api, config=config, mode="discover", previous_records=[], checkpoint=checkpoint)
            api.fail = False
            api.calls = []
            builder.acquire_candidate(api=api, config=config, mode="discover", previous_records=[], checkpoint=self.checkpoint(temporary, config=config))
            self.assertEqual(len(api.calls), 1)
            self.assertIn(" repo:", api.calls[0])

    def test_validation_resume_reuses_success_and_retries_scan_error(self):
        # A missing mirror is retriable; successful immutable package parsing is reusable.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(api=FixtureAPI(revision), config=CONFIG, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror, repository_workers=1)
            expected = builder.build_candidate(**arguments)
            checkpoint_dir = root / "checkpoint"
            failed_args = {**arguments, "mirror_root": root / "absent"}
            incomplete = builder.build_candidate(**failed_args, checkpoint=self.checkpoint(checkpoint_dir))
            self.assertFalse(incomplete[0]["complete"])
            self.assertEqual(json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"], {})
            actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir))
            self.assertEqual(canonical_json(actual[0]), canonical_json(expected[0]))

            with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("finished validation repeated")):
                resumed = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir), validation_only=True)
            self.assertEqual(canonical_json(resumed[0]), canonical_json(expected[0]))
            self.assertEqual(actual[1], resumed[1])

    def test_changed_head_is_frozen_but_previous_reviewed_and_source_invalidate_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(api=FixtureAPI(revision), config=CONFIG, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror, repository_workers=1)
            checkpoint_dir = root / "checkpoint"
            candidate, _ = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir))
            with mock.patch.object(builder, "scan_repository", wraps=builder.scan_repository) as scan:
                builder.build_candidate(**{**arguments, "api": FixtureAPI("f" * 40)}, checkpoint=self.checkpoint(checkpoint_dir))
                self.assertEqual(scan.call_count, 0)
            prior = {**candidate["records"][0], "revision": "e" * 40}
            for change in ("previous", "reviewed", "source"):
                with self.subTest(change=change):
                    extra = {"previous_records": [prior]} if change == "previous" else {}
                    patch = mock.patch.object(builder, "reviewed_release_map", return_value={("owner/repo", revision, "packages/demo"): "changed"}) if change == "reviewed" else mock.patch.dict("os.environ", {"GITHUB_SHA": "b" * 40}) if change == "source" else mock.patch.dict("os.environ", {})
                    # A new runtime mirror path is a source context change, while SHA is acquisition-bound.
                    if change == "source":
                        with patch, self.assertRaisesRegex(ValueError, "implementation changed"):
                            self.checkpoint(checkpoint_dir)
                        continue
                    with patch, mock.patch.object(builder, "scan_repository", wraps=builder.scan_repository) as scan:
                        builder.build_candidate(**{**arguments, **extra}, checkpoint=self.checkpoint(checkpoint_dir))
                        self.assertEqual(scan.call_count, 1)

    def test_metadata_change_remains_frozen_and_matches_original_bytes(self):
        class MetadataAPI(FixtureAPI):
            def graphql(self, query, variables):
                result = super().graphql(query, variables)
                result["r0"].update({"stargazerCount": 900, "pushedAt": "2026-10-01T00:00:00Z"})
                return result
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(config=CONFIG, mode="discover", generated_at=STAMP, previous_records=[], mirror_root=mirror)
            expected = builder.build_candidate(api=FixtureAPI(revision), **arguments, checkpoint=self.checkpoint(root / "checkpoint"))
            with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("immutable validation repeated")):
                actual = builder.build_candidate(api=MetadataAPI(revision), **arguments, checkpoint=self.checkpoint(root / "checkpoint"))
            self.assertEqual(canonical_json(expected[0]), canonical_json(actual[0]))
            self.assertEqual(actual[0]["records"][0]["stars"], 42)

    def test_interrupted_validation_restores_first_repository_only(self):
        # Red if successful work disappears when the second repository errors.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(api=FixtureAPI(revision), config=CONFIG, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror, repository_workers=1)
            sample = builder.build_candidate(**arguments)[0]["records"][0]
            state = {"repository": "owner/repo", "revision": revision, "available": True,
                "stars": sample["stars"], "updated_at": sample["repository_updated_at"]}
            api = SearchFixtureAPI(revision, [("owner/repo", "packages/demo/plugin.json"), ("other/repo", "packages/demo/plugin.json")])
            states = {"owner/repo": state, "other/repo": {**state, "repository": "other/repo"}}
            def scan(repository_name, state, pending, *args):
                record = {**sample, "slug": "discovery:" + repository_name + "//packages/demo", "repository": repository_name, "owner": repository_name.split("/")[0]}
                return {pending[0][1]: record}, []
            checkpoint = self.checkpoint(root / "checkpoint")
            original_save = checkpoint.save_result
            def interrupted_save(*args):
                original_save(*args)
                raise OSError("process interruption after durable first repository")
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=scan), mock.patch.object(checkpoint, "save_result", side_effect=interrupted_save):
                with self.assertRaisesRegex(OSError, "interruption"):
                    builder.build_candidate(**{**arguments, "api": api}, checkpoint=checkpoint)
            resumed = self.checkpoint(root / "checkpoint")
            saved = next(iter(resumed.read(root / "checkpoint" / "validation.json", "validation")["payload"]["results"]))
            calls = []
            def remaining_scan(repository_name, *args):
                self.assertNotEqual(repository_name, saved)
                calls.append(repository_name)
                return scan(repository_name, *args)
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=remaining_scan):
                actual = builder.build_candidate(**{**arguments, "api": api}, checkpoint=resumed, validation_only=True)
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=scan):
                expected = builder.build_candidate(**{**arguments, "api": api})
            self.assertEqual(len(calls), 1)
            self.assertEqual(canonical_json(actual[0]), canonical_json(expected[0]))

    def test_configuration_implementation_timestamp_and_mode_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = self.checkpoint(temporary)
            builder.acquire_candidate(api=FixtureAPI("a" * 40), config=CONFIG, mode="discover", previous_records=[], checkpoint=checkpoint)
            with self.assertRaisesRegex(ValueError, "configuration"):
                self.checkpoint(temporary, config={**CONFIG, "maximum_file_size": 11})
            with mock.patch("scripts.discovery_checkpoint.implementation_digest", return_value="sha256:" + "0" * 64), self.assertRaisesRegex(ValueError, "implementation"):
                self.checkpoint(temporary)
            with self.assertRaisesRegex(ValueError, "mode"):
                self.checkpoint(temporary, mode="reconcile")
            with self.assertRaisesRegex(ValueError, "generated_at"):
                self.checkpoint(temporary, generated_at=(NOW + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def test_corrupt_stale_truncated_and_traversal_checkpoint_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = self.checkpoint(temporary)
            builder.acquire_candidate(api=FixtureAPI("a" * 40), config=CONFIG, mode="discover", previous_records=[], checkpoint=checkpoint)
            path = checkpoint.path
            original = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "stale"):
                self.checkpoint(temporary, now=NOW + timedelta(days=1, seconds=1))
            for mutation in ("digest", "truncated", "coverage", "traversal", "unknown", "queue_type"):
                with self.subTest(mutation=mutation):
                    value = json.loads(original)
                    if mutation == "digest":
                        value["payload"]["complete"] = False
                    elif mutation == "coverage":
                        value["payload"]["stages"][CONFIG["query"]]["partitions"] = []
                    elif mutation == "traversal":
                        value["payload"]["refresh_paths"] = {"owner/repo": ["../outside"]}
                    elif mutation == "unknown":
                        value["payload"]["token"] = "forbidden"
                    elif mutation == "queue_type":
                        value["payload"]["stages"][CONFIG["query"]]["queue"] = [[False, "10"]]
                    if mutation not in {"digest", "truncated"}:
                        value["payload_digest"] = sha256_digest(canonical_json(value["payload"]))
                    atomic_json(path, value)
                    if mutation == "truncated":
                        with path.open("wb") as stream:
                            stream.write(b"{")
                    with self.assertRaises(ValueError):
                        self.checkpoint(temporary)

    def test_atomic_write_failure_preserves_finished_partition_and_aborts(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = self.checkpoint(temporary)
            builder.acquire_candidate(api=FixtureAPI("a" * 40), config=CONFIG, mode="discover", previous_records=[], checkpoint=checkpoint)
            before = checkpoint.path.read_bytes()
            with mock.patch("scripts.discovery_checkpoint.os.replace", side_effect=OSError("disk failure")), self.assertRaises(OSError):
                checkpoint.save_acquisition()
            self.assertEqual(checkpoint.path.read_bytes(), before)
            self.assertTrue(self.checkpoint(temporary).payload["complete"])

    def test_unsupported_raw_hits_remain_inert_and_preserve_diagnostics(self):
        api = SearchFixtureAPI("a" * 40, [("owner/repo", "../plugin.json"), ("owner/repo", "packages/demo/plugin.json"),
            ("owner/repo", "nested//plugin.json"), ("owner/repo", "/leading/plugin.json"),
            ("owner/repo", "unicode/é/plugin.json"), ("bad-owner!/repo", "plugin.json")])
        config = {**CONFIG, "seeds": [{"repository": "owner/repo", "paths": [""]}]}
        with tempfile.TemporaryDirectory() as temporary:
            expected = builder.acquire_candidate(api=api, config=config, mode="discover", previous_records=[])
            actual = builder.acquire_candidate(api=api, config=config, mode="discover", previous_records=[], checkpoint=self.checkpoint(temporary, config=config))
            self.assertEqual(expected, actual)
            self.checkpoint(temporary, config=config)

    def test_cli_split_acquisition_validate_and_all_produce_same_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            config = {**CONFIG, "query": '"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" filename:plugin.json'}
            config_path = root / "config.json"
            atomic_json(config_path, config)
            common = ["build_discovery_index.py", "--mode", "discover", "--config", str(config_path),
                "--checkpoint-dir", str(root / "checkpoint"), "--mirror-root", str(mirror),
                "--diagnostics-output", str(root / "diagnostics.json")]
            with mock.patch.object(builder, "GitHubAPI", return_value=FixtureAPI(revision)):
                with mock.patch("sys.argv", common + ["--phase", "acquire", "--output", str(root / "input.json"), "--generated-at", STAMP]):
                    self.assertEqual(builder.main(), 0)
                self.assertEqual((root / "input.json").read_bytes(), (root / "checkpoint" / "acquisition.json").read_bytes())
                with mock.patch("sys.argv", common + ["--phase", "validate", "--output", str(root / "candidate.json")]):
                    self.assertEqual(builder.main(), 0)
            expected, diagnostics = builder.build_candidate(api=FixtureAPI(revision), config=config, mode="discover",
                generated_at=STAMP, previous_records=[], mirror_root=mirror)
            self.assertEqual((root / "candidate.json").read_bytes(), canonical_json(expected))
            self.assertEqual((root / "diagnostics.json").read_bytes(), canonical_json({"schema_version": 1, "diagnostics": diagnostics}))

    def test_acquisition_slice_yields_after_saved_partition_and_resumes_pending(self):
        # Red if budget expiry discards a completed partition or emits a candidate.
        clock = FakeClock()
        class ExpiringAPI(PartitionAPI):
            def get(self, path, parameters=None):
                response = super().get(path, parameters)
                if "size:0..5" in parameters["q"]:
                    clock.seconds = 2
                return response
        class PendingAPI(PartitionAPI):
            def get(self, path, parameters=None):
                self.assert_path(path)
                if "size:6..10" not in parameters["q"]:
                    raise AssertionError("completed partition repeated")
                return super().get(path, parameters)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {**CONFIG, "query": '"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" filename:plugin.json'}
            atomic_json(root / "config.json", config)
            command = ["build_discovery_index.py", "--mode", "discover", "--phase", "acquire", "--config", str(root / "config.json"),
                "--checkpoint-dir", str(root / "checkpoint"), "--output", str(root / "candidate.json"),
                "--diagnostics-output", str(root / "diagnostics.json"), "--work-budget-seconds", "1"]
            with mock.patch.object(builder, "GitHubAPI", return_value=ExpiringAPI()), mock.patch.object(builder, "WorkBudget", return_value=WorkBudget(1, monotonic=clock)), mock.patch("sys.argv", command):
                self.assertEqual(builder.main(), 4)
            self.assertFalse((root / "candidate.json").exists())
            self.assertFalse((root / "diagnostics.json").exists())
            checkpoint = DiscoveryCheckpoint(root / "checkpoint", root=ROOT, config=config, mode="discover")
            self.assertFalse(checkpoint.payload["complete"])
            actual = builder.acquire_candidate(api=PendingAPI(), config=config, mode="discover", previous_records=[], checkpoint=checkpoint)
            expected = builder.acquire_candidate(api=PartitionAPI(), config=config, mode="discover", previous_records=[])
            self.assertEqual(actual, expected)

    def test_validation_slice_stops_admission_saves_success_and_resumes(self):
        # Red if a queued repo starts after expiry, or yield becomes scan_error.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(api=FixtureAPI(revision), config=CONFIG, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror, repository_workers=1)
            sample = builder.build_candidate(**arguments)[0]["records"][0]
            names = ["first/repo", "second/repo", "third/repo"]
            api = SearchFixtureAPI(revision, [(name, "packages/demo/plugin.json") for name in names])
            states = {name: {"repository": name, "revision": revision, "available": True,
                "stars": sample["stars"], "updated_at": sample["repository_updated_at"]} for name in names}
            clock = FakeClock()
            calls = []
            def scan(name, state, pending, *args):
                calls.append(name)
                clock.seconds = 2
                record = {**sample, "slug": "discovery:" + name + "//packages/demo", "repository": name, "owner": name.split("/")[0]}
                return {pending[0][1]: record}, []
            checkpoint_dir = root / "checkpoint"
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=scan):
                with self.assertRaises(CheckpointYield):
                    builder.build_candidate(**{**arguments, "api": api}, checkpoint=self.checkpoint(checkpoint_dir), work_budget=WorkBudget(1, monotonic=clock))
            self.assertEqual(calls, ["first/repo"])
            saved = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]
            self.assertEqual(set(saved), {"first/repo"})
            self.assertEqual(saved["first/repo"]["diagnostics"], [])
            calls.clear()
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=scan):
                actual = builder.build_candidate(**{**arguments, "api": api}, checkpoint=self.checkpoint(checkpoint_dir), validation_only=True)
                self.assertEqual(calls, ["second/repo", "third/repo"])
                expected = builder.build_candidate(**{**arguments, "api": api})
            self.assertEqual(canonical_json(actual[0]), canonical_json(expected[0]))

            # Both already-running reads must be saved when the first result
            # reaches the deadline; a third read must never be admitted.
            barrier = threading.Barrier(2)
            clock.seconds = 0
            calls.clear()
            def inflight_scan(name, *args):
                barrier.wait(timeout=5)
                return scan(name, *args)
            inflight_dir = root / "inflight-checkpoint"
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=inflight_scan):
                with self.assertRaises(CheckpointYield):
                    builder.build_candidate(**{**arguments, "api": api, "repository_workers": 2}, checkpoint=self.checkpoint(inflight_dir), work_budget=WorkBudget(1, monotonic=clock))
            inflight = json.loads((inflight_dir / "validation.json").read_bytes())["payload"]["results"]
            self.assertEqual(set(calls), {"first/repo", "second/repo"})
            self.assertEqual(set(inflight), set(calls))

    def test_retry_wait_is_honored_across_slice_without_losing_partition_progress(self):
        clock = FakeClock()
        budget = WorkBudget(2, monotonic=clock)
        api = builder.GitHubAPI("fixture-token", work_budget=budget)
        error = urllib.error.HTTPError("https://api.github.com/search/code", 429, "limited", {"Retry-After": "120"}, io.BytesIO(b"rate limited"))
        class RateLimitedLastPartition(PartitionAPI):
            def get(self, path, parameters=None):
                if "size:6..10" in parameters["q"]:
                    return api.get(path, parameters)
                return super().get(path, parameters)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint_dir = root / "checkpoint"
            config = {**CONFIG, "query": '"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" filename:plugin.json'}
            atomic_json(root / "config.json", config)
            command = ["build_discovery_index.py", "--mode", "discover", "--phase", "acquire", "--config", str(root / "config.json"),
                "--checkpoint-dir", str(checkpoint_dir), "--output", str(root / "candidate.json"),
                "--diagnostics-output", str(root / "diagnostics.json"), "--work-budget-seconds", "2", "--generated-at", STAMP]
            def advance(seconds):
                clock.seconds += seconds
            with mock.patch.object(api.opener, "open", side_effect=error) as opened, mock.patch.object(builder.time, "sleep", side_effect=advance) as sleep, mock.patch.object(builder, "GitHubAPI", return_value=RateLimitedLastPartition()), mock.patch.object(builder, "WorkBudget", return_value=budget), mock.patch("sys.argv", command):
                self.assertEqual(builder.main(), 4)
                self.assertEqual(opened.call_count, 1)
                sleep.assert_called_once_with(120)
                self.assertEqual(clock.seconds, 120)
            self.assertFalse((root / "candidate.json").exists())
            retained = self.checkpoint(checkpoint_dir, config=config).payload["stages"][config["query"]]
            self.assertEqual(retained["queue"], [[6, 10]])
            self.assertEqual(len(retained["items"]), 51)
            next_api = builder.GitHubAPI("fixture-token", work_budget=WorkBudget(2, monotonic=clock))
            response = mock.Mock()
            response.read.return_value = json.dumps(PartitionAPI().get("search/code", {"q": config["query"] + " size:6..10", "page": 1, "sort": "indexed", "order": "asc"})).encode()
            with mock.patch.object(next_api.opener, "open") as opened:
                opened.return_value.__enter__.return_value = response
                actual = builder.acquire_candidate(api=next_api, config=config, mode="discover", previous_records=[], checkpoint=self.checkpoint(checkpoint_dir, config=config))
                self.assertEqual(opened.call_count, 1)
                self.assertEqual(clock.seconds, 120)
            expected = builder.acquire_candidate(api=PartitionAPI(), config=config, mode="discover", previous_records=[])
            self.assertEqual(actual, expected)
        with mock.patch.object(api.opener, "open") as opened, self.assertRaises(CheckpointYield):
            api.graphql("query { fixture }", {})
        opened.assert_not_called()

    def test_package_yield_is_not_classified_as_invalid(self):
        pinned = mock.Mock()
        with mock.patch.object(builder, "PinnedRepository", return_value=pinned), mock.patch.object(builder, "make_record", side_effect=CheckpointYield("slice")):
            with self.assertRaises(CheckpointYield):
                builder.scan_repository("owner/repo", {"repository": "owner/repo", "revision": "a" * 40},
                    [("packages/demo", "owner/repo\x00packages/demo", None)], STAMP, {}, Path("/inert-mirror"))
        pinned.close.assert_called_once()

    def test_validation_deadline_interrupts_blob_read_preserves_completed_and_resumes(self):
        # Red if an active blob read drains beyond the slice, caches its partial
        # repository, or writes a candidate on yield instead of exit 4.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root, repository="first/repo")
            (mirror / "second").mkdir()
            git(root, "clone", "--quiet", "--bare", str(mirror / "first/repo.git"), str(mirror / "second/repo.git"))
            names = ["first/repo", "second/repo"]
            config = {**CONFIG, "query": '"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" filename:plugin.json'}
            api = SearchFixtureAPI(revision, [(name, "packages/demo/plugin.json") for name in names])
            states = {name: {"repository": name, "revision": revision, "available": True,
                "stars": 1, "updated_at": STAMP} for name in names}
            checkpoint_dir = root / "checkpoint"
            builder.acquire_candidate(api=api, config=config, mode="discover", previous_records=[],
                checkpoint=self.checkpoint(checkpoint_dir, config=config))
            acquisition_bytes = (checkpoint_dir / "acquisition.json").read_bytes()
            atomic_json(root / "config.json", config)
            command = ["build_discovery_index.py", "--mode", "discover", "--phase", "validate",
                "--config", str(root / "config.json"), "--checkpoint-dir", str(checkpoint_dir),
                "--mirror-root", str(mirror), "--repository-workers", "1", "--work-budget-seconds", "30",
                "--output", str(root / "candidate.json"), "--diagnostics-output", str(root / "diagnostics.json")]
            original_scan, original_popen, original_git = builder.scan_repository, subprocess.Popen, builder.git
            budget = WorkBudget(30)
            current = []
            stalled = []
            stalled_started = []
            def scan(name, *args):
                current[:] = [name]
                return original_scan(name, *args)
            def bounded_git(directory, *args, **kwargs):
                if current == ["second/repo"] and args[0] == "show":
                    # Reserve the short deadline for the stalled boundary,
                    # independent of fixture Git speed on an overloaded CI VM.
                    stalled_started.append(time.monotonic())
                    budget.deadline = stalled_started[-1] + 0.2
                return original_git(directory, *args, **kwargs)
            def popen(arguments, **kwargs):
                if current == ["second/repo"] and arguments[:2] == ["git", "show"]:
                    # Inert test-only process and child retain both output pipes.
                    # The actual Git runner must kill the group before draining.
                    arguments = [sys.executable, "-c", "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)']); time.sleep(3)"]
                    process = original_popen(arguments, **kwargs)
                    stalled.append(process)
                    return process
                return original_popen(arguments, **kwargs)
            with mock.patch.object(builder, "WorkBudget", return_value=budget), mock.patch.object(builder, "GitHubAPI", return_value=api), mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", side_effect=scan), mock.patch.object(builder, "git", side_effect=bounded_git), mock.patch.object(build_bridges.subprocess, "Popen", side_effect=popen), mock.patch("sys.argv", command):
                self.assertEqual(builder.main(), 4)
            self.assertEqual(len(stalled), 1)
            self.assertLess(time.monotonic() - stalled_started[0], 2)
            self.assertIsNotNone(stalled[0].returncode)
            self.assertFalse((root / "candidate.json").exists())
            self.assertFalse((root / "diagnostics.json").exists())
            self.assertEqual((checkpoint_dir / "acquisition.json").read_bytes(), acquisition_bytes)
            saved = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]
            self.assertEqual(set(saved), {"first/repo"})
            self.assertEqual(saved["first/repo"]["diagnostics"], [])
            arguments = dict(api=api, config=config, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror, repository_workers=1)
            with mock.patch.object(builder, "repository_states", return_value=states), mock.patch.object(builder, "scan_repository", wraps=original_scan) as resumed_scan:
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=config), validation_only=True)
                self.assertEqual([call.args[0] for call in resumed_scan.call_args_list], ["second/repo"])
                expected = builder.build_candidate(**arguments)
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))

    def test_constructor_deadline_cleans_temporary_repository(self):
        # Red if acquisition timeout becomes scan_error or leaks a bare repo.
        original_popen, original_temporary = subprocess.Popen, tempfile.TemporaryDirectory
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def popen(arguments, **kwargs):
                return original_popen([sys.executable, "-c", "import time; time.sleep(3)"], **kwargs)
            def temporary_repository(**kwargs):
                return original_temporary(dir=root, **kwargs)
            with mock.patch.object(build_bridges.subprocess, "Popen", side_effect=popen), mock.patch.object(build_bridges.tempfile, "TemporaryDirectory", side_effect=temporary_repository):
                with self.assertRaises(CheckpointYield):
                    build_bridges.PinnedRepository("owner/repo", "a" * 40, None, work_budget=WorkBudget(0.1))
            self.assertEqual(list(root.iterdir()), [])

    def test_package_yield_preserves_first_package_and_resume_only_missing_with_same_bytes(self):
        # Red when repository interruption repeats its already validated package
        # or publishes a candidate with only a prefix of its immutable inputs.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ["packages/a", "packages/b"]
            arguments = package_fixture(root, paths)
            expected = builder.build_candidate(**arguments)
            checkpoint_dir = root / "checkpoint"
            builder.acquire_candidate(api=arguments["api"], config=arguments["config"], mode="discover", previous_records=[],
                checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]))
            acquisition_bytes = (checkpoint_dir / "acquisition.json").read_bytes()
            atomic_json(root / "config.json", arguments["config"])
            command = ["build_discovery_index.py", "--mode", "discover", "--phase", "validate",
                "--config", str(root / "config.json"), "--checkpoint-dir", str(checkpoint_dir),
                "--mirror-root", str(arguments["mirror_root"]), "--repository-workers", "1", "--work-budget-seconds", "1",
                "--output", str(root / "candidate.json"), "--diagnostics-output", str(root / "diagnostics.json")]
            clock, make_record = FakeClock(), builder.make_record
            calls = []
            def interrupted(repository, state, path, *args):
                calls.append(path)
                if path == paths[1]:
                    clock.seconds = 2
                    repository.work_budget.check()
                return make_record(repository, state, path, *args)
            checkpoint_writer = threading.get_ident()
            original_save = DiscoveryCheckpoint.save_result
            def save(checkpoint, *args):
                self.assertEqual(threading.get_ident(), checkpoint_writer)
                return original_save(checkpoint, *args)
            with mock.patch.object(builder, "GitHubAPI", return_value=arguments["api"]), mock.patch.object(builder, "WorkBudget", return_value=WorkBudget(1, monotonic=clock)), mock.patch.object(builder, "make_record", side_effect=interrupted), mock.patch.object(DiscoveryCheckpoint, "save_result", new=save), mock.patch("sys.argv", command):
                self.assertEqual(builder.main(), 4)
            self.assertEqual(calls, paths)
            self.assertFalse((root / "candidate.json").exists())
            self.assertFalse((root / "diagnostics.json").exists())
            self.assertEqual((checkpoint_dir / "acquisition.json").read_bytes(), acquisition_bytes)
            partial = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]["owner/repo"]
            self.assertFalse(partial["complete"])
            self.assertEqual([identity for identity, _ in partial["records"]], ["owner/repo\x00" + paths[0]])
            with mock.patch.object(builder, "make_record", wraps=make_record) as resumed:
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertEqual([call.args[2] for call in resumed.call_args_list], [paths[1]])
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))
            finished = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]["owner/repo"]
            self.assertEqual(finished["input_digest"], partial["input_digest"])
            self.assertTrue(finished["complete"])

    def test_partial_keeps_valid_invalid_and_prior_outcomes_retries_error_and_tail_in_original_order(self):
        # Red if a transient error discards unrelated completed outcomes, an
        # unavailable prior loses its invalid diagnostic, or resume reorders errors.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ["packages/a-invalid", "packages/b-valid", "packages/c-error", "packages/d-invalid", "packages/e-tail"]
            arguments = package_fixture(root, paths, invalid=(paths[0], paths[3]))
            sample = builder.build_candidate(**arguments)[0]["records"][0]
            prior = {**sample, "slug": "discovery:owner/repo//" + paths[3], "package_path": paths[3], "revision": "e" * 40}
            arguments["previous_records"] = [prior]
            expected = builder.build_candidate(**arguments)
            checkpoint_dir = root / "checkpoint"
            make_record = builder.make_record
            def interrupted(repository, state, path, *args):
                if path == paths[2]:
                    raise build_bridges.BridgeError("transient inert source failure")
                if path == paths[4]:
                    raise CheckpointYield("fixture slice boundary")
                return make_record(repository, state, path, *args)
            with mock.patch.object(builder, "make_record", side_effect=interrupted), self.assertRaises(CheckpointYield):
                builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]))
            partial = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]["owner/repo"]
            self.assertFalse(partial["complete"])
            self.assertEqual([item["path"] for item in partial["diagnostics"]], [paths[0], paths[3]])
            self.assertEqual(set(dict(partial["records"])), {"owner/repo\x00" + paths[1], "owner/repo\x00" + paths[3]})
            self.assertEqual(dict(partial["records"])["owner/repo\x00" + paths[3]], {**prior, "availability": "unavailable"})
            # A digest-correct cache must not drop the unavailable fallback:
            # otherwise the previous available record silently survives.
            validation_path = checkpoint_dir / "validation.json"
            envelope = json.loads(validation_path.read_bytes())
            broken = json.loads(canonical_json(envelope))
            broken["payload"]["results"]["owner/repo"]["records"] = [
                entry for entry in partial["records"] if entry[0] != "owner/repo\x00" + paths[3]
            ]
            broken["payload_digest"] = sha256_digest(canonical_json(broken["payload"]))
            atomic_json(validation_path, broken)
            with mock.patch.object(builder, "scan_repository") as scanner, self.assertRaisesRegex(builder.DiscoveryError, "missing unavailable"):
                builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            scanner.assert_not_called()
            atomic_json(validation_path, envelope)
            # Another transient failure with no yield must keep the prior safe
            # prefix and still leave only that failing package retryable.
            def transient(repository, state, path, *args):
                if path == paths[2]:
                    raise build_bridges.BridgeError("retry source failure")
                return make_record(repository, state, path, *args)
            with mock.patch.object(builder, "make_record", side_effect=transient) as retried:
                incomplete = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertFalse(incomplete[0]["complete"])
            self.assertEqual([call.args[2] for call in retried.call_args_list], [paths[2], paths[4]])
            with mock.patch.object(builder, "make_record", wraps=make_record) as resumed:
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertEqual([call.args[2] for call in resumed.call_args_list], [paths[2]])
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))

    def test_transient_repository_acquisition_preserves_completed_root_package(self):
        # A repository-level fetch error uses path=''. It must not discard an
        # earlier completed root package which has the same empty package path.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ["", "packages/tail"]
            arguments = package_fixture(root, paths)
            expected = builder.build_candidate(**arguments)
            checkpoint_dir = root / "checkpoint"
            make_record = builder.make_record
            def interrupted(repository, state, path, *args):
                if path == paths[1]:
                    raise CheckpointYield("fixture slice boundary")
                return make_record(repository, state, path, *args)
            with mock.patch.object(builder, "make_record", side_effect=interrupted), self.assertRaises(CheckpointYield):
                builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]))
            with mock.patch.object(builder, "PinnedRepository", side_effect=build_bridges.BridgeError("transient fixture fetch")):
                failed = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertFalse(failed[0]["complete"])
            saved = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]["owner/repo"]
            self.assertEqual(set(dict(saved["records"])), {"owner/repo\x00"})
            with mock.patch.object(builder, "make_record", wraps=make_record) as resumed:
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertEqual([call.args[2] for call in resumed.call_args_list], [paths[1]])
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))

    def test_record_associated_with_scan_error_is_not_cached_as_success(self):
        # Even a returned record cannot prove completion of a failed package.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ["packages/a", "packages/b"]
            arguments = package_fixture(root, paths)
            expected = builder.build_candidate(**arguments)
            records = {builder.record_identity(record["repository"], record["package_path"]): record for record in expected[0]["records"]}
            checkpoint_dir = root / "checkpoint"
            with mock.patch.object(builder, "scan_repository", return_value=(records, [{
                "kind": "scan_error", "repository": "owner/repo", "path": paths[1], "error": "transient fixture source failure",
            }])):
                failed = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]))
            self.assertFalse(failed[0]["complete"])
            saved = json.loads((checkpoint_dir / "validation.json").read_bytes())["payload"]["results"]["owner/repo"]
            self.assertEqual(set(dict(saved["records"])), {"owner/repo\x00" + paths[0]})
            self.assertFalse(saved["complete"])
            with mock.patch.object(builder, "make_record", wraps=builder.make_record) as resumed:
                actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertEqual([call.args[2] for call in resumed.call_args_list], [paths[1]])
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))

    def test_hostile_partial_package_outcomes_fail_closed_before_any_read(self):
        # Every mutation remains digest-correct and schema-valid where possible;
        # it must fail at the immutable package outcome boundary, not be reused.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ["packages/a", "packages/b"]
            arguments = package_fixture(root, paths)
            checkpoint_dir = root / "checkpoint"
            expected = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]))
            path = checkpoint_dir / "validation.json"
            complete = json.loads(path.read_bytes())
            partial = json.loads(path.read_bytes())
            result = partial["payload"]["results"]["owner/repo"]
            result["complete"] = False
            result["records"] = result["records"][:1]
            def invalid(package_path):
                return {"kind": "invalid", "repository": "owner/repo", "path": package_path, "error": "fixture invalid"}
            mutations = ("unknown", "wrong_revision", "wrong_path", "duplicate_records", "duplicate_diagnostics",
                         "conflicting_outcomes", "false_complete", "partial_all", "unavailable_no_invalid", "unavailable_not_prior",
                         "unknown_diagnostic", "wrong_diagnostic_repository", "scan_error", "missing_complete", "complete_type")
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    value = json.loads(canonical_json(partial))
                    result = value["payload"]["results"]["owner/repo"]
                    identity, record = result["records"][0]
                    if mutation == "unknown":
                        result["records"][0][0] = "unknown/repo\x00packages/a"
                    elif mutation == "wrong_revision":
                        record["revision"] = "f" * 40
                    elif mutation == "wrong_path":
                        record.update(package_path=paths[1], slug="discovery:owner/repo//" + paths[1])
                    elif mutation == "duplicate_records":
                        result["records"].append([identity, record])
                    elif mutation == "duplicate_diagnostics":
                        result["records"] = []
                        result["diagnostics"] = [invalid(paths[0]), invalid(paths[0])]
                    elif mutation == "conflicting_outcomes":
                        result["diagnostics"] = [invalid(paths[0])]
                    elif mutation == "false_complete":
                        result["complete"] = True
                    elif mutation == "partial_all":
                        result["records"] = complete["payload"]["results"]["owner/repo"]["records"]
                    elif mutation.startswith("unavailable_"):
                        record["availability"] = "unavailable"
                        if mutation == "unavailable_not_prior":
                            result["diagnostics"] = [invalid(paths[0])]
                    elif mutation == "unknown_diagnostic":
                        result["diagnostics"] = [invalid("packages/unknown")]
                    elif mutation == "wrong_diagnostic_repository":
                        result["diagnostics"] = [{**invalid(paths[1]), "repository": "unknown/repo"}]
                    elif mutation == "scan_error":
                        result["diagnostics"] = [{**invalid(paths[1]), "kind": "scan_error"}]
                    elif mutation == "missing_complete":
                        del result["complete"]
                    elif mutation == "complete_type":
                        result["complete"] = 1
                    value["payload_digest"] = sha256_digest(canonical_json(value["payload"]))
                    atomic_json(path, value)
                    with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("hostile cache admitted")) as scanner:
                        with self.assertRaises((ValueError, builder.DiscoveryError)):
                            builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
                    scanner.assert_not_called()
            atomic_json(path, complete)
            actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir, config=arguments["config"]), validation_only=True)
            self.assertEqual(canonical_json(list(actual)), canonical_json(list(expected)))

    def test_overlong_manifest_error_remains_resumable_and_byte_identical(self):
        # A real schema error echoes its invalid 70k value. Red if the writer
        # produces a checkpoint that its strict reader rejects on the next slice.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, _ = create_mirror(root)
            source = root / "source"
            manifest_path = source / "packages" / "demo" / "plugin.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["description"] = {"invalid-string-type": "x" * 70_000}
            atomic_json(manifest_path, manifest)
            git(source, "add", "packages/demo/plugin.json")
            git(source, "commit", "--quiet", "-m", "test: add oversized invalid manifest fixture")
            revision = git(source, "rev-parse", "HEAD")
            git(mirror / "owner/repo.git", "fetch", "--quiet", str(source), "main")
            arguments = dict(api=FixtureAPI(revision), config=CONFIG, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror)
            expected = builder.build_candidate(**arguments)
            self.assertTrue(expected[0]["complete"])
            self.assertEqual(expected[1][0]["kind"], "invalid")
            self.assertEqual(len(expected[1][0]["error"]), builder.MAX_DIAGNOSTIC_ERROR_CHARS)
            checkpoint_dir = root / "checkpoint"
            initial = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir))
            with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("finished invalid outcome repeated")):
                resumed = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir), validation_only=True)
            for result in (initial, resumed):
                self.assertEqual(canonical_json(result[0]), canonical_json(expected[0]))
                self.assertEqual(canonical_json(result[1]), canonical_json(expected[1]))
            with mock.patch.object(builder, "scan_repository", side_effect=RuntimeError("z" * 70_000)):
                incomplete = builder.build_candidate(**arguments)
            self.assertFalse(incomplete[0]["complete"])
            self.assertEqual(incomplete[1][0]["kind"], "scan_error")
            self.assertEqual(len(incomplete[1][0]["error"]), builder.MAX_DIAGNOSTIC_ERROR_CHARS)

    def test_writer_rejects_oversized_diagnostic_before_mutating_existing_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = self.checkpoint(temporary)
            builder.acquire_candidate(api=FixtureAPI("a" * 40), config=CONFIG, mode="discover", previous_records=[], checkpoint=checkpoint)
            checkpoint.start_validation({}, lambda records: None, ["owner/repo", "other/repo"])
            checkpoint.save_states({"owner/repo": {"repository": "owner/repo", "revision": "a" * 40,
                "available": True, "stars": 0, "updated_at": STAMP}})
            checkpoint.save_result("owner/repo", "sha256:" + "a" * 64, [], [
                {"kind": "invalid", "repository": "owner/repo", "path": "packages/demo", "error": "valid bounded diagnostic"}])
            before_bytes = (checkpoint.directory / "validation.json").read_bytes()
            before_results = canonical_json(checkpoint.results)
            with self.assertRaisesRegex(ValueError, "invalid string"):
                checkpoint.save_result("other/repo", "sha256:" + "b" * 64, [], [
                    {"kind": "invalid", "repository": "other/repo", "path": "packages/demo", "error": "x" * 65_537}])
            self.assertEqual((checkpoint.directory / "validation.json").read_bytes(), before_bytes)
            self.assertEqual(canonical_json(checkpoint.results), before_results)
            restored = self.checkpoint(temporary)
            restored.start_validation({}, lambda records: None, ["owner/repo", "other/repo"])
            self.assertEqual(canonical_json(restored.results), before_results)

    def test_slice_budget_rejects_unbounded_invalid_or_unsplit_requests(self):
        for value in (0, -1, float("inf"), float("nan"), 86401):
            with self.subTest(value=value), self.assertRaises(ValueError):
                WorkBudget(value)
        command = ["build_discovery_index.py", "--mode", "discover", "--output", "unused.json",
            "--diagnostics-output", "unused-diagnostics.json", "--work-budget-seconds", "10"]
        with mock.patch("sys.argv", command):
            self.assertEqual(builder.main(), 1)


if __name__ == "__main__":
    unittest.main()
