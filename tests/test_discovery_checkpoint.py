from __future__ import annotations

import json
import io
import tempfile
import threading
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import build_discovery_index as builder
from scripts.discovery_checkpoint import CheckpointYield, DiscoveryCheckpoint, WorkBudget, atomic_json
from scripts.directory_publication import canonical_json, sha256_digest
from tests.test_discovery_index import FixtureAPI, PartitionAPI, SearchFixtureAPI, create_mirror, git

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc).replace(microsecond=0)
STAMP = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
CONFIG = {"schema_version": 1, "query": "schema filename:plugin.json", "maximum_file_size": 10,
          "maximum_records": 1000, "seeds": []}


class FakeClock:
    seconds = 0

    def __call__(self):
        return self.seconds


class DiscoveryCheckpointTests(unittest.TestCase):
    def checkpoint(self, directory, **kwargs):
        return DiscoveryCheckpoint(directory, root=ROOT, config=kwargs.pop("config", CONFIG),
            mode=kwargs.pop("mode", "discover"), generated_at=kwargs.pop("generated_at", STAMP), now=kwargs.pop("now", NOW), **kwargs)

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
            self.assertFalse((checkpoint_dir / "validation.json").exists())
            actual = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir))
            self.assertEqual(canonical_json(actual[0]), canonical_json(expected[0]))

            with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("finished validation repeated")):
                resumed = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir), validation_only=True)
            self.assertEqual(canonical_json(resumed[0]), canonical_json(expected[0]))
            self.assertEqual(actual[1], resumed[1])

    def test_changed_revision_previous_reviewed_and_source_invalidate_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(api=FixtureAPI(revision), config=CONFIG, mode="discover", generated_at=STAMP,
                previous_records=[], mirror_root=mirror, repository_workers=1)
            checkpoint_dir = root / "checkpoint"
            candidate, _ = builder.build_candidate(**arguments, checkpoint=self.checkpoint(checkpoint_dir))
            with mock.patch.object(builder, "scan_repository", wraps=builder.scan_repository) as scan:
                builder.build_candidate(**{**arguments, "api": FixtureAPI("f" * 40)}, checkpoint=self.checkpoint(checkpoint_dir))
                self.assertEqual(scan.call_count, 1)
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

    def test_metadata_change_reuses_validation_and_matches_uninterrupted_bytes(self):
        class MetadataAPI(FixtureAPI):
            def graphql(self, query, variables):
                result = super().graphql(query, variables)
                result["r0"].update({"stargazerCount": 900, "pushedAt": "2026-10-01T00:00:00Z"})
                return result
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror, revision = create_mirror(root)
            arguments = dict(config=CONFIG, mode="discover", generated_at=STAMP, previous_records=[], mirror_root=mirror)
            builder.build_candidate(api=FixtureAPI(revision), **arguments, checkpoint=self.checkpoint(root / "checkpoint"))
            expected = builder.build_candidate(api=MetadataAPI(revision), **arguments)
            with mock.patch.object(builder, "scan_repository", side_effect=AssertionError("immutable validation repeated")):
                actual = builder.build_candidate(api=MetadataAPI(revision), **arguments, checkpoint=self.checkpoint(root / "checkpoint"))
            self.assertEqual(canonical_json(expected[0]), canonical_json(actual[0]))
            self.assertEqual(actual[0]["records"][0]["stars"], 900)

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
            checkpoint.start_validation({}, lambda records: None)
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
            restored.start_validation({}, lambda records: None)
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
