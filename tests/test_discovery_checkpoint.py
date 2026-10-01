from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import build_discovery_index as builder
from scripts.discovery_checkpoint import DiscoveryCheckpoint, atomic_json
from scripts.directory_publication import canonical_json, sha256_digest
from tests.test_discovery_index import FixtureAPI, PartitionAPI, SearchFixtureAPI, create_mirror

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc).replace(microsecond=0)
STAMP = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
CONFIG = {"schema_version": 1, "query": "schema filename:plugin.json", "maximum_file_size": 10,
          "maximum_records": 1000, "seeds": []}


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


if __name__ == "__main__":
    unittest.main()
