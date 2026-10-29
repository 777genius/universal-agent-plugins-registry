from __future__ import annotations

import base64
import copy
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import skillspector_coverage as coverage
from scripts import publish_skillspector_coverage as publisher
from scripts import build_discovery_index as acquisition
from scripts import discover_skillspector_sources as discovery
from scripts import skillspector_reports as legacy
from scripts.directory_publication import PublicationError, canonical_json, format_timestamp, sha256_digest
from scripts.discovery_checkpoint import CheckpointYield
from tests.test_skillspector_reports import fixture_repository, item, scanner, upstream_report

COMMIT = "c" * 40


def ago(days=0):
    return format_timestamp(datetime.now(timezone.utc) - timedelta(days=days, seconds=2))


def outcome(subject, *, status="error", days=0):
    record = legacy.empty_record(subject)
    if status != "error":
        record.update(status=status, scanned_at=ago(days), report_digest="sha256:" + "b" * 64)
        record["source"]["content_digest"] = "sha256:" + "a" * 64
        if status == "partial":
            legacy.add_error(record, "partial", "Incomplete static coverage.")
    else:
        legacy.add_error(record, "acquisition_failed", "Source unavailable.")
    return {"id": subject["id"], "source_digest": coverage.source_digest(subject),
            "last_attempted_at": ago(days), "record": record}


def worker(selection, outcomes=(), *, index=0, count=1):
    return {"schema_version": 2, "source_commit": COMMIT, "generated_at": legacy.now(),
        "selection_digest": sha256_digest(canonical_json(selection)), "scanner": coverage.SCANNER,
        "profile": coverage.PROFILE, "partition": {"index": index, "count": count}, "attempts": list(outcomes)}


def bundle(directory, selection=None, outcomes=None):
    selection = selection or {"schema_version": 1, "sources": [item()]}
    outcomes = [outcome(selection["sources"][0])] if outcomes is None else outcomes
    coverage.merge_reports(selection, None, [worker(selection, outcomes)], source_commit=COMMIT, output_dir=directory)
    return coverage.read_bundle(directory)


class CoverageTests(unittest.TestCase):
    def test_thousand_roots_roll_forward_without_fabricating_pending_evidence(self):
        selection = {"schema_version": 1, "sources": [item(id=f"fixture/{n:04d}", path=f"skills/s{n}") for n in range(1000)]}
        chosen = coverage.plan_attempts(selection, None, 0, 1, 128)
        self.assertEqual(len(chosen), 128)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = bundle(root, selection, [outcome(source) for source in chosen])
            self.assertEqual(first["manifest"]["coverage"], {"selected": 1000, "reported": 128, "pending": 872})
            following = coverage.plan_attempts(selection, first, 0, 1, 128)
            self.assertEqual(following[0]["id"], "fixture/0128")
            self.assertFalse(set(first["records"]) & {source["id"] for source in following})

    def test_cache_partial_and_complete_seven_days_errors_one_day(self):
        subjects = [item(id=f"fixture/{n}", path=f"skills/s{n}") for n in range(4)]
        selection = {"schema_version": 1, "sources": subjects}
        with tempfile.TemporaryDirectory() as temporary:
            prior = bundle(Path(temporary), selection, [outcome(subjects[0], status="complete", days=2),
                outcome(subjects[1], status="partial", days=2), outcome(subjects[2], days=0),
                outcome(subjects[3], status="complete", days=8)])
            self.assertEqual([s["id"] for s in coverage.plan_attempts(selection, prior, 0, 1, 128)], [subjects[3]["id"]])

    def test_old_failures_cannot_starve_never_attempted_sources_and_revision_changes(self):
        subjects = [item(id=f"fixture/{n}", path=f"skills/s{n}") for n in range(3)]
        selection = {"schema_version": 1, "sources": subjects}
        with tempfile.TemporaryDirectory() as temporary:
            prior = bundle(Path(temporary), selection, [outcome(subjects[0], days=5), outcome(subjects[1], days=2)])
            chosen = coverage.plan_attempts(selection, prior, 0, 1, 128)
            self.assertEqual([s["id"] for s in chosen], [subjects[2]["id"], subjects[0]["id"], subjects[1]["id"]])
            changed = copy.deepcopy(selection)
            changed["sources"][0]["revision"] = "d" * 40
            records, _ = coverage.compatible_previous(prior, changed)
            self.assertNotIn(subjects[0]["id"], records)

    def test_logical_progress_survives_four_serialized_repository_head_changes(self):
        selection = {"schema_version": 1, "sources": [item(id=f"fixture/{n:03d}", path=f"skills/s{n}") for n in range(129)]}
        previous, visited = None, set()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number, revision in enumerate("abcd"):
                current = copy.deepcopy(selection)
                for subject in current["sources"]:
                    subject["revision"] = revision * 40
                chosen = coverage.plan_attempts(current, previous, 0, 1, 128)
                self.assertEqual(len(chosen), 128)
                if number == 1:
                    self.assertEqual(chosen[0]["id"], "fixture/128")
                visited.update(subject["id"] for subject in chosen)
                coverage.merge_reports(current, previous, [worker(current,
                    [outcome(subject, status="complete", days=4 - number) for subject in chosen])],
                    source_commit=COMMIT, output_dir=root / str(number))
                previous = coverage.read_bundle(root / str(number))
                self.assertEqual(previous["manifest"]["coverage"]["pending"], 1)
                self.assertTrue(all(record["source"]["revision"] == revision * 40
                    for record in previous["records"].values()))
                self.assertEqual(len(previous["history"]), 128 if number == 0 else 129)
        self.assertEqual(len(visited), 129)

    def test_legacy_attempts_derive_history_and_pending_history_survives_without_evidence(self):
        selection = {"schema_version": 1, "sources": [item(id="fixture/known"),
            item(id="fixture/new", path="skills/new")]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prior = bundle(root / "legacy", selection,
                [outcome(selection["sources"][0], status="complete", days=1)])
            state_path = root / "legacy" / "attempts.json"
            state = coverage.read_json(state_path, max_bytes=coverage.MAX_STATE_BYTES)
            del state["history"]
            coverage.write_bounded(state_path, state, coverage.MAX_STATE_BYTES)
            prior = coverage.read_bundle(root / "legacy")
            self.assertEqual(len(prior["history"]), 1)
            changed = copy.deepcopy(selection)
            changed["sources"][0].update(id="fixture/renamed", revision="d" * 40)
            changed["sources"][1]["revision"] = "d" * 40
            coverage.merge_reports(changed, prior, [worker(changed)], source_commit=COMMIT,
                output_dir=root / "pending")
            pending = coverage.read_bundle(root / "pending")
            self.assertEqual(pending["records"], {})
            self.assertEqual(pending["attempts"], {})
            self.assertEqual(pending["manifest"]["coverage"], {"selected": 2, "reported": 0, "pending": 2})
            history = list(pending["history"].values())
            self.assertEqual([entry["id"] for entry in history], ["fixture/renamed"])
            self.assertEqual(history[0]["last_attempted_at"], list(prior["history"].values())[0]["last_attempted_at"])
            self.assertEqual([subject["id"] for subject in coverage.plan_attempts(changed, pending, 0, 1, 128)],
                ["fixture/new", "fixture/renamed"])
            self.assertEqual(coverage.logical_digest(item(repository="OWNER/REPO", revision="b" * 40)),
                coverage.logical_digest(item()))

    def test_logical_history_rejects_unknown_duplicate_future_and_regressed_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prior = bundle(root)
            path = root / "attempts.json"
            valid = coverage.read_json(path, max_bytes=coverage.MAX_STATE_BYTES)
            variants = [None]
            for modify in (
                lambda state: state.update(history=[]),
                lambda state: state["history"].append(copy.deepcopy(state["history"][0])),
                lambda state: state["history"][0].update(id="unknown/subject"),
                lambda state: state["history"][0].update(logical_digest="sha256:" + "0" * 64),
                lambda state: state["history"][0].update(last_attempted_at="2099-01-01T00:00:00Z"),
                lambda state: state["history"][0].update(last_attempted_at=ago(5)),
                lambda state: state.update(history=[state["history"][0]] * (coverage.MAX_SOURCES + 1)),
            ):
                altered = copy.deepcopy(valid)
                modify(altered)
                variants.append(altered)
            for altered in variants:
                with self.subTest(history=altered):
                    coverage.write_bounded(path, altered, coverage.MAX_STATE_BYTES)
                    with self.assertRaises(PublicationError):
                        coverage.read_bundle(root)

    def test_repository_partition_is_case_insensitive_and_exclusive(self):
        self.assertEqual(coverage.partition_for("Owner/Repo"), coverage.partition_for("owner/repo"))
        subjects = [item(id=f"fixture/{n}", repository=f"owner/repo{n}", path=f"skills/s{n}") for n in range(80)]
        selection = {"schema_version": 1, "sources": subjects}
        all_ids = [s["id"] for index in range(8) for s in coverage.plan_attempts(selection, None, index, 8, 128)]
        self.assertEqual(sorted(all_ids), sorted(s["id"] for s in subjects))

    def test_cold_queue_preserves_reviewed_and_popular_priority_instead_of_lexical_ids(self):
        subjects = [item(id="z-reviewed/known", path="skills/known"),
                    item(id="m-popular/top", path="skills/popular"),
                    item(id="a-tail/low", path="skills/tail")]
        selection = {"schema_version": 1, "sources": subjects}
        chosen = coverage.plan_attempts(selection, None, 0, 1, 2)
        self.assertEqual([source["id"] for source in chosen], [source["id"] for source in subjects[:2]])

    def test_actual_inert_fixture_scan_has_no_llm_and_reuses_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, selection = fixture_repository(root)
            executable = scanner(root)
            with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "must-not-pass", "SKILLSPECTOR_YARA_RULES_DIR": "/untrusted"}):
                result = coverage.scan_partition(selection, executable, None, source_commit=COMMIT,
                    partition_index=0, partition_count=1, mirror_root=mirrors)
            record = result["attempts"][0]["record"]
            self.assertEqual(record["status"], "complete")
            self.assertRegex(record["source"]["content_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(record["skill_name"], "demo")
            prior = bundle(root / "report", selection, result["attempts"])
            with mock.patch.object(coverage, "PinnedRepository", side_effect=AssertionError("cache must avoid acquisition")):
                warm = coverage.scan_partition(selection, executable, prior, source_commit=COMMIT,
                    partition_index=0, partition_count=1, mirror_root=mirrors)
            self.assertEqual(warm["attempts"], [])
            coverage.merge_reports(selection, prior, [warm], source_commit=COMMIT, output_dir=root / "warm")
            self.assertEqual(coverage.read_bundle(root / "warm")["records"][record["id"]]["scanned_at"], record["scanned_at"])

    def test_scanner_llm_metadata_is_rejected(self):
        raw = upstream_report()
        raw["metadata"]["llm_requested"] = True
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, selection = fixture_repository(root)
            result = coverage.scan_partition(selection, scanner(root, raw), None, source_commit=COMMIT,
                partition_index=0, partition_count=1, mirror_root=mirrors)
            self.assertEqual(result["attempts"][0]["record"]["status"], "error")

    def test_acquisition_errors_have_attempt_time_and_are_not_immediate_retries(self):
        selection = {"schema_version": 1, "sources": [item(), item(id="fixture/other", path="skills/other")]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = coverage.scan_partition(selection, scanner(root), None, source_commit=COMMIT,
                partition_index=0, partition_count=1, mirror_root=root / "missing")
            self.assertEqual(len(result["attempts"]), 2)
            prior = bundle(root / "report", selection, result["attempts"])
            self.assertEqual(coverage.plan_attempts(selection, prior, 0, 1, 128), [])

    def test_cooperative_budget_keeps_completed_outcomes(self):
        selection = {"schema_version": 1, "sources": [item(), item(id="fixture/other", repository="owner/other", path="skills/other")]}
        budget = mock.Mock()
        budget.remaining.side_effect = [5, 5, 5, CheckpointYield("done")]
        pinned = mock.Mock()
        with mock.patch.object(legacy, "verify_scanner"), mock.patch.object(coverage, "WorkBudget", return_value=budget), \
             mock.patch.object(coverage, "PinnedRepository", return_value=pinned), \
             mock.patch.object(coverage, "scan_selected", side_effect=lambda _, subject, __, ___: outcome(subject)["record"]):
            result = coverage.scan_partition(selection, Path("/trusted/scanner"), None, source_commit=COMMIT, partition_index=0, partition_count=1)
        self.assertEqual(len(result["attempts"]), 1)
        pinned.close.assert_called_once()

    def test_worker_forged_partition_identity_duplicate_or_missing_artifacts_rejected(self):
        selection = {"schema_version": 1, "sources": [item()]}
        valid = worker(selection, [outcome(item())])
        variants = []
        altered = copy.deepcopy(valid); altered["attempts"][0]["record"]["source"]["revision"] = "d" * 40; variants.append(altered)
        altered = copy.deepcopy(valid); altered["profile"]["digest"] = "sha256:" + "0" * 64; variants.append(altered)
        altered = copy.deepcopy(valid); altered["attempts"] *= 2; variants.append(altered)
        altered = copy.deepcopy(valid); altered["partition"]["count"] = 8; altered["partition"]["index"] = (coverage.partition_for("owner/repo") + 1) % 8; variants.append(altered)
        for altered in variants:
            with self.subTest(altered=altered), self.assertRaises(PublicationError):
                coverage.validate_worker(altered, selection, COMMIT)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(PublicationError):
            coverage.merge_reports(selection, None, [worker(selection, count=2)], source_commit=COMMIT, output_dir=Path(temporary))

    def test_shards_split_and_remain_content_addressed_across_generations(self):
        subjects = [item(id=f"fixture/{n}", path=f"skills/s{n}") for n in range(3)]
        selection = {"schema_version": 1, "sources": subjects}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(coverage, "MAX_SHARD_RECORDS", 2):
            root = Path(temporary)
            first = bundle(root / "first", selection, [outcome(s) for s in subjects])
            self.assertEqual(len(first["manifest"]["shards"]), 2)
            second = coverage.merge_reports(selection, first, [worker(selection)], source_commit=COMMIT, output_dir=root / "second")
            self.assertEqual(first["manifest"]["shards"], second["shards"])
            shard = root / "second" / second["shards"][0]["path"]
            shard.write_bytes(shard.read_bytes() + b" ")
            with self.assertRaises(PublicationError):
                coverage.read_bundle(root / "second")

    def test_pending_bundle_is_valid_but_does_not_claim_a_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            prior = bundle(Path(temporary), outcomes=[])
            self.assertEqual(prior["records"], {})
            self.assertEqual(prior["manifest"]["coverage"], {"selected": 1, "reported": 0, "pending": 1})

    def test_one_of_thirteen_plugin_roots_preserves_the_twelve_pending_roots(self):
        subjects = [item(id=f"plugin/s{n}", kind="plugin_skill", plugin_path="plugins/demo",
            path=f"plugins/demo/skills/s{n}") for n in range(13)]
        selection = {"schema_version": 1, "sources": subjects}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prior = bundle(root, selection, [outcome(subjects[0], status="complete")])
            self.assertEqual(prior["manifest"]["plugin_coverage"], [{"repository": "owner/repo",
                "plugin_path": "plugins/demo", "selected": 13, "reported": 1, "pending": 12}])
            self.assertEqual(prior["records"][subjects[0]["id"]]["status"], "complete")
            self.assertEqual(len(prior["records"]), 1)
            impossible = copy.deepcopy(prior["manifest"])
            impossible["coverage"].update(reported=13, pending=0)
            impossible["shards"][0]["record_count"] = 13
            with self.assertRaises(PublicationError):
                coverage.validate_manifest(impossible)
            manifest = prior["manifest"]
            # Internally consistent forged counts must still bind to the real selection.
            manifest["plugin_coverage"][0].update(selected=1, pending=0)
            coverage.write_bounded(root / "index.json", manifest, coverage.MAX_MANIFEST_BYTES)
            with self.assertRaises(PublicationError):
                publisher.validate_directory(root, COMMIT)

    def test_fully_pending_plugin_is_present_and_duplicate_coverage_joins_are_rejected(self):
        subject = item(kind="plugin_skill", plugin_path="plugins/demo", path="plugins/demo/skills/first")
        selection = {"schema_version": 1, "sources": [subject]}
        with tempfile.TemporaryDirectory() as temporary:
            prior = bundle(Path(temporary), selection, [])
            manifest = prior["manifest"]
            self.assertEqual(manifest["plugin_coverage"][0]["reported"], 0)
            self.assertEqual(manifest["plugin_coverage"][0]["pending"], 1)
            duplicate = copy.deepcopy(manifest["plugin_coverage"][0])
            duplicate["repository"] = "OWNER/REPO"
            manifest["plugin_coverage"].append(duplicate)
            with self.assertRaises(PublicationError):
                coverage.validate_manifest(manifest)

    def test_input_limit_is_enforced_before_blob_body_is_acquired(self):
        pinned = mock.Mock(root=Path("/unused"), revision="a" * 40, work_budget=None)
        tree = b"100644 blob " + b"b" * 40 + b"\tskills/demo/SKILL.md\0"
        with mock.patch.object(acquisition, "git", side_effect=[tree, b"20"]) as git:
            with self.assertRaises(acquisition.DiscoveryInputLimitError):
                acquisition.bounded_package_files(pinned, "skills/demo", max_files=512,
                    max_file_bytes=16, max_tree_bytes=16)
        self.assertEqual(git.call_count, 2)
        self.assertFalse(any("show" in call.args for call in git.call_args_list))

    def test_oversized_source_has_an_explicit_limit_refusal_without_materializing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, selection = fixture_repository(root)
            with mock.patch.object(legacy, "MAX_TREE_BYTES", 16), \
                 mock.patch.object(coverage, "materialize_package") as materialize:
                result = coverage.scan_partition(selection, scanner(root), None, source_commit=COMMIT,
                    partition_index=0, partition_count=1, mirror_root=mirrors)
            materialize.assert_not_called()
            record = result["attempts"][0]["record"]
            self.assertEqual(record["status"], "error")
            self.assertIsNone(record["source"]["content_digest"])
            self.assertIsNone(record["scanned_at"])
            self.assertEqual(record["errors"][0]["code"], "input_limit_exceeded")

    def test_discovery_summary_identity_and_cache_are_validated_against_selection(self):
        row = {"source": "owner/repo", "skillId": "demo", "name": "demo"}
        catalog = {"complete": True, "pages": 1, "provider_total": 1, "error": None}
        states = {"owner/repo": {"available": True, "repository": "owner/repo", "revision": "a" * 40}}
        with mock.patch.object(discovery, "repository_states", return_value=states), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([item()], [], {})):
            selection, summary = discovery.discover([row], catalog, mock.Mock(token=None), coverage.WorkBudget(10), source_commit=COMMIT)
        # The legacy v2 validator retains its original 10k inventory contract.
        summary["bounds"]["roots"] = coverage.MAX_SOURCES
        coverage.validate_discovery_summary(summary, selection, COMMIT)
        for key, value in [("selection_digest", "sha256:" + "0" * 64), ("selected_roots", 2)]:
            altered = copy.deepcopy(summary); altered[key] = value
            with self.subTest(key=key), self.assertRaises(PublicationError):
                coverage.validate_discovery_summary(altered, selection, COMMIT)
        altered = copy.deepcopy(summary)
        altered["resolution_cache"]["owner/repo"]["selected_ids"] = ["unselected/subject"]
        with self.assertRaises(PublicationError):
            coverage.validate_discovery_summary(altered, selection, COMMIT)


class FakeGitHub:
    def __init__(self, *, old=None, conflict=False, main=COMMIT, main_changed=False):
        self.old, self.conflict, self.main, self.main_changed = old, conflict, main, main_changed
        self.calls, self.main_reads = [], 0

    def request(self, method, path, data=None):
        self.calls.append((method, path, copy.deepcopy(data)))
        if path == "git/ref/heads/main":
            self.main_reads += 1
            return {"object": {"sha": "f" * 40 if self.main_changed and self.main_reads > 1 else self.main}}
        if method == "GET" and path.startswith("git/ref/"):
            return {"object": {"sha": "a" * 40}} if self.old is not None else None
        if method == "GET" and path.startswith("git/trees/"):
            return {"truncated": False, "tree": self.old["tree"]}
        if path == "git/blobs":
            body = base64.b64decode(data["content"])
            return {"sha": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()}
        if path == "git/trees" and any("content" in entry for entry in data["tree"]):
            entries = []
            for entry in data["tree"]:
                body = entry["content"].encode()
                entries.append({"path": entry["path"], "sha": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()})
            return {"sha": "b" * 40, "truncated": False, "tree": entries}
        if self.conflict and method == "PATCH":
            raise PublicationError("non-fast-forward")
        return {"sha": "b" * 40}


class PublicationTests(unittest.TestCase):
    def test_only_explicit_static_files_and_legacy_survive_atomic_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = bundle(root)
            prior = copy.deepcopy(current["manifest"])
            prior["generated_at"] = ago(1)
            paths = [publisher.LEGACY_PATH, publisher.PREFIX + prior["shards"][0]["path"],
                     publisher.PREFIX + "shards/" + "e" * 64 + ".json"]
            tree = [{"path": path, "mode": "100644", "type": "blob", "sha": "d" * 40} for path in paths]
            github = FakeGitHub(old={"tree": tree})
            publisher.publish(github, root, COMMIT, fetch=lambda *_args, **_kwargs: canonical_json(prior))
            payload = next(data for method, path, data in github.calls if path == "git/trees" and all("sha" in entry for entry in data["tree"]))
            published_paths = {entry["path"] for entry in payload["tree"]}
            self.assertIn(publisher.LEGACY_PATH, published_paths)
            self.assertIn(publisher.PREFIX + "attempts.json", published_paths)
            self.assertNotIn(paths[2], published_paths)
            self.assertTrue(all(entry["mode"] == "100644" for entry in payload["tree"]))
            self.assertEqual(github.calls[-1], ("PATCH", "git/refs/heads/skillspector-reports", {"sha": "b" * 40, "force": False}))

    def test_publication_rejects_obsolete_main_stale_manifest_and_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = bundle(root)
            github = FakeGitHub(main="f" * 40)
            with self.assertRaises(PublicationError): publisher.publish(github, root, COMMIT)
            self.assertTrue(all(method == "GET" for method, _, _ in github.calls))
            github = FakeGitHub(old={"tree": []})
            with self.assertRaises(PublicationError):
                publisher.publish(github, root, COMMIT, fetch=lambda *_args, **_kwargs: canonical_json(current["manifest"]))
            self.assertTrue(all(method == "GET" for method, _, _ in github.calls))
            older = copy.deepcopy(current["manifest"]); older["generated_at"] = ago(1); older["shards"] = []
            older["coverage"] = {"selected": 1, "reported": 0, "pending": 1}
            github = FakeGitHub(old={"tree": []}, conflict=True)
            with self.assertRaises(PublicationError):
                publisher.publish(github, root, COMMIT, fetch=lambda *_args, **_kwargs: canonical_json(older))
            self.assertEqual(len([call for call in github.calls if call[0] == "PATCH"]), 1)
            github = FakeGitHub(main_changed=True)
            with self.assertRaises(PublicationError): publisher.publish(github, root, COMMIT)
            self.assertFalse(any(path.startswith("git/refs") for _, path, _ in github.calls))

    def test_artifact_tampering_extra_files_and_missing_attempts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle(root)
            (root / "script.py").write_text("untrusted")
            with self.assertRaises(PublicationError): publisher.validate_directory(root, COMMIT)
            (root / "script.py").unlink()
            state = coverage.read_json(root / "attempts.json", max_bytes=coverage.MAX_STATE_BYTES)
            state["attempts"] = []
            coverage.write_bounded(root / "attempts.json", state, coverage.MAX_STATE_BYTES)
            with self.assertRaises(PublicationError): publisher.validate_directory(root, COMMIT)

    def test_previous_fetches_commit_pinned_static_json_and_validates_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle(root / "current")
            requested = []
            def fetch(commit, relative, maximum, *, optional=False):
                requested.append((commit, relative))
                path = root / "current" / relative
                return path.read_bytes() if path.exists() else None
            github = FakeGitHub(old={"tree": []})
            publisher.previous(github, root / "previous", fetch=fetch)
            self.assertTrue(all(commit == "a" * 40 for commit, _ in requested))
            self.assertEqual(coverage.read_bundle(root / "previous")["manifest"]["coverage"]["reported"], 1)
            self.assertEqual([call[1] for call in github.calls], ["git/ref/heads/skillspector-reports"])

    def test_upload_batches_blobs_instead_of_one_api_write_per_repository(self):
        subjects = [item(id=f"fixture/{n}", repository=f"owner/repo{n}") for n in range(100)]
        selection = {"schema_version": 1, "sources": subjects}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle(root, selection, [outcome(subject) for subject in subjects])
            github = FakeGitHub()
            publisher.publish(github, root, COMMIT)
        self.assertFalse(any(path == "git/blobs" for _, path, _ in github.calls))
        self.assertEqual(len([call for call in github.calls if call[:2] == ("POST", "git/trees")]), 2)


if __name__ == "__main__":
    unittest.main()
