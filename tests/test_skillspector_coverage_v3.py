from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import skillspector_coverage_v3 as coverage
from scripts import publish_skillspector_coverage_v3 as publisher
from scripts import skillspector_reports as scanner
from scripts import discover_skillspector_sources as discovery
from scripts.discovery_checkpoint import WorkBudget
from scripts.directory_publication import PublicationError
from tests.test_skillspector_reports import item, upstream_report, fixture_repository, scanner as fake_scanner

COMMIT = "c" * 40


def record(subject, status="complete", reason=None, profile_id="static-standard-v3"):
    value = scanner.empty_record_v3(subject, profile_id)
    if status == "error":
        return coverage.fail(value, reason or "acquisition_failed", "A reproducible fixture failure.")
    raw = upstream_report()
    if status == "partial":
        raw["analysis_completeness"].update(is_complete=False, status="partial", partially_inspected_files=1)
        raw["analysis_completeness"]["ledger_exceptions"] = [{"reason_code": reason or "static_parse_limit", "message": "Bounded fixture limitation."}]
    value["source"]["content_digest"] = "sha256:" + "a" * 64
    value["scanned_at"] = scanner.now()
    return scanner.normalize_report_v3(value, json.dumps(raw).encode(), 0, Path("/source"))


def worker(selection, records=(), previous=None):
    outcomes = []
    old = coverage.compatible_attempts(previous, selection)
    prior = coverage.previous_records(previous, selection)
    by_id = {subject["id"]: subject for subject in selection["sources"]}
    for value in records:
        identifier = value["id"]
        outcomes.append({"record": value, "attempt": coverage.make_attempt(by_id[identifier], value, old.get(identifier), prior.get(identifier))})
    return {"schema_version": 3, "source_commit": COMMIT, "generated_at": scanner.now(),
        "scanner": coverage.SCANNER, "profile": coverage.PROFILE,
        "selection_digest": coverage.sha256_digest(coverage.canonical_json(selection)),
        "partition": {"index": 0, "count": 1}, "attempts": outcomes}


def bundle(path, selection, records=(), previous=None):
    coverage.merge_reports(selection, previous, [worker(selection, records, previous)], source_commit=COMMIT, output_dir=path)
    return coverage.read_bundle(path)


class QueueTests(unittest.TestCase):
    def discovery_summary(self, selection, aliases=()):
        # The helper models a current verified resolution while retaining the
        # complete summary contract used by merge and publication validation.
        selected, summary = discovery.discover([], {"complete": True, "pages": 0, "provider_total": 0, "error": None},
            mock.Mock(), WorkBudget(10), source_commit=COMMIT, reviewed=selection["sources"])
        self.assertEqual(selected, selection)
        for state in summary["source_states"]:
            source = next(source for source in selection["sources"] if source["id"] == state["id"])
            state.update(state="resolved", current=True, reason=None, revision=source["revision"])
        summary["repository_aliases"] = list(aliases)
        coverage.validate_discovery_summary(summary, selection, COMMIT)
        return summary

    def test_verified_rename_keeps_exact_original_source_as_historical_until_rescan(self):
        old = item(id="old/repo/demo", repository="old/repo")
        new = item(id="canonical/renamed/demo", repository="canonical/renamed", revision="d" * 40)
        first = {"schema_version": 1, "sources": [old]}
        selected = {"schema_version": 1, "sources": [new]}
        alias = {"repository": "old/repo", "canonical_repository": "canonical/renamed", "revision": new["revision"]}
        summary = self.discovery_summary(selected, [alias])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root / "old", first, [record(old)])
            coverage.merge_reports(selected, prior, [worker(selected)], source_commit=COMMIT,
                output_dir=root / "renamed", discovery_summary=summary)
            renamed = coverage.read_bundle(root / "renamed")
            historical = renamed["records"][new["id"]]
            self.assertEqual(historical["source"], prior["records"][old["id"]]["source"])
            self.assertEqual(historical["freshness"], "historical")
            self.assertEqual(historical["target_revision"], new["revision"])
            self.assertEqual(renamed["manifest"]["coverage"]["stale"], 1)
            self.assertEqual(coverage.plan_attempts(selected, renamed, 0, 1, 1), [new])
            # Discovery now uses the canonical name, so it need not see the
            # redirect again. The previous manifest proves this exact target pin.
            coverage.merge_reports(selected, renamed, [worker(selected)], source_commit=COMMIT,
                output_dir=root / "retained", discovery_summary=self.discovery_summary(selected))
            retained = coverage.read_bundle(root / "retained")
            self.assertEqual(retained["records"][new["id"]]["source"], historical["source"])
            self.assertEqual(retained["manifest"]["repository_aliases"], [alias])
            coverage.merge_reports(selected, renamed, [worker(selected, [record(new)], renamed)], source_commit=COMMIT,
                output_dir=root / "rescanned", discovery_summary=summary)
            refreshed = coverage.read_bundle(root / "rescanned")
            self.assertEqual(refreshed["records"][new["id"]]["source"]["repository"], "canonical/renamed")
            self.assertEqual(refreshed["manifest"]["coverage"]["complete"], 1)

    def test_same_revision_rename_never_promotes_original_repository_to_current(self):
        old = item(repository="old/repo")
        new = item(repository="canonical/renamed")
        selected = {"schema_version": 1, "sources": [new]}
        alias = {"repository": "old/repo", "canonical_repository": "canonical/renamed", "revision": new["revision"]}
        with tempfile.TemporaryDirectory() as directory:
            prior = bundle(Path(directory), {"schema_version": 1, "sources": [old]}, [record(old)])
            retained = coverage.previous_records(prior, selected, repository_aliases=[alias])[new["id"]]
            self.assertEqual(retained["freshness"], "historical")
            retained["freshness"] = "current"
            with self.assertRaises(PublicationError):
                coverage.contract.validate_record(retained, new, datetime.now(timezone.utc), repository_aliases=[alias])

    def test_old_rename_proof_cannot_link_a_recreated_repository_or_a_new_target_pin(self):
        old = item(repository="old/repo")
        old_selection = {"schema_version": 1, "sources": [old]}
        alias = {"repository": "old/repo", "canonical_repository": "canonical/renamed", "revision": old["revision"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root / "old", old_selection, [record(old)])
            prior["manifest"]["repository_aliases"] = [alias]
            changed = {"schema_version": 1, "sources": [item(repository="canonical/renamed", revision="d" * 40)]}
            self.assertEqual(coverage.previous_records(prior, changed), {})
            same_pin = {"schema_version": 1, "sources": [item(repository="canonical/renamed")]}
            self.assertIn(old["id"], coverage.previous_records(prior, same_pin))
            # A fresh direct observation of the old name overrides a prior
            # redirect even if an attacker copied the former Git commit.
            summary = self.discovery_summary(old_selection)
            aliases = coverage.verified_aliases(prior, old_selection, summary)
            self.assertEqual(aliases, [])

    def test_timeout_escalates_actual_process_environment_then_complete_reuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirrors, selection = fixture_repository(root)
            partial = upstream_report()
            partial["analysis_completeness"].update(is_complete=False, status="partial", partially_inspected_files=1,
                ledger_exceptions=[{"reason_code": "runtime_limit", "message": "Internal deadline reached."}])
            executable = fake_scanner(root)
            text = executable.read_text()
            text = text.replace(f"print(json.dumps({upstream_report()!r}))", f"print(json.dumps({upstream_report()!r} if float(os.environ['SKILLSPECTOR_MAX_WORKFLOW_SECONDS']) > 45 else {partial!r}))")
            executable.write_text(text)
            first = coverage.scan_partition(selection, executable, None, source_commit=COMMIT, partition_count=1, mirror_root=mirrors)
            self.assertEqual(first["attempts"][0]["record"]["status"], "partial")
            coverage.merge_reports(selection, None, [first], source_commit=COMMIT, output_dir=root / "first")
            prior = coverage.read_bundle(root / "first")
            self.assertEqual(prior["attempts"][selection["sources"][0]["id"]]["next_profile"], "static-extended-v3")
            second = coverage.scan_partition(selection, executable, prior, source_commit=COMMIT, partition_count=1, mirror_root=mirrors)
            self.assertEqual(second["attempts"][0]["record"]["status"], "complete")
            self.assertEqual(second["attempts"][0]["record"]["profile"], scanner.EXTENDED_PROFILE)
            coverage.merge_reports(selection, prior, [second], source_commit=COMMIT, output_dir=root / "second")
            final = coverage.read_bundle(root / "second")
            self.assertEqual(final["manifest"]["coverage"]["complete"], 1)
            self.assertEqual(len(final["records"][selection["sources"][0]["id"]]["attempt_history"]), 2)
            self.assertEqual(coverage.plan_attempts(selection, final, 0, 1, 128,
                current=datetime.now(timezone.utc) + timedelta(days=30)), [])

    def test_permanent_parser_limitation_is_blocked_until_source_changes(self):
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root / "first", selection, [record(source, "partial", "static_parse_limit")])
            self.assertEqual(prior["attempts"][source["id"]]["disposition"], "blocked")
            self.assertEqual(coverage.plan_attempts(selection, prior, 0, 1, 128,
                current=datetime.now(timezone.utc) + timedelta(days=30)), [])
            changed = copy.deepcopy(selection)
            changed["sources"][0]["revision"] = "d" * 40
            pending = bundle(root / "changed", changed, previous=prior)
            self.assertEqual(pending["manifest"]["coverage"], {"selected": 1, "reported": 1, "pending": 1,
                "complete": 0, "partial": 0, "error": 0, "stale": 1})
            self.assertEqual(pending["records"][source["id"]]["source"]["revision"], source["revision"])
            self.assertEqual(coverage.plan_attempts(changed, pending, 0, 1, 128), changed["sources"])

    def test_network_failures_have_bounded_backoff_and_keep_useful_evidence(self):
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root / "partial", selection, [record(source, "partial", "runtime_limit")])
            for number in range(2, 5):
                prior = bundle(root / str(number), selection,
                    [record(source, "error", "acquisition_failed", "static-extended-v3")], prior)
                self.assertEqual(prior["records"][source["id"]]["status"], "partial")
                self.assertEqual(prior["records"][source["id"]]["retry"]["latest_status"], "error")
                if number < 4:
                    self.assertEqual(coverage.plan_attempts(selection, prior, 0, 1, 128), [])
            self.assertEqual(prior["attempts"][source["id"]]["disposition"], "exhausted")
            self.assertEqual(coverage.plan_attempts(selection, prior, 0, 1, 128,
                current=datetime.now(timezone.utc) + timedelta(days=99)), [])

    def test_new_retry_and_changed_lanes_share_a_small_budget(self):
        retry, changed = item(id="fixture/retry", path="skills/retry"), item(id="fixture/changed", path="skills/changed")
        first = {"schema_version": 1, "sources": [retry, changed]}
        with tempfile.TemporaryDirectory() as directory:
            prior = bundle(Path(directory), first, [record(retry, "partial", "runtime_limit"), record(changed)])
            changed = copy.deepcopy(changed)
            changed["revision"] = "d" * 40
            sources = [item(id=f"fixture/new{n}", path=f"skills/new{n}") for n in range(40)] + [retry, changed]
            planned = coverage.plan_attempts({"schema_version": 1, "sources": sources}, prior, 0, 1, 3)
            self.assertEqual({subject["id"] for subject in planned}, {"fixture/new0", "fixture/retry", "fixture/changed"})

    def test_zero_skill_selection_and_empty_workers_are_publishable(self):
        with tempfile.TemporaryDirectory() as directory:
            result = bundle(Path(directory), {"schema_version": 1, "sources": []})
            self.assertTrue(all(value == 0 for value in result["manifest"]["coverage"].values()))
            publisher.validate_directory(Path(directory), COMMIT)

    def test_historical_prefix_does_not_consume_the_active_attempt_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirrors, selection = fixture_repository(root)
            current = selection["sources"][0]
            historical = item(id="fixture/historical", path="skills/removed")
            selection["sources"].insert(0, historical)
            summary = {"source_states": [{"current": False, "repository": historical["repository"],
                "selected_ids": [historical["id"]]}, {"current": True, "repository": current["repository"],
                "selected_ids": [current["id"]]}]}
            result = coverage.scan_partition(selection, fake_scanner(root), None, source_commit=COMMIT,
                partition_count=1, maximum_attempts=1, mirror_root=mirrors, discovery_summary=summary)
            self.assertEqual([entry["attempt"]["id"] for entry in result["attempts"]], [current["id"]])

    def test_orphaned_report_retry_history_is_rejected(self):
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle(root, selection, [record(source)])
            state = coverage.read_json(root / "attempts.json", max_bytes=coverage.MAX_STATE_BYTES)
            state["attempts"] = []
            coverage.write_bounded(root / "attempts.json", state, coverage.MAX_STATE_BYTES)
            with self.assertRaises(PublicationError):
                coverage.read_bundle(root)

    def test_forged_retry_state_and_shard_bytes_are_rejected(self):
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root, selection, [record(source, "partial", "runtime_limit")])
            state = coverage.read_json(root / "attempts.json", max_bytes=coverage.MAX_STATE_BYTES)
            state["attempts"][0]["attempt_count"] = 1000
            coverage.write_bounded(root / "attempts.json", state, coverage.MAX_STATE_BYTES)
            with self.assertRaises(PublicationError):
                coverage.read_bundle(root)
            shard = root / prior["manifest"]["shards"][0]["path"]
            shard.write_bytes(shard.read_bytes() + b" ")
            with self.assertRaises(PublicationError):
                coverage.read_bundle(root)

    def test_old_policy_is_readable_but_new_policy_requires_refresh(self):
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root / "before", selection, [record(source)])
            old_digest = prior["manifest"]["profile"]["digest"]
            with mock.patch.dict(coverage.PROFILE, {"digest": "sha256:" + "d" * 64}), \
                 mock.patch.dict(scanner.PROFILES["static-standard-v3"], {"digest": "sha256:" + "e" * 64}):
                # Persisted artifacts are internally validated under their own policy.
                loaded = coverage.read_bundle(root / "before")
                self.assertEqual(loaded["manifest"]["profile"]["digest"], old_digest)
                self.assertEqual(coverage.plan_attempts(selection, loaded, 0, 1, 1), [source])
                fresh = bundle(root / "after", selection, previous=loaded)
                self.assertEqual(fresh["manifest"]["coverage"]["complete"], 0)
                self.assertEqual(fresh["manifest"]["coverage"]["stale"], 1)

    def test_actual_scan_worker_measures_timings_and_keeps_credentials_out(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirrors, selection = fixture_repository(root)
            with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "do-not-inherit", "SKILLSPECTOR_YARA_RULES_DIR": "/untrusted"}):
                result = coverage.scan_partition(selection, fake_scanner(root), None, source_commit=COMMIT,
                    partition_count=1, mirror_root=mirrors)
            coverage.validate_worker(result, selection, COMMIT)
            execution = result["attempts"][0]["record"]["execution"]
            self.assertGreater(execution["acquisition_seconds"], 0)
            self.assertGreater(execution["analysis_seconds"], 0)


class PublicationTests(unittest.TestCase):
    def test_previous_download_keeps_float_confidence_and_exact_digest(self):
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = bundle(root / "source", selection, [record(source)])
            github = mock.Mock()
            github.request.return_value = {"object": {"sha": "a" * 40}}
            versions = []
            def fetch(commit, relative, maximum, *, optional=False, version=3):
                versions.append(version)
                path = root / "source" / relative
                return path.read_bytes() if path.exists() else None
            publisher.previous(github, root / "download", fetch=fetch)
            self.assertEqual(coverage.read_bundle(root / "download")["manifest"], original["manifest"])
            self.assertEqual(set(versions), {3})

    def test_v2_fallback_only_when_v3_does_not_exist(self):
        from tests.test_skillspector_coverage import bundle as legacy_bundle
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = legacy_bundle(root / "legacy")
            github = mock.Mock()
            github.request.return_value = {"object": {"sha": "a" * 40}}
            def fetch(commit, relative, maximum, *, optional=False, version=3):
                if version == 3:
                    return None
                path = root / "legacy" / relative
                return path.read_bytes() if path.exists() else None
            publisher.previous(github, root / "download", fetch=fetch)
            loaded = coverage.read_bundle(root / "download")
            self.assertEqual(loaded["manifest"], prior["manifest"])
            migrated = bundle(root / "migrated", loaded["selection"], previous=loaded)
            self.assertEqual(migrated["manifest"]["coverage"]["stale"], 1)
            with self.assertRaises(PublicationError):
                publisher.previous(github, root / "bad", fetch=lambda *args, **kwargs: b"{}")

    def test_atomic_publisher_preserves_legacy_bytes_and_refuses_obsolete_main(self):
        from tests.test_skillspector_coverage import FakeGitHub
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle(root, selection, [record(source)])
            legacy_paths = [publisher.LEGACY_PATH, publisher.v2.PREFIX + "index.json",
                publisher.v2.PREFIX + "attempts.json", publisher.v2.PREFIX + "selection.json",
                publisher.v2.PREFIX + "shards/" + "d" * 64 + ".json"]
            tree = [{"path": path, "mode": "100644", "type": "blob", "sha": "d" * 40} for path in legacy_paths]
            tree.append({"path": "unrelated.py", "mode": "100644", "type": "blob", "sha": "e" * 40})
            github = FakeGitHub(old={"tree": tree})
            result = publisher.publish(github, root, COMMIT, fetch=lambda *args, **kwargs: None)
            self.assertEqual(len(result), 40)
            payload = next(data for method, path, data in github.calls if path == "git/trees" and
                           all("sha" in entry for entry in data["tree"]))
            entries = {entry["path"]: entry["sha"] for entry in payload["tree"]}
            self.assertTrue(all(entries[path] == "d" * 40 for path in legacy_paths))
            self.assertNotIn("unrelated.py", entries)
            self.assertEqual(github.calls[-1], ("PATCH", "git/refs/heads/skillspector-reports", {"sha": result, "force": False}))
            for github in (FakeGitHub(main="f" * 40), FakeGitHub(main_changed=True)):
                with self.assertRaises(PublicationError):
                    publisher.publish(github, root, COMMIT, fetch=lambda *args, **kwargs: None)
                self.assertFalse(any(method == "PATCH" for method, _, _ in github.calls))


if __name__ == "__main__":
    unittest.main()
