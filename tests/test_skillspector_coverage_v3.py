from __future__ import annotations

import copy
import json
import subprocess
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

    def test_large_repository_does_not_hide_a_small_plugin_in_the_same_partition(self):
        bulk = [item(id=f"bulk/skill{n}", repository="fixture/bulk", path=f"skills/skill{n}") for n in range(40)]
        plugin = item(id="plugin:fixture/marketing/campaign", repository="fixture/bulk", kind="plugin_skill",
            path="plugins/marketing/skills/campaign", plugin_path="plugins/marketing")
        selection = {"schema_version": 1, "sources": [*bulk, plugin]}
        self.assertEqual(coverage.plan_attempts(selection, None, 0, 1, 2), [bulk[0], plugin])

    def test_plugin_packages_share_turns_and_progress_survives_publication(self):
        packages = [[item(id=f"plugin:fixture/{name}/skill{n}", kind="plugin_skill",
            repository="fixture/shared", path=f"plugins/{name}/skills/skill{n}", plugin_path=f"plugins/{name}")
            for n in range(3)] for name in ("bulk-a", "bulk-b", "small")]
        selection = {"schema_version": 1, "sources": [source for package in packages for source in package]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = coverage.plan_attempts(selection, None, 0, 1, 2)
            self.assertEqual(first, [packages[0][0], packages[1][0]])
            earlier = coverage.format_timestamp(datetime.now(timezone.utc) - timedelta(minutes=10))
            with mock.patch.object(scanner, "now", return_value=earlier):
                prior = bundle(root / "first", selection, [record(source) for source in first])
            # The previous two packages still have work. The untouched package
            # must get a slot before either starts its second root.
            second = coverage.plan_attempts(selection, prior, 0, 1, 2)
            self.assertEqual(second[0], packages[2][0])
            final = bundle(root / "second", selection, [record(source) for source in second], prior)
            third = coverage.plan_attempts(selection, final, 0, 1, 1)
            untouched_previous_round = packages[1] if second[1] in packages[0] else packages[0]
            self.assertEqual(third, [untouched_previous_round[1]])
            self.assertEqual(final["manifest"]["coverage"]["complete"], 4)
            self.assertEqual(final["manifest"]["coverage"]["pending"], 5)

    def test_changed_source_keeps_group_recency_without_reusing_its_scan(self):
        old = item(id="fixture/old", repository="fixture/shared", path="skills/old")
        untouched = item(id="fixture/untouched", repository="fixture/other", path="skills/untouched")
        with tempfile.TemporaryDirectory() as directory:
            prior = bundle(Path(directory), {"schema_version": 1, "sources": [old]}, [record(old)])
            changed = old | {"revision": "d" * 40}
            new_same_repository = item(id="fixture/new", repository="fixture/shared", path="skills/new")
            selected = {"schema_version": 1, "sources": [new_same_repository, untouched, changed]}
            self.assertEqual({source["id"] for source in coverage.plan_attempts(selected, prior, 0, 1, 2)},
                {untouched["id"], changed["id"]})
            self.assertEqual(coverage.previous_records(prior, selected)[old["id"]]["freshness"], "historical")

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

    def test_scanner_upgrade_requeues_complete_and_blocked_sources_without_old_retry_state(self):
        complete = item(id="fixture/complete", path="skills/complete")
        limited = item(id="fixture/limited", path="skills/limited")
        selection = {"schema_version": 1, "sources": [complete, limited]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = bundle(root / "before", selection, [record(complete), record(limited, "partial", "reference_missing")])
            with mock.patch.dict(coverage.SCANNER, {"revision": "f" * 40}):
                self.assertEqual(coverage.compatible_attempts(prior, selection), {})
                self.assertEqual({source["id"] for source in coverage.plan_attempts(selection, prior, 0, 1, 128)},
                    {complete["id"], limited["id"]})
                historical = bundle(root / "pending", selection, previous=prior)
                self.assertEqual(historical["manifest"]["coverage"]["stale"], 2)
                self.assertEqual(historical["attempts"], {})
                refreshed = bundle(root / "refreshed", selection, [record(complete), record(limited)], historical)
                self.assertEqual(refreshed["manifest"]["coverage"]["complete"], 2)
                self.assertTrue(all(attempt["attempt_count"] == 1 for attempt in refreshed["attempts"].values()))

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

    def test_malformed_analyzer_output_is_a_publishable_source_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirrors, selection = fixture_repository(root)
            raw = upstream_report()
            raw["issues"] = [{"id": "E4", "severity": "HIGH", "explanation": "Fixture signal",
                              "location": {"file": "SKILL.md", "start_line": 1}}]
            raw["analysis_completeness"]["analyzer_statuses"] = []
            result = coverage.scan_partition(selection, fake_scanner(root, raw), None,
                source_commit=COMMIT, partition_count=1, mirror_root=mirrors)
            coverage.validate_worker(result, selection, COMMIT)
            value = result["attempts"][0]["record"]
            self.assertEqual(value["status"], "error")
            self.assertEqual(value["findings"], [])
            self.assertEqual(value["coverage"]["reasons"][0]["code"], "scan_failed")
            coverage.merge_reports(selection, None, [result], source_commit=COMMIT, output_dir=root / "report")
            self.assertEqual(coverage.read_bundle(root / "report")["manifest"]["coverage"]["error"], 1)


class WorkerBudgetTests(unittest.TestCase):
    def run_worker(self, selection, previous, *, budget_seconds=2100,
                   acquisition_seconds=0, package_seconds=0,
                   materialization_seconds=0, scan_seconds=0, scan_timeout=False):
        """Exercise real admission, materialization, normalization and history with a fake clock."""
        elapsed, calls = [0.0], []
        pinned = mock.Mock()
        materialize = coverage.materialize_package

        def prepare(seconds, budget):
            elapsed[0] += min(seconds, budget.remaining())
            budget.check()

        def acquire(*args, work_budget, **kwargs):
            prepare(acquisition_seconds, work_budget)
            return pinned

        def package(*args, **kwargs):
            prepare(package_seconds, pinned.work_budget)
            return [("SKILL.md", 0o644, b"---\nname: fixture\n---\nStatic fixture.\n")]

        def materialize_with_elapsed_time(files, root, budget):
            materialize(files, root, budget)
            # A final local write/digest can consume time after its last budget
            # checkpoint. The caller must check again before admitting analysis.
            elapsed[0] += materialization_seconds

        def analyze(executable, arguments, home, timeout, profile_id):
            environment = scanner.environment_v3(home, profile_id, timeout)
            calls.append({"profile": profile_id, "timeout": timeout,
                "workflow": float(environment["SKILLSPECTOR_MAX_WORKFLOW_SECONDS"]),
                "artifact": float(environment["SKILLSPECTOR_MAX_STATIC_ANALYSIS_SECONDS_PER_ARTIFACT"])})
            elapsed[0] += timeout if scan_timeout else scan_seconds
            if scan_timeout:
                raise subprocess.TimeoutExpired("fake-static-scan", timeout)
            return 0, json.dumps(upstream_report()).encode()

        with mock.patch.object(coverage.time, "monotonic", side_effect=lambda: elapsed[0]), \
             mock.patch.object(scanner, "verify_scanner"), \
             mock.patch.object(coverage, "PinnedRepository", side_effect=acquire) as acquisition, \
             mock.patch.object(coverage, "bounded_package_files", side_effect=package), \
             mock.patch.object(coverage, "materialize_package", side_effect=materialize_with_elapsed_time), \
             mock.patch.object(scanner, "run_scanner_v3", side_effect=analyze):
            result = coverage.scan_partition(selection, Path("/unused-scanner"), previous,
                source_commit=COMMIT, partition_count=1, budget_seconds=budget_seconds)
        coverage.validate_worker(result, selection, COMMIT)
        return result, calls, acquisition.call_count, pinned.close.call_count, elapsed[0]

    def assert_deferred(self, root, selection, previous, result):
        self.assertEqual(result["attempts"], [])
        coverage.merge_reports(selection, previous, [result], source_commit=COMMIT, output_dir=root)
        merged = coverage.read_bundle(root)
        self.assertEqual(merged["attempts"], (previous or {}).get("attempts", {}))
        self.assertEqual(merged["records"], (previous or {}).get("records", {}))
        self.assertEqual(coverage.plan_attempts(selection, merged, 0, 1, 128), selection["sources"])
        return merged

    def test_worker_tail_defers_standard_and_extended_without_consuming_attempts(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        for profile_id in scanner.PROFILE_DOCUMENTS:
            with self.subTest(profile=profile_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                previous = (bundle(root / "prior", selection, [record(subject, "partial", "runtime_limit")])
                    if profile_id == "static-extended-v3" else None)
                result, calls, acquired, _, _ = self.run_worker(selection, previous, budget_seconds=20)
                self.assertEqual((calls, acquired), ([], 0))
                preserved = self.assert_deferred(root / "deferred", selection, previous, result)
                resumed, calls, _, closed, _ = self.run_worker(selection, preserved)
                profile = scanner.PROFILE_DOCUMENTS[profile_id]
                self.assertEqual(calls, [{"profile": profile_id, "timeout": profile["timeout_seconds"],
                    "workflow": profile["workflow_seconds"], "artifact": profile["static_artifact_seconds"]}])
                self.assertEqual(closed, 1)
                attempt = resumed["attempts"][0]["attempt"]
                self.assertEqual(attempt["attempt_count"], 2 if previous else 1)
                self.assertEqual(attempt["disposition"], "none")
                self.assertEqual(len(attempt["history"]), attempt["attempt_count"])

    def test_worker_limited_repository_and_package_acquisition_are_deferred(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        for profile_id in scanner.PROFILE_DOCUMENTS:
            for phase in ("acquisition_seconds", "package_seconds"):
                with self.subTest(profile=profile_id, phase=phase), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    previous = (bundle(root / "prior", selection, [record(subject, "partial", "runtime_limit")])
                        if profile_id == "static-extended-v3" else None)
                    timeout = scanner.PROFILE_DOCUMENTS[profile_id]["timeout_seconds"]
                    result, calls, _, closed, elapsed = self.run_worker(selection, previous,
                        budget_seconds=timeout + 10, **{phase: 20})
                    self.assertEqual(calls, [])
                    self.assertEqual(elapsed, 10)
                    self.assertEqual(closed, 1 if phase == "package_seconds" else 0)
                    self.assert_deferred(root / "deferred", selection, previous, result)

    def test_admission_is_rechecked_after_materialization(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        for profile_id in scanner.PROFILE_DOCUMENTS:
            with self.subTest(profile=profile_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                previous = (bundle(root / "prior", selection, [record(subject, "partial", "runtime_limit")])
                    if profile_id == "static-extended-v3" else None)
                timeout = scanner.PROFILE_DOCUMENTS[profile_id]["timeout_seconds"]
                result, calls, acquired, closed, _ = self.run_worker(selection, previous,
                    budget_seconds=timeout + 10, materialization_seconds=11)
                self.assertEqual((calls, acquired, closed), ([], 1, 1))
                self.assert_deferred(root / "deferred", selection, previous, result)

    def test_full_source_preparation_deadline_remains_a_real_attempt(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        for phase, reason in (("acquisition_seconds", "acquisition_failed"),
                              ("package_seconds", "preparation_timeout")):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                previous = bundle(Path(directory), selection, [record(subject, "partial", "runtime_limit")])
                result, calls, _, _, elapsed = self.run_worker(selection, previous,
                    **{phase: coverage.PREPARATION_SECONDS + 1})
                self.assertEqual(calls, [])
                self.assertEqual(elapsed, coverage.PREPARATION_SECONDS)
                outcome = result["attempts"][0]
                self.assertEqual(outcome["record"]["coverage"]["reasons"][0]["code"], reason)
                self.assertEqual(outcome["attempt"]["attempt_count"], 2)
                self.assertEqual(outcome["attempt"]["disposition"], "scheduled")
                self.assertEqual(outcome["attempt"]["reason"], "transient_source_failure")

    def test_full_profile_timeout_still_escalates_or_exhausts(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        for profile_id in scanner.PROFILE_DOCUMENTS:
            with self.subTest(profile=profile_id), tempfile.TemporaryDirectory() as directory:
                previous = (bundle(Path(directory), selection, [record(subject, "partial", "runtime_limit")])
                    if profile_id == "static-extended-v3" else None)
                result, calls, _, closed, elapsed = self.run_worker(selection, previous, scan_timeout=True)
                timeout = scanner.PROFILE_DOCUMENTS[profile_id]["timeout_seconds"]
                self.assertEqual(calls[0]["timeout"], timeout)
                self.assertEqual((elapsed, closed), (timeout, 1))
                outcome = result["attempts"][0]
                self.assertEqual(outcome["record"]["execution"]["analysis_seconds"], timeout)
                self.assertEqual(outcome["attempt"]["attempt_count"], 2 if previous else 1)
                self.assertEqual(outcome["attempt"]["reason"],
                    "extended_budget_exhausted" if previous else "extended_profile_required")
                self.assertEqual(outcome["attempt"]["disposition"], "exhausted" if previous else "scheduled")

    def test_deferral_keeps_prior_completed_work_and_next_source_queued(self):
        sources = [item(id=f"fixture/{name}", path=f"skills/{name}") for name in ("first", "second")]
        selection = {"schema_version": 1, "sources": sources}
        result, calls, acquired, closed, _ = self.run_worker(selection, None, budget_seconds=65, scan_seconds=45)
        self.assertEqual((len(calls), acquired, closed), (1, 1, 1))
        self.assertEqual([outcome["attempt"]["id"] for outcome in result["attempts"]], [sources[0]["id"]])
        with tempfile.TemporaryDirectory() as directory:
            coverage.merge_reports(selection, None, [result], source_commit=COMMIT, output_dir=Path(directory))
            previous = coverage.read_bundle(Path(directory))
            self.assertEqual(coverage.plan_attempts(selection, previous, 0, 1, 128), [sources[1]])
            resumed, calls, _, _, _ = self.run_worker(selection, previous)
            self.assertEqual(calls[0]["timeout"], scanner.PROFILE_DOCUMENTS["static-standard-v3"]["timeout_seconds"])
            self.assertEqual(resumed["attempts"][0]["attempt"]["id"], sources[1]["id"])
            self.assertEqual(resumed["attempts"][0]["attempt"]["attempt_count"], 1)


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

    def test_many_small_shards_bound_inline_tree_cardinality_below_byte_limit(self):
        from tests.test_skillspector_publication_transport import FakeGitHub
        sources = [item(id=f"fixture/{index}", repository=f"owner/repo{index}") for index in range(128)]
        selection = {"schema_version": 1, "sources": sources}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "reports"
            bundle(root, selection, [record(source) for source in sources])
            github = FakeGitHub(Path(directory) / "git")
            publisher.publish(github, root, COMMIT)
            inline = [data for method, path, data in github.calls if (method, path) == ("POST", "git/trees")
                      and any("content" in entry for entry in data["tree"])]
            self.assertEqual(len(inline), 2)
            self.assertEqual(len(inline[0]["tree"]), 128)
            self.assertTrue(all(len(data["tree"]) <= 128 for data in inline))
            self.assertLess(sum(len(publisher.canonical_json(data)) for data in inline), publisher.MAX_TREE_UPLOAD_BYTES)
            commit = next(data for method, path, data in github.calls if (method, path) == ("POST", "git/commits"))
            self.assertEqual(len(github.store.flatten(commit["tree"])), 131)

    def test_atomic_publisher_preserves_legacy_bytes_and_refuses_obsolete_main(self):
        from tests.test_skillspector_publication_transport import FakeGitHub
        source = item()
        selection = {"schema_version": 1, "sources": [source]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "reports"
            bundle(root, selection, [record(source)])
            legacy_paths = [publisher.LEGACY_PATH, publisher.v2.PREFIX + "index.json",
                publisher.v2.PREFIX + "attempts.json", publisher.v2.PREFIX + "selection.json",
                publisher.v2.PREFIX + "shards/" + "d" * 64 + ".json"]
            tree = [{"path": path, "mode": "100644", "type": "blob", "sha": "d" * 40} for path in legacy_paths]
            tree.append({"path": "unrelated.py", "mode": "100644", "type": "blob", "sha": "e" * 40})
            github = FakeGitHub(Path(directory) / "git", old={"tree": tree})
            result = publisher.publish(github, root, COMMIT, fetch=lambda *args, **kwargs: None)
            self.assertEqual(len(result), 40)
            commit = next(data for method, path, data in github.calls if (method, path) == ("POST", "git/commits"))
            entries = github.store.flatten(commit["tree"])
            self.assertTrue(all(entries[path] == "d" * 40 for path in legacy_paths))
            self.assertNotIn("unrelated.py", entries)
            self.assertEqual(github.calls[-1], ("PATCH", "git/refs/heads/skillspector-reports", {"sha": result, "force": False}))
            for github in (FakeGitHub(Path(directory) / "git-obsolete", main="f" * 40),
                           FakeGitHub(Path(directory) / "git-race", main_changed=True)):
                with self.assertRaises(PublicationError):
                    publisher.publish(github, root, COMMIT, fetch=lambda *args, **kwargs: None)
                self.assertFalse(any(method == "PATCH" for method, _, _ in github.calls))


if __name__ == "__main__":
    unittest.main()
