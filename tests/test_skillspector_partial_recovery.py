from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import skillspector_coverage_v3 as coverage
from scripts.directory_publication import PublicationError
from tests import test_skillspector_coverage_v3 as fixtures
from tests.test_skillspector_coverage_v3 import COMMIT, bundle, record, worker
from tests.test_skillspector_reports import item, upstream_report


def partition_worker(selection, values, *, count, previous=None):
    value = worker(selection, values, previous)
    index = coverage.partition_for(values[0]["source"]["repository"], count) if values else 0
    value["partition"] = {"index": index, "count": count}
    return value


class PartialMergeTests(unittest.TestCase):
    def setUp(self):
        self.sources = []
        for index in range(100):
            subject = item(id=f"fixture/{index}", repository=f"owner/repo-{index}")
            if not self.sources or coverage.partition_for(subject["repository"], 2) != \
                    coverage.partition_for(self.sources[0]["repository"], 2):
                self.sources.append(subject)
            if len(self.sources) == 2:
                break
        self.selection = {"schema_version": 1, "sources": self.sources}

    def test_partial_requires_independent_count_and_preserves_absent_partition(self):
        first, second = self.sources
        value = partition_worker(self.selection, [record(first)], count=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = bundle(root / "previous", self.selection, [record(second)])
            with self.assertRaisesRegex(PublicationError, "missing worker partition"):
                coverage.merge_reports(self.selection, previous, [value], source_commit=COMMIT, output_dir=root / "strict")
            with self.assertRaisesRegex(PublicationError, "independently expected"):
                coverage.merge_reports(self.selection, previous, [value], source_commit=COMMIT,
                    output_dir=root / "implicit", allow_partial_workers=True)
            result = coverage.merge_reports(self.selection, previous, [value], source_commit=COMMIT,
                output_dir=root / "partial", allow_partial_workers=True, expected_partition_count=2)
            resumed = coverage.read_bundle(root / "partial")
            self.assertEqual(result["coverage"]["complete"], 2)
            self.assertEqual(resumed["records"][second["id"]], previous["records"][second["id"]])
            received = value["partition"]["index"]
            self.assertEqual(result["execution_summary"]["received_partitions"], [received])
            self.assertEqual(result["execution_summary"]["missing_partitions"], [1 - received])
            self.assertEqual(result["execution_summary"]["attempted_sources"], 1)

    def test_cumulative_snapshots_deduplicate_only_exact_prefixes(self):
        sources = [item(id=f"fixture/{name}", path=f"skills/{name}") for name in ("one", "two")]
        selection = {"schema_version": 1, "sources": sources}
        complete = worker(selection, [record(source) for source in sources])
        prefix = copy.deepcopy(complete)
        prefix["attempts"] = prefix["attempts"][:1]
        with tempfile.TemporaryDirectory() as directory:
            manifest = coverage.merge_reports(selection, None, [prefix, complete, prefix, complete],
                source_commit=COMMIT, output_dir=Path(directory))
            self.assertEqual(manifest["coverage"]["complete"], 2)
            self.assertEqual(manifest["execution_summary"]["attempted_sources"], 2)
        conflict = copy.deepcopy(prefix)
        conflict["attempts"][0]["record"]["skill_name"] = "conflicting but schema-valid"
        with self.assertRaisesRegex(PublicationError, "conflicting cumulative"):
            coverage.coalesce_workers([complete, conflict], selection, COMMIT)

    def test_wrong_expected_count_malformed_envelope_and_forged_diagnostics_fail_closed(self):
        value = partition_worker(self.selection, [record(self.sources[0])], count=2)
        with self.assertRaisesRegex(PublicationError, "differs from preparation"):
            coverage.coalesce_workers([value], self.selection, COMMIT, expected_partition_count=1)
        with self.assertRaises(PublicationError):
            coverage.coalesce_workers([{"partition": None}], self.selection, COMMIT)
        with tempfile.TemporaryDirectory() as directory:
            manifest = coverage.merge_reports(self.selection, None, [value], source_commit=COMMIT,
                output_dir=Path(directory), allow_partial_workers=True, expected_partition_count=2)
            manifest["execution_summary"]["missing_partitions"] = []
            with self.assertRaisesRegex(PublicationError, "do not partition"):
                coverage.validate_manifest(manifest)

    def test_current_run_recovery_count_survives_final_assembly_and_is_bounded(self):
        value = partition_worker(self.selection, [record(self.sources[0])], count=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = coverage.merge_reports(self.selection, None, [value], source_commit=COMMIT,
                output_dir=root / "valid", allow_partial_workers=True, expected_partition_count=2,
                recovered_sources=1)
            self.assertEqual(manifest["execution_summary"]["recovered_sources"], 1)
            for invalid in (-1, 3, True):
                with self.subTest(count=invalid), self.assertRaisesRegex(PublicationError, "invalid recovered source"):
                    coverage.merge_reports(self.selection, None, [value], source_commit=COMMIT,
                        output_dir=root / "invalid", allow_partial_workers=True, expected_partition_count=2,
                        recovered_sources=invalid)
            self.assertFalse((root / "invalid").exists())


class RecoveryTests(unittest.TestCase):
    def summary(self, selection, source_commit=COMMIT):
        value = fixtures.QueueTests().discovery_summary(selection)
        value["source_commit"] = source_commit
        return value

    def batch(self, selection, values, previous=None):
        return {"selection": selection, "discovery": self.summary(selection),
                "workers": [worker(selection, values, previous)]}

    def recover(self, root, selection, batches, previous=None):
        commit = "d" * 40
        coverage.recover_previous(selection, previous, batches, source_commit=commit,
            discovery_summary=self.summary(selection, commit), output_dir=root)
        return coverage.read_bundle(root)

    def test_old_main_exact_identity_recovers_and_duplicate_is_idempotent(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        batch = self.batch(selection, [record(subject)])
        original = batch["workers"][0]["attempts"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = self.recover(root / "first", selection, [batch, batch])
            self.assertEqual(recovered["manifest"]["source_commit"], "d" * 40)
            self.assertEqual(recovered["records"][subject["id"]]["scanned_at"], original["record"]["scanned_at"])
            self.assertEqual(recovered["attempts"][subject["id"]], original["attempt"])
            self.assertEqual(recovered["manifest"]["execution_summary"]["recovered_sources"], 1)
            self.assertEqual(coverage.plan_attempts(selection, recovered, 0, 1, 128), [])
            duplicate = self.recover(root / "duplicate", selection, [batch], recovered)
            self.assertEqual(duplicate["attempts"], recovered["attempts"])
            self.assertEqual(duplicate["queue_cursor"], recovered["queue_cursor"])
            self.assertEqual(duplicate["manifest"]["execution_summary"]["recovered_sources"], 0)

    def test_changed_revision_is_not_promoted_and_source_discovery_remains_historical(self):
        old = item()
        old_selection = {"schema_version": 1, "sources": [old]}
        current = {**old, "revision": "b" * 40}
        selection = {"schema_version": 1, "sources": [current]}
        batch = self.batch(old_selection, [record(old)])
        with tempfile.TemporaryDirectory() as directory:
            recovered = self.recover(Path(directory), selection, [batch])
            self.assertEqual(recovered["records"], {})
            self.assertEqual(recovered["manifest"]["coverage"]["pending"], 1)
        summary = self.summary(old_selection, "d" * 40)
        summary["source_states"][0].update(current=False, state="historical", reason="repository_unavailable")
        with tempfile.TemporaryDirectory() as directory:
            coverage.recover_previous(old_selection, None, [batch], source_commit="d" * 40,
                discovery_summary=summary, output_dir=Path(directory))
            recovered = coverage.read_bundle(Path(directory))
            self.assertEqual(recovered["records"][old["id"]]["freshness"], "historical")
            self.assertEqual(recovered["manifest"]["coverage"]["complete"], 0)

    def test_retry_chain_recovers_consecutively_and_keeps_useful_error_fallback(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.batch(selection, [record(subject, "partial", "runtime_limit")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = bundle(root / "baseline", selection, [copy.deepcopy(first["workers"][0]["attempts"][0]["record"])])
            second = self.batch(selection, [record(subject, "error", "acquisition_failed", "static-extended-v3")], baseline)
            recovered = self.recover(root / "recovered", selection, [second, first])
            self.assertEqual(recovered["attempts"][subject["id"]]["attempt_count"], 2)
            self.assertEqual(recovered["records"][subject["id"]]["status"], "partial")
            self.assertEqual(recovered["records"][subject["id"]]["retry"]["latest_status"], "error")
            with self.assertRaisesRegex(PublicationError, "not consecutive"):
                self.recover(root / "gap", selection, [second])

    def test_conflicts_controlled_and_mixed_selection_are_rejected(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        batch = self.batch(selection, [record(subject)])
        conflict = copy.deepcopy(batch)
        conflict["workers"][0]["attempts"][0]["record"]["skill_name"] = "conflict"
        controlled = copy.deepcopy(batch)
        controlled["discovery"]["catalog"]["mode"] = "controlled_immutable_regression"
        mixed = copy.deepcopy(batch)
        mixed["workers"][0]["selection_digest"] = "sha256:" + "0" * 64
        for batches in ([batch, conflict], [controlled], [mixed]):
            with self.subTest(batches=batches), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(PublicationError):
                    self.recover(Path(directory), selection, batches)

    def authentic_batch(self, selection, run_id, second, *, warning=None, previous=None, exit_code=None):
        with mock.patch.object(coverage.scanner, "now", return_value=f"2020-01-01T00:00:{second:02d}Z"):
            value = record(selection["sources"][0])
            if warning is not None:
                raw = upstream_report()
                raw["issues"] = [{"id": "PI1", "severity": "HIGH", "explanation": warning,
                                  "location": {"file": "SKILL.md", "start_line": 1}}]
                value = coverage.scanner.normalize_report_v3(value, json.dumps(raw).encode(), 1, Path("/source"))
            if exit_code is not None:
                value["execution"]["exit_code"] = exit_code
            batch = self.batch(selection, [value], previous)
        batch["execution_origin"] = {"run_id": run_id, "run_attempt": 1}
        return batch

    def test_independent_equivalent_executions_preserve_published_evidence_and_counts(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(selection, 1, 0)
        second = self.authentic_batch(selection, 2, 1)
        second["workers"][0]["attempts"][0]["record"]["report_digest"] = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = self.recover(root / "published", selection, [first])
            recovered = self.recover(root / "recovered", selection, [second], baseline)
            self.assertEqual(recovered["records"], baseline["records"])
            self.assertEqual(recovered["attempts"], baseline["attempts"])
            self.assertEqual(recovered["queue_cursor"], baseline["queue_cursor"])
            self.assertEqual(recovered["manifest"]["execution_summary"]["recovered_sources"], 0)
            both = self.recover(root / "both", selection, [second, first])
            self.assertEqual(both["attempts"], baseline["attempts"])

    def test_independent_clean_and_dirty_conflicts_keep_original_warning_and_bounded_retry(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        clean = self.authentic_batch(selection, 1, 0)
        dirty = self.authentic_batch(selection, 2, 1, warning="An actual preserved warning.")
        original = dirty["workers"][0]["attempts"][0]["record"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, batches in enumerate(([clean, dirty], [dirty, clean])):
                recovered = self.recover(root / f"order-{index}", selection, batches)
                value = recovered["records"][subject["id"]]
                self.assertEqual(value["status"], "partial")
                self.assertFalse(value["coverage"]["grouping_complete"])
                self.assertTrue(value["findings_truncated"])
                self.assertTrue({"recovery_conflict", "normalization_truncated"} <= coverage.reason_codes(value))
                for key in ("source", "scanned_at", "report_digest", "findings", "execution"):
                    self.assertEqual(value[key], original[key])
                self.assertEqual(recovered["attempts"][subject["id"]]["attempt_count"], 1)
                self.assertEqual(recovered["attempts"][subject["id"]]["history"], clean["workers"][0]["attempts"][0]["attempt"]["history"])
                self.assertEqual(coverage.plan_attempts(selection, recovered, 0, 1, 128), [subject])
                replay = self.recover(root / f"replay-{index}", selection, batches, recovered)
                self.assertEqual(replay["records"], recovered["records"])
                self.assertEqual(replay["attempts"], recovered["attempts"])
            for index, (published, incoming) in enumerate(((clean, dirty), (dirty, clean))):
                baseline = self.recover(root / f"prior-{index}", selection, [published])
                recovered = self.recover(root / f"fork-{index}", selection, [incoming], baseline)
                self.assertEqual(recovered["records"][subject["id"]]["findings"], original["findings"])
                self.assertEqual(recovered["attempts"][subject["id"]]["history"], baseline["attempts"][subject["id"]]["history"])

    def test_disjoint_warnings_and_same_fingerprint_different_evidence_are_not_collapsed(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        left = self.authentic_batch(selection, 1, 0, warning="First warning.")
        right = self.authentic_batch(selection, 2, 1, warning="Distinct warning.")
        metadata = copy.deepcopy(left)
        metadata["execution_origin"]["run_id"] = 3
        metadata["workers"][0]["attempts"][0]["record"]["skill_name"] = "different normalized evidence"
        self.assertEqual(left["workers"][0]["attempts"][0]["attempt"]["fingerprint"],
                         metadata["workers"][0]["attempts"][0]["attempt"]["fingerprint"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = self.recover(root / "a", selection, [left, right])
            b = self.recover(root / "b", selection, [right, left])
            self.assertEqual(a["records"], b["records"])
            self.assertIn("not fully represented", a["records"][subject["id"]]["coverage"]["reasons"][-2]["message"])
            value = self.recover(root / "metadata", selection, [left, metadata])["records"][subject["id"]]
            self.assertEqual(value["status"], "partial")
            self.assertIn("recovery_conflict", coverage.reason_codes(value))

    def test_same_origin_conflicts_missing_predecessor_and_exit_code_difference_remain_distinct(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(selection, 1, 0)
        corrupted = copy.deepcopy(first)
        corrupted["workers"][0]["attempts"][0]["record"]["skill_name"] = "corrupt prefix"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(PublicationError, "conflicting cumulative"):
                self.recover(root / "same-origin", selection, [first, corrupted])
            baseline = self.recover(root / "first", selection, [first])
            retry = self.authentic_batch(selection, 2, 1, previous=baseline)
            with self.assertRaisesRegex(PublicationError, "missing predecessor"):
                self.recover(root / "gap", selection, [retry])
            exit_one = self.authentic_batch(selection, 3, 2, exit_code=1)
            changed = self.recover(root / "exit", selection, [first, exit_one])
            self.assertIn("recovery_conflict", coverage.reason_codes(changed["records"][subject["id"]]))

    def test_quarantine_preserves_exhausted_attempt_history_and_reports_bounded_diagnostics(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = None
            for index in range(4):
                with mock.patch.object(coverage.scanner, "now", return_value=f"2020-01-01T00:00:{index:02d}Z"):
                    previous = bundle(root / f"history-{index}", selection, [record(subject)], previous)
            original = copy.deepcopy(previous["attempts"][subject["id"]])
            dirty = self.authentic_batch(selection, 99, 10, warning="Retain the adverse evidence.")
            diagnostics = {}
            coverage.recover_previous(selection, previous, [dirty], source_commit="d" * 40,
                discovery_summary=self.summary(selection, "d" * 40), output_dir=root / "result", diagnostics=diagnostics)
            result = coverage.read_bundle(root / "result")
            attempt = result["attempts"][subject["id"]]
            self.assertEqual(attempt["attempt_count"], 4)
            self.assertEqual(attempt["history"], original["history"])
            self.assertEqual(attempt["status"], original["status"])
            self.assertEqual(attempt["disposition"], "exhausted")
            self.assertEqual(coverage.plan_attempts(selection, result, 0, 1, 128), [])
            self.assertEqual(diagnostics["conflicting_executions"], 1)
            self.assertEqual(diagnostics["examples"][0]["execution_origin"], {"run_id": 99, "run_attempt": 1})

    def test_a_retry_on_an_independent_fork_uses_its_verified_predecessor(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(selection, 1, 0)
        branch = self.authentic_batch(selection, 2, 1, warning="Branch warning.")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            branch_base = self.recover(root / "branch", selection, [branch])
            child = self.authentic_batch(selection, 3, 2, warning="Later branch warning.", previous=branch_base)
            result = self.recover(root / "fork", selection, [child, first, branch])
            self.assertEqual(result["records"][subject["id"]]["status"], "partial")
            self.assertIn("recovery_conflict", coverage.reason_codes(result["records"][subject["id"]]))
            self.assertEqual(result["attempts"][subject["id"]]["attempt_count"], 1)


if __name__ == "__main__":
    unittest.main()
