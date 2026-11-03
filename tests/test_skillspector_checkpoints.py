from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError
from tests.test_skillspector_coverage_v3 import COMMIT, record, worker
from tests.test_skillspector_reports import item


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.sources = [item(id=f"fixture/{name}", path=f"skills/{name}") for name in ("first", "second", "third")]
        self.selection = {"schema_version": 1, "sources": self.sources}

    def run_scan(self, *, checkpoint=None, resume=None, slice_attempts=None, analyze=None, pinned=None):
        pinned = pinned or mock.Mock()
        results = iter(analyze) if isinstance(analyze, list) else None

        def measured_record(*args, **kwargs):
            value = next(results) if results is not None else analyze(*args, **kwargs) if analyze else record(args[1])
            if isinstance(value, BaseException):
                raise value
            value["execution"]["acquisition_seconds"] = 0.0
            value["execution"]["analysis_seconds"] = 0.0
            return value

        with mock.patch.object(scanner, "verify_scanner"), \
             mock.patch.object(coverage, "PinnedRepository", return_value=pinned), \
             mock.patch.object(coverage, "scan_selected", side_effect=measured_record):
            return coverage.scan_partition(self.selection, Path("/scanner"), None,
                source_commit=COMMIT, partition_count=1, maximum_attempts=3,
                checkpoint=checkpoint, resume=resume, slice_attempts=slice_attempts)

    def test_later_crash_preserves_completed_transaction_and_fresh_process_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "worker.json"
            persist = lambda value: coverage.write_bounded(output, value, coverage.MAX_WORKER_BYTES)
            first = record(self.sources[0])
            with self.assertRaisesRegex(RuntimeError, "injected later crash"):
                self.run_scan(checkpoint=persist, analyze=[first, RuntimeError("injected later crash")])
            saved = coverage.read_json(output, max_bytes=coverage.MAX_WORKER_BYTES)
            coverage.validate_worker(saved, self.selection, COMMIT)
            self.assertEqual([value["attempt"]["id"] for value in saved["attempts"]], [self.sources[0]["id"]])
            analyzed = []

            def analyze(_, subject, *args, **kwargs):
                analyzed.append(subject["id"])
                return record(subject)

            resumed = self.run_scan(checkpoint=persist, resume=saved, analyze=analyze)
            self.assertEqual(analyzed, [subject["id"] for subject in self.sources[1:]])
            self.assertEqual(resumed["attempts"][0], saved["attempts"][0])
            self.assertEqual([value["attempt"]["attempt_count"] for value in resumed["attempts"]], [1, 1, 1])
            self.assertEqual(coverage.read_json(output, max_bytes=coverage.MAX_WORKER_BYTES), resumed)

    def test_slice_bound_is_additional_work_but_total_bound_is_cumulative(self):
        snapshots = []
        first = self.run_scan(checkpoint=snapshots.append, slice_attempts=1)
        self.assertEqual(len(snapshots[0]["attempts"]), 0)
        self.assertEqual(len(first["attempts"]), 1)
        second = self.run_scan(resume=first, slice_attempts=1)
        third = self.run_scan(resume=second, slice_attempts=1)
        complete = self.run_scan(resume=third, slice_attempts=1)
        self.assertEqual([len(value["attempts"]) for value in (first, second, third, complete)], [1, 2, 3, 3])
        self.assertEqual(first["attempts"], second["attempts"][:1])

    def test_scanner_setup_and_cleanup_failures_leave_valid_checkpoints(self):
        snapshots = []
        with mock.patch.object(scanner, "verify_scanner", side_effect=RuntimeError("setup")):
            with self.assertRaisesRegex(RuntimeError, "setup"):
                coverage.scan_partition(self.selection, Path("/scanner"), None,
                    source_commit=COMMIT, partition_count=1, checkpoint=snapshots.append)
        coverage.validate_worker(snapshots[-1], self.selection, COMMIT)
        self.assertEqual(snapshots[-1]["attempts"], [])
        pinned = mock.Mock()
        pinned.close.side_effect = RuntimeError("cleanup")
        with self.assertRaisesRegex(RuntimeError, "cleanup"):
            self.run_scan(checkpoint=snapshots.append, slice_attempts=1, pinned=pinned)
        coverage.validate_worker(snapshots[-1], self.selection, COMMIT)
        self.assertEqual(len(snapshots[-1]["attempts"]), 1)

    def test_output_capacity_defers_before_a_second_source_is_executed(self):
        value = worker(self.selection, [record(self.sources[0])])
        occupied = len(coverage.report_json(value))
        reserve = 128 << 10
        analyzed = []

        def analyze(_, subject, *args, **kwargs):
            analyzed.append(subject["id"])
            return record(subject)

        with mock.patch.object(coverage, "MAX_OUTCOME_BYTES", reserve), \
             mock.patch.object(coverage, "MAX_WORKER_BYTES", occupied + reserve - 1):
            result = self.run_scan(analyze=analyze)
        self.assertEqual(analyzed, [self.sources[0]["id"]])
        self.assertEqual(len(result["attempts"]), 1)

    def test_checkpoint_provenance_and_lineage_are_checked_before_execution(self):
        original = worker(self.selection, [record(self.sources[0])])
        for mutate in (lambda value: value.update(source_commit="d" * 40),
                       lambda value: value["partition"].update(count=2),
                       lambda value: value["attempts"][0]["attempt"].update(attempt_count=2)):
            with self.subTest(mutation=mutate):
                invalid = copy.deepcopy(original)
                mutate(invalid)
                with self.assertRaises(PublicationError):
                    self.run_scan(resume=invalid)

    def test_failed_atomic_replace_preserves_previous_bytes_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "worker.json"
            original = worker(self.selection, [record(self.sources[0])])
            coverage.write_bounded(output, original, coverage.MAX_WORKER_BYTES)
            before = output.read_bytes()
            with mock.patch.object(coverage.os, "replace", side_effect=OSError("injected replace interruption")):
                with self.assertRaises(OSError):
                    coverage.write_bounded(output, worker(self.selection), coverage.MAX_WORKER_BYTES)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual([path.name for path in Path(directory).iterdir()], ["worker.json"])

    def test_checkpoint_timestamp_advances_with_outcome_timestamp(self):
        timestamps = iter(f"2020-01-01T00:00:{second:02d}Z" for second in range(60))
        snapshots = []
        with mock.patch.object(scanner, "now", side_effect=lambda: next(timestamps)):
            result = self.run_scan(checkpoint=snapshots.append, slice_attempts=1)
        self.assertGreater(result["generated_at"], snapshots[0]["generated_at"])
        self.assertGreaterEqual(result["generated_at"], result["attempts"][0]["attempt"]["last_attempted_at"])
        coverage.validate_worker(result, self.selection, COMMIT)


if __name__ == "__main__":
    unittest.main()
