from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import skillspector_coverage_v3 as coverage
from scripts.directory_publication import PublicationError
from tests import test_skillspector_coverage_v3 as fixtures
from tests.test_skillspector_coverage_v3 import COMMIT, bundle, record, worker
from tests.test_skillspector_reports import item


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

    def test_independent_main_runs_with_same_fingerprint_dedupe_without_wedging(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        with mock.patch.object(coverage.scanner, "now", return_value="2026-11-03T09:00:00Z"):
            first = self.batch(selection, [record(subject)])
        with mock.patch.object(coverage.scanner, "now", return_value="2026-11-03T09:05:00Z"):
            second = self.batch(selection, [record(subject)])
        earlier = first["workers"][0]["attempts"][0]["attempt"]
        later = second["workers"][0]["attempts"][0]["attempt"]
        self.assertEqual(earlier["fingerprint"], later["fingerprint"])
        self.assertNotEqual(earlier["last_attempted_at"], later["last_attempted_at"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.recover(root / "coalesced", selection, [first, second])
            self.assertEqual(result["attempts"][subject["id"]]["last_attempted_at"],
                             later["last_attempted_at"])
            baseline = self.recover(root / "original", selection, [first])
            duplicate = self.recover(root / "persisted", selection, [second], baseline)
            self.assertEqual(duplicate["attempts"], baseline["attempts"])
            self.assertEqual(duplicate["manifest"]["execution_summary"]["recovered_sources"], 0)
            with mock.patch.object(coverage.scanner, "now", return_value="2026-11-03T09:10:00Z"):
                divergent = self.batch(selection, [record(subject, "partial", "runtime_limit")])
            with self.assertRaisesRegex(PublicationError, "conflicting recovered outcomes"):
                self.recover(root / "divergent", selection, [first, divergent])

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


if __name__ == "__main__":
    unittest.main()
