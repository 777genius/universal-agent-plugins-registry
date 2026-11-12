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

    def test_retained_partial_attempt_replays_without_conflict_or_hidden_changes(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        old = record(subject, "partial", "static_parse_limit", "static-extended-v3")
        old["coverage"]["fully_inspected_files"] = 8
        new = record(subject, "partial", "static_parse_limit", "static-standard-v3")
        new["coverage"]["fully_inspected_files"] = 1
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = bundle(root / "previous", selection, [old])
            incoming = self.batch(selection, [new], previous)
            incoming["execution_origin"] = {"run_id": 3401, "run_attempt": 1}
            retained = self.recover(root / "retained", selection, [incoming], previous)
            prior_record = retained["records"][subject["id"]]
            prior_attempt = retained["attempts"][subject["id"]]
            self.assertEqual(prior_record["coverage"]["fully_inspected_files"], 8)
            self.assertEqual(prior_attempt["attempt_count"], 2)
            self.assertTrue(coverage.retained_degraded_replay(
                subject, prior_record, prior_attempt, incoming["workers"][0]["attempts"][0]))
            for label, batch in (
                ("authenticated", incoming),
                ("no-origin", {key: copy.deepcopy(value) for key, value in incoming.items()
                               if key != "execution_origin"}),
            ):
                replay = self.recover(root / label, selection, [batch], retained)
                self.assertEqual(replay["records"], retained["records"])
                self.assertEqual(replay["attempts"], retained["attempts"])
                self.assertEqual(replay["queue_cursor"], retained["queue_cursor"])
                self.assertEqual(replay["manifest"]["execution_summary"]["recovered_sources"], 0)

            # An independent worker with the same attempt fingerprint but
            # changed report identity must still enter conflict handling.
            forged = copy.deepcopy(incoming)
            forged["execution_origin"]["run_id"] = 3402
            forged["workers"][0]["attempts"][0]["record"]["skill_name"] = "different skill metadata"
            self.assertFalse(coverage.retained_degraded_replay(
                subject, prior_record, prior_attempt, forged["workers"][0]["attempts"][0]))
            divergent = self.recover(root / "divergent", selection, [forged], retained)
            self.assertIn("recovery_conflict", coverage.reason_codes(divergent["records"][subject["id"]]))

    def test_sequential_authenticated_degradation_with_new_risks_is_quarantined(self):
        """Never lose either security warning silently in a verified retry."""
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(
            selection, 5501, 0, warning="Original security risk.", pattern="original-static-risk",
            status="partial", reason="static_parse_limit", profile_id="static-extended-v3",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = self.recover(root / "baseline", selection, [first])
            second = self.authentic_batch(
                selection, 5502, 1, warning="Distinct new security risk.", pattern="new-static-risk",
                status="partial", reason="static_parse_limit", profile_id="static-standard-v3",
                previous=baseline,
            )
            old = baseline["records"][subject["id"]]
            new = second["workers"][0]["attempts"][0]["record"]
            self.assertTrue(coverage.degraded_rescan(old, new))
            self.assertTrue(coverage.finding_identities(new) - coverage.finding_identities(old))

            # Only an authenticated historical producer can reconcile the
            # mismatch. Ordinary merges remain fail-closed and cannot weaken
            # the finding-identity gate.
            untrusted = copy.deepcopy(second)
            untrusted.pop("execution_origin")
            with self.assertRaisesRegex(PublicationError, "degraded partial rescan introduces new findings"):
                self.recover(root / "untrusted", selection, [untrusted], baseline)

            recovered = self.recover(root / "quarantined", selection, [second], baseline)
            value, attempt = recovered["records"][subject["id"]], recovered["attempts"][subject["id"]]
            self.assertEqual(value["status"], "partial")
            self.assertEqual(value["coverage"]["status"], "partial")
            self.assertTrue(value["findings_truncated"])
            self.assertFalse(value["coverage"]["grouping_complete"])
            self.assertTrue({"recovery_conflict", "normalization_truncated"} <=
                            coverage.reason_codes(value))
            self.assertEqual(attempt["attempt_count"], 2)
            self.assertEqual(attempt["history"], second["workers"][0]["attempts"][0]["attempt"]["history"])
            self.assertEqual(attempt["reason"], "recovery_conflict")
            self.assertEqual(attempt["disposition"], "scheduled")
            self.assertEqual(recovered["manifest"]["execution_summary"]["recovered_sources"], 1)
            self.assertEqual(coverage.plan_attempts(selection, recovered, 0, 1, 128), [subject])
            self.assertIn(value["findings"], [old["findings"], new["findings"]])

            # Replaying the exact authenticated artifact is idempotent.
            replay = self.recover(root / "replay", selection, [second], recovered)
            self.assertEqual(replay["records"], recovered["records"])
            self.assertEqual(replay["attempts"], recovered["attempts"])
            self.assertEqual(replay["manifest"]["execution_summary"]["recovered_sources"], 0)

    def test_authenticated_degraded_complete_is_explicit_partial_with_risk_retained(self):
        """A new 'Complete' cannot erase verified same-source risks or analysis."""
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(
            selection, 5611, 0, warning="Original HIGH evidence must remain visible.",
            pattern="old-risk", status="partial", reason="static_parse_limit",
            profile_id="static-extended-v3",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = self.recover(root / "baseline", selection, [first])
            complete = self.authentic_batch(
                selection, 5612, 1, status="complete", previous=baseline,
                profile_id="static-standard-v3",
            )
            old = baseline["records"][subject["id"]]
            fresh = complete["workers"][0]["attempts"][0]["record"]
            self.assertEqual(fresh["status"], "complete")
            self.assertTrue(coverage.degraded_rescan(old, fresh))
            self.assertTrue(coverage.finding_identities(old) - coverage.finding_identities(fresh))

            # Merely claiming the same execution is not authenticated.
            without_origin = copy.deepcopy(complete)
            without_origin.pop("execution_origin")
            with self.assertRaisesRegex(PublicationError, "complete rescan regresses verified"):
                self.recover(root / "unauthenticated", selection, [without_origin], baseline)

            corrupted = copy.deepcopy(complete)
            corrupted["workers"][0]["attempts"][0]["attempt"]["history"][-1]["fingerprint"] = (
                "sha256:" + "f" * 64
            )
            with self.assertRaises(PublicationError):
                self.recover(root / "corrupted", selection, [corrupted], baseline)

            recovered = self.recover(root / "quarantined", selection, [complete], baseline)
            value, attempt = recovered["records"][subject["id"]], recovered["attempts"][subject["id"]]
            self.assertEqual(value["status"], "partial")
            self.assertEqual(value["coverage"]["status"], "partial")
            self.assertEqual(value["findings"], old["findings"])
            self.assertEqual(value["source"], old["source"])
            self.assertTrue(value["findings_truncated"])
            self.assertFalse(value["coverage"]["grouping_complete"])
            self.assertTrue({"recovery_conflict", "normalization_truncated"} <= coverage.reason_codes(value))
            self.assertEqual(attempt["attempt_count"], 2)
            self.assertEqual(attempt["status"], "complete")  # Preserve the actual scanner execution.
            self.assertEqual(attempt["history"], complete["workers"][0]["attempts"][0]["attempt"]["history"])
            self.assertEqual(attempt["reason"], "recovery_conflict")
            self.assertEqual(attempt["disposition"], "scheduled")
            self.assertEqual(attempt["next_profile"], "static-extended-v3")
            self.assertEqual(coverage.plan_attempts(selection, recovered, 0, 1, 128), [subject])
            self.assertEqual(recovered["manifest"]["execution_summary"]["recovered_sources"], 1)

            replay = self.recover(root / "replay", selection, [complete], recovered)
            self.assertEqual(replay["records"], recovered["records"])
            self.assertEqual(replay["attempts"], recovered["attempts"])
            self.assertEqual(replay["manifest"]["execution_summary"]["recovered_sources"], 0)

    def test_authenticated_complete_conflict_preserves_both_original_witnesses(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(
            selection, 5701, 0, warning="Previously verified HIGH risk.", pattern="old-risk",
            status="partial", reason="static_parse_limit", profile_id="static-extended-v3",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = self.recover(root / "baseline", selection, [first])
            old = baseline["records"][subject["id"]]
            clean = self.authentic_batch(selection, 5702, 1, status="complete", previous=baseline)
            self.assertTrue(coverage.degraded_rescan(old, clean["workers"][0]["attempts"][0]["record"]))

            # A later authenticated recovery may preserve the actual execution
            # but may not promote the rejected Complete or discard old evidence.
            recovered = self.recover(root / "recovered", selection, [clean], baseline)
            kept = recovered["records"][subject["id"]]
            self.assertEqual(kept["status"], "partial")
            self.assertEqual(kept["findings"], old["findings"])
            self.assertEqual(kept["coverage"]["fully_inspected_files"], old["coverage"]["fully_inspected_files"])
            self.assertIn("recovery_conflict", coverage.reason_codes(kept))
            self.assertEqual(recovered["attempts"][subject["id"]]["status"], "complete")

            # Even a legacy snapshot with no compatible retry metadata cannot
            # let a first-epoch Complete overwrite its verified Partial record.
            without_attempt = copy.deepcopy(baseline)
            without_attempt["attempts"] = {}
            first_epoch = self.authentic_batch(selection, 5703, 2, status="complete")
            legacy = self.recover(root / "legacy", selection, [first_epoch], without_attempt)
            self.assertEqual(legacy["records"][subject["id"]]["status"], "partial")
            self.assertEqual(legacy["records"][subject["id"]]["findings"], old["findings"])

            # The direct merge of two conflicting scanner reports remains
            # fail-closed, even when the caller claims a trusted worker.
            novel = self.authentic_batch(
                selection, 5704, 3, warning="New HIGH risk.", pattern="new-risk",
                status="complete", previous=baseline,
            )
            outcome = novel["workers"][0]["attempts"][0]
            records, attempts = {subject["id"]: copy.deepcopy(old)}, copy.deepcopy(baseline["attempts"])
            with self.assertRaisesRegex(PublicationError, "degraded complete introduces unrepresented new findings"):
                coverage.apply_outcome(records, attempts, subject, outcome, authenticated_current_worker=True)
            self.assertEqual(records[subject["id"]], old)
            self.assertEqual(attempts, baseline["attempts"])

            # The *authenticated main checkpoint* may retain both original
            # reports, without fabricating a scanner union or claiming Complete.
            merged = self.recover(root / "witness", selection, [novel], baseline)
            kept = merged["records"][subject["id"]]
            self.assertEqual(kept["status"], "partial")
            self.assertEqual(kept["findings"], old["findings"])
            self.assertTrue(kept["findings_truncated"])
            self.assertIn("recovery_conflict", coverage.reason_codes(kept))
            self.assertEqual(len(kept["recovery_witnesses"]), 1)
            witness = kept["recovery_witnesses"][0]
            self.assertEqual(witness["origin"], {"run_id": 5704, "run_attempt": 1})
            self.assertEqual(witness["record"], outcome["record"])
            self.assertNotEqual(witness["record"]["report_digest"], kept["report_digest"])
            self.assertEqual(witness["record"]["source"], kept["source"])
            empty = copy.deepcopy(kept)
            empty["recovery_witnesses"] = []
            with self.assertRaisesRegex(PublicationError, "empty or excessive recovery witness list"):
                coverage.contract.validate_record(empty, subject, coverage.v2.timestamp(coverage.scanner.now(), "generated"),
                    scheduled=True, allowed_profiles=merged["manifest"]["profiles"],
                    scanner_identity=merged["manifest"]["scanner"],
                    repository_aliases=merged["manifest"]["repository_aliases"])
            self.assertEqual(merged["attempts"][subject["id"]]["attempt_count"], 2)
            self.assertEqual(merged["attempts"][subject["id"]]["history"],
                             outcome["attempt"]["history"])
            replay = self.recover(root / "witness-replay", selection, [novel], merged)
            self.assertEqual(replay["records"], merged["records"])
            self.assertEqual(replay["attempts"], merged["attempts"])
            self.assertEqual(replay["manifest"]["execution_summary"]["recovered_sources"], 0)

            # A subsequent single-witness Complete is still missing the other
            # verified findings: it cannot erase the authenticated alternative
            # or silently change this source into Complete.
            later = copy.deepcopy(outcome["record"])
            later_outcome = {"record": later, "attempt": coverage.make_attempt(
                subject, later, merged["attempts"][subject["id"]], kept)}
            later_records = {subject["id"]: copy.deepcopy(kept)}
            later_attempts = copy.deepcopy(merged["attempts"])
            self.assertTrue(coverage.degraded_rescan(kept, later))
            self.assertTrue(coverage.apply_outcome(later_records, later_attempts,
                subject, later_outcome, authenticated_current_worker=True))
            self.assertEqual(later_records[subject["id"]]["status"], "partial")
            self.assertEqual(later_records[subject["id"]]["findings"], old["findings"])
            self.assertEqual(later_records[subject["id"]]["recovery_witnesses"],
                             kept["recovery_witnesses"])

            # Unauthenticated or oversized evidence cannot enter the signed
            # report. Neither adversarial input may modify a prior bundle.
            untrusted = {key: copy.deepcopy(value) for key, value in novel.items()
                         if key != "execution_origin"}
            with self.assertRaises(PublicationError):
                self.recover(root / "untrusted-novel", selection, [untrusted], baseline)
            oversized = copy.deepcopy(novel)
            oversized["workers"][0]["attempts"][0]["record"]["findings"][0]["message"] = "x" * (260 << 10)
            with self.assertRaises(PublicationError):
                self.recover(root / "oversized-witness", selection, [oversized], baseline)
            self.assertFalse((root / "oversized-witness" / "index.json").exists())

    def test_authenticated_recovery_witness_survives_source_revision_drift_as_historical(self):
        """A new catalog pin must not invalidate or mislabel older evidence."""
        original = item()
        selection = {"schema_version": 1, "sources": [original]}
        first = self.authentic_batch(selection, 8801, 0,
            warning="Earlier source-bound warning.", pattern="original-risk",
            status="partial", reason="static_parse_limit")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = self.recover(root / "previous", selection, [first])
            conflicting = self.authentic_batch(selection, 8802, 1,
                warning="Independent source-bound warning.", pattern="alternate-risk",
                status="complete", previous=previous)
            disputed = self.recover(root / "disputed", selection, [conflicting], previous)
            before = disputed["records"][original["id"]]
            self.assertEqual(len(before["recovery_witnesses"]), 1)
            changed = item(revision="b" * 40)
            later_selection = {"schema_version": 1, "sources": [changed]}
            coverage.merge_reports(later_selection, disputed,
                [worker(later_selection)], source_commit=COMMIT, output_dir=root / "later")
            later = coverage.read_bundle(root / "later")
            retained = later["records"][original["id"]]
            self.assertEqual(retained["freshness"], "historical")
            self.assertEqual(retained["target_revision"], changed["revision"])
            self.assertEqual(retained["status"], "partial")
            self.assertEqual(retained["source"], before["source"])
            self.assertEqual(retained["findings"], before["findings"])
            self.assertEqual(retained["recovery_witnesses"], before["recovery_witnesses"])
            self.assertEqual(later["manifest"]["coverage"]["stale"], 1)
            self.assertEqual(later["manifest"]["coverage"]["pending"], 1)
            self.assertEqual(later["manifest"]["coverage"]["complete"], 0)

    def test_sequential_conflict_with_unverified_attempt_history_is_rejected(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        first = self.authentic_batch(
            selection, 5503, 0, warning="Preserved warning.", pattern="old-risk", status="partial",
            reason="static_parse_limit", profile_id="static-extended-v3",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = self.recover(root / "baseline", selection, [first])
            changed = self.authentic_batch(
                selection, 5504, 1, warning="New warning.", pattern="new-risk", status="partial",
                reason="static_parse_limit", profile_id="static-standard-v3",
                previous=baseline,
            )
            changed["workers"][0]["attempts"][0]["attempt"]["history"][-1]["fingerprint"] = (
                "sha256:" + "f" * 64
            )
            with self.assertRaises(PublicationError):
                self.recover(root / "rejected", selection, [changed], baseline)

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

    def authentic_batch(self, selection, run_id, second, *, warning=None, pattern=None, previous=None, exit_code=None,
                        status="complete", reason=None, profile_id="static-standard-v3"):
        with mock.patch.object(coverage.scanner, "now", return_value=f"2020-01-01T00:00:{second:02d}Z"):
            value = record(selection["sources"][0], status, reason, profile_id)
            if warning is not None:
                raw = upstream_report()
                raw["issues"] = [{"id": "PI1", "severity": "HIGH", "explanation": warning,
                                  "location": {"file": "SKILL.md", "start_line": 1},
                                  **({"pattern": pattern} if pattern is not None else {})}]
                if status == "partial":
                    raw["analysis_completeness"].update(is_complete=False, status="partial", partially_inspected_files=1)
                    raw["analysis_completeness"]["ledger_exceptions"] = [{"reason_code": reason or "static_parse_limit", "message": "Bounded fixture limitation."}]
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
        left = self.authentic_batch(selection, 1, 0, warning="First warning.", pattern="old-distinct-risk")
        right = self.authentic_batch(selection, 2, 1, warning="Distinct warning.", pattern="new-distinct-risk")
        metadata = copy.deepcopy(left)
        metadata["execution_origin"]["run_id"] = 3
        metadata["workers"][0]["attempts"][0]["record"]["skill_name"] = "different normalized evidence"
        self.assertEqual(left["workers"][0]["attempts"][0]["attempt"]["fingerprint"],
                         metadata["workers"][0]["attempts"][0]["attempt"]["fingerprint"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(coverage.scanner, "now", return_value="2020-01-01T00:01:00Z"):
                a = self.recover(root / "a", selection, [left, right])
                b = self.recover(root / "b", selection, [right, left])
            self.assertEqual(a["records"], b["records"])
            self.assertIn("not fully represented", a["records"][subject["id"]]["coverage"]["reasons"][-2]["message"])
            # Neither independent original adverse finding may disappear just
            # because the two scanner results have the same number of groups.
            primary = a["records"][subject["id"]]
            original_left = left["workers"][0]["attempts"][0]["record"]
            original_right = right["workers"][0]["attempts"][0]["record"]
            self.assertEqual(primary["findings"], original_left["findings"])
            self.assertEqual(len(primary["recovery_witnesses"]), 1)
            self.assertEqual(primary["recovery_witnesses"][0]["origin"],
                             {"run_id": 2, "run_attempt": 1})
            self.assertEqual(primary["recovery_witnesses"][0]["record"], original_right)
            self.assertEqual(coverage.represented_finding_identities(primary),
                coverage.finding_identities(original_left) | coverage.finding_identities(original_right))
            replay = self.recover(root / "disjoint-replay", selection, [left, right], a)
            self.assertEqual(replay["records"], a["records"])
            self.assertEqual(replay["attempts"], a["attempts"])

            # The same lossless invariant applies when *both* independent
            # originals report Partial rather than Complete.
            partial_left = self.authentic_batch(selection, 11, 3, warning="Partial left risk.", pattern="partial-old-risk",
                status="partial", reason="static_parse_limit")
            partial_right = self.authentic_batch(selection, 12, 4, warning="Partial right risk.", pattern="partial-new-risk",
                status="partial", reason="static_parse_limit")
            partial = self.recover(root / "partial-disjoint", selection, [partial_left, partial_right])
            partial_record = partial["records"][subject["id"]]
            self.assertEqual(partial_record["status"], "partial")
            self.assertEqual(len(partial_record["recovery_witnesses"]), 1)
            self.assertEqual(coverage.represented_finding_identities(partial_record),
                coverage.finding_identities(partial_left["workers"][0]["attempts"][0]["record"]) |
                coverage.finding_identities(partial_right["workers"][0]["attempts"][0]["record"]))
            value = self.recover(root / "metadata", selection, [left, metadata])["records"][subject["id"]]
            self.assertEqual(value["status"], "partial")
            self.assertIn("recovery_conflict", coverage.reason_codes(value))

    def test_conflicting_recovery_counts_changed_source_once_and_replay_zero(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        clean = self.authentic_batch(selection, 1, 0)
        dirty = self.authentic_batch(selection, 2, 1, warning="Recovered adverse evidence.")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            published = self.recover(root / "published", selection, [clean])
            recovered = self.recover(root / "recovered", selection, [dirty], published)
            self.assertEqual(recovered["manifest"]["execution_summary"]["recovered_sources"], 1)
            self.assertEqual(recovered["records"][subject["id"]]["finding_count"], 1)
            self.assertEqual(recovered["records"][subject["id"]]["status"], "partial")
            self.assertEqual(recovered["attempts"][subject["id"]]["history"],
                             published["attempts"][subject["id"]]["history"])
            replay = self.recover(root / "replay", selection, [dirty], recovered)
            self.assertEqual(replay["manifest"]["execution_summary"]["recovered_sources"], 0)
            self.assertEqual(replay["records"], recovered["records"])
            self.assertEqual(replay["attempts"], recovered["attempts"])

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
            retry.pop("execution_origin")
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

    def test_authenticated_same_count_retry_fork_reconciles_without_stalling_prepare(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        original = self.authentic_batch(selection, 50, 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = self.recover(root / "prior", selection, [original])
            clean = self.authentic_batch(selection, 51, 1, previous=prior)
            dirty = self.authentic_batch(selection, 52, 2, warning="Independent second-attempt finding.", previous=prior)
            published = self.recover(root / "published", selection, [clean], prior)
            self.assertEqual(published["attempts"][subject["id"]]["attempt_count"], 2)
            recovered = self.recover(root / "recovered", selection, [dirty], published)
            self.assertEqual(recovered["attempts"][subject["id"]]["attempt_count"], 2)
            self.assertIn("recovery_conflict", coverage.reason_codes(recovered["records"][subject["id"]]))
            self.assertEqual(recovered["records"][subject["id"]]["status"], "partial")
            replay = self.recover(root / "replay", selection, [dirty], recovered)
            self.assertEqual(replay["records"], recovered["records"])
            self.assertEqual(replay["attempts"], recovered["attempts"])

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

    def test_missing_parent_seeds_uncertain_original_history_and_fresh_scan_resolves_it(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = self.authentic_batch(selection, 1, 0, status="partial", reason="runtime_limit")
            prior = self.recover(root / "parent", selection, [parent])
            child = self.authentic_batch(selection, 2, 1, previous=prior, profile_id="static-extended-v3")
            original = child["workers"][0]["attempts"][0]
            seeded = self.recover(root / "seeded", selection, [child])
            value, attempt = seeded["records"][subject["id"]], seeded["attempts"][subject["id"]]
            for key in ("source", "scanned_at", "report_digest", "findings", "execution"):
                self.assertEqual(value[key], original["record"][key])
            self.assertEqual((value["status"], attempt["attempt_count"], attempt["status"]), ("partial", 2, "complete"))
            self.assertFalse(value["coverage"]["grouping_complete"])
            self.assertTrue(value["findings_truncated"])
            self.assertIn("recovery_predecessor_unavailable", coverage.reason_codes(value))
            self.assertEqual(attempt["history"], original["attempt"]["history"])
            self.assertEqual(attempt["next_profile"], "static-extended-v3")
            repeat = self.recover(root / "repeat", selection, [child], seeded)
            self.assertEqual(repeat["records"], seeded["records"])
            self.assertEqual(repeat["attempts"], seeded["attempts"])
            actual_fresh = self.authentic_batch(selection, 3, 2, previous=seeded, profile_id="static-extended-v3")
            recovered_fresh = self.recover(root / "recovered-fresh", selection, [actual_fresh], seeded)
            self.assertEqual(recovered_fresh["records"][subject["id"]]["status"], "complete")
            self.assertNotIn("recovery_predecessor_unavailable", coverage.reason_codes(recovered_fresh["records"][subject["id"]]))
            self.assertEqual(recovered_fresh["attempts"][subject["id"]]["attempt_count"], 3)
            orphan_chain = self.recover(root / "same-batch-orphans", selection, [child, actual_fresh])
            self.assertEqual(orphan_chain["records"][subject["id"]]["status"], "partial")
            changed = {**subject, "revision": "b" * 40}
            changed_selection = {"schema_version": 1, "sources": [changed]}
            new_source = self.authentic_batch(changed_selection, 4, 3)
            new_epoch = self.recover(root / "new-source", changed_selection, [new_source], seeded)
            self.assertEqual(new_epoch["records"][subject["id"]]["status"], "complete")
            self.assertEqual(new_epoch["attempts"][subject["id"]]["attempt_count"], 1)
            fresh = worker(selection, [record(subject, profile_id="static-extended-v3")], seeded)
            coverage.merge_reports(selection, seeded, [fresh], source_commit=COMMIT, output_dir=root / "fresh")
            resolved = coverage.read_bundle(root / "fresh")
            self.assertEqual(resolved["records"][subject["id"]]["status"], "complete")
            self.assertNotIn("recovery_predecessor_unavailable", coverage.reason_codes(resolved["records"][subject["id"]]))
            late = self.recover(root / "late-parent", selection, [parent], resolved)
            self.assertEqual(late["records"], resolved["records"])

    def test_late_warning_parent_backfills_error_child_and_failed_fresh_scan_preserves_it(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = self.authentic_batch(selection, 1, 0, status="partial", reason="runtime_limit", warning="Preserve this warning.")
            prior = self.recover(root / "parent", selection, [parent])
            child = self.authentic_batch(selection, 2, 1, status="error", reason="acquisition_failed",
                previous=prior, profile_id="static-extended-v3")
            original = child["workers"][0]["attempts"][0]
            seeded = self.recover(root / "child", selection, [child])
            self.assertEqual(seeded["records"][subject["id"]]["status"], "error")
            attempt = seeded["attempts"][subject["id"]]
            self.assertEqual(attempt["history"], original["attempt"]["history"])
            self.assertEqual(attempt["next_profile"], original["attempt"]["next_profile"])
            self.assertGreaterEqual(attempt["next_attempt_at"], original["attempt"]["next_attempt_at"])
            early_error = worker(selection, [record(subject, "error", "acquisition_failed", "static-extended-v3")], seeded)
            coverage.merge_reports(selection, seeded, [early_error], source_commit=COMMIT, output_dir=root / "early-error")
            before_parent = coverage.read_bundle(root / "early-error")
            self.assertEqual(before_parent["records"][subject["id"]]["status"], "error")
            self.assertIn("recovery_predecessor_unavailable", coverage.reason_codes(before_parent["records"][subject["id"]]))
            late_after_error = self.recover(root / "late-after-error", selection, [parent], before_parent)
            self.assertEqual(late_after_error["records"][subject["id"]]["findings"], prior["records"][subject["id"]]["findings"])
            self.assertEqual(late_after_error["attempts"], before_parent["attempts"])
            self.assertEqual(late_after_error["records"][subject["id"]]["retry"]["latest_status"], "error")
            recovered_error = self.authentic_batch(selection, 3, 2, previous=seeded, status="error",
                reason="acquisition_failed", profile_id="static-extended-v3")
            recovered_failure = self.recover(root / "recovered-error", selection, [recovered_error], seeded)
            self.assertIn("recovery_predecessor_unavailable", coverage.reason_codes(recovered_failure["records"][subject["id"]]))
            recovered = self.recover(root / "late", selection, [parent], seeded)
            value = recovered["records"][subject["id"]]
            for key in ("source", "report_digest", "findings", "scanned_at", "execution"):
                self.assertEqual(value[key], prior["records"][subject["id"]][key])
            self.assertEqual(value["retry"]["latest_status"], "error")
            self.assertEqual(recovered["attempts"], seeded["attempts"])
            self.assertIn("recovery_predecessor_unavailable", coverage.reason_codes(value))
            fresh_error = worker(selection, [record(subject, "error", "acquisition_failed", "static-extended-v3")], recovered)
            coverage.merge_reports(selection, recovered, [fresh_error], source_commit=COMMIT, output_dir=root / "failure")
            failed = coverage.read_bundle(root / "failure")
            self.assertEqual(failed["records"][subject["id"]]["findings"], value["findings"])
            self.assertEqual(failed["records"][subject["id"]]["status"], "partial")
            self.assertEqual(failed["attempts"][subject["id"]]["attempt_count"], 3)

    def test_persisted_count_two_reconciles_independent_equivalent_and_divergent_forks(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a1 = self.recover(root / "a1", selection, [self.authentic_batch(selection, 1, 0)])
            a2 = self.authentic_batch(selection, 2, 1, previous=a1)
            published = self.recover(root / "a2", selection, [a2], a1)
            b1 = self.recover(root / "b1", selection, [self.authentic_batch(selection, 3, 2)])
            b2 = self.authentic_batch(selection, 4, 3, previous=b1)
            same = self.recover(root / "same", selection, [b2], published)
            self.assertEqual(same["records"], published["records"])
            self.assertEqual(same["attempts"], published["attempts"])
            dirty = self.authentic_batch(selection, 5, 4, previous=b1, warning="Independent warning.")
            changed = self.recover(root / "dirty", selection, [dirty], published)
            self.assertEqual(changed["records"][subject["id"]]["status"], "partial")
            self.assertEqual(changed["attempts"][subject["id"]]["attempt_count"], 2)
            self.assertEqual(changed["attempts"][subject["id"]]["history"], published["attempts"][subject["id"]]["history"])
            again = self.recover(root / "repeat", selection, [dirty], changed)
            self.assertEqual(again["records"], changed["records"])
            self.assertEqual(again["attempts"], changed["attempts"])

    def test_unavailable_parent_does_not_reset_four_attempt_cap_or_admit_truncated_history(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = None
            for index in range(3):
                with mock.patch.object(coverage.scanner, "now", return_value=f"2020-01-01T00:00:{index:02d}Z"):
                    prior = bundle(root / f"parent-{index}", selection, [record(subject)], prior)
            fourth = self.authentic_batch(selection, 10, 4, previous=prior)
            result = self.recover(root / "fourth", selection, [fourth])
            attempt = result["attempts"][subject["id"]]
            self.assertEqual((attempt["attempt_count"], attempt["disposition"]), (4, "exhausted"))
            self.assertEqual(attempt["history"], fourth["workers"][0]["attempts"][0]["attempt"]["history"])
            self.assertEqual(coverage.plan_attempts(selection, result, 0, 1, 128), [])
            self.assertEqual(result["records"][subject["id"]]["status"], "partial")
            invalid = copy.deepcopy(fourth)
            invalid["workers"][0]["attempts"][0]["attempt"]["history"].pop(0)
            with self.assertRaises(PublicationError):
                self.recover(root / "truncated", selection, [invalid])

    def test_current_epoch_history_suffix_preserves_real_older_profile_prefix_and_backfill(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        parent = self.authentic_batch(selection, 1, 1, status="partial", reason="runtime_limit", warning="Original parent warning.")
        parent_outcome = parent["workers"][0]["attempts"][0]
        legacy = copy.deepcopy(parent_outcome["attempt"]["history"][0])
        legacy.update(at="2019-01-01T00:00:00Z")
        legacy["profile"]["digest"] = "sha256:" + "a" * 64
        parent_outcome["attempt"] = coverage.make_attempt(subject, parent_outcome["record"],
            previous_record={"attempt_history": [legacy]}, at=parent_outcome["attempt"]["last_attempted_at"])
        coverage.validate_worker(parent["workers"][0], selection, COMMIT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = self.recover(root / "parent", selection, [parent])
            self.assertEqual(prior["attempts"][subject["id"]]["history"], parent_outcome["attempt"]["history"])
            child = self.authentic_batch(selection, 2, 2, previous=prior, status="error",
                reason="acquisition_failed", profile_id="static-extended-v3")
            original = child["workers"][0]["attempts"][0]["attempt"]
            self.assertEqual((original["attempt_count"], len(original["history"])), (2, 3))
            seeded = self.recover(root / "seeded", selection, [child])
            self.assertEqual(seeded["attempts"][subject["id"]]["history"], original["history"])
            backfilled = self.recover(root / "backfilled", selection, [parent], seeded)
            self.assertEqual(backfilled["records"][subject["id"]]["findings"], parent_outcome["record"]["findings"])
            self.assertEqual(backfilled["attempts"][subject["id"]]["history"], original["history"])
            self.assertEqual(backfilled["records"][subject["id"]]["retry"]["latest_status"], "error")
            tampered = copy.deepcopy(child)
            tampered["workers"][0]["attempts"][0]["attempt"]["history"][-2]["profile"]["digest"] = legacy["profile"]["digest"]
            with self.assertRaises(PublicationError):
                self.recover(root / "bad-epoch", selection, [tampered])
            originless = copy.deepcopy(child)
            originless.pop("execution_origin")
            with self.assertRaises(PublicationError):
                self.recover(root / "originless", selection, [originless])

    def test_late_parent_epoch_matches_after_old_prefix_rolls_out_of_bounded_history(self):
        subject = item()
        selection = {"schema_version": 1, "sources": [subject]}
        parent = self.authentic_batch(selection, 1, 1, status="partial", reason="runtime_limit", warning="Retain parent warning.")
        original = parent["workers"][0]["attempts"][0]
        prefix = []
        for second in range(7):
            entry = copy.deepcopy(original["attempt"]["history"][0])
            entry["at"] = f"2019-01-01T00:00:{second:02d}Z"
            entry["profile"]["digest"] = "sha256:" + "a" * 64
            prefix.append(entry)
        original["attempt"] = coverage.make_attempt(subject, original["record"],
            previous_record={"attempt_history": prefix}, at=original["attempt"]["last_attempted_at"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = self.recover(root / "parent", selection, [parent])
            child = self.authentic_batch(selection, 2, 2, previous=prior, status="error",
                reason="acquisition_failed", profile_id="static-extended-v3")
            original_child = child["workers"][0]["attempts"][0]["attempt"]
            self.assertEqual(len(original_child["history"]), 8)
            seeded = self.recover(root / "seeded", selection, [child])
            recovered = self.recover(root / "late", selection, [parent], seeded)
            value = recovered["records"][subject["id"]]
            self.assertEqual(value["findings"], original["record"]["findings"])
            self.assertEqual(recovered["attempts"][subject["id"]]["history"], original_child["history"])
            self.assertIn("recovery_predecessor_unavailable", coverage.reason_codes(value))
            self.assertEqual(value["retry"]["latest_status"], "error")


if __name__ == "__main__":
    unittest.main()
