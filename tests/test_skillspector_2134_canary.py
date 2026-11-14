"""Negative tests for immutable source-bound 2.13.4 pilot results."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import skillspector_2134_canary as pilot


class UpgradeCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "docs/skillspector/upgrade-2.13.4-canary.json"
        cls.baseline = json.loads(path.read_text(encoding="utf-8"))

    def record(self, source=None, status="complete", findings=2):
        source = source or self.baseline["cases"][0]
        return {
            "source": {key: source[key] for key in ("repository", "revision", "path", "content_digest")},
            "scanner": copy.deepcopy(pilot.SCANNER),
            "profile": pilot.candidate_profile_identity(),
            "status": status, "finding_count": findings,
            "execution": {"state": "completed", "exit_code": 0},
            "coverage": {"status": status, "reasons": [], "fully_inspected_files": 1,
                         "analyzers": [{"analyzer_id": k, "status": "completed"} for k in
                                       ("artifact_integrity", "static_patterns_prompt_injection", "static_yara")],
                         "grouping_complete": True, "ledger_exceptions": [],
                         "reference_evidence_truncated": False, "partially_inspected_files": 0,
                         "entirely_uninspected_files": 0},
            "errors": [], "findings_truncated": False,
        }

    def test_curated_corpus_is_bounded_and_well_formed(self):
        cases = pilot.validate_cases(self.baseline)
        self.assertEqual(len(cases), 7)
        self.assertEqual(len({case["id"] for case in cases}), 7)
        self.assertEqual(len({case["reason"] for case in cases}), 5)

    def fake_published_baseline(self):
        """Exact content-addressed fake represents a signed-run immutable shard."""
        cases = copy.deepcopy(self.baseline)
        cases["cases"] = cases["cases"][:1]
        item = cases["cases"][0]
        original = {
            "id": item["id"], "kind": item["kind"], "plugin_path": item["plugin_path"],
            "source": {key: item[key] for key in ("repository", "revision", "path", "content_digest")},
            "status": "partial", "freshness": "current", "finding_count": item["finding_count"],
            "scanner": {"id": "skillspector", "version": "2.13.1"},
            "retry": {"reason": item["reason"]}, "findings": [], "report_digest": "sha256:" + "1" * 64,
            "finding_group_count": 0, "findings_truncated": False,
            "coverage": {"grouping_complete": True, "original_findings": []},
        }
        shard_data = {"schema_version": 3, "repository": item["repository"], "records": [original]}
        shard_bytes = (json.dumps(shard_data, sort_keys=True, separators=(",", ":")) + "\n").encode()
        shard_digest = "sha256:" + hashlib.sha256(shard_bytes).hexdigest()
        path = "shards/" + shard_digest[7:] + ".json"
        manifest = {"schema_version": 3, "source_commit": "a" * 40,
                    "shards": [{"path": path, "digest": shard_digest, "repository": item["repository"],
                                "bytes": len(shard_bytes), "record_count": 1}]}
        index_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        cases["manifest_digest"] = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
        blobs = {"index.json": index_bytes, path: shard_bytes}
        return cases, blobs

    def test_baseline_reads_and_checks_original_publication_digest(self):
        cases, blobs = self.fake_published_baseline()
        proof = pilot.verify_published_baseline(cases, fetcher=lambda path, _: blobs[path])
        self.assertEqual(len(proof), 1)
        self.assertEqual(proof[0]["original_report_digest"], "sha256:" + "1" * 64)
        self.assertEqual(proof[0]["original_finding_group_count"], 0)
        self.assertTrue(proof[0]["original_findings_sha256"].startswith("sha256:"))

    def test_baseline_tamper_or_replay_is_rejected(self):
        cases, blobs = self.fake_published_baseline()
        cases_bad = copy.deepcopy(cases)
        cases_bad["manifest_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "manifest SHA-256"):
            pilot.verify_published_baseline(cases_bad, fetcher=lambda path, _: blobs[path])
        bad_fixture = copy.deepcopy(cases)
        bad_fixture["cases"][0]["finding_count"] += 1
        with self.assertRaisesRegex(ValueError, "identical"):
            pilot.verify_published_baseline(bad_fixture, fetcher=lambda path, _: blobs[path])
        poisoned = dict(blobs)
        key = next(p for p in blobs if p != "index.json")
        poisoned[key] = blobs[key] + b" "
        with self.assertRaisesRegex(ValueError, "immutable digest"):
            pilot.verify_published_baseline(cases, fetcher=lambda path, _: poisoned[path])
        drifted = copy.deepcopy(cases)
        drifted["cases"][0]["revision"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "identical"):
            pilot.verify_published_baseline(drifted, fetcher=lambda path, _: blobs[path])

    def test_nonportable_or_untrusted_source_rejected(self):
        for changed in ({"path": "../SKILL.md"}, {"revision": "main"}, {"repository": "https://bad.example/a"},
                        {"content_digest": "sha256:" + "0" * 63}, {"status": "complete"}, {"reason": "unreviewed"}):
            with self.subTest(changed=changed):
                cases = copy.deepcopy(self.baseline)
                cases["cases"][0].update(changed)
                with self.assertRaises(ValueError):
                    pilot.validate_cases(cases)

    def test_duplicate_source_rejected(self):
        cases = copy.deepcopy(self.baseline)
        cases["cases"][1]["id"] = cases["cases"][0]["id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pilot.validate_cases(cases)

    def test_complete_is_not_automatically_authorized(self):
        old = self.baseline["cases"][0]
        result = pilot.compare(old, self.record(old, findings=5))
        self.assertTrue(result["candidate_complete"])
        self.assertTrue(result["manual_finding_review_required"])
        self.assertFalse(result["fewer_findings"])
        self.assertEqual(result["old_reason"], "reference_missing")

    def test_decreased_findings_requires_review_even_if_complete(self):
        old = self.baseline["cases"][1]
        result = pilot.compare(old, self.record(old, findings=0))
        self.assertTrue(result["candidate_complete"])
        self.assertTrue(result["fewer_findings"])
        self.assertTrue(result["manual_finding_review_required"])

    def test_source_replay_or_upgrade_identity_mismatch_fails(self):
        old = self.baseline["cases"][0]
        for patch in ({"content_digest": "sha256:" + "0" * 64}, {"revision": "a" * 40}):
            with self.subTest(patch=patch):
                record = self.record(old)
                record["source"].update(patch)
                with self.assertRaisesRegex(ValueError, "immutable baseline"):
                    pilot.compare(old, record)
        record = self.record(old)
        record["scanner"]["version"] = "2.13.1"
        with self.assertRaisesRegex(ValueError, "identity"):
            pilot.compare(old, record)

    def test_unpatched_candidate_profile_identity_is_mandatory(self):
        old = self.baseline["cases"][0]
        expected = pilot.candidate_profile_identity()
        self.assertEqual(expected["id"], "static-standard-v3")
        for changed in ({"digest": "sha256:" + "f" * 64},
                        {"id": "static-extended-v3"}):
            record = self.record(old)
            record["profile"].update(changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "candidate profile identity"):
                pilot.compare(old, record)

    def test_false_complete_fails_closed(self):
        old = self.baseline["cases"][0]
        mutations = [
            lambda r: r["coverage"].update(status="partial"),
            lambda r: r["coverage"].update(fully_inspected_files=0),
            lambda r: r["coverage"].update(grouping_complete=False),
            lambda r: r["coverage"].update(ledger_exceptions=[{"reason_code": "missing"}]),
            lambda r: r["execution"].update(state="failed"),
            lambda r: r["coverage"].update(reasons=[{"code": "reference_missing"}]),
            lambda r: r.update(errors=[{"code": "runtime_limit"}]),
            lambda r: r["coverage"].update(partially_inspected_files=1),
            lambda r: r["coverage"].update(entirely_uninspected_files=1),
            lambda r: r.update(findings_truncated=True),
            lambda r: r["coverage"].update(analyzers=[]),
            lambda r: r["coverage"]["analyzers"][0].update(status="partial"),
            lambda r: r["execution"].update(exit_code=137),
        ]
        for mutate in mutations:
            record = self.record(old)
            mutate(record)
            with self.subTest(record=record), self.assertRaisesRegex(ValueError, "complete evidence"):
                pilot.compare(old, record)

    def test_deduplicated_security_occurrences_keep_raw_count(self):
        record = self.record(findings=2)
        record.update(finding_group_count=1, findings=[{
            "id": "sha256:" + "a" * 64, "rule": "AE99", "severity": "HIGH",
            "path": "SKILL.md", "raw_count": 2,
            # The real v3 normalizer deduplicates positions across detections.
            "occurrences": [{"path": "SKILL.md", "line": 12}],
        }])
        original = pilot.finding_group_evidence(record)
        self.assertTrue(original["grouping_complete"])
        self.assertEqual(original["groups"][0]["raw_count"], 2)
        self.assertEqual(original["groups"][0]["occurrence_count"], 1)
        record["findings"][0]["occurrences"] = []
        with self.assertRaisesRegex(ValueError, "invalid or duplicate"):
            pilot.finding_group_evidence(record)
        record["findings"][0]["occurrences"] = [
            {"line": 1}, {"line": 2}, {"line": 3},
        ]
        with self.assertRaisesRegex(ValueError, "invalid or duplicate"):
            pilot.finding_group_evidence(record)

    def test_interrupted_canary_receipt_retains_evidence_but_never_qualifies(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "proof.json"
            cases = {"source_report_commit": "a" * 40,
                     "cases": [{"id": "source-1"}, {"id": "source-2"}]}
            evidence = [{"original_finding_groups": {"groups": ["original"]}},
                        {"original_finding_groups": {"groups": ["second"]}}]
            completed = [{"id": "source-1", "new_status": "partial",
                          "candidate_record": {"findings": [{"evidence": "visible"}]}}]
            checkpoint = pilot.measurement_receipt(cases, evidence, completed, finished=False)
            pilot.persist_receipt(output, checkpoint)
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(persisted["measurement_finished"])
            self.assertFalse(persisted["safe_for_automatic_publication"])
            self.assertEqual(persisted["cases_completed"], 1)
            self.assertEqual(persisted["cases_expected"], 2)
            self.assertEqual(persisted["results"][0]["candidate_record"]["findings"][0]["evidence"], "visible")
            self.assertFalse(output.with_name("proof.json.tmp").exists())
            with self.assertRaisesRegex(ValueError, "incomplete or out-of-order"):
                pilot.measurement_receipt(cases, evidence, completed, finished=True)
            second = {"id": "source-2", "new_status": "partial",
                      "candidate_record": {"findings": []}}
            complete = pilot.measurement_receipt(cases, evidence, [completed[0], second], finished=True)
            pilot.persist_receipt(output, complete)
            final = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(final["measurement_finished"])
            self.assertFalse(final["safe_for_automatic_publication"])
            self.assertEqual(final["cases_completed"], 2)

    def test_security_group_identity_loss_even_with_unchanged_count(self):
        original = self.record()
        a = {"id": "sha256:" + "a" * 64, "rule": "S1", "severity": "HIGH", "path": "SKILL.md"}
        b = {"id": "sha256:" + "b" * 64, "rule": "S2", "severity": "LOW", "path": "src.py"}
        c = {"id": "sha256:" + "c" * 64, "rule": "S3", "severity": "LOW", "path": "SKILL.md"}
        for group in (a, b, c):
            group.update(raw_count=1, occurrences=[{"path": group["path"], "line": 1}])
        original.update(finding_group_count=2, findings=[a, b])
        original["coverage"]["original_findings"] = [{"id": "AE1", "reason": "missing"}]
        bound = {"original_finding_groups": pilot.finding_group_evidence(original)}
        candidate = copy.deepcopy(original)
        candidate["findings"] = [b, c]  # Same total; a HIGH finding vanished.
        difference = pilot.finding_group_delta(bound, candidate)
        self.assertEqual(difference["old_group_count"], difference["new_group_count"])
        self.assertEqual(difference["old_groups_not_in_candidate"], [a["id"]])
        self.assertEqual(difference["candidate_groups_not_in_old"], [c["id"]])
        self.assertFalse(difference["eligible_for_no_loss_assertion"])
        self.assertTrue(difference["independent_review_required"])

    def test_group_delta_refuses_incomplete_or_changed_coverage_evidence(self):
        original = self.record()
        group = {"id": "sha256:" + "a" * 64, "rule": "SC1", "severity": "CRITICAL", "path": "SKILL.md",
                 "raw_count": 1, "occurrences": [{"path": "SKILL.md", "line": 3}]}
        original.update(finding_group_count=1, finding_count=1, findings=[group])
        original["coverage"]["original_findings"] = [{"id": "AE1"}]
        bound = {"original_finding_groups": pilot.finding_group_evidence(original)}
        unchanged = pilot.finding_group_delta(bound, copy.deepcopy(original))
        self.assertTrue(unchanged["eligible_for_no_loss_assertion"])
        changed = copy.deepcopy(original)
        changed["coverage"]["original_findings"] = []
        delta = pilot.finding_group_delta(bound, changed)
        self.assertTrue(delta["coverage_findings_digest_changed"])
        self.assertFalse(delta["eligible_for_no_loss_assertion"])
        changed["coverage"]["original_findings"] = original["coverage"]["original_findings"]
        changed["coverage"]["grouping_complete"] = False
        self.assertFalse(pilot.finding_group_delta(bound, changed)["eligible_for_no_loss_assertion"])

    def test_group_id_match_must_not_hide_missing_occurrence(self):
        original = self.record()
        group = {"id": "sha256:" + "b" * 64, "rule": "S1", "severity": "HIGH",
                 "path": "SKILL.md", "raw_count": 2,
                 "occurrences": [{"path": "SKILL.md", "line": 5},
                                 {"path": "SKILL.md", "line": 9}]}
        original.update(finding_group_count=1, findings=[group])
        bound = {"original_finding_groups": pilot.finding_group_evidence(original)}
        changed = copy.deepcopy(original)
        changed["findings"][0]["occurrences"].pop()
        changed["findings"][0]["raw_count"] = 1
        changed["finding_count"] = 1
        delta = pilot.finding_group_delta(bound, changed)
        self.assertEqual(delta["old_groups_not_in_candidate"], [])
        self.assertEqual(delta["matching_ids_with_changed_occurrences_or_evidence"],
                         [group["id"]])
        self.assertFalse(delta["eligible_for_no_loss_assertion"])

    def test_finding_occurrence_accounting_fails_closed(self):
        record = self.record()
        group = {"id": "sha256:" + "c" * 64, "rule": "S1", "severity": "HIGH",
                 "path": "SKILL.md", "raw_count": 2,
                 "occurrences": [{"path": "SKILL.md", "line": 5},
                                 {"path": "SKILL.md", "line": 9}]}
        record.update(finding_group_count=1, finding_count=2, findings=[group])
        self.assertEqual(pilot.finding_group_evidence(record)["group_count"], 1)
        missing_occurrence = copy.deepcopy(record)
        missing_occurrence["findings"][0]["occurrences"].pop()
        with self.assertRaisesRegex(ValueError, "normalized security finding group"):
            pilot.finding_group_evidence(missing_occurrence)
        missing_total = copy.deepcopy(record)
        missing_total["finding_count"] = 1
        with self.assertRaisesRegex(ValueError, "count contradicts"):
            pilot.finding_group_evidence(missing_total)
        zero_group = copy.deepcopy(record)
        zero_group["findings"][0].update(raw_count=0, occurrences=[])
        with self.assertRaisesRegex(ValueError, "normalized security finding group"):
            pilot.finding_group_evidence(zero_group)

    def test_malformed_group_identity_or_incomplete_enumeration_rejected(self):
        original = self.record()
        original.update(finding_group_count=1, findings=[])
        with self.assertRaisesRegex(ValueError, "enumeration"):
            pilot.finding_group_evidence(original)
        a = {"id": "sha256:" + "a" * 64, "rule": "SC1", "severity": "HIGH", "path": "SKILL.md",
             "raw_count": 1, "occurrences": [{"path": "SKILL.md", "line": 3}]}
        original.update(finding_group_count=2, findings=[a, copy.deepcopy(a)])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pilot.finding_group_evidence(original)

    def test_unpatched_canary_profile_is_not_mislabeled_as_production_patch(self):
        source = {"id": "static-standard-v3", "reference_inventory_patch": "uap-directory-inventory-url-host-v2"}
        candidate = pilot.candidate_profile(source)
        self.assertNotIn("reference_inventory_patch", candidate)
        self.assertEqual(candidate["reference_analyzer_semantics"], "unmodified-upstream-2.13.4")
        self.assertEqual(candidate["upgrade_canary_scanner_revision"], pilot.SCANNER["revision"])
        self.assertEqual(source["reference_inventory_patch"], "uap-directory-inventory-url-host-v2")

    def test_partial_remains_partial(self):
        old = self.baseline["cases"][0]
        record = self.record(old, status="partial")
        record["coverage"]["reasons"] = [{"code": "reference_missing"}]
        result = pilot.compare(old, record)
        self.assertFalse(result["candidate_complete"])
        self.assertEqual(result["coverage_reasons"], ["reference_missing"])
        self.assertTrue(result["manual_finding_review_required"])


    def test_normalization_failure_probe_preserves_exception_without_raw_leak(self):
        secret = "a sensitive source excerpt"
        capture = {}

        def failing_normalizer():
            raise ValueError(secret)

        wrapped = pilot.probe_normalization(failing_normalizer, capture)
        with self.assertRaisesRegex(ValueError, secret):
            wrapped()
        self.assertEqual(capture["stage"], "normalize_report_v3")
        self.assertEqual(capture["exception_type"], "ValueError")
        self.assertEqual(
            capture["message_sha256"],
            "sha256:" + hashlib.sha256(secret.encode()).hexdigest(),
        )
        self.assertNotIn(secret, json.dumps(capture))
        self.assertEqual(pilot.probe_normalization(lambda x: x + 1, {})(2), 3)


    def test_ephemeral_finding_id_drift_is_distinct_from_security_evidence_change(self):
        group_id = "sha256:" + "f" * 64
        old_id = "finding-" + "1" * 32
        new_id = "finding-" + "2" * 32
        original = self.record(findings=1)
        group = {
            "id": group_id, "rule": "RP1", "severity": "MEDIUM",
            "path": "SKILL.md", "raw_count": 1,
            "finding_ids": [old_id],
            "occurrences": [{"path": "SKILL.md", "line": 5, "finding_id": old_id}],
            "evidence": {"risk": "retained"},
        }
        original.update(finding_group_count=1, findings=[group])
        original["coverage"]["original_findings"] = []
        baseline = {"original_finding_groups": pilot.finding_group_evidence(original)}

        candidate = copy.deepcopy(original)
        candidate["findings"][0]["finding_ids"] = [new_id]
        candidate["findings"][0]["occurrences"][0]["finding_id"] = new_id
        delta = pilot.finding_group_delta(baseline, candidate)
        self.assertEqual(delta["matching_ids_with_only_generated_id_drift"], [group_id])
        self.assertEqual(delta["matching_ids_with_semantic_evidence_change"], [])
        # A diagnostic alone never authorizes a Complete promotion.
        self.assertFalse(delta["eligible_for_no_loss_assertion"])

        candidate["findings"][0]["occurrences"][0]["line"] = 6
        delta = pilot.finding_group_delta(baseline, candidate)
        self.assertEqual(delta["matching_ids_with_semantic_evidence_change"], [group_id])
        self.assertEqual(delta["matching_ids_with_only_generated_id_drift"], [])

        candidate = copy.deepcopy(original)
        candidate["findings"][0]["evidence"]["risk"] = "lost"
        delta = pilot.finding_group_delta(baseline, candidate)
        self.assertEqual(delta["matching_ids_with_semantic_evidence_change"], [group_id])

    def test_unrecognized_finding_id_is_not_silently_discarded(self):
        group = {"rule": "SC1", "finding_ids": ["custom-id"],
                 "occurrences": [{"finding_id": "custom-id", "line": 1}]}
        changed = copy.deepcopy(group)
        changed["finding_ids"] = ["other-id"]
        changed["occurrences"][0]["finding_id"] = "other-id"
        self.assertNotEqual(pilot.semantic_group_digest(group),
                            pilot.semantic_group_digest(changed))


    def test_unexpected_ledger_probe_reports_only_bounded_key_names(self):
        body = json.dumps({"analysis_completeness": {"ledger_exceptions": [
            {"reason_code": "static_parse_limit",
             "parser_diagnostic": {"source_path": "PRIVATE-DO-NOT-LOG"},
             "observed_records": 200, "path": "PRIVATE-DO-NOT-LOG"},
            {"limit_records": 100, "PRIVATE-KEY-NAME!": "PRIVATE-DO-NOT-LOG"},
        ]}}).encode()
        result = pilot.unexpected_ledger_key_probe(body)
        self.assertEqual(result["unexpected_ledger_field_count"], 4)
        self.assertEqual(result["unexpected_ledger_fields"], [
            "[unsafe-key]", "limit_records", "observed_records", "parser_diagnostic"])
        self.assertNotIn("PRIVATE-DO-NOT-LOG", json.dumps(result))
        self.assertEqual(pilot.unexpected_ledger_key_probe(b"not-json"),
                         {"schema_probe": "unavailable"})

    def test_probed_ledger_failure_still_propagates_original_exception(self):
        capture = {}
        report = json.dumps({"analysis_completeness": {"ledger_exceptions": [
            {"reason_code": "static_parse_limit", "observed_records": 43},
        ]}}).encode()
        def fails(record, body, code, root):
            raise ValueError("SkillSpector ledger fields are invalid")
        with self.assertRaisesRegex(ValueError, "ledger fields"):
            pilot.probe_normalization(fails, capture)({}, report, 1, None)
        self.assertEqual(capture["unexpected_ledger_fields"], ["observed_records"])
        self.assertEqual(capture["exception_type"], "ValueError")


    def test_exact_2134_parser_diagnostic_accepts_only_typed_bounded_metadata(self):
        parser = {
            "cause": "resource_limit", "check": "command_word_boundary",
            "source_start_offset": 0, "source_end_offset": 8,
            "start_line": 1, "end_line": 1, "unchecked_scope": "command_word",
            "observed_is_lower_bound": True, "full_input_checked": False,
            "location_precision": "source_span",
            "observed_characters": 128, "limit_characters": 64,
        }
        report = {"analysis_completeness": {"ledger_exceptions": [
            {"reason_code": "static_parse_limit", "parser_diagnostic": parser},
        ]}}
        payload = lambda value: json.dumps(value).encode()
        self.assertEqual(pilot.validate_2134_parser_diagnostics(payload(report)), 1)
        mutations = [
            lambda v: v["analysis_completeness"]["ledger_exceptions"][0]["parser_diagnostic"].update(
                source_end_offset=0),
            lambda v: v["analysis_completeness"]["ledger_exceptions"][0]["parser_diagnostic"].update(
                check="unknown_attacker_check"),
            lambda v: v["analysis_completeness"]["ledger_exceptions"][0]["parser_diagnostic"].update(
                check=[]),
            lambda v: v["analysis_completeness"]["ledger_exceptions"][0]["parser_diagnostic"].update(
                observed_characters=-1),
            lambda v: v["analysis_completeness"]["ledger_exceptions"][0]["parser_diagnostic"].update(
                full_input_checked="yes"),
            lambda v: v["analysis_completeness"]["ledger_exceptions"][0]["parser_diagnostic"].update(
                untrusted_source_text="secret"),
        ]
        for mutate in mutations:
            malformed = copy.deepcopy(report)
            mutate(malformed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                pilot.validate_2134_parser_diagnostics(payload(malformed))

    def test_readonly_parser_adapter_restores_production_fields_on_both_paths(self):
        from scripts import skillspector_reports as scanner
        old_fields = scanner.LEDGER_FIELDS
        report = {"analysis_completeness": {"ledger_exceptions": []}}
        def inner(record, body, code, root):
            self.assertIn("parser_diagnostic", scanner.LEDGER_FIELDS)
            return {"qualifying": True}
        result = pilot.normalize_readonly_2134_ledger(
            inner, {"scanner": copy.deepcopy(pilot.SCANNER)}, json.dumps(report).encode(), 0, None)
        self.assertEqual(result, {"qualifying": True})
        self.assertEqual(scanner.LEDGER_FIELDS, old_fields)
        def failure(*_args):
            raise ValueError("original failure")
        with self.assertRaisesRegex(ValueError, "original failure"):
            pilot.normalize_readonly_2134_ledger(
                failure, {"scanner": copy.deepcopy(pilot.SCANNER)}, json.dumps(report).encode(), 0, None)
        self.assertEqual(scanner.LEDGER_FIELDS, old_fields)
        with self.assertRaisesRegex(ValueError, "identity differs"):
            pilot.normalize_readonly_2134_ledger(
                inner, {"scanner": {"version": "unknown"}}, json.dumps(report).encode(), 0, None)
        self.assertEqual(scanner.LEDGER_FIELDS, old_fields)


if __name__ == "__main__":
    unittest.main()
