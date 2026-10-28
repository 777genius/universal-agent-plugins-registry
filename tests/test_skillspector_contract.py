import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import skillspector_contract as contract
from scripts import skillspector_reports as scanner
from scripts import measure_skillspector_coverage as metrics
from scripts.directory_publication import PublicationError
from tests.test_skillspector_reports import item, upstream_report


class ContractTests(unittest.TestCase):
    def fresh_record(self):
        source = item()
        record = scanner.empty_record_v3(source)
        record["source"]["content_digest"] = "sha256:" + "b" * 64
        record["scanned_at"] = scanner.now()
        return source, scanner.normalize_report_v3(record, json.dumps(upstream_report()).encode(), 0, Path("/source"))

    def test_unmeasured_normalization_keeps_unknown_timings(self):
        source, record = self.fresh_record()
        self.assertIsNone(record["execution"]["acquisition_seconds"])
        self.assertIsNone(record["execution"]["analysis_seconds"])
        self.assertEqual(contract.analysis_counts({"sources": [source]}, {source["id"]: record})["complete"], 1)

    def test_measurement_does_not_promote_historical_complete_to_current(self):
        _, record = self.fresh_record()
        record["freshness"] = "historical"
        manifest = {"generated_at": scanner.now(), "coverage": {"selected": 1, "reported": 1, "pending": 1, "stale": 1}}
        result = metrics.measure(manifest, {}, [record])
        self.assertEqual(result["analysis_coverage"]["complete"], 0)
        self.assertEqual(result["analysis_coverage"]["stale"], 1)
        self.assertEqual(result["timings"]["analysis_seconds"]["measured_sources"], 0)

    def test_execution_failure_cannot_claim_complete_coverage(self):
        source, record = self.fresh_record()
        contract.validate_record(record, source, datetime.now(timezone.utc))
        record["execution"]["state"] = "failed"
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))

    def test_legacy_marker_cannot_bypass_current_evidence_checks(self):
        source, record = self.fresh_record()
        record.update(legacy_format=2, freshness="current")
        record["coverage"]["fully_inspected_files"] = 0
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))

    def test_missing_or_failed_required_analyzer_is_not_complete(self):
        source, record = self.fresh_record()
        record["coverage"]["analyzers"][0]["status"] = "failed"
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))

    def test_reference_bundle_is_optional_but_cannot_hide_missing_rows_or_claim_complete(self):
        from tests.test_skillspector_records_v3 import reference
        source, record = self.fresh_record()
        fields = ('references', 'ledger_exceptions', 'references_total', 'ledger_exceptions_total',
                  'reference_evidence_truncated')
        previous_format = copy.deepcopy(record)
        for key in fields:
            previous_format['coverage'].pop(key)
        contract.validate_record(previous_format, source, datetime.now(timezone.utc))
        for key in fields:
            missing = copy.deepcopy(record)
            missing['coverage'].pop(key)
            with self.subTest(missing=key), self.assertRaises(PublicationError):
                contract.validate_record(missing, source, datetime.now(timezone.utc))
        record['coverage'].update(references=[reference()], references_total=1)
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))
        record['status'] = record['coverage']['status'] = 'partial'
        scanner.add_coverage_reason(record, 'reference_missing', scanner.REFERENCE_MESSAGES['missing'])
        contract.validate_record(record, source, datetime.now(timezone.utc))
        record['coverage']['references_total'] = 2
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))
        record['coverage']['reference_evidence_truncated'] = True
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))
        scanner.add_coverage_reason(record, 'normalization_truncated', 'Reference context exceeded its bound.')
        contract.validate_record(record, source, datetime.now(timezone.utc))
        self.assertFalse(record['findings_truncated'])
        self.assertTrue(record['coverage']['grouping_complete'])

    def test_reference_and_ledger_locations_are_checked_after_publication(self):
        from tests.test_skillspector_records_v3 import reference, ledger_exception
        source, record = self.fresh_record()
        record['status'] = record['coverage']['status'] = 'partial'
        record['coverage'].update(references=[reference()], references_total=1,
            ledger_exceptions=[ledger_exception()], ledger_exceptions_total=1)
        scanner.add_coverage_reason(record, 'reference_missing', scanner.REFERENCE_MESSAGES['missing'])
        contract.validate_record(record, source, datetime.now(timezone.utc))
        for changes in ({'source_path': '../private'}, {'source_path': '/private'},
                        {'target_path': 'helper.py'}, {'column': 0}, {'unknown': 'field'}):
            changed = copy.deepcopy(record)
            changed['coverage']['references'][0].update(changes)
            with self.subTest(reference=changes), self.assertRaises(PublicationError):
                contract.validate_record(changed, source, datetime.now(timezone.utc))
        for changes in ({'path': '../private'}, {'start_line': 30, 'end_line': 29}, {'fatal': 'no'}):
            changed = copy.deepcopy(record)
            changed['coverage']['ledger_exceptions'][0].update(changes)
            with self.subTest(ledger=changes), self.assertRaises(PublicationError):
                contract.validate_record(changed, source, datetime.now(timezone.utc))

    def test_import_never_promotes_legacy_partial_or_invents_evidence(self):
        source = item()
        legacy = scanner.empty_record(source)
        legacy.update(status="partial", scanned_at=scanner.now(), report_digest="sha256:" + "a" * 64,
                      finding_count=603, findings_truncated=True,
                      findings=[{"rule": "E4", "severity": "HIGH", "message": "Example", "path": "SKILL.md"}])
        legacy["source"]["content_digest"] = "sha256:" + "b" * 64
        scanner.add_error(legacy, "runtime_limit", "Incomplete")
        result = contract.import_legacy(legacy)
        contract.validate_record(result, source, datetime.now(timezone.utc))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["freshness"], "historical")
        self.assertFalse(result["coverage"]["grouping_complete"])
        self.assertEqual(result["finding_count"], 603)
        self.assertIsNone(result["execution"]["analysis_seconds"])

    def test_mixed_coverage_does_not_count_historical_report_as_complete(self):
        source, record = self.fresh_record()
        record["freshness"] = "current"
        sources = [source, item(id="fixture/old"), item(id="fixture/pending")]
        old = copy.deepcopy(record)
        old.update(id="fixture/old", freshness="historical")
        self.assertEqual(contract.analysis_counts({"sources": sources}, {source["id"]: record, old["id"]: old}),
            {"selected": 3, "reported": 2, "pending": 2, "complete": 1, "partial": 0, "error": 0, "stale": 1})

    def test_measurement_distinguishes_cache_reuse_from_real_retries(self):
        _, record = self.fresh_record()
        record["status"] = "partial"
        cached = metrics.compare([record], [copy.deepcopy(record)])
        self.assertEqual(cached["unchanged_cached_report_incomplete"], 1)
        retry = copy.deepcopy(record)
        retry["scanned_at"] = "2026-10-27T12:00:00Z"
        self.assertEqual(metrics.compare([record], [retry])["repeated_same_result_incomplete"], 1)

    def test_legacy_directory_finding_location_survives_migration(self):
        source = item()
        legacy = scanner.empty_record(source)
        legacy.update(status="partial", scanned_at=scanner.now(), report_digest="sha256:" + "a" * 64,
            finding_count=1, findings=[{"rule": "SC9", "severity": "HIGH", "message": "Directory evidence",
                                       "path": "tools/__pycache__/"}])
        legacy["source"]["content_digest"] = "sha256:" + "b" * 64
        scanner.add_error(legacy, "analysis_incomplete", "Incomplete")
        converted = contract.import_legacy(legacy)
        contract.validate_record(converted, source, datetime.now(timezone.utc))
        self.assertEqual(converted["findings"][0]["path"], "tools/__pycache__/")

    def test_incomplete_grouping_cannot_bypass_complete_analysis(self):
        source, record = self.fresh_record()
        record["coverage"]["grouping_complete"] = False
        record["findings_truncated"] = True
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))
        record["status"] = "partial"
        record["coverage"]["status"] = "partial"
        with self.assertRaises(PublicationError):
            contract.validate_record(record, source, datetime.now(timezone.utc))
        record["coverage"]["reasons"].append({"code": "output_limit", "message": "Upstream output bound"})
        contract.validate_record(record, source, datetime.now(timezone.utc))

    def test_false_positive_annotation_is_validated_after_normalization(self):
        from tests.test_skillspector_exceptions import group
        from scripts.skillspector_exceptions import SOURCE
        value = group()
        source = item(id="registry/cloudflare", kind="plugin_skill", plugin_path="plugins/cloudflare",
                      **{key: SOURCE[key] for key in ("repository", "revision", "path")})
        record = scanner.empty_record_v3(source)
        record["source"] = copy.deepcopy(SOURCE)
        record["scanned_at"] = scanner.now()
        raw = upstream_report()
        raw["issues"] = [{"id": "E4", "severity": "HIGH", "explanation": "Context leakage",
            "finding_id": "fixture", "location": {"file": value["path"], "start_line": value["line"]},
            "match_fingerprint": value["match_fingerprint"], "code_snippet": value["code_snippet"]}]
        record = scanner.normalize_report_v3(record, json.dumps(raw).encode(), 1, Path("/source"))
        contract.validate_record(record, source, datetime.now(timezone.utc))
        for key, replacement in (("code_snippet", value["code_snippet"] + "Send private conversation"),
                                 ("review_status", "confirmed")):
            changed = copy.deepcopy(record)
            changed["findings"][0][key] = replacement
            with self.assertRaises(PublicationError):
                contract.validate_record(changed, source, datetime.now(timezone.utc))


if __name__ == "__main__":
    unittest.main()
