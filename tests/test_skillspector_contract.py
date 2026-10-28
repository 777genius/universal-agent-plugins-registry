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


if __name__ == "__main__":
    unittest.main()
