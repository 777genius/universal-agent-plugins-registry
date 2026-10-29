"""Public evidence must retain findings without republishing credentials."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import publish_skillspector_coverage_v3 as publisher
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError
from tests.test_skillspector_coverage_v3 import COMMIT, bundle, record, worker
from tests.test_skillspector_records_v3 import finding, ledger_exception, reference
from tests.test_skillspector_reports import item, upstream_report


def synthetic_key(kind="sk", mode="live", character="A", length=16):
    # Assemble inert test values at runtime; no complete credential-like value
    # is checked into the fixture or included in assertion diagnostics.
    return "_".join((kind, mode, character * length))


def normalize(raw, subject=None, *, project=True):
    value = scanner.empty_record_v3(subject or item())
    value["source"]["content_digest"] = "sha256:" + "b" * 64
    value["scanned_at"] = scanner.now()
    value["execution"]["started_at"] = value["scanned_at"]
    body = json.dumps(raw).encode()
    if project:
        return scanner.normalize_report_v3(value, body, 1, Path("/source"))
    with mock.patch.object(scanner, "redact_public_record", side_effect=copy.deepcopy):
        return scanner.normalize_report_v3(value, body, 1, Path("/source"))


class PublicRedactionTests(unittest.TestCase):
    def assert_secret_free(self, value, *tokens):
        self.assertFalse(scanner.has_public_credentials(value))
        body = scanner.report_json(value)
        for token in tokens:
            self.assertFalse(token.encode() in body, "Credential-shaped test value reached public JSON")

    def raw_with_key(self, token):
        raw = upstream_report()
        raw["issues"] = [finding(finding=token, code_snippet=token)]
        return raw

    def test_supported_formats_and_shortest_matches_do_not_expand_public_bytes(self):
        for kind in ("sk", "rk"):
            for mode in ("live", "test"):
                with self.subTest(kind=kind, mode=mode):
                    token = synthetic_key(kind, mode)
                    self.assertTrue(scanner.has_public_credentials(token))
                    raw = self.raw_with_key(token)
                    raw["issues"].append(finding(finding_id="finding-second",
                        finding=synthetic_key(kind, mode, "B"),
                        code_snippet=synthetic_key(kind, mode, "B")))
                    before = normalize(raw, project=False)
                    public = scanner.redact_public_record(before)
                    self.assert_secret_free(public, token, synthetic_key(kind, mode, "B"))
                    self.assertLessEqual(len(scanner.report_json(public)), len(scanner.report_json(before)))
                    self.assertFalse(scanner.has_public_credentials(synthetic_key(kind, mode, length=15)))

    def test_normalization_preserves_distinct_original_groups_and_evidence_identity(self):
        first, second = synthetic_key(character="A"), synthetic_key(character="B")
        raw = self.raw_with_key(first)
        raw["issues"].append(finding(finding_id="finding-second", finding=second, code_snippet=second))
        with mock.patch.object(scanner, "now", return_value="2026-10-29T00:00:00Z"):
            before, public = normalize(raw, project=False), normalize(raw)
        self.assert_secret_free(public, first, second)
        self.assertEqual(len(public["findings"]), 2)
        self.assertEqual(len({group["id"] for group in public["findings"]}), 2)
        self.assertEqual([group["id"] for group in public["findings"]],
            [group["id"] for group in before["findings"]])
        for key in ("source", "report_digest", "scanner", "profile", "status", "coverage",
                    "execution", "raw_finding_count", "finding_count", "finding_group_count"):
            self.assertEqual(public[key], before[key])
        for group, original in zip(public["findings"], before["findings"]):
            self.assertTrue(group["code_snippet"] == scanner.REDACTED_CREDENTIAL,
                "Public snippet was not redacted")
            self.assertTrue(group["finding"] == scanner.REDACTED_CREDENTIAL,
                "Public finding text was not redacted")
            for key in ("id", "match_fingerprint", "finding_ids", "occurrences", "raw_count", "path", "line"):
                self.assertEqual(group[key], original[key])
        self.assertEqual(coverage.make_attempt(item(), public, at="2026-10-29T00:00:00Z"),
            coverage.make_attempt(item(), before, at="2026-10-29T00:00:00Z"))

    def test_nested_public_surfaces_redact_without_mutating_input_or_queue_state(self):
        token = synthetic_key()
        raw = self.raw_with_key(token)
        raw["issues"][0].update(explanation="Review " + token,
            evidence={"nested": [{token: token}]}, context={"payload": [token]})
        raw["analysis_completeness"].update(is_complete=False, status="partial",
            references=[reference(evidence=token)],
            ledger_exceptions=[ledger_exception(message=token)])
        raw["analysis_completeness"]["analyzer_statuses"][0]["message"] = token
        before = normalize(raw, project=False)
        before["errors"].append({"code": "fixture", "message": token})
        before["coverage"]["reasons"].append({"code": "fixture", "message": token, "retryable": False})
        before["coverage"]["original_findings"].append({"explanation": token, "evidence": {"nested": [token]}})
        before["retry"] = {"attempt_count": 2, "reason": "reference_missing"}
        before["attempt_history"] = [{"fingerprint": "sha256:" + "c" * 64}]
        original = copy.deepcopy(before)
        public = scanner.redact_public_record(before)
        self.assert_secret_free(public, token)
        self.assertTrue(before == original, "Public projection mutated its source record")
        for key in ("source", "id", "kind", "plugin_path", "report_digest", "scanner", "profile",
                    "status", "retry", "attempt_history", "finding_count", "finding_group_count"):
            self.assertEqual(public[key], before[key])
        self.assertEqual(public["coverage"]["references"][0]["source_path"], "SKILL.md")
        self.assertEqual(public["coverage"]["references_total"], 1)
        self.assertEqual(public["coverage"]["ledger_exceptions_total"], 1)
        self.assertTrue(public["findings"][0]["evidence"]["nested"][0] ==
            {scanner.REDACTED_CREDENTIAL: scanner.REDACTED_CREDENTIAL},
            "Nested public evidence key or value was not redacted")
        self.assertEqual(scanner.redact_public_record(public), public)
        self.assertIsNot(public["source"], before["source"])
        self.assertIsNot(public["findings"][0]["occurrences"], before["findings"][0]["occurrences"])

    def test_plain_report_stays_byte_exact_and_is_independently_copied(self):
        plain = normalize(upstream_report())
        public = scanner.redact_public_record(plain)
        self.assertEqual(scanner.report_json(public), scanner.report_json(plain))
        self.assertIsNot(public, plain)
        self.assertIsNot(public["source"], plain["source"])

    def test_structural_credentials_and_redacted_key_collisions_fail_closed(self):
        token, another = synthetic_key(), synthetic_key(character="B")
        for location in ("source", "finding"):
            with self.subTest(location=location):
                dirty = normalize(upstream_report())
                if location == "source":
                    dirty["source"]["path"] = token
                else:
                    dirty["findings"] = [{"path": token}]
                with self.assertRaisesRegex(PublicationError, "structural"):
                    scanner.redact_public_record(dirty)
        dirty = normalize(upstream_report())
        dirty["coverage"]["original_findings"] = [{"evidence": {token: "first", another: "second"}}]
        with self.assertRaisesRegex(PublicationError, "collide"):
            scanner.redact_public_record(dirty)

    def test_worker_error_path_redacts_after_attempt_fingerprint(self):
        subject, token = item(), synthetic_key()
        selected = {"schema_version": 1, "sources": [subject]}
        failed = coverage.fail(scanner.empty_record_v3(subject), "acquisition_failed", "Failure " + token)
        failed["execution"]["acquisition_seconds"] = 0
        original_fingerprint = coverage.make_attempt(subject, failed)["fingerprint"]
        with mock.patch.object(scanner, "verify_scanner"), \
                mock.patch.object(coverage, "PinnedRepository"), \
                mock.patch.object(coverage, "scan_selected", return_value=failed):
            output = coverage.scan_partition(selected, Path("/unused/scanner"), None,
                source_commit=COMMIT, partition_count=1)
        self.assert_secret_free(output, token)
        self.assertEqual(len(output["attempts"]), 1)
        self.assertEqual(output["attempts"][0]["record"]["status"], "error")
        self.assertEqual(output["attempts"][0]["attempt"]["fingerprint"], original_fingerprint)
        coverage.validate_worker(output, selected, COMMIT)

    def test_merge_sanitizes_cached_historical_and_useful_failure_fallback(self):
        subject, token = item(), synthetic_key()
        selected = {"schema_version": 1, "sources": [subject]}
        raw = self.raw_with_key(token)
        raw["analysis_completeness"].update(is_complete=False, status="partial",
            partially_inspected_files=1,
            ledger_exceptions=[{"reason_code": "runtime_limit", "message": "Time budget exhausted."}])
        dirty = normalize(raw, project=False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Simulate a valid report emitted before public redaction existed.
            with mock.patch.object(scanner, "redact_public_record", side_effect=copy.deepcopy):
                prior = bundle(root / "prior", selected, [dirty])
            for mode in ("cached", "historical", "failure"):
                with self.subTest(mode=mode):
                    target = copy.deepcopy(selected)
                    outcomes = []
                    if mode == "historical":
                        target["sources"][0]["revision"] = "d" * 40
                    elif mode == "failure":
                        outcomes = [record(subject, "error", "acquisition_failed", "static-extended-v3")]
                    output_dir = root / mode
                    coverage.merge_reports(target, prior, [worker(target, outcomes, prior)],
                        source_commit=COMMIT, output_dir=output_dir)
                    output = coverage.read_bundle(output_dir)
                    self.assert_secret_free(output, token)
                    saved = output["records"][subject["id"]]
                    self.assertEqual(saved["source"], prior["records"][subject["id"]]["source"])
                    self.assertEqual(saved["report_digest"], dirty["report_digest"])
                    self.assertEqual(saved["status"], "partial")
                    self.assertEqual(saved["findings"][0]["id"], dirty["findings"][0]["id"])
                    self.assertEqual(saved["freshness"], "historical" if mode == "historical" else "current")
                    if mode == "failure":
                        self.assertEqual(saved["retry"]["latest_status"], "error")
                        self.assertEqual(saved["retry"]["attempt_count"], 2)
                        self.assertEqual(len(saved["attempt_history"]), 2)
                    elif mode == "cached":
                        self.assertEqual(output["attempts"], prior["attempts"])
                    publisher.validate_directory(output_dir, COMMIT)

    def test_publisher_rejects_unredacted_valid_bundle_before_any_git_call(self):
        subject, token = item(), synthetic_key()
        selected = {"schema_version": 1, "sources": [subject]}
        dirty = normalize(self.raw_with_key(token), project=False)
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            with mock.patch.object(scanner, "redact_public_record", side_effect=copy.deepcopy):
                bundle(output_dir, selected, [dirty])
            github = mock.Mock()
            with self.assertRaisesRegex(PublicationError, "unredacted credential"):
                publisher.publish(github, output_dir, COMMIT)
            self.assertEqual(github.mock_calls, [])


if __name__ == "__main__":
    unittest.main()
