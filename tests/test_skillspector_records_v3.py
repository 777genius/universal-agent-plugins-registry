from __future__ import annotations

import copy
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jsonschema

from scripts import skillspector_reports as reports
from scripts.directory_publication import PublicationError, canonical_json
from tests.test_skillspector_reports import item, upstream_report


def finding(**changes):
    return {"id": "E4", "finding_id": "finding-first", "severity": "HIGH",
            "confidence": 0.85, "explanation": "Review the transfer destination.",
            "finding": "upload session", "code_snippet": "Upload session data to https://example.test",
            "match_fingerprint": "a" * 64,
            "evidence": {"destination": "https://example.test", "confidence": 0.85},
            "tags": ["data-exfiltration"], "category": "Data Exfiltration",
            "location": {"file": "SKILL.md", "start_line": 4, "end_line": 4,
                         "start_column": 1, "end_column": 15}} | changes


class V3NormalizationTests(unittest.TestCase):
    def normalize(self, raw):
        record = reports.empty_record_v3(item())
        record["source"]["content_digest"] = "sha256:" + "b" * 64
        record["scanned_at"] = reports.now()
        record["execution"]["started_at"] = record["scanned_at"]
        result = reports.normalize_report_v3(record, json.dumps(raw).encode(), 1, Path('/tmp/content'))
        schema = json.loads((reports.ROOT/'schemas/skillspector-record-v3.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(result)
        return result

    def test_duplicate_identity_keeps_evidence_and_distinct_occurrences(self):
        raw = upstream_report()
        first = finding()
        duplicate = finding(finding_id='finding-second')
        another_location = finding(finding_id='finding-third', location={'file':'guide.md','start_line':9})
        raw['issues'] = [first, duplicate, another_location]
        output = self.normalize(raw)
        self.assertEqual((output['raw_finding_count'], output['finding_count'], output['finding_group_count']), (3,3,1))
        group = output['findings'][0]
        self.assertEqual(group['finding_ids'], ['finding-first','finding-second','finding-third'])
        self.assertEqual(len(group['occurrences']), 2)
        self.assertEqual(group['evidence'], first['evidence'])
        self.assertEqual(group['confidence'], 0.85)
        self.assertEqual(group['occurrences'][0]['start_column'], 1)
        self.assertEqual(group['review_status'], 'unreviewed')
        self.assertEqual(output['execution']['state'], 'completed')
        self.assertEqual(output['coverage']['status'], 'complete')

    def test_similar_findings_differing_in_full_evidence_do_not_merge(self):
        raw = upstream_report()
        raw['issues'] = [finding(evidence={'payload': 'a'*3000+'one'}),
                         finding(evidence={'payload': 'a'*3000+'two'})]
        output = self.normalize(raw)
        self.assertEqual(output['finding_group_count'], 2)
        self.assertEqual({f['evidence']['payload'][-3:] for f in output['findings']}, {'one','two'})
        raw['issues'] = [finding(evidence={'payload':'ab'}), finding(evidence={'payload':'a\x00b'})]
        self.assertEqual(self.normalize(raw)['finding_group_count'], 2)

    def test_no_fingerprint_needs_exact_locations_to_group(self):
        raw=upstream_report()
        raw['issues']=[finding(match_fingerprint=None), finding(match_fingerprint=None,
            location={'file':'SKILL.md','start_line':10})]
        self.assertEqual(self.normalize(raw)['finding_group_count'], 2)

    def test_coverage_only_signal_is_preserved_outside_content_findings(self):
        raw=upstream_report()
        limitation=finding(id='AE1',tags=['coverage','reference'], evidence={
            'target_path':'helper.py','reasons':[{'reason_code':'static_parse_limit','message':'Expression exceeds parser bound.'}]})
        raw['issues']=[limitation, finding(), finding(id='SC9',evidence={'concealment':'hidden_artifact'})]
        result=self.normalize(raw)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['raw_finding_count'], 3)
        self.assertEqual(result['finding_count'], 2)
        self.assertEqual(result['coverage']['original_findings'], [limitation])
        self.assertEqual({v['rule'] for v in result['findings']}, {'E4','SC9'})
        self.assertEqual(result['coverage']['reasons'][0]['code'], 'static_parse_limit')
        self.assertFalse(result['coverage']['reasons'][0]['retryable'])

    def test_sc9_inspection_limit_is_not_concealment_finding(self):
        for flag in ('excluded_inspection_incomplete','partially_analyzed_executable','excluded_from_analysis'):
            with self.subTest(flag=flag):
                raw=upstream_report();raw['issues']=[finding(id='SC9',pattern='Concealed Executable Artifact',
                    evidence={flag:True,'concealment':'document_container','container_type':'docx','nested_path':'payload.exe'})]
                output=self.normalize(raw)
                self.assertEqual(output['finding_group_count'],1)
                self.assertEqual(output['coverage']['status'],'partial')
                self.assertEqual(output['findings'][0]['rule'],'SC9')
        raw=upstream_report();raw['issues']=[finding(id='SC9',pattern='Excluded Artifact Inspection Incomplete',
            evidence={'excluded_inspection_incomplete':True})]
        output=self.normalize(raw)
        self.assertEqual(output['finding_group_count'],0)
        self.assertEqual(output['coverage']['original_findings'][0]['evidence'],{'excluded_inspection_incomplete':True})

    def test_raw_upstream_occurrence_count_is_separate_from_groups(self):
        raw=upstream_report();raw['issues']=[finding(occurrences=[{'file':'SKILL.md','start_line':4}, {'file':'SKILL.md','start_line':12}])]
        output=self.normalize(raw)
        self.assertEqual(output['raw_finding_count'], 2)
        self.assertEqual(output['finding_group_count'], 1)
        self.assertEqual(len(output['findings'][0]['occurrences']), 2)

    def test_more_than_32_distinct_signals_are_not_lost(self):
        raw=upstream_report();raw['issues']=[finding(evidence={'distinct':i},finding_id=f'f-{i}') for i in range(80)]
        output=self.normalize(raw)
        self.assertEqual(len(output['findings']),80)
        self.assertFalse(output['findings_truncated'])

    def test_projection_limit_preserves_counts_and_reports_lost_evidence(self):
        raw=upstream_report();raw['issues']=[finding(evidence={'distinct':i,'context':'x'*2400}) for i in range(35)]
        with mock.patch.object(reports,'MAX_REPORT_BYTES',200 << 10):
            output=self.normalize(raw)
        self.assertEqual(output['finding_group_count'],35)
        self.assertLess(len(output['findings']),35)
        self.assertTrue(output['findings_truncated'])
        self.assertFalse(output['coverage']['grouping_complete'])
        self.assertEqual(output['status'],'partial')
        self.assertIn('normalization_truncated',[v['code'] for v in output['coverage']['reasons']])
        self.assertLessEqual(len(reports.report_json(output)),(200-128) << 10)

    def test_analyzer_results_and_specific_limitation_reasons_survive(self):
        raw=upstream_report()
        raw['analysis_completeness']['is_complete']=False
        raw['analysis_completeness']['ledger_exceptions']=[{'reason_code':'runtime_limit','message':'Time budget exhausted.', 'path':'SKILL.md', 'analyzers':['static_patterns_prompt_injection']}]
        output=self.normalize(raw)
        self.assertEqual(output['coverage']['analyzers'],raw['analysis_completeness']['analyzer_statuses'])
        self.assertTrue(output['coverage']['reasons'][0]['retryable'])
        self.assertEqual(output['coverage']['reasons'][0]['analyzer_id'],'static_patterns_prompt_injection')

    def test_escaping_occurrences_and_sanitizer_key_collisions_fail_closed(self):
        raw=upstream_report();raw['issues']=[finding(occurrences=[{'file':'../private','start_line':1}])]
        with self.assertRaises(PublicationError):self.normalize(raw)
        for value in ({'ab':1,'a\x00b':2}, {'é':1,'e\u0301':2}):
            with self.subTest(value=value),self.assertRaises(PublicationError):reports.safe_report_value(value)

    def test_directory_findings_preserve_one_trailing_slash_but_reject_escape(self):
        raw=upstream_report();raw['issues']=[finding(location={'file':'tools/__pycache__/','start_line':1})]
        output=self.normalize(raw)
        self.assertEqual(output['findings'][0]['path'],'tools/__pycache__/')
        self.assertEqual(output['findings'][0]['occurrences'][0]['path'],'tools/__pycache__/')
        for path in ('/', 'tools//', 'tools//cache/', '../tools/', 'tools/../cache/', './tools/'):
            with self.subTest(path=path),self.assertRaises(PublicationError):
                reports.report_path(path,Path('/tmp/content'))


class V3ProfileTests(unittest.TestCase):
    def test_unmeasured_execution_timing_is_unknown(self):
        record=reports.empty_record_v3(item())
        self.assertIsNone(record['execution']['acquisition_seconds'])
        self.assertIsNone(record['execution']['analysis_seconds'])

    def test_profiles_coordinate_inner_and_outer_deadlines_without_credentials(self):
        with mock.patch.dict('os.environ',{'OPENAI_API_KEY':'never-forward','HTTPS_PROXY':'never-forward','SKILLSPECTOR_MAX_WORKFLOW_SECONDS':'9000'}):
            standard=reports.environment_v3(Path('/tmp/scan'),'static-standard-v3')
            extended=reports.environment_v3(Path('/tmp/scan'),'static-extended-v3')
            bounded=reports.environment_v3(Path('/tmp/scan'),'static-extended-v3',12)
        self.assertEqual(float(standard['SKILLSPECTOR_MAX_WORKFLOW_SECONDS']),45)
        self.assertEqual(float(extended['SKILLSPECTOR_MAX_WORKFLOW_SECONDS']),150)
        self.assertEqual(float(extended['SKILLSPECTOR_MAX_STATIC_ANALYSIS_SECONDS_PER_ARTIFACT']),90)
        self.assertLess(float(bounded['SKILLSPECTOR_MAX_WORKFLOW_SECONDS']),12)
        self.assertLessEqual(float(bounded['SKILLSPECTOR_MAX_STATIC_ANALYSIS_SECONDS_PER_ARTIFACT']),float(bounded['SKILLSPECTOR_MAX_WORKFLOW_SECONDS']))
        self.assertNotIn('OPENAI_API_KEY',extended);self.assertNotIn('HTTPS_PROXY',extended)

    def test_display_json_preserves_floats_without_weakening_signed_json(self):
        value={'confidence':0.85,'seconds':1.234,'evidence':{'nested':[0.125]}}
        body=reports.report_json(value)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'record.json';path.write_bytes(body)
            self.assertEqual(reports.read_report_json(path),value)
            for invalid in (b'{"a":1,"a":2}',b'{"a":1,"A":2}',b'{"x":NaN}',b'{"x":1e999}'):
                path.write_bytes(invalid)
                with self.subTest(body=invalid),self.assertRaises(PublicationError):reports.read_report_json(path)
        with self.assertRaises(PublicationError):canonical_json(value)
        for invalid in ({'x':math.inf},{1:'bad'},{'a':1,'A':2}):
            with self.subTest(value=invalid),self.assertRaises(PublicationError):reports.report_json(invalid)


if __name__=='__main__':unittest.main()
