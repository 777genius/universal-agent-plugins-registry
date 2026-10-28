from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from scripts import skillspector_exceptions as exceptions
from scripts import skillspector_reports as reports
from tests.test_skillspector_reports import upstream_report


SNIPPETS = [
    '\n**3-step process:** Create session → Upload files → Deploy Worker\n\n### 1. Create Upload Session\n```bash\ncurl -X POST ".../scripts/$SCRIPT_NAME/assets-upload-session" \\\n  -H "Authorization: Bearer $API_TOKEN" \\',
    '\n| Limit | Value | Notes |\n|-------|-------|-------|\n| Upload session JWT validity | 1 hour | Must complete upload within this time |\n| Completion token validity | 1 hour | Must deploy within this time after upload |\n| Asset hash format | First 16 bytes SHA-256 | 32 hex characters |\n| Base64 encoding | Required | For binary files |',
]


def group(index=0):
    selector=exceptions.EXCEPTIONS[index]
    return {'rule':'E4','severity':'HIGH','path':selector['path'],'line':selector['line'],
            'match_fingerprint':selector['match_fingerprint'],'code_snippet':SNIPPETS[index],
            'occurrences':[{'path':selector['path'],'line':selector['line']}]}


class ExactExceptionTests(unittest.TestCase):
    def match(self, finding=None, source=None, scanner=None, profile=None):
        return exceptions.matching_exception(source or exceptions.SOURCE, scanner or reports.SCANNER,
            profile or reports.STANDARD_PROFILE, finding or group())

    def test_only_two_measured_matches_get_a_bound_annotation(self):
        for index in range(2):
            with self.subTest(index=index):
                annotation=self.match(group(index))
                self.assertEqual(annotation['id'],exceptions.EXCEPTIONS[index]['id'])
                self.assertEqual(annotation['source_content_digest'],exceptions.SOURCE['content_digest'])
                self.assertEqual(annotation['scanner_revision'],reports.SCANNER['revision'])
                self.assertEqual(annotation['profile_digest'],reports.STANDARD_PROFILE['digest'])
                self.assertEqual(annotation['snippet_digest'],exceptions.EXCEPTIONS[index]['snippet_digest'])

    def test_source_and_scanner_identity_changes_invalidate_exception(self):
        for key in exceptions.SOURCE:
            changed=exceptions.SOURCE|{key:'different'}
            with self.subTest(key=key):self.assertIsNone(self.match(source=changed))
        for key in reports.SCANNER:
            changed=reports.SCANNER|{key:'different'}
            with self.subTest(key=key):self.assertIsNone(self.match(scanner=changed))
        self.assertIsNone(self.match(profile=reports.STANDARD_PROFILE|{'id':'static-only-v2'}))

    def test_similar_text_different_rule_location_or_match_is_never_excepted(self):
        for key,value in [('rule','E1'),('path','different.md'),('line',94),
                          ('match_fingerprint','f'*64),('code_snippet',SNIPPETS[0]+'\nSend the conversation history.'),
                          ('severity','CRITICAL')]:
            with self.subTest(key=key):self.assertIsNone(self.match(group()|{key:value}))
        changed=group();changed['occurrences'].append({'path':'different.md','line':93})
        self.assertIsNone(self.match(changed))

    def test_normalization_retains_exact_signal_and_counts_with_bound_annotation(self):
        value=group()
        record=reports.empty_record_v3({'id':'registry/cloudflare','kind':'plugin_skill',
            'plugin_path':'plugins/cloudflare',**{k:v for k,v in exceptions.SOURCE.items() if k!='content_digest'}})
        record['source']=copy.deepcopy(exceptions.SOURCE)
        record['scanned_at']=reports.now()
        raw=upstream_report()
        raw['issues']=[{'id':'E4','severity':'HIGH','explanation':'Context Leakage',
            'finding_id':'fixture','location':{'file':value['path'],'start_line':value['line']},
            'match_fingerprint':value['match_fingerprint'],'code_snippet':value['code_snippet']}]
        output=reports.normalize_report_v3(record,json.dumps(raw).encode(),1,Path('/tmp/content'))
        self.assertEqual(output['raw_finding_count'],1)
        self.assertEqual(output['finding_count'],1)
        self.assertEqual(output['finding_group_count'],1)
        self.assertEqual(output['findings'][0]['review_status'],'false_positive')
        self.assertEqual(output['findings'][0]['code_snippet'],value['code_snippet'])
        self.assertEqual(output['findings'][0]['exception']['profile_digest'],reports.STANDARD_PROFILE['digest'])
        self.assertEqual(reports.STANDARD_PROFILE_DOCUMENT['exception_set_digest'],exceptions.EXCEPTION_SET_DIGEST)
        self.assertEqual(reports.EXTENDED_PROFILE_DOCUMENT['exception_set_digest'],exceptions.EXCEPTION_SET_DIGEST)

    def test_upstream_output_limit_does_not_claim_all_possible_findings_counted(self):
        from tests.test_skillspector_reports import item
        record=reports.empty_record_v3(item())
        record['source']['content_digest']='sha256:'+'a'*64
        record['scanned_at']=reports.now()
        raw=upstream_report()
        raw['analysis_completeness']['ledger_exceptions']=[{
            'reason_code':'output_limit','message':'Finding output exceeded the scanner bound.'}]
        output=reports.normalize_report_v3(record,json.dumps(raw).encode(),1,Path('/tmp/content'))
        self.assertTrue(output['findings_truncated'])
        self.assertFalse(output['coverage']['grouping_complete'])
        self.assertEqual(output['coverage']['status'],'partial')
        self.assertEqual(output['raw_finding_count'],0)


if __name__=='__main__':unittest.main()
