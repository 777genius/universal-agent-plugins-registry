from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import measure_skillspector_profiles as measurement
from scripts import skillspector_reports as reports
from scripts.directory_publication import sha256_digest
from tests.test_skillspector_reports import fixture_repository, scanner, upstream_report
from tests.test_skillspector_records_v3 import finding
from tests.test_skillspector_redaction import synthetic_key


class ProfileMeasurementTests(unittest.TestCase):
    def test_real_process_serializes_public_projection_and_keeps_raw_report_separate(self):
        token = synthetic_key()
        raw = upstream_report()
        raw["issues"] = [finding(finding=token, code_snippet=token)]
        normalized_inputs = []
        normalize = reports.normalize_report_v3

        def capture_normalization(record, *args):
            public = normalize(record, *args)
            normalized_inputs.append(copy.deepcopy(record))
            return public

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, selection = fixture_repository(root)
            executable = scanner(root, raw)
            output = root / "measurements"
            with mock.patch.object(reports, "normalize_report_v3", side_effect=capture_normalization):
                result = measurement.measure(selection["sources"][0], "static-extended-v3",
                    executable, mirrors, output)
            self.assertEqual(result["status"], "complete")
            records = list(output.glob("*/record.json"))
            self.assertEqual(len(records), 1)
            public = reports.read_report_json(records[0])
            body = (records[0].parent / "raw.json").read_bytes()
            self.assertTrue(token.encode() in body, "Raw report lost original inert test evidence")
            self.assertFalse(reports.has_public_credentials(public), "Public measurement retained a credential-shaped value")
            self.assertTrue(reports.has_public_credentials(normalized_inputs[0]),
                "Fixture did not exercise the distinct public return value")
            self.assertEqual(public["findings"][0]["code_snippet"], reports.REDACTED_CREDENTIAL)
            self.assertEqual(result["raw_report_digest"], sha256_digest(body))
            self.assertEqual(public["report_digest"], sha256_digest(body))
            self.assertEqual(result["normalized_record_digest"], sha256_digest(records[0].read_bytes()))
            for key in ("source", "id", "kind", "plugin_path", "report_digest", "scanner", "profile",
                        "status", "execution", "raw_finding_count", "finding_count", "finding_group_count"):
                self.assertEqual(public[key], normalized_inputs[0][key])
            for key in ("id", "match_fingerprint", "finding_ids", "occurrences", "raw_count", "path", "line"):
                self.assertEqual(public["findings"][0][key], normalized_inputs[0]["findings"][0][key])

    def test_real_process_preserves_raw_and_full_record_with_matching_digests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            mirrors,selection=fixture_repository(root)
            raw=upstream_report()
            raw['issues']=[{'id':'E4','severity':'HIGH','explanation':'Check this operation.',
                'confidence':0.85,'finding_id':'test-finding','evidence':{'score':0.75},
                'location':{'file':'SKILL.md','start_line':2}}]
            executable=scanner(root,raw)
            output=root/'measurements'
            result=measurement.measure(selection['sources'][0],'static-extended-v3',executable,mirrors,output)
            self.assertEqual(result['status'],'complete')
            records=list(output.glob('*/record.json'))
            self.assertEqual(len(records),1)
            record=reports.read_report_json(records[0])
            body=(records[0].parent/'raw.json').read_bytes()
            self.assertEqual(result['raw_report_digest'],sha256_digest(body))
            self.assertEqual(record['report_digest'],sha256_digest(body))
            self.assertEqual(result['normalized_record_digest'],sha256_digest(records[0].read_bytes()))
            self.assertEqual(record['findings'][0]['evidence'],{'score':0.75})
            self.assertEqual(record['findings'][0]['confidence'],0.85)
            self.assertEqual(record['profile'],reports.EXTENDED_PROFILE)
            self.assertGreater(result['analysis_seconds'],0)
            invocation=json.loads((records[0].parent/'invocation.json').read_text())
            self.assertEqual(invocation['content_digest'],record['source']['content_digest'])


if __name__=='__main__':unittest.main()
