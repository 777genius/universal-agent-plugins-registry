"""Adversarial security-evidence proof; no network and no scanner execution."""
import copy
import unittest

from scripts.skillspector_cohort_evidence_v2 import compare_findings_v2, EvidenceRejected


def record(first='a', second='b'):
    ids = [f'finding-{character * 32}' for character in (first, second)]
    return {
        'id': 'plugin:pinned/security', 'finding_group_count': 1,
        'finding_count': 2, 'raw_finding_count': 3, 'findings_truncated': False,
        'coverage': {'grouping_complete': True, 'reference_evidence_truncated': False},
        'findings': [{'rule': 'RP1', 'severity': 'HIGH', 'path': 'SKILL.md',
                     'line': 5, 'match_fingerprint': '4b5c',
                     'evidence': 'no hidden instructions',
                     'finding_ids': ids,
                     'occurrences': [
                         {'finding_id': ids[0], 'path': 'SKILL.md', 'line': 5,
                          'column': 1, 'snippet': 'a'},
                         {'finding_id': ids[1], 'path': 'SKILL.md', 'line': 6,
                          'column': 8, 'snippet': 'b'}]}],
    }


class FindingParityV2Tests(unittest.TestCase):
    def test_ephemeral_id_rotation_preserves_all_other_evidence(self):
        candidate = record('c', 'd')
        proof = compare_findings_v2(record(), candidate)
        self.assertEqual(proof['schema_version'], 2)
        self.assertTrue(proof['semantic_findings_unchanged'])
        for gate in ('publication_authorized', 'certified_complete',
                     'source_identity_verified', 'scanner_coverage_verified',
                     'coverage_only_raw_findings_verified'):
            self.assertFalse(proof[gate])
        self.assertEqual(proof['production_partial_reduction'], 0)

    def test_empty_findings_need_proven_grouping(self):
        a = record()
        a['findings'] = []
        a['finding_group_count'] = a['finding_count'] = a['raw_finding_count'] = 0
        self.assertTrue(compare_findings_v2(a, copy.deepcopy(a))['semantic_findings_unchanged'])
        a['coverage']['grouping_complete'] = False
        with self.assertRaises(EvidenceRejected):
            compare_findings_v2(a, a)

    def test_true_security_and_coverage_changes_fail(self):
        for label, mutate in (
            ('severity', lambda x: x['findings'][0].update(severity='LOW')),
            ('rule', lambda x: x['findings'][0].update(rule='SAFE')),
            ('fingerprint', lambda x: x['findings'][0].update(match_fingerprint='changed')),
            ('evidence', lambda x: x['findings'][0].update(evidence='removed')),
            ('path', lambda x: x['findings'][0].update(path='other.md')),
            ('line', lambda x: x['findings'][0].update(line=9)),
            ('occurrence_position', lambda x: x['findings'][0]['occurrences'][0].update(column=9)),
            ('snippet', lambda x: x['findings'][0]['occurrences'][1].update(snippet='different')),
            ('removed_occurrence', lambda x: x['findings'][0]['occurrences'].pop()),
            ('raw_coverage_finding_count', lambda x: x.update(raw_finding_count=2)),
            ('truncated', lambda x: x.update(findings_truncated=True)),
            ('incomplete_grouping', lambda x: x['coverage'].update(grouping_complete=False)),
            ('evidence_truncated', lambda x: x['coverage'].update(reference_evidence_truncated=True)),
            ('identity', lambda x: x.update(id='plugin:other')),
        ):
            with self.subTest(label=label):
                b = record('c', 'd')
                mutate(b)
                with self.assertRaises(EvidenceRejected):
                    compare_findings_v2(record(), b)

    def test_invalid_or_unpaired_ephemeral_ids_fail(self):
        for label, mutate in (
            ('non_generated_id', lambda x: x['findings'][0]['finding_ids'].__setitem__(0, 'uuid-like')),
            ('missing_id', lambda x: x['findings'][0]['finding_ids'].pop()),
            ('duplicate_id', lambda x: x['findings'][0]['finding_ids'].__setitem__(1, x['findings'][0]['finding_ids'][0])),
            ('unpaired_id', lambda x: x['findings'][0]['occurrences'][0].update(finding_id='finding-'+'e'*32)),
            ('missing_occurrence_id', lambda x: x['findings'][0]['occurrences'][0].pop('finding_id')),
            ('extra_occurrence', lambda x: x['findings'][0]['occurrences'].append(copy.deepcopy(x['findings'][0]['occurrences'][0]))),
        ):
            with self.subTest(label=label):
                b = record('c', 'd')
                mutate(b)
                with self.assertRaises(EvidenceRejected):
                    compare_findings_v2(record(), b)

    def test_missing_array_or_forged_counts_fail(self):
        for change in (
            {'finding_group_count': 2}, {'finding_count': 3}, {'raw_finding_count': 1},
            {'findings': None}, {'coverage': None},
        ):
            with self.subTest(change=change):
                b = record('c', 'd')
                b.update(change)
                with self.assertRaises(EvidenceRejected):
                    compare_findings_v2(record(), b)


if __name__ == '__main__':
    unittest.main()
