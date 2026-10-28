from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts import prepare_skillspector_corpus as corpus
from scripts import publish_skillspector_coverage_v3 as publisher
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import PublicationError


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/skillspector-reports.yml'


def gate(expression: str, *, repository='777genius/universal-agent-plugins-registry',
         ref='refs/heads/main', selected_corpus='catalog'):
    """Evaluate this workflow's simple publication condition as a truth table.

    Reject new expression features so changes to the publication boundary must
    deliberately extend its tests, rather than silently skipping a predicate.
    """
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    expression = expression.replace('github.repository', 'repository').replace('github.ref', 'ref')
    expression = expression.replace('inputs.corpus', 'selected_corpus').replace('&&', ' and ').replace('||', ' or ')
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq,
               ast.Name, ast.Constant, ast.Load)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError('Publication condition needs an explicit test update')
    return bool(eval(compile(tree, '<workflow publication gate>', 'eval'), {'__builtins__': {}},
        {'repository': repository, 'ref': ref, 'selected_corpus': selected_corpus}))


class SkillSpectorWorkflowV3Tests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)

    def test_controlled_and_branch_runs_cannot_publish(self):
        publish = self.workflow['jobs']['publish']
        for repository in ('777genius/universal-agent-plugins-registry', 'someone/fork'):
            for ref in ('refs/heads/main', 'refs/heads/feature'):
                for selected in ('catalog', 'controlled', ''):
                    with self.subTest(repository=repository, ref=ref, corpus=selected):
                        self.assertEqual(gate(publish['if'], repository=repository, ref=ref,
                            selected_corpus=selected), repository == '777genius/universal-agent-plugins-registry'
                            and ref == 'refs/heads/main' and selected != 'controlled')
        self.assertEqual(publish['needs'], 'assemble')
        self.assertEqual(self.workflow['permissions'], {'contents':'read'})
        for name, job in self.workflow['jobs'].items():
            self.assertEqual(job['permissions'], {'contents':'write' if name == 'publish' else 'read'})

    def test_controlled_run_starts_fresh_and_cannot_reuse_production_cache(self):
        prepare = self.workflow['jobs']['prepare']
        previous = next(s for s in prepare['steps'] if 'publish_skillspector_coverage_v3 previous' in s.get('run',''))
        self.assertIn('if', previous, 'Controlled regression must not silently reuse complete/blocked production attempts')
        self.assertFalse(gate(previous['if'], selected_corpus='controlled'))
        self.assertTrue(gate(previous['if'], selected_corpus='catalog'))
        corpus_step = next(s for s in prepare['steps'] if 'scripts.prepare_skillspector_corpus' in s.get('run',''))
        self.assertTrue(gate(corpus_step['if'], selected_corpus='controlled'))
        self.assertFalse(gate(corpus_step['if'], selected_corpus='catalog'))

    def test_scanner_is_immutable_and_locked_with_no_write_credentials(self):
        scan = self.workflow['jobs']['scan']
        checkout = next(s for s in scan['steps'] if s.get('with',{}).get('repository') == 'NVIDIA/SkillSpector')
        self.assertEqual(checkout['with']['ref'], scanner.SCANNER['revision'])
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        install = next(s['run'] for s in scan['steps'] if 'uv sync' in s.get('run',''))
        self.assertIn('uv sync --directory scanner --frozen --no-dev --python 3.12', install)
        for name, job in self.workflow['jobs'].items():
            for step in job['steps']:
                if step.get('uses','').startswith('actions/checkout@'):
                    self.assertEqual(step['with']['persist-credentials'], 'false')
                    if step['with'].get('repository') != 'NVIDIA/SkillSpector':
                        self.assertEqual(step['with']['ref'], '${{ github.sha }}')
        scan_step = next(s for s in scan['steps'] if 'scripts.skillspector_coverage_v3 scan' in s.get('run',''))
        self.assertNotIn('GITHUB_TOKEN', scan_step.get('env',{}))
        self.assertIn('--discovery-summary', scan_step['run'])
        self.assertIn('--partition-count 8', scan_step['run'])
        self.assertEqual(scan['strategy']['matrix']['partition'], [str(n) for n in range(8)])

    def test_v3_artifact_is_checked_before_publication_credentials(self):
        assemble = self.workflow['jobs']['assemble']
        commands = '\n'.join(s.get('run','') for s in assemble['steps'])
        self.assertIn('scripts.skillspector_coverage_v3 merge', commands)
        self.assertIn('scripts.publish_skillspector_coverage_v3 check', commands)
        uploaded = next(s for s in assemble['steps'] if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(uploaded['with']['name'], 'skillspector-static-report-v3')
        publish = self.workflow['jobs']['publish']['steps']
        downloaded = next(s for s in publish if s.get('uses','').startswith('actions/download-artifact@'))
        self.assertEqual(downloaded['with']['name'], uploaded['with']['name'])
        check = next(i for i,s in enumerate(publish) if 'scripts.publish_skillspector_coverage_v3 check' in s.get('run',''))
        write = next(i for i,s in enumerate(publish) if 'scripts.publish_skillspector_coverage_v3 publish' in s.get('run',''))
        self.assertLess(check,write)
        self.assertNotIn('GITHUB_TOKEN', publish[check].get('env',{}))
        self.assertEqual(publish[write]['env']['GITHUB_TOKEN'], '${{ github.token }}')


class ControlledCorpusPreparationTests(unittest.TestCase):
    def setUp(self):
        self.selection = json.loads((ROOT/'docs/skillspector/controlled-sources-2026-10-28.json').read_text())

    def test_actual_corpus_preserves_all_pinned_roots_and_only_writes_local_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'plan'
            summary=corpus.prepare(self.selection,'c'*40,output)
            written=json.loads((output/'selection.json').read_text())
            self.assertEqual(written,self.selection)
            self.assertEqual(len(written['sources']),15)
            self.assertEqual(summary['catalog']['mode'],'controlled_immutable_regression')
            self.assertEqual(len(summary['source_states']),15)
            self.assertEqual(summary['plugin_states'][0]['skills_total'],13)
            self.assertEqual({p.name for p in output.iterdir()},{'selection.json','coverage.json'})
            for item,state in zip(written['sources'],summary['source_states']):
                self.assertEqual(state['revision'],item['revision'])
                self.assertEqual(state['path'],item['path'])
                self.assertTrue(state['current'])

    def test_mutable_source_commit_and_oversized_controlled_corpus_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'plan'
            with self.assertRaises(PublicationError):corpus.prepare(self.selection,'main',output)
            oversized=copy.deepcopy(self.selection)
            for index in range(18):
                oversized['sources'].append(self.selection['sources'][0]|{'id':f'controlled/extra-{index}', 'path':f'skills/extra-{index}', 'kind':'standalone_skill','plugin_path':None})
            with self.assertRaises(PublicationError):corpus.prepare(oversized,'c'*40,output)

    def test_controlled_artifact_validates_but_direct_publish_makes_no_api_calls(self):
        commit = 'c' * 40
        worker = {'schema_version': 3, 'source_commit': commit, 'generated_at': scanner.now(),
            'scanner': coverage.SCANNER, 'profile': coverage.PROFILE,
            'selection_digest': coverage.sha256_digest(coverage.canonical_json(self.selection)),
            'partition': {'index': 0, 'count': 1}, 'attempts': []}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary = corpus.prepare(self.selection, commit, root / 'plan')
            report_dir = root / 'reports'
            coverage.merge_reports(self.selection, None, [worker], source_commit=commit,
                output_dir=report_dir, discovery_summary=summary)
            checked = publisher.validate_directory(report_dir, commit)
            self.assertEqual(checked['discovery']['catalog']['mode'], 'controlled_immutable_regression')
            github, fetch = mock.Mock(), mock.Mock()
            with self.assertRaisesRegex(PublicationError, 'controlled regression reports'):
                publisher.publish(github, report_dir, commit, fetch=fetch)
            github.request.assert_not_called()
            fetch.assert_not_called()


if __name__=='__main__':unittest.main()
