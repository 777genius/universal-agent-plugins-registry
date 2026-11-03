from __future__ import annotations

import ast
import copy
import json
import tempfile
import subprocess
import os
import sys
import zipfile
import io
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts import prepare_skillspector_corpus as corpus
from scripts import publish_skillspector_coverage_v3 as publisher
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts import skillspector_recovery as recovery
from scripts.directory_publication import PublicationError


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/skillspector-reports.yml'


def expression_value(expression: str, *, repository='777genius/universal-agent-plugins-registry',
                     ref='refs/heads/main', selected_corpus='catalog', run_attempt=2):
    """Evaluate this workflow's simple publication condition as a truth table.

    Reject new expression features so changes to the publication boundary must
    deliberately extend its tests, rather than silently skipping a predicate.
    """
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    expression = expression.replace('github.repository', 'repository').replace('github.ref', 'ref')
    expression = expression.replace('github.run_attempt', 'run_attempt')
    expression = expression.replace('inputs.corpus', 'selected_corpus').replace('steps.config.outputs.corpus', 'selected_corpus').replace('needs.prepare.outputs.corpus', 'selected_corpus').replace('&&', ' and ').replace('||', ' or ')
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq,
               ast.Name, ast.Constant, ast.Load, ast.Gt)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError('Publication condition needs an explicit test update')
    return eval(compile(tree, '<workflow bounded expression>', 'eval'), {'__builtins__': {}},
        {'repository': repository, 'ref': ref, 'selected_corpus': selected_corpus, 'run_attempt': run_attempt})


def gate(expression, **context):
    return bool(expression_value(expression, **context))


class SkillSpectorWorkflowV3Tests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)

    def test_configured_analysis_runner_keeps_publication_on_separate_hosted_runner(self):
        jobs = self.workflow['jobs']
        for name in ('prepare', 'scan', 'assemble'):
            with self.subTest(job=name):
                self.assertEqual(jobs[name]['runs-on'], "${{ github.event_name == 'pull_request' && 'ubuntu-24.04' || vars.CI_LINUX_RUNNER || 'ubuntu-24.04' }}")
                self.assertEqual(jobs[name]['permissions'], {'contents': 'read', 'actions': 'read'})
        # All configured-runner phases depend on the original repository gate.
        self.assertIn("github.repository == '777genius/universal-agent-plugins-registry'", jobs['prepare']['if'])
        self.assertEqual(jobs['scan']['needs'], 'prepare')
        self.assertEqual(set(jobs['assemble']['needs']), {'prepare', 'scan'})
        # Write credentials must never enter the pool that parses source input.
        self.assertEqual(jobs['publish']['runs-on'], 'ubuntu-24.04')
        self.assertEqual(jobs['publish']['permissions'], {'contents': 'write'})

    def test_controlled_and_branch_runs_cannot_publish(self):
        publish = self.workflow['jobs']['publish']
        for repository in ('777genius/universal-agent-plugins-registry', 'someone/fork'):
            for ref in ('refs/heads/main', 'refs/heads/feature'):
                for selected in ('catalog', 'controlled', ''):
                    with self.subTest(repository=repository, ref=ref, corpus=selected):
                        self.assertEqual(gate(publish['if'], repository=repository, ref=ref,
                            selected_corpus=selected), repository == '777genius/universal-agent-plugins-registry'
                            and ref == 'refs/heads/main' and selected != 'controlled')
        self.assertEqual(set(publish['needs']), {'prepare', 'assemble'})
        self.assertEqual(self.workflow['permissions'], {'contents':'read', 'actions':'read'})
        for name, job in self.workflow['jobs'].items():
            self.assertEqual(job['permissions'], {'contents': 'write'} if name == 'publish' else {'contents': 'read', 'actions': 'read'})

    def test_controlled_run_starts_fresh_and_cannot_reuse_production_cache(self):
        prepare = self.workflow['jobs']['prepare']
        previous = next(s for s in prepare['steps'] if 'publish_skillspector_coverage_v3 previous' in s.get('run',''))
        self.assertIn('if', previous, 'Controlled regression must not silently reuse complete/blocked production attempts')
        self.assertFalse(gate(previous['if'], selected_corpus='controlled'))
        self.assertTrue(gate(previous['if'], selected_corpus='catalog'))
        corpus_step = next(s for s in prepare['steps'] if 'scripts.prepare_skillspector_corpus' in s.get('run',''))
        self.assertTrue(gate(corpus_step['if'], selected_corpus='controlled'))
        self.assertFalse(gate(corpus_step['if'], selected_corpus='catalog'))

    def test_controlled_corpus_uses_one_complete_partition_and_catalog_keeps_eight(self):
        outputs = self.workflow['jobs']['prepare']['outputs']
        for selected in ('controlled', 'catalog', ''):
            with self.subTest(corpus=selected):
                config = recovery.execution_config('workflow_dispatch', corpus=selected)
                count = int(config['partition_count'])
                partitions = json.loads(config['partitions'])
                self.assertEqual(count, 1 if selected == 'controlled' else 8)
                self.assertEqual(partitions, list(range(count)))
        scan = self.workflow['jobs']['scan']
        self.assertEqual(scan['strategy']['matrix']['partition'], '${{ fromJSON(needs.prepare.outputs.partitions) }}')
        step = next(s for s in scan['steps'] if 'scripts.skillspector_coverage_v3 scan' in s.get('run', ''))
        self.assertEqual(step['env']['PARTITION_COUNT'], '${{ needs.prepare.outputs.partition_count }}')
        self.assertIn('--partition-count "${PARTITION_COUNT}"', step['run'])

    def test_scanner_is_immutable_and_locked_with_no_write_credentials(self):
        scan = self.workflow['jobs']['scan']
        checkout = next(s for s in scan['steps'] if s.get('with',{}).get('repository') == 'NVIDIA/SkillSpector')
        self.assertEqual(checkout['with']['ref'], scanner.SCANNER['revision'])
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        install = next(s['run'] for s in scan['steps'] if 'uv sync' in s.get('run',''))
        self.assertIn('uv sync --directory scanner --frozen --no-dev --python 3.12', install)
        patch = next(s for s in scan['steps'] if 'patch_skillspector_directory_references.py' in s.get('run', ''))
        self.assertIn('scanner --verify', patch['run'])
        self.assertEqual(scanner.STANDARD_PROFILE_DOCUMENT['reference_inventory_patch'], 'uap-directory-inventory-v1')
        for name, job in self.workflow['jobs'].items():
            for step in job['steps']:
                if step.get('uses','').startswith('actions/checkout@'):
                    self.assertEqual(step['with']['persist-credentials'], 'false')
                    if step['with'].get('repository') != 'NVIDIA/SkillSpector':
                        self.assertEqual(step['with']['ref'], '${{ github.sha }}')
        scan_step = next(s for s in scan['steps'] if 'scripts.skillspector_coverage_v3 scan' in s.get('run',''))
        self.assertNotIn('GITHUB_TOKEN', scan_step.get('env',{}))
        self.assertIn('--discovery-summary', scan_step['run'])
        self.assertIn('--partition-count "${PARTITION_COUNT}"', scan_step['run'])

    def test_v3_artifact_is_checked_before_publication_credentials(self):
        assemble = self.workflow['jobs']['assemble']
        commands = '\n'.join(s.get('run','') for s in assemble['steps'])
        self.assertIn('scripts.skillspector_coverage_v3 merge', commands)
        self.assertIn('scripts.publish_skillspector_coverage_v3 check', commands)
        uploaded = next(s for s in assemble['steps'] if s.get('uses','').startswith('actions/upload-artifact@'))
        self.assertEqual(uploaded['with']['name'], 'skillspector-static-report-v3-a${{ github.run_attempt }}')
        publish = self.workflow['jobs']['publish']['steps']
        downloaded = next(s for s in publish if s.get('uses','').startswith('actions/download-artifact@'))
        self.assertEqual(uploaded['with']['name'], 'skillspector-static-report-v3-a${{ github.run_attempt }}')
        self.assertEqual(downloaded['with']['name'], '${{ needs.assemble.outputs.report_artifact }}')
        check = next(i for i,s in enumerate(publish) if 'scripts.publish_skillspector_coverage_v3 check' in s.get('run',''))
        write = next(i for i,s in enumerate(publish) if 'scripts.publish_skillspector_coverage_v3 publish' in s.get('run',''))
        self.assertLess(check,write)
        self.assertNotIn('GITHUB_TOKEN', publish[check].get('env',{}))
        self.assertEqual(publish[write]['env']['GITHUB_TOKEN'], '${{ github.token }}')

    def test_slice_configuration_executes_with_bounded_total_budgets(self):
        scan = self.workflow['jobs']['scan']
        configure = next(step for step in scan['steps'] if step.get('id') == 'slices')
        expected = {(2100, 128): (3, 700, 43), (2100, 8): (3, 700, 3),
                    (600, 8): (1, 600, 8), (300, 8): (1, 300, 8)}
        for (budget, attempts), values in expected.items():
            with self.subTest(budget=budget, attempts=attempts), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'outputs'
                subprocess.run(['bash', '-eu', '-c', configure['run']], check=True,
                    env={'TOTAL_BUDGET': str(budget), 'MAXIMUM_ATTEMPTS': str(attempts), 'GITHUB_OUTPUT': str(output)})
                result = dict(line.split('=', 1) for line in output.read_text().splitlines())
                self.assertEqual(tuple(int(result[name]) for name in ('count', 'budget', 'attempts')), values)
                self.assertLessEqual(int(result['count']) * int(result['budget']), budget)
        slices = [step for step in scan['steps'] if step.get('id', '').startswith('scan')]
        self.assertEqual(len(slices), 3)
        self.assertGreaterEqual(int(scan['timeout-minutes']) - sum(int(step['timeout-minutes']) for step in slices), 10)
        for step in slices:
            self.assertIn('--slice-attempts', step['run'])
            self.assertIn('--budget-seconds "${SLICE_BUDGET}"', step['run'])

    def test_failed_scan_keeps_pack_upload_later_slice_and_assembly_reachable(self):
        jobs = self.workflow['jobs']
        steps = {step.get('id'): step for step in jobs['scan']['steps'] if step.get('id')}
        # These status functions suppress Actions' implicit success() gate.
        for index in (1, 2, 3):
            self.assertIn('!cancelled()', steps[f'scan{index}']['if'])
            self.assertIn('always()', steps[f'pack{index}']['if'])
            upload = next(step for step in jobs['scan']['steps']
                          if step.get('with', {}).get('name') == f'skillspector-checkpoint-a${{{{ github.run_attempt }}}}-p${{{{ matrix.partition }}}}-s{index}')
            self.assertIn('always()', upload['if'])
            self.assertIn(f"steps.pack{index}.outcome == 'success'", upload['if'])
            self.assertEqual(upload['with']['retention-days'], '90')
        self.assertIn('always()', jobs['assemble']['if'])
        self.assertIn("needs.prepare.result == 'success'", jobs['assemble']['if'])
        merge = next(step['run'] for step in jobs['assemble']['steps'] if 'skillspector_coverage_v3 merge' in step.get('run', ''))
        self.assertIn('--allow-partial-workers', merge)
        self.assertIn('--recovered-sources "${recovered_sources}"', merge)
        self.assertIn('--expected-partition-count "${{ needs.prepare.outputs.partition_count }}"', merge)
        self.assertIn('scripts.skillspector_recovery list-workers', merge)
        self.assertIn('--workers "${workers[@]}"', merge)

    def test_only_main_catalog_runs_can_recover_or_acknowledge_production_inputs(self):
        for job in ('prepare', 'assemble'):
            operation = ' recover ' if job == 'prepare' else ' acknowledge '
            step = next(step for step in self.workflow['jobs'][job]['steps']
                        if operation in step.get('run', ''))
            for branch in ('refs/heads/main', 'refs/heads/feature'):
                for selected in ('catalog', 'controlled'):
                    self.assertEqual(gate(step['if'], ref=branch, selected_corpus=selected),
                                     branch == 'refs/heads/main' and selected == 'catalog')
            self.assertEqual(step['env']['GITHUB_TOKEN'], '${{ github.token }}')

    def test_acknowledgement_uses_only_manifest_selected_before_successful_merge(self):
        steps = self.workflow['jobs']['assemble']['steps']
        merge_index = next(index for index, step in enumerate(steps) if 'skillspector_coverage_v3 merge' in step.get('run', ''))
        ack_index = next(index for index, step in enumerate(steps) if 'skillspector_recovery acknowledge' in step.get('run', ''))
        merge, ack = steps[merge_index], steps[ack_index]
        argument = '--consumed-manifest "${RUNNER_TEMP}/skillspector-plan/consumed-checkpoints.json"'
        self.assertIn(argument, merge['run'])
        self.assertIn(argument, ack['run'])
        self.assertLess(merge['run'].index('list-workers'), merge['run'].index('skillspector_coverage_v3 merge'))
        self.assertIn('publish_skillspector_coverage_v3 check', merge['run'])
        self.assertGreater(ack_index, merge_index)
        self.assertNotIn('always()', ack['if'])
        self.assertNotIn('continue-on-error', merge)

    def test_pr_canary_has_one_effective_controlled_short_configuration(self):
        self.assertIn('pull_request', self.workflow['on'])
        self.assertIn('.github/workflows/skillspector-reports.yml', self.workflow['on']['pull_request']['paths'])
        config = recovery.execution_config('pull_request', corpus='catalog', maximum_attempts='512',
            scan_budget_seconds='2100', discovery_pages='50')
        self.assertEqual(config, {'corpus': 'controlled', 'maximum_attempts': '8', 'scan_budget_seconds': '300',
            'discovery_pages': '1', 'partition_count': '1', 'partitions': '[0]'})
        prepare = self.workflow['jobs']['prepare']
        for key in ('corpus', 'maximum_attempts', 'scan_budget_seconds', 'partition_count', 'partitions'):
            self.assertEqual(prepare['outputs'][key], '${{ steps.config.outputs.' + key + ' }}')
        for job in ('prepare', 'scan', 'assemble'):
            self.assertIn("github.event_name == 'pull_request' && 'ubuntu-24.04'", self.workflow['jobs'][job]['runs-on'])
            self.assertEqual(self.workflow['jobs'][job]['permissions'], {'contents': 'read', 'actions': 'read'})
        for step in self.workflow['jobs']['scan']['steps']:
            if step.get('id', '').startswith('scan'):
                self.assertEqual(step['env']['MAXIMUM_ATTEMPTS'], '${{ needs.prepare.outputs.maximum_attempts }}')
        publish = self.workflow['jobs']['publish']
        self.assertIn("github.ref == 'refs/heads/main'", publish['if'])
        self.assertIn("needs.prepare.outputs.corpus != 'controlled'", publish['if'])
        # An hourly queue drains backlogs without changing worker budgets or scan evidence.
        self.assertEqual(self.workflow['on']['schedule'], [{'cron': '19 * * * *'}])
        self.assertEqual(self.workflow['on']['workflow_dispatch']['inputs']['maximum_attempts']['default'], '256')
        for event in ('push', 'schedule', 'workflow_dispatch'):
            self.assertEqual(recovery.execution_config(event)['maximum_attempts'], '256')
            self.assertEqual(recovery.execution_config(event)['scan_budget_seconds'], '2100')
        self.assertEqual(recovery.execution_config('workflow_dispatch', maximum_attempts='512')['scan_budget_seconds'], '2100')
        self.assertEqual(self.workflow['concurrency']['group'],
            "skillspector-static-reports-${{ github.event_name == 'pull_request' && github.sha || github.ref }}")
        self.assertEqual(self.workflow['concurrency']['queue'], 'max')
        self.assertEqual(self.workflow['concurrency']['cancel-in-progress'], 'false')

    def test_job_retry_artifact_names_are_unique_and_keep_original_prepare_output(self):
        jobs = self.workflow['jobs']
        uploaded_plan = next(step for step in jobs['prepare']['steps']
                             if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(uploaded_plan['with']['name'], 'skillspector-plan-a${{ github.run_attempt }}')
        self.assertEqual(jobs['prepare']['outputs']['plan_artifact'], uploaded_plan['with']['name'])
        for job in ('scan', 'assemble'):
            downloaded = next(step for step in jobs[job]['steps'] if step.get('with', {}).get('name') == '${{ needs.prepare.outputs.plan_artifact }}')
            self.assertIn('download-artifact', downloaded['uses'])
        downloads = [step for step in jobs['assemble']['steps'] if 'pattern' in step.get('with', {})]
        self.assertEqual(downloads[0]['with']['pattern'], 'skillspector-checkpoint-a${{ github.run_attempt }}-*')
        resume = next(step for step in jobs['scan']['steps'] if step.get('id') == 'resume')
        self.assertIn("github.ref == 'refs/heads/main'", resume['if'])
        self.assertIn('github.run_attempt > 1', resume['if'])
        self.assertIn("needs.prepare.outputs.corpus != 'controlled'", resume['if'])
        for selected in ('catalog', 'controlled'):
            self.assertEqual(gate(resume['if'], selected_corpus=selected, run_attempt=2), selected == 'catalog')
            self.assertFalse(gate(resume['if'], selected_corpus=selected, run_attempt=1))
        for step in jobs['scan']['steps']:
            if step.get('id', '').startswith('scan'):
                self.assertIn("steps.resume.outcome == 'success'", step['if'])

    def test_real_merge_shell_handles_flat_single_artifact_zip_and_named_multiple_layout(self):
        from tests.test_skillspector_recovery import package, archive_package
        merge = next(step['run'] for step in self.workflow['jobs']['assemble']['steps']
                     if 'skillspector_coverage_v3 merge' in step.get('run', ''))
        command = merge.replace('${{ needs.prepare.outputs.partition_count }}', '1')
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = package(root)
                archive, _ = archive_package(original)
                (root / 'plan').rename(root / 'skillspector-plan')
                destination = root / 'skillspector-workers'
                if nested:
                    destination /= 'skillspector-checkpoint-a1-p0-s1'
                with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                    zipped.extractall(destination)
                env = {**os.environ, 'RUNNER_TEMP': str(root), 'SOURCE_COMMIT': 'c' * 40,
                       'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '1',
                       'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH']}
                result = subprocess.run(['bash', '-eu', '-c', command], cwd=ROOT, env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                manifest = json.loads((root / 'skillspector-report' / 'index.json').read_text())
                self.assertEqual(manifest['coverage']['complete'], 1)


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
