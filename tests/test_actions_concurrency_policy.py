"""Keep replaceable current-state triggers separate from exact publications."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'


class CurrentStateConcurrencyTests(unittest.TestCase):
    def read(self, name):
        return yaml.load((WORKFLOWS / name).read_text(), Loader=yaml.BaseLoader)

    def test_discovery_coalesces_only_refresh_before_expensive_jobs(self):
        workflow = self.read('discovery-index.yml')
        self.assertEqual(workflow['concurrency'], {
            'group': "discovery-current-${{ github.event_name == 'schedule' && github.event.schedule == '17 */6 * * *' && 'refresh' || github.run_id }}",
            'queue': 'single',
            'cancel-in-progress': 'false',
        })
        self.assertEqual(workflow['jobs']['acquire']['concurrency'], {
            'group': 'discovery-index-acquire',
            'cancel-in-progress': 'false',
            'queue': 'max',
        })
        self.assertEqual(len(workflow['on']['schedule']), 3)

    def test_pages_keeps_reusable_publication_and_durable_job_locks(self):
        workflow = self.read('pages-production-compositor.yml')
        self.assertIn('workflow_call', workflow['on'])
        self.assertEqual(workflow['concurrency'], {
            'group': "pages-current-${{ github.workflow == 'Compose current production Pages' && github.event_name == 'schedule' && 'scheduled' || github.run_id }}",
            'queue': 'single',
            'cancel-in-progress': 'false',
        })
        self.assertEqual(workflow['jobs']['record_pages_checkpoint']['needs'], 'compose')
        self.assertEqual(workflow['jobs']['record_production_marker']['needs'], 'compose')
        for name in ('compose', 'record_pages_checkpoint', 'record_production_marker'):
            with self.subTest(job=name):
                self.assertEqual(workflow['jobs'][name]['concurrency']['cancel-in-progress'], 'false')
                self.assertEqual(workflow['jobs'][name]['concurrency']['queue'], 'max')


if __name__ == '__main__':
    unittest.main()
