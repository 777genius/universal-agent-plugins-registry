from __future__ import annotations

import base64
import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import discover_skillspector_sources as discovery
from scripts import discovery_publication as publication
from scripts import skillspector_coverage as v2
from scripts import skillspector_coverage_v3 as v3
from scripts.directory_publication import PublicationError, canonical_json
from scripts.discovery_checkpoint import WorkBudget
from tests.test_discovery_index import candidate_record
from tests.test_skillspector_reports import item


COMMIT = 'b' * 40


def plugin(repository='owner/repo', path='packages/demo', revision='a' * 40, **changes):
    return {'name': 'community:' + discovery.sha256_digest(canonical_json([repository, path]))[7:39],
            'components': ['skills'], 'source': {'repository': repository, 'revision': revision, 'path': path},
            'expected_skills': 1, 'available': True, 'tree_digest': 'sha256:' + '1' * 64,
            'manifest_digest': 'sha256:' + '2' * 64} | changes


def metadata(plugins):
    return {'complete': True, 'pages': 0, 'provider_total': 0, 'error': None,
            'community': {'state': 'resolved', 'reason': None, 'sequence': 1, 'source_commit': COMMIT,
                'snapshot_digest': 'sha256:' + '3' * 64, 'packages': len(plugins),
                'available_packages': sum(p['available'] for p in plugins),
                'expected_skills': sum(p['expected_skills'] for p in plugins if p['available']),
                'package_identities': {p['name']: {key: p[key] for key in
                    ('source', 'expected_skills', 'tree_digest', 'manifest_digest')} for p in plugins}}}


def documents(_pinned, _budget, *, plugin_path):
    return {'demo': [(plugin_path + '/' if plugin_path else '') + 'skills/demo']}, []


def discover(plugins, *, previous=(), previous_summary=None, budget=None):
    return discovery.discover([], metadata(plugins), mock.Mock(token=None), budget or WorkBudget(10),
        source_commit=COMMIT, previous=previous, previous_summary=previous_summary, plugins=plugins, workers=1)


class CommunityFeedTests(unittest.TestCase):
    def test_signed_feed_expiry_pointer_and_both_payloads_are_authenticated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = bytes(range(32))
            private = Ed25519PrivateKey.from_private_bytes(seed)
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            keys = root / 'trusted.json'
            keys.write_bytes(canonical_json({'schema_version': 1, 'keys': [
                {'key_id': 'fixture', 'public_key': base64.b64encode(public).decode()}]}))
            row = candidate_record('a' * 40)
            row['components']['skills'] = 1
            candidate = root / 'candidate.json'
            candidate.write_bytes(canonical_json({'candidate_schema_version': 1, 'mode': 'discover',
                'generated_at': '2026-08-27T00:00:00Z', 'complete': True,
                'query_manifest_digest': 'sha256:' + '3' * 64,
                'partitions': [{'query': 'fixture', 'size_min': 0, 'size_max': 10, 'total_count': 1}], 'records': [row]}))
            feed = root / 'feed'
            with mock.patch.object(publication, 'ed25519_sign', side_effect=lambda _seed, message: private.sign(message)):
                publication.publish(candidate, feed, keys, seed, 'fixture', 'fixture', COMMIT, 3)
            bodies = {p.relative_to(feed).as_posix(): p.read_bytes() for p in feed.rglob('*') if p.is_file()}
            current = datetime(2026, 8, 28, tzinfo=timezone.utc)
            def load(values, at=current):
                return discovery.load_published_community_plugins(WorkBudget(10),
                    fetch=lambda path, *_: values[path], trusted_keys=keys, current=at)
            plugins, identity = load(bodies)
            self.assertEqual(identity['expected_skills'], 1)
            self.assertEqual(plugins[0]['source'], {'repository': 'owner/repo', 'revision': 'a' * 40, 'path': 'packages/demo'})
            self.assertEqual(plugins[0]['tree_digest'], row['tree_digest'])
            self.assertEqual(identity['state'], 'resolved')
            with self.assertRaises(discovery.DiscoveryError):
                load(bodies, datetime(2026, 9, 1, tzinfo=timezone.utc))
            pointer = json.loads(bodies['latest.json'])
            for field in ('snapshot_path', 'search_path'):
                altered = dict(bodies)
                altered[pointer[field]] = altered[pointer[field]].replace(b'"skills":1', b'"skills":2')
                with self.subTest(field=field), self.assertRaises(PublicationError):
                    load(altered)
            altered = dict(bodies)
            altered['latest.json'] = canonical_json(pointer | {'sequence': 2})
            with self.assertRaises(discovery.DiscoveryError):
                load(altered)

    def test_directory_precedence_deduplicates_package_root_even_at_different_pin(self):
        community = plugin()
        directory = {'name': 'reviewed/demo', 'components': ['skills'],
                     'source': community['source'] | {'revision': 'c' * 40}}
        self.assertEqual(discovery.merge_plugin_sources([directory], [community]), [directory])
        same_pin = directory | {'source': community['source']}
        self.assertEqual(discovery.merge_plugin_sources([same_pin], [community]), [same_pin])


class CommunityInventoryTests(unittest.TestCase):
    def test_crawl_subdeadline_leaves_time_for_community_inventory(self):
        clock, acquired = [0], []
        plugins = [plugin()]
        def work_budget(seconds, *, monotonic=None):
            return WorkBudget(seconds, monotonic=monotonic or (lambda: clock[0]))
        def crawl(budget, **_kwargs):
            self.assertEqual(budget.deadline, 300)
            clock[0] = budget.deadline + .1
            return [], {'complete': False, 'pages': 0, 'provider_total': None, 'error': 'catalog_budget_exhausted'}
        def acquire(*_args, **kwargs):
            acquired.append(kwargs['work_budget'].remaining())
            return mock.Mock()
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(sys, 'argv', ['discover', '--source-commit', COMMIT, '--output', temporary + '/selection.json',
                                             '--summary', temporary + '/coverage.json']), \
             mock.patch.object(discovery, 'WorkBudget', side_effect=work_budget), \
             mock.patch.object(discovery, 'load_published_plugins', return_value=([], {'state': 'resolved'})), \
             mock.patch.object(discovery, 'load_published_community_plugins', return_value=(plugins, metadata(plugins)['community'])), \
             mock.patch.object(discovery, 'browse_catalog', side_effect=crawl), \
             mock.patch.object(discovery, 'load_sources', return_value=[]), \
             mock.patch.object(discovery, 'GitHubAPI'), mock.patch.object(discovery, 'PinnedRepository', side_effect=acquire), \
             mock.patch.object(discovery, 'skill_documents', side_effect=documents), mock.patch('builtins.print'):
            self.assertEqual(discovery.main(), 0)
            written = json.loads((Path(temporary) / 'selection.json').read_bytes())
        self.assertEqual(len(written['sources']), 1)
        self.assertGreater(acquired[0], 800)

    def test_grouped_cold_inventory_reuses_only_complete_pins_and_signed_metadata(self):
        plugins = [plugin(path='packages/one'), plugin(path='packages/two')]
        with mock.patch.object(discovery, 'PinnedRepository') as pinned, \
             mock.patch.object(discovery, 'skill_documents', side_effect=documents) as read:
            first, summary = discover(plugins)
            self.assertEqual(pinned.call_count, 1)
            self.assertEqual(read.call_count, 2)
        self.assertEqual(len(first['sources']), 2)
        v3.validate_discovery_summary(summary, first, COMMIT)
        with mock.patch.object(discovery, 'PinnedRepository') as pinned:
            second, reused = discover(plugins, previous=first['sources'], previous_summary=summary)
            pinned.assert_not_called()
        self.assertEqual(second, first)
        for change in ({'source': plugins[0]['source'] | {'revision': 'd' * 40}},
                       {'tree_digest': 'sha256:' + '4' * 64}, {'expected_skills': 2}):
            changed = [plugins[0] | change, plugins[1]]
            with self.subTest(change=change), mock.patch.object(discovery, 'PinnedRepository') as pinned, \
                 mock.patch.object(discovery, 'skill_documents', side_effect=documents):
                discover(changed, previous=first['sources'], previous_summary=summary)
                self.assertEqual(pinned.call_count, 1)
        for bad in ('malformed', summary['catalog']['community'] | {'sequence': None},
                    summary['catalog']['community'] | {'resolution_attempted': [['owner/repo', 'not-a-pin']]}):
            altered = copy.deepcopy(summary)
            altered['catalog']['community'] = bad
            with self.subTest(malformed_cache=bad), mock.patch.object(discovery, 'PinnedRepository') as pinned, \
                 mock.patch.object(discovery, 'skill_documents', side_effect=documents):
                selected, _ = discover(plugins, previous=first['sources'], previous_summary=altered)
                self.assertEqual(selected, first)
                self.assertEqual(pinned.call_count, 1)

    def test_deadline_persists_actual_attempts_and_prioritizes_untouched_group(self):
        plugins = [plugin(repository='a/repo'), plugin(repository='m/repo'), plugin(repository='z/repo')]
        def run(previous_summary=None):
            clock = [0]
            attempted = []
            def acquire(repository, *_args, **_kwargs):
                attempted.append(repository)
                clock[0] = 2
                raise OSError('inert simulated network failure')
            with mock.patch.object(discovery, 'PinnedRepository', side_effect=acquire):
                selection, summary = discover(plugins, previous_summary=previous_summary,
                                             budget=WorkBudget(1, monotonic=lambda: clock[0]))
            self.assertEqual(selection['sources'], [])
            self.assertTrue(all(s['state'] == 'unavailable' and s['skills_total'] == 1 for s in summary['plugin_states']))
            self.assertEqual(summary['catalog']['community']['resolution_attempted'][-1], [attempted[0], 'a' * 40])
            self.assertFalse(summary['complete'])
            return attempted, json.loads(json.dumps(summary))
        attempted, summary = run()
        self.assertEqual(attempted, ['a/repo'])
        attempted, summary = run(summary)
        self.assertEqual(attempted, ['m/repo'])
        attempted, summary = run(summary)
        self.assertEqual(attempted, ['z/repo'])
        attempted, _ = run(summary)
        self.assertEqual(attempted, ['a/repo'])

    def test_failed_new_pin_and_missing_feed_retain_historical_evidence(self):
        plugins = [plugin()]
        with mock.patch.object(discovery, 'PinnedRepository'), mock.patch.object(discovery, 'skill_documents', side_effect=documents):
            previous, summary = discover(plugins)
        changed = [plugin(revision='d' * 40)]
        with mock.patch.object(discovery, 'PinnedRepository', side_effect=OSError('temporary')):
            selection, failed = discover(changed, previous=previous['sources'], previous_summary=summary)
        self.assertEqual(selection, previous)
        self.assertEqual(failed['source_states'][0]['state'], 'historical')
        self.assertEqual(failed['plugin_states'][0]['skills_total'], 1)
        with mock.patch.object(discovery, 'PinnedRepository', side_effect=OSError('temporary')) as pinned:
            discover(plugins, previous=previous['sources'], previous_summary=failed)
            self.assertEqual(pinned.call_count, 1)  # failed/empty is not a reusable inventory
        meta = metadata([])
        meta['community']['state'] = 'unavailable'
        meta['community']['reason'] = 'community_acquisition_failed'
        selection, unavailable = discovery.discover([], meta, mock.Mock(token=None), WorkBudget(10), source_commit=COMMIT,
            previous=previous['sources'], previous_summary=summary, workers=1)
        self.assertEqual(selection, previous)
        self.assertEqual(unavailable['plugin_states'][0]['reason'], 'community_acquisition_failed')
        self.assertFalse(unavailable['source_states'][0]['current'])
        v3.validate_discovery_summary(unavailable, selection, COMMIT)

    def test_unavailable_package_never_acquires_or_claims_no_skills(self):
        with mock.patch.object(discovery, 'PinnedRepository') as pinned:
            selection, summary = discover([plugin(available=False)])
            pinned.assert_not_called()
        self.assertEqual(selection['sources'], [])
        self.assertEqual(summary['plugin_states'][0]['state'], 'unavailable')
        self.assertEqual(summary['plugin_states'][0]['skills_total'], 1)

    def test_one_repository_failure_preserves_other_groups_and_valid_partial_roots(self):
        plugins = [plugin(repository='bad/repo'), plugin(repository='good/repo', expected_skills=2)]
        def acquire(repository, *_args, **_kwargs):
            if repository == 'bad/repo':
                raise RuntimeError('isolated unexpected acquisition failure')
            return mock.Mock()
        with mock.patch.object(discovery, 'PinnedRepository', side_effect=acquire), \
             mock.patch.object(discovery, 'skill_documents', side_effect=documents):
            selection, summary = discover(plugins)
        self.assertEqual(len(selection['sources']), 1)
        self.assertEqual(selection['sources'][0]['repository'], 'good/repo')
        self.assertEqual(summary['plugin_states'][0]['state'], 'unavailable')
        self.assertEqual(summary['plugin_states'][1]['reason'], 'plugin_inventory_count_mismatch')
        self.assertTrue(summary['source_states'][0]['current'])
        v3.validate_discovery_summary(summary, selection, COMMIT)

    def test_v3_inventory_over_10k_does_not_change_legacy_v2_limit(self):
        selection = {'schema_version': 1, 'sources': [item(id=f'fixture/{i}', path=f'skills/skill-{i}') for i in range(10001)]}
        v3.validate_selection(selection)
        with self.assertRaisesRegex(PublicationError, 'inventory limit'):
            v2.validate_selection(selection)
        with mock.patch.object(discovery, 'MAX_ROOTS', 1), self.assertRaises(discovery.DiscoveryError):
            discovery.merge_plugin_sources([], [plugin(path='one'), plugin(path='two')])


if __name__ == '__main__':
    unittest.main()
