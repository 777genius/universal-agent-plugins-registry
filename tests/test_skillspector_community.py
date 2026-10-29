from __future__ import annotations

import base64
import copy
import io
import json
import sys
import tempfile
import unittest
import urllib.error
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
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget
from tests.test_discovery_index import candidate_record
from tests.test_skillspector_reports import item
from tests.test_skillspector_coverage_v3 import worker


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
    def test_skill_bearing_package_union_emits_over_10k_coverage_rows(self):
        community = [plugin(path=f'packages/community-{index}') for index in range(10_000)]
        directory = [{'name': 'reviewed/demo', 'components': ['skills'],
                      'source': {'repository': 'owner/repo', 'revision': 'a' * 40, 'path': 'packages/demo'}}]
        plugins = discovery.merge_plugin_sources(directory, community)
        with mock.patch.object(discovery, 'PinnedRepository'), \
             mock.patch.object(discovery, 'skill_documents', side_effect=documents):
            inventories, attempted = discovery.resolve_plugin_inventory(
                plugins, [], None, mock.Mock(token=None), WorkBudget(30), 1, None)
        sources = [source for _state, roots, _superseded in inventories for source in roots]
        selection = {'schema_version': 1, 'sources': sources}
        _, summary = discover([])
        summary['catalog'] = metadata(community) | {'plugin_inventory_version': discovery.PLUGIN_RESOLVER_VERSION}
        summary['catalog']['community']['resolution_attempted'] = attempted
        summary.update(selected_roots=len(sources), selection_digest=v3.sha256_digest(canonical_json(selection)),
            plugin_states=[state | {'selected_ids': [source['id'] for source in roots]}
                           for state, roots, _superseded in inventories],
            source_states=[{'id': source['id'], 'repository': source['repository'], 'state': 'resolved', 'current': True,
                'reason': None, 'revision': source['revision'], 'path': source['path'],
                'selected_ids': [source['id']], 'candidates': []} for source in sources])
        self.assertEqual(len(sources), 10_001)
        v3.validate_selection(selection)
        v3.validate_discovery_summary(summary, selection, COMMIT)
        with tempfile.TemporaryDirectory() as temporary:
            manifest = v3.merge_reports(selection, None, [worker(selection) | {'source_commit': COMMIT}], source_commit=COMMIT,
                output_dir=Path(temporary), discovery_summary=summary)
        self.assertEqual(len(manifest['plugin_coverage']), 10_001)
        self.assertEqual(manifest['coverage']['pending'], 10_001)
        self.assertEqual(manifest['shards'], [])

    def test_plugin_coverage_capacity_is_v3_only_and_bounded(self):
        selection = {'schema_version': 1, 'sources': []}
        with tempfile.TemporaryDirectory() as temporary:
            manifest = v3.merge_reports(selection, None, [worker(selection) | {'source_commit': COMMIT}], source_commit=COMMIT,
                output_dir=Path(temporary))
        manifest['coverage'].update(selected=20_000, pending=20_000)
        manifest['plugin_coverage'] = [{'repository': 'owner/repo', 'plugin_path': f'packages/{index}',
            **(manifest['coverage'] | {'selected': 1, 'pending': 1})} for index in range(20_000)]
        v3.validate_manifest(manifest)
        manifest['plugin_coverage'].append(manifest['plugin_coverage'][-1] | {'plugin_path': 'packages/extra'})
        with self.assertRaises(PublicationError):
            v3.validate_manifest(manifest)
        legacy = {key: manifest[key] for key in ('source_commit', 'generated_at', 'scope', 'scanner', 'selection_digest', 'shards')}
        legacy.update(schema_version=2, profile=v2.PROFILE, coverage={'selected': 10_000, 'reported': 0, 'pending': 10_000},
            plugin_coverage=[{key: row[key] for key in ('repository', 'plugin_path', 'selected', 'reported', 'pending')}
                             for row in manifest['plugin_coverage'][:10_000]])
        v2.validate_manifest(legacy)
        legacy['plugin_coverage'].append(legacy['plugin_coverage'][-1] | {'plugin_path': 'packages/extra'})
        with self.assertRaises(PublicationError):
            v2.validate_manifest(legacy)

    def test_directory_and_10k_community_packages_merge_and_publish_without_skills(self):
        community = [plugin(path=f'packages/community-{index}', components=[], expected_skills=0)
                     for index in range(10_000)]
        directory = [{'name': 'reviewed/demo', 'components': [],
                      'source': {'repository': 'reviewed/repo', 'revision': 'c' * 40, 'path': 'packages/demo'}}]
        plugins = discovery.merge_plugin_sources(directory, community)
        with mock.patch.object(discovery, 'PinnedRepository') as pinned:
            selection, summary = discovery.discover([], metadata(community), mock.Mock(token=None), WorkBudget(30),
                source_commit=COMMIT, plugins=plugins, workers=1)
            pinned.assert_not_called()
        self.assertEqual(selection['sources'], [])
        self.assertEqual(len(summary['plugin_states']), 10_001)
        self.assertTrue(all(state['state'] == 'not_applicable' for state in summary['plugin_states']))
        v3.validate_discovery_summary(summary, selection, COMMIT)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            manifest = v3.merge_reports(selection, None, [worker(selection) | {'source_commit': COMMIT}], source_commit=COMMIT,
                output_dir=output, discovery_summary=summary)
            restored = v3.read_bundle(output)
        self.assertEqual(len(manifest['plugin_states']), 10_001)
        self.assertEqual(restored['manifest']['plugin_states'], summary['plugin_states'])

    def test_v3_plugin_states_are_bounded_at_20k_while_v2_stays_at_10k(self):
        selection, summary = discover([])
        state = {'id': 'reviewed/0', 'repository': 'owner/repo', 'plugin_path': 'packages/0',
                 'revision': 'a' * 40, 'state': 'not_applicable', 'reason': 'plugin_has_no_skills',
                 'skills_total': 0, 'selected_ids': []}
        summary['plugin_states'] = [state | {'id': f'reviewed/{index}', 'plugin_path': f'packages/{index}'}
                                    for index in range(20_000)]
        v3.validate_discovery_summary(summary, selection, COMMIT)
        with tempfile.TemporaryDirectory() as temporary:
            manifest = v3.merge_reports(selection, None, [worker(selection) | {'source_commit': COMMIT}], source_commit=COMMIT,
                output_dir=Path(temporary), discovery_summary=summary)
        self.assertEqual(len(manifest['plugin_states']), 20_000)
        extra = state | {'id': 'reviewed/extra', 'plugin_path': 'packages/extra'}
        summary['plugin_states'].append(extra)
        with self.assertRaisesRegex(PublicationError, 'plugin resolution states'):
            v3.validate_discovery_summary(summary, selection, COMMIT)
        manifest['plugin_states'].append(extra)
        with self.assertRaises(PublicationError):
            v3.validate_manifest(manifest)
        legacy = copy.deepcopy(summary)
        legacy['bounds']['roots'] = 10_000
        legacy['plugin_states'] = legacy['plugin_states'][:10_000]
        v2.validate_discovery_summary(legacy, selection, COMMIT)
        legacy['plugin_states'].append(extra)
        with self.assertRaisesRegex(PublicationError, 'plugin resolution states'):
            v2.validate_discovery_summary(legacy, selection, COMMIT)

    def test_graphql_rate_limit_retries_preserve_the_plugin_inventory_window(self):
        clock, acquired = [0], []
        budget = WorkBudget(1200, monotonic=lambda: clock[0])
        api = discovery.GitHubAPI('fixture-token', work_budget=budget)
        plugins = [plugin()]
        listing = {'source': 'owner/catalog', 'skillId': 'demo', 'name': 'demo'}

        def rate_limited(*_args, **_kwargs):
            raise urllib.error.HTTPError('https://api.github.com/graphql', 403, 'rate limited',
                {'Retry-After': '120'}, io.BytesIO(b'secondary rate limit'))

        def advance(seconds):
            clock[0] += seconds

        def acquire(*_args, **kwargs):
            acquired.append(kwargs['work_budget'].remaining())
            return mock.Mock()

        with mock.patch.object(api.opener, 'open', side_effect=rate_limited) as request, \
             mock.patch('scripts.build_discovery_index.time.sleep', side_effect=advance), \
             mock.patch.object(discovery, 'PinnedRepository', side_effect=acquire), \
             mock.patch.object(discovery, 'skill_documents', side_effect=documents):
            selection, summary = discovery.discover([listing], metadata(plugins), api, budget,
                source_commit=COMMIT, plugins=plugins, workers=1)

        self.assertEqual(request.call_count, 10)
        self.assertEqual(clock[0], 1200)
        self.assertEqual(acquired, [600])
        self.assertIs(api.work_budget, budget)
        self.assertEqual(len(selection['sources']), 1)
        self.assertEqual(summary['plugin_states'][0]['state'], 'resolved')
        self.assertEqual(summary['catalog']['community']['resolution_attempted'], [['owner/repo', 'a' * 40]])
        self.assertEqual(summary['source_states'][0]['state'], 'unavailable')
        self.assertFalse(summary['complete'])
        v3.validate_discovery_summary(summary, selection, COMMIT)

    def test_graphql_retry_longer_than_remaining_budget_preserves_completed_plugin_inventory(self):
        clock, acquired = [0], []
        budget = WorkBudget(90, monotonic=lambda: clock[0])
        api = discovery.GitHubAPI('fixture-token', work_budget=budget)
        plugins = [plugin()]
        listing = {'source': 'owner/catalog', 'skillId': 'demo', 'name': 'demo'}

        def rate_limited(*_args, **_kwargs):
            raise urllib.error.HTTPError('https://api.github.com/graphql', 403, 'rate limited',
                {'Retry-After': '120'}, io.BytesIO(b'secondary rate limit'))

        def acquire(*_args, **kwargs):
            acquired.append(kwargs['work_budget'].remaining())
            return mock.Mock()

        def advance(seconds):
            clock[0] += seconds

        with mock.patch.object(api.opener, 'open', side_effect=rate_limited) as request, \
             mock.patch('scripts.build_discovery_index.time.sleep', side_effect=advance) as sleep, \
             mock.patch.object(discovery, 'PinnedRepository', side_effect=acquire), \
             mock.patch.object(discovery, 'skill_documents', side_effect=documents):
            selection, summary = discovery.discover([listing], metadata(plugins), api, budget,
                source_commit=COMMIT, plugins=plugins, workers=1)

        self.assertEqual(acquired, [45])
        self.assertEqual(request.call_count, 1)
        sleep.assert_called_once_with(120)
        self.assertEqual(clock[0], 120)  # Preserve the server's full backoff.
        self.assertIs(api.work_budget, budget)
        self.assertEqual(len(selection['sources']), 1)
        self.assertEqual(summary['plugin_states'][0]['state'], 'resolved')
        self.assertEqual(summary['catalog']['community']['resolution_attempted'], [['owner/repo', 'a' * 40]])
        self.assertEqual(summary['source_states'][0]['state'], 'unavailable')
        v3.validate_discovery_summary(summary, selection, COMMIT)

    def test_plugin_half_window_exhaustion_leaves_standalone_resolution_time(self):
        clock, events = [0], []
        budget = WorkBudget(120, monotonic=lambda: clock[0])
        api = mock.Mock(token=None, work_budget=budget)
        plugins = [plugin()]
        listing = {'source': 'owner/catalog', 'skillId': 'demo', 'name': 'demo'}

        def acquire(repository, *_args, **kwargs):
            remaining = kwargs['work_budget'].remaining()
            events.append((repository, remaining))
            if repository == 'owner/repo':
                clock[0] = kwargs['work_budget'].deadline
                raise CheckpointYield('simulated acquisition used its entire allowance')
            return mock.Mock()

        def states(_api, repositories, *, work_budget):
            events.append(('graphql', work_budget.remaining()))
            return {repository: {'available': True, 'repository': repository, 'revision': 'a' * 40}
                    for repository in repositories}

        with mock.patch.object(discovery, 'repository_states', side_effect=states), \
             mock.patch.object(discovery, 'PinnedRepository', side_effect=acquire), \
             mock.patch.object(discovery, 'skill_documents', return_value=({'demo': ['skills/demo']}, [])):
            selection, summary = discovery.discover([listing], metadata(plugins), api, budget,
                source_commit=COMMIT, plugins=plugins, workers=1)

        self.assertEqual(events, [('owner/repo', 60), ('graphql', 60), ('owner/catalog', 60)])
        self.assertEqual([source['kind'] for source in selection['sources']], ['standalone_skill'])
        self.assertEqual(summary['source_states'][0]['state'], 'resolved')
        self.assertEqual(summary['plugin_states'][0]['reason'], 'plugin_discovery_budget_exhausted')
        self.assertIs(api.work_budget, budget)
        v3.validate_discovery_summary(summary, selection, COMMIT)

    def test_directory_only_inventory_retains_standalone_first_order(self):
        events = []
        directory = plugin() | {'name': 'reviewed/demo'}
        listing = {'source': 'owner/catalog', 'skillId': 'demo', 'name': 'demo'}
        budget = WorkBudget(10)

        def states(_api, _repositories, *, work_budget):
            events.append('standalone')
            return {'owner/catalog': {'available': False, 'repository': 'owner/catalog'}}

        def inventories(_plugins, _previous, _summary, _api, inventory_budget, _workers, _mirror_root):
            events.append('plugins')
            self.assertIs(inventory_budget, budget)
            return [], []

        with mock.patch.object(discovery, 'repository_states', side_effect=states), \
             mock.patch.object(discovery, 'resolve_plugin_inventory', side_effect=inventories):
            discovery.discover([listing], metadata([]), mock.Mock(token=None), budget,
                source_commit=COMMIT, plugins=[directory], workers=1)
        self.assertEqual(events, ['standalone', 'plugins'])

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
        self.assertGreater(acquired[0], 400)
        self.assertLessEqual(acquired[0], 450)

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

    def test_combined_cold_group_history_over_10k_retains_valid_cached_inventory(self):
        plugins = [plugin()]
        with mock.patch.object(discovery, 'PinnedRepository'), mock.patch.object(discovery, 'skill_documents', side_effect=documents):
            previous, summary = discover(plugins)
        history = [[f'owner/repo-{index}', 'a' * 40] for index in range(20_001)]
        for count in (10_001, 20_000, 20_001):
            prior = copy.deepcopy(summary)
            prior['catalog']['community']['resolution_attempted'] = history[:count]
            with self.subTest(groups=count), mock.patch.object(discovery, 'PinnedRepository') as pinned, \
                 mock.patch.object(discovery, 'skill_documents', side_effect=documents):
                selected, _ = discover(plugins, previous=previous['sources'], previous_summary=prior)
                self.assertEqual(selected, previous)
                self.assertEqual(pinned.call_count, int(count > 20_000))

    def test_extra_invalid_skill_keeps_the_inventory_denominator_incomplete(self):
        plugins = [plugin(expected_skills=1)]
        with mock.patch.object(discovery, 'PinnedRepository'), mock.patch.object(discovery, 'skill_documents',
                return_value=({'demo': ['packages/demo/skills/demo']}, ['packages/demo/skills/invalid/SKILL.md'])):
            selection, summary = discover(plugins)
        state = summary['plugin_states'][0]
        self.assertEqual(state['state'], 'unresolved')
        self.assertEqual(state['reason'], 'plugin_inventory_count_mismatch')
        self.assertEqual(state['skills_total'], 2)
        self.assertEqual(len(state['selected_ids']), 1)
        self.assertEqual(summary['catalog']['community']['expected_skills'], 1)
        self.assertTrue(summary['source_states'][0]['current'])
        self.assertFalse(summary['complete'])
        v3.validate_discovery_summary(summary, selection, COMMIT)

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
