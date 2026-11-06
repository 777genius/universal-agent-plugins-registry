"""Recovery authenticates Actions origin separately from scanner JSON claims."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
import urllib.request
import urllib.error
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import skillspector_recovery as recovery
from scripts import publish_skillspector_coverage_v3 as publisher
from scripts import skillspector_coverage_v3 as coverage
from scripts.directory_publication import PublicationError
from tests import test_skillspector_coverage_v3 as fixtures
from tests.test_skillspector_coverage_v3 import COMMIT, item, record, worker, bundle


NOW = datetime(2026, 11, 3, 0, tzinfo=timezone.utc)


def run_metadata(**changes):
    return {"id": 101, "run_attempt": 1, "head_sha": COMMIT, "head_branch": "main",
        "event": "workflow_dispatch", "status": "completed", "created_at": "2026-11-02T17:00:00Z",
        "path": recovery.WORKFLOW, "workflow_id": 9,
        "repository": {"full_name": recovery.REPOSITORY},
        "head_repository": {"full_name": recovery.REPOSITORY}, **changes}


def package(root, *, branch="main", corpus="catalog", attempt=1):
    plan = root / "plan"
    plan.mkdir()
    selection = {"schema_version": 1, "sources": [item()]}
    summary = fixtures.QueueTests().discovery_summary(selection)
    if corpus == "controlled":
        summary["catalog"]["mode"] = "controlled_immutable_regression"
    value = worker(selection, [record(selection["sources"][0])])
    coverage.write_bounded(plan / "selection.json", selection, coverage.MAX_SELECTION_BYTES)
    coverage.write_bounded(plan / "coverage.json", summary, coverage.MAX_DISCOVERY_BYTES)
    coverage.write_bounded(root / "worker.json", value, coverage.MAX_WORKER_BYTES)
    output = root / "package"
    recovery.pack(plan, root / "worker.json", output, slice_index=1, environment={
        "GITHUB_REPOSITORY": recovery.REPOSITORY, "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": str(attempt),
        "GITHUB_SHA": COMMIT, "GITHUB_REF_NAME": branch, "GITHUB_EVENT_NAME": "workflow_dispatch", "SCAN_CORPUS": corpus})
    return output


def archive_package(directory, *, mutate=None):
    entries = {p.name: p.read_bytes() for p in directory.iterdir()}
    if mutate:
        mutate(entries)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries.items():
            archive.writestr(name, body)
    body = out.getvalue()
    artifact = {"id": 501, "name": "skillspector-checkpoint-a1-p0-s1", "expired": False,
        "size_in_bytes": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "workflow_run": {"id": 101, "head_sha": COMMIT, "head_branch": "main"}}
    return body, artifact


class FakeActions:
    def __init__(self, run, artifact):
        self.run, self.artifact, self.calls = run, artifact, []

    def request(self, method, path, data=None):
        self.calls.append((method, path))
        if method != "GET":
            raise AssertionError("recovery transport must be read only")
        if path == "actions/workflows/skillspector-reports.yml":
            return {"id": 9}
        if path == 'git/ref/heads/main':
            return {'object': {'sha': COMMIT}}
        if path.startswith("actions/workflows/9/runs?"):
            return {"workflow_runs": [self.run]}
        if path == "actions/runs/101":
            return self.run
        if path.startswith("actions/runs/101/artifacts?"):
            return {"total_count": 1, "artifacts": [self.artifact]}
        if path == "actions/runs/101/attempts/1":
            return {**self.run, "run_attempt": 1}
        raise AssertionError(path)


class CheckpointTransportTests(unittest.TestCase):
    def test_run_sha_must_belong_to_explicit_main_history_even_with_main_branch_label(self):
        class AncestryAPI:
            def __init__(self, status, merge_base):
                self.status, self.merge_base, self.calls = status, merge_base, []
            def request(self, method, path):
                self.calls.append((method, path))
                if path == 'git/ref/heads/main':
                    return {'object': {'sha': 'd' * 40}}
                if path == f'compare/{COMMIT}...{"d" * 40}?per_page=1':
                    return {'status': self.status, 'base_commit': {'sha': COMMIT},
                            'merge_base_commit': {'sha': self.merge_base}}
                raise AssertionError(path)
        ancestral = AncestryAPI('ahead', COMMIT)
        self.assertEqual(recovery.trusted_main_run(ancestral, run_metadata(), 9)['head_sha'], COMMIT)
        self.assertEqual(ancestral.calls[0], ('GET', 'git/ref/heads/main'))
        self.assertIn(('GET', f'compare/{COMMIT}...{"d" * 40}?per_page=1'), ancestral.calls)
        for status, merge_base in [('diverged', 'e' * 40), ('behind', 'e' * 40), ('ahead', 'e' * 40)]:
            # A workflow dispatched from a tag also named main can claim this metadata.
            with self.subTest(status=status, merge_base=merge_base), self.assertRaises(PublicationError):
                recovery.trusted_main_run(AncestryAPI(status, merge_base), run_metadata(head_branch='main'), 9)

    def test_single_flat_and_multiple_named_checkpoint_download_layouts_are_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, _ = archive_package(original)
            selection = json.loads((original / 'selection.json').read_text())
            missing = root / 'missing'
            missing.mkdir()
            with self.assertRaises(PublicationError):
                recovery.assembly_worker_paths(missing, selection, COMMIT, run_id=101, run_attempt=1)
            flat = root / 'flat'
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                archive.extractall(flat)
            self.assertEqual(recovery.assembly_worker_paths(flat, selection, COMMIT, run_id=101, run_attempt=1), [flat / 'worker.json'])
            multiple = root / 'multiple'
            for index in (1, 2):
                target = multiple / f'skillspector-checkpoint-a1-p0-s{index}'
                with zipfile.ZipFile(io.BytesIO(body)) as archive:
                    archive.extractall(target)
                provenance = json.loads((target / 'provenance.json').read_text())
                provenance['slice'] = index
                (target / 'provenance.json').write_bytes(coverage.report_json(provenance))
            paths = recovery.assembly_worker_paths(multiple, selection, COMMIT, run_id=101, run_attempt=1)
            self.assertEqual(len(paths), 2)
            (multiple / 'unrelated').mkdir()
            with self.assertRaises(PublicationError):
                recovery.assembly_worker_paths(multiple, selection, COMMIT, run_id=101, run_attempt=1)
            (multiple / 'unrelated').rmdir()
            with self.assertRaises(PublicationError):
                recovery.assembly_worker_paths(multiple, selection, COMMIT, run_id=101, run_attempt=2)
            (flat / 'unexpected.json').symlink_to(flat / 'worker.json')
            with self.assertRaises(PublicationError):
                recovery.assembly_worker_paths(flat, selection, COMMIT, run_id=101, run_attempt=1)

    def test_maximum_quarantine_status_including_own_retry_extension_fits_and_writes(self):
        artifact_rows = (recovery.MAX_RECOVERY_RUNS + 1) * recovery.MAX_RUN_ARTIFACTS
        summary = {'status': 'deferred', 'runs': recovery.MAX_RECOVERY_RUNS + 1, 'bytes': recovery.MAX_TOTAL_BYTES,
            'retention_days': 90, 'maximum_runs_per_prepare': recovery.MAX_RECOVERY_RUNS,
            'cursor': {'before': '2026-11-02T17:00:00Z', 'page': 10000, 'offset': 99}, 'recovered_sources': 20000,
            'rejected': [{'artifact_id': 2**63 - 1 - index, 'reason': 'excluded_controlled'} for index in range(artifact_rows)] +
                        [{'run_id': 2**63 - 1 - index, 'reason': 'untrusted_run'} for index in range(500)]}
        summary['reconciliation'] = {'equivalent_executions': 20000, 'conflicting_executions': 20000,
            'missing_predecessor_executions': 20000,
            'examples': [{'id': 'x' * 512, 'reason': 'recovery_predecessor_unavailable',
                          'execution_origin': {'run_id': 2**63 - 1, 'run_attempt': 2**63 - 1}} for _ in range(32)]}
        self.assertEqual(len(summary['rejected']), 2228)
        self.assertLess(len(coverage.report_json(summary)), recovery.MAX_STATUS_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'recovery-status.json'
            coverage.write_bounded(path, summary, recovery.MAX_STATUS_BYTES)
            self.assertEqual(coverage.read_json(path, max_bytes=recovery.MAX_STATUS_BYTES), summary)
            with self.assertRaises(PublicationError):
                coverage.write_bounded(path, {'padding': 'x' * recovery.MAX_STATUS_BYTES}, recovery.MAX_STATUS_BYTES)

    def test_acknowledgement_capacity_covers_400_runs_and_the_declared_worst_case(self):
        def state(run_count, artifact_count):
            return {'schema_version': 1, 'cursor': None, 'runs': [
                {'run_id': 2**63 - 1 - index, 'run_attempt': 2**63 - 1, 'head_sha': 'f' * 40,
                 'created_at': '2026-11-02T17:00:00Z', 'complete': True, 'rejections': [],
                 'artifacts': [{'id': 2**63 - 1 - index * artifact_count - number,
                                'digest': 'sha256:' + 'f' * 64} for number in range(artifact_count)]}
                for index in range(run_count)]}
        ordinary = state(400, 24)
        recovery.validate_state(ordinary)
        self.assertLess(len(coverage.canonical_json(ordinary)), recovery.MAX_STATE_BYTES)
        worst = state(recovery.MAX_RUNS, recovery.MAX_RUN_ARTIFACTS)
        worst['runs'].sort(key=lambda row: (row['created_at'], row['run_id'], row['run_attempt']))
        recovery.validate_state(worst)
        encoded = coverage.report_json(worst)
        self.assertLess(len(encoded), recovery.MAX_STATE_BYTES)
        self.assertEqual(publisher.CONTROL_FILES['recovery.json'], recovery.MAX_STATE_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'recovery.json'
            path.write_bytes(encoded)
            self.assertEqual(recovery.read_state(path), worst)
            path.write_bytes(b' ' * (recovery.MAX_STATE_BYTES * 2 + 1))
            with self.assertRaises(PublicationError):
                recovery.read_state(path)
        with self.assertRaises(PublicationError):
            recovery.validate_state(state(recovery.MAX_RUNS + 1, 1))
        conflicting = state(1, 1)
        conflicting['runs'][0]['rejections'] = [{'id': conflicting['runs'][0]['artifacts'][0]['id'], 'reason': 'invalid_checkpoint'}]
        with self.assertRaises(PublicationError):
            recovery.validate_state(conflicting)

    def test_acknowledgement_limits_compact_oldest_and_repair_finite_oversize(self):
        def row(identifier):
            return {'run_id': identifier, 'run_attempt': 1, 'head_sha': COMMIT,
                    'created_at': '2026-11-02T17:00:00Z',
                    'artifacts': [{'id': identifier, 'digest': 'sha256:' + 'f' * 64}]}
        with mock.patch.object(recovery, 'MAX_STATE_BYTES', 1800), mock.patch.object(recovery, 'MAX_RUNS', 6), \
                tempfile.TemporaryDirectory() as temporary:
            state = {'schema_version': 1, 'runs': [], 'cursor': {'before': '2026-11-02T18:00:00Z', 'page': 6, 'offset': 0}}
            for identifier in range(1, 18):
                state = recovery.merge_state(state, {'schema_version': 1, 'runs': [row(identifier)]}, now=NOW)
                self.assertLessEqual(len(coverage.canonical_json(state)), recovery.MAX_STATE_BYTES)
                self.assertLessEqual(len(state['runs']), 6)
            self.assertEqual(state['runs'][-1]['run_id'], 17)
            self.assertEqual(state['cursor']['page'], 6)
            self.assertNotIn(1, [entry['run_id'] for entry in state['runs']])
            legacy = {'schema_version': 1, 'runs': [row(identifier) for identifier in range(21, 31)]}
            self.assertGreater(len(coverage.canonical_json(legacy)), recovery.MAX_STATE_BYTES)
            self.assertLessEqual(len(coverage.canonical_json(legacy)), recovery.MAX_STATE_BYTES * 2)
            path = Path(temporary) / 'recovery.json'
            path.write_bytes(coverage.canonical_json(legacy))
            repaired = recovery.read_state(path)
            self.assertLessEqual(len(coverage.canonical_json(repaired)), recovery.MAX_STATE_BYTES)
            self.assertEqual(repaired['runs'][-1]['run_id'], 30)

    def test_rerun_staging_accepts_eight_prior_runs_plus_one_current_run(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            staged = root / 'staged'
            staged.mkdir()
            bound = (recovery.MAX_RECOVERY_RUNS + 1) * recovery.MAX_RUN_ARTIFACTS
            self.assertEqual(bound, 1728)
            for index in range(bound):
                shutil.copytree(original, staged / str(index))
            self.assertEqual(len(recovery.load_recovery_batches(staged)), bound)
            (staged / 'over-bound').mkdir()
            with self.assertRaises(PublicationError):
                recovery.load_recovery_batches(staged)

    def test_malformed_rejected_run_identifier_is_bounded_and_not_echoed(self):
        class MalformedAPI(FakeActions):
            def request(self, method, path, data=None):
                if path.startswith('actions/workflows/9/runs?'):
                    return {'workflow_runs': [run_metadata(id='private-token-' + 'x' * 10000)]}
                return super().request(method, path, data)
        with tempfile.TemporaryDirectory() as temporary:
            _, status = recovery.collect(MalformedAPI(run_metadata(), None), Path(temporary),
                {'schema_version': 1, 'runs': []}, token='read-only', now=NOW)
            self.assertEqual(status['rejected'], [{'run_id': None, 'reason': 'untrusted_run'}])
            self.assertNotIn(b'private-token', coverage.report_json(status))

    def test_authenticated_roundtrip_keeps_exact_outcome_and_source_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, artifact = archive_package(original)
            target = root / "staged" / "101-1-501"
            batch = recovery.unpack_archive(body, artifact, run_metadata(), target)
            self.assertEqual(batch["workers"][0]["attempts"], json.loads((original / "worker.json").read_text())["attempts"])
            loaded = recovery.load_recovery_batches(target.parent)
            self.assertEqual(loaded[0]["selection"], batch["selection"])
            self.assertEqual(loaded[0]["source_commit"], COMMIT)
            self.assertEqual(loaded[0]['execution_origin'], {'run_id': 101, 'run_attempt': 1})

    def test_actual_main_origin_is_required_even_when_json_claims_main(self):
        for changes in ({"head_branch": "feature"}, {"workflow_id": 10}, {"path": ".github/workflows/foreign.yml"},
                        {"repository": {"full_name": "someone/fork"}}, {"head_repository": {"full_name": "someone/fork"}},
                        {"repository": None}, {"head_repository": None}, {"event": "pull_request"}, {"status": "in_progress"}):
            with self.subTest(changes=changes), self.assertRaises(PublicationError):
                recovery.trusted_run(run_metadata(**changes), 9)

    def test_branch_controlled_and_wrong_attempt_packages_cannot_recover(self):
        for kwargs, run in (({"branch": "feature"}, run_metadata()),
                            ({"corpus": "controlled"}, run_metadata()),
                            ({"attempt": 2}, run_metadata())):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                body, artifact = archive_package(package(root, **kwargs))
                with self.assertRaises(PublicationError):
                    recovery.unpack_archive(body, artifact, run, root / "staged")
                self.assertFalse((root / "staged").exists())

    def test_zip_and_internal_digest_are_independent_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, artifact = archive_package(original)
            bad = {**artifact, "digest": "sha256:" + "f" * 64}
            with self.assertRaisesRegex(PublicationError, "archive digest"):
                recovery.unpack_archive(body, bad, run_metadata(), root / "a")
            body, artifact = archive_package(original, mutate=lambda entries: entries.update({"worker.json": b"{}"}))
            with self.assertRaisesRegex(PublicationError, "file identity"):
                recovery.unpack_archive(body, artifact, run_metadata(), root / "b")
            body, artifact = archive_package(original, mutate=lambda entries: entries.update({"../outside": b"x"}))
            with self.assertRaisesRegex(PublicationError, "unexpected"):
                recovery.unpack_archive(body, artifact, run_metadata(), root / "c")
            self.assertFalse((root / "outside").exists())

    def test_duplicate_zip_members_and_symlink_entries_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            for corruption in ("duplicate", "symlink"):
                out = io.BytesIO()
                with zipfile.ZipFile(out, "w") as archive:
                    for path in original.iterdir():
                        if corruption == "symlink" and path.name == "worker.json":
                            entry = zipfile.ZipInfo(path.name)
                            entry.create_system = 3
                            entry.external_attr = 0o120777 << 16
                            archive.writestr(entry, path.read_bytes())
                        else:
                            archive.writestr(path.name, path.read_bytes())
                    if corruption == "duplicate":
                        archive.writestr("worker.json", (original / "worker.json").read_bytes())
                body = out.getvalue()
                _, artifact = archive_package(original)
                artifact["digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
                with self.subTest(corruption=corruption), self.assertRaises(PublicationError):
                    recovery.unpack_archive(body, artifact, run_metadata(), root / corruption)

    def test_redirect_drops_authorization_and_rejects_http(self):
        request = urllib.request.Request("https://api.github.com/example", headers={"Authorization": "Bearer private"})
        handler = recovery.StripRedirectCredentials()
        redirected = handler.redirect_request(request, None, 302, "redirect", {}, "https://signed.example/artifact")
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(PublicationError):
            handler.redirect_request(request, None, 302, "redirect", {}, "http://signed.example/artifact")

    def test_acknowledged_run_is_not_downloaded_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            api = FakeActions(run_metadata(), artifact)
            fetch = mock.Mock(return_value=body)
            state, status = recovery.collect(api, root / "staged", {"schema_version": 1, "runs": []},
                token="read-only", fetch_archive=fetch, now=NOW)
            self.assertEqual((status["status"], status["runs"]), ("ready", 1))
            self.assertEqual(state["runs"][0]["artifacts"], [{"id": 501, "digest": artifact["digest"]}])
            fresh = FakeActions(run_metadata(), artifact)
            again, _ = recovery.collect(fresh, root / "next", state, token="read-only", fetch_archive=fetch, now=NOW)
            self.assertEqual(again, state)
            self.assertEqual(fetch.call_count, 1)
            self.assertFalse(any("artifacts?" in path for _, path in fresh.calls))

    def test_soft_transport_budget_defers_without_losing_cursor_or_misclassifying_artifacts(self):
        class BudgetedActions(FakeActions):
            seconds = 120

            def remaining_seconds(self):
                return self.seconds

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            api = BudgetedActions(run_metadata(), artifact)
            fetch = mock.Mock(return_value=body)
            old = {'schema_version': 1, 'runs': []}
            deferred, status = recovery.collect(api, root / 'deferred', old,
                token='read-only', fetch_archive=fetch, now=NOW)
            self.assertEqual(status['status'], 'deferred')
            self.assertEqual(status['runs'], 0)
            self.assertEqual(deferred['runs'], [])
            self.assertEqual(deferred['cursor'], {'before': '2026-11-03T00:00:00Z', 'page': 1, 'offset': 0})
            self.assertEqual(recovery.load_recovery_batches(root / 'deferred'), [])
            fetch.assert_not_called()
            self.assertEqual(status['rejected'], [])

            api.seconds = 600
            resumed, completed = recovery.collect(api, root / 'resumed', deferred,
                token='read-only', fetch_archive=fetch, now=NOW)
            self.assertEqual(completed['status'], 'ready')
            self.assertEqual(resumed['runs'][0]['artifacts'],
                [{'id': artifact['id'], 'digest': artifact['digest']}])
            self.assertEqual(len(recovery.load_recovery_batches(root / 'resumed')), 1)
            self.assertEqual(fetch.call_count, 1)

    def test_artifact_inventory_defers_between_pages_and_resumes_without_false_receipt(self):
        class PaginatedBudget(FakeActions):
            seconds = 600
            drop_after_first = True

            def remaining_seconds(self):
                return self.seconds

            def request(self, method, path, data=None):
                if path.startswith("actions/runs/101/artifacts?"):
                    self.calls.append((method, path))
                    if path.endswith("page=1"):
                        if self.drop_after_first:
                            self.seconds = 120
                        return {"total_count": 101, "artifacts": [{"name": "unrelated"}] * 100}
                    if path.endswith("page=2"):
                        return {"total_count": 101, "artifacts": [self.artifact]}
                    raise AssertionError(path)
                return super().request(method, path, data)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            api = PaginatedBudget(run_metadata(), artifact)
            fetch = mock.Mock(return_value=body)
            deferred, summary = recovery.collect(api, root / "deferred",
                {"schema_version": 1, "runs": []}, token="read-only",
                fetch_archive=fetch, now=NOW)
            self.assertEqual(summary["status"], "deferred")
            self.assertEqual(summary["runs"], 0)
            self.assertEqual(summary["rejected"], [])
            self.assertEqual(deferred["runs"], [])
            self.assertEqual(deferred["cursor"],
                {"before": "2026-11-03T00:00:00Z", "page": 1, "offset": 0})
            self.assertFalse(any("page=2" in path for _, path in api.calls))
            fetch.assert_not_called()

            api.seconds, api.drop_after_first = 600, False
            resumed, completed = recovery.collect(api, root / "resumed", deferred,
                token="read-only", fetch_archive=fetch, now=NOW)
            self.assertEqual(completed["status"], "ready")
            self.assertEqual(resumed["runs"][0]["artifacts"],
                [{"id": artifact["id"], "digest": artifact["digest"]}])
            self.assertTrue(any("page=2" in path for _, path in api.calls))
            self.assertEqual(fetch.call_count, 1)

    def test_low_budget_does_not_request_metadata_or_attempt_current_run_acknowledgement(self):
        class BudgetedActions(FakeActions):
            def remaining_seconds(self):
                return 120

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            api = BudgetedActions(run_metadata(), artifact)
            for current in (None, 101):
                with self.subTest(current_run=current):
                    state, summary = recovery.collect(api, root / f"low-{current}",
                        {'schema_version': 1, 'runs': []}, token='read-only',
                        current_run=current, now=NOW, fetch_archive=lambda *_: body)
                    self.assertEqual(summary['status'], 'deferred')
                    self.assertEqual(state['runs'], [])
                    self.assertEqual(api.calls, [])
                    self.assertEqual(summary['cursor'] is None, current is not None)

    def test_rerun_own_collection_deferral_is_reported_without_claiming_checkpoint_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, artifact = archive_package(original)
            plan = root / 'plan'
            plan.mkdir(exist_ok=True)
            api = FakeActions(run_metadata(), artifact)
            calls = 0
            original_collect = recovery.collect

            def limited(github, directory, state, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    return state, {'status': 'deferred', 'runs': 0, 'bytes': 0,
                        'rejected': [], 'cursor': state.get('cursor')}
                return original_collect(github, directory, state, **kwargs, now=NOW,
                    fetch_archive=lambda *_: body)

            with mock.patch.object(recovery, 'collect', side_effect=limited), \
                 mock.patch.dict(recovery.os.environ, {'GITHUB_RUN_ATTEMPT': '2'}):
                summary = recovery.recover_plan(api, plan, COMMIT, token='read-only', current_id=101)
            self.assertEqual(summary['status'], 'deferred')
            self.assertEqual(summary['runs'], 0)  # Current run is intentionally excluded from historical recovery.
            self.assertEqual(json.loads((plan / 'recovery-status.json').read_text())['status'], 'deferred')

    def test_signed_cohort_production_guard_accepts_only_main_manual_or_scheduled_event(self):
        from scripts import skillspector_cohort_publish_cli as cli
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.json'
            path.write_text('{}')
            correct = {'GITHUB_REPOSITORY': cli.REPOSITORY, 'GITHUB_REF': 'refs/heads/main'}
            for event in ('workflow_dispatch', 'schedule'):
                with self.subTest(event=event), \
                     mock.patch.dict(cli.os.environ, {**correct, 'GITHUB_EVENT_NAME': event}), \
                     mock.patch('sys.argv', ['cohort', '--candidate', str(path)]), \
                     mock.patch.object(cli, 'publish_one') as published:
                    self.assertEqual(cli.main(), 0)
                    published.assert_called_once()
            for env in ({**correct, 'GITHUB_EVENT_NAME': 'pull_request'},
                        {'GITHUB_REPOSITORY': cli.REPOSITORY, 'GITHUB_REF': 'refs/heads/other',
                         'GITHUB_EVENT_NAME': 'schedule'}):
                with self.subTest(env=env), mock.patch.dict(cli.os.environ, env), \
                     mock.patch('sys.argv', ['cohort', '--candidate', str(path)]), \
                     mock.patch.object(cli, 'publish_one') as published, \
                     self.assertRaises(PublicationError):
                    cli.main()
                published.assert_not_called()

    def test_controlled_main_artifact_is_acknowledged_but_never_staged_for_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root, corpus="controlled"))
            state, status = recovery.collect(FakeActions(run_metadata(), artifact), root / "staged",
                {"schema_version": 1, "runs": []}, token="read-only", fetch_archive=lambda *_: body, now=NOW)
            self.assertEqual(len(state["runs"]), 1)
            self.assertEqual(recovery.load_recovery_batches(root / "staged"), [])
            self.assertEqual(status["rejected"], [{"artifact_id": 501, "reason": "excluded_controlled"}])

    def test_obsolete_policy_is_acknowledged_without_poisoning_current_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            document = json.loads((original / "worker.json").read_text())
            document["scanner"]["revision"] = "d" * 40
            contents = coverage.report_json(document)
            (original / "worker.json").write_bytes(contents)
            provenance = json.loads((original / "provenance.json").read_text())
            provenance["files"]["worker.json"] = {"bytes": len(contents), "digest": "sha256:" + hashlib.sha256(contents).hexdigest()}
            (original / "provenance.json").write_bytes(coverage.report_json(provenance))
            body, artifact = archive_package(original)
            _, status = recovery.collect(FakeActions(run_metadata(), artifact), root / "staged",
                {"schema_version": 1, "runs": []}, token="read-only", fetch_archive=lambda *_: body, now=NOW)
            self.assertEqual(recovery.load_recovery_batches(root / "staged"), [])
            self.assertEqual(status["rejected"][0]["reason"], "unsupported_policy")

    def test_earlier_run_attempt_is_authenticated_through_its_own_api_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            api = FakeActions(run_metadata(run_attempt=2), artifact)
            state, _ = recovery.collect(api, root / "staged", {"schema_version": 1, "runs": []},
                token="read-only", fetch_archive=lambda *_: body, now=NOW)
            self.assertIn(("GET", "actions/runs/101/attempts/1"), api.calls)
            self.assertEqual(state["runs"][0]["run_attempt"], 2)

    def test_fresh_prepare_recovers_old_main_artifact_under_new_source_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = package(root)
            body, artifact = archive_package(old)
            new_plan = root / "fresh-plan"
            new_plan.mkdir()
            selection = json.loads((old / "selection.json").read_text())
            summary = json.loads((old / "coverage.json").read_text())
            next_commit = "e" * 40
            summary["source_commit"] = next_commit
            coverage.write_bounded(new_plan / "selection.json", selection, coverage.MAX_SELECTION_BYTES)
            coverage.write_bounded(new_plan / "coverage.json", summary, coverage.MAX_DISCOVERY_BYTES)
            with mock.patch.object(recovery, "download_archive", return_value=body):
                recovery.recover_plan(FakeActions(run_metadata(), artifact), new_plan, next_commit, token="read-only")
            self.assertEqual(json.loads((new_plan / 'recovery-status.json').read_text())['recovered_sources'], 1)
            restored = coverage.read_bundle(new_plan / "previous")
            original_worker = json.loads((old / "worker.json").read_text())
            outcome = original_worker["attempts"][0]
            identifier = outcome["attempt"]["id"]
            self.assertEqual(restored["manifest"]["source_commit"], next_commit)
            self.assertEqual(restored["attempts"][identifier], outcome["attempt"])
            self.assertEqual(restored["records"][identifier]["scanned_at"], outcome["record"]["scanned_at"])
            self.assertEqual(restored["records"][identifier]["findings"], outcome["record"]["findings"])
            self.assertEqual(coverage.plan_attempts(selection, restored, 0, 1, 8), [])
            self.assertFalse((new_plan / "recovery").exists())
            self.assertFalse((new_plan / "previous-recovered").exists())

    def test_cursor_reaches_run_501_even_when_new_runs_arrive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            runs = [run_metadata(id=identifier) for identifier in range(601, 100, -1)]
            class PagedActions(FakeActions):
                arrivals = []
                def request(self, method, path, data=None):
                    if path.startswith('actions/workflows/9/runs?'):
                        self.calls.append((method, path))
                        query = urllib.parse.parse_qs(path.partition('?')[2])
                        self.assert_anchor = query['created'][0]
                        page = int(query['page'][0])
                        anchor = query['created'][0].removeprefix('<=')
                        eligible = [row for row in self.arrivals + runs if row['created_at'] <= anchor]
                        return {'workflow_runs': eligible[(page - 1) * 100:page * 100]}
                    if '/artifacts?' in path and not path.startswith('actions/runs/101/'):
                        return {'total_count': 0, 'artifacts': []}
                    return super().request(method, path, data)
            api = PagedActions(run_metadata(), artifact)
            state, status = recovery.collect(api, root / 'first', {'schema_version': 1, 'runs': []},
                token='read-only', fetch_archive=lambda *_: body, now=NOW)
            self.assertEqual(status['status'], 'deferred')
            self.assertEqual(state['cursor']['page'], 6)
            anchor = api.assert_anchor
            # A new run after the anchor is intentionally outside this stable cycle.
            next_api = PagedActions(run_metadata(), artifact)
            next_api.arrivals = [run_metadata(id=999, created_at='2026-11-03T01:00:00Z')]
            next_state, status = recovery.collect(next_api, root / 'second', state,
                token='read-only', fetch_archive=lambda *_: body, now=NOW)
            self.assertEqual(next_api.assert_anchor, anchor)
            self.assertIsNone(next_state['cursor'])
            self.assertEqual(len(recovery.load_recovery_batches(root / 'second')), 1)
            self.assertEqual(next_state['runs'][0]['run_id'], 101)

    def test_short_checkpoint_download_defers_without_quarantine_and_recovers_on_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            state = {'schema_version': 1, 'runs': []}
            # Reproduce an interrupted HTTP read returning an intact prefix.
            # The artifact listing still advertises the full immutable ZIP size.
            with self.assertRaisesRegex(recovery.GitHubTransportError, 'checkpoint download incomplete'):
                recovery.collect(FakeActions(run_metadata(), artifact), root / 'truncated', state,
                    token='read-only', fetch_archive=lambda *_: body[:-1], now=NOW)
            self.assertEqual(state, {'schema_version': 1, 'runs': []})
            self.assertFalse((root / 'truncated' / '101-1-501').exists())
            restored, status = recovery.collect(FakeActions(run_metadata(), artifact), root / 'retried', state,
                token='read-only', fetch_archive=lambda *_: body, now=NOW)
            self.assertEqual(status['status'], 'ready')
            self.assertEqual(restored['runs'][0]['rejections'], [])
            self.assertEqual(restored['runs'][0]['artifacts'],
                             [{'id': artifact['id'], 'digest': artifact['digest']}])
            self.assertEqual(len(recovery.load_recovery_batches(root / 'retried')), 1)

    def test_malformed_newer_artifact_is_quarantined_without_starving_valid_older_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body, artifact = archive_package(package(root))
            bad_artifact = {**artifact, 'id': 502, 'digest': 'sha256:' + 'f' * 64,
                            'workflow_run': {**artifact['workflow_run'], 'id': 102}}
            class MixedActions(FakeActions):
                def request(self, method, path, data=None):
                    if path.startswith('actions/workflows/9/runs?'):
                        return {'workflow_runs': [run_metadata(id=102), run_metadata()]}
                    if path.startswith('actions/runs/102/artifacts?'):
                        return {'total_count': 1, 'artifacts': [bad_artifact]}
                    return super().request(method, path, data)
            state, status = recovery.collect(MixedActions(run_metadata(), artifact), root / 'staged',
                {'schema_version': 1, 'runs': []}, token='read-only', fetch_archive=lambda *_: body, now=NOW)
            self.assertEqual(status['rejected'], [{'artifact_id': 502, 'reason': 'invalid_checkpoint'}])
            self.assertEqual(len(recovery.load_recovery_batches(root / 'staged')), 1)
            rejected = next(row for row in state['runs'] if row['run_id'] == 102)
            self.assertEqual(rejected['artifacts'], [])
            self.assertEqual(rejected['rejections'], [{'id': 502, 'reason': 'invalid_checkpoint'}])

    def test_failed_job_retry_restores_exact_acknowledged_prefix_before_new_scans(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, artifact = archive_package(original)
            api = FakeActions(run_metadata(run_attempt=2), artifact)
            output = root / 'resumed.json'
            count = recovery.restore_current(api, root / 'plan', output, token='read-only', partition=0,
                fetch_archive=lambda *_: body, environment={'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2',
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': COMMIT})
            self.assertEqual(count, 1)
            self.assertEqual(json.loads(output.read_text())['attempts'], json.loads((original / 'worker.json').read_text())['attempts'])
            self.assertIn(('GET', 'actions/runs/101/attempts/1'), api.calls)

    def test_same_run_resume_rejects_noninteger_artifact_id_before_download_or_path_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            _, artifact = archive_package(original)
            artifact['id'] = '../outside'
            download = mock.Mock()
            with self.assertRaises(PublicationError):
                recovery.restore_current(FakeActions(run_metadata(run_attempt=2), artifact), root / 'plan', root / 'resumed.json',
                    token='read-only', partition=0, fetch_archive=download, environment={'GITHUB_RUN_ID': '101',
                        'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': COMMIT})
            download.assert_not_called()
            self.assertFalse((root / 'outside').exists())

    def test_retry_after_prepare_recovery_does_not_restore_the_same_attempt_twice(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, artifact = archive_package(original)
            selection = json.loads((original / 'selection.json').read_text())
            completed = json.loads((original / 'worker.json').read_text())
            coverage.merge_reports(selection, None, [completed], source_commit=COMMIT, output_dir=root / 'plan' / 'previous')
            output = root / 'resumed.json'
            count = recovery.restore_current(FakeActions(run_metadata(run_attempt=2), artifact), root / 'plan', output,
                token='read-only', partition=0, fetch_archive=lambda *_: body,
                environment={'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': COMMIT})
            self.assertEqual(count, 0)
            self.assertFalse(output.exists())

    def test_retry_skips_independent_equal_count_progress_recovered_during_prepare(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            body, artifact = archive_package(original)
            selection = json.loads((original / "selection.json").read_text())
            candidate = json.loads((original / "worker.json").read_text())
            with mock.patch.object(coverage.scanner, "now", return_value="2026-11-03T08:00:00Z"):
                independent = worker(selection, [record(selection["sources"][0])])
            self.assertNotEqual(
                candidate["attempts"][0]["attempt"]["last_attempted_at"],
                independent["attempts"][0]["attempt"]["last_attempted_at"])
            coverage.merge_reports(selection, None, [independent], source_commit=COMMIT,
                                   output_dir=root / "plan" / "previous")
            output = root / "resumed.json"
            count = recovery.restore_current(FakeActions(run_metadata(run_attempt=2), artifact),
                root / "plan", output, token="read-only", partition=0,
                fetch_archive=lambda *_: body,
                environment={"GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "2",
                             "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": COMMIT})
            self.assertEqual(count, 0)
            self.assertFalse(output.exists())

    def test_skipped_same_count_resume_keeps_unseen_warning_artifact_recoverable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            selection = json.loads((original / 'selection.json').read_text())
            subject = selection['sources'][0]
            with mock.patch.object(coverage.scanner, 'now', return_value='2026-11-03T08:00:00Z'):
                independent = worker(selection, [record(subject)])
            coverage.merge_reports(selection, None, [independent], source_commit=COMMIT,
                                   output_dir=root / 'plan' / 'previous')
            raw = fixtures.upstream_report()
            raw['issues'] = [{'id': 'PI1', 'severity': 'HIGH', 'explanation': 'Retain the unseen warning.',
                              'location': {'file': 'SKILL.md', 'start_line': 1}}]
            adverse = coverage.scanner.normalize_report_v3(record(subject), json.dumps(raw).encode(), 1, Path('/source'))
            coverage.write_bounded(root / 'adverse-worker.json', worker(selection, [adverse]), coverage.MAX_WORKER_BYTES)
            recovery.pack(root / 'plan', root / 'adverse-worker.json', root / 'adverse-package', slice_index=1, environment={
                'GITHUB_REPOSITORY': recovery.REPOSITORY, 'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_SHA': COMMIT, 'GITHUB_REF_NAME': 'main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'SCAN_CORPUS': 'catalog'})
            body, artifact = archive_package(root / 'adverse-package')
            output = root / 'resumed.json'
            count = recovery.restore_current(FakeActions(run_metadata(run_attempt=2), artifact), root / 'plan', output,
                token='read-only', partition=0, fetch_archive=lambda *_: body,
                environment={'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': COMMIT})
            self.assertEqual(count, 0)
            self.assertFalse(output.exists())
            self.assertFalse((root / 'plan' / 'recovery.json').exists())
            self.assertFalse((root / 'plan' / 'previous' / 'recovery.json').exists())
            # Actual assembly consumed an empty current-attempt checkpoint;
            # the skipped older warning was never part of its merge argv.
            coverage.write_bounded(root / 'empty-worker.json', worker(selection), coverage.MAX_WORKER_BYTES)
            recovery.pack(root / 'plan', root / 'empty-worker.json', root / 'current-package', slice_index=1, environment={
                'GITHUB_REPOSITORY': recovery.REPOSITORY, 'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2',
                'GITHUB_SHA': COMMIT, 'GITHUB_REF_NAME': 'main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'SCAN_CORPUS': 'catalog'})
            consumed = root / 'plan' / 'consumed-checkpoints.json'
            paths = recovery.assembly_worker_paths(root / 'current-package', selection, COMMIT, run_id=101, run_attempt=2)
            recovery.write_consumed_checkpoints(paths, consumed, source_commit=COMMIT, run_id=101, run_attempt=2)
            api = FakeActions(run_metadata(run_attempt=2), artifact)
            with mock.patch.object(recovery, 'GitHub', return_value=api), \
                    mock.patch.object(recovery, 'download_archive', return_value=body), \
                    mock.patch.dict('os.environ', {'GITHUB_TOKEN': 'read-only', 'GITHUB_RUN_ID': '101',
                        'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': COMMIT}), \
                    mock.patch('sys.argv', ['skillspector_recovery', 'acknowledge', '--plan-dir', str(root / 'plan'),
                        '--report-dir', str(root / 'plan' / 'previous'), '--consumed-manifest', str(consumed)]):
                self.assertEqual(recovery.main(), 0)
            receipt = recovery.read_state(root / 'plan' / 'previous' / 'recovery.json')['runs'][0]
            self.assertEqual(receipt['artifacts'], [])
            self.assertEqual(receipt['rejections'], [])
            self.assertFalse(receipt['complete'])
            with mock.patch.object(recovery, 'download_archive', return_value=body):
                result = recovery.recover_plan(api, root / 'plan', COMMIT, token='read-only')
            recovered = coverage.read_bundle(root / 'plan' / 'previous')['records'][subject['id']]
            self.assertEqual(result['reconciliation']['conflicting_executions'], 1)
            self.assertEqual(recovered['finding_count'], 1)
            self.assertEqual(recovered['status'], 'partial')
            self.assertIn('recovery_conflict', coverage.reason_codes(recovered))
            self.assertEqual(recovery.read_state(root / 'plan' / 'recovery.json')['runs'][0]['artifacts'],
                             [{'id': artifact['id'], 'digest': artifact['digest']}])
            self.assertTrue(recovery.read_state(root / 'plan' / 'recovery.json')['runs'][0]['complete'])

    def test_ack_only_consumes_selected_packages_and_defers_same_attempt_or_late_evidence(self):
        for late, mismatch in ((False, False), (True, False), (False, True)):
            with self.subTest(late=late, mismatch=mismatch), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = package(root)
                selection = json.loads((original / 'selection.json').read_text())
                coverage.merge_reports(selection, None, [worker(selection, [record(selection['sources'][0])])],
                    source_commit=COMMIT, output_dir=root / 'plan' / 'previous')
                raw = fixtures.upstream_report()
                raw['issues'] = [{'id': 'PI1', 'severity': 'HIGH', 'explanation': 'Preserve the unconsumed current warning.',
                    'location': {'file': 'SKILL.md', 'start_line': 1}}]
                warning = coverage.scanner.normalize_report_v3(record(selection['sources'][0]), json.dumps(raw).encode(), 1, Path('/source'))
                bodies, artifacts = {}, []
                for index, values in ((1, []), (2, [warning])):
                    coverage.write_bounded(root / f'worker-{index}.json', worker(selection, values), coverage.MAX_WORKER_BYTES)
                    recovery.pack(root / 'plan', root / f'worker-{index}.json', root / f'package-{index}', slice_index=index,
                        environment={'GITHUB_REPOSITORY': recovery.REPOSITORY, 'GITHUB_RUN_ID': '101',
                            'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': COMMIT, 'GITHUB_REF_NAME': 'main',
                            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'SCAN_CORPUS': 'catalog'})
                    body, artifact = archive_package(root / f'package-{index}')
                    artifact.update(id=500 + index, name=f'skillspector-checkpoint-a2-p0-s{index}')
                    bodies[artifact['id']] = body
                    artifacts.append(artifact)
                if mismatch:
                    # The API name matches, but its valid ZIP differs from the
                    # package actually selected for assembly.
                    provenance = json.loads((root / 'package-2' / 'provenance.json').read_text())
                    provenance['slice'] = 1
                    coverage.write_bounded(root / 'package-2' / 'provenance.json', provenance, recovery.MAX_PROVENANCE_BYTES)
                    body, artifact = archive_package(root / 'package-2')
                    artifact.update(id=501, name='skillspector-checkpoint-a2-p0-s1')
                    artifacts, bodies = [artifact], {501: body}
                consumed = root / 'plan' / 'consumed-checkpoints.json'
                paths = recovery.assembly_worker_paths(root / 'package-1', selection, COMMIT, run_id=101, run_attempt=2)
                recovery.write_consumed_checkpoints(paths, consumed, source_commit=COMMIT, run_id=101, run_attempt=2)
                prior = {'schema_version': 1, 'runs': [{'run_id': 99, 'run_attempt': 1, 'head_sha': COMMIT,
                    'created_at': '2026-11-02T17:00:00Z', 'artifacts': [{'id': 400, 'digest': 'sha256:' + 'a' * 64}]}],
                    'cursor': {'before': '2026-11-03T00:00:00Z', 'page': 1, 'offset': 0}}
                coverage.write_bounded(root / 'plan' / 'recovery.json', prior, recovery.MAX_STATE_BYTES)
                class VisibilityAPI(FakeActions):
                    visible = artifacts[:1] if late else artifacts
                    def request(self, method, path, data=None):
                        if path.startswith('actions/runs/101/artifacts?'):
                            return {'total_count': len(self.visible), 'artifacts': self.visible}
                        return super().request(method, path, data)
                api, downloaded = VisibilityAPI(run_metadata(run_attempt=2), None), []
                def download(identifier, _token):
                    downloaded.append(identifier)
                    return bodies[identifier]
                with mock.patch.object(recovery, 'GitHub', return_value=api), \
                        mock.patch.object(recovery, 'download_archive', side_effect=download), \
                        mock.patch.dict('os.environ', {'GITHUB_TOKEN': 'read-only', 'GITHUB_RUN_ID': '101',
                            'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': COMMIT}), \
                        mock.patch('sys.argv', ['skillspector_recovery', 'acknowledge', '--plan-dir', str(root / 'plan'),
                            '--report-dir', str(root / 'plan' / 'previous'), '--consumed-manifest', str(consumed)]):
                    self.assertEqual(recovery.main(), 0)
                state = recovery.read_state(root / 'plan' / 'previous' / 'recovery.json')
                current = next(row for row in state['runs'] if row['run_id'] == 101)
                self.assertFalse(current['complete'])
                self.assertEqual(current['rejections'], [])
                self.assertEqual([row['id'] for row in current['artifacts']], [] if mismatch else [501])
                self.assertEqual(state['cursor'], prior['cursor'])
                self.assertIn(prior['runs'][0], state['runs'])
                self.assertEqual(downloaded, [501])
                api.visible = artifacts
                with mock.patch.object(recovery, 'download_archive', side_effect=download):
                    result = recovery.recover_plan(api, root / 'plan', COMMIT, token='read-only')
                value = coverage.read_bundle(root / 'plan' / 'previous')['records'][selection['sources'][0]['id']]
                self.assertEqual(value['finding_count'], 1)
                self.assertEqual(value['status'], 'partial')
                self.assertEqual(result['reconciliation']['conflicting_executions'], 1)
                closed = next(row for row in recovery.read_state(root / 'plan' / 'recovery.json')['runs'] if row['run_id'] == 101)
                self.assertTrue(closed['complete'])

    def test_consumed_manifest_rejects_wrong_identity_oversize_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package(root)
            selection = coverage.load_selection(root / 'plan' / 'selection.json')
            paths = recovery.assembly_worker_paths(root / 'package', selection, COMMIT, run_id=101, run_attempt=1)
            manifest = root / 'consumed.json'
            recovery.write_consumed_checkpoints(paths, manifest, source_commit=COMMIT, run_id=101, run_attempt=1)
            digest = coverage.sha256_digest((root / 'plan' / 'selection.json').read_bytes())
            with self.assertRaises(PublicationError):
                recovery.read_consumed_checkpoints(manifest, source_commit=COMMIT, run_id=101, run_attempt=2, selection_digest=digest)
            with self.assertRaises(PublicationError):
                recovery.read_consumed_checkpoints(manifest, source_commit=COMMIT, run_id=101, run_attempt=1,
                    selection_digest='sha256:' + '0' * 64)
            link = root / 'link.json'
            link.symlink_to(manifest)
            with self.assertRaises(PublicationError):
                recovery.read_consumed_checkpoints(link, source_commit=COMMIT, run_id=101, run_attempt=1, selection_digest=digest)
            manifest.write_bytes(b' ' * (recovery.MAX_CONSUMED_BYTES + 1))
            with self.assertRaises(PublicationError):
                recovery.read_consumed_checkpoints(manifest, source_commit=COMMIT, run_id=101, run_attempt=1, selection_digest=digest)

    def test_controlled_main_job_retry_never_requests_production_resume_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package(root, corpus='controlled')
            api = mock.Mock()
            result = recovery.restore_current(api, root / 'plan', root / 'resumed.json', token='read-only', partition=0,
                environment={'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_REF': 'refs/heads/main', 'SCAN_CORPUS': 'catalog'})
            self.assertEqual(result, 0)
            api.request.assert_not_called()
            self.assertFalse((root / 'resumed.json').exists())

    def test_unavailable_ancestry_or_earlier_attempt_api_preserves_receipt_and_cursor(self):
        for failure_point in ('ancestry_503', 'ancestry_missing', 'attempt_503', 'attempt_missing', 'attempt_incomplete'):
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = package(root)
                body, artifact = archive_package(original)
                previous = root / 'plan' / 'previous'
                previous.mkdir()
                state = {'schema_version': 1, 'runs': [],
                         'cursor': {'before': '2026-11-02T18:00:00Z', 'page': 1, 'offset': 0}}
                coverage.write_bounded(previous / 'recovery.json', state, recovery.MAX_STATE_BYTES)
                before = (previous / 'recovery.json').read_bytes()
                class UnavailableAPI(FakeActions):
                    def request(self, method, path, data=None):
                        if failure_point.startswith('ancestry') and path == 'git/ref/heads/main':
                            return {'object': {'sha': 'd' * 40}}
                        if path.startswith('compare/') or path == 'actions/runs/101/attempts/1':
                            if failure_point == 'attempt_incomplete':
                                return {'id': 101, 'run_attempt': 1}
                            if failure_point.endswith('missing'):
                                return None
                            raise recovery.GitHubTransportError('GitHub API unavailable; recovery deferred')
                        return super().request(method, path, data)
                metadata = run_metadata(run_attempt=2 if failure_point.startswith('attempt') else 1)
                with mock.patch.object(recovery, 'download_archive', return_value=body), \
                        self.assertRaises(recovery.GitHubTransportError):
                    recovery.recover_plan(UnavailableAPI(metadata, artifact), root / 'plan', COMMIT, token='read-only')
                self.assertEqual((previous / 'recovery.json').read_bytes(), before)
                self.assertFalse((root / 'plan' / 'recovery.json').exists())
                self.assertFalse((root / 'plan' / 'recovery-status.json').exists())

    def test_same_plan_retry_clears_unacknowledged_staging_without_quarantining_valid_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = package(root)
            first_body, first = archive_package(original)
            def next_slice(entries):
                provenance = json.loads(entries['provenance.json'])
                provenance['slice'] = 2
                entries['provenance.json'] = coverage.report_json(provenance)
            second_body, second = archive_package(original, mutate=next_slice)
            second.update(id=502, name='skillspector-checkpoint-a1-p0-s2')
            class TwoArtifacts(FakeActions):
                def request(self, method, path, data=None):
                    if path.startswith('actions/runs/101/artifacts?'):
                        return {'total_count': 2, 'artifacts': [first, second]}
                    return super().request(method, path, data)
            def fail_second(identifier, _token):
                if identifier == 502:
                    raise urllib.error.URLError(TimeoutError('interrupted download'))
                return first_body
            with mock.patch.object(recovery, 'download_archive', side_effect=fail_second), self.assertRaises(urllib.error.URLError):
                recovery.recover_plan(TwoArtifacts(run_metadata(), first), root / 'plan', COMMIT, token='read-only')
            self.assertTrue((root / 'plan' / 'recovery' / '101-1-501').is_dir())
            with mock.patch.object(recovery, 'download_archive', side_effect=lambda identifier, _token: first_body if identifier == 501 else second_body):
                result = recovery.recover_plan(TwoArtifacts(run_metadata(), first), root / 'plan', COMMIT, token='read-only')
            self.assertEqual(result['rejected'], [])
            self.assertEqual(result['recovered_sources'], 1)
            self.assertFalse((root / 'plan' / 'recovery').exists())

    def test_nine_packed_runs_advance_window_and_backfill_late_parent_without_resetting_child(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subjects = [item(id=f'fixture/root-{index}', path=f'skills/root-{index}') for index in range(8)]
            selection = {'schema_version': 1, 'sources': subjects}
            summary = fixtures.QueueTests().discovery_summary(selection)
            with mock.patch.object(coverage.scanner, 'now', return_value='2026-11-02T17:00:00Z'):
                parent_record = record(subjects[0], 'partial', 'runtime_limit')
                parent_worker = worker(selection, [parent_record])
                coverage.merge_reports(selection, None, [parent_worker], source_commit=COMMIT,
                    output_dir=root / 'parent-baseline', discovery_summary=summary)
            parent = coverage.read_bundle(root / 'parent-baseline')
            with mock.patch.object(coverage.scanner, 'now', return_value='2026-11-02T18:00:00Z'):
                child_record = record(subjects[0], 'error', 'acquisition_failed', 'static-extended-v3')
                child_worker = worker(selection, [child_record], parent)
                healthy = [worker(selection, [record(subject)]) for subject in subjects[1:]]
            original_child_attempt = copy.deepcopy(child_worker['attempts'][0]['attempt'])
            workers = [child_worker, *healthy, parent_worker]
            run_ids = list(range(900, 891, -1))
            runs, artifacts, bodies = [], {}, {}
            for index, (run_id, value) in enumerate(zip(run_ids, workers)):
                plan = root / f'origin-{run_id}'
                plan.mkdir()
                coverage.write_bounded(plan / 'selection.json', selection, coverage.MAX_SELECTION_BYTES)
                coverage.write_bounded(plan / 'coverage.json', summary, coverage.MAX_DISCOVERY_BYTES)
                coverage.write_bounded(plan / 'worker.json', value, coverage.MAX_WORKER_BYTES)
                packaged = plan / 'packaged'
                recovery.pack(plan, plan / 'worker.json', packaged, slice_index=1, environment={
                    'GITHUB_REPOSITORY': recovery.REPOSITORY, 'GITHUB_RUN_ID': str(run_id), 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_SHA': COMMIT, 'GITHUB_REF_NAME': 'main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'SCAN_CORPUS': 'catalog'})
                body, artifact = archive_package(packaged)
                artifact.update(id=10000 + run_id, workflow_run={'id': run_id, 'head_sha': COMMIT, 'head_branch': 'main'})
                artifacts[run_id], bodies[artifact['id']] = artifact, body
                runs.append(run_metadata(id=run_id, created_at=f'2026-11-02T19:{9 - index:02d}:00Z'))
            class WindowAPI(FakeActions):
                def request(self, method, path, data=None):
                    if path.startswith('actions/workflows/9/runs?'):
                        return {'workflow_runs': runs}
                    if path.startswith('actions/runs/') and '/artifacts?' in path:
                        run_id = int(path.split('/')[2])
                        return {'total_count': 1, 'artifacts': [artifacts[run_id]]}
                    return super().request(method, path, data)
            plan = root / 'current-plan'
            plan.mkdir()
            coverage.write_bounded(plan / 'selection.json', selection, coverage.MAX_SELECTION_BYTES)
            coverage.write_bounded(plan / 'coverage.json', summary, coverage.MAX_DISCOVERY_BYTES)
            api, downloaded = WindowAPI(run_metadata(), None), []
            def download(identifier, _token):
                downloaded.append(identifier)
                return bodies[identifier]
            with mock.patch.object(recovery, 'download_archive', side_effect=download):
                first = recovery.recover_plan(api, plan, COMMIT, token='read-only')
            first_bundle = coverage.read_bundle(plan / 'previous')
            first_attempt = first_bundle['attempts'][subjects[0]['id']]
            self.assertEqual(first_attempt['attempt_count'], 2)
            self.assertEqual(first_attempt['history'], original_child_attempt['history'])
            self.assertEqual(first['cursor']['offset'], 8)
            self.assertEqual(first['reconciliation']['missing_predecessor_executions'], 1)
            self.assertEqual(first_bundle['manifest']['coverage']['complete'], 7)
            self.assertNotEqual(first_bundle['records'][subjects[0]['id']]['status'], 'complete')
            self.assertEqual(len(downloaded), 8)
            # Publication carries receipts with the newly validated prior bundle.
            shutil.copyfile(plan / 'recovery.json', plan / 'previous' / 'recovery.json')
            with mock.patch.object(recovery, 'download_archive', side_effect=download):
                second = recovery.recover_plan(api, plan, COMMIT, token='read-only')
            second_bundle = coverage.read_bundle(plan / 'previous')
            attempt = second_bundle['attempts'][subjects[0]['id']]
            retained = second_bundle['records'][subjects[0]['id']]
            self.assertEqual(attempt['attempt_count'], 2)
            self.assertEqual(attempt['history'], original_child_attempt['history'])
            self.assertEqual(attempt['status'], 'error')
            self.assertEqual(retained['source']['content_digest'], parent_record['source']['content_digest'])
            self.assertEqual(retained['retry']['latest_status'], 'error')
            self.assertNotEqual(retained['status'], 'complete')
            self.assertIsNone(second['cursor'])
            self.assertEqual(len(downloaded), 9)
            shutil.copyfile(plan / 'recovery.json', plan / 'previous' / 'recovery.json')
            with mock.patch.object(recovery, 'download_archive', side_effect=download):
                third = recovery.recover_plan(api, plan, COMMIT, token='read-only')
            self.assertEqual(third['recovered_sources'], 0)
            self.assertEqual(len(downloaded), 9)
            self.assertEqual(coverage.read_bundle(plan / 'previous')['attempts'][subjects[0]['id']]['attempt_count'], 2)


class DeliveryStatusTests(unittest.TestCase):
    def test_same_main_stale_prepare_cannot_drop_latest_completed_source(self):
        from datetime import timedelta
        from tests.test_skillspector_publication_transport import FakeGitHub
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b = item(id='fixture/a', path='skills/a'), item(id='fixture/b', path='skills/b')
            selection = {'schema_version': 1, 'sources': [a, b]}
            now = datetime.now(timezone.utc)
            with mock.patch.object(coverage.scanner, 'now', return_value=(now - timedelta(seconds=20)).strftime('%Y-%m-%dT%H:%M:%SZ')):
                latest = bundle(root / 'latest', selection, [record(a), record(b)])
            with mock.patch.object(coverage.scanner, 'now', return_value=(now - timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ')):
                candidate = bundle(root / 'candidate', selection, [record(a)])
            tree = [{'path': publisher.PREFIX + path.relative_to(root / 'latest').as_posix(), 'mode': '100644', 'type': 'blob',
                     'sha': hashlib.sha1(b'blob ' + str(len(path.read_bytes())).encode() + b'\0' + path.read_bytes()).hexdigest()}
                    for path in (root / 'latest').rglob('*') if path.is_file()]
            self.assertEqual(latest['manifest']['coverage']['complete'], 2)
            self.assertEqual(candidate['manifest']['coverage']['complete'], 1)
            for baseline in (None, {'schema_version': 1, 'report_commit': 'b' * 40}):
                if baseline is not None:
                    coverage.write_bounded(root / 'candidate' / 'publication-base.json', baseline, 4096)
                github = FakeGitHub(root / ('git-missing' if baseline is None else 'git-stale'), old={'tree': tree}, main=COMMIT)
                with self.assertRaisesRegex(publisher.SupersededCoverage, 'baseline|advanced'):
                    publisher.publish(github, root / 'candidate', COMMIT,
                        fetch=lambda *_args, **_kwargs: coverage.canonical_json(latest['manifest']))
                self.assertFalse(any(method != 'GET' for method, _, _ in github.calls))

    def test_supersession_without_a_remote_receipt_is_not_plain_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "status.json"
            argv = ["publish", "publish", "--report-dir", str(root), "--source-commit", COMMIT, "--status-file", str(status)]
            with mock.patch.object(publisher.sys, "argv", argv), mock.patch.dict(publisher.os.environ, {"GITHUB_TOKEN": "read"}), \
                    mock.patch.object(publisher, "publish", side_effect=publisher.SupersededCoverage("main advanced")):
                self.assertEqual(publisher.main(), 3)
            self.assertEqual(json.loads(status.read_text())["status"], "superseded_without_recovery")

    def test_supersession_with_current_acknowledgement_names_durable_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            coverage.write_bounded(root / "recovery.json", {"schema_version": 1, "runs": [{
                "run_id": 101, "run_attempt": 1, "head_sha": COMMIT, "created_at": "2026-11-02T17:00:00Z",
                "artifacts": [{"id": 501, "digest": "sha256:" + "a" * 64}]}]}, recovery.MAX_STATE_BYTES)
            status = root / "status.json"
            argv = ["publish", "publish", "--report-dir", str(root), "--source-commit", COMMIT, "--status-file", str(status)]
            with mock.patch.object(publisher.sys, "argv", argv), mock.patch.dict(publisher.os.environ, {
                    "GITHUB_TOKEN": "read", "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1"}), \
                    mock.patch.object(publisher, "publish", side_effect=publisher.SupersededCoverage("main advanced")):
                self.assertEqual(publisher.main(), 0)
            self.assertEqual(json.loads(status.read_text())["status"], "superseded_with_durable_recovery")
            with mock.patch.dict(publisher.os.environ, {'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2'}):
                self.assertTrue(publisher.durable_receipt(root, COMMIT), 'A publish-only job retry retains its producing attempt receipt')
            with mock.patch.dict(publisher.os.environ, {'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '0'}):
                self.assertFalse(publisher.durable_receipt(root, COMMIT), 'Future attempt receipts cannot authorize earlier publication')

    def test_optional_recovery_control_crosses_publication_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection = {"schema_version": 1, "sources": [item()]}
            bundle(root, selection, [record(selection["sources"][0])])
            coverage.write_bounded(root / "recovery.json", {"schema_version": 1, "runs": []}, recovery.MAX_STATE_BYTES)
            publisher.validate_directory(root, COMMIT)
            (root / "recovery.json").write_text('{"schema_version":1,"runs":[{}]}')
            with self.assertRaises(PublicationError):
                publisher.validate_directory(root, COMMIT)

    def test_previous_download_uses_finite_repair_budget_then_writes_strict_compacted_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection = {'schema_version': 1, 'sources': [item()]}
            bundle(root / 'published', selection, [record(selection['sources'][0])])
            legacy = {'schema_version': 1, 'runs': [{'run_id': index, 'run_attempt': 1, 'head_sha': COMMIT,
                'created_at': '2026-11-02T17:00:00Z', 'artifacts': [{'id': index, 'digest': 'sha256:' + 'f' * 64}]}
                for index in range(1, 11)]}
            observed = []
            def fetch(_head, relative, maximum, **_kwargs):
                if relative == 'recovery.json':
                    observed.append(maximum)
                    return coverage.canonical_json(legacy)
                path = root / 'published' / relative
                return path.read_bytes() if path.exists() else None
            api = mock.Mock()
            api.request.return_value = {'object': {'sha': 'a' * 40}}
            with mock.patch.object(recovery, 'MAX_STATE_BYTES', 1800), mock.patch.object(recovery, 'MAX_RUNS', 6), \
                    mock.patch.dict(publisher.CONTROL_FILES, {'recovery.json': 1800}):
                publisher.previous(api, root / 'downloaded', fetch=fetch)
                self.assertEqual(observed, [3600])
                self.assertLessEqual((root / 'downloaded' / 'recovery.json').stat().st_size, 1800)
                repaired = recovery.read_state(root / 'downloaded' / 'recovery.json')
                self.assertEqual(repaired['runs'][-1]['run_id'], 10)
                self.assertLessEqual(len(repaired['runs']), 6)


if __name__ == "__main__":
    unittest.main()
