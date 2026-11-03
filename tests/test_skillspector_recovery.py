"""Recovery authenticates Actions origin separately from scanner JSON claims."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
import urllib.request
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
        if path == "git/ref/heads/main":
            return {"object": {"sha": COMMIT}}
        if path == f"compare/{self.run['head_sha']}...{COMMIT}":
            return {"status": "identical", "merge_base_commit": {"sha": self.run["head_sha"]}}
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

    def test_actual_main_origin_is_required_even_when_json_claims_main(self):
        for changes in ({"head_branch": "feature"}, {"workflow_id": 10}, {"path": ".github/workflows/foreign.yml"},
                        {"repository": {"full_name": "someone/fork"}}, {"head_repository": {"full_name": "someone/fork"}},
                        {"event": "pull_request"}, {"status": "in_progress"}):
            with self.subTest(changes=changes), self.assertRaises(PublicationError):
                recovery.trusted_run(FakeActions(run_metadata(**changes), None), run_metadata(**changes), 9)

    def test_main_named_tag_cannot_authorize_recovered_checkpoints(self):
        run = run_metadata()
        api = FakeActions(run, None)
        original = api.request

        def malicious_tag(method, path, data=None):
            if path.startswith("compare/"):
                # A run dispatched against a tag called main can report the
                # same head_branch as the protected branch, but is not ancestral.
                return {"status": "diverged", "merge_base_commit": {"sha": "f" * 40}}
            return original(method, path, data)

        api.request = malicious_tag
        with self.assertRaisesRegex(PublicationError, "protected main history"):
            recovery.trusted_run(api, run, 9)
        self.assertIn(("GET", "git/ref/heads/main"), api.calls)
        legitimate = FakeActions(run, None)
        self.assertEqual(recovery.trusted_run(legitimate, run, 9), run)
        self.assertIn(("GET", f"compare/{COMMIT}...{COMMIT}"), legitimate.calls)

    def test_production_transport_accepts_only_sha_to_sha_ancestry_comparisons(self):
        from scripts.skillspector_publication_transport import GitHub
        requested = []

        def open_request(request, timeout):
            requested.append(request.full_url)
            return io.BytesIO(b'{"status":"identical"}')

        github = GitHub(opener=open_request)
        self.assertEqual(
            github.request("GET", f"compare/{COMMIT}...{COMMIT}")["status"], "identical")
        self.assertEqual(
            requested, [f"https://api.github.com/repos/{recovery.REPOSITORY}/compare/{COMMIT}...{COMMIT}"])
        for unsafe in ("compare/../main", "compare/abc...main", "git/ref/heads/../secrets"):
            with self.subTest(path=unsafe), self.assertRaises(PublicationError):
                github.request("GET", unsafe)
        self.assertEqual(len(requested), 1)

    def test_acknowledgement_limits_evict_oldest_and_repair_bounded_oversize(self):
        def row(identifier):
            return {"run_id": identifier, "run_attempt": 1, "head_sha": COMMIT,
                    "created_at": "2026-11-02T17:00:00Z",
                    "artifacts": [{"id": identifier, "digest": "sha256:" + "f" * 64}]}

        with mock.patch.object(recovery, "MAX_STATE_BYTES", 1800), \
                mock.patch.object(recovery, "MAX_RUNS", 6), tempfile.TemporaryDirectory() as temporary:
            state = {"schema_version": 1, "runs": []}
            for identifier in range(1, 18):
                state = recovery.merge_state(state, {"schema_version": 1, "runs": [row(identifier)]}, now=NOW)
                self.assertLessEqual(len(recovery.canonical_json(state)), recovery.MAX_STATE_BYTES)
                self.assertLessEqual(len(state["runs"]), 6)
            self.assertEqual(state["runs"][-1]["run_id"], 17)
            self.assertNotIn(1, [entry["run_id"] for entry in state["runs"]])
            legacy = {"schema_version": 1, "runs": [row(identifier) for identifier in range(21, 31)]}
            self.assertGreater(len(recovery.canonical_json(legacy)), recovery.MAX_STATE_BYTES)
            self.assertLessEqual(len(recovery.canonical_json(legacy)), recovery.MAX_STATE_BYTES * 2)
            source = Path(temporary) / "recovery.json"
            source.write_bytes(recovery.canonical_json(legacy))
            repaired = recovery.read_state(source)
            self.assertLessEqual(len(recovery.canonical_json(repaired)), recovery.MAX_STATE_BYTES)
            self.assertEqual(repaired["runs"][-1]["run_id"], 30)

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


if __name__ == "__main__":
    unittest.main()
