from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts.directory_publication import PublicationError, canonical_json, format_timestamp, validate_with_schema
from scripts import skillspector_reports as reports


def upstream_report() -> dict:
    return {"metadata": {"skillspector_version": "2.13.1", "llm_requested": False, "inference_usage": []},
            "execution_successful": True, "suppressed_count": 0, "suppressed": [], "issues": [],
            "analysis_completeness": {"is_complete": True, "execution_successful": True,
                                      "status": "complete", "fully_inspected_files": 1, "partially_inspected_files": 0, "entirely_uninspected_files": 0,
                                      "coverage_percent": 100.0, "ledger_exceptions": [], "limitations": [],
                                      "analyzer_statuses": [{"analyzer_id": a, "status": "completed"} for a in
                                                            ["artifact_integrity", "static_patterns_prompt_injection", "static_yara"]]}}


def item(**changes) -> dict:
    return {"id": "fixture/demo", "kind": "standalone_skill", "repository": "owner/repo",
            "revision": "a" * 40, "path": "skills/demo", "plugin_path": None} | changes


def record() -> dict:
    value = reports.empty_record(item())
    value["source"]["content_digest"] = "sha256:" + "b" * 64
    value["scanned_at"] = reports.now()
    value["skill_name"] = "demo"
    return value


def scanner(root: Path, report: dict | None = None, returncode: int = 0) -> Path:
    executable = root / "scanner"
    executable.write_text(f'''#!{sys.executable}
import json, os, sys
if sys.argv[1:] == ['--version']:
    print('SkillSpector v2.13.1')
    raise SystemExit(0)
assert sys.argv[1] == 'scan'
assert sys.argv[3:] == ['--no-llm', '--format', 'json', '--fail-on-incomplete']
assert 'OPENAI_API_KEY' not in os.environ
assert 'PYTHONPATH' not in os.environ
assert 'SKILLSPECTOR_YARA_RULES_DIR' not in os.environ
assert os.getcwd() != sys.argv[2]
print(json.dumps({report or upstream_report()!r}))
raise SystemExit({returncode})
''')
    executable.chmod(0o755)
    return executable


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()


def fixture_repository(root: Path, *, symlink: bool = False) -> tuple[Path, dict]:
    source = root / "source"
    skill = source / "skills/demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\ndescription: Fixture skill\n---\n# Demo\nRead inert data.\n")
    # Executable content must remain inert, regardless of mode and baseline.
    (skill / "evil.py").write_text("raise RuntimeError('must never run')\n")
    (skill / "evil.py").chmod(0o755)
    (skill / ".skillspector-baseline.yaml").write_text("suppress_everything: true\n")
    if symlink:
        (skill / "alias.md").symlink_to("SKILL.md")
    git(source, "init", "-q")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "add", ".")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture")
    revision = git(source, "rev-parse", "HEAD")
    mirrors = root / "mirrors"
    (mirrors / "owner").mkdir(parents=True)
    subprocess.run(["git", "clone", "--quiet", "--bare", str(source), str(mirrors / "owner/repo.git")], check=True)
    return mirrors, {"schema_version": 1, "sources": [item(revision=revision)]}


class NormalizationTests(unittest.TestCase):
    def normalize(self, raw: dict, returncode=0) -> dict:
        return reports.normalize_report(record(), json.dumps(raw).encode(), returncode, Path('/tmp/content'))

    def test_complete_is_coverage_not_safety_and_findings_are_bounded(self):
        raw = upstream_report()
        raw["issues"] = [{"id": "PI1", "severity": "HIGH", "explanation": "Review this warning.",
                          "location": {"file": "SKILL.md", "start_line": n + 1}} for n in range(40)]
        result = self.normalize(raw, 1)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["finding_count"], 40)
        self.assertEqual(len(result["findings"]), 32)
        self.assertTrue(result["findings_truncated"])
        self.assertNotIn("safe", result)
        self.assertEqual(result["scanned_at"], record()["scanned_at"])

    def test_truncation_preserves_highest_severity_findings(self):
        raw=upstream_report()
        severities=['LOW']*33+['INFO','HIGH','MEDIUM','CRITICAL']
        raw['issues']=[{'id':'RULE','severity':severity,'explanation':'Review this warning.',
                        'location':{'file':'SKILL.md','start_line':n+1}} for n,severity in enumerate(severities)]
        result=self.normalize(raw)
        self.assertEqual(result['finding_count'],37)
        self.assertTrue(result['findings_truncated'])
        self.assertEqual(len(result['findings']),32)
        self.assertEqual([f['severity'] for f in result['findings'][:3]],['CRITICAL','HIGH','MEDIUM'])
        self.assertEqual([f['line'] for f in result['findings'][3:]],list(range(1,30)))
        self.assertNotIn('INFO',[f['severity'] for f in result['findings']])

    def test_exit_zero_does_not_override_incomplete_errors_or_failed_analyzer(self):
        variations = []
        raw = upstream_report(); raw['analysis_completeness']['is_complete'] = False; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['status'] = 'partial'; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['partially_inspected_files'] = 1; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['entirely_uninspected_files'] = 1; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['analyzer_statuses'][0]['skipped'] = 1; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['analyzer_statuses'][0]['status'] = 'disabled'; variations.append(raw)
        raw = upstream_report(); raw['errors'] = ['failure']; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['ledger_exceptions'] = [{'reason_code':'timeout'}]; variations.append(raw)
        raw = upstream_report(); raw['analysis_completeness']['analyzer_statuses'] = [{'status':'failed','failed':1}]; variations.append(raw)
        for raw in variations:
            with self.subTest(raw=raw):
                result = self.normalize(raw)
                self.assertEqual(result['status'], 'partial')
                self.assertTrue(result['errors'])

    def test_missing_completeness_or_execution_status_is_rejected(self):
        for field in ['analysis_completeness', 'execution_successful']:
            raw = upstream_report(); del raw[field]
            with self.subTest(field=field), self.assertRaises(PublicationError):
                self.normalize(raw)

    def test_llm_suppressions_scanner_identity_and_path_escape_rejected(self):
        changes = [('metadata', {'skillspector_version':'2.13.1','llm_requested':True,'inference_usage':[]}),
                   ('suppressed_count',1), ('metadata',{'skillspector_version':'2.12.0','llm_requested':False,'inference_usage':[]})]
        for key, value in changes:
            raw=upstream_report();raw[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(PublicationError):self.normalize(raw)
        raw=upstream_report();raw['issues']=[{'id':'x','severity':'HIGH','explanation':'bad','location':{'file':'../escape'}}]
        with self.assertRaises(PublicationError):self.normalize(raw)

    def test_failed_execution_and_nonstandard_exit_are_errors(self):
        raw=upstream_report();raw['execution_successful']=False
        self.assertEqual(self.normalize(raw)['status'],'error')
        self.assertEqual(self.normalize(upstream_report(),2)['status'],'error')


class PipelineTests(unittest.TestCase):
    def test_materialized_immutable_scan_and_exact_fresh_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);mirrors,selection=fixture_repository(root);executable=scanner(root)
            with mock.patch.dict(os.environ, {'OPENAI_API_KEY':'never-inherit','SKILLSPECTOR_YARA_RULES_DIR':'untrusted'}):
                result=reports.build_reports(selection,executable,mirror_root=mirrors,source_commit="c"*40)
            output=result['records'][0]
            self.assertEqual(output['status'],'complete')
            self.assertEqual(output['skill_name'],'demo')
            self.assertEqual(output['source']['revision'],selection['sources'][0]['revision'])
            self.assertRegex(output['source']['content_digest'],r'^sha256:[0-9a-f]{64}$')
            previous=root/'previous.json';previous.write_bytes(canonical_json(result))
            cached=reports.cache_records(previous)
            self.assertEqual(len(cached),1)
            with mock.patch.object(reports,'run_scanner',wraps=reports.run_scanner) as run:
                reused=reports.build_reports(selection,executable,cached,mirror_root=mirrors,source_commit="c"*40)
                self.assertEqual(run.call_count,1) # Version probe only.
                self.assertEqual(reused['records'][0]['scanned_at'],output['scanned_at'])
            for mutation in ['scanner','profile','age','future','status']:
                changed=copy.deepcopy(result)
                if mutation=='scanner':changed['scanner']['revision']='0'*40
                elif mutation=='profile':changed['profile']['digest']='sha256:'+'0'*64
                elif mutation=='age':changed['records'][0]['scanned_at']=format_timestamp(datetime.now(timezone.utc)-timedelta(days=2))
                elif mutation=='future':changed['records'][0]['scanned_at']=format_timestamp(datetime.now(timezone.utc)+timedelta(days=1))
                else:changed['records'][0]['status']='partial'
                previous.write_bytes(canonical_json(changed))
                with self.subTest(mutation=mutation):
                    self.assertEqual(reports.cache_records(previous),{})

    def test_incompatible_or_damaged_optional_cache_does_not_prevent_fresh_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);mirrors,selection=fixture_repository(root);executable=scanner(root)
            previous=root/'previous.json'
            old=copy.deepcopy(reports.build_reports(selection,executable,mirror_root=mirrors,source_commit="c"*40))
            old['scanner']['version']='2.12.0'
            for body in [canonical_json(old), b'{"schema_version":0}', b'{"schema_version":']:
                previous.write_bytes(body)
                with self.subTest(body=body[:80]):
                    cached=reports.cache_records(previous)
                    self.assertEqual(cached,{})
                    with mock.patch.object(reports,'run_scanner',wraps=reports.run_scanner) as run:
                        fresh=reports.build_reports(selection,executable,cached,mirror_root=mirrors,source_commit="c"*40)
                    self.assertEqual(run.call_count,2) # Probe and a fresh scan.
                    self.assertEqual(fresh['records'][0]['status'],'complete')

    def test_acquisition_failure_keeps_all_configured_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);executable=scanner(root)
            selection={'schema_version':1,'sources':[item(),item(id='fixture/other',path='skills/other')]}
            result=reports.build_reports(selection,executable,mirror_root=root/'missing',source_commit='c'*40)
            self.assertEqual(len(result['records']),2)
            for value in result['records']:
                self.assertEqual(value['status'],'error')
                self.assertIsNone(value['source']['content_digest'])
                self.assertIsNone(value['scanned_at'])
                self.assertEqual(value['errors'][0]['code'],'acquisition_failed')

    def test_oversized_skill_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);mirrors,selection=fixture_repository(root);executable=scanner(root)
            with mock.patch.object(reports,'MAX_TREE_BYTES',1):
                result=reports.build_reports(selection,executable,mirror_root=mirrors,source_commit="c"*40)
            self.assertEqual(result['records'][0]['status'],'error')
            self.assertEqual(result['records'][0]['errors'][0]['code'],'scan_failed')

    def test_symlinked_skill_and_timeout_remain_error_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);mirrors,selection=fixture_repository(root,symlink=True);executable=scanner(root)
            result=reports.build_reports(selection,executable,mirror_root=mirrors,source_commit="c"*40)
            self.assertEqual(result['records'][0]['status'],'error')
            self.assertIsNone(result['records'][0]['scanned_at'])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);mirrors,selection=fixture_repository(root);executable=scanner(root)
            original=reports.run_scanner
            def timeout(scanner,arguments,home,timeout):
                if arguments[0]=='scan':raise subprocess.TimeoutExpired('scanner',timeout)
                return original(scanner,arguments,home,timeout)
            with mock.patch.object(reports,'run_scanner',side_effect=timeout):
                result=reports.build_reports(selection,executable,mirror_root=mirrors,source_commit="c"*40)
            self.assertEqual(result['records'][0]['status'],'error')
            self.assertIsNotNone(result['records'][0]['scanned_at'])
            self.assertIsNotNone(result['records'][0]['source']['content_digest'])

    def test_selection_rejects_mutable_refs_duplicate_ids_and_outside_plugin_root(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'selection.json'
            for entries in [[item(revision='main')],[item(),item()],
                            [item(kind='plugin_skill',plugin_path='plugins/demo')]]:
                path.write_bytes(canonical_json({'schema_version':1,'sources':entries}))
                with self.subTest(entries=entries),self.assertRaises(PublicationError):reports.load_selection(path)

    def test_production_selection_validates_and_contains_both_source_kinds(self):
        selection=reports.load_selection(reports.ROOT/'registry/skillspector-selection.json')
        self.assertEqual({r['kind'] for r in selection['sources']},{'plugin_skill','standalone_skill'})


if __name__ == '__main__':
    unittest.main()
