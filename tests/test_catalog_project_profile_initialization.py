"""Offline Claude profile preparation contracts; no native process or network."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.test_catalog_publication_readiness import arguments, catalog, PROJECT_RELEASE_FIXTURE
import catalog_managed_readiness as managed
import catalog_project_readiness as project
import catalog_publication_readiness as gate
import catalog_process_isolation as isolation


class ProjectProfileInitializationTests(unittest.TestCase):
    def tools(self, root):
        directory = root / "tools"
        directory.mkdir()
        for name in ("agentplugins", "codex", "claude", "copilot", "opencode"):
            path = directory / name
            path.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            path.chmod(0o700)
        return SimpleNamespace(
            binary=directory / "agentplugins", project_binary=directory / "agentplugins",
            codex=directory / "codex", claude=directory / "claude",
            copilot=directory / "copilot", opencode=directory / "opencode",
            inspector=None, npx=None)

    def fixture(self, temporary):
        root = Path(temporary).resolve()
        args = self.tools(root)
        case = root / "case"
        case.mkdir(mode=0o700)
        roots, env = gate.isolated_environment(
            case, "https://example.invalid/exact-ledger/", (args.claude,))
        return args, case, roots, env, (args.claude.parent,)

    def native_profile(self, home):
        profile = home / ".claude"
        profile.mkdir(exist_ok=True)
        body = {
            "firstStartTime": "2026-11-11T00:00:00.000Z",
            "firstStartVersion": "2.1.251",
            "machineID": "1" * 64,
        }
        (profile / ".claude.json").write_text(json.dumps(body) + "\n", encoding="utf-8")
        backups = profile / "backups"
        backups.mkdir(exist_ok=True)
        (backups / ".claude.json.backup.1").write_text("{}\n", encoding="utf-8")
        return profile

    @staticmethod
    def native_result(argv, *, stdout="[]\n", returncode=0):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    def test_two_native_controls_use_exact_probe_environment_and_return_first_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, case, roots, env, readonly = self.fixture(temporary)
            # Ambient adapter overrides and credentials are not probe inputs.
            env.update({"ANTHROPIC_API_KEY": "private-fixture-token",
                        "CLAUDE_CONFIG_DIR": "/outside-fixture",
                        "CLAUDE_CODE_CONFIG_DIR": "/another-outside-fixture"})
            expected_env = {key: env[key] for key in ("HOME", "USERPROFILE", "PATH", "TMPDIR", "LANG")}
            expected_env.update({"CLAUDE_CONFIG_DIR": str(roots["home"] / ".claude"),
                                 "DISABLE_AUTOUPDATER": "1",
                                 "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"})
            calls, first_baseline = [], []

            def native(argv, **kwargs):
                self.assertEqual(argv, [str(args.claude), "plugin", "list", "--json"])
                self.assertEqual(kwargs["root"], case)
                self.assertEqual(kwargs["readonly"], readonly)
                self.assertEqual(kwargs["cwd"], roots["workspace"])
                self.assertEqual(kwargs["timeout"], 60)
                self.assertEqual(kwargs["env"], expected_env)
                calls.append(tuple(argv))
                self.assertLessEqual(len(calls), 2)
                if len(calls) == 1:
                    self.native_profile(roots["home"])
                    first_baseline.append(managed.snapshot_paths(project.user_paths(roots)))
                else:
                    self.assertEqual(managed.snapshot_paths(project.user_paths(roots)), first_baseline[0])
                return self.native_result(argv)

            with patch.object(gate, "child", side_effect=native):
                baseline = project.initialize_user_profile(args, case, roots, env, readonly)
            self.assertEqual(len(calls), 2)
            self.assertEqual(baseline, first_baseline[0])
            project.validate_user_isolation(baseline, roots)

    def test_home_substitution_is_rejected_before_reading_profile_at_either_control(self):
        for replace_on in (1, 2):
            with self.subTest(control=replace_on), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                outside_home = Path(temporary).resolve() / "outside-home"
                outside_home.mkdir()
                self.native_profile(outside_home)
                calls, forbidden_reads = [], []
                ordinary_open = Path.open

                def guarded_open(path, *positional, **keywords):
                    if path.resolve().is_relative_to(outside_home):
                        forbidden_reads.append("outside-profile")
                        raise AssertionError("outside profile bytes were accessed before refusal")
                    return ordinary_open(path, *positional, **keywords)

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    self.assertLessEqual(len(calls), replace_on)
                    if len(calls) == replace_on:
                        roots["home"].rename(case / "original-home")
                        roots["home"].symlink_to(outside_home, target_is_directory=True)
                    elif len(calls) == 1:
                        self.native_profile(roots["home"])
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native), \
                        patch.object(Path, "open", guarded_open), self.assertRaises(ValueError):
                    project.initialize_user_profile(args, case, roots, env, readonly)
                self.assertEqual(len(calls), replace_on)
                self.assertEqual(forbidden_reads, [])

    def test_second_control_rejects_profile_changes_without_retry_or_rebaseline(self):
        for mutation in ("profile_bytes", "profile_mode", "new_backup", "new_subdirectory"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    if len(calls) == 1:
                        self.native_profile(roots["home"])
                    elif len(calls) == 2:
                        profile = roots["home"] / ".claude"
                        config = profile / ".claude.json"
                        if mutation == "profile_bytes":
                            body = json.loads(config.read_text())
                            body["machineID"] = "2" * 64
                            config.write_text(json.dumps(body) + "\n", encoding="utf-8")
                        elif mutation == "profile_mode":
                            config.chmod((config.stat().st_mode & 0o7777) ^ 0o020)
                        elif mutation == "new_backup":
                            (profile / "backups" / ".claude.json.backup.2").write_text("{}\n", encoding="utf-8")
                        else:
                            (profile / "unexpected-empty-directory").mkdir()
                    # A third call would be stable. It must never be attempted.
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native), self.assertRaises(ValueError):
                    project.initialize_user_profile(args, case, roots, env, readonly)
                self.assertEqual(len(calls), 2)

    def test_real_isolation_command_preserves_probe_flags_without_auth_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, case, roots, env, readonly = self.fixture(temporary)
            calls = []

            def native(argv, **kwargs):
                transported = {**kwargs["env"], "ANTHROPIC_API_KEY": "private-api-fixture",
                               "CLAUDE_CODE_OAUTH_TOKEN": "private-oauth-fixture",
                               "GITHUB_TOKEN": "private-github-fixture",
                               "UNRELATED_NATIVE_SETTING": "private-unrelated-fixture"}
                command = isolation._command(
                    argv=argv, writable_root=kwargs["root"], cwd=kwargs["cwd"],
                    env=transported, read_only_paths=kwargs["readonly"],
                    bwrap=Path("/usr/bin/bwrap"))
                actual_env = {}
                for index, value in enumerate(command):
                    if value == "--setenv":
                        self.assertNotIn(command[index + 1], actual_env)
                        actual_env[command[index + 1]] = command[index + 2]
                self.assertEqual(actual_env, kwargs["env"])
                self.assertEqual(actual_env["CLAUDE_CONFIG_DIR"], str(roots["home"] / ".claude"))
                self.assertEqual(actual_env["DISABLE_AUTOUPDATER"], "1")
                self.assertEqual(actual_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1")
                for flag in ("--unshare-user", "--unshare-pid", "--disable-userns",
                             "--as-pid-1", "--die-with-parent", "--clearenv", "--new-session"):
                    self.assertIn(flag, command)
                self.assertEqual(command.count("--bind"), 1)
                self.assertEqual(command[-len(argv) - 1:], ["--", *argv])
                calls.append(tuple(argv))
                if len(calls) == 1:
                    self.native_profile(roots["home"])
                return self.native_result(argv)

            with patch.dict(os.environ, {"RUNNER_TEMP": str(Path(temporary).resolve())}, clear=True), \
                    patch.object(gate, "child", side_effect=native):
                baseline = project.initialize_user_profile(args, case, roots, env, readonly)
            self.assertEqual(len(calls), 2)
            project.validate_user_isolation(baseline, roots)

    def test_isolation_rejects_unconfined_profile_or_unpaired_probe_flags(self):
        for mutation in ("outside", "relative", "alias", "noncanonical", "disable_updates",
                         "disable_traffic", "missing_updates", "missing_traffic", "missing_profile"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                native_env = {key: env[key] for key in ("HOME", "USERPROFILE", "PATH", "TMPDIR", "LANG")}
                native_env.update(CLAUDE_CONFIG_DIR=str(roots["home"] / ".claude"),
                                  DISABLE_AUTOUPDATER="1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
                if mutation == "outside":
                    native_env["CLAUDE_CONFIG_DIR"] = str(args.claude.parent)
                elif mutation == "relative":
                    native_env["CLAUDE_CONFIG_DIR"] = "home/.claude"
                elif mutation == "alias":
                    alias = roots["home"] / "profile-alias"
                    alias.symlink_to(args.claude.parent, target_is_directory=True)
                    native_env["CLAUDE_CONFIG_DIR"] = str(alias)
                elif mutation == "noncanonical":
                    native_env["CLAUDE_CONFIG_DIR"] = str(roots["home"] / ".claude/..")
                elif mutation == "disable_updates":
                    native_env["DISABLE_AUTOUPDATER"] = "0"
                elif mutation == "disable_traffic":
                    native_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "0"
                elif mutation == "missing_updates":
                    native_env.pop("DISABLE_AUTOUPDATER")
                elif mutation == "missing_traffic":
                    native_env.pop("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
                else:
                    native_env.pop("CLAUDE_CONFIG_DIR")
                with patch.dict(os.environ, {"RUNNER_TEMP": str(Path(temporary).resolve())}, clear=True), \
                        self.assertRaises(ValueError):
                    isolation._command(
                        argv=[str(args.claude), "plugin", "list", "--json"],
                        writable_root=case, cwd=roots["workspace"], env=native_env,
                        read_only_paths=readonly, bwrap=Path("/usr/bin/bwrap"))

    def test_initialization_preserves_authored_state_outside_claude(self):
        for target in ("home", "config", "workspace", "state", "store", "directory_cache", "cache"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                if target == "home":
                    protected = roots["home"] / ".claude.json"
                elif target == "store":
                    protected = roots["state"] / "store/authored-foreign.json"
                elif target == "directory_cache":
                    protected = roots["state"] / "directory-v1-cache.json"
                else:
                    protected = roots[target] / "authored-foreign.json"
                if target != "home":
                    protected.parent.mkdir(parents=True, exist_ok=True)
                    protected.write_text('{"foreign":1}\n', encoding="utf-8")
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    self.native_profile(roots["home"])
                    protected.write_text('{"foreign":2}\n', encoding="utf-8")
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native), self.assertRaises(ValueError):
                    project.initialize_user_profile(args, case, roots, env, readonly)
                self.assertEqual(len(calls), 1)

    def test_invalid_native_responses_fail_at_the_selected_control(self):
        responses = (
            ("nonzero", "[]\n", 1), ("nonempty", '[{"id":"unexpected"}]', 0),
            ("malformed", "[", 0), ("trailing", "[] {}", 0),
            ("duplicate", '{"private-fixture":1,"private-fixture":2}', 0),
            ("boolean_exit", "[]\n", False), ("object", "{}", 0),
        )
        for control in (1, 2):
            for name, stdout, returncode in responses:
                with self.subTest(control=control, response=name), tempfile.TemporaryDirectory() as temporary:
                    args, case, roots, env, readonly = self.fixture(temporary)
                    calls = []

                    def native(argv, **kwargs):
                        calls.append(tuple(argv))
                        if len(calls) == 1:
                            self.native_profile(roots["home"])
                        if len(calls) == control:
                            return self.native_result(argv, stdout=stdout, returncode=returncode)
                        return self.native_result(argv)

                    with patch.object(gate, "child", side_effect=native), \
                            self.assertRaises((ValueError, gate.publication.PublicationError)):
                        project.initialize_user_profile(args, case, roots, env, readonly)
                    self.assertEqual(len(calls), control)
                    expected_phase = {"nonzero": "native_exit", "nonempty": "native_empty",
                                      "malformed": "native_json", "trailing": "native_json",
                                      "duplicate": "native_json", "boolean_exit": "native_exit",
                                      "object": "native_empty"}[name]
                    self.assertEqual(args.failure_phase,
                                     f"project:claude_profile:{'initialize' if control == 1 else 'stable'}:{expected_phase}")

    def test_timeout_at_either_control_is_not_retried(self):
        for control in (1, 2):
            with self.subTest(control=control), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    if len(calls) == control:
                        raise subprocess.TimeoutExpired(argv, 60, output="private-fixture-output")
                    self.native_profile(roots["home"])
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native), self.assertRaises(subprocess.TimeoutExpired):
                    project.initialize_user_profile(args, case, roots, env, readonly)
                self.assertEqual(len(calls), control)
                self.assertEqual(args.failure_phase,
                                 f"project:claude_profile:{'initialize' if control == 1 else 'stable'}:native_execution")

    def test_first_control_preserves_preexisting_claude_foreign_entries(self):
        for mutation in (None, "content", "remove", "mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                profile = roots["home"] / ".claude"
                profile.mkdir()
                foreign = profile / "authored-settings.json"
                foreign.write_text('{"foreign":1}\n', encoding="utf-8")
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    if len(calls) == 1:
                        self.native_profile(roots["home"])
                        if mutation == "content":
                            foreign.write_text('{"foreign":2}\n', encoding="utf-8")
                        elif mutation == "remove":
                            foreign.unlink()
                        elif mutation == "mode":
                            foreign.chmod((foreign.stat().st_mode & 0o7777) ^ 0o020)
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native):
                    if mutation is None:
                        baseline = project.initialize_user_profile(args, case, roots, env, readonly)
                        project.validate_user_isolation(baseline, roots)
                        self.assertEqual(len(calls), 2)
                    else:
                        with self.assertRaises(ValueError):
                            project.initialize_user_profile(args, case, roots, env, readonly)
                        self.assertEqual(len(calls), 1)

    def test_backup_metadata_must_match_the_final_profile_when_present(self):
        for conflicting_key in (None, "firstStartTime", "firstStartVersion", "machineID"):
            with self.subTest(conflicting_key=conflicting_key), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    if len(calls) == 1:
                        profile = self.native_profile(roots["home"])
                        final = json.loads((profile / ".claude.json").read_text())
                        previous = {key: final[key] for key in ("firstStartTime", "firstStartVersion")}
                        if conflicting_key is not None:
                            previous[conflicting_key] = "different-native-initialization-value"
                        (profile / "backups/.claude.json.backup.1").write_text(
                            json.dumps(previous) + "\n", encoding="utf-8")
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native):
                    if conflicting_key is None:
                        baseline = project.initialize_user_profile(args, case, roots, env, readonly)
                        project.validate_user_isolation(baseline, roots)
                        self.assertEqual(len(calls), 2)
                    else:
                        with self.assertRaisesRegex(ValueError, "backup metadata differs"):
                            project.initialize_user_profile(args, case, roots, env, readonly)
                        self.assertEqual(len(calls), 1)

    def test_initialization_rejects_new_objects_and_non_initialization_metadata(self):
        mutations = (
            "root_file", "root_directory", "nested_backup_directory", "backup_name",
            "backup_malformed", "backup_duplicate", "backup_unknown_field",
            "profile_extra_field", "profile_missing_field", "profile_nonstring",
            "profile_empty_string", "profile_long_string",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    profile = self.native_profile(roots["home"])
                    config = profile / ".claude.json"
                    backup = profile / "backups/.claude.json.backup.2"
                    if mutation == "root_file":
                        (profile / "unexpected.json").write_text("{}\n", encoding="utf-8")
                    elif mutation == "root_directory":
                        (profile / "unexpected-empty-directory").mkdir()
                    elif mutation == "nested_backup_directory":
                        (profile / "backups/nested").mkdir()
                    elif mutation == "backup_name":
                        (profile / "backups/unexpected.json").write_text("{}\n", encoding="utf-8")
                    elif mutation == "backup_malformed":
                        backup.write_text("not JSON", encoding="utf-8")
                    elif mutation == "backup_duplicate":
                        backup.write_text('{"machineID":"a","machineID":"b"}', encoding="utf-8")
                    elif mutation == "backup_unknown_field":
                        backup.write_text('{"projects":{}}', encoding="utf-8")
                    else:
                        body = json.loads(config.read_text())
                        if mutation == "profile_extra_field":
                            body["projects"] = {}
                        elif mutation == "profile_missing_field":
                            body.pop("machineID")
                        elif mutation == "profile_nonstring":
                            body["machineID"] = 7
                        elif mutation == "profile_empty_string":
                            body["machineID"] = ""
                        elif mutation == "profile_long_string":
                            body["machineID"] = "x" * 257
                        else:
                            self.fail("unknown fixture mutation")
                        config.write_text(json.dumps(body), encoding="utf-8")
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native), \
                        self.assertRaises((ValueError, gate.publication.PublicationError)):
                    project.initialize_user_profile(args, case, roots, env, readonly)
                self.assertEqual(len(calls), 1)

    def test_profile_objects_must_be_ordinary_bounded_files(self):
        mutations = (
            "profile_symlink", "profile_directory", "root_symlink", "backup_symlink",
            "backup_directory", "profile_oversize", "backup_oversize", "too_many_backups",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, case, roots, env, readonly = self.fixture(temporary)
                outside = Path(temporary).resolve() / "outside-profile.json"
                outside.write_text('{"private_fixture":"must remain unchanged"}\n', encoding="utf-8")
                outside_before = outside.read_bytes()
                calls = []

                def native(argv, **kwargs):
                    calls.append(tuple(argv))
                    profile = self.native_profile(roots["home"])
                    config = profile / ".claude.json"
                    backup = profile / "backups/.claude.json.backup.1"
                    if mutation == "profile_symlink":
                        config.unlink()
                        config.symlink_to(outside)
                    elif mutation == "profile_directory":
                        config.unlink()
                        config.mkdir()
                    elif mutation == "root_symlink":
                        moved = case / "moved-profile"
                        profile.rename(moved)
                        profile.symlink_to(moved, target_is_directory=True)
                    elif mutation == "backup_symlink":
                        backup.unlink()
                        backup.symlink_to(outside)
                    elif mutation == "backup_directory":
                        backup.unlink()
                        backup.mkdir()
                    elif mutation in ("profile_oversize", "backup_oversize"):
                        selected = config if mutation == "profile_oversize" else backup
                        selected.write_text(json.dumps({"machineID": "x" * 65536}), encoding="utf-8")
                    else:
                        for index in range(2, 11):
                            (profile / "backups" / (".claude.json.backup." + str(index))).write_text(
                                "{}\n", encoding="utf-8")
                    return self.native_result(argv)

                with patch.object(gate, "child", side_effect=native), \
                        self.assertRaises((ValueError, gate.publication.PublicationError)):
                    project.initialize_user_profile(args, case, roots, env, readonly)
                self.assertEqual(len(calls), 1)
                self.assertEqual(outside.read_bytes(), outside_before)

    def test_oversized_profile_bytes_are_rejected_before_reading_at_either_control(self):
        for control in (1, 2):
            for selected_name in (".claude.json", "backups/.claude.json.backup.1"):
                with self.subTest(control=control, file=selected_name), tempfile.TemporaryDirectory() as temporary:
                    args, case, roots, env, readonly = self.fixture(temporary)
                    selected = roots["home"] / ".claude" / selected_name
                    forbidden_reads, attempted_reads, calls = set(), [], []
                    real_open = Path.open

                    def guarded_open(path, mode="r", *positional, **keywords):
                        if path in forbidden_reads and ("r" in mode or "+" in mode):
                            attempted_reads.append(path)
                            self.fail("oversized native profile opened before its size was rejected")
                        return real_open(path, mode, *positional, **keywords)

                    def native(argv, **kwargs):
                        calls.append(tuple(argv))
                        if len(calls) == 1:
                            self.native_profile(roots["home"])
                        if len(calls) == control:
                            selected.write_text(json.dumps({"machineID": "x" * 65536}), encoding="utf-8")
                            forbidden_reads.add(selected)
                        return self.native_result(argv)

                    with patch.object(Path, "open", new=guarded_open), \
                            patch.object(gate, "child", side_effect=native), self.assertRaises(ValueError):
                        project.initialize_user_profile(args, case, roots, env, readonly)
                    self.assertEqual(attempted_reads, [])
                    self.assertEqual(len(calls), control)

    def test_managed_project_add_keeps_initialized_profile_frozen(self):
        for mutation in (None, "new_file", "profile_bytes", "backup_bytes", "durable_state"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args = self.tools(root)
                case_root = root / "case"
                release = copy.deepcopy(PROJECT_RELEASE_FIXTURE)
                release["cli"]["binary_digest"] = gate.digest(args.project_binary.read_bytes())
                calls = []

                def child(argv, **kwargs):
                    if argv[1:] == ["plugin", "list", "--json"]:
                        calls.append("native")
                        self.assertLessEqual(len(calls), 2)
                        if len(calls) == 1:
                            self.native_profile(case_root / "home")
                        return self.native_result(argv)
                    calls.append("add")
                    self.assertEqual(calls, ["native", "native", "add"])
                    self.assertEqual(argv[1:5], ["add", "marketing-kit", "--target", ",".join(managed.CLIENTS)])
                    self.assertEqual(argv[5:], ["--scope", "project", "--project-root",
                                               str(case_root / "workspace"), "--format", "json"])
                    if mutation == "new_file":
                        (case_root / "home/.claude/late-write.json").write_text("{}\n", encoding="utf-8")
                    elif mutation == "profile_bytes":
                        config = case_root / "home/.claude/.claude.json"
                        body = json.loads(config.read_text())
                        body["machineID"] = "2" * 64
                        config.write_text(json.dumps(body) + "\n", encoding="utf-8")
                    elif mutation == "backup_bytes":
                        (case_root / "home/.claude/backups/.claude.json.backup.1").write_text(
                            '{"machineID":"changed"}\n', encoding="utf-8")
                    elif mutation == "durable_state":
                        (case_root / "state/state-v2.json").write_text(
                            '{"installations":[]}\n', encoding="utf-8")
                    # Stop at an existing predicate immediately after the real
                    # User-isolation guard. No later lifecycle is mocked as a pass.
                    return self.native_result(argv, stdout=json.dumps(
                        {"command": "add", "result": "success", "data": {}}))

                with patch.object(project, "RELEASE", release), patch.object(gate, "child", side_effect=child):
                    case = project.expected(catalog(), gate.selected)
                    message = ("Project operation changed User native or durable state" if mutation is not None
                               else "managed saved add incomplete")
                    with self.assertRaisesRegex(ValueError, message):
                        managed.run(args, case_root, case,
                                    {"directory_origin": "https://example.invalid/exact-ledger/"})
                self.assertEqual(calls, ["native", "native", "add"])

    def test_main_redacts_native_profile_failure_and_never_writes_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = self.tools(root)
            release = copy.deepcopy(PROJECT_RELEASE_FIXTURE)
            binary_digest = gate.digest(args.binary.read_bytes())
            release["cli"]["binary_digest"] = binary_digest
            snapshot = catalog()
            invocation = arguments(snapshot)
            baseline = copy.deepcopy(snapshot)
            baseline["sequence"] = 13
            output, sandbox = root / "evidence/catalog-readiness.json", root / "sandbox"
            private = "private-fixture-token " + str(root / "do-not-disclose")
            key = json.dumps(private)
            hostile = "{" + key + ":1," + key + ":2}"
            with self.assertRaises(gate.publication.PublicationError) as direct:
                gate.publication.parse_json_bytes(hostile.encode(), "native fixture", max_bytes=65536)
            self.assertIn(private, str(direct.exception))
            actual_run = managed.run
            native_calls = []

            def dispatch(selected_args, selected_root, case, ctx):
                # Other producer lanes are outside this offline error-path test.
                # The selected Project runner and every validator remain real.
                if case.get("placement_scope") == "project":
                    return actual_run(selected_args, selected_root, case, ctx)

            def native(argv, **kwargs):
                native_calls.append(tuple(argv))
                self.assertEqual(argv, [str(args.claude), "plugin", "list", "--json"])
                return self.native_result(argv, stdout=hostile)

            argv = ["produce", "--feed", str(root / "feed"),
                    "--baseline-feed", str(root / "baseline"),
                    "--trusted-keys", str(root / "trusted-keys.json"),
                    "--sandbox", str(sandbox), "--output", str(output)]
            for field in gate.CONTEXT_FIELDS:
                argv.extend(["--" + field.replace("_", "-"), str(getattr(invocation, field))])
            for field in ("binary", "project_binary", "codex", "claude", "copilot", "opencode"):
                argv.extend(["--" + field.replace("_", "-"), str(getattr(args, field))])
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(project, "RELEASE", release), patch.dict(gate.CLI, {"binary_digest": binary_digest}):
                expected = gate.expected_artifact(
                    snapshot, baseline, {"sequence": 13, "snapshot_digest": "sha256:" + "f" * 64},
                    gate.context(invocation, snapshot,
                                 {"sequence": 20, "snapshot_digest": invocation.snapshot_digest}))
                with patch.object(gate, "canonical_inputs", return_value=(snapshot, expected)), \
                        patch.object(managed, "run", side_effect=dispatch), \
                        patch.object(gate, "child", side_effect=native), \
                        redirect_stdout(stdout), redirect_stderr(stderr):
                    result = gate.main(argv)
            self.assertEqual(result, 1)
            self.assertEqual(len(native_calls), 1)
            self.assertFalse(output.exists())
            self.assertFalse(sandbox.exists())
            failure = output.parent / "catalog-readiness-failure.json"
            self.assertEqual(json.loads(failure.read_text()), {
                "kind": "catalog-readiness-failure-v1", "outcome": "failed",
                "phase": "project:claude_profile:initialize:native_json", "error_class": "PublicationError",
            })
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(),
                             "catalog readiness failed: project:claude_profile:initialize:native_json: PublicationError\n")
            for diagnostic in (failure.read_text(), stdout.getvalue(), stderr.getvalue()):
                self.assertNotIn(private, diagnostic)
                self.assertNotIn(str(root), diagnostic)


if __name__ == "__main__":
    unittest.main()
