from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_registry", ROOT / "scripts" / "build_registry.py")
assert SPEC and SPEC.loader
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)
CANDIDATES = ROOT / "registry/upstream-promotion-audit/runtime-dependencies/2026-09-30/candidates"
PLUGIN_IDS = ("context7", "firebase", "hubspot-developer")

# Intercept the native spawn boundary before the ESM launcher loads. The fixture
# never starts npm or downloads dependencies; its only real child is inert Node.
SPAWN_PROBE = r"""
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
const nativeSpawn = cp.spawnSync;
Object.defineProperty(process, 'platform', { value: process.env.TEST_PLATFORM });
cp.spawnSync = (command, args, options) => {
  const event = {
    command, args, cwd: options.cwd, shell: options.shell ?? false,
    timeout: options.timeout, windowsHide: options.windowsHide,
    stdio: options.stdio,
    cache: options.env.npm_config_cache,
    ignoreScripts: options.env.npm_config_ignore_scripts,
    audit: options.env.npm_config_audit,
    fund: options.env.npm_config_fund,
    updateNotifier: options.env.npm_config_update_notifier,
  };
  fs.appendFileSync(process.env.TEST_EVENTS, JSON.stringify(event) + '\n');
  if (command === process.execPath) return nativeSpawn(command, args, options);
  if (process.env.TEST_FAILURE === 'exit') return { status: 7, stderr: 'synthetic install failure' };
  if (process.env.TEST_FAILURE === 'timeout') {
    return { error: Object.assign(new Error('synthetic timeout'), { code: 'ETIMEDOUT' }) };
  }
  const entrypoint = path.join(options.cwd, process.env.TEST_ENTRYPOINT);
  fs.mkdirSync(path.dirname(entrypoint), { recursive: true });
  fs.mkdirSync(path.join(options.cwd, 'node_modules', '.bin'), { recursive: true });
  fs.writeFileSync(entrypoint, process.env.TEST_SOURCE);
  return { status: 0, stderr: '' };
};
syncBuiltinESMExports();
"""
INERT_ENTRYPOINT = "console.log(JSON.stringify({args: process.argv.slice(2), path: process.env.PATH}));\n"


class LockedNpmLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node = shutil.which("node")
        if not self.node:
            self.skipTest("node is unavailable")

    def fixture(self, root: Path, *, omit_optional: bool, platform: str, failure: str = ""):
        runtime = root / "runtime"
        runtime.mkdir()
        shutil.copyfile(
            CANDIDATES / "context7" / registry.LOCKED_NPM_RUNTIME_PATH / "launcher.mjs",
            runtime / "launcher.mjs",
        )
        lock_body = b"{}\n"
        lock_digest = registry.digest_bytes(lock_body)
        entrypoint = "node_modules/test-fixture/index.cjs"
        (runtime / "package-lock.json").write_bytes(lock_body)
        (runtime / "package.json").write_text('{"private":true}\n')
        (runtime / "runtime.json").write_text(json.dumps({
            "schema_version": 1, "package": "test-fixture", "version": "1.0.0",
            "entrypoint": entrypoint, "package_lock_sha256": lock_digest,
            "omit_optional": omit_optional,
        }))
        probe = root / "spawn-probe.cjs"
        probe.write_text(SPAWN_PROBE)
        plugin_data = root / "plugin data & echo nope %PATH% ^ $x"
        events = root / "events.jsonl"
        env = {
            **os.environ, "PLUGIN_DATA": str(plugin_data),
            "TEST_PLATFORM": platform, "TEST_FAILURE": failure,
            "TEST_EVENTS": str(events), "TEST_ENTRYPOINT": entrypoint,
            "TEST_SOURCE": INERT_ENTRYPOINT,
        }
        # Do not inherit a user's loader or npm settings into this synthetic run.
        env.pop("NODE_OPTIONS", None)
        return runtime, probe, plugin_data, events, env, lock_digest

    def run_launcher(self, runtime, probe, env, args):
        return subprocess.run(
            [self.node, "--require", str(probe), str(runtime / "launcher.mjs"), *args],
            env=env, text=True, capture_output=True, timeout=15, check=False,
        )

    def test_cold_install_command_is_fixed_and_warm_cache_forwards_literal_user_args(self) -> None:
        # Regression boundary: npm.cmd must not be directly spawned on Windows;
        # neither shell syntax in PLUGIN_DATA nor MCP arguments may enter npm's command.
        args = ["--key", "value & echo injected %PATH% ^ $(touch sentinel)", "--quote=\"'"]
        for platform in ("linux", "win32"):
            for omit_optional in (False, True):
                with self.subTest(platform=platform, omit_optional=omit_optional), tempfile.TemporaryDirectory() as temporary:
                    runtime, probe, data, events, env, lock_digest = self.fixture(
                        Path(temporary), omit_optional=omit_optional, platform=platform,
                    )
                    cold = self.run_launcher(runtime, probe, env, args)
                    self.assertEqual(cold.returncode, 0, cold.stderr)
                    self.assertEqual(json.loads(cold.stdout)["args"], args)
                    calls = [json.loads(line) for line in events.read_text().splitlines()]
                    self.assertEqual(len(calls), 2)
                    install, child = calls
                    npm_args = ["ci", "--ignore-scripts", "--omit=dev"]
                    if omit_optional:
                        npm_args.append("--omit=optional")
                    npm_args.extend(["--no-audit", "--no-fund"])
                    if platform == "win32":
                        self.assertEqual(install["command"], "cmd.exe")
                        self.assertEqual(install["args"], [
                            "/d", "/s", "/c", "npm.cmd " + " ".join(npm_args),
                        ])
                    else:
                        self.assertEqual(install["command"], "npm")
                        self.assertEqual(install["args"], npm_args)
                    self.assertIs(install["shell"], False)
                    self.assertEqual(install["timeout"], 600_000)
                    self.assertTrue(install["windowsHide"])
                    self.assertEqual(install["stdio"], ["ignore", "ignore", "pipe"])
                    resolved_data = data.resolve()
                    self.assertEqual(install["cache"], str(resolved_data / "npm-cache"))
                    self.assertEqual(Path(install["cwd"]).parent, resolved_data / "npm-runtime")
                    for field, value in (("ignoreScripts", "true"), ("audit", "false"),
                                         ("fund", "false"), ("updateNotifier", "false")):
                        self.assertEqual(install[field], value)
                    target = resolved_data / "npm-runtime" / lock_digest.removeprefix("sha256:")
                    marker = json.loads((target / ".agentplugins-runtime.json").read_text())
                    self.assertEqual(marker["lock_digest"], lock_digest)
                    self.assertIs(marker["omit_optional"], omit_optional)
                    self.assertEqual(child["args"], [str(target / env["TEST_ENTRYPOINT"]), *args])
                    self.assertEqual(child["stdio"], "inherit")
                    self.assertTrue(json.loads(cold.stdout)["path"].startswith(str(target / "node_modules/.bin")))
                    self.assertFalse(Path(install["cwd"]).exists())
                    self.assertFalse(Path(str(target) + ".lock").exists())
                    warm = self.run_launcher(runtime, probe, env, args)
                    self.assertEqual(warm.returncode, 0, warm.stderr)
                    self.assertEqual(json.loads(warm.stdout)["args"], args)
                    calls = [json.loads(line) for line in events.read_text().splitlines()]
                    self.assertEqual(len(calls), 3, "warm runtime must not reinstall")
                    self.assertEqual(calls[-1]["args"], child["args"])

    def test_failed_or_timed_out_install_does_not_publish_runtime_or_leave_lock(self) -> None:
        for failure, message in (("exit", "synthetic install failure"), ("timeout", "synthetic timeout")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                runtime, probe, data, events, env, _digest = self.fixture(
                    Path(temporary), omit_optional=False, platform="win32", failure=failure,
                )
                result = self.run_launcher(runtime, probe, env, ["literal & argument"])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(len(events.read_text().splitlines()), 1, "failed install must not start MCP")
                self.assertEqual(list((data / "npm-runtime").iterdir()), [])

    def test_reviewed_candidates_and_historical_packages_validate_but_modified_launcher_fails(self) -> None:
        # Validation must admit both exact reviewed implementations while failing
        # closed on an otherwise valid candidate with different launcher bytes.
        candidate_bodies = set()
        historical_digest = "sha256:043042ce8ec048010a2077c0d241ee43022d5c187bec062040ea186073ae0d2a"
        for plugin in PLUGIN_IDS:
            candidate = CANDIDATES / plugin
            published = ROOT / "plugins" / plugin
            with self.subTest(plugin=plugin):
                registry.validate_locked_npm_runtime(candidate)
                registry.validate_locked_npm_runtime(published)
                body = (candidate / registry.LOCKED_NPM_RUNTIME_PATH / "launcher.mjs").read_bytes()
                candidate_bodies.add(body)
                self.assertNotEqual(registry.digest_bytes(body), historical_digest)
                self.assertEqual(registry.digest_bytes(
                    (published / registry.LOCKED_NPM_RUNTIME_PATH / "launcher.mjs").read_bytes(),
                ), historical_digest)
        self.assertEqual(len(candidate_bodies), 1, "all candidates use the reviewed invocation")
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "context7"
            shutil.copytree(CANDIDATES / "context7", package)
            launcher = package / registry.LOCKED_NPM_RUNTIME_PATH / "launcher.mjs"
            launcher.write_bytes(launcher.read_bytes() + b"\n// unreviewed change\n")
            with self.assertRaisesRegex(registry.RegistryError, "launcher is not the reviewed implementation"):
                registry.validate_locked_npm_runtime(package)
