#!/usr/bin/env node
'use strict';

// Configuration/materialization evidence only. No agent, OAuth or MCP tool execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');

const version = process.argv[3];
assert(['0.1.26', '0.1.45'].includes(version), 'Select a tested CLI boundary');
const targets = ['codex', 'cursor', 'kiro', 'gemini', 'opencode', 'cline', 'windsurf', 'vscode'];
const skills = [
  'agents-sdk', 'cloudflare', 'cloudflare-email-service', 'cloudflare-one',
  'cloudflare-one-migrations', 'durable-objects', 'sandbox-migrate-to-next',
  'sandbox-next', 'sandbox-stable', 'turnstile-spin', 'web-perf',
  'workers-best-practices', 'wrangler',
].sort();
const packages = {
  cloudflare: { type: 'remote', url: 'https://mcp.cloudflare.com/mcp' },
  'cloudflare-bindings': { type: 'remote', url: 'https://bindings.mcp.cloudflare.com/mcp' },
  'cloudflare-observability': { type: 'remote', url: 'https://observability.mcp.cloudflare.com/mcp' },
  firecrawl: { type: 'remote', url: 'https://mcp.firecrawl.dev/v2/mcp' },
  playwright: { type: 'locked-local' },
};
const name = process.argv[2];
assert(Object.hasOwn(packages, name), 'Select a supported MCP package');
assert.equal(process.platform, 'linux', 'Run only on the isolated Linux CI runner');
assert(process.env.RUNNER_TEMP, 'RUNNER_TEMP is required');
const repo = path.resolve(__dirname, '../..');
const source = path.join(repo, 'plugins', name);
const base = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, 'cloudflare-lifecycle-'));
const evidence = path.join(process.env.RUNNER_TEMP, 'cloudflare-package-evidence', name);
fs.mkdirSync(evidence, { recursive: true });
const summary = {
  package: name, cli: `universal-agent-plugins@${version}`, targets,
  scope: 'Synthetic Linux profile configuration lifecycle; manual UI preparation acknowledged on removal. No agent runtime, OAuth, MCP tool calls, Claude or Copilot proof.',
  success: false, steps: [],
};
const digest = (value) => createHash('sha256').update(value).digest('hex');
const save = () => fs.writeFileSync(path.join(evidence, 'summary.json'), JSON.stringify(summary, null, 2));
save();

function check(condition, message) {
  // Fixed messages keep artifact failures free of paths, config values and auth data.
  if (!condition) throw new Error(message);
}
function equal(actual, expected, message) {
  check(JSON.stringify(actual) === JSON.stringify(expected), message);
}
const sentinel = { type: 'remote', url: 'https://uap-sentinel.invalid/mcp', enabled: false };
const expectedSkills = name === 'cloudflare' ? skills : [];
const configPath = path.join(base, 'config/opencode/opencode.json');
const skillsPath = path.join(base, 'config/opencode/skills');
const readJSON = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
let env;
let currentStep = 'setup';

function execute(label, executable, args, json = true) {
  currentStep = label;
  console.log(`START ${name}/${label}`);
  const result = spawnSync(executable, args, {
    cwd: path.join(base, 'project'), env, encoding: 'utf8',
    timeout: 300_000, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024,
  });
  const record = {
    step: label, exitCode: result.status, signal: result.signal || null,
    stdoutSHA256: digest(result.stdout || ''), stderrSHA256: digest(result.stderr || ''),
    success: false,
  };
  summary.steps.push(record);
  save();
  check(!result.error && result.status === 0, `${label}: command failed or timed out (no retry)`);
  check(!/invalid[ _-]*skill|unknown[^\n]*frontmatter|skip(?:ped|ping)?[^\n]*skill/i.test(
    `${result.stdout}\n${result.stderr}`), `${label}: invalid or skipped skill diagnostics`);
  let output;
  try { output = json ? JSON.parse(result.stdout) : result.stdout.trim(); }
  catch { throw new Error(`${label}: command did not return JSON`); }
  record.success = true;
  save();
  return output;
}
function cli(label, args) {
  const output = execute(label, path.join(base, 'bin/npx'), [
    '--yes', `universal-agent-plugins@${version}`, ...args, '--format', 'json',
  ]);
  check(output.result === 'success', `${label}: CLI reported failure`);
  return output;
}
function batch(output, label) {
  check(output.data.succeeded === targets.length && output.data.failed === 0,
    `${label}: not all eight targets succeeded`);
  equal(output.data.targets.map((item) => item.target).sort(), [...targets].sort(),
    `${label}: target set mismatch`);
}
function installedSkills() {
  if (!fs.existsSync(skillsPath)) return [];
  return fs.readdirSync(skillsPath).filter((entry) =>
    fs.existsSync(path.join(skillsPath, entry, 'SKILL.md'))).sort();
}
function inspectInstalled() {
  const config = readJSON(configPath);
  const installed = config.mcp[name];
  const expected = packages[name];
  if (expected.type === 'remote') {
    check(installed?.url === expected.url, 'OpenCode MCP endpoint mismatch');
  } else {
    check(installed?.type === 'local', 'OpenCode local MCP type mismatch');
    check(Array.isArray(installed.command) && installed.command.length === 2,
      'OpenCode local MCP command shape mismatch');
    check(installed.command[0] === 'node', 'OpenCode local MCP executable mismatch');
    const pluginRoot = path.resolve(installed.cwd);
    check(pluginRoot.startsWith(path.join(base, 'state/uap/managed/clients/opencode') + path.sep),
      'OpenCode plugin root escaped the isolated root');
    equal(installed.command[1], path.join(pluginRoot,
      'io.github.777genius.agentplugins/runtime/launcher.mjs'),
      'OpenCode locked launcher path mismatch');
    const dataRoot = path.resolve(installed.environment?.PLUGIN_DATA || '');
    check(dataRoot.startsWith(path.join(base, 'state/uap/plugin-data') + path.sep),
      'OpenCode plugin data escaped the isolated root');
    equal(installed.environment, { PLUGIN_DATA: dataRoot, PLUGIN_ROOT: pluginRoot },
      'OpenCode local MCP environment mismatch');
  }
  equal(config.mcp['uap-sentinel'], sentinel, 'Unrelated disabled MCP was changed');
  equal(installedSkills(), expectedSkills, 'OpenCode installed skill set mismatch');
}

try {
  for (const directory of [
    'bin', 'project', 'home/.codex', 'home/.cursor', 'home/.kiro', 'home/.gemini',
    'home/.cline', 'home/.codeium/windsurf', 'config/opencode',
    'config/Code/User/globalStorage/saoudrizwan.claude-dev/settings',
    'cache', 'state', 'data', 'tmp',
  ]) fs.mkdirSync(path.join(base, directory), { recursive: true });
  for (const executable of ['node', 'npm', 'npx']) {
    const original = path.join(path.dirname(process.execPath), executable);
    check(fs.existsSync(original), 'Node installation must include npm and npx');
    fs.symlinkSync(original, path.join(base, 'bin', executable));
  }
  // Never inherit PATH, tokens, credentials, proxy settings or user configuration.
  const systemPaths = ['/usr/bin', '/bin'];
  for (const directory of systemPaths) {
    for (const executable of [...targets, 'claude', 'copilot', 'kiro-cli', 'code']) {
      check(!fs.existsSync(path.join(directory, executable)), 'Agent executable found in system PATH');
    }
  }
  env = {
    PATH: [path.join(base, 'bin'), ...systemPaths].join(':'),
    HOME: path.join(base, 'home'), USERPROFILE: path.join(base, 'home'),
    XDG_CONFIG_HOME: path.join(base, 'config'), XDG_CACHE_HOME: path.join(base, 'cache'),
    XDG_DATA_HOME: path.join(base, 'data'), XDG_STATE_HOME: path.join(base, 'state/xdg'),
    CODEX_HOME: path.join(base, 'home/.codex'), AGENTPLUGINS_HOME: path.join(base, 'state/uap'),
    AGENTPLUGINS_CACHE_DIR: path.join(base, 'cache/uap'),
    NPM_CONFIG_CACHE: path.join(base, 'cache/npm'),
    NPM_CONFIG_USERCONFIG: path.join(base, 'home/user.npmrc'),
    NPM_CONFIG_GLOBALCONFIG: path.join(base, 'home/global.npmrc'),
    NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org',
    NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false',
    TMPDIR: path.join(base, 'tmp'), GIT_CONFIG_GLOBAL: path.join(base, 'home/.gitconfig'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', NO_COLOR: '1', CI: '1', LANG: 'C.UTF-8',
  };
  fs.writeFileSync(configPath, JSON.stringify({ mcp: { 'uap-sentinel': sentinel } }));
  const metadata = execute('npm-metadata', path.join(base, 'bin/npm'), [
    'view', `universal-agent-plugins@${version}`, 'version', 'dist.integrity', '--json',
  ]);
  check(metadata.version === version, 'Unexpected public npm version');
  check(/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(metadata['dist.integrity']), 'Missing npm integrity');
  summary.npm = { version: metadata.version, integrity: metadata['dist.integrity'] };
  const added = cli('add', ['add', source, '--target', targets.join(',')]);
  batch(added, 'add');
  check(/^sha256:[a-f0-9]{64}$/.test(added.data.tree_digest), 'Missing package tree digest');
  check(/^sha256:[a-f0-9]{64}$/.test(added.data.manifest_digest), 'Missing manifest digest');
  summary.packageDigests = {
    tree: added.data.tree_digest, manifest: added.data.manifest_digest,
  };
  for (const target of added.data.targets) {
    const components = target.output.result.plan.components;
    equal(components.filter((item) => item.kind === 'skill').map((item) => item.name).sort(),
      expectedSkills, 'Add plan skill set mismatch');
    equal(components.filter((item) => item.kind === 'mcp_server').map((item) => item.name),
      [name], 'Add plan MCP set mismatch');
  }
  summary.componentCounts = { skills: expectedSkills.length, mcpServers: 1, targets: targets.length };
  const info = cli('info', ['info', name]);
  equal(info.data.clients.map((item) => item.client_id).sort(), [...targets].sort(),
    'Info client set mismatch');
  check(info.data.clients.every((item) => item.materialization === 'materialized'),
    'Info reports incomplete materialization');
  summary.clientStates = info.data.clients.map(({ client_id, materialization, activation, authentication }) =>
    ({ client_id, materialization, activation, authentication }));
  inspectInstalled();
  batch(cli('update', ['update', name, '--target', targets.join(',')]), 'update');
  inspectInstalled();
  // No UI is open: acknowledge removal of prepared external packages, not runtime activation.
  // Default retained data is intentional; do not use --purge or retry uncertain mutations.
  batch(cli('remove', ['remove', name, '--target', targets.join(','), '--external-uninstalled']), 'remove');
  const state = readJSON(path.join(base, 'state/uap/state-v2.json'));
  check(Array.isArray(state.installations), 'Missing installation state after remove');
  check(state.installations.every((item) => Object.keys(item.clients).length === 0),
    'Managed client bindings remain after remove');
  const remaining = readJSON(configPath);
  equal(remaining.mcp['uap-sentinel'], sentinel, 'Remove changed unrelated disabled MCP');
  check(!Object.hasOwn(remaining.mcp, name), 'Managed OpenCode MCP remains after remove');
  for (const skill of expectedSkills) {
    check(!fs.existsSync(path.join(skillsPath, skill)), 'Managed skill folder remains after remove');
  }
  summary.zeroClientBindings = true;
  summary.unrelatedConfigPreserved = true;
  summary.success = true;
} catch (error) {
  // Only our bounded messages are emitted; subprocess stdout/stderr stay private digests.
  const message = String(error.message).split('\n')[0]
    .replaceAll(base, '<isolated-profile>').replaceAll(repo, '<checkout>');
  summary.failure = { step: currentStep, message: message.slice(0, 500) };
  process.exitCode = 1;
} finally {
  save();
  console.log(JSON.stringify(summary));
}
