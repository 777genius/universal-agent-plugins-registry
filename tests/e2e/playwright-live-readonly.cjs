#!/usr/bin/env node
'use strict';

// Public package startup and tools/list only. Never invokes a browser tool.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'playwright-tools-'));
const data = path.join(root, 'plugin-data');
const config = path.join(root, 'inspector.json');
const launcher = path.resolve(__dirname,
  '../../plugins/playwright/io.github.777genius.agentplugins/runtime/launcher.mjs');
fs.mkdirSync(data, { recursive: true });
fs.writeFileSync(config, JSON.stringify({
  mcpServers: {
    playwright: {
      command: 'node',
      args: [launcher],
      env: { PLUGIN_DATA: data },
    },
  },
}));

try {
  const result = spawnSync('npx', [
    '--yes', '@modelcontextprotocol/inspector@2.1.0', '--cli',
    '--config', config, '--server', 'playwright', '--method', 'tools/list',
  ], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    killSignal: 'SIGKILL',
    maxBuffer: 16 * 1024 * 1024,
    env: {
      ...process.env,
      PLUGIN_DATA: data,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
    },
  });
  assert(!result.error && result.status === 0, 'Inspector tools/list failed or timed out');
  const payload = JSON.parse(result.stdout);
  const names = payload.tools?.map((tool) => tool.name).sort();
  assert.equal(names?.length, 24, 'Unexpected Playwright tool count');
  for (const name of ['browser_click', 'browser_navigate', 'browser_snapshot']) {
    assert(names.includes(name), `Missing expected tool ${name}`);
  }
  console.log(JSON.stringify({
    package: '@playwright/mcp@0.0.80',
    inspector: '@modelcontextprotocol/inspector@2.1.0',
    toolCount: names.length,
    expectedToolsPresent: ['browser_click', 'browser_navigate', 'browser_snapshot'],
    scope: 'Integrity-locked MCP startup and tools/list only; no browser tool was invoked.',
  }));
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
