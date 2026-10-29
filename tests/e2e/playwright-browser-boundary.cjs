#!/usr/bin/env node
'use strict';

// One synthetic loopback page, one relative snapshot, and no accounts or external pages.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const readline = require('node:readline');
const { createHash } = require('node:crypto');
const { spawn } = require('node:child_process');

assert.equal(process.platform, 'linux', 'This browser fixture runs on the disposable Linux runner');
// Chromium's profile socket must fit Linux's Unix-socket pathname limit.
const root = fs.mkdtempSync('/tmp/pw-boundary-');
const managed = path.join(root, 'managed-playwright');
const data = path.join(root, 'plugin-data');
const runtimePath = 'io.github.777genius.agentplugins/runtime';
const marker = 'UAP_PLAYWRIGHT_DATA_BOUNDARY';
const owned = new Set();

function treeFingerprint(directory) {
  const entries = [];
  function visit(current, relative = '') {
    for (const name of fs.readdirSync(current).sort()) {
      const absolute = path.join(current, name);
      const item = path.join(relative, name);
      const stat = fs.lstatSync(absolute);
      assert(!stat.isSymbolicLink(), 'Managed package must not contain symlinks');
      entries.push([item, stat.mode & 0o777, stat.isDirectory() ? 'directory'
        : createHash('sha256').update(fs.readFileSync(absolute)).digest('hex')]);
      if (stat.isDirectory()) visit(absolute, item);
    }
  }
  visit(directory);
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

async function bounded(promise, timeout, label) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label + ' timed out')), timeout);
    })]);
  } finally { clearTimeout(timer); }
}

function killOwned(handle) {
  if (!handle.closed && handle.child.pid) {
    try { process.kill(-handle.child.pid, 'SIGKILL'); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
}

function start(args, env) {
  const child = spawn(process.execPath, args, {
    cwd: managed, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'],
  });
  const handle = { child, closed: false, stderr: '', error: null };
  owned.add(handle);
  child.on('error', (error) => { handle.error = error; });
  child.stdin.on('error', (error) => { handle.error ||= error; });
  let outputBytes = 0;
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      outputBytes += Buffer.byteLength(chunk);
      if (stream === child.stderr) handle.stderr = (handle.stderr + chunk).slice(-32768);
      if (outputBytes > 2 * 1024 * 1024) {
        handle.error = new Error('Child output limit exceeded');
        killOwned(handle);
      }
    });
  }
  handle.exit = new Promise((resolve) => child.once('close', (code, signal) => {
    handle.closed = true; owned.delete(handle); resolve({ code, signal });
  }));
  return handle;
}

async function run(args, env, timeout, label) {
  const handle = start(args, env);
  try {
    const result = await bounded(handle.exit, timeout, label);
    assert(!handle.error && result.code === 0, label + ' failed: ' + handle.stderr);
  } finally {
    killOwned(handle);
    await bounded(handle.exit, 5000, label + ' cleanup');
  }
}

function rpc(handle) {
  const pending = new Map();
  const lines = readline.createInterface({ input: handle.child.stdout });
  let nextId = 0, fatal;
  function fail(error) {
    fatal = error;
    for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(error); }
    pending.clear();
  }
  const send = (message) => handle.child.stdin.write(JSON.stringify(message) + '\n');
  lines.on('line', (line) => {
    try {
      const message = JSON.parse(line);
      assert.equal(message.jsonrpc, '2.0');
      if (message.method) {
        if (Object.hasOwn(message, 'id')) {
          assert.equal(message.method, 'ping', 'Unexpected server request');
          send({ jsonrpc: '2.0', id: message.id, result: {} });
        }
        return;
      }
      const waiter = pending.get(message.id);
      if (!waiter) return; // A timed-out request may reply during cleanup.
      pending.delete(message.id); clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
      else waiter.resolve(message.result);
    } catch (error) { fail(error); }
  });
  handle.child.once('close', () => fail(new Error('MCP exited: ' + handle.stderr)));
  return {
    send,
    request(method, params, timeout = 30000) {
      if (fatal || handle.closed) return Promise.reject(fatal || new Error('MCP closed'));
      return new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => {
          pending.delete(id); reject(new Error(method + ' timed out'));
        }, timeout);
        pending.set(id, { resolve, reject, timer });
        send({ jsonrpc: '2.0', id, method, params });
      });
    },
    close: () => lines.close(),
  };
}

async function main() {
  let server, session, client, initialized = false, browserClosed = false, proof;
  try {
    fs.cpSync(path.resolve(__dirname, '../../plugins/playwright'), managed, { recursive: true });
    for (const directory of ['home', 'cache', 'config', 'tmp', 'browsers']) {
      fs.mkdirSync(path.join(data, directory), { recursive: true });
    }
    const userNpmrc = path.join(data, 'user.npmrc');
    const globalNpmrc = path.join(data, 'global.npmrc');
    fs.writeFileSync(userNpmrc, '');
    fs.writeFileSync(globalNpmrc, '');
    const env = {
      PATH: [path.dirname(process.execPath), '/usr/bin', '/bin'].join(path.delimiter),
      HOME: path.join(data, 'home'), USERPROFILE: path.join(data, 'home'),
      XDG_CACHE_HOME: path.join(data, 'cache'), XDG_CONFIG_HOME: path.join(data, 'config'),
      TMPDIR: path.join(data, 'tmp'), PLUGIN_DATA: data,
      PLAYWRIGHT_BROWSERS_PATH: path.join(data, 'browsers'),
      NPM_CONFIG_CACHE: path.join(data, 'npm-cache'), NPM_CONFIG_USERCONFIG: userNpmrc,
      NPM_CONFIG_GLOBALCONFIG: globalNpmrc, NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org',
      NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', CI: '1', NO_COLOR: '1',
    };
    const before = treeFingerprint(managed);
    const launcher = path.join(managed, runtimePath, 'launcher.mjs');
    await run([launcher, '--version'], env, 120000, 'Locked runtime materialization');
    const lock = fs.readFileSync(path.join(managed, runtimePath, 'package-lock.json'));
    const installed = path.join(data, 'npm-runtime', createHash('sha256').update(lock).digest('hex'));
    // Install the browser revision from the already integrity-locked runtime, never a floating npx package.
    await run([path.join(installed, 'node_modules/playwright/cli.js'),
      'install', '--with-deps', '--no-shell', 'chromium'], env, 240000, 'Pinned browser preparation');

    server = http.createServer((_request, response) => {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      response.end('<!doctype html><title>' + marker + '</title><h1>' + marker + '</h1>');
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
    });
    session = start([launcher, '--headless', '--isolated', '--browser', 'chromium'], env);
    client = rpc(session);
    // No client roots or output-dir override: the real MCP must use the launcher's cwd.
    const initializedResult = await client.request('initialize', {
      protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'uap-browser-boundary-fixture', version: '1.0.0' },
    });
    assert.equal(initializedResult.protocolVersion, '2024-11-05');
    assert(initializedResult.capabilities?.tools);
    initialized = true;
    client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const navigate = await client.request('tools/call', {
      name: 'browser_navigate', arguments: { url: 'http://127.0.0.1:' + server.address().port + '/' },
    });
    assert(!navigate.isError, JSON.stringify(navigate));
    assert(JSON.stringify(navigate).includes(marker), 'The real browser did not read the local fixture');
    const snapshot = await client.request('tools/call', {
      name: 'browser_snapshot', arguments: { filename: 'boundary-snapshot.md' },
    });
    assert(!snapshot.isError, JSON.stringify(snapshot));
    const closed = await client.request('tools/call', { name: 'browser_close', arguments: {} });
    assert(!closed.isError, JSON.stringify(closed));
    browserClosed = true;
    session.child.stdin.end();
    // The pinned MCP has a 15-second graceful exit watchdog after stdin closes.
    const exited = await bounded(session.exit, 20000, 'MCP shutdown');
    assert.equal(exited.code, 0, session.stderr);
    assert.equal(treeFingerprint(managed), before, 'The real browser modified the managed package');
    // Explicit relative filenames use cwd; only generated names use .playwright-mcp.
    const artifact = path.join(data, 'boundary-snapshot.md');
    assert(fs.readFileSync(artifact, 'utf8').includes(marker), 'Snapshot was not written under PLUGIN_DATA');
    proof = { package: '@playwright/mcp@0.0.80', fixture: 'loopback static HTML',
      browserTools: ['browser_navigate', 'browser_snapshot', 'browser_close'],
      snapshotUnderPluginData: true, managedPackageUnchanged: true,
      scope: 'Real headless browser and relative artifact boundary; no external page or account.' };
  } finally {
    if (initialized && !browserClosed && !session.closed) {
      await client.request('tools/call', { name: 'browser_close', arguments: {} }, 5000).catch(() => {});
    }
    if (session && !session.closed) {
      session.child.stdin.end();
      await bounded(session.exit, 5000, 'MCP cleanup').catch(() => killOwned(session));
    }
    for (const handle of owned) {
      killOwned(handle);
      await bounded(handle.exit, 5000, 'Owned process cleanup');
    }
    client?.close();
    if (server?.listening) {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
  console.log(JSON.stringify(proof));
}

main().catch((error) => {
  console.error(String(error.stack || error).replaceAll(root, '<temporary>'));
  process.exitCode = 1;
});
