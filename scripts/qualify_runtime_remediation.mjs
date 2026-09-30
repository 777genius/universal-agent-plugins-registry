#!/usr/bin/env node
// This is credential-free runtime evidence, never installer/release qualification.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { delimiter, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { StringDecoder } from "node:string_decoder";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const AUDIT = "registry/upstream-promotion-audit/runtime-dependencies/2026-09-30";
const RUNTIME = "io.github.777genius.agentplugins/runtime";
const NODE = "v24.20.0";
const NPM = "12.0.2";
// Observed from https://registry.npmjs.org/npm/12.0.2; engines support ^24.15.0.
const NPM_INTEGRITY = "sha512-uIXokLlBj6FpNUTQX1PmT5pz7BlIN9QlixX+zdaSNHsd0qUXsbDLr50xzY6Sw7cJVr0uzHKDOle0swmPW/p5Qw==";
const EXPECTED = [
  ["context7", "@upstash/context7-mcp", "4.1.1", "0.2.3"],
  ["firebase", "firebase-tools", "15.32.0", "0.2.4"],
  ["hubspot-developer", "@hubspot/cli", "8.15.0", "0.2.4"],
];
const LAUNCHER_DIGEST = "sha256:2d2cfe5853a02bd67940b2c840e32d34a33e6fa4cc630130b508208f134a610b";
const PROTOCOL = "2024-11-05";
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const STDERR_LIMIT = 256 * 1024;
const digest = (body) => `sha256:${createHash("sha256").update(body).digest("hex")}`;
const json = async (path) => JSON.parse(await readFile(path, "utf8"));
let output = null;
const evidence = {
  format_version: 1, status: "running", started_at: new Date().toISOString(),
  source_sha: null, node_version: process.version, npm_version: NPM,
  npm_integrity: NPM_INTEGRITY, platform: process.platform, arch: process.arch,
  run_id: process.env.QUALIFICATION_RUN_ID || null,
  run_attempt: process.env.QUALIFICATION_RUN_ATTEMPT || null,
  scope: "Exact candidate cold launcher, MCP initialize/tools/list, installed npm signatures/available attestations and advisory audit; no tool calls, accounts, client activation, installer release or complete source-to-artifact binding.",
  results: [],
};
const save = async () => { if (output) await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`); };

// Never persist raw stdout (tool schemas, npm metadata) or inherited environment.
function safeMessage(value) {
  return String(value).replace(/(Bearer\s+)[^\s]+/gi, "$1[redacted]")
    .replace(/((?:token|password|secret|api[_-]?key)\s*[=:]\s*)[^\s,]+/gi, "$1[redacted]")
    .replace(/https?:\/\/[^\s]+/gi, (url) => {
      try { const u = new URL(url); return `${u.protocol}//${u.hostname}${u.pathname}`; }
      catch { return "[redacted URL]"; }
    }).slice(-4096);
}

// Independent reproduction of build_registry.directory_tree_digest's byte framing.
// Candidate entries are ordinary files/directories; reject symlinks and special files.
async function treeDigest(root) {
  const entries = [];
  async function walk(directory, prefix = "") {
    for (const name of await readdir(directory)) {
      assert(![".git", ".plugin-kit-ai.lock"].includes(name.toLowerCase()), "reserved package metadata");
      assert(name.normalize("NFC") === name && !/[\\\x00-\x1f]/.test(name), "unsafe package path");
      const relative = prefix ? `${prefix}/${name}` : name;
      const path = join(directory, name);
      const metadata = await lstat(path);
      assert(!metadata.isSymbolicLink(), `package symlink: ${relative}`);
      assert(metadata.isDirectory() || metadata.isFile(), `special package entry: ${relative}`);
      assert(relative.split("/").length <= 32, "package depth limit");
      entries.push([
        Buffer.from(relative), Buffer.from(metadata.isDirectory() ? "directory" : "file"),
        Buffer.from(metadata.isDirectory() ? "040000" : metadata.mode & 0o111 ? "100755" : "100644"),
        Buffer.alloc(0), metadata.isDirectory() ? Buffer.alloc(0) : await readFile(path),
      ]);
      if (metadata.isDirectory()) await walk(path, relative);
    }
  }
  assert((await lstat(root)).isDirectory(), "package root must be a directory");
  await walk(root);
  const folded = entries.map(([path]) => path.toString().toLowerCase());
  assert.equal(new Set(folded).size, folded.length, "case-folded path collision");
  const hash = createHash("sha256");
  const frame = (value) => {
    const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(value.length));
    hash.update(size); hash.update(value);
  };
  frame(Buffer.from("agentplugins.package-tree\0sha256\0v1"));
  for (const entry of entries.sort((a, b) => Buffer.compare(a[0], b[0]))) {
    for (const field of [Buffer.from("entry"), ...entry]) frame(field);
  }
  return { digest: `sha256:${hash.digest("hex")}`, file_count: entries.filter((e) => e[1].toString() === "file").length };
}

async function validateSources() {
  const recordPath = join(REPO, AUDIT, "remediation-candidates.json");
  const recordBody = await readFile(recordPath);
  const record = JSON.parse(recordBody);
  const smokePath = join(REPO, AUDIT, "launcher-smoke-result.json");
  const smokeBody = await readFile(smokePath);
  const smoke = JSON.parse(smokeBody);
  evidence.record_digest = digest(recordBody);
  evidence.expected_tools_evidence_digest = digest(smokeBody);
  assert.equal(record.format_version, 1);
  assert.equal(record.candidates.length, EXPECTED.length);
  assert.deepEqual(record.candidates.map((c) => c.product_id), EXPECTED.map((c) => c[0]));
  const validated = [];
  for (const [id, dependency, version, packageVersion] of EXPECTED) {
    const candidate = record.candidates.find((c) => c.product_id === id);
    assert.equal(candidate.candidate_path, `${AUDIT}/candidates/${id}`);
    assert.equal(candidate.runtime.package, dependency);
    assert.equal(candidate.runtime.version, version);
    assert.equal(candidate.candidate_package_version, packageVersion);
    assert.equal(candidate.runtime.omit_optional, id === "firebase");
    const root = join(REPO, candidate.candidate_path);
    const manifest = await json(join(root, "plugin.json"));
    assert.equal(manifest.name, id);
    assert.equal(manifest.version, packageVersion);
    assert.equal(digest(await readFile(join(root, "plugin.json"))), candidate.candidate_manifest_digest);
    const tree = await treeDigest(root);
    assert.equal(tree.digest, candidate.candidate_tree_digest);
    const runtime = await json(join(root, RUNTIME, "runtime.json"));
    assert.deepEqual(runtime, candidate.runtime);
    assert.equal(digest(await readFile(join(root, RUNTIME, "package-lock.json"))), runtime.package_lock_sha256);
    assert.equal(digest(await readFile(join(root, RUNTIME, "launcher.mjs"))), LAUNCHER_DIGEST);
    const pkg = await json(join(root, RUNTIME, "package.json"));
    assert.deepEqual(pkg.dependencies, { [dependency]: version });
    assert.equal(pkg.scripts, undefined);
    const lock = await json(join(root, RUNTIME, "package-lock.json"));
    assert.equal(lock.lockfileVersion, 3);
    assert.deepEqual(lock.packages[""].dependencies, pkg.dependencies);
    assert.equal(lock.packages[`node_modules/${dependency}`].version, version);
    assert.equal(lock.packages[`node_modules/${dependency}`].integrity, candidate.npm_root_integrity);
    const mcp = await json(join(root, "mcp.json"));
    assert.deepEqual(Object.keys(mcp.mcpServers), [id]);
    const server = mcp.mcpServers[id];
    assert.equal(server.type, "stdio"); assert.equal(server.command, "node");
    assert.equal(server.args[0], `\${PLUGIN_ROOT}/${RUNTIME}/launcher.mjs`);
    assert(server.args.every((arg) => typeof arg === "string"));
    assert.deepEqual(server.env || {}, id === "hubspot-developer" ? {
      HUBSPOT_CLI_VERSION: runtime.version, HUBSPOT_MCP_STANDALONE: "false",
    } : {});
    const prior = smoke.results.find((r) => r.name === id);
    assert.equal(prior.status, "passed");
    assert.equal(prior.toolNames.length, prior.toolCount);
    assert.equal(new Set(prior.toolNames).size, prior.toolCount);
    validated.push({ candidate, root, server, prior, tree });
  }
  return validated;
}

async function freshEnvironment(root) {
  const paths = {};
  for (const name of ["home", "config", "cache", "tmp", "project", "plugin-data"]) {
    paths[name] = join(root, name); await mkdir(paths[name], { mode: 0o700 });
  }
  const env = {};
  // PATH permits the trusted Node/npm executable; Windows needs OS loader variables.
  for (const name of ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "SystemDrive"]) {
    const key = Object.keys(process.env).find((k) => k.toLowerCase() === name.toLowerCase());
    if (key) env[name] = process.env[key];
  }
  Object.assign(env, {
    HOME: paths.home, USERPROFILE: paths.home, APPDATA: paths.config, LOCALAPPDATA: paths.cache,
    XDG_CONFIG_HOME: paths.config, XDG_CACHE_HOME: paths.cache, XDG_DATA_HOME: paths["plugin-data"],
    TMPDIR: paths.tmp, TMP: paths.tmp, TEMP: paths.tmp, PLUGIN_DATA: paths["plugin-data"],
    CI: "true", LANG: "C.UTF-8", NO_COLOR: "1", FORCE_COLOR: "0",
    npm_config_cache: join(paths.cache, "npm"), npm_config_userconfig: join(paths.config, "user.npmrc"),
    npm_config_globalconfig: join(paths.config, "global.npmrc"), npm_config_registry: "https://registry.npmjs.org/",
    npm_config_ignore_scripts: "true", npm_config_fund: "false", npm_config_update_notifier: "false",
    npm_config_fetch_retries: "1", npm_config_fetch_timeout: "60000",
    GIT_CONFIG_GLOBAL: join(paths.config, "gitconfig"), GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0",
  });
  for (const path of [env.npm_config_userconfig, env.npm_config_globalconfig, env.GIT_CONFIG_GLOBAL]) {
    await writeFile(path, "", { flag: "wx", mode: 0o600 });
  }
  return { paths, env };
}

export function stopTree(child, env) {
  // Never throw from a stream/event callback: cleanup failure is evidence.
  const termination = { requested_signal: process.platform === "win32" ? "taskkill /T /F" : "SIGKILL", dispatched: false };
  try {
    assert(Number.isSafeInteger(child.pid) && child.pid > 0 && child.pid !== process.pid, "unsafe owned process PID");
    if (typeof child.exitCode === "number" || typeof child.signalCode === "string") {
      termination.already_closed = true;
      return termination; // Never signal a PID/process group after its owner exited.
    }
    if (process.platform === "win32") {
      const killed = spawnSync(join(env.SystemRoot, "System32", "taskkill.exe"), ["/pid", String(child.pid), "/T", "/F"],
        { env, stdio: "ignore", timeout: 10_000, windowsHide: true });
      if (killed.error) throw killed.error;
      assert.equal(killed.status, 0, "owned process tree taskkill failed");
    } else {
      process.kill(-child.pid, "SIGKILL");
    }
    termination.dispatched = true;
  } catch (error) {
    termination.error = safeMessage(`${error.code || "cleanup"}: ${error.message}`);
    // The ChildProcess handle owns this exact PID. A direct fallback can stop
    // the leader, but cannot turn failed tree cleanup into a successful proof.
    if (Number.isSafeInteger(child.pid) && child.pid > 0 && child.pid !== process.pid) {
      try { termination.direct_pid_fallback = child.kill("SIGKILL") ? "dispatched" : "not_dispatched"; }
      catch (fallbackError) { termination.direct_pid_fallback = safeMessage(fallbackError.message); }
    }
  }
  return termination;
}

function releaseChildHandles(child) {
  for (const stream of child.stdio || []) stream?.destroy();
  child.unref();
}

export function capturedProcess(command, args, { cwd, env, timeout = 240_000 }, summary) {
  return new Promise((accept, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32", windowsHide: true });
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), failure, settled = false, cleanupTimer;
    const finish = (code, signal) => {
      if (settled) return;
      settled = true; clearTimeout(timer); clearTimeout(cleanupTimer);
      Object.assign(summary, { exit_code: code, signal, stdout_bytes: stdout.length, stdout_digest: digest(stdout),
        stderr_bytes: stderr.length, stderr_digest: digest(stderr) });
      if (failure || code !== 0) {
        summary.error = safeMessage(failure?.message || `exit ${code}: ${stderr}`);
        releaseChildHandles(child); reject(new Error(summary.error));
      } else accept(stdout.toString("utf8"));
    };
    const terminate = (message) => {
      if (failure || settled) return;
      failure = new Error(message); summary.termination = stopTree(child, env);
      cleanupTimer = setTimeout(() => {
        summary.closure_timeout = true;
        releaseChildHandles(child); finish(null, null);
      }, 5000);
    };
    const timer = setTimeout(() => terminate("process timeout"), timeout);
    child.stdout.on("data", (chunk) => {
      if (stdout.length + chunk.length > OUTPUT_LIMIT) terminate("stdout limit exceeded");
      else stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length + chunk.length > STDERR_LIMIT) terminate("stderr limit exceeded");
      else stderr = Buffer.concat([stderr, chunk]);
    });
    child.on("error", (error) => terminate(error.message));
    child.on("close", finish);
  });
}

async function pinnedNpm(root, env) {
  const nodeRoot = dirname(process.execPath);
  const locations = [join(nodeRoot, "node_modules/npm/bin/npm-cli.js"), join(nodeRoot, "../lib/node_modules/npm/bin/npm-cli.js")];
  let bootstrap;
  for (const path of locations) { if ((await lstat(path).catch(() => null))?.isFile()) { bootstrap = path; break; } }
  assert(bootstrap, "setup-node bundled npm CLI not found");
  const target = join(root, "npm-cli"); await mkdir(target);
  await writeFile(join(target, "package.json"), JSON.stringify({ private: true, name: "runtime-qualification-tools", version: "1.0.0" }));
  evidence.npm_bootstrap = { status: "running" }; await save();
  await capturedProcess(process.execPath, [bootstrap, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", `npm@${NPM}`],
    { cwd: target, env }, evidence.npm_bootstrap);
  const lock = await json(join(target, "package-lock.json"));
  assert.equal(lock.packages["node_modules/npm"].version, NPM);
  assert.equal(lock.packages["node_modules/npm"].integrity, NPM_INTEGRITY);
  const cli = join(target, "node_modules/npm/bin/npm-cli.js");
  const check = {};
  assert.equal((await capturedProcess(process.execPath, [cli, "--version"], { cwd: target, env }, check)).trim(), NPM);
  evidence.npm_bootstrap.status = "passed"; evidence.npm_bootstrap.integrity_verified = true;
  // npm's shipped bin/npm shell script resolves relative to the Node installer,
  // so a prefix install alone would silently select setup-node's bundled npm.
  // Bind PATH's npm to this integrity-checked CLI without changing the launcher.
  const bin = join(root, "npm-bin"); await mkdir(bin);
  if (process.platform === "win32") {
    assert(!/[\r\n"%]/.test(process.execPath + cli), "unsafe Windows npm shim path");
    await writeFile(join(bin, "npm.cmd"), `@echo off\r\n"${process.execPath}" "${cli}" %*\r\n`, { flag: "wx" });
  } else {
    const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
    await writeFile(join(bin, "npm"), `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(cli)} "$@"\n`,
      { flag: "wx", mode: 0o755 });
  }
  evidence.npm_bootstrap.launcher_npm_binding = "disposable PATH shim to integrity-checked npm-cli.js; no shell workaround for Windows launcher";
  await save();
  return { cli, bin };
}

export async function mcpSmoke(args, env, cwd, prior, result) {
  const child = spawn(process.execPath, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"],
    detached: process.platform !== "win32", windowsHide: true });
  let buffered = "", total = 0, stderr = Buffer.alloc(0), fatal, finished = false, ownStop = false, aborted = false;
  const decoder = new StringDecoder("utf8");
  const stdoutHash = createHash("sha256");
  const pending = new Map();
  const abort = (error) => {
    fatal ||= error;
    if (aborted) return;
    aborted = true;
    for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(fatal); }
    pending.clear();
    // Keep the original protocol/process error if cleanup also fails.
    result.termination ||= stopTree(child, env);
  };
  const exit = new Promise((accept) => {
    child.on("error", abort);
    child.on("close", (code, signal) => {
      result.exit = { code, signal, controlled_termination: ownStop };
      if (!finished) abort(new Error(`launcher exited before MCP proof: ${code}/${signal}; ${safeMessage(stderr)}`));
      accept({ code, signal });
    });
  });
  child.stdin.on("error", (error) => { if (!ownStop || error.code !== "EPIPE") abort(error); });
  child.stderr.on("data", (chunk) => {
    if (stderr.length + chunk.length > STDERR_LIMIT) abort(new Error("MCP stderr limit exceeded"));
    else stderr = Buffer.concat([stderr, chunk]);
  });
  child.stdout.on("data", (chunk) => {
    total += chunk.length; stdoutHash.update(chunk);
    if (total > OUTPUT_LIMIT) return abort(new Error("MCP stdout limit exceeded"));
    buffered += decoder.write(chunk);
    while (buffered.includes("\n")) {
      const newline = buffered.indexOf("\n"); const line = buffered.slice(0, newline); buffered = buffered.slice(newline + 1);
      try {
        // Empty/non-JSON stdout lines fail: never filter launcher noise into success.
        const message = JSON.parse(line);
        assert.equal(message.jsonrpc, "2.0"); assert.equal(message.error, undefined, "MCP error response");
        if (Object.hasOwn(message, "id")) {
          const waiter = pending.get(message.id); assert(waiter, "unknown/duplicate MCP response ID");
          assert(Object.hasOwn(message, "result")); assert.equal(message.method, undefined);
          clearTimeout(waiter.timer); pending.delete(message.id); waiter.accept(message.result);
        } else {
          assert.equal(typeof message.method, "string", "invalid MCP notification");
        }
      } catch (error) { abort(new Error(`invalid MCP stdout: ${safeMessage(error.message)}`)); }
    }
  });
  const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`);
  const request = (id, method, params, timeout) => new Promise((accept, reject) => {
    if (fatal) return reject(fatal);
    const timer = setTimeout(() => abort(new Error(`${method} timeout`)), timeout);
    pending.set(id, { accept, reject, timer }); send({ jsonrpc: "2.0", id, method, params });
  });
  try {
    const initialize = await request(1, "initialize", { protocolVersion: PROTOCOL, capabilities: {},
      clientInfo: { name: "uap-runtime-remediation-qualification", version: "1.0.0" } }, 660_000);
    assert.equal(initialize.protocolVersion, PROTOCOL);
    assert.equal(initialize.serverInfo?.name, prior.serverInfo.name);
    assert.equal(initialize.serverInfo?.version, prior.serverInfo.version);
    assert(initialize.capabilities?.tools, "server must advertise tools capability");
    result.initialize = { protocol_version: initialize.protocolVersion, server_info: initialize.serverInfo,
      capabilities_digest: digest(JSON.stringify(initialize.capabilities)) }; await save();
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    const listed = await request(2, "tools/list", {}, 30_000);
    assert(Array.isArray(listed.tools)); assert.equal(listed.nextCursor, undefined, "unexpected paginated tool set");
    const names = listed.tools.map((tool) => tool.name);
    assert.equal(new Set(names).size, names.length, "duplicate tools");
    assert.deepEqual([...names].sort(), [...prior.toolNames].sort());
    for (const tool of listed.tools) assert.equal(tool.inputSchema?.type, "object", "tool must expose object input schema");
    result.tools = { count: names.length, names, response_digest: digest(JSON.stringify(listed)), called: false };
    if (fatal) throw fatal;
    // Qualification ends at the complete tool list. HubSpot's nested CLI emits
    // non-protocol stdout on EOF, so do not manufacture an EOF lifecycle test.
    // Kill only this detached owned tree and record the request before signaling.
    finished = true; ownStop = true;
    result.termination = stopTree(child, env);
    child.stdin.destroy();
    let timer;
    const stopped = await Promise.race([exit, new Promise((accept) => { timer = setTimeout(() => accept(null), 5000); })]);
    clearTimeout(timer);
    assert(!result.termination.error, result.termination.error);
    assert(stopped, "owned process tree did not close after bounded termination");
    if (process.platform !== "win32") {
      assert(stopped.code === 0 || stopped.code === null && stopped.signal === "SIGKILL" && result.termination.dispatched,
        "unexpected MCP exit after proof");
    } else {
      assert(stopped.code === 0 || result.termination.dispatched && stopped.signal === null,
        "unexpected MCP exit after proof");
    }
    assert.equal(buffered + decoder.end(), "", "unterminated MCP stdout");
    if (fatal) throw fatal;
  } catch (error) {
    abort(error);
    let timer;
    await Promise.race([exit, new Promise((accept) => { timer = setTimeout(accept, 5000); })]);
    clearTimeout(timer);
    if (!result.exit) result.exit = { code: null, signal: null, closure_timeout: true, controlled_termination: ownStop };
    releaseChildHandles(child);
    throw new Error(`${safeMessage(error.message)}; cleanup: ${result.termination?.error || "none"}; stderr: ${safeMessage(stderr)}`);
  } finally {
    result.output = { stdout_bytes: total, stdout_digest: `sha256:${stdoutHash.digest("hex")}`,
      stderr_bytes: stderr.length, stderr_digest: digest(stderr) };
    await save();
  }
}

async function qualify(item, npm) {
  const { candidate, root: source, server, prior, tree } = item;
  const result = { product_id: candidate.product_id, status: "running", candidate_path: candidate.candidate_path,
    package_version: candidate.candidate_package_version, runtime: candidate.runtime,
    manifest_digest: candidate.candidate_manifest_digest, tree_digest: tree.digest, source_file_count: tree.file_count,
    lock_digest: candidate.runtime.package_lock_sha256, launcher_digest: LAUNCHER_DIGEST, checks: {} };
  evidence.results.push(result); await save();
  try {
    const root = await realpath(await mkdtemp(join(tmpdir(), `uap-remediation-${candidate.product_id}-`)));
    const { paths, env } = await freshEnvironment(root);
    const copied = join(root, "package"); await cp(source, copied, { recursive: true, errorOnExist: true, force: false });
    assert.equal((await treeDigest(copied)).digest, tree.digest);
    env.PATH = `${npm.bin}${delimiter}${dirname(process.execPath)}${delimiter}${env.PATH || ""}`;
    Object.assign(env, server.env || {}); env.PLUGIN_ROOT = copied;
    const runtimeRoot = join(paths["plugin-data"], "npm-runtime", candidate.runtime.package_lock_sha256.slice(7));
    assert.deepEqual(await readdir(paths["plugin-data"]), [], "cold plugin data must be empty");
    assert.equal(await lstat(runtimeRoot).catch(() => null), null, "prewarmed runtime is forbidden");
    assert.equal(await lstat(join(copied, RUNTIME, "node_modules")).catch(() => null), null);
    result.cold = { disposable_root: root, package_root: copied, project_root: paths.project,
      runtime_root: runtimeRoot, plugin_data_initially_empty: true, source_node_modules_absent: true,
      inherited_env_allowlist: ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "SystemDrive"],
      manifest_env: server.env || {}, prewarm: false };
    result.checks.mcp = { status: "running" }; await save();
    const args = server.args.map((arg) => arg.replaceAll("${PLUGIN_ROOT}", copied));
    assert(args.every((arg) => !arg.includes("${")), "unresolved MCP argument");
    await mcpSmoke(args, env, paths.project, prior, result.checks.mcp);
    result.checks.mcp.status = "passed";
    result.checks.materialization = { status: "running" }; await save();
    const marker = await json(join(runtimeRoot, ".agentplugins-runtime.json"));
    assert.deepEqual(marker, { schema_version: 1, lock_digest: candidate.runtime.package_lock_sha256,
      package: candidate.runtime.package, version: candidate.runtime.version,
      omit_optional: candidate.runtime.omit_optional, entrypoint: candidate.runtime.entrypoint });
    const runtimeReal = await realpath(runtimeRoot);
    assert.equal(runtimeReal, resolve(runtimeRoot), "materialized runtime root cannot redirect");
    assert.equal(digest(await readFile(join(runtimeRoot, "package-lock.json"))), candidate.runtime.package_lock_sha256);
    const installedPackage = await json(join(runtimeRoot, "node_modules", candidate.runtime.package, "package.json"));
    assert.equal(installedPackage.version, candidate.runtime.version);
    assert((await lstat(join(runtimeRoot, candidate.runtime.entrypoint))).isFile());
    result.checks.materialization = { status: "passed", marker, marker_digest: digest(JSON.stringify(marker)), runtime_root: runtimeReal };
    const omit = ["--omit=dev", ...(candidate.runtime.omit_optional ? ["--omit=optional"] : [])];
    const audit = result.checks.npm_audit = { status: "running", command: ["audit", ...omit, "--json"] }; await save();
    const auditBody = await capturedProcess(process.execPath, [npm.cli, ...audit.command], { cwd: runtimeRoot, env }, audit);
    const audited = JSON.parse(auditBody);
    assert.equal(audited.error, undefined); assert.equal(audited.metadata?.vulnerabilities?.total, 0);
    audit.vulnerabilities = audited.metadata.vulnerabilities; audit.dependencies = audited.metadata.dependencies; audit.status = "passed";
    const signatures = result.checks.npm_signatures = { status: "running", command: ["audit", "signatures", ...omit] }; await save();
    const signatureBody = await capturedProcess(process.execPath, [npm.cli, ...signatures.command], { cwd: runtimeRoot, env }, signatures);
    const count = Number(signatureBody.match(/audited (\d+) packages? in/)?.[1]);
    const verified = Number(signatureBody.match(/(\d+) packages? (?:have|has) a?\s*verified registry signatures?/)?.[1]);
    const attestations = Number(signatureBody.match(/(\d+) packages? (?:have|has) a?\s*verified attestations?/)?.[1] || 0);
    assert(count > 0 && verified === count, "every npm-audited installed registry package must have a verified signature");
    Object.assign(signatures, { status: "passed", audited_packages: count, verified_registry_signatures: verified,
      verified_attestations: attestations, scope: "Installed closure only; available attestations, no uninstalled optional or complete source-to-artifact verification" });
    assert.equal((await treeDigest(source)).digest, tree.digest, "source package changed during qualification");
    assert.equal((await treeDigest(copied)).digest, tree.digest, "copied package changed during qualification");
    result.status = "passed";
  } catch (error) {
    result.status = "failed"; result.error = safeMessage(error.message);
    for (const check of Object.values(result.checks)) if (check.status === "running") { check.status = "failed"; check.error = result.error; }
  } finally { result.completed_at = new Date().toISOString(); await save(); }
}

async function main() {
  const options = process.argv.slice(2);
  assert(options.length === 1 && options[0] === "--validate-only" ||
    options.length === 2 && options[0] === "--output", "use --validate-only or --output <evidence.json>");
  const validateOnly = options[0] === "--validate-only";
  output = validateOnly ? null : resolve(options[1]);
try {
  await save();
  const git = spawnSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf8" });
  assert.equal(git.status, 0); evidence.source_sha = git.stdout.trim();
  assert.match(evidence.source_sha, /^[0-9a-f]{40}$/);
  const sources = await validateSources(); evidence.source_validation = "passed"; await save();
  if (validateOnly) {
    console.log(JSON.stringify({ source_sha: evidence.source_sha, source_validation: "passed", candidates: sources.map((s) => s.candidate.product_id) }));
  } else {
    assert.equal(process.env.GITHUB_ACTIONS, "true", "runtime execution is restricted to disposable GitHub-hosted runners");
    assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted", "self-hosted/user machines are forbidden");
    assert.equal(process.version, NODE, "exact setup-node version required");
    assert.equal(evidence.source_sha, process.env.QUALIFICATION_SOURCE_SHA, "checkout SHA differs from workflow source SHA");
    assert(["linux", "darwin", "win32"].includes(process.platform));
    const toolingRoot = await realpath(await mkdtemp(join(tmpdir(), "uap-remediation-tooling-")));
    const { env } = await freshEnvironment(toolingRoot);
    const npm = await pinnedNpm(toolingRoot, env);
    for (const source of sources) await qualify(source, npm);
    assert(evidence.results.every((r) => r.status === "passed"), "one or more candidate qualifications failed");
  }
  evidence.status = "passed";
} catch (error) {
  evidence.status = "failed"; evidence.error = safeMessage(error.message); process.exitCode = 1;
} finally {
  evidence.completed_at = new Date().toISOString(); await save();
  if (!validateOnly) console.log(JSON.stringify({ status: evidence.status, evidence: output,
    candidates: evidence.results.map((r) => ({ id: r.product_id, status: r.status, error: r.error })) }));
}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
