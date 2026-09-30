import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mcpSmoke, stopTree, capturedProcess, recordNpmAudit } from "../scripts/qualify_runtime_remediation.mjs";

async function contract(root) {
const prior = { serverInfo: { name: "inert-contract", version: "1.0.0" }, toolNames: ["inert"] };
const env = { PATH: process.env.PATH, HOME: root, USERPROFILE: root };
for (const name of ["SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "SystemDrive"]) {
  const key = Object.keys(process.env).find((key) => key.toLowerCase() === name.toLowerCase());
  if (key) env[name] = process.env[key];
}
const fixture = (mode) => `
  const readline = require("node:readline");
  const mode = ${JSON.stringify(mode)};
  const send = (id, result) => process.stdout.write(JSON.stringify({jsonrpc:"2.0",id,result})+"\\n");
  process.stdin.on("end", () => { process.stdout.write("upstream CLI stopped successfully\\n"); process.exit(0); });
  readline.createInterface({input:process.stdin}).on("line", (line) => {
    const request=JSON.parse(line);
    if(request.method === "initialize") {
      if(mode === "malformed") {process.stdout.write("startup noise\\n");return;}
      send(1,{protocolVersion:"2024-11-05",serverInfo:{name:"inert-contract",version:"1.0.0"},capabilities:{tools:{}}});
    }
    if(request.method === "tools/list") {
      if(mode === "unexpected-death") {process.kill(process.pid,"SIGKILL");return;}
      send(2,{tools:[{name:"inert",inputSchema:{type:"object"}}]});
    }
  });
  setInterval(()=>{},1000);
`;
const good = {};
await mcpSmoke(["-e", fixture("eof-noise")], env, root, prior, good);
assert.equal(good.tools.count, 1);
assert.equal(good.exit.controlled_termination, true);
assert.equal(good.termination.dispatched, true);
assert.equal(good.exit.signal, process.platform === "win32" ? null : "SIGKILL");
console.log("PASS completed proof stops owned tree without manufacturing EOF stdout");

const malformed = {};
await assert.rejects(mcpSmoke(["-e", fixture("malformed")], env, root, prior, malformed), /invalid MCP stdout/);
assert.equal(malformed.exit.controlled_termination, false);
console.log("PASS pre-proof malformed stdout remains failure");

const dead = {};
await assert.rejects(mcpSmoke(["-e", fixture("unexpected-death")], env, root, prior, dead), /exited before MCP proof/);
if (process.platform === "win32") assert.notEqual(dead.exit.code, 0);
else assert.equal(dead.exit.signal, "SIGKILL");
assert.equal(dead.exit.controlled_termination, false);
console.log("PASS unexpected SIGKILL remains failure");
assert.equal(dead.termination.already_closed, true);
assert.equal(dead.termination.dispatched, false);

const earlyExit = {};
await assert.rejects(mcpSmoke(["-e", "process.exit(7)"], env, root, prior, earlyExit), /exited before MCP proof/);
assert.equal(earlyExit.exit.code, 7);
assert.equal(earlyExit.exit.controlled_termination, false);
assert.equal(earlyExit.termination.already_closed, true);
assert.equal(earlyExit.termination.dispatched, false);
console.log("PASS early exited PID/group is never signaled again");

await writeFile(join(root, "audit-fixture.mjs"), "const clean = process.argv.includes(\"--fixture-clean\");\nconst report = { metadata: { vulnerabilities: { low: 0, moderate: 0, high: clean ? 0 : 2, critical: 0, total: clean ? 0 : 2 }, dependencies: { prod: 2, total: 2 } },\n  vulnerabilities: clean ? {} : { axios: { severity: \"high\", range: \"<1.20.0\", isDirect: false,\n    via: [{ source: 111111, name: \"axios\", title: \"Public advisory fixture\", severity: \"high\", range: \"<1.20.0\", url: \"https://github.com/advisories/GHSA-m8m8-qj5v-23w3\" }] },\n    \"@hubspot/local-dev-lib\": { severity: \"high\", range: \"*\", via: [\"axios\"] } } };\nprocess.stdout.write(JSON.stringify(report));\nprocess.exit(Number(process.argv.find((arg) => arg.startsWith(\"--fixture-exit=\"))?.split(\"=\")[1] || \"1\"));\n");
const args = [join(root, "audit-fixture.mjs"), "audit", "--json"];
const observed = {};
await assert.rejects(capturedProcess(process.execPath, args, { cwd: root, env }, observed), /exit 1/);
assert.equal(observed.exit_code, 1);
console.log("PASS default nonzero process exit remains error");

const audit = { status: "running" };
const body = await capturedProcess(process.execPath, args, { cwd: root, env, captureAuditExitOne: true }, audit);
assert.equal(audit.exit_code, 1);
assert.throws(() => recordNpmAudit(body, audit), /2 vulnerabilities.*axios.*<1.20.0.*GHSA-m8m8-qj5v-23w3/);
assert.equal(audit.vulnerabilities.total, 2);
assert.equal(audit.public_diagnostic.packages[0].advisories[0].source, 111111);
assert.equal(audit.public_diagnostic.packages[1].via_dependencies[0], "axios");
assert.notEqual(audit.status, "passed");
console.log("PASS audit exit 1 preserves public names, ranges, IDs, counts and still fails");

await assert.rejects(capturedProcess(process.execPath, [...args, "--fixture-exit=2"], { cwd: root, env, captureAuditExitOne: true }, {}), /exit 2/);
console.log("PASS audit exit 2 remains error");

const cleanButNonzero = {};
const cleanBody = await capturedProcess(process.execPath, [...args, "--fixture-clean"], { cwd: root, env, captureAuditExitOne: true }, cleanButNonzero);
assert.throws(() => recordNpmAudit(cleanBody, cleanButNonzero), /exited 1 with 0 vulnerabilities/);
console.log("PASS even zero advisories cannot hide audit nonzero exit");

const zero = {};
const zeroBody = await capturedProcess(process.execPath, [...args, "--fixture-clean", "--fixture-exit=0"], { cwd: root, env, captureAuditExitOne: true }, zero);
recordNpmAudit(zeroBody, zero);
assert.equal(zero.status, "passed");
assert.throws(() => recordNpmAudit(`noise\n${zeroBody}`, zero), SyntaxError);
console.log("PASS only clean exit 0 passes; non-JSON stdout is never filtered");

if (process.platform === "win32") {
  console.log("SKIP POSIX missing-group/EPERM checks on Windows; real lifecycle checks above ran");
  return;
}

const noGroup = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { detached: false, stdio: "ignore", cwd: root, env });
await once(noGroup, "spawn");
const cleanup = stopTree(noGroup, env);
assert.equal(cleanup.dispatched, false);
assert.match(cleanup.error, /ESRCH|EPERM/);
noGroup.kill("SIGKILL"); await once(noGroup, "close");
console.log("PASS real missing owned process group reports cleanup failure without throwing");

// Inject only the demonstrated OS permission error, while using real spawned
// processes, real pipe handles and the real direct-PID fallback/settlement.
const originalKill = process.kill;
process.kill = (pid, ...args) => {
  if (pid < 0) throw Object.assign(new Error("inert permission failure"), { code: "EPERM" });
  return originalKill.call(process, pid, ...args);
};
try {
  const proofCleanupFailed = {};
  await assert.rejects(mcpSmoke(["-e", fixture("eof-noise")], env, root, prior, proofCleanupFailed), /EPERM/);
  assert.equal(proofCleanupFailed.tools.count, 1);
  assert.equal(proofCleanupFailed.termination.dispatched, false);
  assert.equal(proofCleanupFailed.termination.direct_pid_fallback, "dispatched");
  console.log("PASS completed tools cannot turn group cleanup EPERM into success");

  const pidFile = `${root}/owned-descendant.json`;
  const summary = {};
  const begin = Date.now();
  const parentFixture = `
    const child=require("node:child_process").spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"inherit"});
    require("node:fs").writeFileSync(${JSON.stringify(pidFile)},JSON.stringify({pid:child.pid}));
    setInterval(()=>{},1000);
  `;
  try {
    await assert.rejects(capturedProcess(process.execPath, ["-e", parentFixture], { env, cwd: root, timeout: 1000 }, summary), /process timeout/);
    assert(Date.now() - begin < 8000, "inherited descendant pipes must not keep finalization unbounded");
    assert.equal(summary.closure_timeout, true);
    assert.equal(summary.termination.dispatched, false);
    assert.match(summary.termination.error, /EPERM/);
    assert.equal(summary.termination.direct_pid_fallback, "dispatched");
    console.log("PASS EPERM plus live descendant pipes rejects within bounded cleanup and releases handles");
  } finally {
    const { pid } = JSON.parse(await readFile(pidFile, "utf8"));
    assert(Number.isSafeInteger(pid) && pid > 0 && pid !== process.pid);
    originalKill.call(process, pid, "SIGKILL");
    await rm(pidFile);
  }
} finally { process.kill = originalKill; }

}

const root = await mkdtemp(join(tmpdir(), "uap-qualification-contract-"));
try { await contract(root); }
finally { await rm(root, { recursive: true, force: true }); }
