"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { detectPlatform, expectedAssetName } = require("../lib/platform");
const { prepareRelease, verifyRelease } = require("../scripts/release-assets");
const { stage, stageEvidence, validatePackageMetadata } = require("../scripts/stage-release");

const COMMIT = "a".repeat(40);
const HISTORICAL_COMMIT = "5630ccd92aa91c8ac8cafb37eea8752fd82edce0";
const HISTORICAL_TREE = "cf13cbe2f64ae09d93ad34bfc6047fe99d5ca845";

async function fixtureEvidence(root) {
  const evidenceRoot = path.join(root, "evidence");
  await fsp.mkdir(path.join(evidenceRoot, "evidence"), { recursive: true });
  const record = {
    schema_version: 1,
    evidence_kind: "agentplugins_client_lifecycle",
    recorded_at: "2026-08-30",
    installer: {
      repository: "777genius/plugin-kit-ai",
      commit: HISTORICAL_COMMIT,
      tree: HISTORICAL_TREE,
      version: "0.1.22",
      binary_sha256: "8f417cea031d42b07badbe1b2a37dcd53deb2e5804f99d668f733309ecb4022b"
    },
    package: {
      selector: `ChromeDevTools/chrome-devtools-mcp@${"c".repeat(40)}`,
      repository: "ChromeDevTools/chrome-devtools-mcp",
      revision: "c".repeat(40),
      name: "chrome-devtools",
      version: "1.8.0",
      tree_digest: `sha256:${"d".repeat(64)}`,
      manifest_digest: `sha256:${"e".repeat(64)}`,
      acquisition_closure_digest: `sha256:${"f".repeat(64)}`
    },
    environment: {
      os: "macOS fixture",
      arch: "arm64",
      node: "24.18.0",
      clients: Object.fromEntries(["claude", "gemini", "opencode", "cline", "windsurf"].map((name) => [name, {
        version: ["cline", "windsurf"].includes(name) ? null : "1.0.0",
        host_surface_detected: true
      }])),
      isolation: {
        fresh_home: true, fresh_xdg_roots: true, fresh_claude_config: true,
        fresh_gemini_home: true, fresh_cline_data: true, fresh_agentplugins_state: true,
        user_project_accessed: false, user_client_config_mutated: false
      }
    },
    transcript: [
      {
        step: "add", argv: ["agentplugins", "add"], exit_code: 0, result: "success", status: "completed",
        acquisition_count: 1, source_kind: "github", fetched: true, validated: true,
        targets: Object.fromEntries(["claude", "gemini", "opencode", "cline", "windsurf"].map((name) => [name,
          { outcome: "passed", activation: "active", verification: "installation_verified" }])),
        shared_identity: { installation_count: 1, physical_artifact_id: "fixture", same_tree_digest_for_all_targets: true,
          same_manifest_digest_for_all_targets: true, same_closure_digest_for_all_targets: true }
      },
      {
        step: "client_discovery",
        checks: {
          claude: { argv: ["claude", "plugin", "list"], exit_code: 0, plugin_id: "fixture", plugin_version: "1.8.0",
            enabled: true, skill_count: 6, mcp_command: ["npx", "fixture"] },
          gemini_mcp: { argv: ["gemini", "mcp", "list"], exit_code: 0, server: "fixture", transport: "stdio",
            command: ["npx", "fixture"], connection: "disconnected" },
          gemini_skills: { argv: ["gemini", "skills", "list"], exit_code: 0, enabled_skill_count: 6 },
          opencode: { argv: ["opencode", "debug", "config"], exit_code: 0, server: "fixture", type: "local",
            command: ["npx", "fixture"], cwd_bound_to_managed_package: true, plugin_root_bound: true, plugin_data_bound: true },
          cline: { config: "fixture", transport: "stdio", command: ["npx", "fixture"], plugin_root_bound: true,
            plugin_data_bound: true, projected_skill_count: 6 },
          windsurf: { config: "fixture", command: ["npx", "fixture"], plugin_root_bound: true,
            plugin_data_bound: true, skills: "prepared_only" }
        }
      },
      { step: "doctor", argv: ["agentplugins", "doctor"], exit_code: 0, result: "success", read_only: true,
        installation_count: 1, projection_drift_findings: 0, authentication_not_checked_clients: [] },
      { step: "immutable_update_preflight", argv: ["agentplugins", "update"], exit_code: 1, result: "failure",
        status: "preflight_failed", reason: "immutable", succeeded: 0, failed: 5, mutated_targets: 0, postcondition: "unchanged" },
      { step: "repair", argv: ["agentplugins", "repair"], exit_code: 0, result: "success", status: "completed",
        succeeded: 5, failed: 0, targets: Object.fromEntries(["claude", "gemini", "opencode", "cline", "windsurf"].map((name) => [name, "passed"])) },
      { step: "remove", argv: ["agentplugins", "remove"], exit_code: 0, result: "success", status: "data_retained",
        succeeded: 5, failed: 0, plugin_data_preserved: true,
        targets: Object.fromEntries(["claude", "gemini", "opencode", "cline", "windsurf"].map((name) => [name, "external_completed"])) },
      { step: "post_remove", checks: Object.fromEntries(["agentplugins_installation_count", "claude_plugin_count", "gemini_mcp_count",
        "gemini_skill_count", "opencode_mcp_count", "cline_mcp_count", "cline_skill_count", "windsurf_mcp_count"].map((name) => [name, 0])) }
    ],
    claim_boundary: { lifecycle_e2e: true, client_discovery_e2e: true, browser_tool_runtime_e2e: false,
      model_turn_e2e: false, login_e2e: false, oauth_e2e: false, windsurf_skill_activation_claimed: false }
  };
  const recordBody = JSON.stringify(record, null, 2) + "\n";
  const recordDigest = crypto.createHash("sha256").update(recordBody).digest("hex");
  await fsp.writeFile(path.join(evidenceRoot, "evidence/agentplugins-client-e2e-2026-08-30.json"), recordBody);
  await fsp.writeFile(path.join(evidenceRoot, "AGENTPLUGINS_CLIENT_E2E.md"), [
    "# Fixture evidence",
    record.recorded_at,
    record.installer.commit,
    record.installer.tree,
    record.installer.version,
    record.installer.binary_sha256,
    record.package.selector,
    record.package.version,
    record.package.tree_digest,
    record.package.manifest_digest,
    "evidence/agentplugins-client-e2e-2026-08-30.json",
    recordDigest,
    ""
  ].join("\n"));
  return evidenceRoot;
}

function childNodeEnvironment(extra = {}) {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key === "NODE_UNIQUE_ID" || key === "NODE_CHANNEL_FD" ||
        key === "NODE_CHANNEL_SERIALIZATION_MODE" || key.startsWith("NODE_TEST_")) continue;
    environment[key] = value;
  }
  return { ...environment, ...extra };
}

test("release staging embeds every exact platform asset hash", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-stage-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "package");
  const assetsRoot = path.join(root, "assets");
  await fsp.mkdir(packageRoot);
  await fsp.mkdir(assetsRoot);
  await fsp.writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
    name: "universal-agent-plugins",
    version: "0.0.0-development",
    bin: { agentplugins: "bin/agentplugins.js" }
  }));
  const version = "0.1.0";
  for (const [platform, arch] of [["darwin", "x64"], ["darwin", "arm64"], ["linux", "x64"], ["linux", "arm64"], ["win32", "x64"], ["win32", "arm64"]]) {
    const info = detectPlatform(platform, arch);
    await fsp.writeFile(path.join(assetsRoot, expectedAssetName(version, info)), `${info.key}\n`);
  }
  prepareRelease(assetsRoot, `agentplugins-v${version}`, COMMIT);
  const release = verifyRelease(assetsRoot, `agentplugins-v${version}`, COMMIT);
  const evidenceRoot = await fixtureEvidence(root);
  const manifest = stage(packageRoot, assetsRoot, version, COMMIT, { evidenceRoot });
  assert.equal(manifest.version, version);
  assert.equal(manifest.npm_package, "universal-agent-plugins");
  assert.equal(manifest.producer.repository, "777genius/plugin-kit-ai");
  assert.equal(manifest.producer.commit, COMMIT);
  assert.equal(manifest.producer.release_manifest.sha256, release.manifest_sha256);
  assert.equal(manifest.client_evidence.installer.commit, HISTORICAL_COMMIT);
  assert.notEqual(manifest.client_evidence.installer.commit, manifest.producer.commit);
  assert.notEqual(manifest.client_evidence.installer.version, manifest.version);
  assert.equal(Object.keys(manifest.assets).length, 6);
  for (const asset of Object.values(manifest.assets)) {
    assert.match(asset.sha256, /^[0-9a-f]{64}$/);
    assert.ok(asset.size > 0);
  }
  const pkg = JSON.parse(await fsp.readFile(path.join(packageRoot, "package.json"), "utf8"));
  assert.equal(pkg.version, version);
  assert.equal(
    await fsp.readFile(path.join(packageRoot, "test/evidence-root/AGENTPLUGINS_CLIENT_E2E.md"), "utf8"),
    await fsp.readFile(path.join(evidenceRoot, "AGENTPLUGINS_CLIENT_E2E.md"), "utf8")
  );
});

test("staged package tests are hermetic to repository layout and caller cwd", {
  skip: process.env.AGENTPLUGINS_STAGED_TEST_CHILD === "1"
}, async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-hermetic-stage-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "detached-layout", "package");
  const assetsRoot = path.join(root, "release-assets");
  const callerRoot = path.join(root, "unrelated-caller");
  const npmCache = path.join(root, "npm-cache");
  await fsp.cp(path.resolve(__dirname, ".."), packageRoot, { recursive: true });
  await fsp.rm(path.join(packageRoot, "test", "evidence-root"), { recursive: true, force: true });
  await fsp.mkdir(assetsRoot);
  await fsp.mkdir(callerRoot);
  const version = "0.1.22";
  for (const [platform, arch] of [["darwin", "x64"], ["darwin", "arm64"], ["linux", "x64"], ["linux", "arm64"], ["win32", "x64"], ["win32", "arm64"]]) {
    const info = detectPlatform(platform, arch);
    await fsp.writeFile(path.join(assetsRoot, expectedAssetName(version, info)), `${info.key}\n`);
  }
  prepareRelease(assetsRoot, `agentplugins-v${version}`, COMMIT);
  const evidenceRoot = await fixtureEvidence(root);
  stage(packageRoot, assetsRoot, version, COMMIT, { evidenceRoot });

  const result = childProcess.spawnSync("npm", ["--prefix", packageRoot, "test"], {
    cwd: callerRoot,
    encoding: "utf8",
    env: childNodeEnvironment({
      AGENTPLUGINS_STAGED_TEST_CHILD: "1",
      AGENTPLUGINS_DETACHED_ASSERT_ROOT: packageRoot,
      NPM_CONFIG_CACHE: npmCache
    })
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /[ℹ#] tests [1-9][0-9]*/);
  assert.match(result.stdout, /[ℹ#] pass [1-9][0-9]*/);
  assert.match(result.stdout, /detached package execution sentinel/);

  const packed = childProcess.spawnSync("npm", ["pack", "--ignore-scripts", "--json"], {
    cwd: packageRoot,
    encoding: "utf8",
    env: childNodeEnvironment({ NPM_CONFIG_CACHE: npmCache })
  });
  assert.equal(packed.status, 0, `${packed.stdout}\n${packed.stderr}`);
  const packResult = JSON.parse(packed.stdout);
  assert.equal(packResult.length, 1);
  const packedFiles = packResult[0].files.map(({ path: filename }) => filename);
  assert.ok(packedFiles.includes("README.md"));
  assert.ok(packedFiles.includes("assets.json"));
  assert.equal(packedFiles.some((filename) => filename.startsWith("test/") || filename.includes("evidence-root")), false);
});

test("release staging rejects malformed and internally mismatched historical evidence", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-bad-evidence-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "package");
  const assetsRoot = path.join(root, "assets");
  await fsp.mkdir(packageRoot);
  await fsp.mkdir(assetsRoot);
  await fsp.writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
    name: "universal-agent-plugins", version: "0.0.0-development",
    bin: { agentplugins: "bin/agentplugins.js" }
  }));
  const version = "0.1.9";
  for (const [platform, arch] of [["darwin", "x64"], ["darwin", "arm64"], ["linux", "x64"], ["linux", "arm64"], ["win32", "x64"], ["win32", "arm64"]]) {
    const info = detectPlatform(platform, arch);
    await fsp.writeFile(path.join(assetsRoot, expectedAssetName(version, info)), `${info.key}\n`);
  }
  prepareRelease(assetsRoot, `agentplugins-v${version}`, COMMIT);
  const evidenceRoot = await fixtureEvidence(root);
  const recordPath = path.join(evidenceRoot, "evidence/agentplugins-client-e2e-2026-08-30.json");
  await fsp.writeFile(recordPath, "dummy\n");
  assert.throws(() => stage(packageRoot, assetsRoot, version, COMMIT, { evidenceRoot }), /JSON is malformed/);

  await fsp.rm(path.join(packageRoot, "test"), { recursive: true, force: true });
  const repairedEvidence = await fixtureEvidence(root);
  const record = JSON.parse(await fsp.readFile(recordPath, "utf8"));
  record.package.selector = `ChromeDevTools/chrome-devtools-mcp@${"9".repeat(40)}`;
  await fsp.writeFile(recordPath, JSON.stringify(record));
  assert.throws(() => stage(packageRoot, assetsRoot, version, COMMIT, { evidenceRoot: repairedEvidence }), /package identity is invalid/);

  await fixtureEvidence(root);
  const extraKeyRecord = JSON.parse(await fsp.readFile(recordPath, "utf8"));
  extraKeyRecord.unexpected = true;
  await fsp.writeFile(recordPath, JSON.stringify(extraKeyRecord));
  assert.throws(() => stage(packageRoot, assetsRoot, version, COMMIT, { evidenceRoot }), /record keys are invalid/);

  await fixtureEvidence(root);
  const markdownPath = path.join(evidenceRoot, "AGENTPLUGINS_CLIENT_E2E.md");
  const markdown = await fsp.readFile(markdownPath, "utf8");
  await fsp.writeFile(markdownPath, markdown.replace(/[0-9a-f]{64}\n$/, `${"0".repeat(64)}\n`));
  assert.throws(() => stage(packageRoot, assetsRoot, version, COMMIT, { evidenceRoot }), /does not bind/);
});

test("identical release bytes at different commits produce distinct fail-closed metadata", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-commit-bound-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const version = "0.1.10";
  const results = [];
  for (const commit of ["1".repeat(40), "2".repeat(40)]) {
    const caseRoot = path.join(root, commit[0]);
    const packageRoot = path.join(caseRoot, "package");
    const assetsRoot = path.join(caseRoot, "assets");
    await fsp.mkdir(packageRoot, { recursive: true });
    await fsp.mkdir(assetsRoot);
    await fsp.writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
      name: "universal-agent-plugins", version: "0.0.0-development",
      bin: { agentplugins: "bin/agentplugins.js" }
    }));
    for (const [platform, arch] of [["darwin", "x64"], ["darwin", "arm64"], ["linux", "x64"], ["linux", "arm64"], ["win32", "x64"], ["win32", "arm64"]]) {
      const info = detectPlatform(platform, arch);
      await fsp.writeFile(path.join(assetsRoot, expectedAssetName(version, info)), `${info.key}\n`);
    }
    prepareRelease(assetsRoot, `agentplugins-v${version}`, commit);
    const evidenceRoot = await fixtureEvidence(caseRoot);
    results.push(stage(packageRoot, assetsRoot, version, commit, { evidenceRoot }));
  }
  assert.notEqual(results[0].producer.commit, results[1].producer.commit);
  assert.notEqual(results[0].producer.release_manifest.sha256, results[1].producer.release_manifest.sha256);
  assert.equal(results[0].client_evidence.record_sha256, results[1].client_evidence.record_sha256);
});

test("release verification fails closed on checksum, size, and manifest mismatch", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-release-assets-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const version = "0.1.4";
  for (const [platform, arch] of [["darwin", "x64"], ["darwin", "arm64"], ["linux", "x64"], ["linux", "arm64"], ["win32", "x64"], ["win32", "arm64"]]) {
    const info = detectPlatform(platform, arch);
    await fsp.writeFile(path.join(root, expectedAssetName(version, info)), `${info.key}\n`);
  }
  prepareRelease(root, `agentplugins-v${version}`, COMMIT);
  assert.equal(verifyRelease(root, `agentplugins-v${version}`, COMMIT).gate_eligible, true);

  await fsp.writeFile(path.join(root, "ambiguous-extra-asset"), "unexpected");
  assert.throws(() => verifyRelease(root, `agentplugins-v${version}`, COMMIT), /must contain exactly/);
  await fsp.rm(path.join(root, "ambiguous-extra-asset"));

  const manifestPath = path.join(root, "release-manifest.json");
  const manifest = JSON.parse(await fsp.readFile(manifestPath, "utf8"));
  manifest.assets["linux-amd64"].size += 1;
  await fsp.writeFile(manifestPath, JSON.stringify(manifest));
  const checksumsPath = path.join(root, "checksums.txt");
  const manifestDigest = crypto.createHash("sha256").update(await fsp.readFile(manifestPath)).digest("hex");
  const checksums = (await fsp.readFile(checksumsPath, "utf8")).replace(
    /^[0-9a-f]{64}  release-manifest\.json$/m,
    `${manifestDigest}  release-manifest.json`
  );
  await fsp.writeFile(checksumsPath, checksums);
  assert.throws(() => verifyRelease(root, `agentplugins-v${version}`, COMMIT), /asset metadata mismatch/);

  prepareRelease(root, `agentplugins-v${version}`, COMMIT);
  await fsp.appendFile(path.join(root, `agentplugins_${version}_linux_amd64`), "changed");
  assert.throws(() => verifyRelease(root, `agentplugins-v${version}`, COMMIT), /checksum mismatch/);

  prepareRelease(root, `agentplugins-v${version}`, COMMIT);
  const wrongIdentity = JSON.parse(await fsp.readFile(manifestPath, "utf8"));
  wrongIdentity.commit = "b".repeat(40);
  await fsp.writeFile(manifestPath, JSON.stringify(wrongIdentity));
  assert.throws(() => verifyRelease(root, `agentplugins-v${version}`, COMMIT), /identity does not match/);
});

test("legacy manifests are audit-only and never gate eligible", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-legacy-assets-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const version = "0.1.4";
  for (const [platform, arch] of [["darwin", "x64"], ["darwin", "arm64"], ["linux", "x64"], ["linux", "arm64"], ["win32", "x64"], ["win32", "arm64"]]) {
    const info = detectPlatform(platform, arch);
    await fsp.writeFile(path.join(root, expectedAssetName(version, info)), `${info.key}\n`);
  }
  const { assets } = prepareRelease(root, `agentplugins-v${version}`, COMMIT);
  await fsp.writeFile(path.join(root, "release-manifest.json"), JSON.stringify({
    schema_version: 1,
    tag: `agentplugins-v${version}`,
    commit: COMMIT
  }) + "\n");
  const names = [...Object.values(assets).map((asset) => asset.file), "release-manifest.json"];
  const checksums = names.map((name) => {
    const body = fs.readFileSync(path.join(root, name));
    return `${crypto.createHash("sha256").update(body).digest("hex")}  ${name}`;
  }).join("\n") + "\n";
  await fsp.writeFile(path.join(root, "checksums.txt"), checksums);
  assert.throws(() => verifyRelease(root, `agentplugins-v${version}`, COMMIT), /schema or version/);
  const audited = verifyRelease(root, `agentplugins-v${version}`, COMMIT, { allowLegacyManifest: true });
  assert.equal(audited.manifest_schema, 1);
  assert.equal(audited.gate_eligible, false);

  const stagingRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "agentplugins-legacy-stage-"));
  t.after(() => fsp.rm(stagingRoot, { recursive: true, force: true }));
  const packageRoot = path.join(stagingRoot, "package");
  await fsp.mkdir(packageRoot);
  await fsp.writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
    name: "universal-agent-plugins", version: "0.0.0-development", bin: { agentplugins: "bin/agentplugins.js" }
  }));
  const evidenceRoot = await fixtureEvidence(stagingRoot);
  assert.throws(() => stage(packageRoot, root, version, COMMIT, { allowLegacyManifest: true, evidenceRoot }), /gate-eligible schema-v2/);
});

test("npm distribution name is independent from the agentplugins binary name", () => {
  for (const name of [
    "agentplugins",
    "universal-agent-plugins",
    "agentplugins-cli",
    "@ilyazelenko/agentplugins",
    "@777genius/agentplugins"
  ]) {
    assert.equal(validatePackageMetadata({
      name,
      bin: { agentplugins: "bin/agentplugins.js" }
    }), name);
  }
});

test("release staging rejects unsafe package metadata", () => {
  assert.throws(() => stageEvidence("package", "docs"), /evidence root must be absolute/);
  for (const name of ["AgentPlugins", " agentplugins ", 123, null]) {
    assert.throws(
      () => validatePackageMetadata({ name, bin: { agentplugins: "bin/agentplugins.js" } }),
      /package name is invalid/
    );
  }
  assert.throws(
    () => validatePackageMetadata({ name: "agentplugins-cli", bin: { other: "bin/agentplugins.js" } }),
    /must expose the agentplugins binary/
  );
});
