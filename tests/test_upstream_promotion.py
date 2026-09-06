import argparse
import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import upstream_promotion as promotion
from scripts import upstream_bridge_promotion as bridge_promotion
from scripts import run_upstream_promotion_materialization as lifecycle
from scripts import build_openai_compat as openai_compat
from scripts.build_registry import RegistryError, validated_package_facts
from scripts.repository_identity import CURRENT_REGISTRY_REPOSITORY
from scripts.validate_review_journey import materialize


ROOT = Path(__file__).resolve().parents[1]
FAKE_DIGEST = "sha256:" + "1" * 64
MANIFEST_DIGEST = "sha256:" + "2" * 64
REVIEWED_SHA = "a" * 40
MERGE_SHA = "b" * 40
TEST_RUNTIME_VERSION = "9.9.9"


def next_chrome_bridge_sequence() -> int:
    directory = promotion.read_object(ROOT / "registry/directory.json")
    bridge = next(item for item in directory["distributions"] if item["id"] == "777genius/chrome-devtools-bridge")
    return max(item["sequence"] for item in bridge["releases"]) + 1


def next_github_upstream_sequence() -> int:
    directory = promotion.read_object(ROOT / "registry/directory.json")
    upstream = next(
        (item for item in directory["distributions"] if item["id"] == "github/github"),
        None,
    )
    if upstream is None:
        return 1
    return max((item["sequence"] for item in upstream["releases"]), default=0) + 1


def run_git(repository: Path, *args: str) -> str:
    environment = {
        **os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", *args], cwd=repository, env=environment, check=True,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


def candidate(record: dict, release_sequence: int) -> dict:
    item = record["evidence"][0]
    return {
        "schema_version": 1, "decision": "reviewable_promotion_candidate",
        "product": {"id": "github", "manifest_name": "github"},
        "distribution": {"id": "github/github", "kind": "upstream"},
        "release": {
            "sequence": release_sequence, "package_version": "", "agent_plugins_schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "components": ["mcp"], "tree_digest_algorithm": "agentplugins-tree-sha256-v1",
            "tree_digest": FAKE_DIGEST, "manifest_digest": MANIFEST_DIGEST,
        },
        "policy": copy.deepcopy(record["policy"]),
        "source": {
            "repository": "github/github-mcp-server", "path": "agent-plugin", "upstream_pr_number": 3169,
            "upstream_pr_url": "https://github.com/github/github-mcp-server/pull/3169",
            "merged_at": "2026-09-01T00:00:00Z", "reviewed_pr_head_sha": REVIEWED_SHA,
            "official_candidate_sha": MERGE_SHA, "official_default_ref": "refs/remotes/origin/main",
            "official_default_tip_sha": MERGE_SHA, "byte_classification": "exact",
        },
        "evidence": [{
            "id": item["id"], "record_digest": promotion.sha256(promotion.canonical(item)),
            "level": "materialization", "client": "codex", "installer_version": "0.1.26",
            "artifact": copy.deepcopy(item["artifact"]),
        }],
        "gate_artifacts": [{"name": name, "artifact_digest": FAKE_DIGEST} for name in (
            "pr_metadata", "repository_identity", "default_history", "reviewed_identity",
            "candidate_identity", "package", "policy", "evidence",
        )],
    }


class UpstreamPromotionTests(unittest.TestCase):
    def test_real_watch_list_is_schema_valid_sorted_and_accepts_root_package(self) -> None:
        watch = promotion.validate_watch(ROOT / "registry/upstream-promotions.json")
        self.assertEqual([item["product_id"] for item in watch["entries"]], ["chrome-devtools", "cloudflare-docs", "github"])
        self.assertEqual(watch["entries"][0]["package_path"], ".")
        self.assertEqual(watch["entries"][0]["promotion_mode"], "locked_bridge_manual")
        self.assertEqual(watch["entries"][0]["distribution_id"], "777genius/chrome-devtools-bridge")

    def test_locked_bridge_entrypoint_cannot_escape_its_npm_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = promotion.validate_watch(ROOT / "registry/upstream-promotions.json")
            value["entries"][0]["bridge"]["entrypoint"] = "node_modules/chrome-devtools-mcp/../other/index.js"
            path = Path(temporary) / "watch.json"
            path.write_bytes(promotion.pretty(value))
            with self.assertRaisesRegex(promotion.PromotionError, "entrypoint must remain"):
                promotion.validate_watch(path)

    def test_materialize_supports_an_exact_repository_root_without_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            output = Path(temporary) / "output"
            repository.mkdir()
            run_git(repository, "init", "-q")
            (repository / "plugin.json").write_text("{}\n")
            (repository / "mcp.json").write_text("{}\n")
            (repository / "nested").mkdir()
            (repository / "nested/file.txt").write_text("ok\n")
            run_git(repository, "add", ".")
            run_git(repository, "commit", "-qm", "fixture")
            revision = run_git(repository, "rev-parse", "HEAD")
            output.mkdir()
            materialize(repository, revision, ".", output)
            self.assertEqual(sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()), ["mcp.json", "nested/file.txt", "plugin.json"])

    def test_external_root_package_does_not_depend_on_checkout_directory_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            shutil.copytree(ROOT / "plugins/context7", root)
            with self.assertRaisesRegex(RegistryError, "name must match package directory"):
                validated_package_facts(root)
            facts = validated_package_facts(root, require_directory_name=False)
            self.assertEqual(facts["manifest_name"], "context7")

    def test_materialization_runner_uses_only_disposable_client_homes_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli = root / "agentplugins"
            cli.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                "cmd=sys.argv[1]; dry='--dry-run' in sys.argv\n"
                "clients=['codex','cursor','kiro']\n"
                "targets=[{'target':x,'status':'external_completed'} for x in clients]\n"
                "data={}\n"
                "if cmd=='add' and dry: data={'revision':'b'*40}\n"
                "elif cmd=='add': data={'status':'completed','succeeded':3,'failed':0,'targets':targets,'plugin':'github','revision':'b'*40,'tree_digest':'sha256:'+'1'*64,'manifest_digest':'sha256:'+'2'*64,'version':'','target_outcomes':{x:{'outcome':'passed'} for x in clients}}\n"
                "elif cmd=='info': data={'name':'github','clients':[{'client_id':x,'materialization':'materialized'} for x in clients]}\n"
                "elif cmd=='doctor': data={'healthy':True}\n"
                "elif cmd=='remove': data={'status':'completed','succeeded':3,'failed':0,'targets':targets,'plugin_data_preserved':False,'data_retained':False}\n"
                "elif cmd=='list': data={'installations':[]}\n"
                "print(json.dumps({'schema_version':1,'command':cmd,'result':'success','data':data}))\n"
            )
            cli.chmod(0o755)
            sandbox = root / "sandbox"
            args = argparse.Namespace(
                cli=cli, installer_version="0.1.26", product_id="github",
                repository="github/github-mcp-server", revision=MERGE_SHA,
                path="agent-plugin", targets="codex,cursor,kiro", sandbox=sandbox,
                run_repository="777genius/universal-agent-plugins", run_id="1",
                run_attempt="1", source_sha="c" * 40, keep_sandbox=False,
                local_source_kind="local_bridge",
            )
            result = lifecycle.run(args)
            self.assertEqual(result["outcome"], "passed")
            self.assertEqual(result["clients"], ["codex", "cursor", "kiro"])
            self.assertFalse(sandbox.exists())

    def test_materialization_runner_accepts_all_current_clients_in_canonical_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli = root / "agentplugins"
            clients = list(lifecycle.CLIENT_ORDER)
            cli.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                f"clients={clients!r}\n"
                "cmd=sys.argv[1]; dry='--dry-run' in sys.argv\n"
                "targets=[{'target':x,'status':'external_completed'} for x in clients]\n"
                "data={}\n"
                "if cmd=='add' and dry: data={'revision':'b'*40}\n"
                "elif cmd=='add': data={'status':'completed','succeeded':len(clients),'failed':0,'targets':targets,'plugin':'context7','revision':'b'*40,'tree_digest':'sha256:'+'1'*64,'manifest_digest':'sha256:'+'2'*64,'version':'1.0.0','target_outcomes':{x:{'outcome':'passed'} for x in clients}}\n"
                "elif cmd=='info': data={'name':'context7','clients':[{'client_id':x,'materialization':'materialized'} for x in clients]}\n"
                "elif cmd=='doctor': data={'healthy':True}\n"
                "elif cmd=='remove': data={'status':'completed','succeeded':len(clients),'failed':0,'targets':targets,'plugin_data_preserved':False,'data_retained':False}\n"
                "elif cmd=='list': data={'installations':[]}\n"
                "print(json.dumps({'schema_version':1,'command':cmd,'result':'success','data':data}))\n"
            )
            cli.chmod(0o755)
            sandbox = root / "sandbox"
            args = argparse.Namespace(
                cli=cli, installer_version="0.1.51", product_id="context7",
                repository="upstash/context7", revision=MERGE_SHA,
                path="plugins/agent-plugins/context7", targets=",".join(clients),
                sandbox=sandbox, run_repository=CURRENT_REGISTRY_REPOSITORY,
                run_id="1", run_attempt="1", source_sha="c" * 40,
                keep_sandbox=True, local_source_kind="official_checkout",
            )
            result = lifecycle.run(args)
            self.assertEqual(result["clients"], clients)
            for client, (root_name, relative) in lifecycle.CLIENT_ROOTS.items():
                self.assertTrue((sandbox / root_name / relative).is_dir(), client)

    def test_materialization_runner_rejects_noncanonical_or_unknown_targets(self) -> None:
        base = argparse.Namespace(
            cli=Path("/missing"), installer_version="0.1.51", product_id="context7",
            repository="upstash/context7", revision=MERGE_SHA,
            path="plugins/agent-plugins/context7", sandbox=Path("/missing-sandbox"),
            run_repository=CURRENT_REGISTRY_REPOSITORY, run_id="1", run_attempt="1",
            source_sha="c" * 40, keep_sandbox=False,
            local_source_kind="local_bridge",
        )
        for targets in ("cursor,codex", "codex,codex", "chatgpt", "unknown"):
            with self.subTest(targets=targets), self.assertRaisesRegex(
                lifecycle.MaterializationError, "canonical order"
            ):
                lifecycle.run(argparse.Namespace(**vars(base), targets=targets))

    def test_context7_workflow_uses_an_authenticated_real_claude_cli(self) -> None:
        workflow = (ROOT / ".github/workflows/context7-upstream-materialization.yml").read_text()
        self.assertIn('CLAUDE_CODE_VERSION: "2.1.263"', workflow)
        self.assertIn(
            "CLAUDE_CODE_NPM_INTEGRITY: "
            "sha512-kvvBK6/69iTRYnq0TKVyxVZs1CxYCJGojshQSP+2qaDb66A2xtI4zbCuqkZUWLkFGmHSRqhFf/ATpzH2UNKcwg==",
            workflow,
        )
        self.assertIn('COPILOT_VERSION: "1.0.83"', workflow)
        self.assertIn(
            "COPILOT_NPM_INTEGRITY: "
            "sha512-M8uZI0V0dahYV1KZij3nGDxaXEGG7I7YUZzQPI7NEZkL/83Nl/tNTbPdxKtdWZbOmWoXsPKXty/eEYoj6RHDhA==",
            workflow,
        )
        self.assertIn('npm view "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" dist.integrity', workflow)
        self.assertIn('"@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"', workflow)
        self.assertIn('"@github/copilot@${COPILOT_VERSION}"', workflow)
        self.assertIn('node "$tools/node_modules/@anthropic-ai/claude-code/install.cjs"', workflow)
        self.assertIn('echo "$tools/node_modules/.bin" >> "$GITHUB_PATH"', workflow)

    def test_select_refuses_a_merged_pr_when_reviewed_head_changed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            watch = promotion.validate_watch(ROOT / "registry/upstream-promotions.json")
            watch["entries"] = [watch["entries"][0]]
            watch["entries"][0]["reviewed_head_sha"] = REVIEWED_SHA
            watch["entries"][0]["release_sequence"] = next_chrome_bridge_sequence()
            watch_path = root / "watch.json"
            watch_path.write_bytes(promotion.pretty(watch))
            gh = root / "gh"
            gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                "endpoint=sys.argv[-1]\n"
                "if endpoint.endswith('pulls?state=open&per_page=100'):\n"
                " print('[]')\n"
                "elif endpoint.endswith('/pulls/2623'):\n"
                " print(json.dumps({'number':2623,'state':'closed','draft':False,'merged_at':'2026-09-01T00:00:00Z','merge_commit_sha':'b'*40,'html_url':'https://github.com/ChromeDevTools/chrome-devtools-mcp/pull/2623','head':{'sha':'d'*40},'base':{'ref':'main'}}))\n"
                "else:\n"
                " print(json.dumps({'default_branch':'main'}))\n"
            )
            gh.chmod(0o755)
            args = argparse.Namespace(watch=watch_path, directory=ROOT / "registry/directory.json", gh=gh)
            with mock.patch.dict(os.environ, {"GH_TOKEN": "fixture"}):
                result = promotion.select(args)
            self.assertEqual(result["decision"], "none")
            self.assertEqual(result["diagnostics"][0]["outcome"], "reviewed_head_changed")

    def test_select_routes_exact_locked_bridge_merge_to_manual_pr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            watch = promotion.validate_watch(ROOT / "registry/upstream-promotions.json")
            watch["entries"] = [watch["entries"][0]]
            watch["entries"][0]["reviewed_head_sha"] = REVIEWED_SHA
            watch["entries"][0]["release_sequence"] = next_chrome_bridge_sequence()
            watch_path = root / "watch.json"
            watch_path.write_bytes(promotion.pretty(watch))
            gh = root / "gh"
            gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                "endpoint=sys.argv[-1]\n"
                "if endpoint.endswith('pulls?state=open&per_page=100'):\n print('[]')\n"
                "elif endpoint.endswith('/pulls/2623'):\n"
                f" print(json.dumps({{'number':2623,'state':'closed','draft':False,'merged_at':'2026-09-01T00:00:00Z','merge_commit_sha':'{MERGE_SHA}','html_url':'https://github.com/ChromeDevTools/chrome-devtools-mcp/pull/2623','head':{{'sha':'{REVIEWED_SHA}'}},'base':{{'ref':'main'}}}}))\n"
                "else:\n print(json.dumps({'default_branch':'main'}))\n"
            )
            gh.chmod(0o755)
            args = argparse.Namespace(watch=watch_path, directory=ROOT / "registry/directory.json", gh=gh)
            with mock.patch.dict(os.environ, {"GH_TOKEN": "fixture"}):
                result = promotion.select(args)
            self.assertEqual(result["decision"], "promote_bridge")
            self.assertFalse(result["entry"].get("auto_merge", False))

    @mock.patch.object(
        bridge_promotion,
        "active_registry_repository",
        return_value=CURRENT_REGISTRY_REPOSITORY,
    )
    def test_apply_locked_bridge_release_preserves_targets_and_requires_manual_merge(
        self,
        _active_repository: mock.Mock,
    ) -> None:
        directory = promotion.read_object(ROOT / "registry/directory.json")
        before = next(item for item in directory["distributions"] if item["id"] == "777genius/chrome-devtools-bridge")
        current_policy = next(item for item in before["release_policies"] if item["status"] == "active")
        current_targets = copy.deepcopy(current_policy["targets"])
        next_sequence = max(item["sequence"] for item in before["releases"]) + 1
        plan = {
            "product_id": "chrome-devtools", "distribution_id": "777genius/chrome-devtools-bridge",
            "release_sequence": next_sequence, "minimum_installer_version": "0.1.26", "previous_revision": MERGE_SHA,
            "upstream": {"repository": "ChromeDevTools/chrome-devtools-mcp", "merge_sha": MERGE_SHA},
            "package": {
                "path": "plugins/chrome-devtools", "version": "1.8.0-uap.1",
                "tree_digest": FAKE_DIGEST, "manifest_digest": MANIFEST_DIGEST, "components": ["mcp"],
            },
        }
        bridge_promotion.apply_bridge_release(directory, plan)
        after = next(item for item in directory["distributions"] if item["id"] == "777genius/chrome-devtools-bridge")
        self.assertEqual(after["releases"][-1]["sequence"], next_sequence)
        self.assertEqual(after["releases"][-2]["package_source"]["revision"], MERGE_SHA)
        self.assertEqual(after["releases"][-1]["build_provenance"]["upstream_revision"], MERGE_SHA)
        self.assertEqual(after["release_policies"][-2]["status"], "superseded")
        self.assertEqual(after["release_policies"][-1]["targets"], current_targets)
        self.assertEqual(after["release_policies"][-1]["current_evidence"], [])

    @mock.patch.object(
        bridge_promotion,
        "active_registry_repository",
        return_value=CURRENT_REGISTRY_REPOSITORY,
    )
    def test_prepare_locked_bridge_pins_exact_official_npm_runtime(
        self,
        _active_repository: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "official"
            repository.mkdir()
            run_git(repository, "init", "-q")
            (repository / "plugin.json").write_text(json.dumps({
                "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
                "name": "chrome-devtools", "version": TEST_RUNTIME_VERSION,
                "description": "Official Chrome DevTools MCP package.",
                "author": {"name": "ChromeDevTools"},
                "repository": "https://github.com/ChromeDevTools/chrome-devtools-mcp",
                "license": "Apache-2.0", "keywords": ["chrome", "mcp"],
            }) + "\n")
            (repository / "mcp.json").write_text(json.dumps({
                "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
                "mcpServers": {"chrome-devtools": {
                    "type": "stdio", "command": "npx",
                    "args": ["--prefix", "${PLUGIN_DATA}", f"chrome-devtools-mcp@{TEST_RUNTIME_VERSION}"],
                }},
            }) + "\n")
            (repository / "package.json").write_text(json.dumps({"name": "chrome-devtools-mcp", "version": TEST_RUNTIME_VERSION}) + "\n")
            (repository / "README.md").write_text("# Chrome DevTools\n")
            (repository / "LICENSE").write_text("Apache License 2.0 fixture\n")
            run_git(repository, "add", ".")
            run_git(repository, "commit", "-qm", "test: official package")
            merge_sha = run_git(repository, "rev-parse", "HEAD")

            mirror = root / "mirror" / "ChromeDevTools"
            mirror.mkdir(parents=True)
            subprocess.run(
                ["git", "clone", "--bare", str(repository), str(mirror / "chrome-devtools-mcp.git")],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            candidate = root / "candidate"
            candidate.mkdir()
            for name in ("assets", "bridges", "compat", "plugins", "registry", "docs", "scripts", "tests"):
                shutil.copytree(ROOT / name, candidate / name)
            next_sequence = next_chrome_bridge_sequence()
            candidate_watch = promotion.read_object(candidate / "registry/upstream-promotions.json")
            candidate_watch["entries"][0]["release_sequence"] = next_sequence
            (candidate / "registry/upstream-promotions.json").write_bytes(promotion.pretty(candidate_watch))
            run_git(candidate, "init", "-q")
            run_git(candidate, "add", ".")
            run_git(candidate, "commit", "-qm", "test: trusted base")
            base_sha = run_git(candidate, "rev-parse", "HEAD")
            entry = copy.deepcopy(promotion.validate_watch(ROOT / "registry/upstream-promotions.json")["entries"][0])
            entry["release_sequence"] = next_sequence
            selection = {
                "schema_version": 1, "decision": "promote_bridge", "entry": entry,
                "pr_metadata": {"merge_commit_oid": merge_sha, "merged_at": "2026-09-01T00:00:00Z"},
            }
            selection_path = root / "selection.json"
            selection_path.write_bytes(promotion.pretty(selection))
            fake_npm = root / "npm"
            fake_npm.write_text(
                "#!/usr/bin/env python3\n"
                "import json\nfrom pathlib import Path\n"
                "p=json.loads(Path('package.json').read_text()); name,version=next(iter(p['dependencies'].items()))\n"
                "lock={'name':p['name'],'version':'1.0.0','lockfileVersion':3,'requires':True,'packages':"
                "{'':p, f'node_modules/{name}':{'version':version,'resolved':f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz',"
                "'integrity':'sha512-eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA=='}}}\n"
                "Path('package-lock.json').write_text(json.dumps(lock,indent=2)+'\\n')\n"
            )
            fake_npm.chmod(0o755)
            output = root / "plan.json"
            plan = bridge_promotion.prepare(argparse.Namespace(
                selection=selection_path, official_repository=repository, root=candidate,
                npm=fake_npm, npm_cache=None, upstream_mirror=root / "mirror", output=output,
            ))
            self.assertFalse(plan["auto_merge"])
            self.assertTrue(plan["manual_review_required"])
            self.assertEqual(plan["upstream"]["merge_sha"], merge_sha)
            self.assertEqual(plan["runtime"]["version"], TEST_RUNTIME_VERSION)
            self.assertEqual(plan["package"]["version"], f"{TEST_RUNTIME_VERSION}-uap.1")
            self.assertIn(f"| `chrome-devtools-mcp` | `{TEST_RUNTIME_VERSION}` |", (candidate / "docs/COMPATIBILITY.md").read_text())
            self.assertIn(f"- `chrome-devtools-mcp@{TEST_RUNTIME_VERSION}`", (candidate / "docs/VERIFICATION.md").read_text())
            self.assertEqual(
                json.loads((candidate / "plugins/chrome-devtools/io.github.777genius.agentplugins/runtime/runtime.json").read_text())["package_lock_sha256"],
                plan["runtime"]["package_lock_sha256"],
            )
            raw_path = candidate / f"evidence/upstream-promotions/chrome-devtools/{merge_sha}/materialization.json"
            raw_path.parent.mkdir(parents=True)
            raw = {
                "schema_version": 1, "outcome": "passed", "product_id": "chrome-devtools",
                "repository": entry["repository"], "revision": merge_sha, "path": ".",
                "materialized_source": {"kind": "local_bridge", "path": str(candidate / "plugins/chrome-devtools")},
                "clients": [target["client"] for target in entry["targets"]],
                "installer_version": entry["minimum_installer_version"], "package": {
                    "package_version": plan["package"]["version"],
                    "tree_digest": plan["package"]["tree_digest"],
                    "manifest_digest": plan["package"]["manifest_digest"],
                },
                "run": {"repository": "777genius/universal-agent-plugins", "id": "1", "attempt": "1", "source_sha": "c" * 40},
            }
            raw_path.write_bytes(promotion.pretty(raw))
            run_git(candidate, "add", "bridges/chrome-devtools", "plugins/chrome-devtools", "docs/COMPATIBILITY.md", "docs/VERIFICATION.md", str(raw_path.relative_to(candidate)))
            run_git(candidate, "commit", "-qm", "test(directory): record upstream promotion evidence")
            bridge_commit = run_git(candidate, "rev-parse", "HEAD")

            audit_path = f"registry/upstream-promotion-audit/chrome-devtools/{merge_sha}/manual-review.json"
            bridge_promotion.finalize(argparse.Namespace(
                selection=selection_path, plan=output, materialization=raw_path,
                artifact_revision=bridge_commit, previous_revision=base_sha,
                artifact_path=str(raw_path.relative_to(candidate)),
                directory=candidate / "registry/directory.json", output=candidate / audit_path,
                root=candidate,
            ))
            directory = promotion.read_object(candidate / "registry/directory.json")
            (candidate / "registry/review-preview.json").write_bytes(
                bridge_promotion.encoded(bridge_promotion.directory_preview(directory))
            )
            (candidate / "registry/review-search.json").write_bytes(
                bridge_promotion.encoded(bridge_promotion.directory_search(directory))
            )
            promotion.sync_production_directory_identity(candidate)
            product = next(item for item in directory["products"] if item["id"] == "chrome-devtools")
            projected = candidate / "compat/openai/plugins/chrome-devtools"
            shutil.rmtree(projected)
            openai_compat.project_portable_package(
                candidate / "plugins/chrome-devtools",
                projected,
                product,
                None,
                brand_assets=candidate / "assets",
            )
            run_git(
                candidate,
                "add",
                "registry",
                "compat/openai/plugins/chrome-devtools",
                *(path.as_posix() for path in promotion.PRODUCTION_DIRECTORY_IDENTITY_PATHS),
            )
            run_git(candidate, "commit", "-qm", "feat(directory): review locked chrome-devtools bridge")
            head_sha = run_git(candidate, "rev-parse", "HEAD")
            verdict = bridge_promotion.verify_pr(
                repository=candidate, base_sha=base_sha, head_sha=head_sha,
                branch=f"automation/upstream-promotion-chrome-devtools-{merge_sha[:12]}-{base_sha[:12]}",
                product_id="chrome-devtools", short_sha=merge_sha[:12],
                commits=[bridge_commit, head_sha], audit_path=audit_path,
            )
            self.assertEqual(verdict["outcome"], "verified")
            self.assertFalse(verdict["auto_merge"])

            manifest_path = projected / ".codex-plugin/plugin.json"
            manifest = promotion.read_object(manifest_path)
            manifest["description"] = "tampered projection"
            manifest_path.write_bytes(promotion.pretty(manifest))
            run_git(candidate, "add", str(manifest_path.relative_to(candidate)))
            run_git(candidate, "commit", "--amend", "-qm", "feat(directory): review locked chrome-devtools bridge")
            tampered_head = run_git(candidate, "rev-parse", "HEAD")
            with self.assertRaisesRegex(
                bridge_promotion.PromotionError,
                "OpenAI compatibility projection is stale or non-deterministic",
            ):
                bridge_promotion.verify_pr(
                    repository=candidate, base_sha=base_sha, head_sha=tampered_head,
                    branch=f"automation/upstream-promotion-chrome-devtools-{merge_sha[:12]}-{base_sha[:12]}",
                    product_id="chrome-devtools", short_sha=merge_sha[:12],
                    commits=[bridge_commit, tampered_head], audit_path=audit_path,
                )

    def test_apply_and_verify_exact_two_commit_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_sequence = next_github_upstream_sequence()
            repository = Path(temporary) / "repository"
            repository.mkdir()
            run_git(repository, "init", "-q")
            (repository / "registry").mkdir()
            for name in ("directory.json", "review-preview.json", "review-search.json"):
                shutil.copy2(ROOT / "registry" / name, repository / "registry" / name)
            (repository / "registry/publication").mkdir()
            shutil.copy2(
                ROOT / "registry/publication/config.json",
                repository / "registry/publication/config.json",
            )
            (repository / "scripts").mkdir()
            shutil.copy2(
                ROOT / "scripts/run_launch_evidence_e2e.py",
                repository / "scripts/run_launch_evidence_e2e.py",
            )
            (repository / "tests/e2e").mkdir(parents=True)
            shutil.copy2(
                ROOT / "tests/e2e/production-launch.json",
                repository / "tests/e2e/production-launch.json",
            )
            shutil.copy2(
                ROOT / "tests/test_run_launch_evidence_e2e.py",
                repository / "tests/test_run_launch_evidence_e2e.py",
            )
            run_git(repository, "add", ".")
            run_git(repository, "commit", "-qm", "base")
            base = run_git(repository, "rev-parse", "HEAD")

            raw_path = f"evidence/upstream-promotions/github/{MERGE_SHA}/materialization.json"
            raw_file = repository / raw_path
            raw_file.parent.mkdir(parents=True)
            raw = {
                "schema_version": 1, "outcome": "passed", "product_id": "github",
                "repository": "github/github-mcp-server", "revision": MERGE_SHA, "path": "agent-plugin",
                "clients": ["codex"], "installer_version": "0.1.26",
                "package": {"package_version": "", "tree_digest": FAKE_DIGEST, "manifest_digest": MANIFEST_DIGEST},
                "operations": {"add": "passed"}, "observed_at": "2026-09-01T00:00:00Z",
                "run": {"repository": "777genius/universal-agent-plugins", "id": "1", "attempt": "1", "source_sha": "c" * 40},
                "sandbox": {"kind": "disposable", "real_user_project_used": False, "removed": True},
            }
            raw_file.write_bytes(promotion.pretty(raw))
            selection = {
                "schema_version": 1,
                "decision": "promote",
                "entry": {
                    "product_id": "github", "repository": "github/github-mcp-server",
                    "distribution_id": "github/github", "release_sequence": release_sequence,
                    "reviewed_head_sha": REVIEWED_SHA, "package_path": "agent-plugin",
                    "minimum_installer_version": "0.1.26",
                    "targets": [{
                        "client": "codex", "scopes": ["user"],
                        "delivery": "managed", "authentication": "required",
                    }],
                },
                "pr_metadata": {"merge_commit_oid": MERGE_SHA},
            }
            selection_path = Path(temporary) / "selection.json"
            selection_path.write_bytes(promotion.pretty(selection))
            leaf_directory = raw_file.parent / "clients"
            promotion.write_evidence_artifacts(argparse.Namespace(
                selection=selection_path, materialization=raw_file,
                os="linux", architecture="amd64", output_directory=leaf_directory,
            ))
            run_git(repository, "add", str(raw_file.parent.relative_to(repository)))
            run_git(repository, "commit", "-qm", "evidence")
            evidence_commit = run_git(repository, "rev-parse", "HEAD")

            audit = repository / f"registry/upstream-promotion-audit/github/{MERGE_SHA}"
            audit.mkdir(parents=True)
            review_path, candidate_path = audit / "review-record.json", audit / "promotion-candidate.json"
            promotion.review_record(argparse.Namespace(
                selection=selection_path, materialization=raw_file,
                artifact_revision=evidence_commit,
                artifact_directory=str(leaf_directory.relative_to(repository)),
                repository=repository, os="linux", architecture="amd64",
                output=review_path,
            ))
            review = promotion.read_object(review_path)
            proposed = candidate(review, release_sequence)
            candidate_path.write_bytes(promotion.pretty(proposed))
            promotion.apply_candidate(argparse.Namespace(
                candidate=candidate_path, review_record=review_path,
                directory=repository / "registry/directory.json",
                publication_config=repository / "registry/publication/config.json",
            ))
            source = promotion.read_object(repository / "registry/directory.json")
            (repository / "registry/review-preview.json").write_bytes(promotion.encoded(promotion.directory_preview(source)))
            (repository / "registry/review-search.json").write_bytes(promotion.encoded(promotion.directory_search(source)))
            sync = promotion.sync_production_directory_identity(repository)
            self.assertEqual(sync["directory_source_digest"], promotion.sha256((repository / "registry/directory.json").read_bytes()))
            self.assertEqual(set(sync["changed_paths"]), {path.as_posix() for path in promotion.PRODUCTION_DIRECTORY_IDENTITY_PATHS})
            run_git(repository, "add", ".")
            run_git(repository, "commit", "-qm", "promotion")
            head = run_git(repository, "rev-parse", "HEAD")

            result = promotion.verify_pr(argparse.Namespace(
                repository=repository, base_sha=base, head_sha=head,
                branch=f"automation/upstream-promotion-github-bbbbbbbbbbbb-{base[:12]}",
            ))
            self.assertEqual(result["outcome"], "verified")
            self.assertEqual(result["observer_run_id"], "1")
            self.assertTrue(result["auto_merge"])

            trusted_review = review_path.read_bytes()
            invalid_trust = copy.deepcopy(review)
            invalid_trust["evidence"][0]["trust"] = {
                "kind": "github_actions",
                "workflow": "example/repository/.github/workflows/evidence.yml",
                "source_ref": "refs/heads/main",
                "source_digest": evidence_commit,
            }
            review_path.write_bytes(promotion.pretty(invalid_trust))
            with self.assertRaisesRegex(promotion.PromotionError, "trust is invalid"):
                promotion.verify_pr(argparse.Namespace(
                    repository=repository, base_sha=base, head_sha=head,
                    branch=f"automation/upstream-promotion-github-bbbbbbbbbbbb-{base[:12]}",
                ))
            review_path.write_bytes(trusted_review)

            trusted_candidate = candidate_path.read_bytes()
            leaf_path = leaf_directory / "codex.json"
            trusted_leaf = leaf_path.read_bytes()
            forged_review = copy.deepcopy(review)
            forged_review["evidence"][0]["client_version"] = "forged-client"
            forged_payload = {
                key: value for key, value in forged_review["evidence"][0].items()
                if key not in {"artifact", "trust"}
            }
            leaf_path.write_bytes(promotion.pretty(forged_payload))
            forged_review["evidence"][0]["artifact"]["digest"] = promotion.sha256(
                leaf_path.read_bytes()
            )
            review_path.write_bytes(promotion.pretty(forged_review))
            candidate_path.write_bytes(promotion.pretty(candidate(forged_review, release_sequence)))
            with self.assertRaisesRegex(
                promotion.PromotionError,
                "client evidence artifact differs from aggregate materialization",
            ):
                promotion.verify_pr(argparse.Namespace(
                    repository=repository, base_sha=base, head_sha=head,
                    branch=f"automation/upstream-promotion-github-bbbbbbbbbbbb-{base[:12]}",
                ))
            leaf_path.write_bytes(trusted_leaf)
            review_path.write_bytes(trusted_review)
            candidate_path.write_bytes(trusted_candidate)

            review["evidence"][0]["installer_version"] = "0.1.25"
            review_path.write_bytes(promotion.pretty(review))
            with self.assertRaisesRegex(promotion.PromotionError, "candidate evidence projection"):
                promotion.apply_candidate(argparse.Namespace(
                    candidate=candidate_path, review_record=review_path,
                    directory=repository / "registry/directory.json",
                    publication_config=repository / "registry/publication/config.json",
                ))


if __name__ == "__main__":
    unittest.main()
