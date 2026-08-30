from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_chrome_five_client_lifecycle.py"
SPEC = importlib.util.spec_from_file_location("chrome_five_client_lifecycle", SCRIPT)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ChromeFiveClientLifecycleTests(unittest.TestCase):
    def target(self, client: str, *, dry_run: bool) -> dict:
        support = {
            "claude": "projected",
            "gemini": "native",
            "opencode": "prepared",
            "cline": "native",
            "windsurf": "prepared",
        }[client]
        return {
            "target": client,
            "status": "ready" if dry_run else "external_completed",
            "output": {
                "tree_digest": "sha256:" + "a" * 64,
                "manifest_digest": "sha256:" + "b" * 64,
                "result": {
                    "plan": {
                        "client_id": client,
                        "package_mode": runner.EXPECTED_MODES[client],
                        "physical_artifact_id": "chrome-devtools-123456789abc",
                        "components": [
                            {"kind": "skill", "name": name, "support": support}
                            for name in sorted(runner.EXPECTED_SKILLS)
                        ],
                    },
                    "activation": {"verification": "installation_verified"},
                    "mutated": not dry_run,
                },
            },
        }

    def batch(self, *, dry_run: bool) -> dict:
        return {
            "command": "add",
            "result": "success",
            "data": {
                "status": "planned" if dry_run else "completed",
                "succeeded": 5,
                "failed": 0,
                "dry_run": dry_run,
                "revision": "c" * 40,
                "tree_digest": "sha256:" + "a" * 64,
                "manifest_digest": "sha256:" + "b" * 64,
                "targets": [self.target(client, dry_run=dry_run) for client in runner.CLIENTS],
            },
        }

    def test_dry_run_and_add_require_one_shared_five_target_identity(self) -> None:
        dry_run = self.batch(dry_run=True)
        identity = runner.validate_dry_run(dry_run, "c" * 40)
        self.assertEqual(identity["physical_artifact_id"], "chrome-devtools-123456789abc")
        self.assertEqual(
            runner.validate_add(self.batch(dry_run=False), "c" * 40, identity),
            "chrome-devtools-123456789abc",
        )

        split = self.batch(dry_run=True)
        split["data"]["targets"][3]["output"]["result"]["plan"]["physical_artifact_id"] = "chrome-devtools-deadbeefcafe"
        with self.assertRaises(runner.EvidenceError):
            runner.validate_dry_run(split, "c" * 40)

    def test_timestamp_order_rejects_repinning_evidence_before_the_commit(self) -> None:
        source = {
            "commit_timestamp_utc": "2026-08-30T17:16:23Z",
            "head_observed_at_utc": "2026-08-30T17:06:48Z",
            "lifecycle_started_at_utc": "2026-08-30T17:17:00Z",
            "lifecycle_completed_at_utc": "2026-08-30T17:18:00Z",
            "head_rechecked_at_utc": "2026-08-30T17:19:00Z",
        }
        with self.assertRaises(runner.EvidenceError):
            runner.validate_timestamp_order(source)
        source["head_observed_at_utc"] = "2026-08-30T17:16:24Z"
        runner.validate_timestamp_order(source)

    def test_head_observation_fails_when_pr_changes_during_metadata_lookup(self) -> None:
        values = [
            {"state": "OPEN", "headRefOid": "a" * 40, "url": "https://github.com/o/r/pull/1"},
            {"tree": {"sha": "b" * 40}, "committer": {"date": "2026-08-30T00:00:00Z"}},
            {"state": "OPEN", "headRefOid": "c" * 40, "url": "https://github.com/o/r/pull/1"},
        ]
        with mock.patch.object(runner, "gh_json", side_effect=values):
            with self.assertRaises(runner.EvidenceError):
                runner.observe_upstream_head(
                    Path("/gh"),
                    repository="o/r",
                    pr_number=1,
                    expected_head="a" * 40,
                    env={},
                )

    def test_snapshot_hash_covers_bytes_topology_and_modes_not_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            home = root / "home"
            state.mkdir()
            home.mkdir()
            file = state / "state.json"
            file.write_text("one\n", encoding="utf-8")
            first = runner.snapshot_roots({"state": state, "home": home})
            file.touch()
            self.assertEqual(first, runner.snapshot_roots({"state": state, "home": home}))
            file.write_text("two\n", encoding="utf-8")
            self.assertNotEqual(first, runner.snapshot_roots({"state": state, "home": home}))

    def test_sanitizer_rejects_raw_paths_and_operation_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary) / "sandbox"
            evidence = {"safe": True}
            runner.ensure_sanitized(evidence, sandbox)
            with self.assertRaises(runner.EvidenceError):
                runner.ensure_sanitized({"value": str(sandbox / "home")}, sandbox)
            with self.assertRaises(runner.EvidenceError):
                runner.ensure_sanitized({"operation_id": "op-secret"}, sandbox)

    def test_committed_evidence_matches_the_strict_schema(self) -> None:
        evidence = json.loads(
            (ROOT / "tests/e2e/results/agentplugins-chrome-devtools-multiclient-2026-08-30.json").read_text()
        )
        schema = json.loads(
            (ROOT / "schemas/e2e/chrome-five-client-lifecycle.schema.json").read_text()
        )
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(evidence)
        runner.validate_timestamp_order(evidence["source"])
        self.assertEqual(
            evidence["operations"]["immutable_update"]["state_and_client_snapshot_before"],
            evidence["operations"]["immutable_update"]["state_and_client_snapshot_after"],
        )

    def test_workflow_pins_public_clients_and_uploads_only_sanitized_evidence(self) -> None:
        workflow_source = (ROOT / ".github/workflows/upstream-package-e2e.yml").read_text()
        workflow = yaml.safe_load(workflow_source)
        job = workflow["jobs"]["chrome-five-client-lifecycle"]
        rendered = json.dumps(job, sort_keys=True)
        self.assertIn("universal-agent-plugins@${AGENTPLUGINS_VERSION}", rendered)
        self.assertIn("@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}", rendered)
        self.assertIn("run_chrome_five_client_lifecycle.py", rendered)
        self.assertIn("chrome-five-client-evidence", rendered)
        self.assertIn('(cd "$EVIDENCE_ROOT" && sha256sum evidence.json > evidence.sha256)', workflow_source)
        self.assertNotIn("add.json", rendered)
        self.assertNotIn("info.json", rendered)
        self.assertEqual(
            workflow["env"]["CHROME_UPSTREAM_HEAD"],
            "7e193aed8baa23c692355237a55237540b36cb2f",
        )


if __name__ == "__main__":
    unittest.main()
