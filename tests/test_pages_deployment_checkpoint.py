from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import directory_publication_cas as cas
import pages_compositor as pages
import pages_deployment_checkpoint as checkpoint

REPOSITORY = "777genius/universal-agent-plugins-registry"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["/usr/bin/git", "-C", str(repo), *args], check=True,
                          text=True, capture_output=True).stdout.strip()


class CheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.remote = root / "remote.git"
        self.repo = root / "writer"
        self.other = root / "other"
        self.baseline = root / "baseline.json"
        git(root, "init", "--bare", "-q", str(self.remote))
        for repo in (self.repo, self.other):
            git(root, "init", "-q", str(repo))
            git(repo, "remote", "add", "origin", str(self.remote))
        self.baseline.write_text(json.dumps({"schema_version": 1, "repository": REPOSITORY,
                                             "environment": "github-pages", "deployment_id": 10,
                                             "deployment_sha": "a" * 40, "success_status_id": 101,
                                             "success_log_url": self.log_url(10)}) + "\n")
        self.deployments = {10: {"id": 10, "sha": "a" * 40, "environment": "github-pages",
                                 "updated_at": "2026-09-29T00:00:10Z"}}
        self.statuses = {10: [{"id": 101, "state": "success", "log_url": self.log_url(10)}]}
        self.jobs: dict[int, dict] = {}
        self.backend: dict[str, str] = {}
        self.expired_baseline = False
        self.status_queries: list[int] = []
        self.clock = datetime(2026, 9, 29, 11, 0, tzinfo=timezone.utc)
        self.clock_patch = patch.object(checkpoint, "_now", side_effect=lambda: self.clock)
        self.clock_patch.start()

    def tearDown(self) -> None:
        self.clock_patch.stop()
        self.temporary.cleanup()

    def log_url(self, deployment_id: int) -> str:
        return f"https://github.com/{REPOSITORY}/actions/runs/{1000 + deployment_id}/job/{2000 + deployment_id}"

    def add(self, deployment_id: int, state: str, *, sha: str | None = None) -> None:
        self.deployments[deployment_id] = {"id": deployment_id, "sha": sha or f"{deployment_id:040x}",
                                           "environment": "github-pages",
                                           "updated_at": f"2026-09-29T00:00:{deployment_id:02d}Z"}
        self.statuses[deployment_id] = [{"id": deployment_id * 10, "state": state,
                                        "log_url": self.log_url(deployment_id)}]

    def fetch(self, path: str, _token: str) -> object:
        if path.endswith("/rulesets?includes_parents=false"):
            return [{"id": 1, "name": checkpoint.UPDATE_RULESET},
                    {"id": 2, "name": checkpoint.IMMUTABLE_RULESET}]
        if path.endswith("/rulesets/1") or path.endswith("/rulesets/2"):
            update = path.endswith("/1")
            return {"id": 1 if update else 2,
                    "name": checkpoint.UPDATE_RULESET if update else checkpoint.IMMUTABLE_RULESET,
                    "source_type": "Repository", "source": REPOSITORY, "target": "branch",
                    "enforcement": "active", "conditions": {"ref_name": {
                        "include": [checkpoint.CHECKPOINT_REF], "exclude": []}},
                    "rules": [{"type": kind} for kind in (
                        ["creation", "update"] if update else
                        ["deletion", "non_fast_forward", "required_linear_history"])],
                    "bypass_actors": [{"actor_id": checkpoint.PUBLISHER_APP_ID,
                                       "actor_type": "Integration", "bypass_mode": "always"}] if update else []}
        if "/actions/jobs/" in path:
            return self.jobs.get(int(path.rsplit("/", 1)[1]))
        match = re.search(r"/pages/deployments/([0-9a-f]{40})$", path)
        if match:
            return {"status": self.backend.get(match.group(1), "unknown")}
        match = re.search(r"/deployments/(\d+)/statuses/(\d+)$", path)
        if match:
            dep, sid = map(int, match.groups())
            if dep == 10 and self.expired_baseline:
                raise AssertionError("expired bootstrap status queried")
            return next((s for s in self.statuses[dep] if s["id"] == sid), None)
        match = re.search(r"/deployments/(\d+)/statuses\?per_page=(\d+)(?:&page=(\d+))?$", path)
        if match:
            dep, count, page = int(match.group(1)), int(match.group(2)), int(match.group(3) or 1)
            self.status_queries.append(dep)
            if dep == 10 and self.expired_baseline:
                raise AssertionError("expired bootstrap status queried")
            start = (page - 1) * count
            return self.statuses[dep][start:start + count]
        match = re.search(r"/deployments/(\d+)$", path)
        if match:
            return self.deployments.get(int(match.group(1)))
        if "/deployments?" in path:
            query = path.split("?", 1)[1]
            if "sha=" in query:
                sha = query.split("sha=", 1)[1].split("&", 1)[0]
                return [d for d in self.deployments.values() if d["sha"] == sha]
            page = int(query.rsplit("&page=", 1)[1])
            ordered = [self.deployments[i] for i in sorted(self.deployments, reverse=True)]
            return ordered[(page - 1) * 100:page * 100]
        raise AssertionError(path)

    def advance(self, repo: Path | None = None, **kwargs: object) -> str:
        return checkpoint.advance(repo or self.repo, "origin", self.baseline,
                                  REPOSITORY, "fake", fetch=self.fetch, **kwargs)

    def read(self, repo: Path | None = None) -> tuple[str | None, int, dict[int, dict]]:
        return checkpoint.read_checkpoint(repo or self.repo, "origin", self.baseline,
                                          REPOSITORY, token="fake", fetch=self.fetch)

    def test_gap_stops_at_first_uncertain_deployment(self) -> None:
        self.add(11, "success")
        self.add(12, "in_progress")
        self.add(13, "success")
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[1], 11)
        self.assertEqual(self.advance(), "unchanged")
        self.statuses[12][0]["state"] = "success"
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[1], 13)

    def test_missing_frontier_deployment_never_skips_unknown_history(self) -> None:
        self.assertEqual(self.advance(), "published")
        self.add(11, "success")
        del self.deployments[10]
        with self.assertRaisesRegex(cas.CasError, "cannot bound the old frontier"):
            self.advance()

    def test_lost_push_response_uses_exact_ref_readback(self) -> None:
        self.add(11, "success")

        def lost(repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
            cas._git(repo, args)
            return subprocess.CompletedProcess(args, 1, "", "lost response")

        self.assertEqual(self.advance(push=lost), "published")
        self.assertEqual(self.read()[1], 11)

    def test_competing_writer_reauthenticates_winner(self) -> None:
        self.add(11, "success")
        wrote = False

        def competing(repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
            nonlocal wrote
            if not wrote:
                wrote = True
                self.add(12, "success")
                self.assertEqual(self.advance(self.other), "published")
            return cas._git(repo, args, check=False)

        self.assertEqual(self.advance(push=competing), "unchanged")
        self.assertEqual(self.read()[1], 12)

    def test_catch_up_after_deploy_and_expired_bootstrap_status(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.expired_baseline = True
        self.clock = datetime(2027, 1, 1, 11, 0, tzinfo=timezone.utc)
        self.status_queries.clear()
        self.assertEqual(self.read()[1], 11)
        pages.require_terminal_previous_deployments(
            REPOSITORY, "fake", frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)
        self.assertNotIn(10, self.status_queries)

    def test_bootstrap_accepts_later_inactive_with_exact_prior_success(self) -> None:
        self.deployments[10]["updated_at"] = "2026-09-29T00:01:10Z"
        self.statuses[10].insert(0, {"id": 102, "state": "inactive", "log_url": self.log_url(10)})
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[1], 10)
        self.expired_baseline = True
        self.clock = datetime(2027, 1, 1, 11, 0, tzinfo=timezone.utc)
        pages.require_terminal_previous_deployments(
            REPOSITORY, "fake", frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)

    def test_bootstrap_rejects_new_terminal_receipt_before_immutable_push(self) -> None:
        self.statuses[10].insert(0, {"id": 102, "state": "success", "log_url": self.log_url(99)})
        with self.assertRaisesRegex(cas.CasError, "bootstrap receipt differs"):
            self.advance()
        self.assertIsNone(checkpoint._remote_head(self.repo, "origin"))

    def test_archived_own_success_still_allows_delayed_directory_marker(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.expired_baseline = True
        self.clock = datetime(2027, 1, 1, 11, 0, tzinfo=timezone.utc)
        with patch.object(pages, "_current_compositor_job_id", return_value=2011):
            self.assertEqual(pages.require_successful_current_deployment(
                REPOSITORY, "fake", run_id=1011, run_attempt=1,
                frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch,
            ), "current")

    def test_late_inactive_and_cancelled_backend_require_exact_proofs(self) -> None:
        self.add(11, "failure")
        self.assertEqual(self.advance(), "published")  # Bootstrap only.
        self.assertEqual(self.read()[1], 10)
        self.backend[self.deployments[11]["sha"]] = "deployment_cancelled"
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[1], 11)
        self.add(12, "inactive")
        self.assertEqual(self.advance(), "unchanged")
        self.statuses[12].append({"id": 119, "state": "success", "log_url": self.log_url(12)})
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[1], 12)

    def test_new_backend_status_under_old_deployment_id_blocks_until_reclosed(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.deployments[11]["updated_at"] = "2026-09-29T00:01:11Z"
        self.statuses[11].insert(0, {"id": 111, "state": "in_progress", "log_url": self.log_url(99)})
        with self.assertRaisesRegex(cas.CasError, "late uncheckpointed update"):
            pages.require_terminal_previous_deployments(
                REPOSITORY, "fake", frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)
        with self.assertRaisesRegex(cas.CasError, "late uncertain status"):
            self.advance()
        self.deployments[11]["updated_at"] = "2026-09-29T00:02:11Z"
        self.statuses[11][0] = {"id": 112, "state": "inactive", "log_url": self.log_url(99)}
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[1], 11)
        self.expired_baseline = True
        self.clock = datetime(2027, 1, 1, 11, 0, tzinfo=timezone.utc)
        pages.require_terminal_previous_deployments(
            REPOSITORY, "fake", frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)

    def test_late_inactive_reuses_archived_success_after_status_expiry(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.deployments[11]["updated_at"] = "2026-09-29T00:01:11Z"
        self.statuses[11] = [{"id": 111, "state": "inactive", "log_url": self.log_url(11)}]
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[2][11]["terminal_evidence"], {
            "kind": "prior_success", "status_id": 110, "log_url": self.log_url(11)})

    def test_same_second_foreign_status_cannot_hide_behind_updated_at(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.statuses[11].insert(0, {"id": 111, "state": "in_progress", "log_url": self.log_url(99)})
        with self.assertRaisesRegex(cas.CasError, "late uncheckpointed update"):
            pages.require_terminal_previous_deployments(
                REPOSITORY, "fake", frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)
        with self.assertRaisesRegex(cas.CasError, "late uncertain status"):
            self.advance()

    def test_same_second_terminal_status_is_reclosed(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.statuses[11].insert(0, {"id": 111, "state": "success", "log_url": self.log_url(11)})
        self.assertEqual(self.advance(), "published")
        self.assertEqual(self.read()[2][11]["status_id"], 111)

    def test_status_change_during_final_reread_cannot_reach_branch(self) -> None:
        self.add(11, "success")
        mutated = False

        def fetch(path: str, token: str) -> object:
            nonlocal mutated
            if path.endswith("/deployments/11") and not mutated:
                mutated = True
                self.statuses[11].insert(0, {"id": 111, "state": "in_progress",
                                             "log_url": self.log_url(99)})
            return self.fetch(path, token)

        with self.assertRaisesRegex(cas.CasError, "changed before checkpoint push"):
            checkpoint.advance(self.repo, "origin", self.baseline, REPOSITORY, "fake", fetch=fetch)
        self.assertIsNone(checkpoint._remote_head(self.repo, "origin"))

    def test_final_reread_waits_past_status_second_before_push(self) -> None:
        self.add(11, "success")
        self.clock = datetime(2026, 9, 29, 0, 0, 12, tzinfo=timezone.utc)
        checked_after_boundary = False

        def fake_sleep(seconds: float) -> None:
            self.clock += timedelta(seconds=seconds)

        def fetch(path: str, token: str) -> object:
            nonlocal checked_after_boundary
            if path.endswith("/deployments/11"):
                self.assertGreaterEqual(
                    self.clock, datetime(2026, 9, 29, 0, 0, 14, tzinfo=timezone.utc))
                checked_after_boundary = True
            return self.fetch(path, token)

        with patch.object(checkpoint.time, "sleep", side_effect=fake_sleep):
            self.assertEqual(checkpoint.advance(
                self.repo, "origin", self.baseline, REPOSITORY, "fake", fetch=fetch), "published")
        self.assertTrue(checked_after_boundary)

    def test_same_id_rerun_exempts_only_exact_current_job(self) -> None:
        self.add(11, "success")
        self.assertEqual(self.advance(), "published")
        self.deployments[11]["updated_at"] = "2026-09-29T00:01:11Z"
        self.statuses[11].insert(0, {"id": 111, "state": "in_progress", "log_url": self.log_url(99)})
        with patch.object(pages, "_current_compositor_job_id", return_value=2099):
            pages.require_terminal_previous_deployments(
                REPOSITORY, "fake", run_id=1099, run_attempt=1,
                frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)
        with patch.object(pages, "_current_compositor_job_id", return_value=2098):
            with self.assertRaisesRegex(cas.CasError, "late uncheckpointed update"):
                pages.require_terminal_previous_deployments(
                    REPOSITORY, "fake", run_id=1098, run_attempt=1,
                    frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch)
        self.statuses[11][0] = {"id": 112, "state": "success", "log_url": self.log_url(99)}
        with patch.object(pages, "_current_compositor_job_id", return_value=2099):
            self.assertEqual(pages.require_successful_current_deployment(
                REPOSITORY, "fake", run_id=1099, run_attempt=1,
                frontier=self.baseline, checkpoint_repo=self.repo, fetch=self.fetch,
            ), "current")

    def test_forged_ancestry_is_rejected(self) -> None:
        self.assertEqual(self.advance(), "published")
        head, _, _archived = self.read()
        assert head is not None
        fake = {"schema_version": 1, "repository": REPOSITORY, "environment": "github-pages",
                "bootstrap_manifest_sha256": "sha256:" + "0" * 64, "previous_commit": None,
                "frontier": {"deployment_id": 10, "deployment_sha": "a" * 40},
                "observation": {"observed_at": "2026-09-29T00:00:00Z",
                                "newest_deployment_id": 10, "deployment_count": 0}, "closed_delta": []}
        forged = checkpoint._commit(self.repo, head, fake)
        git(self.repo, "push", "-q", "origin", f"{forged}:{checkpoint.CHECKPOINT_REF}")
        with self.assertRaisesRegex(cas.CasError, "ancestry"):
            self.read()

    def test_workflow_uses_discovery_app_inside_serial_pages_checkpoint_job(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/pages-production-compositor.yml").read_text())
        compose = workflow["jobs"]["compose"]
        writer = workflow["jobs"]["record_pages_checkpoint"]
        self.assertEqual(writer["needs"], "compose")
        self.assertEqual(writer["concurrency"], compose["concurrency"])
        self.assertEqual(writer["environment"], "discovery-publication")
        self.assertIn("github.event_name == 'schedule'", writer["if"])
        self.assertIn("github.event_name == 'workflow_dispatch'", writer["if"])
        body = yaml.safe_dump(writer)
        self.assertIn("DISCOVERY_PUBLISHER_APP_PRIVATE_KEY", body)
        self.assertNotIn("DIRECTORY_PUBLISHER_APP_PRIVATE_KEY", body)
        self.assertIn("pages_deployment_checkpoint.py advance", " ".join(
            step.get("run", "").replace("\\\n", " ") for step in writer["steps"]))
        self.assertIn("--checkpoint-repo pages-checkpoint", " ".join(
            step.get("run", "").replace("\\\n", " ") for step in compose["steps"]))


if __name__ == "__main__":
    unittest.main()
