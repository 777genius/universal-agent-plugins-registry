from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import directory_publication_cas as cas
import pages_compositor as pages

GIT = "/usr/bin/git"
REPOSITORY = "777genius/universal-agent-plugins-registry"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [GIT, "-C", str(repo), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


class PagesCompositorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.remote = root / "remote.git"
        self.repo = root / "publisher"
        self.contract = root / "production-marker.json"
        git(root, "init", "--bare", "-q", str(self.remote))
        git(root, "init", "-q", str(self.repo))
        git(self.repo, "config", "user.name", "iliya")
        git(self.repo, "config", "user.email", "iliyazelenkog@gmail.com")
        (self.repo / "source.txt").write_text("source\n")
        git(self.repo, "add", "source.txt")
        git(self.repo, "commit", "-qm", "source")
        self.source = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "remote", "add", "origin", str(self.remote))
        git(self.repo, "push", "-q", "origin", f"{self.source}:refs/heads/main")
        signed, site = self.directory_pair(self.source, 1)
        self.bootstrap = site
        self.signed_bootstrap = signed
        git(self.repo, "push", "-q", "origin", f"{site}:{pages.LEDGER_REF}")
        git(self.repo, "push", "-q", "origin", f"{signed}:refs/tags/directory-publication-schema-1-sequence-{1:020d}")
        git(self.repo, "push", "-q", "origin", f"{site}:{pages.PRODUCTION_REF}")
        self.contract.write_text(json.dumps({
            "marker_ref": pages.PRODUCTION_REF,
            "bootstrap_materialized_commit": site,
            "bootstrap_sequence": 1,
            "sequence_tag_prefix": "refs/tags/directory-publication-schema-1-sequence-",
        }))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def directory_pair(self, parent: str, sequence: int) -> tuple[str, str]:
        git(self.repo, "checkout", "-q", "--detach", parent)
        stem = f"{sequence:020d}"
        for path, value in (
            ("registry/schemas/1/latest.json", {"sequence": sequence}),
            (f"registry/schemas/1/snapshots/{stem}.json", {"sequence": sequence, "publication_id": f"run-{sequence}"}),
            (f"registry/schemas/1/snapshots/{stem}.envelope.json", {"sequence": sequence}),
        ):
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(value, sort_keys=True) + "\n")
            git(self.repo, "add", path)
        if sequence == 1:
            (self.repo / "registry/schemas/1/ledger-contract.json").write_text("{}\n")
            git(self.repo, "add", "registry/schemas/1/ledger-contract.json")
        git(self.repo, "commit", "-qm", "chore(directory): publish signed snapshot")
        signed = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "index.html").write_text(f"site {sequence}\n")
        git(self.repo, "add", "index.html")
        git(self.repo, "commit", "-qm", "chore(directory): materialize signed production site")
        return signed, git(self.repo, "rev-parse", "HEAD")

    def add_intent(self, parent: str, sequence: int) -> tuple[str, str]:
        signed, site = self.directory_pair(parent, sequence)
        git(self.repo, "push", "-q", "origin", f"{site}:{pages.LEDGER_REF}")
        git(self.repo, "push", "-q", "origin", f"{signed}:refs/tags/directory-publication-schema-1-sequence-{sequence:020d}")
        snapshot = git(self.repo, "show", f"{signed}:registry/schemas/1/snapshots/{sequence:020d}.json") + "\n"
        digest = "sha256:" + hashlib.sha256(snapshot.encode()).hexdigest()
        cas.publish_promotion_intent(
            self.repo, "origin", materialized=site, signed=signed, sequence=sequence,
            publication_id=f"run-{sequence}", snapshot_digest=digest,
            readiness_digest="sha256:" + f"{sequence}" * 64,
        )
        return signed, site

    def feed_append(self, parent: str, sequence: int) -> str:
        git(self.repo, "checkout", "-q", "--detach", parent)
        stem = f"{sequence:020d}"
        for path in ("discovery/latest.json", f"discovery/search/{stem}.json",
                     f"discovery/snapshots/{stem}.json", f"discovery/snapshots/{stem}.envelope.json"):
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({"sequence": sequence}) + "\n")
            git(self.repo, "add", path)
        git(self.repo, "commit", "-qm", f"chore(discovery): publish sequence {sequence}")
        commit = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "push", "-q", "origin", f"{commit}:{pages.LEDGER_REF}")
        git(self.repo, "push", "-q", "origin", f"{commit}:refs/tags/discovery-index-sequence-{sequence:020d}")
        return commit

    def test_queued_compositor_reselects_latest_intent_and_feed_after_lock(self) -> None:
        original = pages.select_composition(self.repo, "origin", self.contract)
        _signed, approved = self.add_intent(self.bootstrap, 2)
        first_feed = self.feed_append(approved, 1)
        selected = pages.select_composition(self.repo, "origin", self.contract)
        self.assertEqual(selected.directory_commit, approved)
        self.assertEqual(selected.ledger_head, first_feed)
        with self.assertRaisesRegex(cas.CasError, "stale"):
            pages.require_current_composition(self.repo, "origin", self.contract, original)
        second_feed = self.feed_append(first_feed, 2)
        with self.assertRaisesRegex(cas.CasError, "stale"):
            pages.require_current_composition(self.repo, "origin", self.contract, selected)
        self.assertEqual(pages.select_composition(self.repo, "origin", self.contract).ledger_head, second_feed)

    def test_older_intents_remain_valid_after_production_marker_catches_up(self) -> None:
        _signed_two, site_two = self.add_intent(self.bootstrap, 2)
        _signed_three, site_three = self.add_intent(site_two, 3)
        git(self.repo, "push", "-q", "--force", "origin", f"{site_three}:{pages.PRODUCTION_REF}")
        selected = pages.select_composition(self.repo, "origin", self.contract)
        self.assertEqual(selected.directory_commit, site_three)
        self.assertEqual(selected.production_marker, site_three)
        self.assertIsNone(selected.intent_ref)

    def test_older_intent_created_after_newer_never_supersedes_it(self) -> None:
        signed_two, site_two = self.directory_pair(self.bootstrap, 2)
        signed_three, site_three = self.directory_pair(site_two, 3)
        git(self.repo, "push", "-q", "origin", f"{site_three}:{pages.LEDGER_REF}")
        for sequence, signed in ((2, signed_two), (3, signed_three)):
            git(self.repo, "push", "-q", "origin", f"{signed}:refs/tags/directory-publication-schema-1-sequence-{sequence:020d}")
        for sequence, signed, site in ((3, signed_three, site_three), (2, signed_two, site_two)):
            snapshot = git(self.repo, "show", f"{signed}:registry/schemas/1/snapshots/{sequence:020d}.json") + "\n"
            cas.publish_promotion_intent(
                self.repo, "origin", materialized=site, signed=signed, sequence=sequence,
                publication_id=f"run-{sequence}",
                snapshot_digest="sha256:" + hashlib.sha256(snapshot.encode()).hexdigest(),
                readiness_digest="sha256:" + f"{sequence}" * 64,
            )
        selected = pages.select_composition(self.repo, "origin", self.contract)
        self.assertEqual(selected.directory_commit, site_three)
        self.assertEqual(selected.intent_ref, cas.promotion_intent_ref(3))

    def test_cancelled_directory_caller_after_intent_can_catch_up_marker(self) -> None:
        _signed, approved = self.add_intent(self.bootstrap, 2)
        self.assertEqual(git(self.repo, "ls-remote", "--refs", "origin", pages.PRODUCTION_REF).split()[0],
                         self.bootstrap)
        scheduled = pages.select_composition(self.repo, "origin", self.contract)
        self.assertEqual(scheduled.directory_commit, approved)
        self.assertEqual(scheduled.production_marker, self.bootstrap)
        self.assertEqual(cas.production_transition(
            self.repo, "origin", production_new=scheduled.directory_commit,
            production_tag=pages.PRODUCTION_REF,
        ), "published")
        self.assertEqual(pages.select_composition(self.repo, "origin", self.contract).production_marker,
                         approved)


class PagesExternalReceiptTests(unittest.TestCase):
    def test_verified_frontier_skips_old_history_but_not_newer_uncertain_deployments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            frontier = Path(directory) / "frontier.json"
            sha = "b" * 40
            log_url = f"https://github.com/{REPOSITORY}/actions/runs/73/job/901"
            frontier.write_text(json.dumps({"schema_version": 1, "repository": REPOSITORY,
                                            "environment": "github-pages", "deployment_id": 50,
                                            "deployment_sha": sha, "success_status_id": 501,
                                            "success_log_url": log_url}))
            state = {"newer": "success", "anchor": "success"}

            def fetch(path: str, _token: str) -> object:
                if path.endswith("/deployments/50"):
                    return {"id": 50, "sha": sha, "environment": "github-pages"}
                if path.endswith("/deployments/50/statuses/501"):
                    return {"id": 501, "state": state["anchor"], "log_url": log_url}
                if "deployments?" in path:
                    return [{"id": 60, "environment": "github-pages"},
                            {"id": 40, "environment": "github-pages"}]
                if "/deployments/40/" in path:
                    raise AssertionError("pre-frontier status was queried")
                if "/deployments/60/statuses?" in path:
                    return [{"state": state["newer"]}]
                raise AssertionError(path)

            pages.require_terminal_previous_deployments(REPOSITORY, "fake", frontier=frontier, fetch=fetch)
            state["newer"] = "in_progress"
            with self.assertRaisesRegex(cas.CasError, "nonterminal"):
                pages.require_terminal_previous_deployments(REPOSITORY, "fake", frontier=frontier, fetch=fetch)
            state["newer"] = "success"
            state["anchor"] = "failure"
            with self.assertRaisesRegex(cas.CasError, "frontier no longer has exact success evidence"):
                pages.require_terminal_previous_deployments(REPOSITORY, "fake", frontier=frontier, fetch=fetch)

    def test_marker_requires_one_successful_current_attempt_deployment(self) -> None:
        statuses = {32: "success", 31: "success"}

        def fetch(path: str, _token: str) -> object:
            if "/actions/runs/73/attempts/2/jobs?" in path:
                return {"total_count": 1, "jobs": [{"id": 902, "run_attempt": 2,
                        "name": "deploy / " + pages.COMPOSITOR_JOB_NAME}]}
            if "deployments?" in path:
                return [{"id": 32, "environment": "github-pages"},
                        {"id": 31, "environment": "github-pages"}]
            deployment_id = int(path.split("/deployments/")[1].split("/")[0])
            job = 902 if deployment_id == 32 else 901
            return [{"state": statuses[deployment_id],
                     "log_url": f"https://github.com/{REPOSITORY}/actions/runs/73/job/{job}"}]

        self.assertEqual(pages.require_successful_current_deployment(
            REPOSITORY, "fake", run_id=73, run_attempt=2, fetch=fetch,
        ), "current")
        statuses[32] = "in_progress"
        with self.assertRaisesRegex(cas.CasError, "no unambiguous success"):
            pages.require_successful_current_deployment(REPOSITORY, "fake", run_id=73,
                                                         run_attempt=2, fetch=fetch)

    def test_delayed_old_marker_skips_after_newer_success(self) -> None:
        own_state = {"value": "success"}

        def fetch(path: str, _token: str) -> object:
            if "/actions/runs/73/attempts/2/jobs?" in path:
                return {"total_count": 1, "jobs": [{"id": 902, "run_attempt": 2,
                        "name": pages.COMPOSITOR_JOB_NAME}]}
            if "deployments?" in path:
                return [{"id": 33, "environment": "github-pages"},
                        {"id": 32, "environment": "github-pages"}]
            if "/actions/jobs/902" in path:
                return {"id": 902, "run_id": 73, "steps": [{"name":
                        "Deploy only the freshly rechecked composition", "status": "completed",
                        "conclusion": "success"}]}
            deployment_id = int(path.split("/deployments/")[1].split("/")[0])
            if deployment_id == 32 and "per_page=100" in path:
                return [{"id": 320, "state": "inactive"}, {"id": 319, "state": "success"}]
            return [{"id": 320 if deployment_id == 32 else 330,
                     "state": own_state["value"] if deployment_id == 32 else "success", "log_url":
                     f"https://github.com/{REPOSITORY}/actions/runs/{74 if deployment_id == 33 else 73}"
                     f"/job/{903 if deployment_id == 33 else 902}"}]

        self.assertEqual(pages.require_successful_current_deployment(
            REPOSITORY, "fake", run_id=73, run_attempt=2, fetch=fetch,
        ), "superseded")
        own_state["value"] = "inactive"
        self.assertEqual(pages.require_successful_current_deployment(
            REPOSITORY, "fake", run_id=73, run_attempt=2, fetch=fetch,
        ), "superseded")

    def test_historical_inactive_is_terminal_only_with_same_deployment_prior_success(self) -> None:
        historical = [{"id": 221, "state": "inactive"}, {"id": 220, "state": "success"}]

        def fetch(path: str, _token: str) -> object:
            if "deployments?" in path:
                return [{"id": 22, "environment": "github-pages"}]
            if "per_page=100" in path:
                return historical
            return [historical[0]]

        pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)
        historical.pop()
        with self.assertRaisesRegex(cas.CasError, "uncertain external backend"):
            pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)

    def test_signed_feed_expiry_stops_composition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory)
            for feed, expiry in (("discovery", "2026-10-02T00:00:00Z"),
                                 ("security", "2026-09-30T00:00:00Z")):
                root = ledger / feed
                (root / "snapshots").mkdir(parents=True)
                (root / "latest.json").write_text(json.dumps({
                    "snapshot_path": "snapshots/00000000000000000001.json",
                }))
                (root / "snapshots/00000000000000000001.json").write_text(json.dumps({
                    "generated_at": "2026-09-29T00:00:00Z", "expires_at": expiry,
                }))
            now = datetime(2026, 10, 1, tzinfo=timezone.utc)
            with self.assertRaisesRegex(cas.CasError, "security signed snapshot is not currently valid"):
                pages.require_current_feed_freshness(ledger, now)
            (ledger / "security/snapshots/00000000000000000001.json").write_text(json.dumps({
                "generated_at": "2026-09-29T00:00:00Z", "expires_at": "2026-10-03T00:00:00Z",
            }))
            pages.require_current_feed_freshness(ledger, now)
            with self.assertRaisesRegex(cas.CasError, "discovery signed snapshot is not currently valid"):
                pages.require_current_feed_freshness(
                    ledger, datetime(2026, 10, 1, 23, 56, tzinfo=timezone.utc),
                    minimum_validity_seconds=900,
                )

    def test_only_current_attempts_single_compositor_deployment_is_exempt(self) -> None:
        states = {32: "in_progress", 31: "success"}

        def fetch(path: str, _token: str) -> object:
            if "/actions/runs/73/attempts/2/jobs?" in path:
                return {"total_count": 1, "jobs": [{"id": 901, "run_attempt": 2,
                        "name": "deploy / " + pages.COMPOSITOR_JOB_NAME}]}
            if "deployments?" in path:
                return [{"id": 32, "environment": "github-pages"},
                        {"id": 31, "environment": "github-pages"}]
            deployment_id = int(path.split("/deployments/")[1].split("/")[0])
            return [{"state": states[deployment_id],
                     "log_url": f"https://github.com/{REPOSITORY}/actions/runs/73/job/901"}]

        pages.require_terminal_previous_deployments(
            REPOSITORY, "fake", run_id=73, run_attempt=2, fetch=fetch,
        )
        states[31] = "in_progress"
        with self.assertRaisesRegex(cas.CasError, "multiple current-run"):
            pages.require_terminal_previous_deployments(
                REPOSITORY, "fake", run_id=73, run_attempt=2, fetch=fetch,
            )

    def test_other_attempts_deployment_cannot_be_exempted(self) -> None:
        def fetch(path: str, _token: str) -> object:
            if "/actions/runs/73/attempts/2/jobs?" in path:
                return {"total_count": 1, "jobs": [{"id": 902, "run_attempt": 2,
                        "name": pages.COMPOSITOR_JOB_NAME}]}
            if "deployments?" in path:
                return [{"id": 32, "environment": "github-pages"}]
            return [{"state": "in_progress",
                     "log_url": f"https://github.com/{REPOSITORY}/actions/runs/73/job/901"}]

        with self.assertRaisesRegex(cas.CasError, "deployment 32 remains nonterminal"):
            pages.require_terminal_previous_deployments(
                REPOSITORY, "fake", run_id=73, run_attempt=2, fetch=fetch,
            )

    def test_older_in_progress_deployment_blocks_even_if_newest_succeeded(self) -> None:
        def fetch(path: str, _token: str) -> object:
            if "deployments?" in path:
                return [{"id": 12, "environment": "github-pages"},
                        {"id": 11, "environment": "github-pages"}]
            return [{"state": "success" if "/12/" in path else "in_progress"}]

        with self.assertRaisesRegex(cas.CasError, "deployment 11 remains nonterminal"):
            pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)

    def test_cancelled_runner_external_deploy_blocks_until_terminal_receipt(self) -> None:
        state = {"value": "in_progress"}

        def fetch(path: str, _token: str) -> object:
            if "deployments?" in path:
                return [{"id": 22, "environment": "github-pages"}]
            return [{"state": state["value"]}]

        with self.assertRaisesRegex(cas.CasError, "nonterminal"):
            pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)
        state["value"] = "success"
        pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)

    def test_failed_environment_is_safe_only_if_deploy_step_never_started(self) -> None:
        step = {"name": "Deploy exact ledger tree", "status": "completed",
                "conclusion": "skipped", "started_at": "2026-09-29T00:00:00Z"}
        backend = {"status": ""}
        duplicate = {"value": False}
        sha = "a" * 40

        def fetch(path: str, _token: str) -> object:
            if "deployments?sha=" in path:
                result = [{"id": 22, "environment": "github-pages", "sha": sha}]
                return result + ([{"id": 23, "environment": "github-pages", "sha": sha}]
                                 if duplicate["value"] else [])
            if "deployments?" in path:
                return [{"id": 22, "environment": "github-pages", "sha": sha}]
            if "/statuses?" in path:
                return [{"state": "failure", "log_url":
                         f"https://github.com/{REPOSITORY}/actions/runs/73/job/901"}]
            if "/actions/jobs/901" in path:
                return {"id": 901, "run_id": 73, "steps": [step]}
            if "/pages/deployments/" in path:
                return backend
            raise AssertionError(path)

        pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)
        step["conclusion"] = "failure"
        step["started_at"] = "2026-09-29T00:00:00Z"
        with self.assertRaisesRegex(cas.CasError, "uncertain external backend"):
            pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)
        backend["status"] = "deployment_cancelled"
        pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)
        duplicate["value"] = True
        with self.assertRaisesRegex(cas.CasError, "uncertain external backend"):
            pages.require_terminal_previous_deployments(REPOSITORY, "fake", fetch=fetch)

    def test_missing_disabled_or_mismatched_intent_ruleset_fails_closed(self) -> None:
        names = (pages.INTENT_CREATION_RULESET, pages.INTENT_IMMUTABLE_RULESET)
        details = {
            1: {"id": 1, "name": names[0], "source_type": "Repository", "source": REPOSITORY,
                "target": "tag", "enforcement": "active",
                "conditions": {"ref_name": {"include": [f"{cas.PROMOTION_INTENT_PREFIX}*"], "exclude": []}},
                "rules": [{"type": "creation"}],
                "bypass_actors": [{"actor_id": 4684827, "actor_type": "Integration", "bypass_mode": "always"}]},
            2: {"id": 2, "name": names[1], "source_type": "Repository", "source": REPOSITORY,
                "target": "tag", "enforcement": "active",
                "conditions": {"ref_name": {"include": [f"{cas.PROMOTION_INTENT_PREFIX}*"], "exclude": []}},
                "rules": [{"type": "update"}, {"type": "deletion"}], "bypass_actors": []},
        }
        summaries = [{"id": 1, "name": names[0]}, {"id": 2, "name": names[1]}]

        def fetch(path: str, _token: str) -> object:
            if path.endswith("includes_parents=false"):
                return summaries
            return details[int(path.rsplit("/", 1)[1])]

        pages.require_protected_intent_policy(REPOSITORY, "fake", fetch=fetch)
        summaries.pop()
        with self.assertRaisesRegex(cas.CasError, "missing"):
            pages.require_protected_intent_policy(REPOSITORY, "fake", fetch=fetch)
        summaries.append({"id": 2, "name": names[1]})
        details[2]["enforcement"] = "disabled"
        with self.assertRaisesRegex(cas.CasError, "does not enforce"):
            pages.require_protected_intent_policy(REPOSITORY, "fake", fetch=fetch)
        details[2]["enforcement"] = "active"
        del details[1]["bypass_actors"]
        del details[2]["bypass_actors"]
        pages.require_protected_intent_policy(REPOSITORY, "fake", fetch=fetch)
        details[1]["bypass_actors"] = []
        with self.assertRaisesRegex(cas.CasError, "bypass policy differs"):
            pages.require_protected_intent_policy(REPOSITORY, "fake", fetch=fetch)


if __name__ == "__main__":
    unittest.main()
