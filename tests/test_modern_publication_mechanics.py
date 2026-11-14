"""Real disposable Git/Ed25519 transactions; no production issuer is provisioned."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import directory_deployment_contract as deployment
import directory_publication as publication
import directory_publication_cas as cas
import observe_modern_directory_publication as observation
import pages_compositor as pages
import prepare_directory_publication as prepare
import sign_directory_publication as signer
import verify_directory_publication as verifier
from directory_feed_contract import LEGACY_FEED, MODERN_FEED
from tests.test_directory_publication import install_fixture_feed, write_valid_package

FIXTURES = ROOT / "tests/fixtures/directory-publication"


def git(repo: Path, *arguments: str) -> str:
    return cas._git(repo, arguments).stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(publication.canonical_json(value))


class ModernPublicationMechanicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.source, self.repo, self.remote = (self.root / name for name in ("source", "publisher", "remote.git"))
        git(self.root, "init", "--bare", "-q", str(self.remote))
        for repo in (self.source, self.repo):
            git(self.root, "init", "-q", str(repo))
            git(repo, "config", "user.name", cas.MARKER_NAME)
            git(repo, "config", "user.email", cas.MARKER_EMAIL)
        self.package = self.source / "plugins/demo"
        write_valid_package(self.package, repository="example/uap")
        shutil.copytree(ROOT / "schemas", self.source / "schemas")
        write_json(self.source / "tests/e2e/production-launch.json",
                   json.loads((ROOT / "tests/e2e/production-launch.json").read_bytes()))
        keys = json.loads((FIXTURES / "trusted-keys.json").read_bytes())["keys"]
        for feed, key in ((LEGACY_FEED, keys[0]), (MODERN_FEED, keys[1])):
            write_json(self.source / feed.trusted_keys_path, {"schema_version": 1, "keys": [key]})
        self.config = {"schema_version": 1, "repository": "example/uap", "snapshot_lifetime_days": 30}
        write_json(self.source / MODERN_FEED.trust_config_path, self.config)
        git(self.source, "add", ".")
        git(self.source, "commit", "-qm", "reviewed test source")
        initial_source = git(self.source, "rev-parse", "HEAD")
        git(self.repo, "fetch", "-q", str(self.source), initial_source)
        git(self.repo, "checkout", "-q", "--detach", initial_source)
        install_fixture_feed(self.repo)
        git(self.repo, "add", LEGACY_FEED.feed_path)
        git(self.repo, "commit", "-qm", "chore(directory): publish signed snapshot")
        self.legacy_signed = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "index.html").write_text("approved legacy site\n")
        git(self.repo, "add", "index.html")
        git(self.repo, "commit", "-qm", "chore(directory): materialize signed production site")
        self.seed = git(self.repo, "rev-parse", "HEAD")
        self.legacy_contract = self.source / LEGACY_FEED.deployment_contract_path
        write_json(self.legacy_contract, {"marker_ref": LEGACY_FEED.production_ref,
                                          "bootstrap_materialized_commit": self.seed})
        self.contract = self.source / MODERN_FEED.deployment_contract_path
        self.public_authority = {
            "contract_version": 1, "marker_ref": MODERN_FEED.production_ref,
            "sequence_tag_prefix": MODERN_FEED.sequence_ref_prefix,
            "bootstrap_ledger_commit": self.seed,
            "origin": "https://test.invalid/registry/modern/schemas/1/", "publisher_app_id": 123,
        }
        write_json(self.contract, self.public_authority)
        git(self.source, "add", ".")
        git(self.source, "commit", "-qm", "reviewed disposable public authority")
        self.main = git(self.source, "rev-parse", "HEAD")
        git(self.repo, "fetch", "-q", str(self.source), self.main)
        git(self.repo, "remote", "add", "origin", str(self.remote))
        git(self.repo, "push", "-q", "origin", f"{self.main}:refs/heads/main",
            f"{self.seed}:{LEGACY_FEED.ledger_ref}", f"{self.seed}:{MODERN_FEED.ledger_ref}",
            f"{self.seed}:{LEGACY_FEED.production_ref}",
            f"{self.legacy_signed}:{LEGACY_FEED.sequence_ref_prefix}{15:020d}")
        for module in (publication, deployment, pages, signer, verifier, observation):
            self.stack.enter_context(mock.patch.object(module, "ROOT", self.source))
        self.now = publication.format_timestamp(datetime.now(timezone.utc) - timedelta(seconds=10))
        self.seeds = json.loads((FIXTURES / "test-private-seeds.json").read_bytes())
        self.stack.enter_context(mock.patch.dict(os.environ, {MODERN_FEED.private_key_environment: self.seeds["test-next"]}))
        fixture = json.loads((FIXTURES / "initial-source.json").read_bytes())
        distribution = fixture["distributions"][0]
        release = distribution["releases"][0]
        release.pop("published_at")
        release["package_source"]["revision"] = None
        release["tree_digest"] = prepare.package_tree_digest(self.package)
        release["manifest_digest"] = prepare.manifest_digest(self.package)
        policy = distribution["release_policies"][0]
        policy["status"] = "active"
        policy["targets"][0]["client"] = "hermes"
        distribution["releases"], distribution["release_policies"] = [release], [policy]
        self.directory = fixture
        self.sequence = 0

    def refs(self) -> str:
        return git(self.repo, "ls-remote", "--refs", "origin")

    def commit(self, parent: str, path: str | None, content: str, message: str) -> str:
        git(self.repo, "checkout", "-q", "--detach", parent)
        if path is not None:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            git(self.repo, "add", path)
        git(self.repo, "commit", "--allow-empty", "-qm", message)
        return git(self.repo, "rev-parse", "HEAD")

    def prepare_pair(self) -> tuple[str, str, str, str]:
        previous = None
        parent = self.seed if not self.sequence else self.materialized
        git(self.repo, "checkout", "-q", "--detach", parent)
        if self.sequence:
            self.now = publication.format_timestamp(publication.parse_timestamp(self.now, "fixture time") + timedelta(seconds=1))
            previous = publication.load_ledger_latest(
                self.repo, publication.load_feed_trusted_keys(self.source / MODERN_FEED.trusted_keys_path, MODERN_FEED),
                minimum_sequence=self.sequence, feed=MODERN_FEED,
            )[0]
            git(self.source, "fetch", "-q", str(self.repo), self.main)
            git(self.source, "checkout", "-q", "--detach", self.main)
        publication_id = f"modern-{self.sequence + 1}"
        candidate = prepare.build_candidate(self.directory, self.config, self.main, publication_id,
                                            previous, repository_root=self.source, feed=MODERN_FEED)
        self.assertEqual(candidate["evidence"], [])  # Support metadata invented no evidence.
        candidate_path = self.root / "candidate.json"
        write_json(candidate_path, candidate)
        arguments = ["sign", "--candidate", str(candidate_path), "--candidate-digest",
                     publication.candidate_digest(candidate_path.read_bytes()), "--ledger", str(self.repo),
                     "--key-id", "test-next", "--now", self.now, "--result", str(self.root / "result.json"),
                     "--ledger-seed-commit", self.seed]
        if not self.sequence:
            arguments += ["--initialize-ledger"]
        else:
            arguments += ["--ledger-sequence-floor", str(self.sequence)]
        with mock.patch.object(sys, "argv", arguments), redirect_stdout(io.StringIO()):
            self.assertEqual(signer.main(feed=MODERN_FEED), 0)
        self.sequence += 1
        git(self.repo, "add", MODERN_FEED.feed_path)
        git(self.repo, "commit", "-qm", "chore(directory): publish signed snapshot")
        signed = git(self.repo, "rev-parse", "HEAD")
        materialized = self.commit(signed, None, "", "chore(directory): materialize signed production site")
        marker = cas.create_marker(self.repo, self.main, publication_id)
        self.signed, self.materialized = signed, materialized
        return signed, materialized, marker, parent

    def publish(self, *, approve: bool = True, lost_response: bool = False) -> pages.CompositionPlan | None:
        signed, materialized, marker, parent = self.prepare_pair()
        tag = MODERN_FEED.sequence_ref_prefix + f"{self.sequence:020d}"
        pushes = []

        def push(arguments):
            pushes.append(arguments)
            cas._git(self.repo, arguments)
            return False  # The response is lost after the real local Git push.

        options = dict(source=self.main, marker=marker, ledger_old=parent, signed=signed,
                       materialized=materialized, sequence_tag=tag, publication_id=f"modern-{self.sequence}",
                       feed=MODERN_FEED)
        self.assertEqual(cas.atomic_materialized_transition(self.repo, "origin", **options,
                         push_runner=push if lost_response else None), "published")
        self.assertEqual(cas.atomic_materialized_transition(self.repo, "origin", **options), "committed")
        if lost_response:
            self.assertEqual(len(pushes), 1)
            self.assertTrue(any(MODERN_FEED.ledger_ref in part for part in pushes[0]))
            self.assertFalse(any(LEGACY_FEED.ledger_ref in part for part in pushes[0]))
        self.main = marker
        if approve:
            self.approve(signed, materialized, self.sequence)
            return pages.select_composition(self.repo, "origin", feed=MODERN_FEED)
        return None

    def approve(self, signed: str, materialized: str, sequence: int) -> None:
        publication_id, digest = cas._snapshot_identity(self.repo, signed, sequence, feed=MODERN_FEED)
        options = dict(materialized=materialized, signed=signed, sequence=sequence,
                       publication_id=publication_id, snapshot_digest=digest,
                       readiness_digest="sha256:" + "a" * 64, feed=MODERN_FEED)
        self.assertEqual(cas.publish_promotion_intent(self.repo, "origin", **options), "published")
        self.assertEqual(cas.publish_promotion_intent(self.repo, "origin", **options), "committed")

    def transport(self, plan: pages.CombinedCompositionPlan):
        prefix = self.public_authority["origin"]

        def fetch(_opener, url, maximum):
            self.assertTrue(url.startswith(prefix))
            relative = url.removeprefix(prefix)
            body = cas._git(self.repo, ["show", f"{plan.modern.signed_commit}:{MODERN_FEED.feed_path}/{relative}"]).stdout.encode()
            self.assertLessEqual(len(body), maximum)
            return body

        return fetch

    def advance_legacy(self) -> str:
        parent = git(self.repo, "ls-remote", "--refs", "origin", LEGACY_FEED.ledger_ref).split()[0]
        git(self.repo, "checkout", "-q", "--detach", parent)
        snapshot = json.loads((FIXTURES / "snapshot.json").read_bytes())
        snapshot.update(sequence=16, publication_id="legacy-16")
        body = publication.canonical_json(snapshot)
        envelope = json.loads((FIXTURES / "envelope-current.json").read_bytes())
        envelope.update(sequence=16, snapshot_digest=publication.sha256_digest(body),
            signature=base64.b64encode(publication.ed25519_sign(
                publication.ed25519_private_key(self.seeds["test-current"]), publication.signature_message(body))).decode())
        latest = json.loads((FIXTURES / "latest.json").read_bytes())
        latest.update(sequence=16, snapshot_path=f"snapshots/{16:020d}.json",
                      envelope_path=f"snapshots/{16:020d}.envelope.json")
        feed = self.repo / LEGACY_FEED.feed_path
        write_json(feed / latest["snapshot_path"], snapshot)
        write_json(feed / latest["envelope_path"], envelope)
        write_json(feed / "latest.json", latest)
        git(self.repo, "add", LEGACY_FEED.feed_path)
        git(self.repo, "commit", "-qm", "chore(directory): publish signed snapshot")
        signed = git(self.repo, "rev-parse", "HEAD")
        site = self.commit(signed, "index.html", "new approved legacy site\n",
                           "chore(directory): materialize signed production site")
        git(self.repo, "push", "-q", "origin", f"{site}:{LEGACY_FEED.ledger_ref}",
            f"{signed}:{LEGACY_FEED.sequence_ref_prefix}{16:020d}")
        cas.publish_promotion_intent(self.repo, "origin", materialized=site, signed=signed, sequence=16,
            publication_id="legacy-16", snapshot_digest=publication.sha256_digest(body), readiness_digest="sha256:" + "b" * 64)
        return site

    def append_feed(self, parent: str, feed: str, sequence: int = 1) -> str:
        git(self.repo, "checkout", "-q", "--detach", parent)
        stem = f"{sequence:020d}"
        names = ["latest.json", f"snapshots/{stem}.json", f"snapshots/{stem}.envelope.json"]
        if feed == "discovery":
            names.append(f"search/{stem}.json")
        for name in names:
            write_json(self.repo / feed / name, {"sequence": sequence})
        git(self.repo, "add", feed)
        git(self.repo, "commit", "-qm", f"chore({feed}): publish sequence {sequence}")
        return git(self.repo, "rev-parse", "HEAD")

    def test_real_prepare_sign_cas_lost_ack_intent_composition_and_verified_readback(self) -> None:
        legacy_before = git(self.repo, "rev-parse", f"{self.seed}:registry/schemas/1")
        self.publish(lost_response=True)
        plan = pages.combine_composition(self.repo, "origin")
        self.assertIsNone(plan.modern.production_marker)
        self.assertEqual(plan.modern.sequence, 1)
        self.assertEqual(git(self.repo, "rev-parse", f"{plan.tree}:registry/schemas/1"), legacy_before)
        self.assertEqual(git(self.repo, "show", f"{plan.tree}:index.html"), "approved legacy site")
        reacquired = self.root / "reacquired"
        git(self.root, "clone", "-q", "--no-checkout", str(self.remote), str(reacquired))
        git(reacquired, "checkout", "-q", "--detach", self.materialized)
        loaded = publication.load_ledger_latest(reacquired,
            publication.load_feed_trusted_keys(self.source / MODERN_FEED.trusted_keys_path, MODERN_FEED),
            minimum_sequence=1, seed_commit=self.seed, feed=MODERN_FEED)
        self.assertEqual(loaded[0]["sequence"], 1)
        with mock.patch.object(observation.observer, "fetch", side_effect=self.transport(plan)):
            receipt = observation.observe_composition(self.repo, "origin", plan)
        self.assertEqual(receipt["ledger_commit"], self.materialized)
        self.assertEqual(receipt["composition_tree"], plan.tree)
        self.assertEqual(receipt["publication_id"], "modern-1")
        self.assertEqual(receipt["source_commit"], loaded[0]["source_commit"])
        self.assertEqual(cas.production_transition(self.repo, "origin", production_new=self.materialized,
                         production_tag=MODERN_FEED.production_ref, feed=MODERN_FEED), "published")
        selected = pages.select_composition(self.repo, "origin", feed=MODERN_FEED)
        self.assertEqual(selected.production_marker, self.materialized)
        self.assertEqual(git(self.repo, "ls-remote", "--refs", "origin", LEGACY_FEED.production_ref).split()[0], self.seed)

    def test_seed_or_signed_pair_without_approved_intent_is_not_production(self) -> None:
        before = self.refs()
        with self.assertRaises(cas.CasError):
            pages.select_composition(self.repo, "origin", feed=MODERN_FEED)
        self.assertEqual(self.refs(), before)
        self.publish(approve=False)
        with self.assertRaisesRegex(cas.CasError, "approved immutable intent"):
            pages.select_composition(self.repo, "origin", feed=MODERN_FEED)
        with self.assertRaisesRegex(cas.CasError, "approved immutable intent"):
            cas.production_transition(self.repo, "origin", production_new=self.materialized,
                                      production_tag=MODERN_FEED.production_ref, feed=MODERN_FEED)
        self.assertNotIn(MODERN_FEED.production_ref, self.refs())

    def test_modern_materialization_rejects_site_and_every_sibling_feed_change(self) -> None:
        signed, materialized, _marker, _parent = self.prepare_pair()
        cas.validate_materialized_descendant(self.repo, materialized, signed, feed=MODERN_FEED)
        for path in ("index.html", "registry/schemas/1/latest.json", "discovery/latest.json", "security/latest.json",
                     MODERN_FEED.feed_path + "/latest.json"):
            altered = self.commit(signed, path, "changed\n", "chore(directory): materialize signed production site")
            with self.subTest(path=path), self.assertRaisesRegex(cas.CasError, "exact signed tree"):
                cas.validate_materialized_descendant(self.repo, altered, signed, feed=MODERN_FEED)
        legacy_site = self.commit(self.legacy_signed, "index.html", "allowed legacy site\n",
                                  "chore(directory): materialize signed production site")
        cas.validate_materialized_descendant(self.repo, legacy_site, self.legacy_signed)

    def test_wrong_namespaces_and_reconstructed_profiles_cannot_mutate_refs(self) -> None:
        signed, materialized, marker, parent = self.prepare_pair()
        before = self.refs()
        for feed, tag in ((MODERN_FEED, LEGACY_FEED.sequence_ref_prefix + f"{1:020d}"),
                          (LEGACY_FEED, MODERN_FEED.sequence_ref_prefix + f"{1:020d}")):
            with self.subTest(feed=feed.name), self.assertRaises(cas.CasError):
                cas.atomic_materialized_transition(self.repo, "origin", source=self.main, marker=marker,
                    ledger_old=parent, signed=signed, materialized=materialized, sequence_tag=tag,
                    publication_id="modern-1", feed=feed)
        with self.assertRaises(ValueError):
            cas.production_transition(self.repo, "origin", production_new=materialized,
                                      production_tag=MODERN_FEED.production_ref, feed=replace(MODERN_FEED))
        with self.assertRaises(cas.CasError):
            cas.production_transition(self.repo, "origin", production_new=materialized,
                                      production_tag=LEGACY_FEED.production_ref, feed=MODERN_FEED)
        self.assertEqual(self.refs(), before)

    def test_missing_or_redirected_reviewed_authority_fails_before_remote_io(self) -> None:
        self.contract.unlink()
        with mock.patch.object(pages, "_git") as remote:
            with self.assertRaises(publication.PublicationError):
                pages.combine_composition(self.repo, "origin")
            remote.assert_not_called()
        self.contract.symlink_to(self.legacy_contract)
        with self.assertRaisesRegex(ValueError, "reviewed-source"):
            deployment.load_modern_deployment_contract()

    def test_legacy_and_modern_advances_keep_the_other_authority_and_live_feeds(self) -> None:
        self.publish()
        first = pages.combine_composition(self.repo, "origin")
        first_modern = git(self.repo, "rev-parse", f"{first.tree}:{MODERN_FEED.feed_path}")
        legacy = self.advance_legacy()
        for feed in ("discovery", "security"):
            legacy = self.append_feed(legacy, feed)
            git(self.repo, "push", "-q", "origin", f"{legacy}:{LEGACY_FEED.ledger_ref}",
                f"{legacy}:refs/tags/{feed}-index-sequence-{1:020d}")
        with self.assertRaisesRegex(cas.CasError, "stale"):
            pages.require_current_combined_composition(self.repo, "origin", first)
        after_legacy = pages.combine_composition(self.repo, "origin")
        self.assertEqual(git(self.repo, "rev-parse", f"{after_legacy.tree}:{MODERN_FEED.feed_path}"), first_modern)
        self.assertEqual(git(self.repo, "show", f"{after_legacy.tree}:index.html"), "new approved legacy site")
        self.publish()
        after_modern = pages.combine_composition(self.repo, "origin")
        self.assertEqual(after_modern.modern.sequence, 2)
        for path in (LEGACY_FEED.feed_path, "discovery", "security"):
            self.assertEqual(git(self.repo, "rev-parse", f"{after_modern.tree}:{path}"),
                             git(self.repo, "rev-parse", f"{after_legacy.tree}:{path}"))
        old_snapshot = MODERN_FEED.feed_path + f"/snapshots/{1:020d}.json"
        self.assertEqual(git(self.repo, "show", f"{after_modern.tree}:{old_snapshot}"),
                         git(self.repo, "show", f"{first.tree}:{old_snapshot}"))

    def test_modern_reassembly_and_readback_refuse_foreign_interleaving(self) -> None:
        self.publish()
        first_signed, first_materialized = self.signed, self.materialized
        for feed in ("discovery", "security"):
            foreign = self.append_feed(first_materialized, feed)
            with self.subTest(feed=feed), self.assertRaisesRegex(cas.CasError, "foreign feed"):
                cas.validate_staged_lineage(self.repo, foreign, first_signed, feed=MODERN_FEED)
            with self.assertRaisesRegex(cas.CasError, "prepare a new publication"):
                cas.reassemble_materialization(self.repo, ledger_old=self.seed, prepared_signed=first_signed,
                    prepared_materialized=first_materialized, ledger_head=foreign,
                    sequence_tag=MODERN_FEED.sequence_ref_prefix + f"{1:020d}", feed=MODERN_FEED)
        git(self.repo, "push", "-q", "origin", f"{foreign}:{MODERN_FEED.ledger_ref}")
        with self.assertRaisesRegex(cas.CasError, "foreign feed append"):
            pages.select_composition(self.repo, "origin", feed=MODERN_FEED)

    def test_rebased_entrypoint_keeps_exact_modern_objects_and_resolves_lost_ack(self) -> None:
        signed, materialized, marker, parent = self.prepare_pair()
        options = dict(source=self.main, marker=marker, ledger_old=parent, prepared_signed=signed,
            prepared_materialized=materialized, authenticated_head=parent, publication_id="modern-1",
            sequence_tag=MODERN_FEED.sequence_ref_prefix + f"{1:020d}", feed=MODERN_FEED)

        def lose_response(arguments):
            cas._git(self.repo, arguments)
            return False

        result = cas.atomic_rebased_materialized_transition(self.repo, "origin", **options, push_runner=lose_response)
        self.assertEqual((result.status, result.signed, result.materialized), ("published", signed, materialized))
        retry = cas.atomic_rebased_materialized_transition(self.repo, "origin", **options)
        self.assertEqual((retry.status, retry.signed, retry.materialized), ("committed", signed, materialized))

    def test_split_sign_and_materialize_transitions_use_only_modern_refs(self) -> None:
        signed, materialized, marker, parent = self.prepare_pair()
        options = dict(source=self.main, marker=marker, ledger_old=parent, ledger_new=signed,
                       sequence_tag=MODERN_FEED.sequence_ref_prefix + f"{1:020d}", feed=MODERN_FEED)
        self.assertEqual(cas.atomic_transition(self.repo, "origin", **options), "published")
        self.assertEqual(cas.materialize_transition(self.repo, "origin", ledger_old=signed,
                         ledger_new=materialized, feed=MODERN_FEED), "published")
        self.assertEqual(cas.atomic_transition(self.repo, "origin", **options), "materialized")
        self.assertEqual(git(self.repo, "ls-remote", "--refs", "origin", LEGACY_FEED.ledger_ref).split()[0], self.seed)

    def test_conflicting_main_ledger_or_sequence_never_updates_other_refs(self) -> None:
        signed, materialized, marker, parent = self.prepare_pair()
        tag = MODERN_FEED.sequence_ref_prefix + f"{1:020d}"
        competitor = self.commit(parent, "foreign.txt", "foreign\n", "unrelated commit")
        for ref, restore in (("refs/heads/main", self.main), (MODERN_FEED.ledger_ref, parent), (tag, None)):
            git(self.repo, "push", "-q", "--force", "origin", f"{competitor}:{ref}")
            before = self.refs()
            with self.subTest(ref=ref), self.assertRaisesRegex(cas.CasError, "ref conflict"):
                cas.atomic_materialized_transition(self.repo, "origin", source=self.main, marker=marker,
                    ledger_old=parent, signed=signed, materialized=materialized, sequence_tag=tag,
                    publication_id="modern-1", feed=MODERN_FEED)
            self.assertEqual(self.refs(), before)
            git(self.repo, "push", "-q", "--force", "origin", f"{restore or ''}:{ref}")

    def test_observation_rejects_foreign_identity_and_ref_changes_without_receipt(self) -> None:
        self.publish()
        plan = pages.combine_composition(self.repo, "origin")
        with mock.patch.object(observation.observer, "fetch", side_effect=self.transport(plan)):
            real = observation.observer.observe_once(self.public_authority["origin"],
                    self.source / MODERN_FEED.trusted_keys_path, 1, feed=MODERN_FEED)
        for field, wrong in (("sequence", 2), ("publication_id", "foreign"),
                             ("source_commit", "a" * 40), ("snapshot_digest", "sha256:" + "b" * 64)):
            with self.subTest(field=field), mock.patch.object(observation.observer, "observe_once", return_value={**real, field: wrong}):
                with self.assertRaisesRegex(publication.PublicationError, "differs from the selected"):
                    observation.observe_composition(self.repo, "origin", plan)
        altered = replace(plan, modern=replace(plan.modern, directory_commit=self.seed))
        with mock.patch.object(observation.observer, "fetch") as fetch:
            with self.assertRaisesRegex(cas.CasError, "stale"):
                observation.observe_composition(self.repo, "origin", altered)
            fetch.assert_not_called()

        def advance_during_observation(*_args, **_kwargs):
            self.advance_legacy()
            return real

        with mock.patch.object(observation.observer, "observe_once", side_effect=advance_during_observation):
            with self.assertRaisesRegex(cas.CasError, "stale"):
                observation.observe_composition(self.repo, "origin", plan)

    def test_verifier_uses_current_modern_schema_and_refuses_legacy_keys(self) -> None:
        self.publish()
        args = ["verify", "--feed", str(self.repo / MODERN_FEED.feed_path), "--now", self.now]
        with mock.patch.object(sys, "argv", args), redirect_stdout(io.StringIO()):
            self.assertEqual(verifier.main(feed=MODERN_FEED), 0)
        keys = json.loads((FIXTURES / "trusted-keys.json").read_bytes())["keys"]
        write_json(self.source / MODERN_FEED.trusted_keys_path, {"schema_version": 1, "keys": [keys[0]]})
        with self.assertRaisesRegex(publication.PublicationError, "independent of legacy"):
            deployment.load_modern_deployment_contract()

    def test_public_contract_rejects_wrong_seed_namespace_origin_and_app(self) -> None:
        cases = [("marker_ref", LEGACY_FEED.production_ref), ("sequence_tag_prefix", LEGACY_FEED.sequence_ref_prefix),
                 ("bootstrap_ledger_commit", "main"), ("publisher_app_id", True), ("publisher_app_id", 0)]
        cases += [("origin", origin) for origin in (
            "http://test.invalid/registry/modern/schemas/1/", "https://test.invalid/registry/schemas/1/",
            "https://user@test.invalid/registry/modern/schemas/1/", self.public_authority["origin"] + "?override=1",
            "https://test.invalid:bad/registry/modern/schemas/1/", "https://test.invalid:65536/registry/modern/schemas/1/",
            "https://test.invalid:0/registry/modern/schemas/1/", "https://test .invalid/registry/modern/schemas/1/",
            "https://777genius.github.io/registry/modern/schemas/1/",
            "https://777GENIUS.github.io./registry/modern/schemas/1/",
            "https://777genius.github.io:00443/registry/modern/schemas/1/",
        )]
        for field, value in cases:
            write_json(self.contract, {**self.public_authority, field: value})
            with self.subTest(field=field, value=value), self.assertRaises(publication.PublicationError):
                deployment.load_modern_deployment_contract()
        write_json(self.contract, self.public_authority)
        self.publish()
        write_json(self.contract, {**self.public_authority, "bootstrap_ledger_commit": self.main})
        with self.assertRaisesRegex(cas.CasError, "lineage"):
            pages.select_composition(self.repo, "origin", feed=MODERN_FEED)

    def test_production_is_monotonic_and_conflicting_intent_does_not_replace_approval(self) -> None:
        self.publish()
        first = self.materialized
        self.assertEqual(cas.production_transition(self.repo, "origin", production_new=first,
                         production_tag=MODERN_FEED.production_ref, feed=MODERN_FEED), "published")
        self.publish()
        self.assertEqual(cas.production_transition(self.repo, "origin", production_new=self.materialized,
                         production_tag=MODERN_FEED.production_ref, feed=MODERN_FEED), "published")
        self.assertEqual(cas.production_transition(self.repo, "origin", production_new=first,
                         production_tag=MODERN_FEED.production_ref, feed=MODERN_FEED), "superseded")
        self.assertEqual(cas.production_transition(self.repo, "origin", production_new=self.materialized,
                         production_tag=MODERN_FEED.production_ref, feed=MODERN_FEED), "committed")
        before = self.refs()
        publication_id, digest = cas._snapshot_identity(self.repo, self.signed, 2, feed=MODERN_FEED)
        with self.assertRaisesRegex(cas.CasError, "another object"):
            cas.publish_promotion_intent(self.repo, "origin", materialized=self.materialized, signed=self.signed,
                sequence=2, publication_id=publication_id, snapshot_digest=digest,
                readiness_digest="sha256:" + "c" * 64, feed=MODERN_FEED)
        with self.assertRaisesRegex(cas.CasError, "protected namespace"):
            cas.parse_promotion_intent(self.repo, LEGACY_FEED.intent_ref_prefix + f"{2:020d}", "a" * 40,
                                       feed=MODERN_FEED)
        self.assertEqual(self.refs(), before)

    def test_combined_plan_detects_ref_movement_while_composing(self) -> None:
        self.publish()
        overlay = pages._overlay_modern_tree

        def advance(*arguments):
            result = overlay(*arguments)
            self.advance_legacy()
            return result

        with mock.patch.object(pages, "_overlay_modern_tree", side_effect=advance):
            with self.assertRaisesRegex(cas.CasError, "stale during selection"):
                pages.combine_composition(self.repo, "origin")

    def test_fixed_overlay_refuses_unpublished_files_and_linked_artifacts(self) -> None:
        signed, _materialized, _marker, _parent = self.prepare_pair()
        extra = self.commit(signed, MODERN_FEED.feed_path + "/private.txt", "not public\n", "unapproved file")
        with self.assertRaisesRegex(cas.CasError, "non-public"):
            pages._overlay_modern_tree(self.repo, self.seed, extra)
        git(self.repo, "checkout", "-q", "--detach", signed)
        linked = self.repo / MODERN_FEED.feed_path / "latest.json"
        linked.unlink()
        linked.symlink_to("../../../../outside.json")
        git(self.repo, "add", MODERN_FEED.feed_path)
        git(self.repo, "commit", "-qm", "unapproved link")
        with self.assertRaisesRegex(cas.CasError, "non-regular"):
            pages._overlay_modern_tree(self.repo, self.seed, git(self.repo, "rev-parse", "HEAD"))


class ModernEntrypointContractTests(unittest.TestCase):
    def test_unprovisioned_entrypoints_refuse_before_artifact_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            cases = {
                "modern_directory_publication_cas.py": ["marker", "--source", "a" * 40,
                    "--publication-id", "test", "--output", str(output)],
                "modern_pages_compositor.py": ["plan", "--output", str(output)],
                "verify_modern_directory_publication.py": ["--feed", str(Path(temporary) / "absent"),
                    "--now", "2026-11-14T00:00:00Z"],
                "observe_modern_directory_publication.py": ["--plan", "absent.json", "--output", str(output)],
            }
            for script, arguments in cases.items():
                for extra in ([], ["--origin", "https://untrusted.invalid"], ["--trusted-keys", "untrusted.json"],
                              ["--contract", "untrusted.json"], ["--profile", "legacy"]):
                    with self.subTest(script=script, extra=extra):
                        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / script), *arguments, *extra],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("unrecognized arguments" if extra else MODERN_FEED.deployment_contract_path, result.stderr)
                        self.assertFalse(output.exists())

    def test_package_imports_keep_singleton_and_error_identity(self) -> None:
        from scripts import directory_feed_contract as feeds
        from scripts import directory_publication_cas as package_cas
        from scripts import pages_compositor as package_pages
        from scripts import verify_directory_publication as package_verifier
        from scripts import observe_modern_directory_publication as package_observer
        from scripts import modern_directory_publication_cas as cas_entry
        from scripts import modern_pages_compositor as pages_entry
        from scripts import verify_modern_directory_publication as verify_entry

        self.assertIs(cas_entry.main, package_cas.main)
        self.assertIs(pages_entry.main, package_pages.main)
        self.assertIs(verify_entry.main, package_verifier.main)
        self.assertIs(package_observer.cas.CasError, package_cas.CasError)
        self.assertIs(package_observer.MODERN_FEED, feeds.MODERN_FEED)
        with self.assertRaisesRegex(package_cas.CasError, "fixed reviewed"):
            package_pages.select_composition(ROOT, "origin", Path("untrusted.json"), feed=feeds.MODERN_FEED)


if __name__ == "__main__":
    unittest.main()
