from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import discover_skillspector_sources as discovery
from scripts.discovery_checkpoint import WorkBudget
from scripts.skillspector_coverage import validate_discovery_summary, validate_selection
from scripts.directory_publication import PublicationError
from tests.test_skillspector_reports import fixture_repository, git, item


def listing(name="demo", slug="demo", source="owner/repo"):
    return {"source": source, "skillId": slug, "name": name}


def catalog(complete=True):
    return {"complete": complete, "pages": 1, "provider_total": 1, "error": None}


class CatalogTests(unittest.TestCase):
    def test_explicit_path_is_preserved_but_slug_is_not_promoted_to_a_path(self):
        row = listing(slug="skills/demo") | {"path": "packages/current/skills/demo/SKILL.md", "installs": 10}
        rows, _ = discovery.browse_catalog(WorkBudget(10), fetch=lambda *_:
            {"page": 0, "total": 1, "hasMore": False, "skills": [row]})
        self.assertEqual(rows, [{key: row[key] for key in ("source", "skillId", "name", "path")}])
        del row["path"]
        rows, _ = discovery.browse_catalog(WorkBudget(10), fetch=lambda *_:
            {"page": 0, "total": 1, "hasMore": False, "skills": [row]})
        self.assertNotIn("path", rows[0])

    def test_pages_stop_at_end_and_keep_exact_raw_name(self):
        pages = [{"page": 0, "total": 2, "hasMore": True, "skills": [listing("Demo Skill")]},
                 {"page": 1, "total": 2, "hasMore": False, "skills": [listing("révision", "revision")]}]
        fetch = mock.Mock(side_effect=pages)
        rows, meta = discovery.browse_catalog(WorkBudget(10), fetch=fetch)
        self.assertEqual([r["name"] for r in rows], ["Demo Skill", "révision"])
        self.assertTrue(meta["complete"])
        self.assertEqual(fetch.call_count, 2)

    def test_transient_failure_preserves_acquired_pages_and_is_explicit(self):
        fetch = mock.Mock(side_effect=[{"page": 0, "total": 2, "hasMore": True, "skills": [listing()]}, OSError()])
        rows, meta = discovery.browse_catalog(WorkBudget(10), fetch=fetch)
        self.assertEqual(len(rows), 1)
        self.assertFalse(meta["complete"])
        self.assertEqual(meta["error"], "catalog_acquisition_failed")

    def test_malformed_page_is_atomic_and_pagination_is_bounded(self):
        value = {"page": 0, "total": 2, "hasMore": True, "skills": [listing(), listing()]}
        rows, meta = discovery.browse_catalog(WorkBudget(10), fetch=lambda *_: value)
        self.assertEqual(rows, [])
        self.assertFalse(meta["complete"])
        value["skills"] = [listing()]
        rows, meta = discovery.browse_catalog(WorkBudget(10), fetch=lambda *_: value, max_pages=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(meta["error"], "catalog_page_limit_reached")

    def test_rank_overlap_never_claims_a_complete_census(self):
        pages = [{"page": n, "total": 2, "hasMore": n == 0, "skills": [listing()]} for n in range(2)]
        rows, meta = discovery.browse_catalog(WorkBudget(10), fetch=mock.Mock(side_effect=pages))
        self.assertEqual(len(rows), 1)
        self.assertFalse(meta["complete"])

    def test_empty_terminal_page_is_success_and_expired_budget_is_explicit(self):
        rows, meta = discovery.browse_catalog(WorkBudget(10), fetch=lambda *_:
            {"page": 0, "total": 0, "hasMore": False, "skills": []})
        self.assertEqual(rows, [])
        self.assertTrue(meta["complete"])
        budget = WorkBudget(1, monotonic=lambda: 0)
        budget.monotonic = lambda: 2
        rows, meta = discovery.browse_catalog(budget, fetch=mock.Mock())
        self.assertEqual(meta["error"], "catalog_budget_exhausted")


class PublishedDirectoryTests(unittest.TestCase):
    fixtures = discovery.ROOT / "tests/fixtures/directory-publication"

    def feed(self):
        return {"latest.json": (self.fixtures / "latest.json").read_bytes(),
                "snapshots/00000000000000000015.json": (self.fixtures / "snapshot.json").read_bytes(),
                "snapshots/00000000000000000015.envelope.json": (self.fixtures / "envelope-current.json").read_bytes()}

    def test_temporary_directory_network_failure_is_retried_with_a_bound(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"{}"
        opener = mock.Mock()
        opener.open.side_effect = [OSError("temporary connection failure"), response]
        with mock.patch.object(discovery.urllib.request, "build_opener", return_value=opener), \
             mock.patch.object(discovery.time, "sleep"):
            self.assertEqual(discovery.fetch_directory("latest.json", 1024, WorkBudget(20)), b"{}")
        self.assertEqual(opener.open.call_count, 2)
        opener.open.side_effect = OSError("persistent connection failure")
        opener.open.reset_mock()
        with mock.patch.object(discovery.urllib.request, "build_opener", return_value=opener), \
             mock.patch.object(discovery.time, "sleep"), self.assertRaises(OSError):
            discovery.fetch_directory("latest.json", 1024, WorkBudget(20))
        self.assertEqual(opener.open.call_count, 3)

    def test_directory_sources_are_authenticated_and_immutable(self):
        feed = self.feed()
        plugins, identity = discovery.load_published_plugins(WorkBudget(10),
            fetch=lambda relative, *_: feed[relative], trusted_keys=self.fixtures / "trusted-keys.json",
            current=datetime(2026, 8, 21, tzinfo=timezone.utc))
        self.assertEqual(identity["sequence"], 15)
        self.assertEqual(identity["state"], "resolved")
        self.assertTrue(plugins)
        self.assertTrue(all(discovery.SHA_RE.fullmatch(plugin["source"]["revision"]) for plugin in plugins))
        feed["snapshots/00000000000000000015.json"] = feed["snapshots/00000000000000000015.json"].replace(
            b'"publication_id":"fixture-1"', b'"publication_id":"fixture-2"')
        with self.assertRaises(PublicationError):
            discovery.load_published_plugins(WorkBudget(10), fetch=lambda relative, *_: feed[relative],
                trusted_keys=self.fixtures / "trusted-keys.json", current=datetime(2026, 8, 21, tzinfo=timezone.utc))

    def test_expired_directory_does_not_refresh_card_identity(self):
        feed = self.feed()
        with self.assertRaises(discovery.DiscoveryError):
            discovery.load_published_plugins(WorkBudget(10), fetch=lambda relative, *_: feed[relative],
                trusted_keys=self.fixtures / "trusted-keys.json", current=datetime(2026, 10, 28, tzinfo=timezone.utc))

    def test_cloudflare_skill_bridge_is_distinct_from_legacy_mcp_only_distribution(self):
        source = json.loads((discovery.ROOT / "registry/directory.json").read_bytes())
        for distribution in source["distributions"]:
            for release in distribution["releases"]:
                if release["package_source"]["revision"] is None:
                    release["package_source"]["revision"] = "4" * 40
        plugins = {plugin["name"]: plugin for plugin in discovery.published_plugin_sources(source)}
        skill_bridge = plugins["777genius/cloudflare-bridge"]
        self.assertIn("skills", skill_bridge["components"])
        self.assertEqual(skill_bridge["source"], {"repository": "777genius/universal-agent-plugins-registry",
            "revision": "4" * 40, "path": "plugins/cloudflare"})
        mcp_only = plugins["777genius/cloudflare"]
        self.assertNotIn("skills", mcp_only["components"])
        self.assertEqual(mcp_only["source"]["repository"], "777genius/universal-agent-plugins")


class DocumentTests(unittest.TestCase):
    def test_only_exact_skill_candidates_request_blob_sizes(self):
        skill_oid, unrelated_oid = "a" * 40, "b" * 40
        tree = (f"100644 blob {skill_oid}\tskills/demo/SKILL.md\0" +
                f"100644 blob {unrelated_oid}\tunrelated-large-artifact.zip\0").encode()
        pinned = mock.Mock()
        budget = WorkBudget(10)
        with mock.patch.object(discovery, "bounded_tree", return_value=tree), \
             mock.patch.object(discovery, "read_blobs", return_value={skill_oid: b"---\nname: demo\n---\n"}) as read:
            names, invalid = discovery.skill_documents(pinned, budget)
        self.assertEqual(names, {"demo": ["skills/demo"]})
        self.assertEqual(invalid, [])
        read.assert_called_once_with(pinned, [skill_oid], max_files=discovery.MAX_DOCUMENTS,
            max_file_bytes=discovery.MAX_DOCUMENT_BYTES, max_tree_bytes=discovery.MAX_DOCUMENT_TOTAL_BYTES, budget=budget)
        self.assertNotIn(unrelated_oid, str(read.call_args_list))

    def test_exact_declared_names_crlf_and_unicode(self):
        self.assertEqual(discovery.declared_name("---\r\nname: révision 2\r\n---\r\nbody".encode()), "révision 2")

    def test_ambiguous_yaml_and_oversized_documents_are_rejected(self):
        for body in [b"---\nname: first\nname: second\n---\n", b"---\nname: &a demo\nother: *a\n---\n",
                     b"---\nname: []\n---\n", b"no frontmatter", b"x" * (discovery.MAX_DOCUMENT_BYTES + 1)]:
            with self.subTest(body=body[:60]), self.assertRaises(Exception):
                discovery.declared_name(body)

    def test_nested_and_root_names_are_resolved_without_executing_scripts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, selection = fixture_repository(root)
            source = root / "source"
            (source / "SKILL.md").write_text("---\nname: Root Name\n---\n")
            (source / "unrelated").symlink_to("missing")
            git(source, "add", ".")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "root")
            revision = git(source, "rev-parse", "HEAD")
            git(mirrors / "owner/repo.git", "fetch", str(source), f"{revision}:{revision}")
            pinned = discovery.PinnedRepository("owner/repo", revision, mirrors)
            try:
                rows, diagnostics, names = discovery.resolve_listings("owner/repo", revision,
                    [listing("Root Name", "root-slug"), listing()], pinned, WorkBudget(10))
            finally:
                pinned.close()
            self.assertEqual({r["path"] for r in rows}, {"", "skills/demo"})
            self.assertEqual(names["Root Name"], [""])
            self.assertEqual(diagnostics, [])

    def test_duplicate_declared_name_is_never_first_match_and_symlink_not_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, selection = fixture_repository(root)
            source = root / "source"
            (source / "duplicate").mkdir()
            (source / "duplicate/SKILL.md").write_text("---\nname: demo\n---\n")
            (source / "alias").mkdir()
            (source / "alias/SKILL.md").symlink_to("../skills/demo/SKILL.md")
            git(source, "add", ".")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "duplicate")
            revision = git(source, "rev-parse", "HEAD")
            git(mirrors / "owner/repo.git", "fetch", str(source), f"{revision}:{revision}")
            pinned = discovery.PinnedRepository("owner/repo", revision, mirrors)
            try:
                rows, diagnostics, _ = discovery.resolve_listings("owner/repo", revision, [listing()], pinned, WorkBudget(10))
            finally:
                pinned.close()
            self.assertEqual(rows, [])
            self.assertEqual([d["code"] for d in diagnostics], ["ambiguous_name", "invalid_skill_documents"])
            self.assertEqual(diagnostics[0]["candidates"], ["duplicate", "skills/demo"])
            self.assertEqual(diagnostics[0]["count"], 2)

    def test_exact_path_resolves_duplicate_and_ignores_unrelated_oversized_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, _ = fixture_repository(root)
            source = root / "source"
            (source / "duplicate").mkdir()
            (source / "duplicate/SKILL.md").write_text("---\nname: demo\n---\n")
            (source / "oversized").mkdir()
            (source / "oversized/SKILL.md").write_bytes(b"x" * (discovery.MAX_DOCUMENT_BYTES + 1))
            git(source, "add", ".")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "duplicate")
            revision = git(source, "rev-parse", "HEAD")
            git(mirrors / "owner/repo.git", "fetch", str(source), f"{revision}:{revision}")
            pinned = discovery.PinnedRepository("owner/repo", revision, mirrors)
            try:
                for path in ("skills/demo", "skills/demo/SKILL.md"):
                    rows, diagnostics, _ = discovery.resolve_listings("owner/repo", revision,
                        [listing() | {"path": path}], pinned, WorkBudget(10))
                    self.assertEqual([row["path"] for row in rows], ["skills/demo"])
                    self.assertEqual(diagnostics, [])
            finally:
                pinned.close()

    def test_exact_path_name_mismatch_missing_file_or_symlink_never_falls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirrors, _ = fixture_repository(root)
            source = root / "source"
            (source / "other").mkdir()
            (source / "other/SKILL.md").write_text("---\nname: something-else\n---\n")
            (source / "alias").mkdir()
            (source / "alias/SKILL.md").symlink_to("../skills/demo/SKILL.md")
            git(source, "add", ".")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "paths")
            revision = git(source, "rev-parse", "HEAD")
            git(mirrors / "owner/repo.git", "fetch", str(source), f"{revision}:{revision}")
            pinned = discovery.PinnedRepository("owner/repo", revision, mirrors)
            try:
                for path, expected in (("other", "declared_name_mismatch"), ("missing", "skill_path_not_found"),
                                       ("alias", "invalid_skill_document")):
                    with self.subTest(path=path):
                        rows, diagnostics, _ = discovery.resolve_listings("owner/repo", revision,
                            [listing() | {"path": path}], pinned, WorkBudget(10))
                        self.assertEqual(rows, [])
                        self.assertEqual(diagnostics[0]["code"], expected)
            finally:
                pinned.close()

    def test_unsafe_explicit_paths_are_rejected_before_git_reads(self):
        for path in ("../skills/demo", "/skills/demo", "skills/./demo", "skills/demo/", "https://example.test/SKILL.md"):
            with self.subTest(path=path), mock.patch.object(discovery, "skill_documents") as documents:
                rows, diagnostics, _ = discovery.resolve_listings("owner/repo", "a" * 40,
                    [listing() | {"path": path}], mock.Mock(), WorkBudget(10))
                documents.assert_not_called()
                self.assertEqual(rows, [])
                self.assertEqual(diagnostics[0]["code"], "invalid_skill_path")

    def test_catalog_path_cannot_claim_a_different_repository(self):
        with mock.patch.object(discovery, "skill_documents") as documents:
            rows, diagnostics, _ = discovery.resolve_listings("owner/repo", "a" * 40,
                [listing(source="other/repo") | {"path": "skills/demo"}], mock.Mock(), WorkBudget(10))
        documents.assert_not_called()
        self.assertEqual(rows, [])
        self.assertEqual(diagnostics[0]["code"], "source_identity_mismatch")


class DiscoveryTests(unittest.TestCase):
    def state(self, revision="a" * 40):
        return {"owner/repo": {"available": True, "repository": "owner/repo", "revision": revision}}

    def run_discovery(self, rows, **kwargs):
        return discovery.discover(rows, kwargs.pop("catalog", catalog()), mock.Mock(token=None), WorkBudget(10),
                                  source_commit="b" * 40, **kwargs)

    def removed_exact_root(self, root):
        mirrors, original = fixture_repository(root)
        rows = [listing() | {"path": "skills/demo"}]
        with mock.patch.object(discovery, "repository_states", return_value=self.state(original["sources"][0]["revision"])):
            previous, summary = self.run_discovery(rows, mirror_root=mirrors)
        source = root / "source"
        git(source, "rm", "skills/demo/SKILL.md")
        git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "remove skill")
        revision = git(source, "rev-parse", "HEAD")
        git(mirrors / "owner/repo.git", "fetch", str(source), f"{revision}:{revision}")
        return rows, mirrors, revision, previous, summary

    def test_removed_exact_root_preserves_report_history_and_pending_current_coverage(self):
        from scripts import skillspector_coverage_v3 as coverage
        from tests.test_skillspector_coverage_v3 import bundle, record, worker
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows, mirrors, revision, previous, prior_summary = self.removed_exact_root(root)
            with mock.patch.object(discovery, "repository_states", return_value=self.state(revision)), \
                 mock.patch.object(discovery, "PinnedRepository", wraps=discovery.PinnedRepository) as acquired:
                selection, summary = self.run_discovery(rows, mirror_root=mirrors,
                    previous=previous["sources"], previous_summary=prior_summary)
            self.assertEqual([call.args[1] for call in acquired.call_args_list], [revision])
            old = previous["sources"][0]
            self.assertEqual(selection, previous)
            self.assertEqual(summary["source_states"][0], {"id": old["id"], "repository": "owner/repo",
                "state": "historical", "current": False, "reason": "skill_removed", "revision": revision,
                "path": "skills/demo", "selected_ids": [old["id"]], "candidates": []})
            self.assertEqual(summary["diagnostic_counts"], {"skill_removed": 1})
            self.assertFalse(summary["complete"])
            validate_discovery_summary(summary, selection, "b" * 40)
            prior = bundle(root / "prior-report", previous, [record(old)])
            # Worker fixtures use the immutable test commit c; the discovery
            # identity is independent of either scanned source revision.
            summary["source_commit"] = "c" * 40
            coverage.merge_reports(selection, prior, [worker(selection)], source_commit="c" * 40,
                output_dir=root / "report", discovery_summary=summary)
            published = coverage.read_bundle(root / "report")
            self.assertEqual(published["records"][old["id"]]["source"], prior["records"][old["id"]]["source"])
            self.assertEqual(published["records"][old["id"]]["freshness"], "historical")
            self.assertEqual(published["manifest"]["coverage"], {"selected": 1, "reported": 1,
                "pending": 1, "complete": 0, "partial": 0, "error": 0, "stale": 1})
            # The validated prior removal proof binds this exact examined pin.
            # Retain it even if the old commit is no longer fetchable.
            with mock.patch.object(discovery, "repository_states", return_value=self.state(revision)), \
                 mock.patch.object(discovery, "PinnedRepository", side_effect=OSError("old commit unavailable")) as acquired:
                again, current_summary = self.run_discovery(rows, mirror_root=mirrors,
                    previous=selection["sources"], previous_summary=summary)
            acquired.assert_not_called()
            self.assertEqual(again, previous)
            self.assertEqual(current_summary["source_states"][0]["reason"], "skill_removed")
            # The same proof cannot label a different newly examined revision.
            for target, path in (("e" * 40, "skills/demo"), (revision, "skills/another")):
                _, removed = discovery.previous_existence_proofs(selection["sources"], summary)
                self.assertNotIn((old["id"], discovery.subject_key(old), target, path), removed)

    def test_removed_exact_root_can_be_proven_by_old_pinned_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows, mirrors, revision, previous, _ = self.removed_exact_root(Path(temporary))
            with mock.patch.object(discovery, "repository_states", return_value=self.state(revision)):
                selection, summary = self.run_discovery(rows, mirror_root=mirrors, previous=previous["sources"])
            self.assertEqual(selection, previous)
            self.assertEqual(summary["source_states"][0]["reason"], "skill_removed")

    def test_fresh_bad_path_and_unverified_old_seed_are_not_reported_as_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows, mirrors, revision, previous, prior_summary = self.removed_exact_root(Path(temporary))
            for earlier, summary in (([], None),
                    ([previous["sources"][0] | {"path": "skills/never-present"}], prior_summary)):
                with self.subTest(previous=earlier), \
                     mock.patch.object(discovery, "repository_states", return_value=self.state(revision)):
                    path = earlier[0]["path"] if earlier else "skills/demo"
                    selection, current = self.run_discovery([rows[0] | {"path": path}], mirror_root=mirrors,
                        previous=earlier, previous_summary=summary)
                self.assertEqual(selection["sources"], [])
                self.assertEqual(current["source_states"][0]["state"], "unresolved")
                self.assertEqual(current["source_states"][0]["reason"], "skill_path_not_found")

    def test_unavailable_repository_does_not_claim_verified_skill_was_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows, mirrors, _, previous, prior_summary = self.removed_exact_root(Path(temporary))
            with mock.patch.object(discovery, "repository_states", return_value={}), \
                 mock.patch.object(discovery, "PinnedRepository") as pinned:
                selection, summary = self.run_discovery(rows, mirror_root=mirrors,
                    previous=previous["sources"], previous_summary=prior_summary)
            pinned.assert_not_called()
            self.assertEqual(selection, previous)
            state = summary["source_states"][0]
            self.assertEqual(state["state"], "historical")
            self.assertEqual(state["reason"], "repository_unavailable")
            self.assertIsNone(state["revision"])

    def test_missing_repo_and_incomplete_catalog_preserve_historical_selection(self):
        previous = [item(id="owner/repo/demo"), item(id="other/repo/demo", repository="other/repo")]
        with mock.patch.object(discovery, "repository_states", return_value={}):
            selection, summary = self.run_discovery([listing()], previous=previous, catalog=catalog(False))
        self.assertEqual(selection["sources"], previous)
        self.assertEqual(summary["repositories_retained"], 2)
        self.assertFalse(summary["complete"])

    def test_transient_acquisition_error_retains_previous_and_not_fake_success(self):
        previous = [item(id="owner/repo/demo")]
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository", side_effect=OSError("temporary")):
            selection, summary = self.run_discovery([listing()], previous=previous)
        self.assertEqual(selection["sources"], previous)
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["diagnostic_counts"]["repository_acquisition_failed"], 1)
        state = summary["source_states"][0]
        self.assertEqual(state["state"], "historical")
        self.assertFalse(state["current"])
        self.assertEqual(state["selected_ids"], [previous[0]["id"]])
        validate_discovery_summary(summary, selection, "b" * 40)

    def test_cache_requires_both_exact_pin_and_candidate_digest(self):
        row = item(id="owner/repo/demo")
        hint_digest = discovery.listing_hints_digest([listing()])
        prior = {"resolution_cache": {"owner/repo": {"revision": row["revision"], "hints_digest": hint_digest,
                 "selected_ids": [row["id"]], "diagnostics": []}}}
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository") as pinned:
            selection, summary = self.run_discovery([listing()], previous=[row], previous_summary=prior)
            pinned.assert_not_called()
        self.assertEqual(selection["sources"], [row])
        self.assertTrue(summary["complete"])
        with mock.patch.object(discovery, "repository_states", return_value=self.state("c" * 40)), \
             mock.patch.object(discovery, "PinnedRepository", side_effect=OSError()) as pinned:
            self.run_discovery([listing()], previous=[row], previous_summary=prior)
            pinned.assert_called_once()

    def test_resolver_upgrade_revisits_cached_ambiguity_to_retain_candidates(self):
        prior = {"resolution_cache": {"owner/repo": {"revision": "a" * 40,
            "hints_digest": discovery.sha256_digest(discovery.canonical_json([listing()])),
            "selected_ids": [], "diagnostics": [{"code": "ambiguous_name", "repository": "owner/repo", "id": "owner/repo/demo"}]}}}
        issue = {"code": "ambiguous_name", "repository": "owner/repo", "id": "owner/repo/demo",
                 "candidates": ["first", "second"], "count": 2}
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository") as pinned, \
             mock.patch.object(discovery, "resolve_listings", return_value=([], [issue], {})):
            selection, summary = self.run_discovery([listing()], previous_summary=prior)
            pinned.assert_called_once()
        self.assertEqual(summary["source_states"][0]["candidates"], ["first", "second"])
        validate_discovery_summary(summary, selection, "b" * 40)

    def test_successful_missing_name_does_not_retain_old_mapping(self):
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([], [{"code": "skill_not_found"}], {})):
            selection, summary = self.run_discovery([listing()], previous=[item(id="owner/repo/demo")])
        self.assertEqual(selection["sources"], [])
        self.assertEqual(summary["diagnostic_counts"], {"skill_not_found": 1})

    def test_reviewed_subjects_deduplicate_generated_roots_and_publishers_stay_unsupported(self):
        row = item(id="reviewed/demo")
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([item(id="owner/repo/demo")], [], {})):
            selection, summary = self.run_discovery([listing(), listing(source="docs.example.com")], reviewed=[row])
        self.assertEqual(selection["sources"], [item(id="owner/repo/demo")])
        self.assertEqual(summary["diagnostic_counts"], {"unsupported_source": 1})

    def test_current_exact_name_match_supersedes_reviewed_old_revision(self):
        old = item(id="legacy/demo", revision="c" * 40)
        current = item(id="owner/repo/demo")
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([current], [], {})):
            selection, _ = self.run_discovery([listing()], reviewed=[old])
        self.assertEqual(selection["sources"], [current])

    def test_dry_run_page_bound_is_exposed_without_claiming_full_catalog(self):
        selection, summary = self.run_discovery([], catalog=catalog(False), reviewed=[item()], max_pages=1)
        self.assertEqual(summary["bounds"]["pages"], 1)
        self.assertFalse(summary["complete"])

    def test_source_validation_rejects_traversal_and_plugin_escape(self):
        self.assertFalse(discovery.valid_source(item(path="../outside")))
        self.assertFalse(discovery.valid_source(item(kind="plugin_skill", plugin_path="plugins/demo", path="skills/demo")))

    def test_transient_renamed_repository_keeps_canonical_previous_subject(self):
        previous = item(id="owner/repo/demo", repository="canonical/renamed")
        state = {"owner/repo": {"available": True, "repository": "canonical/renamed", "revision": "a" * 40}}
        with mock.patch.object(discovery, "repository_states", return_value=state), \
             mock.patch.object(discovery, "PinnedRepository", side_effect=OSError("temporary")):
            selection, summary = self.run_discovery([listing()], previous=[previous])
        self.assertEqual(selection["sources"], [previous])
        self.assertEqual(summary["repositories_retained"], 1)

    def test_explicit_published_plugin_replaces_historical_revision_only_on_success(self):
        old = item(id="reviewed/demo", kind="plugin_skill", path="plugins/current/skills/demo",
                   plugin_path="plugins/current", revision="c" * 40)
        plugin = {"name": "current", "components": ["skills"], "source": {
            "repository": "owner/repo", "revision": "d" * 40, "path": "plugins/current"}}
        with mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "skill_documents", return_value=({"demo": [old["path"]]}, [])):
            selection, _ = self.run_discovery([], reviewed=[old], plugins=[plugin])
        self.assertEqual(len(selection["sources"]), 1)
        self.assertEqual(selection["sources"][0]["revision"], "d" * 40)
        with mock.patch.object(discovery, "PinnedRepository", side_effect=OSError("temporary")):
            selection, summary = self.run_discovery([], reviewed=[old], plugins=[plugin])
        self.assertEqual(selection["sources"], [old])
        self.assertEqual(summary["diagnostic_counts"]["plugin_acquisition_failed"], 1)

    def test_plugin_enumeration_ignores_unrelated_and_nested_document_limits(self):
        for plugin_path in ("", "plugins/current"):
            for document_limit in (1, discovery.MAX_DOCUMENTS):
                with self.subTest(plugin_path=plugin_path, document_limit=document_limit), \
                     tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    mirrors, _ = fixture_repository(root)
                    source = root / "source"
                    skill_path = (plugin_path + "/" if plugin_path else "") + "skills/demo"
                    skill = source / skill_path
                    skill.mkdir(parents=True, exist_ok=True)
                    (skill / "SKILL.md").write_text("---\nname: demo\n---\nRead helpers/note.txt.\n")
                    (skill / "helpers").mkdir()
                    (skill / "helpers/note.txt").write_text("inert helper data\n")
                    # Neither another package nor a nested reference document
                    # is a root installed by this plugin. Do not hydrate them.
                    (skill / "helpers/SKILL.md").write_bytes(b"x" * (discovery.MAX_DOCUMENT_BYTES + 1))
                    (source / "unrelated").mkdir()
                    (source / "unrelated/SKILL.md").write_bytes(b"x" * (discovery.MAX_DOCUMENT_BYTES + 1))
                    git(source, "add", ".")
                    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "package")
                    revision = git(source, "rev-parse", "HEAD")
                    git(mirrors / "owner/repo.git", "fetch", str(source), f"{revision}:{revision}")
                    plugin = {"name": "current", "components": ["skills"], "source": {
                        "repository": "owner/repo", "revision": revision, "path": plugin_path}}
                    with mock.patch.object(discovery, "MAX_DOCUMENTS", document_limit), \
                         mock.patch.object(discovery, "read_blobs", wraps=discovery.read_blobs) as read:
                        selection, summary = self.run_discovery([], plugins=[plugin], mirror_root=mirrors)
                    expected = item(id="plugin:current/demo", kind="plugin_skill", revision=revision,
                                    path=skill_path, plugin_path=plugin_path)
                    self.assertEqual(selection["sources"], [expected])
                    self.assertEqual(summary["plugin_states"][0]["state"], "resolved")
                    self.assertEqual(summary["plugin_states"][0]["skills_total"], 1)
                    self.assertEqual(len(read.call_args.args[1]), 1)
                    validate_selection(selection)
                    validate_discovery_summary(summary, selection, "b" * 40)

    def test_subject_identity_is_repository_case_insensitive(self):
        self.assertEqual(discovery.subject_key(item(repository="Owner/Repo")), discovery.subject_key(item()))

    def test_equivalent_listing_aliases_keep_both_card_mappings_after_deduplication(self):
        first, second = item(id="owner/repo/first"), item(id="owner/repo/second")
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([first, second], [], {})):
            selection, summary = self.run_discovery([listing(slug="first"), listing(slug="second")])
        self.assertEqual(selection["sources"], [first])
        self.assertEqual([state["selected_ids"] for state in summary["source_states"]], [[first["id"]], [first["id"]]])
        self.assertEqual(summary["catalog_coverage"]["resolved"], 2)
        self.assertNotIn("owner/repo", summary["resolution_cache"])
        validate_discovery_summary(summary, selection, "b" * 40)

    def test_failed_refresh_never_regresses_current_to_older_reviewed_bootstrap(self):
        old = item(id="owner/repo/demo", revision="c" * 40)
        previous = item(id="owner/repo/demo", revision="d" * 40)
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository", side_effect=OSError("temporary")):
            selection, _ = self.run_discovery([listing()], previous=[previous], reviewed=[old])
        self.assertEqual(selection["sources"], [previous])

    def test_renamed_repo_fetches_canonical_but_reports_provider_join_identity(self):
        state = {"owner/repo": {"available": True, "repository": "canonical/renamed", "revision": "a" * 40}}
        with mock.patch.object(discovery, "repository_states", return_value=state), \
             mock.patch.object(discovery, "PinnedRepository") as pinned, \
             mock.patch.object(discovery, "resolve_listings", return_value=([item(id="owner/repo/demo")], [], {})) as resolve:
            selection, summary = self.run_discovery([listing()])
        self.assertEqual(pinned.call_args.args[0], "canonical/renamed")
        self.assertEqual(resolve.call_args.args[0], "owner/repo")
        self.assertEqual(selection["sources"][0]["repository"], "owner/repo")
        self.assertEqual(summary["repository_aliases"], [{"repository": "owner/repo",
            "canonical_repository": "canonical/renamed", "revision": "a" * 40}])
        validate_discovery_summary(summary, selection, "b" * 40)

    def test_non_skill_plugin_is_not_waiting_for_a_scanner(self):
        plugin = {"name": "mcp-only", "components": ["mcp"], "source": {
            "repository": "owner/repo", "revision": "d" * 40, "path": "plugins/mcp-only"}}
        with mock.patch.object(discovery, "PinnedRepository") as pinned:
            selection, summary = self.run_discovery([], plugins=[plugin])
            pinned.assert_not_called()
        self.assertEqual(summary["plugin_states"], [{"id": "mcp-only", "repository": "owner/repo",
            "plugin_path": "plugins/mcp-only", "revision": "d" * 40, "state": "not_applicable",
            "reason": "plugin_has_no_skills", "skills_total": 0, "selected_ids": []}])
        validate_discovery_summary(summary, selection, "b" * 40)
        validate_selection(selection)

    def test_plugin_no_longer_declares_skills_does_not_resurrect_historical_work(self):
        old = item(id="old/demo", kind="plugin_skill", path="plugins/current/skills/demo", plugin_path="plugins/current")
        plugin = {"name": "current", "components": ["mcp"], "source": {
            "repository": "owner/repo", "revision": "d" * 40, "path": "plugins/current"}}
        with mock.patch.object(discovery, "PinnedRepository") as pinned:
            selection, summary = self.run_discovery([], previous=[old], reviewed=[old], plugins=[plugin], catalog=catalog(False))
            pinned.assert_not_called()
        self.assertEqual(selection["sources"], [])
        self.assertEqual(summary["plugin_states"][0]["state"], "not_applicable")
        validate_selection(selection)
        validate_discovery_summary(summary, selection, "b" * 40)

    def test_unresolved_and_unsupported_cards_publish_separate_catalog_coverage(self):
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([], [{"code": "ambiguous_name",
                 "repository": "owner/repo", "id": "owner/repo/demo", "candidates": ["first", "second"], "count": 2}], {})):
            selection, summary = self.run_discovery([listing(), listing(source="docs.example.com")])
        self.assertEqual(summary["catalog_coverage"], {"observed": 2, "resolved": 0, "historical": 0,
            "unresolved": 1, "unavailable": 0, "unsupported": 1})
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["source_states"][0]["candidates"], ["first", "second"])
        validate_discovery_summary(summary, selection, "b" * 40)
        summary["catalog_coverage"]["resolved"] = 1
        with self.assertRaises(PublicationError):
            validate_discovery_summary(summary, selection, "b" * 40)

    def test_unavailable_signed_directory_retains_previous_plugin_evidence_as_historical(self):
        old = item(id="plugin:bridge/demo", kind="plugin_skill", path="plugins/current/skills/demo", plugin_path="plugins/current")
        old_state = {"id": "bridge", "repository": "owner/repo", "plugin_path": "plugins/current",
                     "revision": "a" * 40, "state": "resolved", "reason": None, "skills_total": 1, "selected_ids": [old["id"]]}
        metadata = catalog() | {"directory": {"state": "unavailable", "reason": "directory_acquisition_failed",
            "sequence": None, "source_commit": None, "snapshot_digest": None}}
        selection, summary = self.run_discovery([], previous=[old], previous_summary={"plugin_states": [old_state]}, catalog=metadata)
        self.assertEqual(selection["sources"], [old])
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["plugin_states"][0]["state"], "unavailable")
        self.assertEqual(summary["source_states"][0]["state"], "historical")
        self.assertFalse(summary["source_states"][0]["current"])
        validate_discovery_summary(summary, selection, "b" * 40)

    def test_changed_revision_with_failed_refresh_is_explicitly_historical(self):
        previous = [item(id="owner/repo/demo", revision="c" * 40)]
        with mock.patch.object(discovery, "repository_states", return_value=self.state("d" * 40)), \
             mock.patch.object(discovery, "PinnedRepository", side_effect=OSError("temporary")):
            selection, summary = self.run_discovery([listing()], previous=previous)
        self.assertEqual(selection["sources"][0]["revision"], "c" * 40)
        self.assertEqual(summary["source_states"][0]["revision"], "d" * 40)
        self.assertEqual(summary["catalog_coverage"]["historical"], 1)
        validate_discovery_summary(summary, selection, "b" * 40)
        summary["source_states"][0].update(current=True, state="resolved", reason=None, path="skills/demo")
        summary["catalog_coverage"].update(historical=0, resolved=1)
        with self.assertRaises(PublicationError):
            validate_discovery_summary(summary, selection, "b" * 40)

    def test_moved_root_with_new_slug_supersedes_same_exact_declared_name(self):
        old = item(id="legacy/demo", revision="c" * 40)
        current = item(id="owner/repo/new-slug", path="new-location/demo")
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([current], [], {})):
            selection, _ = self.run_discovery([listing("demo", "new-slug")], reviewed=[old])
        self.assertEqual(selection["sources"], [current])

    def test_reviewed_successor_and_popularity_win_before_alphabetical_cold_tail_and_cap(self):
        old = item(id="legacy/reviewed", path="skills/reviewed", revision="c" * 40)
        reviewed = item(id="owner/repo/z-reviewed", path="skills/reviewed")
        popular = item(id="owner/repo/z-popular", path="skills/popular")
        tail = item(id="owner/repo/a-tail", path="skills/tail")
        rows = [listing("popular", "z-popular"), listing("tail", "a-tail"), listing("reviewed", "z-reviewed")]
        with mock.patch.object(discovery, "repository_states", return_value=self.state()), \
             mock.patch.object(discovery, "PinnedRepository"), \
             mock.patch.object(discovery, "resolve_listings", return_value=([tail, popular, reviewed], [], {})):
            selection, _ = self.run_discovery(rows, reviewed=[old])
            self.assertEqual(selection["sources"], [reviewed, popular, tail])
            with mock.patch.object(discovery, "MAX_ROOTS", 2):
                capped, summary = self.run_discovery(rows, reviewed=[old])
        self.assertEqual(capped["sources"], [reviewed, popular])
        self.assertTrue(summary["selection_truncated"])
        self.assertNotIn("owner/repo", summary["resolution_cache"])


if __name__ == "__main__":
    unittest.main()
