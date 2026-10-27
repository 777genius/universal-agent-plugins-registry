from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import discover_skillspector_sources as discovery
from scripts.discovery_checkpoint import WorkBudget
from tests.test_skillspector_reports import fixture_repository, git, item


def listing(name="demo", slug="demo", source="owner/repo"):
    return {"source": source, "skillId": slug, "name": name}


def catalog(complete=True):
    return {"complete": complete, "pages": 1, "provider_total": 1, "error": None}


class CatalogTests(unittest.TestCase):
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


class DocumentTests(unittest.TestCase):
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


class DiscoveryTests(unittest.TestCase):
    def state(self, revision="a" * 40):
        return {"owner/repo": {"available": True, "repository": "owner/repo", "revision": revision}}

    def run_discovery(self, rows, **kwargs):
        return discovery.discover(rows, kwargs.pop("catalog", catalog()), mock.Mock(token=None), WorkBudget(10),
                                  source_commit="b" * 40, **kwargs)

    def test_missing_repo_and_incomplete_catalog_preserve_historical_selection(self):
        previous = [item(id="owner/repo/demo"), item(id="other/repo/demo", repository="other/repo")]
        with mock.patch.object(discovery, "repository_states", return_value={}):
            selection, summary = self.run_discovery([listing()], previous=previous, catalog=catalog(False))
        self.assertEqual(selection["sources"], sorted(previous, key=lambda s: s["id"]))
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

    def test_cache_requires_both_exact_pin_and_candidate_digest(self):
        row = item(id="owner/repo/demo")
        hint_digest = discovery.sha256_digest(discovery.canonical_json([listing()]))
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


if __name__ == "__main__":
    unittest.main()
