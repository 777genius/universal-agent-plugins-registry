"""Fail-closed tests for the UNSIGNED modern Pi v1 candidate staging boundary."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from directory_publication import PublicationError
from pi_modern_feed_candidate import (main, proposed_source, read_evidence_object,
                                      require_committed_directory_source,
                                      require_complete_source_eligibility,
                                      require_unsigned_preproduction_eligibility,
                                      validate_platform_report, write_unsigned_candidate)

HEAD = "a" * 40
DIGEST = "sha256:" + "b" * 64


def source_case(name: str, status: str = "active") -> dict:
    return {
        "distribution": name, "distribution_status": status, "release_sequence": 1,
        "source": f"github:owner/repo@{HEAD}//plugins/tool",
        "revision": HEAD, "tree_digest": DIGEST, "manifest_name": "tool",
        "components": ["mcp"],
    }


def receipt(source: dict, scope: str, status: str) -> dict:
    value = {**source, "scope": scope, "status": status}
    if status == "planned":
        value["exit_code"] = 0
        value["planned_actions"] = [{
            "client_id": "pi", "action": "install", "alias": source["manifest_name"],
            "revision": source["revision"], "package_digest": source["tree_digest"],
        }]
    elif status == "refused":
        value["exit_code"] = 1
        value["diagnostic"] = (
            "agentplugins: dependency conflict for directory:777genius/hubspot-crm: "
            "marketing-kit version 0.1.0\n"
        )
    return value


class ModernPiEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = source_case("owner/tool")
        self.marketing = source_case("777genius/marketing-kit")
        self.suspended = source_case("owner/suspended", "suspended")
        self.sources = [self.tool, self.marketing, self.suspended]
        self.report = {
            "schema_version": 1, "kind": "pi-direct-source-planning",
            "source_commit": HEAD, "runner_os": "Linux",
            "cli_version": "0.1.102", "signed_pi_policy_published": False,
            "runtime_claims": False, "account_authentication": "not_tested",
            "scopes": ["user", "project"], "active_policy_count": 3,
            "results": [
                *[receipt(self.tool, s, "planned") for s in ("user", "project")],
                *[receipt(self.marketing, s, "refused") for s in ("user", "project")],
                *[receipt(self.suspended, s, "not_eligible") for s in ("user", "project")],
            ],
        }

    def test_source_plans_cannot_open_nonpreproduction_path_even_if_all_planned(self) -> None:
        # An all-green dry-run/planning report is never a signed managed
        # install receipt. Refuse the no-flag path *before* Git, file writes,
        # source reviews, or policy validation can run.
        arguments = [
            "pi_modern_feed_candidate.py", "--source-head", HEAD,
            "--review", "unused-review.json", "--report", "linux=unused.json",
            "--report", "macos=unused.json", "--report", "windows=unused.json",
            "--output", "unused-candidate.json",
        ]
        with mock.patch.object(sys, "argv", arguments):
            with mock.patch("pi_modern_feed_candidate.require_exact_checkout") as checkout:
                with self.assertRaisesRegex(RuntimeError, "--preproduction-only"):
                    main()
                checkout.assert_not_called()

    def test_unsigned_candidate_output_is_exclusive_and_cannot_clobber(self) -> None:
        # A path must be created once, never overwritten by a later candidate.
        # This also covers the path appearing just before the write, unlike
        # an exists() check followed by write_text().
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review" / "candidate.json"
            candidate = {"schema_version": 1, "kind": "unsigned-review-only"}
            write_unsigned_candidate(path, candidate)
            first_bytes = path.read_bytes()
            self.assertEqual(json.loads(first_bytes), candidate)
            with self.assertRaises(FileExistsError):
                write_unsigned_candidate(path, {"schema_version": 2})
            self.assertEqual(path.read_bytes(), first_bytes)

            path.unlink()
            path.write_bytes(b"do not overwrite this unrelated artifact")
            with self.assertRaises(FileExistsError):
                write_unsigned_candidate(path, candidate)
            self.assertEqual(path.read_bytes(), b"do not overwrite this unrelated artifact")

    def test_competing_creation_immediately_before_open_preserves_bytes(self) -> None:
        # Deterministically inject a different writer at the last open call,
        # not before the validation. The output must never be truncated.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "candidate.json"
            path.parent.mkdir(mode=0o700)
            unexpected = b"independent writer's output"
            candidate = {"schema_version": 1}
            if os.name == "posix":
                real_open = os.open

                def race(name, flags, mode=0o777, *, dir_fd=None):
                    if name == path.name and dir_fd is not None:
                        path.write_bytes(unexpected)
                    return real_open(name, flags, mode, dir_fd=dir_fd)

                patch = mock.patch("pi_modern_feed_candidate.os.open", side_effect=race)
            else:
                from pi_modern_feed_candidate import open_windows_exclusive_nofollow
                real_open = open_windows_exclusive_nofollow

                def race_windows(target):
                    if target == path:
                        path.write_bytes(unexpected)
                    return real_open(target)

                patch = mock.patch("pi_modern_feed_candidate.open_windows_exclusive_nofollow",
                                  side_effect=race_windows)
            with patch, self.assertRaises(FileExistsError):
                write_unsigned_candidate(path, candidate)
            self.assertEqual(path.read_bytes(), unexpected)

    def test_candidate_output_symlink_cannot_redirect_or_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            private.mkdir(mode=0o700)
            path = private / "candidate.json"
            target = private / "foreign.json"
            target.write_bytes(b"keep existing foreign bytes")
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable on this runner: {error}")
            with self.assertRaises((FileExistsError, OSError)):
                write_unsigned_candidate(path, {"schema_version": 1})
            self.assertEqual(target.read_bytes(), b"keep existing foreign bytes")
            path.unlink()
            path.symlink_to(private / "missing.json")
            with self.assertRaises((FileExistsError, OSError)):
                write_unsigned_candidate(path, {"schema_version": 1})
            self.assertFalse((private / "missing.json").exists())

    def test_junction_classification_rejects_parent_without_creating_output(self) -> None:
        # Simulate Path.is_junction on all platforms, including older Python.
        # A junction may not be reported by Path.is_symlink on Windows.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "candidate.json"
            path.parent.mkdir(mode=0o700)
            with mock.patch.object(Path, "is_junction", return_value=True, create=True):
                with self.assertRaisesRegex(RuntimeError, "symlink or junction"):
                    write_unsigned_candidate(path, {"schema_version": 1})
            self.assertFalse(path.exists())

    @unittest.skipUnless(os.name == "nt", "native Windows NTFS junction")
    def test_native_windows_parent_junction_cannot_redirect_output(self) -> None:
        # This is a genuine NTFS junction, not a mocked final-file symlink.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "private-real"
            real_parent.mkdir()
            junction = root / "private-junction"
            subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(real_parent)],
                check=True, capture_output=True, text=True,
            )
            self.assertTrue(junction.is_junction())
            with self.assertRaisesRegex(RuntimeError, "symlink or junction"):
                write_unsigned_candidate(junction / "candidate.json", {"schema_version": 1})
            self.assertFalse((real_parent / "candidate.json").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX directory-descriptor protection")
    def test_parent_symlink_swap_cannot_redirect_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            private.mkdir(mode=0o700)
            path = private / "candidate.json"
            moved = Path(directory) / "private-original"
            redirected = Path(directory) / "unexpected-repository"
            redirected.mkdir(mode=0o700)
            real_open = os.open

            def swap_parent(name, flags, mode=0o777, *, dir_fd=None):
                if name == path.name and dir_fd is not None:
                    private.rename(moved)
                    private.symlink_to(redirected, target_is_directory=True)
                return real_open(name, flags, mode, dir_fd=dir_fd)

            with mock.patch("pi_modern_feed_candidate.os.open", side_effect=swap_parent):
                write_unsigned_candidate(path, {"schema_version": 1})
            self.assertEqual(json.loads((moved / path.name).read_text()), {"schema_version": 1})
            self.assertFalse((redirected / path.name).exists())

    @unittest.skipUnless(os.name == "posix", "POSIX private directory permissions")
    def test_shared_parent_does_not_qualify_as_private_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "shared"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "owner-private"):
                write_unsigned_candidate(parent / "candidate.json", {"schema_version": 1})
            self.assertFalse((parent / "candidate.json").exists())

    def test_candidate_source_must_equal_committed_directory_bytes(self) -> None:
        with mock.patch("pi_modern_feed_candidate.subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, b"committed")) as read:
            require_committed_directory_source(HEAD, b"committed")
            with self.assertRaisesRegex(RuntimeError, "working Directory source differs"):
                require_committed_directory_source(HEAD, b"uncommitted")
            self.assertEqual(read.call_args.args[0],
                             ["git", "show", f"{HEAD}:registry/directory.json"])
            self.assertTrue(read.call_args.kwargs["check"])

    def test_duplicate_json_keys_cannot_reinterpret_ci_or_auth_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            for body in (
                '{"runner_os":"Linux","runner_os":"Windows"}',
                '{"authentication":"required","authentication":"not_required"}',
            ):
                path.write_text(body, encoding="utf-8")
                with self.subTest(body=body), self.assertRaisesRegex(
                    PublicationError, "duplicate JSON key"
                ):
                    read_evidence_object(path)

    def test_review_and_ci_evidence_must_be_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected a JSON object"):
                read_evidence_object(path)

    def test_known_marketing_refusal_remains_explicit_failure(self) -> None:
        self.assertEqual(validate_platform_report(self.report, "linux", HEAD, self.sources),
                         (2, 2))

    def test_source_refusal_cannot_stage_unsigned_modern_candidate(self) -> None:
        # Reviewed, exact-head source evidence is not enough if the real CLI
        # still refuses Marketing Kit's signed HubSpot dependency closure.
        counts = {"linux": (2, 2), "macos": (2, 2), "windows": (2, 2)}
        with self.assertRaisesRegex(RuntimeError, "zero refused saved dependency plans"):
            require_complete_source_eligibility(counts, expected_eligible=4)

    def test_all_os_source_plans_can_reach_review_stage(self) -> None:
        # This helper is only a source-planning gate, NOT signed entitlement.
        require_complete_source_eligibility(
            {"linux": (4, 0), "macos": (4, 0), "windows": (4, 0)}, expected_eligible=4
        )

    def test_unsigned_review_gate_cannot_accept_partial_or_spoofed_os_counts(self) -> None:
        for counts in (
            {"linux": (4, 0)},
            {"linux": (4, 0), "macos": (4, 0), "windows": (2, 0)},
            {"linux": (4, 0), "macos": (4, 0), "windows": (4, 2)},
            {"linux": (True, 0), "macos": (True, 0), "windows": (True, 0)},
            {"linux": (4, False), "macos": (4, False), "windows": (4, False)},
            {"linux": (-1, 0), "macos": (-1, 0), "windows": (-1, 0)},
        ):
            with self.subTest(counts=counts), self.assertRaisesRegex(
                RuntimeError, "complete identical 3-OS"
            ):
                require_complete_source_eligibility(counts, expected_eligible=4)

    def test_preproduction_gate_rejects_boolean_or_negative_case_totals(self) -> None:
        for counts in (
            {"linux": (True, 2), "macos": (True, 2), "windows": (True, 2)},
            {"linux": (2, False), "macos": (2, False), "windows": (2, False)},
            {"linux": (-1, 2), "macos": (-1, 2), "windows": (-1, 2)},
        ):
            with self.subTest(counts=counts), self.assertRaisesRegex(
                RuntimeError, "complete consistent 3-OS"
            ):
                require_unsigned_preproduction_eligibility(counts, expected_eligible=4)

    def test_known_legacy_refusal_allows_only_unsigned_preproduction_review(self) -> None:
        counts = {"linux": (2, 2), "macos": (2, 2), "windows": (2, 2)}
        require_unsigned_preproduction_eligibility(counts, expected_eligible=4)
        with self.assertRaisesRegex(RuntimeError, "zero refused saved dependency plans"):
            require_complete_source_eligibility(counts, expected_eligible=4)

    def test_unsigned_preproduction_rejects_missing_or_divergent_os(self) -> None:
        for counts in (
            {"linux": (2, 2), "macos": (2, 2)},
            {"linux": (2, 2), "macos": (2, 2), "windows": (4, 0)},
            {"linux": (0, 2), "macos": (0, 2), "windows": (0, 2)},
            {"linux": (2, 4), "macos": (2, 4), "windows": (2, 4)},
        ):
            with self.subTest(counts=counts), self.assertRaisesRegex(
                RuntimeError, "complete consistent 3-OS"
            ):
                require_unsigned_preproduction_eligibility(counts, expected_eligible=4)


    def test_complete_72_gate_rejects_consistently_missing_scopes(self) -> None:
        # Three matching OS summaries cannot hide two unexecuted saved cases.
        counts = {platform: (70, 0) for platform in ("linux", "macos", "windows")}
        with self.assertRaisesRegex(RuntimeError, "complete identical 3-OS"):
            require_complete_source_eligibility(counts, expected_eligible=72)
        require_complete_source_eligibility(
            {platform: (72, 0) for platform in counts}, expected_eligible=72
        )

    def test_preproduction_gate_requires_all_72_classified_scopes(self) -> None:
        counts = {platform: (68, 2) for platform in ("linux", "macos", "windows")}
        with self.assertRaisesRegex(RuntimeError, "complete consistent 3-OS"):
            require_unsigned_preproduction_eligibility(counts, expected_eligible=72)
        require_unsigned_preproduction_eligibility(
            {platform: (70, 2) for platform in counts}, expected_eligible=72
        )

    def test_expected_count_cannot_be_spoofed_by_bool(self) -> None:
        counts = {platform: (4, 0) for platform in ("linux", "macos", "windows")}
        with self.assertRaisesRegex(RuntimeError, "complete identical 3-OS"):
            require_complete_source_eligibility(counts, expected_eligible=True)

    def test_unknown_refusal_cannot_be_counted_as_reviewed(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][0]["status"] = "refused"
        report["runner_os"] = "Windows"
        with self.assertRaisesRegex(RuntimeError, "unexpected eligibility failure"):
            validate_platform_report(report, "windows", HEAD, self.sources)

    def test_duplicate_or_missing_scope_is_rejected(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][1] = copy.deepcopy(report["results"][0])
        report["runner_os"] = "macOS"
        with self.assertRaisesRegex(RuntimeError, "repeated case"):
            validate_platform_report(report, "macos", HEAD, self.sources)

    def test_root_install_digest_is_mandatory(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][0]["planned_actions"][0]["package_digest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(RuntimeError, "root identity missing"):
            validate_platform_report(report, "linux", HEAD, self.sources)

    def test_suspended_policy_cannot_qualify(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][-1]["status"] = "planned"
        with self.assertRaisesRegex(RuntimeError, "suspended source"):
            validate_platform_report(report, "linux", HEAD, self.sources)

    def test_linux_report_cannot_be_mislabeled_windows(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unqualified source evidence"):
            validate_platform_report(self.report, "windows", HEAD, self.sources)

    def test_source_head_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unqualified source evidence"):
            validate_platform_report(self.report, "linux", "d" * 40, self.sources)

    def test_planned_status_needs_actual_successful_cli_exit(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][0]["exit_code"] = 1
        with self.assertRaisesRegex(RuntimeError, "successful CLI exit"):
            validate_platform_report(report, "linux", HEAD, self.sources)

    def test_refused_status_needs_actual_failed_cli_exit(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][2]["exit_code"] = 0
        with self.assertRaisesRegex(RuntimeError, "real failed CLI exit"):
            validate_platform_report(report, "linux", HEAD, self.sources)

    def test_marketing_refusal_must_be_exact_signed_dependency_denial(self) -> None:
        # Transient failures and other dependency errors are not proof of
        # the one observed 0.1.102 Marketing Kit signed-policy refusal.
        for diagnostic in (
            "",
            "agentplugins: network timeout",
            "agentplugins: dependency conflict for directory:777genius/notion: marketing-kit version 0.1.0",
            "agentplugins: dependency conflict for directory:777genius/hubspot-crm: marketing-kit version 0.1.1",
        ):
            report = copy.deepcopy(self.report)
            report["results"][2]["diagnostic"] = diagnostic
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(
                RuntimeError, "verified signed HubSpot policy conflict"
            ):
                validate_platform_report(report, "linux", HEAD, self.sources)

    def test_planned_actions_cannot_include_other_clients(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][0]["planned_actions"].append({
            "client_id": "codex", "action": "install",
            "alias": "other", "revision": HEAD, "package_digest": DIGEST,
        })
        with self.assertRaisesRegex(RuntimeError, "Pi-only"):
            validate_platform_report(report, "linux", HEAD, self.sources)

    def test_source_only_report_must_not_claim_runtime_or_account_auth(self) -> None:
        for field, value in (("runtime_claims", True),
                             ("account_authentication", "tested"),
                             ("signed_pi_policy_published", True),
                             ("scopes", ["user"])):
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report[field] = value
                with self.assertRaisesRegex(RuntimeError, "unqualified source evidence"):
                    validate_platform_report(report, "linux", HEAD, self.sources)

    def test_reject_boolean_release_sequence_spoof(self) -> None:
        report = copy.deepcopy(self.report)
        report["results"][0]["release_sequence"] = True
        with self.assertRaisesRegex(RuntimeError, "invalid release sequence"):
            validate_platform_report(report, "linux", HEAD, self.sources)


class ModernPiCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = source_case("owner/tool")
        self.source = {
            "schema_version": 1,
            "distributions": [
                {"id": "owner/tool", "status": "active",
                 "release_policies": [
                     {"release_sequence": 1, "status": "active",
                      "minimum_installer_version": "0.1.26",
                      "targets": [{"client": "codex", "authentication": "required",
                                   "scopes": ["user"], "delivery": "managed"}]},
                     {"release_sequence": 0, "status": "revoked",
                      "minimum_installer_version": "0.1.8", "targets": []}]},
                {"id": "owner/suspended", "status": "suspended",
                 "release_policies": [{"release_sequence": 1, "status": "active",
                                       "minimum_installer_version": "0.1.26", "targets": []}]},
            ],
        }
        self.review = {"schema_version": 1, "source_commit": HEAD, "reviews": [{
            "distribution": "owner/tool", "release_sequence": 1,
            "tree_digest": DIGEST, "authentication": "required",
            "transport": "streamable-http",
            "evidence_url": "https://github.com/owner/repo/actions/runs/123",
        }]}

    def test_only_active_candidate_changes_and_original_is_immutable(self) -> None:
        original = copy.deepcopy(self.source)
        candidate = proposed_source(self.source, [self.tool], self.review)
        self.assertEqual(self.source, original)
        active = candidate["distributions"][0]["release_policies"][0]
        self.assertEqual(active["minimum_installer_version"], "0.1.102")
        self.assertEqual(active["targets"][-1], {
            "client": "pi", "scopes": ["user"], "delivery": "managed",
            "authentication": "required",
        })
        self.assertEqual(candidate["distributions"][0]["release_policies"][1],
                         self.source["distributions"][0]["release_policies"][1])
        self.assertEqual(candidate["distributions"][1], self.source["distributions"][1])

    def test_project_planning_does_not_fabricate_a_signed_v1_project_grant(self) -> None:
        # E2E user/project placements do not change v1's User-only wire grant.
        candidate = proposed_source(self.source, [self.tool], self.review)
        targets = candidate["distributions"][0]["release_policies"][0]["targets"]
        self.assertEqual([target["scopes"] for target in targets if target["client"] == "pi"],
                         [["user"]])


    def test_without_explicit_review_candidate_cannot_be_generated(self) -> None:
        review = copy.deepcopy(self.review)
        review["reviews"] = []
        with self.assertRaisesRegex(RuntimeError, "all active Pi targets"):
            proposed_source(self.source, [self.tool], review)

    def test_boolean_review_schema_version_cannot_impersonate_v1(self) -> None:
        review = copy.deepcopy(self.review)
        review["schema_version"] = True
        with self.assertRaisesRegex(RuntimeError, "review document contract"):
            proposed_source(self.source, [self.tool], review)

    def test_boolean_review_release_sequence_cannot_impersonate_one(self) -> None:
        review = copy.deepcopy(self.review)
        review["reviews"][0]["release_sequence"] = True
        with self.assertRaisesRegex(RuntimeError, "must be an integer"):
            proposed_source(self.source, [self.tool], review)

    def test_review_digest_mismatch_is_rejected(self) -> None:
        review = copy.deepcopy(self.review)
        review["reviews"][0]["tree_digest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(RuntimeError, "not pinned"):
            proposed_source(self.source, [self.tool], review)

    def test_review_may_not_redefine_signed_policy(self) -> None:
        source = copy.deepcopy(self.source)
        source["distributions"][0]["release_policies"][0]["targets"].append({
            "client": "pi", "scopes": ["user"], "delivery": "managed",
            "authentication": "required",
        })
        with self.assertRaisesRegex(RuntimeError, "overlaps a legacy Pi policy"):
            proposed_source(source, [self.tool], self.review)

    def test_unknown_authentication_does_not_become_a_signed_pi_target(self) -> None:
        review = copy.deepcopy(self.review)
        review["reviews"][0]["authentication"] = "unknown"
        with self.assertRaisesRegex(RuntimeError, "Pi authentication is unresolved"):
            proposed_source(self.source, [self.tool], review)

    def test_only_skills_may_use_skills_transport(self) -> None:
        review = copy.deepcopy(self.review)
        review["reviews"][0]["transport"] = "skills"
        with self.assertRaisesRegex(RuntimeError, "component/transport"):
            proposed_source(self.source, [self.tool], review)


if __name__ == "__main__":
    unittest.main()
