"""Fail-closed tests for the UNSIGNED modern Pi v1 candidate staging boundary."""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from directory_publication import PublicationError
from pi_modern_feed_candidate import (proposed_source, read_evidence_object,
                                      require_complete_source_eligibility,
                                      validate_platform_report)

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
            require_complete_source_eligibility(counts)

    def test_all_os_source_plans_can_reach_review_stage(self) -> None:
        # This helper is only a source-planning gate, NOT signed entitlement.
        require_complete_source_eligibility(
            {"linux": (4, 0), "macos": (4, 0), "windows": (4, 0)}
        )

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
