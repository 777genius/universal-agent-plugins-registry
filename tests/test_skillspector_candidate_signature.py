"""Signed unpublished candidate checks: never authorize a production status change."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_candidate_cohort as candidate
from scripts import skillspector_candidate_signature as signing
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.directory_publication import (
    PublicationError, canonical_json, ed25519_public_bytes,
)
from tests.test_bounded_cohort import BoundedCohortTests


REPORT_SHA = "b" * 40
KEY_ID = "uap-skillspector-candidate-test"
SEED = bytes(range(32))


def full_candidate():
    previous, selection = BoundedCohortTests.fixture()
    plan = admission.build_plan(previous, selection, REPORT_SHA)
    records, comparisons = [], []
    for item in plan["selection"]["sources"]:
        old = previous["records"][item["id"]]
        old.update(kind=item["kind"], plugin_path=item["plugin_path"],
                   finding_count=0, findings=[])
        new = {
            "id": item["id"], "kind": item["kind"],
            "plugin_path": item["plugin_path"], "source": copy.deepcopy(old["source"]),
            "scanner": copy.deepcopy(candidate.NEW_SCANNER),
            "profile": copy.deepcopy(candidate.PROFILE),
            "status": "complete", "errors": [], "findings_truncated": False,
            "raw_finding_count": 0, "finding_count": 0,
            "finding_group_count": 0, "findings": [],
            "execution": {"state": "completed", "exit_code": 0},
            "coverage": {
                "status": "complete", "fully_inspected_files": 1,
                "partially_inspected_files": 0, "entirely_uninspected_files": 0,
                "grouping_complete": True, "reference_evidence_truncated": False,
                "references_total": 0, "references": [], "reasons": [],
                "ledger_exceptions_total": 0, "ledger_exceptions": [],
            },
        }
        comparisons.append(candidate.verify_candidate(item, old, new))
        records.append(new)
    proof = {
        "schema_version": 1,
        "kind": "skillspector-2.13.3-nine-source-candidate",
        "base_report_commit": REPORT_SHA,
        "base_manifest_digest": admission.digest(previous["manifest"]),
        "scanner": copy.deepcopy(candidate.NEW_SCANNER),
        "profile": copy.deepcopy(candidate.PROFILE),
        "profile_policy_digest": candidate.PROFILE["digest"],
        "candidate_status": "measured_complete_unpublished",
        "live_selection_verified": False,
        "publication_authorized": False,
        "comparisons": comparisons,
        "records": records,
    }
    return proof, previous


class SignedCandidateTests(unittest.TestCase):
    def sign(self, proof, previous):
        """Exercise signer policy on a synthetic witness while testing real IO separately."""
        with mock.patch.object(signing, "load_verified_previous", return_value=previous):
            return signing.sign_unpublished_candidate(
                proof, Path("/verified-fixture"), REPORT_SHA, KEY_ID, SEED)

    def fixture(self):
        proof, previous = full_candidate()
        envelope = self.sign(proof, previous)
        return proof, previous, envelope

    def verify(self, proof, previous, envelope, keys=None):
        """Check signed bytes using the matching synthetic witness fixture."""
        body = scanner.report_json(proof)
        sealed = canonical_json(envelope)
        with mock.patch.object(signing, "load_verified_previous", return_value=previous):
            return signing.verify_signed_candidate(
                body, sealed, keys if keys is not None else
                {KEY_ID: ed25519_public_bytes(SEED)}, Path("/verified-fixture"), REPORT_SHA,
            )

    def test_exact_nine_source_evidence_signed_but_not_published(self):
        proof, previous, envelope = self.fixture()
        result = self.verify(proof, previous, envelope)
        self.assertEqual(len(result["records"]), 9)
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["live_selection_verified"])
        self.assertEqual(result["scanner"], admission.NEW_SCANNER)

    def test_nonempty_risk_finding_survives_signed_round_trip(self):
        proof, previous = full_candidate()
        row = proof["records"][0]
        finding = {"rule": "E4", "severity": "HIGH", "path": "SKILL.md",
                   "line": 7, "occurrences": [{"path": "SKILL.md", "line": 7}]}
        old = previous["records"][row["id"]]
        old.update(findings=[copy.deepcopy(finding)], finding_count=1)
        row.update(findings=[copy.deepcopy(finding)], finding_count=1,
                   raw_finding_count=1, finding_group_count=1)
        row["execution"]["exit_code"] = 1
        item = next(i for i in previous["selection"]["sources"] if i["id"] == row["id"])
        proof["comparisons"][0] = candidate.verify_candidate(item, old, row)
        sealed = self.sign(proof, previous)
        verified = self.verify(proof, previous, sealed)
        self.assertEqual(verified["records"][0]["findings"], [finding])
        self.assertEqual(verified["records"][0]["execution"]["exit_code"], 1)

    def test_signature_message_exact_domain_and_length(self):
        proof, _, _ = self.fixture()
        body = scanner.report_json(proof)
        domain = b"UAP-SKILLSPECTOR-UNPUBLISHED-CANDIDATE-ED25519-V1" + bytes([0])
        self.assertEqual(signing.DOMAIN, domain)
        self.assertEqual(signing.signature_message(body),
                         domain + len(body).to_bytes(8, "big") + body)

    def test_missing_previous_manifest_and_omitted_groups_fail(self):
        proof, previous = full_candidate()
        previous.pop("manifest")
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)
        proof, previous = full_candidate()
        proof["records"][0].update(raw_finding_count=1, finding_count=1,
                                    finding_group_count=1)
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)

    def test_malformed_counts_and_reference_status_are_rejected(self):
        for field in ("raw_finding_count", "finding_count", "finding_group_count"):
            proof, previous = full_candidate()
            proof["records"][0][field] = True
            with self.assertRaises(PublicationError):
                self.sign(proof, previous)
        proof, previous = full_candidate()
        proof["records"][0]["coverage"]["fully_inspected_files"] = True
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)
        proof, previous = full_candidate()
        proof["records"][0]["execution"]["exit_code"] = True
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)
        proof, previous = full_candidate()
        state = proof["records"][0]["coverage"]
        state["references"] = [{"status": "unknown", "disposition": "analyzed"}]
        state["references_total"] = 1
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)

    def test_load_verified_bundle_detects_shard_corruption(self):
        from tests.test_skillspector_coverage_v3 import bundle, record
        from tests.test_skillspector_reports import item
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = item()
            previous = bundle(root, {"schema_version": 1, "sources": [source]},
                              [record(source)])
            coverage.write_bounded(root / "publication-base.json",
                                   {"schema_version": 1, "report_commit": REPORT_SHA}, 4096)
            loaded = signing.load_verified_previous(root, REPORT_SHA)
            self.assertEqual(loaded["manifest"], previous["manifest"])
            with self.assertRaises(PublicationError):
                signing.load_verified_previous(root, "c" * 40)
            shard = root / previous["manifest"]["shards"][0]["path"]
            shard.write_bytes(shard.read_bytes().replace(b'"records"', b'"tampered"'))
            with self.assertRaises(PublicationError):
                signing.load_verified_previous(root, REPORT_SHA)

    def test_missing_or_wrong_trust_key_fails_closed(self):
        proof, previous, envelope = self.fixture()
        with self.assertRaises(PublicationError):
            self.verify(proof, previous, envelope, keys={})
        with self.assertRaises(PublicationError):
            self.verify(proof, previous, envelope, keys={KEY_ID: b"\x00" * 32})

    def test_malformed_duplicate_json_and_invalid_public_key_type_fail_closed(self):
        proof, previous, envelope = self.fixture()
        with self.assertRaises(PublicationError):
            signing.verify_signed_candidate(
                b'{"schema_version":1,"schema_version":1}\n',
                canonical_json(envelope), {KEY_ID: ed25519_public_bytes(SEED)},
                Path("/verified-fixture"), REPORT_SHA,
            )
        with self.assertRaises(PublicationError):
            self.verify(proof, previous, envelope, keys={KEY_ID: "X" * 32})

    def test_changed_status_and_missing_reference_cannot_be_signed(self):
        proof, previous = full_candidate()
        proof["records"][0]["status"] = "partial"
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)
        proof, previous = full_candidate()
        new = proof["records"][0]
        new["coverage"]["references"] = [{"status": "missing", "disposition": "partial"}]
        new["coverage"]["references_total"] = 1
        with self.assertRaises(PublicationError):
            self.sign(proof, previous)

    def test_claimed_live_or_publication_authorization_rejected(self):
        proof, previous = full_candidate()
        for flag in ("live_selection_verified", "publication_authorized"):
            wrong = copy.deepcopy(proof)
            wrong[flag] = True
            with self.assertRaises(PublicationError):
                self.sign(wrong, previous)

    def test_changed_source_bytes_and_old_baseline_rejected(self):
        proof, previous = full_candidate()
        wrong = copy.deepcopy(proof)
        wrong["records"][0]["source"]["content_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(PublicationError):
            self.sign(wrong, previous)
        wrong_prev = copy.deepcopy(previous)
        first_id = proof["records"][0]["id"]
        wrong_prev["records"][first_id]["freshness"] = "historical"
        with self.assertRaises((PublicationError, admission.CohortRejected)):
            self.verify(proof, wrong_prev, self.fixture()[2])

    def test_bounded_exact_bytes_and_signature_domain(self):
        proof, previous, envelope = self.fixture()
        tampered = copy.deepcopy(envelope)
        tampered["signature_domain"] = "UAP-DIRECTORY-SNAPSHOT-ED25519-V1"
        with self.assertRaises(PublicationError):
            self.verify(proof, previous, tampered)
        tampered = copy.deepcopy(envelope)
        tampered["candidate_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(PublicationError):
            self.verify(proof, previous, tampered)
        with self.assertRaises(PublicationError):
            signing.verify_signed_candidate(
                scanner.report_json(proof) + b" ", canonical_json(envelope),
                {KEY_ID: ed25519_public_bytes(SEED)}, Path("/verified-fixture"), REPORT_SHA,
            )

    def test_unexpected_compare_or_ninth_missing_rejected(self):
        proof, previous = full_candidate()
        wrong = copy.deepcopy(proof)
        wrong["comparisons"][0]["findings_changed"] = True
        with self.assertRaises(PublicationError):
            self.sign(wrong, previous)
        wrong = copy.deepcopy(proof)
        wrong["records"].pop()
        with self.assertRaises(PublicationError):
            self.sign(wrong, previous)


if __name__ == "__main__":
    unittest.main()
