"""Separate signed static-analysis release: full findings, no install approval."""
from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_candidate_cohort as candidate
from scripts import skillspector_candidate_signature
from scripts import skillspector_cohort_release_protocol as release
from scripts import skillspector_reports as scanner
from scripts.directory_publication import (
    PublicationError, canonical_json, ed25519_public_bytes, sha256_digest,
)
from tests.test_bounded_cohort import BoundedCohortTests

REPORT_SHA = "b" * 40
MAIN_SHA = "c" * 40
KEY_ID = "uap-skillspector-release-test"
SEED = bytes(range(32))
KEYS = {KEY_ID: ed25519_public_bytes(SEED)}
GENERATED = "2026-11-05T12:00:00Z"
EXPIRES = "2026-11-06T12:00:00Z"
NOW = datetime(2026, 11, 5, 13, tzinfo=timezone.utc)


def qualified_fixture():
    """Build exactly nine community package-root candidates, one with risk."""
    previous, selection = BoundedCohortTests.fixture()
    by_old_id = previous["records"]
    revised_records, packages = {}, {}
    for item in selection["sources"]:
        if item["id"] == "unrelated":
            continue
        repository, path = item["repository"], item["plugin_path"]
        package = "community:" + sha256_digest(canonical_json(
            [repository, path]))[7:39]
        old_id = item["id"]
        item.update(id="plugin:" + package + "/" + item["path"].rsplit("/", 1)[-1],
                    kind="plugin_skill")
        row = by_old_id[old_id]
        row.update(id=item["id"], kind=item["kind"],
                   plugin_path=item["plugin_path"], finding_count=0, findings=[])
        revised_records[row["id"]] = row
        packages[package] = (repository, path)
    previous["records"] = revised_records
    previous["manifest"]["selection_digest"] = admission.digest(selection)
    plan = admission.build_plan(previous, selection, REPORT_SHA)
    rows, comparisons, pins = [], [], []
    for index, item in enumerate(plan["selection"]["sources"]):
        old = previous["records"][item["id"]]
        findings = ([{"rule": "E4", "severity": "HIGH", "path": "SKILL.md",
                      "line": 9, "occurrences": [{"path": "SKILL.md", "line": 9}]}]
                    if index == 0 else [])
        new = {
            "id": item["id"], "kind": item["kind"], "plugin_path": item["plugin_path"],
            "source": copy.deepcopy(old["source"]),
            "scanner": copy.deepcopy(candidate.NEW_SCANNER),
            "profile": copy.deepcopy(candidate.PROFILE),
            "status": "complete", "errors": [], "findings_truncated": False,
            "raw_finding_count": len(findings), "finding_count": len(findings),
            "finding_group_count": len(findings), "findings": findings,
            "execution": {"state": "completed", "exit_code": 1 if findings else 0},
            "coverage": {
                "status": "complete", "fully_inspected_files": 1,
                "partially_inspected_files": 0, "entirely_uninspected_files": 0,
                "grouping_complete": True, "reference_evidence_truncated": False,
                "references_total": 0, "references": [], "reasons": [],
                "ledger_exceptions_total": 0, "ledger_exceptions": [],
            },
        }
        rows.append(new)
        comparisons.append(candidate.verify_candidate(item, old, new))
        package = item["id"].split("/", 1)[0][len("plugin:"):]
        pins.append({
            "id": item["id"], "repository": item["repository"],
            "revision": item["revision"], "path": item["path"],
            "plugin_path": item["plugin_path"],
            "content_digest": old["source"]["content_digest"],
            "signed_package_id": package,
            "signed_package_tree_digest": "sha256:" + "1" * 64,
            "signed_package_manifest_digest": "sha256:" + "2" * 64,
        })
    proof = {
        "schema_version": 1, "kind": "skillspector-2.13.3-nine-source-candidate",
        "base_report_commit": REPORT_SHA,
        "base_manifest_digest": admission.digest(previous["manifest"]),
        "scanner": copy.deepcopy(candidate.NEW_SCANNER),
        "profile": copy.deepcopy(candidate.PROFILE),
        "profile_policy_digest": candidate.PROFILE["digest"],
        "candidate_status": "measured_complete_unpublished",
        "live_selection_verified": False, "publication_authorized": False,
        "comparisons": comparisons, "records": rows,
    }
    live = {
        "schema_version": 1, "kind": release.SOURCE_KIND,
        "base_report_commit": REPORT_SHA,
        "base_manifest_digest": proof["base_manifest_digest"],
        "community": {"sequence": 8, "source_commit": "d" * 40,
                      "snapshot_digest": "sha256:" + "3" * 64},
        "directory": {"sequence": 10, "source_commit": "e" * 40,
                      "snapshot_digest": "sha256:" + "4" * 64},
        "source_pins_verified_against_fresh_signed_feeds": True,
        "provider_listing_verified": False,
        "candidate_scan_verified": False,
        "publication_authorized": False,
        "sources": pins,
    }
    return proof, live, previous


class CohortReleaseTests(unittest.TestCase):
    def fixture(self):
        """Test a real signed round-trip with the old-v3 admission mock boundary."""
        proof, live, previous = qualified_fixture()
        with mock.patch.object(skillspector_candidate_signature, "load_verified_previous",
                               return_value=previous):
            snapshot = release.build_release(
                proof, live, Path("/synthetic-v3"), MAIN_SHA, GENERATED, EXPIRES, now=NOW)
        with mock.patch.object(skillspector_candidate_signature, "load_verified_previous",
                               return_value=previous):
            envelope = release.sign_release(
                snapshot, KEYS, KEY_ID, SEED, Path("/synthetic-v3"), now=NOW)
        return snapshot, envelope, previous

    def verify(self, snapshot, envelope, previous, keys=None, now=NOW):
        """Run exact byte and Ed25519 verification after the old-v3 readback stub."""
        body = scanner.report_json(snapshot)
        signed = canonical_json(envelope)
        with mock.patch.object(skillspector_candidate_signature, "load_verified_previous",
                               return_value=previous):
            return release.verify_release(body, signed, KEYS if keys is None else keys,
                                          Path("/synthetic-v3"), now=now)

    def test_complete_signed_release_retains_risk_and_old_unpublished_flags(self):
        snapshot, envelope, previous = self.fixture()
        verified = self.verify(snapshot, envelope, previous)
        self.assertEqual(verified["kind"], release.RELEASE_KIND)
        self.assertEqual(len(verified["candidate"]["records"]), 9)
        self.assertEqual(verified["candidate"]["records"][0]["findings"][0]["rule"], "E4")
        self.assertEqual(verified["candidate"]["records"][0]["execution"]["exit_code"], 1)
        self.assertFalse(verified["candidate"]["publication_authorized"])
        self.assertFalse(verified["signed_sources"]["publication_authorized"])
        self.assertEqual(verified["source_commit"], MAIN_SHA)
        self.assertTrue(all(record["status"] == "complete"
                            for record in verified["candidate"]["records"]))
        self.assertTrue(all(value["status"] == "partial"
                            for value in previous["records"].values()))

    def test_unique_dedicated_domain_and_length_prefix(self):
        snapshot, _, _ = self.fixture()
        body = scanner.report_json(snapshot)
        self.assertEqual(release.DOMAIN,
                         b"UAP-SKILLSPECTOR-COHORT-RELEASE-ED25519-V1" + bytes([0]))
        self.assertEqual(release.signing_message(body),
                         release.DOMAIN + len(body).to_bytes(8, "big") + body)
        self.assertNotEqual(release.DOMAIN,
                            skillspector_candidate_signature.DOMAIN)

    def test_wrong_or_unregistered_signer_and_tampered_bytes_rejected(self):
        snapshot, envelope, previous = self.fixture()
        with self.assertRaises(PublicationError):
            release.sign_release(snapshot, {}, KEY_ID, SEED,
                                 Path("/synthetic-v3"), now=NOW)
        with self.assertRaises(PublicationError):
            release.sign_release(snapshot, KEYS, KEY_ID, bytes([1]) * 32,
                                 Path("/synthetic-v3"), now=NOW)
        with self.assertRaises(PublicationError):
            self.verify(snapshot, envelope, previous, keys={KEY_ID: bytes(32)})
        tampered = copy.deepcopy(snapshot)
        tampered["candidate"]["records"][0]["findings"].clear()
        with self.assertRaises(PublicationError):
            self.verify(tampered, envelope, previous)
        tampered_envelope = copy.deepcopy(envelope)
        tampered_envelope["signature_domain"] = skillspector_candidate_signature.DOMAIN_NAME
        with self.assertRaises(PublicationError):
            self.verify(snapshot, tampered_envelope, previous)

    def test_valid_registered_key_cannot_sign_unverified_candidate_or_expiry(self):
        snapshot, _, previous = self.fixture()
        changed = copy.deepcopy(snapshot)
        changed["candidate"]["records"][0]["source"]["content_digest"] = "sha256:" + "0" * 64
        expired = copy.deepcopy(snapshot)
        expired["expires_at"] = "2026-11-05T12:10:00Z"
        for value in (changed, expired):
            with self.subTest(kind=value["expires_at"]), \
                 mock.patch.object(skillspector_candidate_signature,
                                   "load_verified_previous", return_value=previous), \
                 self.assertRaises(PublicationError):
                release.sign_release(
                    value, KEYS, KEY_ID, SEED, Path("/synthetic-v3"), now=NOW)

    def test_changed_candidate_source_or_signed_live_pin_rejected(self):
        proof, pins, previous = qualified_fixture()
        wrong = copy.deepcopy(proof)
        wrong["records"][0]["source"]["content_digest"] = "sha256:" + "0" * 64
        with mock.patch.object(skillspector_candidate_signature, "load_verified_previous",
                               return_value=previous), self.assertRaises(PublicationError):
            release.build_release(wrong, pins, Path("/synthetic-v3"),
                                  MAIN_SHA, GENERATED, EXPIRES, now=NOW)
        wrongpins = copy.deepcopy(pins)
        wrongpins["sources"][0]["revision"] = "0" * 40
        with mock.patch.object(skillspector_candidate_signature, "load_verified_previous",
                               return_value=previous), self.assertRaises(PublicationError):
            release.build_release(proof, wrongpins, Path("/synthetic-v3"),
                                  MAIN_SHA, GENERATED, EXPIRES, now=NOW)

    def test_unknown_pin_duplicate_pin_and_unverified_live_feed_fail(self):
        proof, pins, previous = qualified_fixture()
        variants = []
        missing = copy.deepcopy(pins)
        missing["sources"].pop()
        variants.append(missing)
        duplicate = copy.deepcopy(pins)
        duplicate["sources"][0] = copy.deepcopy(duplicate["sources"][1])
        variants.append(duplicate)
        unverified = copy.deepcopy(pins)
        unverified["source_pins_verified_against_fresh_signed_feeds"] = False
        variants.append(unverified)
        promoted = copy.deepcopy(pins)
        promoted["publication_authorized"] = True
        variants.append(promoted)
        for variant in variants:
            with self.subTest(variant=variant), mock.patch.object(
                    skillspector_candidate_signature, "load_verified_previous",
                    return_value=previous), self.assertRaises(PublicationError):
                release.build_release(proof, variant, Path("/synthetic-v3"),
                                      MAIN_SHA, GENERATED, EXPIRES, now=NOW)

    def test_expiry_future_generation_and_overlong_lifetime_fail(self):
        proof, pins, previous = qualified_fixture()
        invalid = [
            ("2026-11-05T12:00:00Z", "2026-11-05T12:00:00Z"),
            ("2026-11-05T12:00:00Z", "2026-11-08T12:00:00Z"),
            ("2026-11-05T13:10:00Z", "2026-11-06T13:10:00Z"),
            ("2026-11-04T12:00:00Z", "2026-11-05T12:59:59Z"),
        ]
        for generated_at, expires_at in invalid:
            with self.subTest(generated_at=generated_at, expires_at=expires_at), \
                 mock.patch.object(skillspector_candidate_signature,
                                   "load_verified_previous", return_value=previous), \
                 self.assertRaises(PublicationError):
                release.build_release(proof, pins, Path("/synthetic-v3"), MAIN_SHA,
                                      generated_at, expires_at, now=NOW)

    def test_release_json_and_envelope_must_be_canonical(self):
        snapshot, envelope, previous = self.fixture()
        with mock.patch.object(skillspector_candidate_signature,
                               "load_verified_previous", return_value=previous):
            with self.assertRaises(PublicationError):
                release.verify_release(scanner.report_json(snapshot) + b" ",
                                       canonical_json(envelope), KEYS,
                                       Path("/synthetic-v3"), now=NOW)
            with self.assertRaises(PublicationError):
                release.verify_release(scanner.report_json(snapshot),
                                       canonical_json(envelope) + b" ", KEYS,
                                       Path("/synthetic-v3"), now=NOW)
            with self.assertRaises(PublicationError):
                release.verify_release(b'{"schema_version":1,"schema_version":1}\n',
                                       canonical_json(envelope), KEYS,
                                       Path("/synthetic-v3"), now=NOW)


if __name__ == "__main__":
    unittest.main()
