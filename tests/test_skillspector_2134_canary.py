"""Negative tests for immutable source-bound 2.13.4 pilot results."""
import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts import skillspector_2134_canary as pilot


class UpgradeCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "docs/skillspector/upgrade-2.13.4-canary.json"
        cls.baseline = json.loads(path.read_text(encoding="utf-8"))

    def record(self, source=None, status="complete", findings=2):
        source = source or self.baseline["cases"][0]
        return {
            "source": {key: source[key] for key in ("repository", "revision", "path", "content_digest")},
            "scanner": copy.deepcopy(pilot.SCANNER),
            "status": status, "finding_count": findings,
            "execution": {"state": "completed"},
            "coverage": {"status": status, "reasons": [], "fully_inspected_files": 1,
                         "grouping_complete": True, "ledger_exceptions": [],
                         "reference_evidence_truncated": False, "partially_inspected_files": 0,
                         "entirely_uninspected_files": 0},
            "errors": [], "findings_truncated": False,
        }

    def test_curated_corpus_is_bounded_and_well_formed(self):
        cases = pilot.validate_cases(self.baseline)
        self.assertEqual(len(cases), 7)
        self.assertEqual(len({case["id"] for case in cases}), 7)
        self.assertEqual(len({case["reason"] for case in cases}), 5)

    def fake_published_baseline(self):
        """Exact content-addressed fake represents a signed-run immutable shard."""
        cases = copy.deepcopy(self.baseline)
        cases["cases"] = cases["cases"][:1]
        item = cases["cases"][0]
        original = {
            "id": item["id"], "kind": item["kind"], "plugin_path": item["plugin_path"],
            "source": {key: item[key] for key in ("repository", "revision", "path", "content_digest")},
            "status": "partial", "freshness": "current", "finding_count": item["finding_count"],
            "scanner": {"id": "skillspector", "version": "2.13.1"},
            "retry": {"reason": item["reason"]}, "findings": [], "report_digest": "sha256:" + "1" * 64,
        }
        shard_data = {"schema_version": 3, "repository": item["repository"], "records": [original]}
        shard_bytes = (json.dumps(shard_data, sort_keys=True, separators=(",", ":")) + "\n").encode()
        shard_digest = "sha256:" + hashlib.sha256(shard_bytes).hexdigest()
        path = "shards/" + shard_digest[7:] + ".json"
        manifest = {"schema_version": 3, "source_commit": "a" * 40,
                    "shards": [{"path": path, "digest": shard_digest, "repository": item["repository"],
                                "bytes": len(shard_bytes), "record_count": 1}]}
        index_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        cases["manifest_digest"] = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
        blobs = {"index.json": index_bytes, path: shard_bytes}
        return cases, blobs

    def test_baseline_reads_and_checks_original_publication_digest(self):
        cases, blobs = self.fake_published_baseline()
        proof = pilot.verify_published_baseline(cases, fetcher=lambda path, _: blobs[path])
        self.assertEqual(len(proof), 1)
        self.assertEqual(proof[0]["original_report_digest"], "sha256:" + "1" * 64)
        self.assertEqual(proof[0]["original_finding_group_count"], None)
        self.assertTrue(proof[0]["original_findings_sha256"].startswith("sha256:"))

    def test_baseline_tamper_or_replay_is_rejected(self):
        cases, blobs = self.fake_published_baseline()
        cases_bad = copy.deepcopy(cases)
        cases_bad["manifest_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "manifest SHA-256"):
            pilot.verify_published_baseline(cases_bad, fetcher=lambda path, _: blobs[path])
        bad_fixture = copy.deepcopy(cases)
        bad_fixture["cases"][0]["finding_count"] += 1
        with self.assertRaisesRegex(ValueError, "identical"):
            pilot.verify_published_baseline(bad_fixture, fetcher=lambda path, _: blobs[path])
        poisoned = dict(blobs)
        key = next(p for p in blobs if p != "index.json")
        poisoned[key] = blobs[key] + b" "
        with self.assertRaisesRegex(ValueError, "immutable digest"):
            pilot.verify_published_baseline(cases, fetcher=lambda path, _: poisoned[path])
        drifted = copy.deepcopy(cases)
        drifted["cases"][0]["revision"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "identical"):
            pilot.verify_published_baseline(drifted, fetcher=lambda path, _: blobs[path])

    def test_nonportable_or_untrusted_source_rejected(self):
        for changed in ({"path": "../SKILL.md"}, {"revision": "main"}, {"repository": "https://bad.example/a"},
                        {"content_digest": "sha256:" + "0" * 63}, {"status": "complete"}, {"reason": "unreviewed"}):
            with self.subTest(changed=changed):
                cases = copy.deepcopy(self.baseline)
                cases["cases"][0].update(changed)
                with self.assertRaises(ValueError):
                    pilot.validate_cases(cases)

    def test_duplicate_source_rejected(self):
        cases = copy.deepcopy(self.baseline)
        cases["cases"][1]["id"] = cases["cases"][0]["id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pilot.validate_cases(cases)

    def test_complete_is_not_automatically_authorized(self):
        old = self.baseline["cases"][0]
        result = pilot.compare(old, self.record(old, findings=5))
        self.assertTrue(result["candidate_complete"])
        self.assertTrue(result["manual_finding_review_required"])
        self.assertFalse(result["fewer_findings"])
        self.assertEqual(result["old_reason"], "reference_missing")

    def test_decreased_findings_requires_review_even_if_complete(self):
        old = self.baseline["cases"][1]
        result = pilot.compare(old, self.record(old, findings=0))
        self.assertTrue(result["candidate_complete"])
        self.assertTrue(result["fewer_findings"])
        self.assertTrue(result["manual_finding_review_required"])

    def test_source_replay_or_upgrade_identity_mismatch_fails(self):
        old = self.baseline["cases"][0]
        for patch in ({"content_digest": "sha256:" + "0" * 64}, {"revision": "a" * 40}):
            with self.subTest(patch=patch):
                record = self.record(old)
                record["source"].update(patch)
                with self.assertRaisesRegex(ValueError, "immutable baseline"):
                    pilot.compare(old, record)
        record = self.record(old)
        record["scanner"]["version"] = "2.13.1"
        with self.assertRaisesRegex(ValueError, "identity"):
            pilot.compare(old, record)

    def test_false_complete_fails_closed(self):
        old = self.baseline["cases"][0]
        mutations = [
            lambda r: r["coverage"].update(status="partial"),
            lambda r: r["coverage"].update(fully_inspected_files=0),
            lambda r: r["coverage"].update(grouping_complete=False),
            lambda r: r["coverage"].update(ledger_exceptions=[{"reason_code": "missing"}]),
            lambda r: r["execution"].update(state="failed"),
            lambda r: r["coverage"].update(reasons=[{"code": "reference_missing"}]),
            lambda r: r.update(errors=[{"code": "runtime_limit"}]),
            lambda r: r["coverage"].update(partially_inspected_files=1),
            lambda r: r["coverage"].update(entirely_uninspected_files=1),
            lambda r: r.update(findings_truncated=True),
        ]
        for mutate in mutations:
            record = self.record(old)
            mutate(record)
            with self.subTest(record=record), self.assertRaisesRegex(ValueError, "complete evidence"):
                pilot.compare(old, record)

    def test_security_group_identity_loss_even_with_unchanged_count(self):
        original = self.record()
        a = {"id": "sha256:" + "a" * 64, "rule": "S1", "severity": "HIGH", "path": "SKILL.md"}
        b = {"id": "sha256:" + "b" * 64, "rule": "S2", "severity": "LOW", "path": "src.py"}
        c = {"id": "sha256:" + "c" * 64, "rule": "S3", "severity": "LOW", "path": "SKILL.md"}
        original.update(finding_group_count=2, findings=[a, b])
        original["coverage"]["original_findings"] = [{"id": "AE1", "reason": "missing"}]
        bound = {"original_finding_groups": pilot.finding_group_evidence(original)}
        candidate = copy.deepcopy(original)
        candidate["findings"] = [b, c]  # Same total; a HIGH finding vanished.
        difference = pilot.finding_group_delta(bound, candidate)
        self.assertEqual(difference["old_group_count"], difference["new_group_count"])
        self.assertEqual(difference["old_groups_not_in_candidate"], [a["id"]])
        self.assertEqual(difference["candidate_groups_not_in_old"], [c["id"]])
        self.assertFalse(difference["eligible_for_no_loss_assertion"])
        self.assertTrue(difference["independent_review_required"])

    def test_group_delta_refuses_incomplete_or_changed_coverage_evidence(self):
        original = self.record()
        group = {"id": "sha256:" + "a" * 64, "rule": "SC1", "severity": "CRITICAL", "path": "SKILL.md"}
        original.update(finding_group_count=1, findings=[group])
        original["coverage"]["original_findings"] = [{"id": "AE1"}]
        bound = {"original_finding_groups": pilot.finding_group_evidence(original)}
        unchanged = pilot.finding_group_delta(bound, copy.deepcopy(original))
        self.assertTrue(unchanged["eligible_for_no_loss_assertion"])
        changed = copy.deepcopy(original)
        changed["coverage"]["original_findings"] = []
        delta = pilot.finding_group_delta(bound, changed)
        self.assertTrue(delta["coverage_findings_digest_changed"])
        self.assertFalse(delta["eligible_for_no_loss_assertion"])
        changed["coverage"]["original_findings"] = original["coverage"]["original_findings"]
        changed["coverage"]["grouping_complete"] = False
        self.assertFalse(pilot.finding_group_delta(bound, changed)["eligible_for_no_loss_assertion"])

    def test_malformed_group_identity_or_incomplete_enumeration_rejected(self):
        original = self.record()
        original.update(finding_group_count=1, findings=[])
        with self.assertRaisesRegex(ValueError, "enumeration"):
            pilot.finding_group_evidence(original)
        a = {"id": "sha256:" + "a" * 64, "rule": "SC1", "severity": "HIGH", "path": "SKILL.md"}
        original.update(finding_group_count=2, findings=[a, copy.deepcopy(a)])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pilot.finding_group_evidence(original)

    def test_partial_remains_partial(self):
        old = self.baseline["cases"][0]
        record = self.record(old, status="partial")
        record["coverage"]["reasons"] = [{"code": "reference_missing"}]
        result = pilot.compare(old, record)
        self.assertFalse(result["candidate_complete"])
        self.assertEqual(result["coverage_reasons"], ["reference_missing"])
        self.assertTrue(result["manual_finding_review_required"])


if __name__ == "__main__":
    unittest.main()
