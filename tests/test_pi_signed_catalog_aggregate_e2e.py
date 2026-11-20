"""Synthetic offline regression only; never production signed evidence."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pi_signed_catalog_aggregate_e2e as subject


class SignedSavedAggregateTests(unittest.TestCase):
    def sample(self, folder: Path):
        sources = [{"distribution": f"777genius/example-{n:02d}",
                    "release_sequence": 1, "distribution_status": "active"}
                   for n in range(36)]
        sources.append({"distribution": "777genius/suspended", "release_sequence": 1,
                        "distribution_status": "suspended"})
        head = "a" * 40
        for platform in subject.PLATFORMS:
            for shard in range(subject.SHARDS):
                cases = [{"distribution": item["distribution"], "release_sequence": 1,
                          "scope": scope, "status": "passed", "snapshot_sequence": 50,
                          "snapshot_digest": "sha256:" + "b" * 64,
                          "installed_dependency_count": 1}
                         for item, scope in subject.expected_shard(sources, shard)]
                report = {"kind": "pi-signed-full-catalog-saved-production-e2e",
                          "source_head": head, "platform": platform, "shard": shard,
                          "cli_version": subject.PUBLIC_CLI,
                          "signed_production_default": True, "synthetic_signed_feed": False,
                          "status": "passed", "cases": cases}
                self.write(folder, platform, shard, report)
        return sources, head

    def write(self, folder, platform, shard, report):
        (folder / f"pi-signed-full-{platform}-{shard}.json").write_text(
            json.dumps(report), encoding="utf-8")

    def modify(self, folder, platform="macos-15", shard=3):
        path = folder / f"pi-signed-full-{platform}-{shard}.json"
        return path, json.loads(path.read_text(encoding="utf-8"))

    def test_216_exact_same_snapshot_across_18_shards(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sources, head = self.sample(folder)
            report = subject.aggregate_reports(folder, head, sources)
            self.assertEqual(report["scope_executions"], 216)
            self.assertEqual(report["per_os"], {name: 72 for name in subject.PLATFORMS})
            self.assertEqual(report["snapshot_digest"], "sha256:" + "b" * 64)

    def test_missing_extra_or_mismatched_head_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sources, head = self.sample(folder)
            with self.assertRaises(RuntimeError):
                subject.aggregate_reports(folder, "f" * 40, sources)
            path, _ = self.modify(folder)
            contents = path.read_bytes()
            path.unlink()
            with self.assertRaises(RuntimeError):
                subject.aggregate_reports(folder, head, sources)
            path.write_bytes(contents)
            (folder / "unexpected.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                subject.aggregate_reports(folder, head, sources)

    def test_mixed_signed_snapshot_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sources, head = self.sample(folder)
            path, report = self.modify(folder)
            for case in report["cases"]:
                case["snapshot_digest"] = "sha256:" + "c" * 64
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "different signed snapshots"):
                subject.aggregate_reports(folder, head, sources)
            for case in report["cases"]:
                case.pop("snapshot_digest")
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                subject.aggregate_reports(folder, head, sources)

    def test_queued_skipped_refused_or_duplicate_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            sources, head = self.sample(folder)
            path, report = self.modify(folder)
            for bad in ("skipped", "queued", "refused"):
                changed = json.loads(json.dumps(report))
                changed["cases"][0]["status"] = bad
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(status=bad), self.assertRaises(RuntimeError):
                    subject.aggregate_reports(folder, head, sources)
            changed = json.loads(json.dumps(report))
            changed["cases"][0] = dict(changed["cases"][1])
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                subject.aggregate_reports(folder, head, sources)


if __name__ == "__main__":
    unittest.main()
