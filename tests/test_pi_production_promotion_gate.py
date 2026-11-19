"""Promotion never treats unsigned/synthetic Pi eligibility as signed saved E2E."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pi_production_promotion_gate import PromotionDenied, require_pi_free_ledger, require_pi_free_snapshot


def snapshot() -> dict:
    return {
        "sequence": 48,
        "distributions": [{"id": "owner/demo", "release_policies": [
            {"status": "active", "targets": [{"client": "codex"}]}
        ]}],
        "evidence": [{"id": "e", "client": "codex"}],
    }


class PiProductionPromotionGateTests(unittest.TestCase):
    def test_pi_free_legacy_snapshot_preserves_existing_publication(self) -> None:
        require_pi_free_snapshot(snapshot(), 48)

    def test_pi_target_denied_even_when_superseded_or_revoked(self) -> None:
        for status in ("active", "superseded", "revoked"):
            with self.subTest(status=status):
                record = snapshot()
                record["distributions"][0]["release_policies"][0].update(
                    status=status, targets=[{"client": "pi", "delivery": "managed"}]
                )
                with self.assertRaisesRegex(PromotionDenied, "72/72 production signed saved"):
                    require_pi_free_snapshot(record, 48)

    def test_unreferenced_pi_evidence_also_denied(self) -> None:
        record = snapshot()
        record["evidence"].append({"id": "pi-only", "client": "pi"})
        with self.assertRaisesRegex(PromotionDenied, "72/72 production signed saved"):
            require_pi_free_snapshot(record, 48)

    def test_missing_or_forged_snapshot_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ledger = Path(temp)
            with self.assertRaisesRegex(PromotionDenied, "missing"):
                require_pi_free_ledger(ledger, "48")
            target = ledger / "registry/schemas/1/snapshots/00000000000000000048.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(snapshot()), encoding="utf-8")
            require_pi_free_ledger(ledger, "48")
            with self.assertRaisesRegex(PromotionDenied, "sequence differs"):
                require_pi_free_snapshot(snapshot(), 49)
            with self.assertRaisesRegex(PromotionDenied, "duplicate"):
                target.write_text('{"sequence":48,"sequence":48,"distributions":[],"evidence":[]}', encoding="utf-8")
                require_pi_free_ledger(ledger, "48")
            target.write_text(
                '{"sequence":48,"distributions":[],"evidence":[],"extra":NaN}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PromotionDenied, "non-JSON numeric constant"):
                require_pi_free_ledger(ledger, "48")
            target.unlink()
            target.symlink_to(Path(temp) / "nonexistent")
            with self.assertRaisesRegex(PromotionDenied, "contains a symlink"):
                require_pi_free_ledger(ledger, "48")

    def test_parent_symlink_cannot_redirect_signed_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            outside = base / "outside/schemas/1/snapshots"
            outside.mkdir(parents=True)
            (outside / "00000000000000000048.json").write_text(
                json.dumps(snapshot()), encoding="utf-8"
            )
            ledger = base / "ledger"
            ledger.mkdir()
            (ledger / "registry").symlink_to(base / "outside", target_is_directory=True)
            with self.assertRaisesRegex(PromotionDenied, "contains a symlink"):
                require_pi_free_ledger(ledger, "48")

    def test_malformed_or_bypass_fields_fail_closed(self) -> None:
        for wrong in (None, {}, {"sequence": True, "distributions": [], "evidence": []},
                      {"sequence": 48, "distributions": [{"release_policies": ["pi"]}], "evidence": []},
                      {"sequence": 48, "distributions": [], "evidence": [{"client": None}]}):
            with self.subTest(wrong=wrong), self.assertRaises(PromotionDenied):
                require_pi_free_snapshot(wrong, 48)


if __name__ == "__main__":
    unittest.main()
