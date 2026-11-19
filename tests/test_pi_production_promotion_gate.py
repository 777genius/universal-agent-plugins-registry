"""Promotion never treats unsigned/synthetic Pi eligibility as signed saved E2E."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from directory_publication import candidate_digest, canonical_json
from pi_production_promotion_gate import (
    PromotionDenied, require_pi_free_candidate, require_pi_free_ledger,
    require_pi_free_snapshot,
)


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

    def test_pre_sign_candidate_exact_digest_and_pi_denial(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            candidate_path = Path(temp) / "candidate.json"
            safe = {"distributions": snapshot()["distributions"], "evidence": snapshot()["evidence"]}
            safe_bytes = canonical_json(safe)
            candidate_path.write_bytes(safe_bytes)
            require_pi_free_candidate(candidate_path, candidate_digest(safe_bytes))
            with self.assertRaisesRegex(PromotionDenied, "digest differs"):
                require_pi_free_candidate(candidate_path, "sha256:" + "0" * 64)
            with self.assertRaisesRegex(PromotionDenied, "canonical"):
                candidate_path.write_bytes(json.dumps(safe).encode("utf-8"))
                require_pi_free_candidate(candidate_path, candidate_digest(candidate_path.read_bytes()))
            for target in (True, False):
                pi = json.loads(json.dumps(safe))
                if target:
                    pi["distributions"][0]["release_policies"][0]["targets"][0]["client"] = "pi"
                else:
                    pi["evidence"].append({"id": "unreferenced-pi", "client": "pi"})
                pi_bytes = canonical_json(pi)
                candidate_path.write_bytes(pi_bytes)
                with self.subTest(target=target), self.assertRaisesRegex(PromotionDenied, "72/72 production signed saved"):
                    require_pi_free_candidate(candidate_path, candidate_digest(pi_bytes))
            candidate_path.unlink()
            candidate_path.symlink_to(Path(temp) / "missing")
            with self.assertRaisesRegex(PromotionDenied, "symlink"):
                require_pi_free_candidate(candidate_path, "sha256:" + "0" * 64)

    def test_pre_sign_gate_runs_before_private_key_step(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/directory-publication.yml").read_text(encoding="utf-8")
        sign_job = workflow.split("\n  sign:\n", 1)[1].split("\n  completed_rerun:\n", 1)[0]
        gate = sign_job.index("- name: Deny Pi candidate before private signing seed")
        signing = sign_job.index("- name: Validate candidate digest, sequence, and sign")
        self.assertLess(gate, signing)
        pre_sign_step = sign_job[gate:signing]
        self.assertIn("if: inputs.resume_publication_id == ''", pre_sign_step)
        self.assertIn("--candidate ../candidate/candidate.json", pre_sign_step)
        self.assertIn('--candidate-digest "${EXPECTED_CANDIDATE_DIGEST}"', pre_sign_step)
        self.assertNotIn("DIRECTORY_ED25519_PRIVATE_KEY", pre_sign_step)

    def test_signed_ledger_publish_is_gated_before_publisher_token(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/directory-publication.yml").read_text(encoding="utf-8")
        materialize = workflow.split("\n  materialize_site:\n", 1)[1].split(
            "\n  gate_exact_staged_publication:\n", 1
        )[0]
        gate = materialize.index("trusted-source/scripts/pi_production_promotion_gate.py")
        token = materialize.index("- name: Acquire dedicated publisher token")
        publish = materialize.index("- name: Publish the signed and materialized commits with exact CAS")
        self.assertLess(gate, token)
        self.assertLess(token, publish)
        self.assertIn('--ledger ledger --sequence "$EXPECTED_SEQUENCE"', materialize)
        # Resumed publication skips the signed bundle checkout, but still
        # needs the trusted gate source before a publisher token is minted.
        checkout = materialize.split("- uses: actions/checkout@", 1)[1].split(
            "- uses: actions/setup-python@", 1
        )[0]
        self.assertIn("path: trusted-source", checkout)
        self.assertNotIn("if: inputs.resume_publication_id == ''", checkout)


if __name__ == "__main__":
    unittest.main()
