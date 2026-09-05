from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from scripts.build_registry import directory_tree_digest, digest_bytes
from scripts.directory_publication import PublicationError, canonical_json
from scripts.security_index import (
    SCANNER,
    assessment_from_report,
    build_security_candidate,
    policy,
    previous_records,
)
import scripts.security_publication as security_publication


def git(directory: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=directory, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def make_lintai(root: Path, findings: list[dict[str, object]] | None = None, *, fail_scan: bool = False) -> Path:
    executable = root / "lintai"
    report = {
        "schema_version": 1,
        "tool": SCANNER,
        "policy": {"id": "agent-plugin-install", "version": 1, "preset": "recommended"},
        "stats": {"scanned_files": 2},
        "findings": findings or [],
        "diagnostics": [],
        "runtime_errors": [],
    }
    source = f"""#!{sys.executable}
import json, sys
if sys.argv[1:] == ['version']:
    print('lintai 0.1.2')
    raise SystemExit(0)
if sys.argv[1] == 'scan-agent-plugin':
    if {fail_scan!r}:
        raise SystemExit(99)
    print(json.dumps({report!r}, separators=(',', ':')))
    raise SystemExit({1 if findings else 0})
raise SystemExit(2)
"""
    executable.write_text(source, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def make_discovery(root: Path) -> tuple[dict[str, object], Path]:
    source = root / "source"
    package = source / "packages" / "demo"
    package.mkdir(parents=True)
    manifest = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "demo",
        "version": "1.2.3",
        "description": "Security index fixture",
        "author": {"name": "Fixture"},
        "repository": "https://github.com/owner/repo",
        "license": "Apache-2.0",
    }
    (package / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
    (package / "mcp.json").write_text(json.dumps({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"demo": {"type": "streamable-http", "url": "https://example.test/mcp"}},
    }), encoding="utf-8")
    git(source, "init", "--quiet", "--initial-branch=main")
    git(source, "config", "user.email", "fixture@example.test")
    git(source, "config", "user.name", "Fixture")
    git(source, "add", ".")
    git(source, "commit", "--quiet", "-m", "fixture")
    revision = git(source, "rev-parse", "HEAD")
    mirror_root = root / "mirrors"
    bare = mirror_root / "owner" / "repo.git"
    bare.parent.mkdir(parents=True)
    subprocess.run(["git", "clone", "--quiet", "--bare", str(source), str(bare)], check=True)
    record = {
        "slug": "discovery:owner/repo//packages/demo",
        "name": "demo", "description": "Security index fixture", "owner": "owner",
        "repository": "owner/repo", "package_path": "packages/demo", "revision": revision,
        "version": "1.2.3", "license": "Apache-2.0", "schema_version": "1.0.0",
        "components": {"extensions": 0, "mcp": 1, "skills": 0},
        "mcp_transports": ["streamable-http"],
        "compatible_clients": ["codex", "cursor", "copilot", "vscode", "kiro"],
        "authentication": "unknown", "status": "conformant_unreviewed", "runtime_reviewed": False,
        "tree_digest": directory_tree_digest(package),
        "manifest_digest": digest_bytes((package / "plugin.json").read_bytes()),
        "stars": 42, "repository_updated_at": "2026-09-05T00:00:00Z",
        "reviewed_distribution_id": None, "availability": "available",
        "author": {"name": "Fixture"}, "first_seen": "2026-09-05T00:00:00Z",
        "last_seen": "2026-09-05T00:00:00Z",
    }
    discovery = {
        "discovery_schema_version": 1, "sequence": 20, "publication_id": "fixture-20",
        "source_commit": "a" * 40, "generated_at": "2026-09-05T00:00:00Z",
        "expires_at": "2026-09-08T00:00:00Z", "complete": True,
        "query_manifest_digest": "sha256:" + "3" * 64, "partitions": [],
        "search_projection": {
            "path": "search/00000000000000000020.json",
            "digest": "sha256:" + "4" * 64, "record_count": 1,
        },
        "records": [record],
    }
    return discovery, mirror_root


def finding(code: str, *, severity: str = "warn", confidence: str = "high") -> dict[str, object]:
    return {
        "rule_code": code, "severity": severity, "confidence": confidence,
        "category": "security", "message": f"finding {code}",
        "location": {"normalized_path": "mcp.json", "start": {"line": 2}},
    }


class SecurityIndexTests(unittest.TestCase):
    def test_policy_digest_is_the_cross_language_contract(self) -> None:
        self.assertEqual(
            policy()["digest"],
            "sha256:41d3640d31eac89e7b30777bbbe937b307908e4a8d7c29a3a0edca49cfe1d755",
        )

    def test_report_preserves_counts_and_applies_narrow_blocking_policy(self) -> None:
        record = {"tree_digest": "sha256:" + "1" * 64, "manifest_digest": "sha256:" + "2" * 64}
        body = json.dumps({
            "schema_version": 1, "tool": SCANNER,
            "policy": {"id": "agent-plugin-install", "version": 1},
            "stats": {"scanned_files": 3},
            "findings": [finding("SEC330"), finding("SEC301"), finding("SEC330", confidence="medium")],
            "runtime_errors": [],
        }, separators=(",", ":")).encode()
        result = assessment_from_report(record, body)
        self.assertEqual(result["outcome"], "blocking_findings")
        self.assertEqual(result["counts"], {"blocking": 1, "warnings": 2, "total": 3})
        self.assertEqual(result["report_digest"], digest_bytes(body))

    def test_builder_scans_exact_materialized_subject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            discovery, mirrors = make_discovery(root)
            lintai = make_lintai(root, [finding("SEC301")])
            candidate = build_security_candidate(
                discovery, lintai, {}, discovery["generated_at"], mirror_root=mirrors, workers=1,
            )
        self.assertTrue(candidate["complete"])
        self.assertEqual(candidate["coverage"], {"subjects": 1, "checked": 1, "unavailable": 0})
        self.assertEqual(candidate["records"][0]["subject"], {
            "tree_digest": discovery["records"][0]["tree_digest"],
            "manifest_digest": discovery["records"][0]["manifest_digest"],
        })
        self.assertEqual(candidate["records"][0]["outcome"], "warnings")

    def test_exact_previous_subject_skips_scan_but_scanner_mismatch_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            discovery, mirrors = make_discovery(root)
            lintai = make_lintai(root, fail_scan=True)
            cached = {
                "subject": {
                    "tree_digest": discovery["records"][0]["tree_digest"],
                    "manifest_digest": discovery["records"][0]["manifest_digest"],
                },
                "outcome": "no_blocking_findings", "counts": {"blocking": 0, "warnings": 0, "total": 0},
                "scanned_files": 2, "report_digest": "sha256:" + "9" * 64, "findings": [],
            }
            candidate = build_security_candidate(
                discovery, lintai, {(cached["subject"]["tree_digest"], cached["subject"]["manifest_digest"]): cached},
                discovery["generated_at"], mirror_root=mirrors, workers=1,
            )
            self.assertEqual(candidate["records"], [cached])
            previous = root / "previous.json"
            previous.write_bytes(canonical_json({
                "security_schema_version": 1, "sequence": 1, "publication_id": "fixture",
                "source_commit": "b" * 40, "generated_at": "2026-09-05T00:00:00Z",
                "expires_at": "2026-10-05T00:00:00Z", "complete": True,
                "discovery": {"sequence": 20, "snapshot_digest": "sha256:" + "7" * 64},
                "scanner": {"id": "lintai", "version": "0.1.1"}, "policy": policy(),
                "coverage": {"subjects": 1, "checked": 1, "unavailable": 0}, "records": [cached],
            }))
            self.assertEqual(previous_records(previous), {})


class SecurityPublicationTests(unittest.TestCase):
    def test_signed_feed_is_append_only_and_domain_separated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            feed = root / "security"
            feed.mkdir()
            seed = bytes(range(32))
            private = Ed25519PrivateKey.from_private_bytes(seed)
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            trusted = root / "trusted.json"
            trusted.write_bytes(canonical_json({
                "schema_version": 1,
                "keys": [{"key_id": "security-test", "public_key": base64.b64encode(public).decode("ascii")}],
            }))
            candidate = root / "candidate.json"
            candidate.write_bytes(canonical_json({
                "candidate_schema_version": 1, "generated_at": "2026-09-05T00:00:00Z", "complete": True,
                "discovery": {"sequence": 20, "snapshot_digest": "sha256:" + "7" * 64},
                "scanner": SCANNER, "policy": policy(),
                "coverage": {"subjects": 0, "checked": 0, "unavailable": 0}, "records": [],
            }))

            def verify(public_bytes: bytes, message: bytes, signature: bytes) -> None:
                Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)

            with mock.patch.object(security_publication, "ed25519_sign", side_effect=lambda _seed, message: private.sign(message)), \
                 mock.patch.object(security_publication, "ed25519_verify", side_effect=verify):
                first = security_publication.publish(
                    candidate, feed, trusted, seed, "security-test", "run-1", "c" * 40, 30,
                )
                self.assertEqual(first["sequence"], 1)
                snapshot, latest = security_publication.load_latest(feed, trusted)
                self.assertEqual(snapshot["sequence"], latest["sequence"])
                envelope = json.loads((feed / latest["envelope_path"]).read_text())
                self.assertEqual(envelope["signature_domain"], "UAP-SECURITY-INDEX-ED25519-V1")
                self.assertNotEqual(
                    security_publication.signature_message((feed / latest["snapshot_path"]).read_bytes()),
                    b"UAP-DISCOVERY-INDEX-ED25519-V1\0" + len((feed / latest["snapshot_path"]).read_bytes()).to_bytes(8, "big") + (feed / latest["snapshot_path"]).read_bytes(),
                )
                body = (feed / latest["snapshot_path"]).read_bytes()
                tampered = json.loads(body)
                tampered["publication_id"] = "tampered"
                with self.assertRaisesRegex(PublicationError, "digest mismatch"):
                    security_publication.verify_bundle(
                        canonical_json(tampered), (feed / latest["envelope_path"]).read_bytes(), trusted,
                    )


if __name__ == "__main__":
    unittest.main()
