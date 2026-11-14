"""Fixed schema-1 lineages, using existing test keys only in disposable trees."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FIXTURES = ROOT / "tests" / "fixtures" / "directory-publication"
sys.path.insert(0, str(SCRIPTS))

import directory_publication as publication
import directory_publication_cas as cas
import sign_directory_publication as signer
from directory_feed_contract import LEGACY_FEED, MODERN_FEED, fixed_feed, reviewed_source_path


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_bytes())


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(publication.canonical_json(value))


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


class FixedFeedContractTests(unittest.TestCase):
    def test_package_imports_preserve_profile_and_error_identity(self) -> None:
        from scripts import directory_feed_contract as feeds
        from scripts import directory_publication as package_publication
        from scripts import directory_publication_cas as package_cas
        from scripts import prepare_directory_publication as package_prepare
        from scripts import prepare_modern_directory_publication as package_prepare_entry
        from scripts import publication_trust_policy as package_trust
        from scripts import sign_directory_publication as package_sign
        from scripts import sign_modern_directory_publication as package_sign_entry

        self.assertIs(package_prepare_entry.main, package_prepare.main)
        self.assertIs(package_sign_entry.main, package_sign.main)
        self.assertIs(package_prepare.PublicationError, package_publication.PublicationError)
        self.assertIs(package_sign.PublicationError, package_publication.PublicationError)
        self.assertIs(package_trust.require, package_publication.require)
        self.assertEqual(package_sign.snapshot_evidence_for_sequence([], [], 1, feed=feeds.MODERN_FEED), [])
        candidate = fixture("candidate.json")
        candidate["distributions"][0]["release_policies"][0]["targets"][0]["client"] = "hermes"
        package_sign.validate_bound_candidate(candidate, feed=feeds.MODERN_FEED)
        with self.assertRaises(package_publication.PublicationError):
            package_sign.validate_bound_candidate(candidate)
        # An invalid source must reach the schema gate, not reject the fixed
        # modern profile because a sibling imported a second module identity.
        with self.assertRaises(package_publication.PublicationError):
            package_prepare.build_candidate({}, {}, "a" * 40, "test", None, feed=feeds.MODERN_FEED)
        with self.assertRaisesRegex(package_cas.CasError, "wrong feed tag namespace"):
            package_cas.validate_signed_directory_append(ROOT, "a" * 40, "b" * 40,
                                                         "invalid", feed=feeds.MODERN_FEED)
        with self.assertRaisesRegex(ValueError, "fixed trusted entrypoint"):
            package_sign.snapshot_evidence_for_sequence([], [], 1, feed=replace(feeds.MODERN_FEED))

    def test_legacy_schema_public_definition_fragments_still_resolve(self) -> None:
        snapshot = fixture("snapshot.json")
        cases = {
            "timestamp": (snapshot["generated_at"], "not-a-timestamp"),
            "release": (snapshot["distributions"][0]["releases"][0], {"sequence": 1}),
            "distribution": (snapshot["distributions"][0], {"id": "example/demo"}),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "external-reference.schema.json"
            for name, (valid, invalid) in cases.items():
                write_json(path, {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "$ref": "https://agent-plugins.org/schemas/directory-snapshot.schema.json#/$defs/" + name,
                })
                with self.subTest(fragment=name):
                    publication.validate_with_schema(valid, path)
                    with self.assertRaises(publication.PublicationError):
                        publication.validate_with_schema(invalid, path)

    def test_profile_cannot_be_reconstructed_or_selected_by_candidate(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            MODERN_FEED.name = "legacy"  # type: ignore[misc]
        for feed in (LEGACY_FEED, MODERN_FEED):
            self.assertIs(fixed_feed(feed), feed)
            with self.assertRaisesRegex(ValueError, "fixed trusted entrypoint"):
                fixed_feed(replace(feed))
        candidate = fixture("candidate.json")
        candidate["feed"] = "modern"
        with self.assertRaisesRegex(publication.PublicationError, "candidate fields"):
            signer.validate_bound_candidate(candidate)
        for field in ("feed_path", "ledger_ref", "sequence_tag_prefix", "trusted_keys_path",
                      "trust_config_path", "private_key_environment"):
            self.assertNotEqual(getattr(LEGACY_FEED, field), getattr(MODERN_FEED, field))

    def test_modern_known_clients_do_not_expand_legacy_or_allow_unknown_ids(self) -> None:
        for client in ("hermes", "antigravity", "pi"):
            candidate = fixture("candidate.json")
            candidate["distributions"][0]["release_policies"][0]["targets"][0]["client"] = client
            candidate["evidence"][0]["client"] = client
            with self.subTest(client=client):
                signer.validate_bound_candidate(candidate, feed=MODERN_FEED)
                with self.assertRaisesRegex(publication.PublicationError, "historical Directory"):
                    signer.validate_bound_candidate(candidate)
                candidate["evidence"][0]["client"] = "future-agent"
                with self.assertRaises(publication.PublicationError):
                    signer.validate_bound_candidate(candidate, feed=MODERN_FEED)

    def test_evidence_cutover_is_per_lineage_with_shared_schema_one_records(self) -> None:
        modern = fixture("snapshot.json")
        modern["sequence"] = 1
        legacy = copy.deepcopy(modern)
        legacy["evidence"] = signer.snapshot_evidence_for_sequence(
            modern["evidence"], modern["distributions"], 1,
        )
        self.assertEqual(legacy["evidence"], signer.snapshot_evidence_for_sequence(
            modern["evidence"], modern["distributions"], 1, feed=LEGACY_FEED,
        ))
        self.assertEqual(modern["evidence"], signer.snapshot_evidence_for_sequence(
            modern["evidence"], modern["distributions"], 1, feed=MODERN_FEED,
        ))
        for validate_schema in (True, False):
            with self.subTest(schema=validate_schema):
                publication.validate_snapshot_semantics(modern, feed=MODERN_FEED, validate_schema=validate_schema)
                publication.validate_snapshot_semantics(legacy, validate_schema=validate_schema)
                with self.assertRaises(publication.PublicationError):
                    publication.validate_snapshot_semantics(modern, validate_schema=validate_schema)
                with self.assertRaises(publication.PublicationError):
                    publication.validate_snapshot_semantics(legacy, feed=MODERN_FEED, validate_schema=validate_schema)
        # The unchanged signed current-evidence fixture still validates as legacy sequence 15.
        publication.validate_snapshot_semantics(fixture("snapshot.json"))

    def test_modern_key_trust_is_fixed_and_disjoint_by_id_and_bytes(self) -> None:
        keys = fixture("trusted-keys.json")["keys"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_path = root / LEGACY_FEED.trusted_keys_path
            modern_path = root / MODERN_FEED.trusted_keys_path
            write_json(legacy_path, {"schema_version": 1, "keys": [keys[0]]})
            write_json(modern_path, {"schema_version": 1, "keys": [keys[1]]})
            with mock.patch.object(publication, "ROOT", root):
                self.assertEqual(set(publication.load_feed_trusted_keys(modern_path, MODERN_FEED)), {"test-next"})
                with self.assertRaisesRegex(publication.PublicationError, "fixed reviewed-source"):
                    publication.load_feed_trusted_keys(legacy_path, MODERN_FEED)
                for entry in (keys[0], {**keys[1], "key_id": keys[0]["key_id"]},
                              {**keys[0], "key_id": "renamed-legacy"}):
                    write_json(modern_path, {"schema_version": 1, "keys": [entry]})
                    with self.subTest(key=entry["key_id"]), self.assertRaisesRegex(
                        publication.PublicationError, "independent of legacy",
                    ):
                        publication.load_feed_trusted_keys(modern_path, MODERN_FEED)
                modern_path.unlink()
                modern_path.symlink_to(legacy_path)
                with self.assertRaisesRegex(ValueError, "reviewed-source path"):
                    publication.load_feed_trusted_keys(modern_path, MODERN_FEED)
            config = root / MODERN_FEED.trust_config_path
            config.symlink_to(legacy_path)
            with self.assertRaisesRegex(ValueError, "reviewed-source path"):
                reviewed_source_path(root, MODERN_FEED.trust_config_path)

    def test_unprovisioned_modern_entrypoints_fail_before_artifact_or_secret_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = ["--ledger", str(root / "ledger")]
            cases = {
                "prepare_modern_directory_publication.py": [
                    "--directory", str(root / "missing.json"), "--source-commit", "a" * 40,
                    "--publication-id", "test", "--output", str(root / "candidate.json"),
                    "--digest-output", str(root / "digest.txt"),
                ],
                "sign_modern_directory_publication.py": [
                    "--candidate", str(root / "missing.json"), "--candidate-digest", "sha256:" + "a" * 64,
                    "--key-id", "test-next", "--now", "2026-08-20T00:00:00Z",
                    "--result", str(root / "result.json"),
                ],
            }
            for script, args in cases.items():
                for extra in ([], ["--config", "untrusted.json"], ["--trusted-keys", "untrusted.json"],
                              ["--feed", "legacy"]):
                    with self.subTest(script=script, extra=extra):
                        result = subprocess.run(
                            [sys.executable, "-I", str(SCRIPTS / script), *args, *common, *extra],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        if extra:
                            self.assertIn("unrecognized arguments", result.stderr)
                        else:
                            self.assertIn(MODERN_FEED.trust_config_path, result.stderr)
                            self.assertNotIn("missing.json", result.stderr)
                        self.assertEqual(list(root.iterdir()), [])


class ModernSignerBoundaryTests(unittest.TestCase):
    def test_disposable_signing_append_retry_and_lineage_isolation(self) -> None:
        # Copy trusted code into a disposable source tree. Existing fixture keys
        # are provisioned there only; repository production trust stays absent.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            scripts = source / "scripts"
            scripts.mkdir(parents=True)
            for name in ("sign_modern_directory_publication.py", "sign_directory_publication.py",
                         "directory_publication.py", "directory_feed_contract.py", "client_contract.py",
                         "legacy_directory_client_boundary.py", "publication_trust_policy.py", "sequence_boundaries.py"):
                shutil.copyfile(SCRIPTS / name, scripts / name)
            (source / "registry").mkdir()
            for name in ("client-capabilities.json", "client-capabilities.lock.json"):
                shutil.copyfile(ROOT / "registry" / name, source / "registry" / name)
            keys = fixture("trusted-keys.json")["keys"]
            write_json(source / LEGACY_FEED.trusted_keys_path, {"schema_version": 1, "keys": [keys[0]]})
            write_json(source / MODERN_FEED.trusted_keys_path, {"schema_version": 1, "keys": [keys[1]]})
            config = json.loads((ROOT / LEGACY_FEED.trust_config_path).read_bytes())
            write_json(source / MODERN_FEED.trust_config_path, config)
            candidate = fixture("candidate.json")
            policy = candidate["distributions"][0]["release_policies"][0]
            policy["targets"] = [{**policy["targets"][0], "client": "hermes"}]
            record = candidate["evidence"][0]
            record["client"] = "hermes"
            record["level"] = "materialization"
            record["artifact"]["repository"] = "777genius/universal-agent-plugins"
            record["trust"] = {
                "kind": "github_actions",
                "workflow": "777genius/universal-agent-plugins/.github/workflows/launch-evidence-e2e.yml",
                "source_ref": "refs/heads/main", "source_digest": record["artifact"]["revision"],
            }
            write_json(root / "candidate.json", candidate)
            ledger = root / "ledger"
            legacy_artifact = ledger / LEGACY_FEED.feed_path / "snapshots" / "00000000000000000015.json"
            legacy_artifact.parent.mkdir(parents=True)
            legacy_bytes = (FIXTURES / "snapshot.json").read_bytes()
            legacy_artifact.write_bytes(legacy_bytes)
            git(ledger, "init", "-q")
            git(ledger, "config", "user.name", "Fixture")
            git(ledger, "config", "user.email", "fixture@example.test")
            git(ledger, "add", ".")
            git(ledger, "commit", "-qm", "seed")
            seed_commit = git(ledger, "rev-parse", "HEAD")

            def sign(*args: str, key_id: str = "test-next", modern_secret: bool = True,
                     now: str = "2026-08-20T00:00:00Z") -> subprocess.CompletedProcess[str]:
                environment = os.environ.copy()
                environment.pop(MODERN_FEED.private_key_environment, None)
                # A legacy secret cannot substitute for the modern credential.
                environment[LEGACY_FEED.private_key_environment] = fixture("test-private-seeds.json")["test-current"]
                if modern_secret:
                    environment[MODERN_FEED.private_key_environment] = fixture("test-private-seeds.json")[key_id]
                return subprocess.run([
                    sys.executable, "-I", str(scripts / "sign_modern_directory_publication.py"),
                    "--candidate", str(root / "candidate.json"), "--candidate-digest",
                    publication.candidate_digest((root / "candidate.json").read_bytes()),
                    "--ledger", str(ledger), "--key-id", key_id,
                    "--now", now, "--result", str(root / "result.json"),
                    "--ledger-seed-commit", seed_commit, *args,
                ], env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

            missing = sign("--initialize-ledger", modern_secret=False)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn(MODERN_FEED.private_key_environment + " is not set", missing.stderr)
            wrong_key = sign("--initialize-ledger", key_id="test-current")
            self.assertNotEqual(wrong_key.returncode, 0)
            self.assertIn("not trusted", wrong_key.stderr)
            self.assertFalse((ledger / MODERN_FEED.feed_path).exists())
            signed = sign("--initialize-ledger")
            self.assertEqual(signed.returncode, 0, signed.stderr)
            trusted = publication.load_public_keys(source / MODERN_FEED.trusted_keys_path)
            loaded = publication.load_ledger_latest(ledger, trusted, seed_commit=seed_commit,
                                                    minimum_sequence=1, feed=MODERN_FEED)
            self.assertEqual(loaded[0]["sequence"], 1)
            self.assertEqual(loaded[0]["evidence"][0]["trust"], record["trust"])
            with self.assertRaises(publication.PublicationError):
                publication.load_ledger_latest(ledger, trusted)
            with self.assertRaisesRegex(publication.PublicationError, "immutable tag floor"):
                publication.load_ledger_latest(ledger, trusted, minimum_sequence=2, feed=MODERN_FEED)
            with self.assertRaisesRegex(publication.PublicationError, "unknown signing key"):
                publication.load_ledger_latest(ledger, publication.load_public_keys(source / LEGACY_FEED.trusted_keys_path), feed=MODERN_FEED)
            contract_path = ledger / MODERN_FEED.feed_path / "ledger-contract.json"
            contract = json.loads(contract_path.read_bytes())
            write_json(contract_path, {**contract, "sequence_tag_prefix": LEGACY_FEED.sequence_tag_prefix})
            with self.assertRaisesRegex(publication.PublicationError, "namespace marker"):
                publication.load_ledger_latest(ledger, trusted, feed=MODERN_FEED)
            write_json(contract_path, contract)
            first = ledger / MODERN_FEED.feed_path / "snapshots" / "00000000000000000001.json"
            first_bytes = first.read_bytes()
            git(ledger, "add", ".")
            git(ledger, "commit", "-qm", "chore(directory): publish signed snapshot")
            signed_commit = git(ledger, "rev-parse", "HEAD")
            tag = MODERN_FEED.sequence_ref_prefix + "00000000000000000001"
            cas.validate_signed_directory_append(ledger, seed_commit, signed_commit, tag, feed=MODERN_FEED)
            with self.assertRaisesRegex(cas.CasError, "wrong feed tag namespace"):
                cas.validate_signed_directory_append(ledger, seed_commit, signed_commit, tag)
            with self.assertRaisesRegex(cas.CasError, "exact immutable publication shape"):
                cas.validate_signed_directory_append(ledger, seed_commit, signed_commit,
                                                     LEGACY_FEED.sequence_ref_prefix + "00000000000000000001")
            git(ledger, "tag", tag.removeprefix("refs/tags/"))
            retry = sign("--initialize-ledger")
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertTrue(json.loads((root / "result.json").read_bytes())["reused"])
            candidate["publication_id"] = "fixture-2"
            write_json(root / "candidate.json", candidate)
            stale = sign("--ledger-sequence-floor", "2")
            self.assertNotEqual(stale.returncode, 0)
            second = sign("--ledger-sequence-floor", "1", now="2026-08-21T00:00:00Z")
            self.assertEqual(second.returncode, 0, second.stderr)
            publication.load_ledger_latest(ledger, trusted, minimum_sequence=2, feed=MODERN_FEED)
            self.assertEqual(first.read_bytes(), first_bytes)
            self.assertEqual(legacy_artifact.read_bytes(), legacy_bytes)


if __name__ == "__main__":
    unittest.main()
