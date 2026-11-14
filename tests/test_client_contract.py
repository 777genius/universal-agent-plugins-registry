"""Released client identity, provenance, schema drift and legacy isolation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_registry import CLIENT_IDS, RegistryError, resolve_directory
from client_contract import (
    CONTRACT_PATH, LOCK_PATH, SOURCE_PATH, ClientContractError, load_client_ids,
)
from directory_publication import CLIENTS, PublicationError
from legacy_directory_client_boundary import require_legacy_directory_clients
from sync_client_contract import SCHEMA_CLIENT_ENUMS, generated_schema, sync_schemas, update_pin


class ClientContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="uap-client-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in (CONTRACT_PATH, LOCK_PATH, *(
            Path("schemas") / f"{name}.schema.json" for name in SCHEMA_CLIENT_ENUMS
        )):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.lock = json.loads((self.root / LOCK_PATH).read_bytes())

    def write_contract(self, body: bytes) -> None:
        (self.root / CONTRACT_PATH).write_bytes(body)
        self.lock["digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
        (self.root / LOCK_PATH).write_text(json.dumps(self.lock), encoding="utf-8")

    def test_consumers_and_generated_schemas_match_the_released_contract_offline(self) -> None:
        with mock.patch("socket.socket", side_effect=AssertionError("offline contract opened a socket")):
            clients = load_client_ids(self.root)
            self.assertEqual(CLIENT_IDS, clients)
            self.assertEqual(CLIENTS, frozenset(clients))
            self.assertTrue({"hermes", "antigravity", "pi"}.issubset(clients))
            self.assertEqual(sync_schemas(self.root), [])

    def test_changed_artifact_bytes_cannot_silently_change_client_admission(self) -> None:
        with (self.root / CONTRACT_PATH).open("ab") as output:
            output.write(b" ")
        with self.assertRaisesRegex(ClientContractError, "digest differs"):
            load_client_ids(self.root)

    def test_publication_package_import_does_not_depend_on_script_path_injection(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "from scripts.directory_publication import CLIENTS; assert 'pi' in CLIENTS"],
            cwd=ROOT, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))

    def test_pin_requires_exact_release_source_and_commit(self) -> None:
        cases = {
            "revision": "main", "release": "latest", "repository": "other/repository",
            "path": "../client.json", "schema_version": True,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                pin = {**self.lock, field: value}
                (self.root / LOCK_PATH).write_text(json.dumps(pin), encoding="utf-8")
                with self.assertRaises(ClientContractError):
                    load_client_ids(self.root)

    def test_even_a_matching_digest_cannot_admit_ambiguous_or_malformed_ids(self) -> None:
        for body in (
            b'[{"id":"codex","id":"pi"}]', b'[{"id":"pi"},{"id":"pi"}]',
            b'[{"id":"Pi"}]', b'[{"id":"../pi"}]', b'[{"id":true}]',
            b'[{"id":"future--agent"}]', b'[{"id":"future-"}]',
            b'[]', b'{}', b'[{"id":"pi","invalid":NaN}]',
            '[{"id":"pi"}]'.encode("utf-16"),
        ):
            with self.subTest(body=body):
                self.write_contract(body)
                with self.assertRaises(ClientContractError):
                    load_client_ids(self.root)

    def test_a_new_released_client_updates_all_schemas_but_not_legacy_authority(self) -> None:
        rows = json.loads((self.root / CONTRACT_PATH).read_bytes())
        rows.append({**rows[-1], "id": "future-agent"})
        self.write_contract(json.dumps(rows).encode("utf-8"))
        original = {name: (self.root / "schemas" / f"{name}.schema.json").read_bytes()
                    for name in SCHEMA_CLIENT_ENUMS}
        self.assertEqual(len(sync_schemas(self.root)), len(SCHEMA_CLIENT_ENUMS))
        for name, body in original.items():
            self.assertEqual((self.root / "schemas" / f"{name}.schema.json").read_bytes(), body)
        sync_schemas(self.root, write=True)
        self.assertEqual(sync_schemas(self.root), [])
        for name, pointers in SCHEMA_CLIENT_ENUMS.items():
            schema = json.loads((self.root / "schemas" / f"{name}.schema.json").read_bytes())
            for pointer in pointers:
                value = schema
                for part in pointer.split("/"):
                    value = value[part]
                self.assertEqual(tuple(value), load_client_ids(self.root))
        with self.assertRaisesRegex(PublicationError, "historical Directory v1 publisher"):
            require_legacy_directory_clients([], [{"client": "future-agent"}])

    def test_schema_generation_refuses_to_modify_an_unrelated_matching_enum(self) -> None:
        body = b'{"client":{"enum":["codex"]},"unrelated":{"enum":["codex"]}}'
        with self.assertRaisesRegex(ClientContractError, "unexpected schema field"):
            generated_schema(body, ("client/enum",), ("codex", "pi"))

    def test_schema_generation_refuses_missing_pointers(self) -> None:
        with self.assertRaisesRegex(ClientContractError, "pointer is absent"):
            generated_schema(b'{}', ("client/enum",), ("pi",))

    def test_installer_capability_never_adds_a_package_grant(self) -> None:
        source = json.loads((ROOT / "registry" / "directory.json").read_bytes())
        for client in ("hermes", "antigravity", "pi"):
            self.assertIn(client, CLIENT_IDS)
            with self.subTest(client=client), self.assertRaises(RegistryError):
                resolve_directory(source, "context7", [client])

    def test_pin_update_reads_the_committed_release_not_dirty_working_content(self) -> None:
        checkout = self.root / "upstream"
        checkout.mkdir()

        def git(*arguments: str) -> bytes:
            return subprocess.run(["git", "-C", str(checkout), *arguments],
                                  check=True, capture_output=True).stdout

        git("init", "-q")
        artifact = checkout / SOURCE_PATH
        artifact.parent.mkdir(parents=True)
        expected = (ROOT / CONTRACT_PATH).read_bytes()
        artifact.write_bytes(expected)
        git("add", SOURCE_PATH)
        git("-c", "user.name=Contract test", "-c", "user.email=contract@example.invalid",
            "commit", "-q", "-m", "Committed release contract")
        git("tag", "agentplugins-v0.1.108")
        revision = git("rev-parse", "HEAD").decode("ascii").strip()
        artifact.write_bytes(b'[{"id":"unreleased-agent"}]')
        with self.assertRaisesRegex(ClientContractError, "differs from the reviewed"):
            update_pin(self.root, checkout, "agentplugins-v0.1.108", "0" * 40)
        update_pin(self.root, checkout, "agentplugins-v0.1.108", revision)
        self.assertEqual((self.root / CONTRACT_PATH).read_bytes(), expected)
        pin = json.loads((self.root / LOCK_PATH).read_bytes())
        self.assertEqual(pin["revision"], revision)
        self.assertEqual(load_client_ids(self.root), CLIENT_IDS)


if __name__ == "__main__":
    unittest.main()
