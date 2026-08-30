import fcntl
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "uap_observer_reset", ROOT / "deploy/uap-observer-reset.py",
)
assert SPEC is not None and SPEC.loader is not None
reset = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reset
SPEC.loader.exec_module(reset)


MACHINE = "a" * 32
OLD_INSTALL = "b" * 64
OLD_CLOSURE = "c" * 64
NEW_INSTALL = "d" * 64
NEW_CLOSURE = "e" * 64


class FakeSystemd:
    def __init__(self, *, public_active: bool = True, recreate_failure: bool = False):
        self.states = {
            unit: {"active": True, "enabled": unit != reset.PUBLIC_HOP_UNIT}
            for unit in reset.ALL_UNITS
        }
        self.states[reset.PUBLIC_HOP_UNIT] = {"active": public_active, "enabled": False}
        self.recreate_failure = recreate_failure
        self.events = []
        self.public_closure = OLD_CLOSURE if public_active else None

    def state(self, unit):
        return dict(self.states[unit])

    def stop(self, units):
        self.events.append(("stop", tuple(units)))
        for unit in units:
            self.states[unit]["active"] = False

    def start(self, units):
        self.events.append(("start", tuple(units)))
        for unit in units:
            self.states[unit]["active"] = True

    def enable(self, units):
        for unit in units:
            self.states[unit]["enabled"] = True

    def disable(self, units):
        for unit in units:
            self.states[unit]["enabled"] = False

    def daemon_reload(self):
        self.events.append(("daemon-reload",))
        self.states[reset.PUBLIC_HOP_UNIT]["active"] = False

    def validate_public_hop_contract(self):
        return {"contract": "exact-v1"}

    def recreate_public_hop(self, closure):
        self.events.append(("recreate-public-hop", closure))
        if self.recreate_failure:
            raise reset.ResetError("injected public hop recreation failure")
        self.public_closure = closure
        self.states[reset.PUBLIC_HOP_UNIT]["active"] = True

    def verify_public_hop(self, closure):
        if self.public_closure != closure or not self.states[reset.PUBLIC_HOP_UNIT]["active"]:
            raise reset.ResetError("public hop closure differs")


class FailOnce:
    def __init__(self, name):
        self.name = name
        self.triggered = False

    def __call__(self, name):
        if name == self.name and not self.triggered:
            self.triggered = True
            raise reset.InjectedFailure(name)


class FakeExecutor:
    def __init__(self, fixture, *, failure=None):
        self.fixture = fixture
        self.failure = failure
        self.prepare_count = 0

    def prepare_new(self, controller, journal):
        self.prepare_count += 1
        self.fixture.install_candidate(journal["prepared"]["manifest"])
        if self.failure:
            raise reset.ResetError(self.failure)
        managed = (
            "uap-observer-egress-proxy.socket", "uap-observer-runner.socket",
            "uap-observer-signer.service", "uap-observer.service",
            "uap-observer-caddy.service",
        )
        self.fixture.systemd.start(managed)
        self.fixture.systemd.recreate_public_hop(NEW_CLOSURE)
        return {"install_identity": NEW_INSTALL, "closure_digest": NEW_CLOSURE}

    def verify_new(self, controller, journal):
        new = journal["new"]
        controller._validate_install(new["install_identity"], new["closure_digest"])
        self.fixture.systemd.verify_public_hop(new["closure_digest"])


class LockCheckingExecutor(FakeExecutor):
    def prepare_new(self, controller, journal):
        descriptor = os.open(self.fixture.path("/run/lock/uap-observer-install.lock"), os.O_RDWR)
        try:
            with self.fixture.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        return super().prepare_new(controller, journal)


class ProjectionMismatchExecutor(FakeExecutor):
    def prepare_new(self, controller, journal):
        result = super().prepare_new(controller, journal)
        projection = self.fixture.path(
            "/var/lib/uap-observer/proofs/codex/native-projection.json"
        )
        projection.chmod(0o600)
        projection.write_bytes(b'{"client_id":"codex","entries":[{}],"schema_version":2}\n')
        projection.chmod(0o440)
        return result


class ObserverResetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.layout = reset.Layout.for_test(self.root)
        self.systemd = FakeSystemd()
        self._base_filesystem()
        self.executor = FakeExecutor(self)

    def tearDown(self):
        self.temporary.cleanup()

    def path(self, logical):
        return self.layout.path(logical)

    def mkdir(self, logical, mode=0o755):
        path = self.path(logical)
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
        return path

    def file(self, logical, body=b"fixture\n", mode=0o644):
        path = self.path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(mode)
        return path

    def _install(self, install_identity, closure_digest):
        closures = self.mkdir("/opt/uap-observer-closures", 0o755)
        closure = closures / closure_digest
        closure.mkdir()
        closure.chmod(0o755)
        (closure / ".complete").write_text("complete-v1\n")
        (closure / ".install-identity").write_text(install_identity + "\n")
        (closure / "bin").mkdir()
        (closure / "bin" / "caddy").write_text("binary")
        for marker in (closure / ".complete", closure / ".install-identity"):
            marker.chmod(0o644)
        current = self.path("/opt/uap-observer-current")
        current.parent.mkdir(parents=True, exist_ok=True)
        current.symlink_to(f"uap-observer-closures/{closure_digest}")

    def _mutable(self):
        state = self.mkdir("/var/lib/uap-observer", 0o711)
        for name in ("jobs", "profiles", "proofs", "state", "workspaces"):
            (state / name).mkdir()
        for root in ("/var/lib/uap-observer-human", "/var/lib/uap-observer-consent"):
            parent = self.mkdir(root, 0o755)
            for name in ("pending", "reserved", "consumed"):
                (parent / name).mkdir()

    def _units(self):
        systemd = self.mkdir("/etc/systemd/system", 0o755)
        for unit in reset.UNITS:
            path = systemd / unit
            path.write_text("[Unit]\n")
            path.chmod(0o644)
        for name in ("uap-observer.service.d", "uap-observer-runner.service.d"):
            dropin = systemd / name
            dropin.mkdir()
            (dropin / "egress.conf").write_text("[Service]\n")

    def _base_filesystem(self):
        for logical in ("/run/lock", "/proc", "/sys/fs/cgroup/system.slice"):
            self.mkdir(logical)
        self.file("/etc/machine-id", (MACHINE + "\n").encode(), 0o444)
        sentinel = json.dumps({
            "machine_id": MACHINE,
            "purpose": reset.SENTINEL_PURPOSE,
            "schema_version": 1,
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.file("/etc/uap-observer-disposable.json", sentinel, 0o600)
        self.file("/etc/uap-observer-ed25519.key", b"private fixture\n", 0o600)
        self.file("/etc/uap-observer-ed25519.pub", b"public fixture\n", 0o644)
        self.mkdir("/opt/uap-observer-inputs", 0o755)
        self.mkdir("/etc/caddy", 0o755)
        self.mkdir("/var/lib/caddy", 0o700)
        self.mkdir("/var/log/caddy", 0o700)
        self.file("/var/lib/caddy/uap-vm-internal-Caddyfile", b"observer.test {\n}\n", 0o600)
        self.file(
            "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt",
            b"test internal CA\n", 0o644,
        )
        for logical in (
            "/root/caddy_2.11.4_linux_amd64.tar.gz", "/root/Caddyfile",
            "/root/uap-observer-adapter-config.json", "/root/uap-observer.json",
            "/root/uap-observer-egress-allowlist.json",
        ):
            self.file(logical, b"reviewed fixture\n", 0o600)
        self._prepared_bundle()
        self._install(OLD_INSTALL, OLD_CLOSURE)
        self._mutable()
        self._units()

    def _prepared_bundle(self):
        prepared = self.mkdir(reset.PREPARED_ROOT, 0o700)
        for name in reset.PREPARED_INVENTORY:
            child = prepared / name
            child.mkdir()
            child.chmod(0o700)
        evidence = prepared / "evidence"
        source = evidence / "source"
        source.mkdir()
        source.chmod(0o700)
        (source / "fixture").write_text("reviewed source\n")
        (source / "fixture").chmod(0o400)
        clients = {}
        self.projection_bodies = {}
        for index, client in enumerate(reset.CLIENTS, start=1):
            for name in ("seeds", "path"):
                child = prepared / name / client
                child.mkdir()
                child.chmod(0o700)
                artifact = child / "fixture"
                artifact.write_text(f"{name}-{client}\n")
                artifact.chmod(0o400)
            projection_body = json.dumps(
                {"client_id": client, "entries": [], "schema_version": 2},
                sort_keys=True, separators=(",", ":"),
            ).encode() + b"\n"
            self.projection_bodies[client] = projection_body
            projection = "sha256:" + hashlib.sha256(projection_body).hexdigest()
            projection_file = prepared / "projection-digests" / f"{client}.sha256"
            projection_file.write_text(projection + "\n")
            projection_file.chmod(0o400)
            clients[client] = {
                "seed": f"seeds/{client}",
                "seed_digest": "sha256:" + str(index + 3) * 64,
                "projection_digest": projection,
            }
        adapter_config = {
            "clients": {
                client: {
                    "native_projection": {
                        "path": f"/var/lib/uap-observer/proofs/{client}/native-projection.json",
                        "sha256": clients[client]["projection_digest"],
                    },
                }
                for client in reset.CLIENTS
            },
        }
        installer_files = {
            "uap-observer-adapter-config.json": json.dumps(
                adapter_config, sort_keys=True, separators=(",", ":"),
            ).encode() + b"\n",
            "uap-observer.json": b"observer\n",
            "caddy_2.11.4_linux_amd64.tar.gz": b"archive\n",
            "Caddyfile": b"caddy\n",
            "uap-observer-egress-allowlist.json": b"egress\n",
        }
        for name, body in installer_files.items():
            path = evidence / name
            path.write_bytes(body)
            path.chmod(0o400)
        def digest(name):
            return "sha256:" + hashlib.sha256(installer_files[name]).hexdigest()
        manifest = {
            "schema_version": 1,
            "purpose": reset.PREPARED_PURPOSE,
            "catalog_sha": "f" * 40,
            "new_install_identity": NEW_INSTALL,
            "installer": {
                "source_root": "evidence/source",
                "adapter_config": "evidence/uap-observer-adapter-config.json",
                "adapter_sha256": digest("uap-observer-adapter-config.json"),
                "observer_config": "evidence/uap-observer.json",
                "observer_sha256": digest("uap-observer.json"),
                "caddy_archive": "evidence/caddy_2.11.4_linux_amd64.tar.gz",
                "caddy_config": "evidence/Caddyfile",
                "caddy_config_sha256": digest("Caddyfile"),
                "egress_allowlist": "evidence/uap-observer-egress-allowlist.json",
                "egress_sha256": digest("uap-observer-egress-allowlist.json"),
            },
            "clients": clients,
            "tree_digests": {
                name: reset.prepared_tree_digest(prepared / name, os.getuid())
                for name in reset.PREPARED_INVENTORY
            },
        }
        manifest_path = prepared / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        manifest_path.chmod(0o400)

    def controller(self, *, failpoint=None, systemd=None, executor=None):
        return reset.ResetController(
            self.layout, systemd=systemd or self.systemd,
            runtime_probe=reset.RuntimeProbe(self.layout), failpoint=failpoint,
            executor=executor or self.executor,
        )

    def install_candidate(self, manifest):
        self._install(NEW_INSTALL, NEW_CLOSURE)
        self._mutable()
        for client in reset.CLIENTS:
            proof = self.mkdir(f"/var/lib/uap-observer/proofs/{client}", 0o710)
            projection = proof / "native-projection.json"
            projection.write_bytes(self.projection_bodies[client])
            projection.chmod(0o440)
            self.assertEqual(
                "sha256:" + hashlib.sha256(projection.read_bytes()).hexdigest(),
                manifest["clients"][client]["projection_digest"],
            )
        self._units()

    def test_apply_status_finalize_roundtrip_is_clean_and_recreates_public_hop(self):
        controller = self.controller()
        applied = controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(applied["phase"], "new-ready")
        self.assertEqual(applied["old_quarantined"], applied["old_total"])
        self.assertTrue(self.path("/opt/uap-observer-current").is_symlink())
        self.assertEqual(self.systemd.events[0], ("stop", (reset.PUBLIC_HOP_UNIT,)))
        result = controller.finalize(
            MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE,
        )
        self.assertEqual(result["phase"], "finalized")
        self.assertFalse(self.path(reset.PREPARED_ROOT).exists())
        self.assertFalse(controller.journal_dir.exists())
        self.assertEqual(self.systemd.public_closure, NEW_CLOSURE)
        self.assertEqual(list(self.root.rglob(".uap-observer-reset-*")), [])

    def test_rollback_before_candidate_restores_exact_old_install_and_unit_state(self):
        controller = self.controller(failpoint=FailOnce("after-applied"))
        with self.assertRaises(reset.InjectedFailure):
            controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        result = controller.rollback(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(result["phase"], "rolled_back")
        controller._validate_install(OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(self.systemd.public_closure, OLD_CLOSURE)
        self.assertTrue(self.path(reset.PREPARED_ROOT).exists())
        self.assertFalse(controller.journal_dir.exists())

    def test_rollback_after_candidate_and_partial_install_removes_candidate_only(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.file("/usr/local/bin/caddy.new", b"partial", 0o755)
        controller.rollback(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        controller._validate_install(OLD_INSTALL, OLD_CLOSURE)
        self.assertFalse(self.path("/usr/local/bin/caddy.new").exists())
        self.assertNotEqual(self.path("/opt/uap-observer-current").readlink(), Path(f"uap-observer-closures/{NEW_CLOSURE}"))

    def test_apply_is_idempotent_after_every_quarantine_failpoint(self):
        for index in (0, len(reset.MANAGED) // 2, len(reset.MANAGED) - 1):
            with self.subTest(index=index):
                self.tearDown()
                self.setUp()
                failure = FailOnce(f"after-quarantine:{index}")
                with self.assertRaises(reset.InjectedFailure):
                    self.controller(failpoint=failure).apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                result = self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                self.assertEqual(result["phase"], "new-ready")

    def test_rollback_is_idempotent_after_candidate_and_restore_failpoints(self):
        for name in ("after-candidate-quarantine:0", "after-old-restore:0"):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                controller = self.controller()
                controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                with self.assertRaises(reset.InjectedFailure):
                    self.controller(failpoint=FailOnce(name)).rollback(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                self.controller().rollback(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                self.controller()._validate_install(OLD_INSTALL, OLD_CLOSURE)

    def test_rollback_cleanup_is_resumable_after_every_candidate_delete(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        with self.assertRaises(reset.InjectedFailure):
            self.controller(failpoint=FailOnce("after-delete:0")).rollback(
                MACHINE, OLD_INSTALL, OLD_CLOSURE,
            )
        self.assertEqual(self.controller().status(MACHINE)["phase"], "rollback-cleanup")
        result = self.controller().rollback(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(result["phase"], "rolled_back")
        self.controller()._validate_install(OLD_INSTALL, OLD_CLOSURE)

    def test_rollback_completion_is_resumable_at_every_tombstone_boundary(self):
        for failpoint in (
            "after-completion-marker", "after-journal-unlink",
            "after-journal-dir-remove", "after-completion-remove",
        ):
            with self.subTest(failpoint=failpoint):
                self.tearDown()
                self.setUp()
                self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                with self.assertRaises(reset.InjectedFailure):
                    self.controller(failpoint=FailOnce(failpoint)).rollback(
                        MACHINE, OLD_INSTALL, OLD_CLOSURE,
                    )
                result = self.controller().rollback(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                self.assertEqual(result["phase"], "rolled_back")
                self.assertFalse(self.path("/var/lib/uap-observer-reset.completed").exists())
                self.assertFalse(self.path("/var/lib/uap-observer-reset").exists())

    def test_finalize_is_resumable_after_partial_old_cleanup(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        with self.assertRaises(reset.InjectedFailure):
            self.controller(failpoint=FailOnce("after-delete:0")).finalize(
                MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE,
            )
        result = self.controller().finalize(
            MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE,
        )
        self.assertEqual(result["phase"], "finalized")

    def test_finalize_is_idempotent_after_completed_cleanup(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        first = controller.finalize(MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE)
        second = controller.finalize(MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE)
        self.assertEqual(first, second)

    def test_finalize_completion_is_resumable_at_every_tombstone_boundary(self):
        for failpoint in (
            "after-completion-marker", "after-journal-unlink",
            "after-journal-dir-remove", "after-completion-remove",
        ):
            with self.subTest(failpoint=failpoint):
                self.tearDown()
                self.setUp()
                self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                with self.assertRaises(reset.InjectedFailure):
                    self.controller(failpoint=FailOnce(failpoint)).finalize(
                        MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE,
                    )
                result = self.controller().finalize(
                    MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE,
                )
                self.assertEqual(result["phase"], "finalized")
                self.assertFalse(self.path("/var/lib/uap-observer-reset.completed").exists())
                self.assertFalse(self.path("/var/lib/uap-observer-reset").exists())

    def test_guards_reject_wrong_machine_identity_and_foreign_sentinel(self):
        controller = self.controller()
        with self.assertRaisesRegex(reset.ResetError, "machine-id"):
            controller.apply("f" * 32, OLD_INSTALL, OLD_CLOSURE)
        with self.assertRaisesRegex(reset.ResetError, "closure markers"):
            controller.apply(MACHINE, "f" * 64, OLD_CLOSURE)
        sentinel = self.path("/etc/uap-observer-disposable.json")
        sentinel.write_text('{}\n')
        sentinel.chmod(0o600)
        with self.assertRaisesRegex(reset.ResetError, "sentinel"):
            controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)

    def test_control_symlink_and_hardlink_are_rejected(self):
        sentinel = self.path("/etc/uap-observer-disposable.json")
        original = sentinel.with_suffix(".original")
        sentinel.rename(original)
        sentinel.symlink_to(original.name)
        with self.assertRaises(reset.ResetError):
            self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        sentinel.unlink()
        original.rename(sentinel)
        os.link(sentinel, sentinel.with_suffix(".hardlink"))
        with self.assertRaises(reset.ResetError):
            self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)

    def test_quarantine_substitution_blocks_finalize_before_cleanup(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        journal = controller._read_journal()
        entry = journal["old"][0]
        target = self.path(entry["quarantine"])
        target.unlink()
        target.symlink_to("/nonexistent")
        with self.assertRaisesRegex(reset.ResetError, "substituted"):
            controller.finalize(MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE)
        self.assertTrue(controller.journal_path.exists())

    def test_jobs_and_pending_attestations_reject_before_first_rename(self):
        for logical in (
            "/var/lib/uap-observer/jobs/job",
            "/var/lib/uap-observer-human/pending/attestation",
            "/var/lib/uap-observer-consent/pending/consent",
        ):
            with self.subTest(logical=logical):
                self.tearDown()
                self.setUp()
                self.file(logical)
                with self.assertRaisesRegex(reset.ResetError, "pending work"):
                    self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
                self.assertTrue(self.path("/opt/uap-observer-current").is_symlink())

    def test_install_lock_excludes_reset(self):
        lock = self.path("/run/lock/uap-observer-install.lock")
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(reset.ResetError, "another observer install"):
                self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        finally:
            os.close(descriptor)

    def test_preserved_signing_key_and_static_input_drift_fail_closed(self):
        controller = self.controller()
        key_before = self.path("/etc/uap-observer-ed25519.key").read_bytes()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(self.path("/etc/uap-observer-ed25519.key").read_bytes(), key_before)
        inputs = self.path("/opt/uap-observer-inputs")
        inputs.chmod(0o700)
        with self.assertRaisesRegex(reset.ResetError, "preserved path changed"):
            controller.status(MACHINE)

    def test_public_hop_recreation_failure_keeps_old_quarantine_and_prepared_seeds(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        failing = FakeSystemd(recreate_failure=True)
        failing.states = self.systemd.states
        failing.states[reset.PUBLIC_HOP_UNIT]["active"] = False
        failing_executor = FakeExecutor(self)
        with self.assertRaisesRegex(reset.ResetError, "recreation failure"):
            self.controller(systemd=failing, executor=failing_executor).finalize(
                MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE,
            )
        self.assertTrue(controller.journal_path.exists())
        self.assertTrue(self.path(reset.PREPARED_ROOT).exists())

    def test_prepared_root_inventory_is_exact_and_rollback_preserves_it(self):
        self.mkdir(f"{reset.PREPARED_ROOT}/foreign", 0o700)
        with self.assertRaisesRegex(reset.ResetError, "prepared reset root inventory"):
            self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)

    def test_prepared_manifest_and_tree_substitution_reject_before_stop(self):
        seed = self.path(f"{reset.PREPARED_ROOT}/seeds/codex/fixture")
        seed.chmod(0o600)
        seed.write_text("substituted!\n")
        seed.chmod(0o400)
        with self.assertRaisesRegex(reset.ResetError, "prepared tree digest"):
            self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(self.systemd.events, [])
        self.assertTrue(self.path("/opt/uap-observer-current").is_symlink())

    def test_prepared_adapter_projection_must_match_reviewed_manifest(self):
        prepared = self.path(reset.PREPARED_ROOT)
        adapter_path = prepared / "evidence/uap-observer-adapter-config.json"
        adapter = json.loads(adapter_path.read_text())
        adapter["clients"]["codex"]["native_projection"]["sha256"] = "sha256:" + "0" * 64
        adapter_body = json.dumps(adapter, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        adapter_path.chmod(0o600)
        adapter_path.write_bytes(adapter_body)
        adapter_path.chmod(0o400)
        manifest_path = prepared / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["installer"]["adapter_sha256"] = "sha256:" + hashlib.sha256(adapter_body).hexdigest()
        manifest["tree_digests"]["evidence"] = reset.prepared_tree_digest(
            prepared / "evidence", os.getuid(),
        )
        manifest_path.chmod(0o600)
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        manifest_path.chmod(0o400)
        with self.assertRaisesRegex(reset.ResetError, "adapter projection binding"):
            self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(self.systemd.events, [])

    def test_installed_projection_digest_mismatch_auto_rolls_back(self):
        executor = ProjectionMismatchExecutor(self)
        with self.assertRaisesRegex(reset.ResetError, "installed projection digest differs"):
            self.controller(executor=executor).apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.controller()._validate_install(OLD_INSTALL, OLD_CLOSURE)

    def test_prepared_hardlink_is_rejected(self):
        source = self.path(f"{reset.PREPARED_ROOT}/path/codex/fixture")
        os.link(source, source.with_name("hardlink"))
        with self.assertRaisesRegex(reset.ResetError, "hardlinked"):
            self.controller().apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)

    def test_preserved_in_place_content_change_with_restored_mtime_is_rejected(self):
        controller = self.controller(failpoint=FailOnce("after-applied"))
        with self.assertRaises(reset.InjectedFailure):
            controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        key = self.path("/etc/uap-observer-ed25519.key")
        info = key.stat()
        original = key.read_bytes()
        key.write_bytes(b"X" * len(original))
        key.chmod(0o600)
        os.utime(key, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaisesRegex(reset.ResetError, "file content changed"):
            controller.status(MACHINE)

    def test_wrong_internal_ca_content_is_rejected_without_metadata_signal(self):
        controller = self.controller(failpoint=FailOnce("after-applied"))
        with self.assertRaises(reset.InjectedFailure):
            controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        ca = self.path("/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt")
        info = ca.stat()
        encoded = ca.read_bytes()
        ca.write_bytes(b"Z" * len(encoded))
        ca.chmod(0o644)
        os.utime(ca, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaisesRegex(reset.ResetError, "content changed"):
            controller.status(MACHINE)

    def test_install_lock_remains_held_through_preparation(self):
        executor = LockCheckingExecutor(self)
        result = self.controller(executor=executor).apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.assertEqual(result["phase"], "new-ready")
        self.assertEqual(executor.prepare_count, 1)

    def test_public_hop_hostname_and_ca_command_are_strict(self):
        self.assertEqual(reset.caddy_hostname("observer.example.test {\n}\n"), "observer.example.test")
        for invalid in ("{\n}\n", "one.test {\n}\ntwo.test {\n}\n", "127.0.0.1 {\n}\n"):
            with self.assertRaises(reset.ResetError):
                reset.caddy_hostname(invalid)
        source = (ROOT / "deploy/uap-observer-reset.py").read_text()
        self.assertIn('"--cacert", str(ca_root)', source)
        self.assertNotIn('"--insecure"', source)
        self.assertIn('"--resolve", f"{host}:443:127.0.0.1"', source)

    def test_installer_accepts_only_reviewed_inherited_fd9(self):
        installer = (ROOT / "deploy/uap-observer-install.sh").read_text()
        self.assertIn('UAP_OBSERVER_INSTALL_LOCK_FD', installer)
        self.assertIn("test \"$(readlink -f /proc/self/fd/9)\" = /run/lock/uap-observer-install.lock", installer)
        self.assertIn("stat -c '%u:%a:%h' /run/lock/uap-observer-install.lock", installer)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "requires privileged Linux sandbox")
    def test_privileged_linux_sandbox_roundtrip_has_zero_residue(self):
        controller = self.controller()
        controller.apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        controller.finalize(MACHINE, OLD_INSTALL, OLD_CLOSURE, NEW_INSTALL, NEW_CLOSURE)
        self.assertFalse(controller.journal_dir.exists())
        self.assertFalse(self.path(reset.PREPARED_ROOT).exists())

    def test_prepare_failure_automatically_rolls_back_and_preserves_primary_error(self):
        executor = FakeExecutor(self, failure="injected prepare failure")
        with self.assertRaisesRegex(reset.ResetError, "injected prepare failure"):
            self.controller(executor=executor).apply(MACHINE, OLD_INSTALL, OLD_CLOSURE)
        self.controller()._validate_install(OLD_INSTALL, OLD_CLOSURE)
        self.assertFalse(self.path("/var/lib/uap-observer-reset").exists())

    def test_prepare_and_rollback_failure_reports_both_errors(self):
        systemd = FakeSystemd(recreate_failure=True)
        executor = FakeExecutor(self, failure="primary preparation failure")
        with self.assertRaises(reset.ResetError) as caught:
            self.controller(systemd=systemd, executor=executor).apply(
                MACHINE, OLD_INSTALL, OLD_CLOSURE,
            )
        message = str(caught.exception)
        self.assertIn("primary preparation failure", message)
        self.assertIn("automatic rollback also failed", message)
        self.assertIn("public hop recreation failure", message)


if __name__ == "__main__":
    unittest.main()
