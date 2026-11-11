"""Portable guards plus mandatory Linux execution probes (no models or services)."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "catalog_process_isolation", Path(__file__).resolve().parents[1]
    / "scripts" / "catalog_process_isolation.py")
isolation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(isolation)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.case = self.base / "case"
        self.case.mkdir(mode=0o700)
        self.environment = patch.dict(os.environ, {"RUNNER_TEMP": str(self.base)}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def command(self, **changes):
        args = dict(argv=["/usr/bin/true"], writable_root=self.case, cwd=self.case,
                    env={"HOME": str(self.case), "GITHUB_TOKEN": "secret"},
                    read_only_paths=(), bwrap=Path("/usr/bin/bwrap"))
        args.update(changes)
        return isolation._command(**args)

    def test_boundary_flags_and_no_secret_environment(self):
        command = self.command()
        for flag in ("--unshare-user", "--unshare-pid", "--disable-userns",
                     "--as-pid-1", "--die-with-parent", "--clearenv", "--new-session"):
            self.assertIn(flag, command)
        self.assertNotIn("--unshare-net", command)
        self.assertNotIn("GITHUB_TOKEN", command)
        self.assertNotIn("secret", command)
        self.assertEqual(command[-2:], ["--", "/usr/bin/true"])
        self.assertEqual(command.count("--bind"), 1)

    def test_rejects_shell_string_and_outside_cwd(self):
        for changes in ({"argv": "echo unsafe"}, {"argv": []}, {"cwd": self.base}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.command(**changes)

    def test_rejects_shared_root_and_workspace_overlap(self):
        self.case.chmod(0o755)
        with self.assertRaises(ValueError):
            self.command()
        self.case.chmod(0o700)
        with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(self.case)}):
            with self.assertRaises(ValueError):
                self.command()
        with self.assertRaises(ValueError):
            self.command(writable_root=self.base, cwd=self.base)

    def test_rejects_aliases_broad_and_overlapping_exposure(self):
        alias = self.base / "alias"
        alias.symlink_to(self.case, target_is_directory=True)
        for changes in ({"writable_root": alias}, {"read_only_paths": (self.base,)},
                        {"read_only_paths": (self.case,)}, {"read_only_paths": (alias,)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.command(**changes)

    def test_rejects_hardlink_to_outside_inode(self):
        outside = self.base / "producer.py"
        outside.write_text("trusted")
        os.link(outside, self.case / "innocent")
        with self.assertRaisesRegex(ValueError, "hardlinks"):
            self.command()

    def test_allows_fully_contained_hardlinks(self):
        original = self.case / "package"
        original.write_text("installed")
        nested = self.case / "nested"
        nested.mkdir()
        os.link(original, nested / "package-link")
        self.assertIn("--bind", self.command())

    def test_tools_are_exposed_readonly_after_temp_hiding(self):
        tools = self.base / "exposure-tools"
        tools.mkdir()
        command = self.command(read_only_paths=(tools,))
        mount = command.index(str(tools))
        self.assertEqual(command[mount - 1], "--ro-bind")
        self.assertLess(command.index("--tmpfs"), mount)
        self.assertGreater(command.index("--remount-ro"), mount)

    def test_missing_wrapper_never_launches_unisolated_child(self):
        with patch.object(isolation.subprocess, "Popen") as popen:
            with self.assertRaises(RuntimeError):
                isolation.run_isolated(["true"], writable_root=self.case, cwd=self.case,
                                       env={}, read_only_paths=(), timeout=1,
                                       bwrap=self.base / "missing")
            popen.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfds required")
    def test_missing_pidfd_support_never_launches_a_child(self):
        with patch.object(isolation.os, "pidfd_open", side_effect=OSError("unavailable")), \
                patch.object(isolation.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(RuntimeError, "working Linux pidfds"):
                isolation.run_isolated(["/usr/bin/true"], writable_root=self.case, cwd=self.case,
                                       env={}, read_only_paths=(), timeout=1)
            popen.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open")
                     and hasattr(signal, "pidfd_send_signal"), "Linux pidfds required")
class StartupHandshakeTests(unittest.TestCase):
    setUp = GuardTests.setUp

    def protocol_case(self, mode="normal", *, delay=None, bad_status=None, signal_error=False):
        # Inert wrapper models upstream info-before-block ordering. It is not a
        # namespace/confinement substitute; the real Linux probes remain below.
        for name in ("child.json", "executed"):
            (self.case / name).unlink(missing_ok=True)
        wrapper = self.base / "protocol.py"
        wrapper.write_text('''#!/usr/bin/python3
import ctypes, json, os, sys, time
from pathlib import Path
info = int(sys.argv[sys.argv.index('--info-fd') + 1])
gate = int(sys.argv[sys.argv.index('--block-fd') + 1]) if '--block-fd' in sys.argv else None
case = Path(sys.argv[sys.argv.index('--chdir') + 1])
mode = sys.argv[-1]
ready_read, ready_write = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(info)
    os.close(ready_write)
    os.read(ready_read, 1)
    os.close(ready_read)
    (case / 'child.json').write_text(json.dumps({'pid': os.getpid()}))
    if mode == 'setup_failure':
        os._exit(7)
    if gate is not None:
        os.read(gate, 1)  # Upstream also releases on EOF; model that exactly.
        os.close(gate)
    os.setsid()
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(1, 9, 0, 0, 0) == 0
    assert libc.prctl(1, 0, 0, 0, 0) == 0  # An untrusted client can clear PDEATHSIG.
    (case / 'executed').write_text('yes')
    if mode == 'sleep':
        os.close(1)
        os.close(2)
        time.sleep(3)
    os._exit(0)
os.close(ready_read)
payload = b'{broken' if mode == 'malformed' else json.dumps({'child-pid': pid}).encode()
os.write(info, payload)
os.close(info)
os.write(ready_write, b'1')
os.close(ready_write)
_, status = os.waitpid(pid, 0)
os._exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 1)
''')
        wrapper.chmod(0o700)
        timeout = 1 if delay or mode == "sleep" else 2
        real_popen, real_pipe, real_pidfd = subprocess.Popen, os.pipe, os.pidfd_open
        real_signal = signal.pidfd_send_signal
        observed = {"pipes": [], "control_fd": None, "status_read": False}

        def pipe():
            pair = real_pipe()
            if len(observed["pipes"]) < 4:
                observed["pipes"].extend(pair)
            return pair

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            observed["process"] = process
            limit = time.monotonic() + 1.5
            while True:
                try:
                    observed["child"] = json.loads((self.case / "child.json").read_text())["pid"]
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= limit:
                        raise AssertionError("protocol fixture did not start")
                    time.sleep(0.002)
            try:
                observed["control_fd"] = real_pidfd(observed["child"])
            except ProcessLookupError:
                self.assertEqual(mode, "setup_failure")
            if delay == "before_capture":
                time.sleep(timeout + 0.02)
            return process

        def status(path, **_):
            self.assertEqual(path, f"/proc/{observed['child']}/status")
            observed["status_read"] = True
            if delay == "after_capture":
                time.sleep(timeout + 0.02)
            parent = 0 if bad_status == "parent" else observed["process"].pid
            namespace = 2 if bad_status == "namespace" else 1
            return io.StringIO(f"PPid:\t{parent}\nNSpid:\t{observed['child']} {namespace}\n")

        def send(fd, sig):
            if signal_error and sig != 0:
                raise PermissionError("controlled pidfd signal error")
            return real_signal(fd, sig)

        try:
            with patch.object(isolation.os, "pipe", side_effect=pipe), \
                    patch.object(isolation.subprocess, "Popen", side_effect=popen), \
                    patch.object(isolation, "open", side_effect=status, create=True), \
                    patch.object(isolation.signal, "pidfd_send_signal", side_effect=send):
                try:
                    observed["result"] = isolation.run_isolated(
                        ["fixture", mode], writable_root=self.case, cwd=self.case,
                        env={}, read_only_paths=(), timeout=timeout, bwrap=wrapper)
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                    observed["error"] = error
            fd = observed["control_fd"]
            observed["alive"] = fd is not None and not select.select([fd], [], [], 0.2)[0]
            observed["executed"] = (self.case / "executed").exists()
            for fd in observed["pipes"]:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            return observed
        finally:
            fd = observed["control_fd"]
            if fd is not None:
                try:
                    real_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(fd)
            if "process" in observed:
                try:
                    os.killpg(observed["process"].pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                observed["process"].communicate(timeout=3)

    def test_expired_startup_never_releases_client_or_leaves_live_child(self):
        result = self.protocol_case("sleep", delay="before_capture")
        self.assertIsInstance(result.get("error"), subprocess.TimeoutExpired)
        self.assertFalse(result["status_read"])
        self.assertFalse(result["executed"])
        self.assertFalse(result["alive"])

    def test_rejected_metadata_and_expired_identity_never_release_client(self):
        cases = (({"mode": "malformed"}, RuntimeError, "incomplete bubblewrap"),
                 ({"bad_status": "parent"}, RuntimeError, "unexpected namespace"),
                 ({"bad_status": "namespace"}, RuntimeError, "unexpected namespace"),
                 ({"delay": "after_capture"}, subprocess.TimeoutExpired, "timed out"),
                 ({"delay": "after_capture", "signal_error": True}, PermissionError, "controlled pidfd signal"))
        for changes, error_type, message in cases:
            with self.subTest(changes=changes):
                result = self.protocol_case(**changes)
                self.assertIsInstance(result.get("error"), error_type)
                self.assertIn(message, str(result["error"]))
                self.assertEqual(result["status_read"], changes.get("mode") != "malformed")
                self.assertFalse(result["executed"])
                self.assertFalse(result["alive"])

    def test_valid_identity_releases_client_and_timeout_kills_it(self):
        for mode in ("normal", "sleep", "setup_failure"):
            with self.subTest(mode=mode):
                result = self.protocol_case(mode)
                self.assertFalse(result["alive"])
                if mode == "sleep":
                    self.assertIsInstance(result.get("error"), subprocess.TimeoutExpired)
                    self.assertTrue(result["status_read"])
                    self.assertTrue(result["executed"])
                else:
                    self.assertNotIn("error", result)
                    self.assertEqual(result["result"].returncode, 7 if mode == "setup_failure" else 0)
                if mode == "normal":
                    self.assertTrue(result["status_read"])
                    self.assertTrue(result["executed"])
                if mode == "setup_failure":
                    self.assertFalse(result["executed"])

    def test_failed_launch_closes_all_protocol_descriptors(self):
        real_pipe = os.pipe
        for fail_pipe in (False, True):
            with self.subTest(fail_pipe=fail_pipe):
                descriptors = []
                def pipe():
                    if fail_pipe and descriptors:
                        raise OSError("controlled pipe error")
                    pair = real_pipe()
                    descriptors.extend(pair)
                    return pair
                with patch.object(isolation.os, "pipe", side_effect=pipe), \
                        patch.object(isolation.subprocess, "Popen", side_effect=OSError("controlled launch error")) as popen:
                    with self.assertRaisesRegex(OSError, "controlled (pipe|launch) error"):
                        isolation.run_isolated(["fixture"], writable_root=self.case, cwd=self.case,
                                               env={}, read_only_paths=(), timeout=1, bwrap=Path(sys.executable))
                    if fail_pipe:
                        popen.assert_not_called()
                self.assertEqual(len(descriptors), 2 if fail_pipe else 4)
                for fd in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_unavailable_pidfd_signal_refuses_before_launch_and_closes_probe(self):
        descriptors = []
        real_pidfd = os.pidfd_open
        def pidfd(pid):
            fd = real_pidfd(pid)
            descriptors.append(fd)
            return fd
        with patch.object(isolation.os, "pidfd_open", side_effect=pidfd), \
                patch.object(isolation.signal, "pidfd_send_signal", side_effect=OSError("controlled unavailable signal")), \
                patch.object(isolation.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(RuntimeError, "working Linux pidfds"):
                isolation.run_isolated(["fixture"], writable_root=self.case, cwd=self.case,
                                       env={}, read_only_paths=(), timeout=1, bwrap=Path(sys.executable))
            popen.assert_not_called()
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])


@unittest.skipUnless(sys.platform == "linux", "real isolation requires Linux namespaces")
class LinuxIsolationTests(GuardTests):
    def setUp(self):
        super().setUp()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.tools = self.base / "tools"
        self.tools.mkdir()
        self.output = self.base / "github-output"
        self.targets = [self.workspace / "producer.py", self.tools / "cli",
                        self.base / "evidence.json", self.output]
        for path in self.targets:
            path.write_text("trusted")
        os.environ.update(GITHUB_WORKSPACE=str(self.workspace),
                          GITHUB_OUTPUT=str(self.output), PARENT_SECRET="private-token")
        self.env = {**os.environ, "HOME": str(self.case), "TMPDIR": str(self.case),
                    "PATH": "/usr/bin:/bin"}
        # system Python is outside masked runner tool directories on Ubuntu.
        self.python = "/usr/bin/python3"

    def run_child(self, code, *, timeout=10):
        result = isolation.run_isolated(
            [self.python, "-c", code], writable_root=self.case, cwd=self.case,
            env=self.env, read_only_paths=(self.tools,), timeout=timeout)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_real_write_denial_parent_proc_and_environment_absent(self):
        paths = [str(path) for path in self.targets]
        probe = f"""
import json, os
from pathlib import Path
denied = []
for target in {paths!r}:
    try:
        Path(target).write_text('tampered')
    except OSError:
        denied.append(target)
Path('owned').write_text('ok')
visible = []
for entry in Path('/proc').iterdir():
    if entry.name.isdigit():
        try:
            visible.append((entry / 'environ').read_bytes().decode(errors='replace'))
        except OSError:
            pass
assert not any('private-token' in value for value in visible)
assert not Path('/proc/{os.getpid()}/root').exists()
assert 'GITHUB_OUTPUT' not in os.environ
assert 'PARENT_SECRET' not in os.environ
assert Path({str(self.tools / 'cli')!r}).read_text() == 'trusted'
print(json.dumps(denied))
"""
        result = self.run_child(probe)
        self.assertEqual(json.loads(result.stdout), paths)
        self.assertEqual((self.case / "owned").read_text(), "ok")
        for path in self.targets:
            self.assertEqual(path.read_text(), "trusted")

    def test_nested_user_namespace_is_denied_despite_apparmor_allowance(self):
        self.run_child("""
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype = ctypes.c_int
before = os.readlink('/proc/self/ns/user')
result = libc.unshare(0x10000000)  # CLONE_NEWUSER
error = ctypes.get_errno()
assert result == -1, 'nested user namespace escaped --disable-userns'
assert error in (errno.EPERM, errno.ENOSPC), ('unexpected unshare failure', error)
assert os.readlink('/proc/self/ns/user') == before
""")

    def test_detached_grandchild_dies_when_initial_child_exits(self):
        self.run_child("""
import os, time
from pathlib import Path
if os.fork() == 0:
    os.setsid()
    os.close(1)
    os.close(2)
    Path('started').write_text('yes')
    time.sleep(0.4)
    Path('escaped').write_text('bad')
    os._exit(0)
while not Path('started').exists():
    time.sleep(0.01)
""")
        time.sleep(0.6)
        self.assertFalse((self.case / "escaped").exists())

    def test_timeout_kills_detached_descendant(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_child("""
import os, time
from pathlib import Path
if os.fork() == 0:
    os.setsid()
    os.close(1)
    os.close(2)
    time.sleep(1.5)
    Path('escaped').write_text('bad')
    os._exit(0)
time.sleep(30)
""", timeout=1)
        time.sleep(0.7)
        self.assertFalse((self.case / "escaped").exists())


if __name__ == "__main__":
    unittest.main()
