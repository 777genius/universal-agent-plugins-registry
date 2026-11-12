"""Fail-closed Linux boundary for untrusted catalog children, never the producer.

Public network access is intentional. All host mounts are read-only; only a
private, caller-created case directory is writable. CI must run the Linux tests
before executing catalog packages: python -m unittest discover -s tests -p
'test_catalog_process_isolation.py' -v. No VM, daemon, or weaker fallback exists.
"""
from __future__ import annotations

import os
import json
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time


_ENV = frozenset({
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "CI", "NO_COLOR",
    "HOME", "CODEX_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "TMPDIR", "TMP", "TEMP", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
    "GIT_TERMINAL_PROMPT", "NPM_CONFIG_CACHE", "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_PREFIX", "NPM_CONFIG_REGISTRY", "NPM_CONFIG_IGNORE_SCRIPTS",
    "NPM_CONFIG_AUDIT", "NPM_CONFIG_FUND", "NPM_CONFIG_UPDATE_NOTIFIER",
    "NPM_CONFIG_GLOBALCONFIG", "AGENTPLUGINS_HOME", "AGENTPLUGINS_DIRECTORY_ORIGIN",
    "PLUGIN_ROOT", "PLUGIN_DATA", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "CLAUDE_CONFIG_DIR", "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "COREPACK_HOME", "NODE_REPL_HISTORY", "npm_config_audit", "npm_config_cache",
    "npm_config_fund", "npm_config_globalconfig", "npm_config_update_notifier",
    "npm_config_userconfig",
})


def _canonical(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError(f"isolation paths must be absolute and contain no aliases: {path}")
    return path


def _overlap(left: Path, right: Path) -> bool:
    return left.is_relative_to(right) or right.is_relative_to(left)


def _command(argv, writable_root, cwd, env, read_only_paths, bwrap):
    root, work = _canonical(writable_root), _canonical(cwd)
    info = root.stat()
    if (not root.is_dir() or len(root.parts) < 3 or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077 or not work.is_relative_to(root)):
        raise ValueError("writable_root must be a private owned case directory containing cwd")
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace and _overlap(root, Path(workspace).resolve()):
        raise ValueError("case directory must not overlap the producer workspace")
    hidden = {Path(p).resolve() for p in ("/home", "/root", "/tmp", "/var/tmp", "/run")}
    for name in ("GITHUB_WORKSPACE", "RUNNER_TEMP"):
        if os.environ.get(name):
            hidden.add(Path(os.environ[name]).resolve())
    if root in hidden or any(p.is_relative_to(root) for p in hidden):
        raise ValueError("writable_root cannot contain a protected host directory")
    # Existing hardlinks could otherwise make an outside producer inode writable.
    links: dict[tuple[int, int], list[int]] = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            item = path.lstat()
            if path.is_mount():
                raise ValueError("case directory cannot contain host mounts")
            if stat.S_ISREG(item.st_mode):
                count = links.setdefault((item.st_dev, item.st_ino), [0, item.st_nlink])
                count[0] += 1
                if count[1] != item.st_nlink:
                    raise ValueError("case directory hardlinks changed during validation")
    if any(observed != total for observed, total in links.values()):
        raise ValueError("case directory cannot contain hardlinks to outside inodes")
    exposed = tuple(_canonical(path) for path in read_only_paths)
    for path in exposed:
        if _overlap(path, root) or any(p.is_relative_to(path) for p in hidden):
            raise ValueError("read-only exposure must be narrow and separate from the case")
        if workspace and _overlap(path, Path(workspace).resolve()):
            raise ValueError("cannot re-expose producer workspace")
        if any(path.is_relative_to(Path(home)) for home in ("/home", "/root")):
            runner_temp = os.environ.get("RUNNER_TEMP")
            if not runner_temp or not path.is_relative_to(Path(runner_temp).resolve()):
                raise ValueError("home exposures must be explicit runner-temp tools only")
    if not argv or any(not isinstance(a, str) or "\0" in a for a in argv):
        raise ValueError("argv must be a nonempty sequence of strings")
    if isinstance(argv, (str, bytes)):
        raise ValueError("argv must not be a shell string")
    claude = {"CLAUDE_CONFIG_DIR", "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"}
    if claude & env.keys():
        profile = Path(env.get("CLAUDE_CONFIG_DIR", ""))
        if (env.get("DISABLE_AUTOUPDATER") != "1"
                or env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC") != "1"
                or not profile.is_absolute() or profile != profile.resolve()
                or not profile.is_relative_to(root)):
            raise ValueError("Claude profile setup requires a confined profile and disabled background traffic")
    command = [str(bwrap), "--unshare-user", "--unshare-pid", "--unshare-ipc",
               "--unshare-uts", "--unshare-cgroup", "--disable-userns",
               "--die-with-parent", "--as-pid-1", "--new-session", "--cap-drop", "ALL",
               "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"]
    # Hide ancestors first; subsequent mounts restore only explicit tool paths.
    for path in sorted(hidden, key=lambda p: (len(p.parts), str(p))):
        command += ["--tmpfs", str(path)]
    for path in exposed:
        command += ["--ro-bind", str(path), str(path)]
    # Ubuntu may resolve this through /run/systemd/resolve, which is hidden.
    resolver = Path("/etc/resolv.conf").resolve()
    if resolver.is_file() and any(resolver.is_relative_to(p) for p in hidden):
        command += ["--ro-bind", str(resolver), str(resolver)]
    command += ["--bind", str(root), str(root)]
    for path in sorted(hidden, key=lambda p: (-len(p.parts), str(p))):
        command += ["--remount-ro", str(path)]
    command += ["--remount-ro", "/dev", "--clearenv"]
    for name, value in sorted(env.items()):
        if name in _ENV:
            command += ["--setenv", name, value]
    command += ["--chdir", str(work), "--", *argv]
    return command


def run_isolated(argv: list[str], *, writable_root: Path, cwd: Path,
                 env: dict[str, str], read_only_paths: tuple[Path, ...],
                 timeout: int, bwrap: Path = Path("/usr/bin/bwrap")) -> subprocess.CompletedProcess[str]:
    """Run one child; namespace/setup failures remain nonzero, never run directly."""
    if sys.platform != "linux" or not bwrap.is_file() or not os.access(bwrap, os.X_OK):
        raise RuntimeError("catalog isolation requires Linux and executable /usr/bin/bwrap")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    command = _command(argv, writable_root, cwd, env, read_only_paths, bwrap)
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("catalog isolation requires Linux pidfd support")
    probe_fd = None
    try:
        probe_fd = os.pidfd_open(os.getpid())
        signal.pidfd_send_signal(probe_fd, 0)
    except OSError as error:
        raise RuntimeError("catalog isolation requires working Linux pidfds") from error
    finally:
        if probe_fd is not None:
            os.close(probe_fd)
    # bubblewrap reports the host PID of the sandbox's PID 1 before executing
    # the client. Hold a pidfd so timeout cleanup cannot target a reused PID.
    read_fd, write_fd = os.pipe()
    try:
        release_read, release_write = os.pipe()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    # --block-fd pauses before --new-session and exec. Do not let client code
    # run until its namespace init is pinned and validated. EOF also releases
    # this gate, so exceptional cleanup must finish before closing the writer.
    command[1:1] = ["--info-fd", str(write_fd), "--block-fd", str(release_read)]
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, env={"PATH": "/usr/bin:/bin"}, cwd="/",
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, close_fds=True,
                                   pass_fds=(write_fd, release_read), start_new_session=True)
    except BaseException:
        os.close(read_fd)
        os.close(release_write)
        raise
    finally:
        os.close(write_fd)
        os.close(release_read)
    pidfd = None
    try:
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([read_fd], [], [], remaining)[0]:
                raise subprocess.TimeoutExpired(command, timeout)
            part = os.read(read_fd, 4096 - len(data))
            if not part:
                if data:
                    raise RuntimeError("incomplete bubblewrap process information")
                break  # A failed bubblewrap setup has no running sandbox.
            data.extend(part)
            try:
                info = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                if len(data) == 4096:
                    raise RuntimeError("invalid bubblewrap process information")
                continue
            child = info.get("child-pid") if isinstance(info, dict) else None
            if type(child) is not int or child <= 0:
                raise RuntimeError("invalid bubblewrap process identity")
            try:
                candidate_fd = os.pidfd_open(child)
            except ProcessLookupError:
                pass  # PID 1 has already exited, taking the namespace with it.
            else:
                try:
                    with open(f"/proc/{child}/status", encoding="utf-8") as status:
                        fields = dict(line.rstrip().split(":", 1) for line in status if ":" in line)
                    if (fields.get("PPid", "").strip() != str(process.pid)
                            or fields.get("NSpid", "").split()[-1:] != ["1"]):
                        raise RuntimeError("bubblewrap reported an unexpected namespace process")
                except FileNotFoundError:
                    # The pidfd still refers only to the exited namespace init.
                    pass
                except BaseException:
                    os.close(candidate_fd)
                    raise
                pidfd = candidate_fd
            break
        if pidfd is not None:
            if deadline - time.monotonic() <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                os.write(release_write, b"\0")
            except BrokenPipeError:
                pass  # The sandbox already exited during setup.
            os.close(release_write)
            release_write = None
        stdout, stderr = process.communicate(timeout=max(0, deadline - time.monotonic()))
    except BaseException:
        try:
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        raise
    finally:
        if release_write is not None:
            os.close(release_write)
        os.close(read_fd)
        if pidfd is not None:
            os.close(pidfd)
    if not data and process.returncode == 0:
        raise RuntimeError("bubblewrap completed without process information")
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
