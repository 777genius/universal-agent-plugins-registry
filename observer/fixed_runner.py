#!/usr/bin/env python3
"""Reviewed fixed-adapter runner, isolated from observer state and signing."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import stat
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_MESSAGE = 8 << 20
MAX_ADAPTER_OUTPUT = 4 << 20
RUNNER_TOTAL_SECONDS = 840
ARTIFACT_NAMES = {
    "runtime-attestations.json", "notion-oauth-attestations.json",
    "chatgpt-cloudflare-attestation.json", "consent.json",
}
ARTIFACT_ORDER = (
    "runtime-attestations.json", "notion-oauth-attestations.json",
    "chatgpt-cloudflare-attestation.json", "consent.json",
)
ARTIFACT_IDENTITIES = {
    "runtime-attestations.json": ("codex", "cursor", "kiro"),
    "notion-oauth-attestations.json": ("codex", "cursor", "kiro"),
    "chatgpt-cloudflare-attestation.json": ("control",),
    "consent.json": ("control",),
}
FIXED_CONFIG = Path("/opt/uap-observer-current/etc/uap-observer-adapter-config.json")
FIXED_ENTRYPOINTS = {
        artifact: Path(f"/opt/uap-observer-current/libexec/uap-observer-adapter-{name}")
    for artifact, name in {
        "runtime-attestations.json": "runtime", "notion-oauth-attestations.json": "notion",
        "chatgpt-cloudflare-attestation.json": "chatgpt", "consent.json": "consent",
    }.items()
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def validate_artifacts(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ARTIFACT_NAMES or not all(isinstance(item, dict) for item in value.values()):
        raise ValueError("adapter artifact set is not canonical")
    return value


def open_directory(path: Path, *, allowed_owners: set[int]) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("protected directory path is invalid")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in allowed_owners | {0}:
                raise ValueError("protected directory component is not trusted")
            if info.st_mode & 0o022 and not sticky_root:
                raise ValueError("protected directory component is writable")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def read_owned_regular(
    path: Path, limit: int, *, owner_uid: int, executable: bool = False,
    exact_mode: int | None = None, group_gid: int | None = None,
    expected_nlink: int = 1,
) -> bytes:
    parent_fd = open_directory(path.parent, allowed_owners={owner_uid, os.geteuid()})
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
            raise ValueError("protected file is not trusted")
        if info.st_nlink != expected_nlink:
            raise ValueError("protected file hardlink count differs")
        if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
            raise ValueError("protected file mode differs")
        if group_gid is not None and info.st_gid != group_gid:
            raise ValueError("protected file group differs")
        if executable and not info.st_mode & stat.S_IXUSR:
            raise ValueError("protected executable is not executable")
        if info.st_size > limit:
            raise ValueError("protected file exceeds size bound")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > limit:
            raise ValueError("protected file exceeds size bound")
        return value
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def write_new_owned(path: Path, value: bytes, *, uid: int | None = None, gid: int | None = None) -> None:
    parent_fd = open_directory(path.parent, allowed_owners={os.geteuid()})
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        view = memoryview(value)
        while view:
            view = view[os.write(descriptor, view):]
        if uid is not None and gid is not None:
            os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.wait()


def delegated_job_cgroup(
    cgroup_root: Path = Path("/sys/fs/cgroup"), cgroup_file: Path = Path("/proc/self/cgroup"),
) -> Path:
    controllers = cgroup_root / "cgroup.controllers"
    if not controllers.is_file():
        raise ValueError("reviewed runner requires delegated cgroup v2")
    relative: str | None = None
    for line in cgroup_file.read_text().splitlines():
        if line.startswith("0::/"):
            relative = line[3:]
            break
    if relative is None or not relative.startswith("/") or ".." in Path(relative).parts:
        raise ValueError("reviewed runner cgroup identity is invalid")
    # cgroup paths are namespace-absolute.  Joining an absolute Path would
    # silently discard cgroup_root, so make it explicitly root-relative.
    parent = cgroup_root.joinpath(*Path(relative).parts[1:])
    if parent != cgroup_root and cgroup_root not in parent.parents:
        raise ValueError("reviewed runner cgroup escaped the cgroup v2 mount")
    target = parent / f"uap-job-{os.getpid()}-{secrets.token_hex(8)}"
    target.mkdir(mode=0o700)
    return target


def destroy_job_cgroup(
    target: Path, *, kill: Any | None = None, events: Any | None = None,
    remove: Any | None = None,
) -> None:
    kill = kill or (lambda: (target / "cgroup.kill").write_text("1"))
    events = events or (lambda: (target / "cgroup.events").read_text())
    remove = remove or target.rmdir
    try:
        kill()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if "populated 0" in events():
                break
            time.sleep(0.01)
    finally:
        remove()


def tombstone_record(root: Path, challenge: str) -> None:
    """Atomically consume a root-created challenge record after adapter success."""
    if not re.fullmatch(r"[a-f0-9]{64}", challenge):
        raise ValueError("challenge record identity is invalid")
    pending = open_directory(root / "pending", allowed_owners={0})
    consumed = open_directory(root / "consumed", allowed_owners={0})
    try:
        source = f"{challenge}.json"
        try:
            os.stat(source, dir_fd=consumed, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("challenge record was already consumed")
        info = os.stat(source, dir_fd=pending, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1:
            raise ValueError("challenge record is not trusted")
        os.rename(source, source, src_dir_fd=pending, dst_dir_fd=consumed)
    finally:
        os.close(pending)
        os.close(consumed)


@dataclass(frozen=True)
class Adapter:
    artifact: str
    executable: Path
    digest: str
    config: Path
    config_digest: str


class ReviewedRunner:
    def __init__(self, adapters: tuple[Adapter, ...], state_root: Path, *, protected: bool = True):
        if {adapter.artifact for adapter in adapters} != ARTIFACT_NAMES:
            raise ValueError("reviewed adapter set is not canonical")
        if tuple(adapter.artifact for adapter in adapters) != ARTIFACT_ORDER:
            raise ValueError("reviewed adapter order is not canonical")
        self.adapters, self.state_root = adapters, state_root
        self.protected = protected
        self._owner_uid = 0 if protected else os.geteuid()
        if protected:
            self._identities = {}
            self._config_gid = grp.getgrnam("uap-observer-adapter-config").gr_gid
            for identity in ("codex", "cursor", "kiro", "control"):
                account = pwd.getpwnam(f"uap-observer-{identity}")
                group = grp.getgrnam(f"uap-observer-{identity}")
                expected_home = f"/var/empty/uap-observer-{identity}"
                if (
                    account.pw_uid == 0 or account.pw_gid != group.gr_gid
                    or account.pw_dir != expected_home
                    or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}
                ):
                    raise ValueError("reviewed adapter execution identity differs")
                home = os.stat(expected_home, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(home.st_mode) or home.st_uid != account.pw_uid
                    or home.st_gid != account.pw_gid or stat.S_IMODE(home.st_mode) != 0o700
                    or set(os.getgrouplist(account.pw_name, account.pw_gid)) != {account.pw_gid, self._config_gid}
                ):
                    raise ValueError("reviewed adapter home or groups differ")
                self._identities[identity] = (account.pw_uid, account.pw_gid)
            if len({uid for uid, _ in self._identities.values()}) != 4 or len({gid for _, gid in self._identities.values()}) != 4:
                raise ValueError("reviewed adapter execution identities are not distinct")
        else:
            self._identities = {identity: (os.geteuid(), os.getegid()) for identity in ("codex", "cursor", "kiro", "control")}
            self._config_gid = os.getegid()
        for adapter in adapters:
            links = 5 if protected else 1
            encoded = read_owned_regular(adapter.executable, 1 << 20, owner_uid=self._owner_uid, executable=True, expected_nlink=links)
            if "sha256:" + hashlib.sha256(encoded).hexdigest() != adapter.digest:
                raise ValueError("reviewed adapter digest mismatch")

    def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(context, dict) or set(context) != {"request", "github_attestation"}:
            raise ValueError("runner context is not canonical")
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o711)
        state_info = self.state_root.stat()
        if self.protected and (state_info.st_uid != 0 or stat.S_IMODE(state_info.st_mode) != 0o711):
            raise ValueError("runner job root is not root-controlled")
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=self.state_root))
        os.chmod(run_dir, 0o711)
        deadline = time.monotonic() + RUNNER_TOTAL_SECONDS
        try:
            artifacts: dict[str, Any] = {}
            for index, adapter in enumerate(self.adapters):
                links = 5 if self.protected else 1
                encoded_adapter = read_owned_regular(adapter.executable, 1 << 20, owner_uid=self._owner_uid, executable=True, expected_nlink=links)
                if "sha256:" + hashlib.sha256(encoded_adapter).hexdigest() != adapter.digest:
                    raise ValueError("reviewed adapter changed after runner startup")
                partials = []
                for identity in ARTIFACT_IDENTITIES[adapter.artifact]:
                    uid, gid = self._identities[identity]
                    invocation_dir = run_dir / f"adapter-{index}-{identity}"
                    invocation_dir.mkdir(mode=0o700)
                    context_path, output = invocation_dir / "context.json", invocation_dir / "artifact.json"
                    write_new_owned(context_path, canonical_json(context), uid=uid if self.protected else None, gid=gid if self.protected else None)
                    if self.protected:
                        os.chown(invocation_dir, uid, gid)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("reviewed adapters exceeded total deadline")
                    job_cgroup = delegated_job_cgroup() if self.protected else None
                    try:
                        def contain_and_drop_privileges() -> None:
                            if job_cgroup is not None:
                                (job_cgroup / "cgroup.procs").write_text(str(os.getpid()))
                            if self.protected:
                                os.setgroups([self._config_gid])
                                os.setgid(gid)
                                os.setuid(uid)
                        process = subprocess.Popen(
                            [str(adapter.executable), "--context", str(context_path), "--output", str(output)],
                            cwd=invocation_dir,
                            env={
                                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                                "UAP_OBSERVER_ADAPTER_CONFIG_SHA256": adapter.config_digest,
                                "UAP_OBSERVER_ADAPTER_CLIENT": identity,
                            },
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True,
                            preexec_fn=contain_and_drop_privileges if self.protected else None,
                            shell=False,
                        )
                        try:
                            return_code = process.wait(timeout=remaining)
                        except subprocess.TimeoutExpired:
                            kill_process_group(process)
                            raise TimeoutError("reviewed adapter exceeded deadline") from None
                        finally:
                            kill_process_group(process)
                    finally:
                        if job_cgroup is not None:
                            destroy_job_cgroup(job_cgroup)
                    if return_code != 0:
                        raise ValueError("reviewed adapter failed")
                    partials.append(json.loads(read_owned_regular(output, MAX_ADAPTER_OUTPUT, owner_uid=uid)))
                    if self.protected and adapter.artifact in {"consent.json", "chatgpt-cloudflare-attestation.json"}:
                        challenge = context["request"]["challenge"]["value"]
                        root = Path("/var/lib/uap-observer-consent" if adapter.artifact == "consent.json" else "/var/lib/uap-observer-human")
                        tombstone_record(root, challenge)
                if len(partials) == 1:
                    artifacts[adapter.artifact] = partials[0]
                else:
                    if not all(isinstance(partial, dict) and set(partial) == {"schema_version", "attestations"} and partial["schema_version"] == 1 and isinstance(partial["attestations"], list) for partial in partials):
                        raise ValueError("split adapter artifact is not canonical")
                    artifacts[adapter.artifact] = {"schema_version": 1, "attestations": [record for partial in partials for record in partial["attestations"]]}
            return validate_artifacts(artifacts)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


def read_exact(stream: socket.socket, size: int) -> bytes:
    chunks = []
    while size:
        chunk = stream.recv(size)
        if not chunk:
            raise ValueError("runner request was truncated")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def peer_uid(stream: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("runner requires Linux SO_PEERCRED")
    _, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid


def handle(stream: socket.socket, runner: ReviewedRunner, allowed_uid: int) -> None:
    try:
        if peer_uid(stream) != allowed_uid:
            raise ValueError("runner peer is not authorized")
        stream.settimeout(20)
        length = struct.unpack("!I", read_exact(stream, 4))[0]
        if not 1 <= length <= MAX_MESSAGE:
            raise ValueError("runner request length is invalid")
        context = json.loads(read_exact(stream, length))
        response = canonical_json({"artifacts": runner.execute(context)})
    except Exception:
        response = canonical_json({"error": "reviewed runner failed"})
    try:
        stream.sendall(struct.pack("!I", len(response)) + response)
    except (BrokenPipeError, ConnectionResetError):
        pass


def serve(listener: socket.socket, runner: ReviewedRunner, allowed_uid: int, *, once: bool = False) -> None:
    while True:
        stream, _ = listener.accept()
        with stream:
            handle(stream, runner, allowed_uid)
        if once:
            return


def load_adapters(path: Path, *, adapter_gid: int | None = None, enforce_fixed: bool = False) -> tuple[Adapter, ...]:
    value = json.loads(read_owned_regular(path, 64 << 10, owner_uid=0))
    if not isinstance(value, dict) or set(value) != {"schema_version", "config", "artifacts"} or value.get("schema_version") != 1:
        raise ValueError("adapter manifest is not canonical")
    config_item, artifact_items = value["config"], value["artifacts"]
    if not isinstance(config_item, dict) or set(config_item) != {"path", "sha256"} or not isinstance(artifact_items, dict) or set(artifact_items) != ARTIFACT_NAMES:
        raise ValueError("adapter manifest is not canonical")
    config = Path(config_item["path"])
    config_digest = config_item["sha256"]
    if (enforce_fixed and config != FIXED_CONFIG) or not config.is_absolute() or not isinstance(config_digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", config_digest):
        raise ValueError("adapter manifest config is invalid")
    expected_gid = os.getegid() if adapter_gid is None else adapter_gid
    encoded_config = read_owned_regular(config, 4 << 20, owner_uid=0, exact_mode=0o640, group_gid=expected_gid)
    if "sha256:" + hashlib.sha256(encoded_config).hexdigest() != config_digest:
        raise ValueError("adapter config digest mismatch")
    adapters = []
    for artifact in ARTIFACT_ORDER:
        item = artifact_items[artifact]
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("adapter manifest entry is invalid")
        executable = Path(item["path"])
        digest = item["sha256"]
        if (enforce_fixed and executable != FIXED_ENTRYPOINTS[artifact]) or not executable.is_absolute() or not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("adapter manifest entry is invalid")
        adapters.append(Adapter(artifact, executable, digest, config, config_digest))
    executable_stats = [os.stat(adapter.executable, follow_symlinks=False) for adapter in adapters]
    expected_links = 5 if enforce_fixed else 4
    if len({(item.st_dev, item.st_ino) for item in executable_stats}) != 1 or any(item.st_nlink != expected_links for item in executable_stats) or len({adapter.digest for adapter in adapters}) != 1:
        raise ValueError("adapter entrypoints are not exact hardlinks")
    return tuple(adapters)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-fd", type=int, default=3)
    args = parser.parse_args()
    allowed_uid = pwd.getpwnam("uap-observer").pw_uid
    adapter_gid = grp.getgrnam("uap-observer-adapter-config").gr_gid
    listener = socket.socket(fileno=args.socket_fd)
    adapters = load_adapters(Path("/opt/uap-observer-current/etc/uap-observer-adapters.json"), adapter_gid=adapter_gid, enforce_fixed=True)
    serve(listener, ReviewedRunner(adapters, Path("/var/lib/uap-observer/jobs")), allowed_uid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
