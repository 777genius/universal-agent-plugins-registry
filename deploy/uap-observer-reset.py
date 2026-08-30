#!/usr/bin/env python3
"""Fail-closed reset transaction for one disposable UAP observer VM.

The production CLI intentionally has no root/path overrides.  Tests construct a
``Layout.for_test`` and call ``ResetController`` directly; an operator can never
redirect the privileged command at an arbitrary tree.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
SENTINEL_PURPOSE = "uap-observer-e2e-disposable"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MACHINE_ID = re.compile(r"[0-9a-f]{32}\Z")
UNITS = (
    "uap-observer.service",
    "uap-observer-signer.service",
    "uap-observer-runner.service",
    "uap-observer-runner.socket",
    "uap-observer-caddy.service",
    "uap-observer-egress-proxy.service",
    "uap-observer-egress-proxy.socket",
)
PUBLIC_HOP_UNIT = "uap-observer-caddy-internal.service"
ALL_UNITS = (*UNITS, PUBLIC_HOP_UNIT)
MANAGED = (
    "/opt/uap-observer-current",
    "/opt/uap-observer-closures",
    "/var/lib/uap-observer",
    "/var/lib/uap-observer-human",
    "/var/lib/uap-observer-consent",
    *(f"/etc/systemd/system/{unit}" for unit in UNITS),
    "/etc/systemd/system/uap-observer.service.d",
    "/etc/systemd/system/uap-observer-runner.service.d",
)
PRESERVED = (
    "/etc/uap-observer-ed25519.key",
    "/etc/uap-observer-ed25519.pub",
    "/opt/uap-observer-inputs",
    "/etc/caddy",
    "/var/lib/caddy",
    "/var/log/caddy",
    "/var/lib/caddy/uap-vm-internal-Caddyfile",
    "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt",
    "/root/caddy_2.11.4_linux_amd64.tar.gz",
    "/root/Caddyfile",
    "/root/uap-observer-adapter-config.json",
    "/root/uap-observer.json",
    "/root/uap-observer-egress-allowlist.json",
)
PREPARED_ROOT = "/root/uap-observer-reset-prepared-v1"
PREPARED_INVENTORY = ("evidence", "path", "projection-digests", "seeds")
PREPARED_PURPOSE = "uap-observer-same-vm-reset-prepared-v1"
PREPARED_TREE_DOMAIN = b"uap-observer-reset-prepared-tree-v1\0"
CLIENTS = ("codex", "cursor", "kiro")
PARTIALS = (
    "/opt/uap-observer-source.new",
    "/opt/uap-observer-venv.new",
    "/opt/uap-observer-runtime.new",
    "/opt/uap-observer-current.new",
    "/usr/local/libexec/uap-observer-runner.new",
    "/usr/local/libexec/uap-observer-egress-proxy.new",
    "/usr/local/libexec/uap-observer-fixed-adapter.new",
    "/usr/local/libexec/uap-observer-attest-chatgpt.new",
    "/usr/local/libexec/uap-observer-attest-consent.new",
    "/usr/local/libexec/uap-observer-provision-profile.new",
    "/usr/local/libexec/uap-observer-recover-profile-seed.new",
    "/usr/local/libexec/uap-observer-adapter-runtime.new",
    "/usr/local/libexec/uap-observer-adapter-notion.new",
    "/usr/local/libexec/uap-observer-adapter-chatgpt.new",
    "/usr/local/libexec/uap-observer-adapter-consent.new",
    "/usr/local/bin/caddy.new",
    "/etc/uap-observer.json.new",
    "/etc/uap-observer-egress-allowlist.json.new",
    "/etc/uap-observer-adapter-config.json.new",
    "/etc/uap-observer-adapters.json.new",
    "/etc/caddy/Caddyfile.new",
)


class ResetError(RuntimeError):
    pass


class InjectedFailure(ResetError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    folded: set[str] = set()
    for key, child in pairs:
        normalized = key.casefold()
        if key in value or normalized in folded:
            raise ResetError("duplicate or case-confusable JSON member")
        value[key] = child
        folded.add(normalized)
    return value


def strict_json(encoded: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ResetError(f"non-finite JSON value {value}")

    return json.loads(
        encoded,
        object_pairs_hook=strict_object,
        parse_constant=reject_constant,
    )


@dataclasses.dataclass(frozen=True)
class Layout:
    root: Path | None
    expected_uid: int

    @classmethod
    def production(cls) -> "Layout":
        return cls(None, 0)

    @classmethod
    def for_test(cls, root: Path) -> "Layout":
        return cls(root.resolve(), os.getuid())

    def path(self, logical: str) -> Path:
        if not logical.startswith("/") or ".." in Path(logical).parts:
            raise ResetError("non-canonical managed path")
        if self.root is None:
            return Path(logical)
        return self.root / logical.removeprefix("/")


def metadata(path: Path) -> dict[str, Any]:
    info = os.lstat(path)
    kind = (
        "directory" if stat.S_ISDIR(info.st_mode)
        else "regular" if stat.S_ISREG(info.st_mode)
        else "symlink" if stat.S_ISLNK(info.st_mode)
        else "special"
    )
    result: dict[str, Any] = {
        "device": info.st_dev,
        "inode": info.st_ino,
        "kind": kind,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "nlink": info.st_nlink,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }
    if kind == "symlink":
        result["target"] = os.readlink(path)
    return result


def stable_metadata(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(value.get(field) for field in (
        "device", "inode", "kind", "mode", "uid", "gid", "nlink", "size",
        "mtime_ns", "target",
    ))


def validate_root_control(path: Path, uid: int, mode: int, kind: str) -> dict[str, Any]:
    observed = metadata(path)
    if (
        observed["kind"] != kind
        or observed["uid"] != uid
        or observed["mode"] != mode
        or (kind == "regular" and observed["nlink"] != 1)
    ):
        raise ResetError(f"protected control path differs: {path}")
    return observed


def read_control(path: Path, uid: int, mode: int, maximum: int = 64 << 10) -> bytes:
    before = validate_root_control(path, uid, mode, "regular")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_NOATIME"):
        flags |= os.O_NOATIME
    descriptor = os.open(path, flags)
    try:
        if stable_metadata(metadata_from_stat(os.fstat(descriptor))) != stable_metadata(before):
            raise ResetError(f"protected control path changed while opening: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        encoded = b"".join(chunks)
        if len(encoded) > maximum:
            raise ResetError(f"protected control path is oversized: {path}")
        if stable_metadata(metadata_from_stat(os.fstat(descriptor))) != stable_metadata(before):
            raise ResetError(f"protected control path changed while reading: {path}")
        if stable_metadata(metadata(path)) != stable_metadata(before):
            raise ResetError(f"protected control pathname changed while reading: {path}")
        return encoded
    finally:
        os.close(descriptor)


def metadata_from_stat(info: os.stat_result) -> dict[str, Any]:
    kind = (
        "directory" if stat.S_ISDIR(info.st_mode)
        else "regular" if stat.S_ISREG(info.st_mode)
        else "symlink" if stat.S_ISLNK(info.st_mode)
        else "special"
    )
    return {
        "device": info.st_dev, "inode": info.st_ino, "kind": kind,
        "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
        "gid": info.st_gid, "nlink": info.st_nlink, "size": info.st_size,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def prepared_tree_digest(root: Path, expected_uid: int) -> str:
    root_info = os.lstat(root)
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ResetError("prepared tree root is not a directory")
    device = root_info.st_dev
    entries: list[tuple[str, os.stat_result]] = [(".", root_info)]

    def collect(directory: Path, relative: Path) -> None:
        if len(entries) > 1_000_000:
            raise ResetError("prepared tree entry bound exceeded")
        for child in sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name)):
            path = Path(child.path)
            info = os.lstat(path)
            name = str(relative / child.name)
            if info.st_dev != device:
                raise ResetError("prepared tree crosses a filesystem boundary")
            if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o022:
                raise ResetError("prepared tree ownership or writable mode differs")
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ResetError("prepared tree contains a link or special file")
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ResetError("prepared tree contains a hardlinked file")
            entries.append((name, info))
            if stat.S_ISDIR(info.st_mode):
                collect(path, relative / child.name)

    collect(root, Path())
    digest = hashlib.sha256(PREPARED_TREE_DOMAIN)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_NOATIME"):
        flags |= os.O_NOATIME
    for relative, before in entries:
        path = root if relative == "." else root / relative
        kind = b"directory" if stat.S_ISDIR(before.st_mode) else b"regular"
        fields = (
            relative.encode("utf-8"), kind,
            f"{stat.S_IMODE(before.st_mode):04o}".encode(), str(before.st_uid).encode(),
            str(before.st_gid).encode(), str(before.st_nlink).encode(), str(before.st_size).encode(),
        )
        for field in fields:
            digest.update(length_prefix(field))
        if kind == b"directory":
            digest.update(length_prefix(b""))
            continue
        descriptor = os.open(path, flags)
        try:
            def tree_stable(info: os.stat_result) -> tuple[int, ...]:
                return (
                    info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns,
                )
            if tree_stable(os.fstat(descriptor)) != tree_stable(before):
                raise ResetError("prepared file changed while opening")
            contents = hashlib.sha256()
            size = 0
            while True:
                block = os.read(descriptor, 1 << 20)
                if not block:
                    break
                contents.update(block)
                size += len(block)
            if (
                size != before.st_size
                or tree_stable(os.fstat(descriptor)) != tree_stable(before)
                or tree_stable(os.lstat(path)) != tree_stable(before)
            ):
                raise ResetError("prepared file changed while reading")
            digest.update(length_prefix(str(size).encode()))
            digest.update(length_prefix(contents.digest()))
        finally:
            os.close(descriptor)
    return "sha256:" + digest.hexdigest()


def regular_file_digest(path: Path, expected: Mapping[str, Any] | None = None) -> str:
    before = metadata(path)
    if before["kind"] != "regular" or before["nlink"] != 1:
        raise ResetError("preserved file is not a single-link regular file")
    if expected is not None and stable_metadata(before) != stable_metadata(expected):
        raise ResetError("preserved file metadata differs")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_NOATIME"):
        flags |= os.O_NOATIME
    descriptor = os.open(path, flags)
    try:
        if stable_metadata(metadata_from_stat(os.fstat(descriptor))) != stable_metadata(before):
            raise ResetError("preserved file changed while opening")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            digest.update(block)
            size += len(block)
        if (
            size != before["size"]
            or stable_metadata(metadata_from_stat(os.fstat(descriptor))) != stable_metadata(before)
            or stable_metadata(metadata(path)) != stable_metadata(before)
        ):
            raise ResetError("preserved file changed while reading")
        return "sha256:" + digest.hexdigest()
    finally:
        os.close(descriptor)


def preserved_tree_digest(root: Path) -> str:
    root_info = os.lstat(root)
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ResetError("preserved tree root is not a directory")
    device = root_info.st_dev
    digest = hashlib.sha256(b"uap-observer-reset-preserved-tree-v1\0")
    count = 0

    def consume(path: Path, relative: str) -> None:
        nonlocal count
        count += 1
        if count > 1_000_000:
            raise ResetError("preserved tree entry bound exceeded")
        info = os.lstat(path)
        if info.st_dev != device:
            raise ResetError("preserved tree crosses a filesystem boundary")
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ResetError("preserved tree contains a link or special file")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ResetError("preserved tree contains a hardlinked file")
        kind = b"directory" if stat.S_ISDIR(info.st_mode) else b"regular"
        for field in (
            relative.encode(), kind, f"{stat.S_IMODE(info.st_mode):04o}".encode(),
            str(info.st_uid).encode(), str(info.st_gid).encode(), str(info.st_nlink).encode(),
            str(info.st_size).encode(),
        ):
            digest.update(length_prefix(field))
        if kind == b"regular":
            digest.update(length_prefix(regular_file_digest(path, metadata(path)).encode()))
        else:
            digest.update(length_prefix(b""))
            for child in sorted(os.scandir(path), key=lambda item: os.fsencode(item.name)):
                consume(Path(child.path), child.name if relative == "." else f"{relative}/{child.name}")

    consume(root, ".")
    return "sha256:" + digest.hexdigest()


def caddy_hostname(encoded: str) -> str:
    matches = re.findall(
        r"(?m)^\s*([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)\s*\{\s*$",
        encoded,
    )
    hosts = [host for host in matches if "." in host and not host.replace(".", "").isdigit()]
    if len(hosts) != 1:
        raise ResetError("public Caddy hop must contain one exact hostname")
    return hosts[0].lower()


class Systemd:
    def _run(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["systemctl", *arguments], check=check, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def state(self, unit: str) -> dict[str, bool]:
        active = self._run("is-active", "--quiet", unit, check=False).returncode == 0
        enabled = self._run("is-enabled", "--quiet", unit, check=False).returncode == 0
        return {"active": active, "enabled": enabled}

    def stop(self, units: Sequence[str]) -> None:
        self._run("stop", *units)

    def start(self, units: Sequence[str]) -> None:
        if units:
            self._run("start", *units)

    def enable(self, units: Sequence[str]) -> None:
        if units:
            self._run("enable", *units)

    def disable(self, units: Sequence[str]) -> None:
        if units:
            self._run("disable", *units)

    def daemon_reload(self) -> None:
        self._run("daemon-reload")

    def _property(self, unit: str, name: str) -> str:
        return self._run("show", unit, f"--property={name}", "--value").stdout.strip()

    def public_hop_contract(self) -> dict[str, str]:
        names = (
            "FragmentPath", "Transient", "Type", "Restart", "User", "Group",
            "ExecStart", "PrivateTmp", "ProtectSystem", "ProtectHome",
            "ReadWritePaths", "ReadOnlyPaths", "AmbientCapabilities",
            "CapabilityBoundingSet", "NoNewPrivileges", "LimitNOFILE",
            "Description",
        )
        return {name: self._property(PUBLIC_HOP_UNIT, name) for name in names}

    def validate_public_hop_contract(self) -> dict[str, str]:
        contract = self.public_hop_contract()
        scalar = {
            "FragmentPath": "/run/systemd/transient/uap-observer-caddy-internal.service",
            "Transient": "yes",
            "Type": "notify",
            "Restart": "no",
            "User": "caddy",
            "Group": "caddy",
            "PrivateTmp": "yes",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "AmbientCapabilities": "cap_net_bind_service",
            "CapabilityBoundingSet": "cap_net_bind_service",
            "NoNewPrivileges": "yes",
            "LimitNOFILE": "1048576",
            "Description": "Disposable UAP VM internal-CA ingress",
        }
        if any(contract.get(key) != expected for key, expected in scalar.items()):
            raise ResetError("transient public Caddy hop properties differ")
        expected_exec = (
            "/opt/uap-observer-current/bin/caddy run --environ --config "
            "/var/lib/caddy/uap-vm-internal-Caddyfile --adapter caddyfile"
        )
        if expected_exec not in contract["ExecStart"]:
            raise ResetError("transient public Caddy hop command differs")
        if "/var/lib/caddy" not in contract["ReadWritePaths"] or "/var/log/caddy" not in contract["ReadWritePaths"]:
            raise ResetError("transient public Caddy hop write paths differ")
        if "/opt/uap-observer-current" not in contract["ReadOnlyPaths"]:
            raise ResetError("transient public Caddy hop read-only path differs")
        return contract

    def recreate_public_hop(self, closure: str) -> None:
        executable = f"/opt/uap-observer-closures/{closure}/bin/caddy"
        current = Path("/opt/uap-observer-current/bin/caddy")
        if not current.exists() or current.resolve() != Path(executable):
            raise ResetError("public Caddy executable is not the exact current closure")
        command = (
            "systemd-run", "--unit=uap-observer-caddy-internal.service",
            "--description=Disposable UAP VM internal-CA ingress",
            "--service-type=notify", "--uid=caddy", "--gid=caddy",
            "--property=Restart=no", "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
            "--property=ReadWritePaths=/var/lib/caddy /var/log/caddy",
            "--property=ReadOnlyPaths=/opt/uap-observer-current",
            "--property=AmbientCapabilities=cap_net_bind_service",
            "--property=CapabilityBoundingSet=cap_net_bind_service",
            "--property=NoNewPrivileges=yes", "--property=LimitNOFILE=1048576",
            "/opt/uap-observer-current/bin/caddy", "run", "--environ", "--config",
            "/var/lib/caddy/uap-vm-internal-Caddyfile", "--adapter", "caddyfile",
        )
        subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not self.state(PUBLIC_HOP_UNIT)["active"]:
            raise ResetError("recreated public Caddy hop is not active")
        self.validate_public_hop_contract()
        main_pid = self._property(PUBLIC_HOP_UNIT, "MainPID")
        if not main_pid.isdecimal() or main_pid == "0":
            raise ResetError("public Caddy hop has no main process")
        if Path(f"/proc/{main_pid}/exe").resolve() != Path(executable):
            raise ResetError("public Caddy hop process is not using the new closure")

    def verify_public_hop(self, closure: str) -> None:
        self.validate_public_hop_contract()
        executable = Path(f"/opt/uap-observer-closures/{closure}/bin/caddy")
        main_pid = self._property(PUBLIC_HOP_UNIT, "MainPID")
        if not main_pid.isdecimal() or main_pid == "0" or Path(f"/proc/{main_pid}/exe").resolve() != executable:
            raise ResetError("public Caddy hop process is not using the expected closure")
        config_path = Path("/var/lib/caddy/uap-vm-internal-Caddyfile")
        config = config_path.read_text(encoding="utf-8")
        host = caddy_hostname(config)
        ca_root = Path("/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt")
        ca = metadata(ca_root)
        if ca["kind"] != "regular" or ca["nlink"] != 1 or ca["mode"] & 0o022:
            raise ResetError("public Caddy internal CA metadata differs")
        regular_file_digest(ca_root, ca)
        result = subprocess.run(
            ["curl", "--cacert", str(ca_root), "--silent", "--show-error", "--output", "/dev/null",
             "--connect-timeout", "5", "--max-time", "15", "--write-out", "%{http_code}",
             "--resolve", f"{host}:443:127.0.0.1", f"https://{host}/v1/stable-launch/observe"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if not result.stdout.isdecimal() or result.stdout == "000":
            raise ResetError("public Caddy hop endpoint did not respond")


class RuntimeProbe:
    def __init__(self, layout: Layout):
        self.layout = layout

    def assert_quiescent(self) -> None:
        cgroup = self.layout.path("/sys/fs/cgroup/system.slice/uap-observer-runner.service")
        if cgroup.exists():
            for path in cgroup.rglob("uap-job-*"):
                raise ResetError(f"observer runner job cgroup remains: {path.name}")
            procs = cgroup / "cgroup.procs"
            if procs.exists() and procs.read_text().strip():
                raise ResetError("observer runner cgroup still contains processes")
        proc = self.layout.path("/proc")
        if proc.exists():
            for child in proc.iterdir():
                if not child.name.isdecimal():
                    continue
                try:
                    cgroups = (child / "cgroup").read_bytes()
                    command = (child / "cmdline").read_bytes()
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
                if b"uap-observer" in cgroups or b"/opt/uap-observer-current/" in command:
                    raise ResetError("observer runtime process remains")
        for logical in (
            "/var/lib/uap-observer/jobs",
            "/var/lib/uap-observer-human/pending",
            "/var/lib/uap-observer-human/reserved",
            "/var/lib/uap-observer-consent/pending",
            "/var/lib/uap-observer-consent/reserved",
        ):
            path = self.layout.path(logical)
            if path.exists() and any(path.iterdir()):
                raise ResetError(f"observer pending work remains: {logical}")


class PreparedExecutor:
    def __init__(self, layout: Layout, systemd: Systemd):
        self.layout = layout
        self.systemd = systemd

    def _run(self, arguments: Sequence[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["UAP_OBSERVER_INSTALL_LOCK_FD"] = "9"
        return subprocess.run(
            list(arguments), check=True, text=True, env=environment, pass_fds=(9,),
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )

    def prepare_new(self, controller: "ResetController", journal: Mapping[str, Any]) -> dict[str, str]:
        prepared = self.layout.path(PREPARED_ROOT)
        manifest = journal["prepared"]["manifest"]
        installer = manifest["installer"]
        source = prepared / installer["source_root"]
        command = (
            str(source / "deploy/uap-observer-install.sh"), str(source),
            str(prepared / installer["adapter_config"]), installer["adapter_sha256"],
            str(prepared / installer["observer_config"]), installer["observer_sha256"],
            str(prepared / installer["caddy_archive"]),
            str(prepared / installer["caddy_config"]), installer["caddy_config_sha256"],
            str(prepared / installer["egress_allowlist"]), installer["egress_sha256"],
        )
        self._run(command)
        current = self.layout.path("/opt/uap-observer-current")
        target = os.readlink(current)
        prefix = "uap-observer-closures/"
        if not target.startswith(prefix) or DIGEST.fullmatch(target.removeprefix(prefix)) is None:
            raise ResetError("new observer current pointer is invalid")
        closure = target.removeprefix(prefix)
        controller._validate_install(manifest["new_install_identity"], closure)
        helper = current / "libexec/uap-observer-provision-profile"
        for client in CLIENTS:
            contract = manifest["clients"][client]
            seed = prepared / contract["seed"]
            shown = self._run((
                str(helper), "--client", client, "--root-owned-seed", str(seed),
                "--seed-digest", "show",
            ), capture=True).stdout.strip()
            if shown != contract["seed_digest"]:
                raise ResetError(f"prepared seed digest differs: {client}")
            self._run((
                str(helper), "--client", client, "--root-owned-seed", str(seed),
                "--seed-digest", contract["seed_digest"],
            ))
        library = source / "deploy/uap-observer-install-lib.sh"
        validation = (
            'set -eu; . "$1"; '
            'observer_validate_installed_accounts_and_state "$2" "$2/runtime"; '
            'observer_validate_protected_inputs "$2" "$2/runtime"'
        )
        self._run(("/bin/sh", "-c", validation, "reset-validation", str(library), str(current)))
        managed = (
            "uap-observer-egress-proxy.socket", "uap-observer-runner.socket",
            "uap-observer-signer.service", "uap-observer.service",
            "uap-observer-caddy.service",
        )
        self.systemd.start(managed)
        for unit in managed:
            if not self.systemd.state(unit)["active"]:
                raise ResetError(f"new observer unit is not active: {unit}")
        self.systemd.recreate_public_hop(closure)
        self.systemd.verify_public_hop(closure)
        self._verify_listeners()
        return {"install_identity": manifest["new_install_identity"], "closure_digest": closure}

    def verify_new(self, controller: "ResetController", journal: Mapping[str, Any]) -> None:
        new = journal.get("new")
        if not isinstance(new, dict):
            raise ResetError("new observer install is not journaled")
        controller._validate_install(new["install_identity"], new["closure_digest"])
        for unit in (
            "uap-observer-egress-proxy.socket", "uap-observer-runner.socket",
            "uap-observer-signer.service", "uap-observer.service",
            "uap-observer-caddy.service", PUBLIC_HOP_UNIT,
        ):
            if not self.systemd.state(unit)["active"]:
                raise ResetError(f"new observer unit is not active: {unit}")
        self.systemd.verify_public_hop(new["closure_digest"])
        self._verify_listeners()

    def _verify_listeners(self) -> None:
        completed = subprocess.run(
            ["ss", "-H", "-lnt"], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        listeners: dict[int, set[str]] = {80: set(), 443: set(), 8765: set(), 8766: set()}
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            address = fields[3]
            match = re.search(r"(?:\[([^]]+)\]|([^:]+)):(\d+)\Z", address)
            if match and int(match.group(3)) in listeners:
                listeners[int(match.group(3))].add(match.group(1) or match.group(2))
        if listeners[8765] != {"127.0.0.1"} or listeners[8766] != {"127.0.0.2"}:
            raise ResetError("observer private listener inventory differs")
        if not listeners[80] or not listeners[443]:
            raise ResetError("observer public listener is absent")


class ResetController:
    def __init__(
        self,
        layout: Layout,
        systemd: Systemd | Any | None = None,
        runtime_probe: RuntimeProbe | Any | None = None,
        executor: PreparedExecutor | Any | None = None,
        failpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.layout = layout
        self.systemd = systemd or Systemd()
        self.runtime_probe = runtime_probe or RuntimeProbe(layout)
        self.executor = executor or PreparedExecutor(layout, self.systemd)
        self.failpoint = failpoint or (lambda _name: None)
        self.journal_dir = layout.path("/var/lib/uap-observer-reset")
        self.journal_path = self.journal_dir / "journal.json"
        self.completion_path = layout.path("/var/lib/uap-observer-reset.completed")

    def locked(self):
        controller = self

        class Lock:
            def __enter__(self) -> int:
                lock_dir = controller.layout.path("/run/lock")
                lock_dir.mkdir(parents=True, exist_ok=True)
                lock_path = lock_dir / "uap-observer-install.lock"
                inherited = os.environ.get("UAP_OBSERVER_INSTALL_LOCK_FD")
                if inherited not in (None, "", "9"):
                    raise ResetError("observer install lock FD must be the reviewed descriptor 9")
                if inherited == "9":
                    try:
                        resolved = Path("/proc/self/fd/9").resolve(strict=True)
                    except (FileNotFoundError, OSError) as error:
                        raise ResetError("inherited observer install lock FD is unavailable") from error
                    if resolved != lock_path.resolve():
                        raise ResetError("inherited observer install lock FD points elsewhere")
                    self.descriptor = 9
                    self.owned = False
                else:
                    descriptor = os.open(
                        lock_path,
                        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0o600,
                    )
                    self.owned = True
                    if controller.layout.root is None and descriptor != 9:
                        os.dup2(descriptor, 9, inheritable=True)
                        os.close(descriptor)
                        descriptor = 9
                    self.descriptor = descriptor
                try:
                    fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    if self.owned:
                        os.close(self.descriptor)
                    raise ResetError("another observer install or reset is active") from error
                observed = metadata(lock_path)
                if observed["kind"] != "regular" or observed["nlink"] != 1 or observed["uid"] != controller.layout.expected_uid:
                    if self.owned:
                        os.close(self.descriptor)
                    raise ResetError("observer install lock path metadata differs")
                return self.descriptor

            def __exit__(self, *_args: Any) -> None:
                if self.owned:
                    os.close(self.descriptor)

        return Lock()

    def _machine(self, expected: str) -> None:
        if MACHINE_ID.fullmatch(expected) is None:
            raise ResetError("machine-id must be 32 lowercase hexadecimal characters")
        actual = read_control(
            self.layout.path("/etc/machine-id"), self.layout.expected_uid, 0o444, 4096,
        ).decode("ascii").strip()
        if actual != expected:
            raise ResetError("machine-id differs from the approved disposable VM")
        sentinel = strict_json(read_control(
            self.layout.path("/etc/uap-observer-disposable.json"),
            self.layout.expected_uid, 0o600,
        ))
        expected_sentinel = {
            "machine_id": expected,
            "purpose": SENTINEL_PURPOSE,
            "schema_version": SCHEMA_VERSION,
        }
        if sentinel != expected_sentinel:
            raise ResetError("disposable observer sentinel differs")

    def _validate_ids(self, install_identity: str, closure_digest: str) -> None:
        if DIGEST.fullmatch(install_identity) is None:
            raise ResetError("install identity must be 64 lowercase hexadecimal characters")
        if DIGEST.fullmatch(closure_digest) is None:
            raise ResetError("closure digest must be 64 lowercase hexadecimal characters")

    def _validate_install(self, install_identity: str, closure_digest: str) -> None:
        self._validate_ids(install_identity, closure_digest)
        current = self.layout.path("/opt/uap-observer-current")
        current_meta = metadata(current)
        expected_target = f"uap-observer-closures/{closure_digest}"
        if (
            current_meta["kind"] != "symlink"
            or current_meta["uid"] != self.layout.expected_uid
            or current_meta.get("target") != expected_target
        ):
            raise ResetError("observer current pointer differs from the expected closure")
        closures = self.layout.path("/opt/uap-observer-closures")
        validate_root_control(closures, self.layout.expected_uid, 0o755, "directory")
        names = sorted(path.name for path in closures.iterdir())
        if names != [closure_digest]:
            raise ResetError("observer closure inventory differs")
        closure = closures / closure_digest
        validate_root_control(closure, self.layout.expected_uid, 0o755, "directory")
        complete = read_control(closure / ".complete", self.layout.expected_uid, 0o644).decode().strip()
        identity = read_control(
            closure / ".install-identity", self.layout.expected_uid, 0o644,
        ).decode().strip()
        if complete != "complete-v1" or identity != install_identity:
            raise ResetError("observer closure markers differ")

    def _validate_fixed_inventory(self) -> None:
        state = self.layout.path("/var/lib/uap-observer")
        validate_root_control(state, self.layout.expected_uid, 0o711, "directory")
        names = sorted(path.name for path in state.iterdir())
        if names != ["jobs", "profiles", "proofs", "state", "workspaces"]:
            raise ResetError("observer mutable inventory differs")
        systemd = self.layout.path("/etc/systemd/system")
        observed = sorted(path.name for path in systemd.iterdir() if path.name.startswith("uap-observer"))
        expected = sorted([*UNITS, "uap-observer.service.d", "uap-observer-runner.service.d"])
        if observed != expected:
            raise ResetError("observer systemd inventory differs")
        for logical in PARTIALS:
            path = self.layout.path(logical)
            if path.exists() or path.is_symlink():
                raise ResetError(f"installer partial exists: {logical}")
        closures = self.layout.path("/opt/uap-observer-closures")
        if any(path.name.startswith(".new-") for path in closures.iterdir()):
            raise ResetError("installer closure partial exists")

    def _preserved(self) -> dict[str, dict[str, Any]]:
        values: dict[str, dict[str, Any]] = {}
        for logical in PRESERVED:
            path = self.layout.path(logical)
            observed = metadata(path)
            if observed["kind"] not in {"directory", "regular"}:
                raise ResetError(f"preserved path has unsafe type: {logical}")
            if observed["uid"] != self.layout.expected_uid and logical.startswith(("/etc/", "/opt/")):
                raise ResetError(f"preserved control path has unsafe owner: {logical}")
            if logical == "/etc/uap-observer-ed25519.key" and (
                observed["kind"] != "regular" or observed["mode"] != 0o600 or observed["nlink"] != 1
            ):
                raise ResetError("observer signing key metadata differs")
            if logical == "/etc/uap-observer-ed25519.pub" and (
                observed["kind"] != "regular" or observed["nlink"] != 1
            ):
                raise ResetError("observer public key metadata differs")
            values[logical] = {
                "metadata": observed,
                "sha256": regular_file_digest(path, observed) if observed["kind"] == "regular" else None,
                "tree_digest": preserved_tree_digest(path) if observed["kind"] == "directory" else None,
            }
        return values

    def _assert_preserved(self, journal: Mapping[str, Any]) -> None:
        expected = journal.get("preserved")
        if not isinstance(expected, dict) or set(expected) != set(PRESERVED):
            raise ResetError("reset journal preserved inventory differs")
        for logical, before in expected.items():
            path = self.layout.path(logical)
            if stable_metadata(metadata(path)) != stable_metadata(before["metadata"]):
                raise ResetError(f"preserved path changed during reset: {logical}")
            if before["sha256"] is not None and regular_file_digest(path, before["metadata"]) != before["sha256"]:
                raise ResetError(f"preserved file content changed during reset: {logical}")
            if before["tree_digest"] is not None and preserved_tree_digest(path) != before["tree_digest"]:
                raise ResetError(f"preserved tree content changed during reset: {logical}")

    def _transaction_id(self, machine: str, install: str, closure: str) -> str:
        return hashlib.sha256(f"{machine}\0{install}\0{closure}".encode()).hexdigest()[:24]

    def _quarantine(self, logical: str, transaction: str, candidate: bool = False) -> str:
        prefix = f".uap-observer-reset-{transaction}"
        if candidate:
            prefix += "-candidate"
        if logical.startswith("/opt/"):
            root = Path("/opt") / prefix
        elif logical.startswith("/var/lib/"):
            root = Path("/var/lib") / prefix
        elif logical.startswith("/etc/systemd/system/"):
            root = Path("/etc/systemd/system") / prefix
        elif logical.startswith("/usr/local/libexec/"):
            root = Path("/usr/local/libexec") / prefix
        elif logical.startswith("/usr/local/bin/"):
            root = Path("/usr/local/bin") / prefix
        elif logical.startswith("/etc/caddy/"):
            root = Path("/etc/caddy") / prefix
        elif logical.startswith("/etc/"):
            root = Path("/etc") / prefix
        else:
            raise ResetError(f"unreviewed quarantine domain: {logical}")
        name = logical.strip("/").replace("/", "--")
        return str(root / name)

    def _entry(self, logical: str, transaction: str, candidate: bool = False) -> dict[str, Any]:
        return {
            "source": logical,
            "quarantine": self._quarantine(logical, transaction, candidate),
            "metadata": metadata(self.layout.path(logical)),
        }

    def _write_journal(self, journal: Mapping[str, Any], create: bool = False) -> None:
        self.journal_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.journal_dir, 0o700)
        validate_root_control(self.journal_dir, self.layout.expected_uid, 0o700, "directory")
        temporary = self.journal_dir / ".journal.json.new"
        if temporary.exists() or temporary.is_symlink():
            raise ResetError("reset journal temporary path already exists")
        encoded = json.dumps(journal, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ResetError("short reset journal write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if create and (self.journal_path.exists() or self.journal_path.is_symlink()):
            temporary.unlink()
            raise ResetError("reset transaction already exists")
        os.replace(temporary, self.journal_path)
        fsync_directory(self.journal_dir)

    def _read_journal(self) -> dict[str, Any]:
        value = strict_json(read_control(
            self.journal_path, self.layout.expected_uid, 0o600, 1 << 20,
        ))
        required = {
            "schema_version", "transaction_id", "phase", "machine_id",
            "old_install_identity", "old_closure_digest", "preserved", "prepared",
            "units", "public_hop_contract", "old", "candidate", "new",
        }
        if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
            raise ResetError("reset journal schema differs")
        return value

    def _bind(self, journal: Mapping[str, Any], machine: str, install: str | None, closure: str | None) -> None:
        self._machine(machine)
        if journal.get("machine_id") != machine:
            raise ResetError("reset journal machine identity differs")
        if install is not None and journal.get("old_install_identity") != install:
            raise ResetError("reset journal old install identity differs")
        if closure is not None and journal.get("old_closure_digest") != closure:
            raise ResetError("reset journal old closure differs")

    def _ensure_quarantine_parent(self, logical: str) -> None:
        path = self.layout.path(logical)
        parent = path.parent
        base = parent.parent
        validate_root_control(base, self.layout.expected_uid, stat.S_IMODE(os.lstat(base).st_mode), "directory")
        if not parent.exists():
            os.mkdir(parent, 0o700)
            fsync_directory(base)
        validate_root_control(parent, self.layout.expected_uid, 0o700, "directory")

    def _move(self, entry: Mapping[str, Any], reverse: bool = False) -> None:
        source_logical = str(entry["quarantine"] if reverse else entry["source"])
        target_logical = str(entry["source"] if reverse else entry["quarantine"])
        expected = entry["metadata"]
        source = self.layout.path(source_logical)
        target = self.layout.path(target_logical)
        self._ensure_quarantine_parent(str(entry["quarantine"]))
        source_exists = source.exists() or source.is_symlink()
        target_exists = target.exists() or target.is_symlink()
        if target_exists and not source_exists:
            if stable_metadata(metadata(target)) != stable_metadata(expected):
                raise ResetError(f"quarantine object was substituted: {target_logical}")
            return
        if source_exists and target_exists:
            raise ResetError("both reset source and quarantine target exist")
        if not source_exists:
            raise ResetError(f"reset source disappeared: {source_logical}")
        if stable_metadata(metadata(source)) != stable_metadata(expected):
            raise ResetError(f"reset source was substituted: {source_logical}")
        source_parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        target_parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            if os.fstat(source_parent).st_dev != os.fstat(target_parent).st_dev:
                raise ResetError("quarantine rename is not on one filesystem")
            os.rename(
                source.name, target.name,
                src_dir_fd=source_parent, dst_dir_fd=target_parent,
            )
            os.fsync(source_parent)
            os.fsync(target_parent)
        finally:
            os.close(target_parent)
            os.close(source_parent)
        if stable_metadata(metadata(target)) != stable_metadata(expected):
            raise ResetError("quarantine identity changed during rename")

    def _states(self) -> dict[str, dict[str, bool]]:
        return {unit: self.systemd.state(unit) for unit in ALL_UNITS}

    def _prepared(self) -> dict[str, Any]:
        root = self.layout.path(PREPARED_ROOT)
        observed = validate_root_control(root, self.layout.expected_uid, 0o700, "directory")
        expected_root = [*PREPARED_INVENTORY, "manifest.json"]
        if sorted(path.name for path in root.iterdir()) != sorted(expected_root):
            raise ResetError("prepared reset root inventory differs")
        children: dict[str, dict[str, Any]] = {}
        for name in PREPARED_INVENTORY:
            child = root / name
            children[name] = validate_root_control(child, self.layout.expected_uid, 0o700, "directory")
        manifest_path = root / "manifest.json"
        encoded = read_control(manifest_path, self.layout.expected_uid, 0o400, 1 << 20)
        manifest = strict_json(encoded)
        digest_pattern = re.compile(r"sha256:[0-9a-f]{64}\Z")
        installer_fields = {
            "source_root", "adapter_config", "adapter_sha256", "observer_config",
            "observer_sha256", "caddy_archive", "caddy_config",
            "caddy_config_sha256", "egress_allowlist", "egress_sha256",
        }
        client_fields = {"seed", "seed_digest", "projection_digest"}
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema_version", "purpose", "catalog_sha", "new_install_identity", "installer", "clients", "tree_digests"}
            or manifest.get("schema_version") != 1
            or manifest.get("purpose") != PREPARED_PURPOSE
            or re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("catalog_sha", ""))) is None
            or DIGEST.fullmatch(str(manifest.get("new_install_identity", ""))) is None
            or not isinstance(manifest.get("installer"), dict)
            or set(manifest["installer"]) != installer_fields
            or not isinstance(manifest.get("clients"), dict)
            or set(manifest["clients"]) != set(CLIENTS)
            or not isinstance(manifest.get("tree_digests"), dict)
            or set(manifest["tree_digests"]) != set(PREPARED_INVENTORY)
        ):
            raise ResetError("prepared reset manifest schema differs")
        exact_paths = {
            "source_root": "evidence/source",
            "adapter_config": "evidence/uap-observer-adapter-config.json",
            "observer_config": "evidence/uap-observer.json",
            "caddy_archive": "evidence/caddy_2.11.4_linux_amd64.tar.gz",
            "caddy_config": "evidence/Caddyfile",
            "egress_allowlist": "evidence/uap-observer-egress-allowlist.json",
        }
        installer = manifest["installer"]
        if any(installer.get(field) != value for field, value in exact_paths.items()):
            raise ResetError("prepared installer path differs")
        for field in ("adapter_sha256", "observer_sha256", "caddy_config_sha256", "egress_sha256"):
            if not isinstance(installer.get(field), str) or digest_pattern.fullmatch(installer[field]) is None:
                raise ResetError("prepared installer digest differs")
        evidence_expected = {
            "source", "uap-observer-adapter-config.json", "uap-observer.json",
            "caddy_2.11.4_linux_amd64.tar.gz", "Caddyfile",
            "uap-observer-egress-allowlist.json",
        }
        if {path.name for path in (root / "evidence").iterdir()} != evidence_expected:
            raise ResetError("prepared evidence inventory differs")
        for client in CLIENTS:
            client_value = manifest["clients"][client]
            if (
                not isinstance(client_value, dict) or set(client_value) != client_fields
                or client_value.get("seed") != f"seeds/{client}"
                or any(digest_pattern.fullmatch(str(client_value.get(field, ""))) is None for field in ("seed_digest", "projection_digest"))
            ):
                raise ResetError(f"prepared client contract differs: {client}")
        adapter_path = root / installer["adapter_config"]
        adapter = strict_json(read_control(
            adapter_path, self.layout.expected_uid, 0o400, 4 << 20,
        ))
        adapter_clients = adapter.get("clients") if isinstance(adapter, dict) else None
        if not isinstance(adapter_clients, dict):
            raise ResetError("prepared adapter config client inventory differs")
        for client in CLIENTS:
            record = adapter_clients.get(client)
            projection_contract = record.get("native_projection") if isinstance(record, dict) else None
            expected_contract = {
                "path": f"/var/lib/uap-observer/proofs/{client}/native-projection.json",
                "sha256": manifest["clients"][client]["projection_digest"],
            }
            if projection_contract != expected_contract:
                raise ResetError(f"prepared adapter projection binding differs: {client}")
        for name in ("seeds", "path"):
            if {path.name for path in (root / name).iterdir()} != set(CLIENTS):
                raise ResetError(f"prepared {name} inventory differs")
        projection = root / "projection-digests"
        if {path.name for path in projection.iterdir()} != {f"{client}.sha256" for client in CLIENTS}:
            raise ResetError("prepared projection digest inventory differs")
        for client in CLIENTS:
            value = read_control(
                projection / f"{client}.sha256", self.layout.expected_uid, 0o400, 4096,
            ).decode("ascii")
            if value != manifest["clients"][client]["projection_digest"] + "\n":
                raise ResetError(f"prepared projection digest file differs: {client}")
        for field, relative in (
            ("adapter_sha256", installer["adapter_config"]),
            ("observer_sha256", installer["observer_config"]),
            ("caddy_config_sha256", installer["caddy_config"]),
            ("egress_sha256", installer["egress_allowlist"]),
        ):
            path = root / relative
            actual = "sha256:" + hashlib.sha256(read_control(
                path, self.layout.expected_uid, stat.S_IMODE(os.lstat(path).st_mode), 4 << 20,
            )).hexdigest()
            if actual != installer[field]:
                raise ResetError(f"prepared installer content digest differs: {field}")
        tree_digests = {
            name: prepared_tree_digest(root / name, self.layout.expected_uid)
            for name in PREPARED_INVENTORY
        }
        if tree_digests != manifest["tree_digests"]:
            raise ResetError("prepared tree digest differs")
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if encoded != canonical:
            raise ResetError("prepared manifest is not canonical JSON")
        return {
            "root": observed,
            "children": children,
            "manifest_sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
            "tree_digests": tree_digests,
            "manifest": manifest,
        }

    def _assert_prepared(self, journal: Mapping[str, Any], allow_removed: bool = False) -> None:
        root = self.layout.path(PREPARED_ROOT)
        if allow_removed and not root.exists() and not root.is_symlink():
            return
        expected = journal.get("prepared")
        if not isinstance(expected, dict) or set(expected) != {"root", "children", "manifest_sha256", "tree_digests", "manifest"}:
            raise ResetError("prepared reset journal binding differs")
        observed = self._prepared()
        if observed != expected:
            raise ResetError("prepared reset bundle changed")

    def _stop_and_quiesce(self) -> None:
        self.systemd.stop((PUBLIC_HOP_UNIT,))
        self.systemd.stop(UNITS)
        for unit in ALL_UNITS:
            if self.systemd.state(unit)["active"]:
                raise ResetError(f"observer unit remains active: {unit}")
        self.runtime_probe.assert_quiescent()

    def _clean_postcheck(self) -> None:
        for logical in MANAGED:
            path = self.layout.path(logical)
            if path.exists() or path.is_symlink():
                raise ResetError(f"managed path remains after reset: {logical}")
        for logical in PARTIALS:
            path = self.layout.path(logical)
            if path.exists() or path.is_symlink():
                raise ResetError(f"installer partial remains after reset: {logical}")

    def _assert_installed_projections(self, manifest: Mapping[str, Any]) -> None:
        for client in CLIENTS:
            path = self.layout.path(
                f"/var/lib/uap-observer/proofs/{client}/native-projection.json"
            )
            encoded = read_control(path, self.layout.expected_uid, 0o440, 16 << 20)
            actual = "sha256:" + hashlib.sha256(encoded).hexdigest()
            if actual != manifest["clients"][client]["projection_digest"]:
                raise ResetError(f"installed projection digest differs: {client}")

    def apply(self, machine: str, old_install: str, old_closure: str) -> dict[str, Any]:
        with self.locked():
            self._machine(machine)
            self._validate_ids(old_install, old_closure)
            if self.completion_path.exists() or self.completion_path.is_symlink():
                raise ResetError("completed reset cleanup remains; run finalize or rollback")
            if self.journal_path.exists() or self.journal_path.is_symlink():
                journal = self._read_journal()
                self._bind(journal, machine, old_install, old_closure)
                if journal["phase"] not in {"prepared", "quarantining", "applied", "new-ready"}:
                    raise ResetError(f"reset transaction is {journal['phase']}; apply cannot continue")
            else:
                self._validate_install(old_install, old_closure)
                self._validate_fixed_inventory()
                transaction = self._transaction_id(machine, old_install, old_closure)
                journal = {
                    "schema_version": SCHEMA_VERSION,
                    "transaction_id": transaction,
                    "phase": "prepared",
                    "machine_id": machine,
                    "old_install_identity": old_install,
                    "old_closure_digest": old_closure,
                    "preserved": self._preserved(),
                    "prepared": self._prepared(),
                    "units": (states := self._states()),
                    "public_hop_contract": (
                        self.systemd.validate_public_hop_contract()
                        if states[PUBLIC_HOP_UNIT]["active"] else None
                    ),
                    "old": [self._entry(path, transaction) for path in MANAGED],
                    "candidate": [],
                    "new": None,
                }
                self._write_journal(journal, create=True)
                self.failpoint("after-journal")
            self._assert_preserved(journal)
            self._assert_prepared(journal)
            if journal["phase"] == "new-ready":
                self.executor.verify_new(self, journal)
                self._assert_installed_projections(journal["prepared"]["manifest"])
                return self._status(journal)
            self._stop_and_quiesce()
            self.failpoint("after-stop")
            if journal["phase"] != "applied":
                journal["phase"] = "quarantining"
                self._write_journal(journal)
                for index, entry in enumerate(journal["old"]):
                    self._move(entry)
                    self.failpoint(f"after-quarantine:{index}")
                self._clean_postcheck()
                self._assert_preserved(journal)
                journal["phase"] = "applied"
                self._write_journal(journal)
            else:
                self._clean_postcheck()
            self.failpoint("after-applied")
            try:
                self._assert_prepared(journal)
                new = self.executor.prepare_new(self, journal)
                self._assert_prepared(journal)
                self._assert_installed_projections(journal["prepared"]["manifest"])
                expected = journal["prepared"]["manifest"]["new_install_identity"]
                if new.get("install_identity") != expected or DIGEST.fullmatch(str(new.get("closure_digest", ""))) is None:
                    raise ResetError("prepared executor returned a different new install")
                journal["new"] = new
                journal["phase"] = "new-ready"
                self._write_journal(journal)
                self.executor.verify_new(self, journal)
                return self._status(journal)
            except InjectedFailure:
                raise
            except Exception as primary:
                try:
                    self._rollback_locked(journal)
                except Exception as rollback_error:
                    raise ResetError(
                        "new observer preparation failed: "
                        f"{primary}; automatic rollback also failed: {rollback_error}"
                    ) from primary
                raise

    def status(self, machine: str) -> dict[str, Any]:
        with self.locked():
            self._machine(machine)
            if not self.journal_path.exists() and not self.journal_path.is_symlink():
                completion = self._read_completion(optional=True)
                if completion is None:
                    raise ResetError("reset transaction is absent")
                if completion["machine_id"] != machine:
                    raise ResetError("reset completion machine identity differs")
                return {
                    "schema_version": SCHEMA_VERSION,
                    "transaction_id": completion["transaction_id"],
                    "phase": completion["outcome"],
                    "old_quarantined": 0,
                    "old_total": 0,
                    "candidate_quarantined": 0,
                    "new_install_identity": (
                        None if completion["new"] is None
                        else completion["new"]["install_identity"]
                    ),
                }
            journal = self._read_journal()
            self._bind(journal, machine, None, None)
            self._assert_preserved(journal)
            self._assert_prepared(journal, allow_removed=journal["phase"] == "finalizing")
            return self._status(journal)

    def _status(self, journal: Mapping[str, Any]) -> dict[str, Any]:
        old_quarantined = sum(
            1 for entry in journal["old"]
            if self.layout.path(entry["quarantine"]).exists()
            or self.layout.path(entry["quarantine"]).is_symlink()
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "transaction_id": journal["transaction_id"],
            "phase": journal["phase"],
            "old_quarantined": old_quarantined,
            "old_total": len(journal["old"]),
            "candidate_quarantined": len(journal["candidate"]),
            "new_install_identity": None if journal["new"] is None else journal["new"]["install_identity"],
        }

    def _candidate_paths(self) -> list[str]:
        values = list(MANAGED)
        for logical in PARTIALS:
            path = self.layout.path(logical)
            if path.exists() or path.is_symlink():
                values.append(logical)
        closures = self.layout.path("/opt/uap-observer-closures")
        if closures.is_dir():
            # The whole closures root is already in MANAGED; no child wildcard
            # is separately moved.
            pass
        return values

    def _prepare_candidate(self, journal: dict[str, Any]) -> None:
        if journal["candidate"]:
            return
        transaction = journal["transaction_id"]
        entries = []
        old_by_source = {entry["source"]: entry for entry in journal["old"]}
        for logical in self._candidate_paths():
            source = self.layout.path(logical)
            old = old_by_source.get(logical)
            old_quarantine_exists = old is not None and (
                self.layout.path(old["quarantine"]).exists()
                or self.layout.path(old["quarantine"]).is_symlink()
            )
            if not old_quarantine_exists and old is not None:
                # Apply did not yet move this old object; it is not candidate.
                continue
            if source.exists() or source.is_symlink():
                entries.append(self._entry(logical, transaction, candidate=True))
        journal["candidate"] = entries
        journal["phase"] = "rolling_back"
        self._write_journal(journal)

    def _restore_units(self, journal: Mapping[str, Any]) -> None:
        self.systemd.daemon_reload()
        enabled = [unit for unit, state in journal["units"].items() if state["enabled"] and unit != PUBLIC_HOP_UNIT]
        disabled = [unit for unit, state in journal["units"].items() if not state["enabled"] and unit != PUBLIC_HOP_UNIT]
        self.systemd.enable(enabled)
        self.systemd.disable(disabled)
        active = [unit for unit, state in journal["units"].items() if state["active"] and unit != PUBLIC_HOP_UNIT]
        self.systemd.start(active)
        for unit in active:
            if not self.systemd.state(unit)["active"]:
                raise ResetError(f"restored observer unit is not active: {unit}")
        if journal["units"][PUBLIC_HOP_UNIT]["active"]:
            self.systemd.recreate_public_hop(journal["old_closure_digest"])
            self.systemd.verify_public_hop(journal["old_closure_digest"])

    def rollback(self, machine: str, old_install: str, old_closure: str) -> dict[str, Any]:
        with self.locked():
            if not self.journal_path.exists() and not self.journal_path.is_symlink():
                self._machine(machine)
                self._validate_ids(old_install, old_closure)
                completion = self._read_completion(optional=True)
                if completion is not None:
                    self._validate_completion(
                        completion, "rolled_back", machine, old_install, old_closure,
                    )
                    self._validate_install(old_install, old_closure)
                    self._finish_completion(completion)
                else:
                    self._validate_install(old_install, old_closure)
                    self._assert_no_quarantine(
                        self._transaction_id(machine, old_install, old_closure)
                    )
                return {"schema_version": SCHEMA_VERSION, "phase": "rolled_back"}
            journal = self._read_journal()
            self._bind(journal, machine, old_install, old_closure)
            return self._rollback_locked(journal)

    def _rollback_locked(self, journal: dict[str, Any]) -> dict[str, Any]:
        if journal["phase"] == "finalizing":
            raise ResetError("finalization already began; rollback is no longer possible")
        if journal["phase"] not in {
            "prepared", "quarantining", "applied", "new-ready", "rolling_back",
            "rollback-cleanup",
        }:
            raise ResetError(f"reset transaction is {journal['phase']}; rollback cannot continue")
        self._assert_preserved(journal)
        self._assert_prepared(journal)
        if journal["phase"] != "rollback-cleanup":
            self._stop_and_quiesce()
            self._prepare_candidate(journal)
            for index, entry in enumerate(journal["candidate"]):
                quarantine = self.layout.path(entry["quarantine"])
                if quarantine.exists() or quarantine.is_symlink():
                    if stable_metadata(metadata(quarantine)) != stable_metadata(entry["metadata"]):
                        raise ResetError("candidate quarantine was substituted")
                else:
                    self._move(entry)
                self.failpoint(f"after-candidate-quarantine:{index}")
            for index, entry in enumerate(reversed(journal["old"])):
                quarantine = self.layout.path(entry["quarantine"])
                source = self.layout.path(entry["source"])
                if quarantine.exists() or quarantine.is_symlink():
                    if source.exists() or source.is_symlink():
                        raise ResetError("candidate source remains before old restore")
                    self._move(entry, reverse=True)
                elif stable_metadata(metadata(source)) != stable_metadata(entry["metadata"]):
                    raise ResetError("old reset object is missing or substituted")
                self.failpoint(f"after-old-restore:{index}")
            self._validate_install(journal["old_install_identity"], journal["old_closure_digest"])
            self._assert_preserved(journal)
            self._assert_prepared(journal)
            self._restore_units(journal)
            self._assert_preserved(journal)
            journal["phase"] = "rollback-cleanup"
            self._write_journal(journal)
        else:
            self._validate_install(journal["old_install_identity"], journal["old_closure_digest"])
        self._delete_entries(journal["candidate"])
        self._remove_transaction_roots(journal, "rolled_back")
        return {"schema_version": SCHEMA_VERSION, "phase": "rolled_back"}

    def _verify_public_hop_new_pointer(self, journal: Mapping[str, Any], closure: str) -> None:
        if not journal["units"][PUBLIC_HOP_UNIT]["active"]:
            return
        if not self.systemd.state(PUBLIC_HOP_UNIT)["active"]:
            self.systemd.recreate_public_hop(closure)
        if not self.systemd.state(PUBLIC_HOP_UNIT)["active"]:
            raise ResetError("public Caddy hop did not restart")
        if hasattr(self.systemd, "verify_public_hop"):
            self.systemd.verify_public_hop(closure)
            return
        show = subprocess.run(
            ["systemctl", "show", PUBLIC_HOP_UNIT, "--property=ExecStart", "--value"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        expected = f"/opt/uap-observer-closures/{closure}/bin/caddy"
        if expected not in show and "/opt/uap-observer-current/bin/caddy" not in show:
            raise ResetError("public Caddy hop executable is not bound to the new observer pointer")

    def finalize(
        self,
        machine: str,
        old_install: str,
        old_closure: str,
        new_install: str,
        new_closure: str,
    ) -> dict[str, Any]:
        with self.locked():
            if not self.journal_path.exists() and not self.journal_path.is_symlink():
                self._machine(machine)
                self._validate_ids(old_install, old_closure)
                completion = self._read_completion(optional=True)
                if completion is not None:
                    self._validate_completion(
                        completion, "finalized", machine, old_install, old_closure,
                        new_install, new_closure,
                    )
                self._validate_install(new_install, new_closure)
                transaction = self._transaction_id(machine, old_install, old_closure)
                self._assert_no_quarantine(transaction)
                if self.layout.path(PREPARED_ROOT).exists() or self.layout.path(PREPARED_ROOT).is_symlink():
                    raise ResetError("completed reset still has prepared residue")
                self.executor.verify_new(self, {"new": {
                    "install_identity": new_install, "closure_digest": new_closure,
                }})
                if completion is not None:
                    self._finish_completion(completion)
                return {"schema_version": SCHEMA_VERSION, "phase": "finalized", "new_install_identity": new_install}
            journal = self._read_journal()
            self._bind(journal, machine, old_install, old_closure)
            if journal["phase"] not in {"new-ready", "finalizing"}:
                raise ResetError(f"reset transaction is {journal['phase']}; finalize cannot continue")
            self._validate_install(new_install, new_closure)
            self._assert_preserved(journal)
            self._assert_prepared(journal, allow_removed=journal["phase"] == "finalizing")
            self._verify_public_hop_new_pointer(journal, new_closure)
            if journal.get("new") != {"install_identity": new_install, "closure_digest": new_closure}:
                raise ResetError("verified new install differs from the journal")
            self.executor.verify_new(self, journal)
            self._assert_installed_projections(journal["prepared"]["manifest"])
            self._assert_preserved(journal)
            if journal["new"] is None:
                journal["new"] = {
                    "install_identity": new_install,
                    "closure_digest": new_closure,
                }
            journal["phase"] = "finalizing"
            self._write_journal(journal)
            self._delete_entries(journal["old"])
            self._assert_preserved(journal)
            prepared = self.layout.path(PREPARED_ROOT)
            if prepared.exists() or prepared.is_symlink():
                self._assert_prepared(journal)
                self._remove_tree(prepared)
            self._remove_transaction_roots(journal, "finalized")
            return {"schema_version": SCHEMA_VERSION, "phase": "finalized", "new_install_identity": new_install}

    def _preflight_tree(self, path: Path, device: int, budget: list[int]) -> None:
        info = os.lstat(path)
        budget[0] += 1
        if budget[0] > 1_000_000:
            raise ResetError("reset cleanup entry bound exceeded")
        if info.st_dev != device:
            raise ResetError("reset cleanup crosses a filesystem boundary")
        if stat.S_ISDIR(info.st_mode):
            for child in os.scandir(path):
                self._preflight_tree(Path(child.path), device, budget)
        elif not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            raise ResetError("reset cleanup contains a special file")

    def _remove_tree(self, path: Path) -> None:
        info = os.lstat(path)
        self._preflight_tree(path, info.st_dev, [0])

        def remove(current: Path) -> None:
            observed = os.lstat(current)
            if stat.S_ISDIR(observed.st_mode):
                for child in list(os.scandir(current)):
                    remove(Path(child.path))
                os.rmdir(current)
            else:
                os.unlink(current)

        remove(path)
        fsync_directory(path.parent)

    def _delete_entries(self, entries: Iterable[Mapping[str, Any]]) -> None:
        for index, entry in enumerate(entries):
            quarantine = self.layout.path(str(entry["quarantine"]))
            if not (quarantine.exists() or quarantine.is_symlink()):
                continue
            if stable_metadata(metadata(quarantine)) != stable_metadata(entry["metadata"]):
                raise ResetError("quarantined reset object was substituted before cleanup")
            self._remove_tree(quarantine)
            self.failpoint(f"after-delete:{index}")

    def _completion_record(self, journal: Mapping[str, Any], outcome: str) -> dict[str, Any]:
        if outcome not in {"finalized", "rolled_back"}:
            raise ResetError("reset completion outcome differs")
        new = journal.get("new") if outcome == "finalized" else None
        if outcome == "finalized" and not isinstance(new, dict):
            raise ResetError("finalized reset has no new install identity")
        return {
            "schema_version": SCHEMA_VERSION,
            "outcome": outcome,
            "transaction_id": journal["transaction_id"],
            "machine_id": journal["machine_id"],
            "old_install_identity": journal["old_install_identity"],
            "old_closure_digest": journal["old_closure_digest"],
            "new": new,
        }

    def _read_completion(self, optional: bool = False) -> dict[str, Any] | None:
        if not (self.completion_path.exists() or self.completion_path.is_symlink()):
            if optional:
                return None
            raise ResetError("reset completion record is absent")
        value = strict_json(read_control(
            self.completion_path, self.layout.expected_uid, 0o600, 64 << 10,
        ))
        required = {
            "schema_version", "outcome", "transaction_id", "machine_id",
            "old_install_identity", "old_closure_digest", "new",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("outcome") not in {"finalized", "rolled_back"}
            or re.fullmatch(r"[0-9a-f]{24}", str(value.get("transaction_id", ""))) is None
            or MACHINE_ID.fullmatch(str(value.get("machine_id", ""))) is None
            or DIGEST.fullmatch(str(value.get("old_install_identity", ""))) is None
            or DIGEST.fullmatch(str(value.get("old_closure_digest", ""))) is None
        ):
            raise ResetError("reset completion record schema differs")
        new = value["new"]
        if value["outcome"] == "rolled_back":
            if new is not None:
                raise ResetError("rolled-back completion unexpectedly binds a new install")
        elif (
            not isinstance(new, dict)
            or set(new) != {"install_identity", "closure_digest"}
            or DIGEST.fullmatch(str(new.get("install_identity", ""))) is None
            or DIGEST.fullmatch(str(new.get("closure_digest", ""))) is None
        ):
            raise ResetError("finalized completion new install binding differs")
        if value["transaction_id"] != self._transaction_id(
            value["machine_id"], value["old_install_identity"], value["old_closure_digest"],
        ):
            raise ResetError("reset completion transaction identity differs")
        return value

    def _write_completion(self, record: Mapping[str, Any]) -> None:
        encoded = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode() + b"\n"
        temporary = self.completion_path.with_name(self.completion_path.name + ".new")
        if self.completion_path.exists() or self.completion_path.is_symlink():
            if temporary.exists() or temporary.is_symlink():
                raise ResetError("reset completion temporary path also exists")
            if read_control(
                self.completion_path, self.layout.expected_uid, 0o600, 64 << 10,
            ) != encoded:
                raise ResetError("reset completion record differs")
            return
        if temporary.exists() or temporary.is_symlink():
            if read_control(
                temporary, self.layout.expected_uid, 0o600, 64 << 10,
            ) != encoded:
                raise ResetError("reset completion temporary record differs")
        else:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ResetError("short reset completion write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.replace(temporary, self.completion_path)
        fsync_directory(self.completion_path.parent)

    def _validate_completion(
        self,
        completion: Mapping[str, Any],
        outcome: str,
        machine: str,
        old_install: str,
        old_closure: str,
        new_install: str | None = None,
        new_closure: str | None = None,
    ) -> None:
        expected_new = (
            None if new_install is None
            else {"install_identity": new_install, "closure_digest": new_closure}
        )
        expected = {
            "schema_version": SCHEMA_VERSION,
            "outcome": outcome,
            "transaction_id": self._transaction_id(machine, old_install, old_closure),
            "machine_id": machine,
            "old_install_identity": old_install,
            "old_closure_digest": old_closure,
            "new": expected_new,
        }
        if completion != expected:
            raise ResetError("reset completion record binding differs")

    def _assert_no_quarantine(self, transaction: str) -> None:
        for parent in (
            "/opt", "/var/lib", "/etc/systemd/system", "/usr/local/libexec",
            "/usr/local/bin", "/etc/caddy", "/etc",
        ):
            root = self.layout.path(parent)
            if root.exists() and any(
                path.name.startswith(f".uap-observer-reset-{transaction}")
                for path in root.iterdir()
            ):
                raise ResetError("completed reset still has quarantine residue")

    def _finish_completion(self, completion: Mapping[str, Any]) -> None:
        if self.journal_path.exists() or self.journal_path.is_symlink():
            raise ResetError("reset journal remains during completion recovery")
        if self.journal_dir.exists() or self.journal_dir.is_symlink():
            validate_root_control(
                self.journal_dir, self.layout.expected_uid, 0o700, "directory",
            )
            if any(self.journal_dir.iterdir()):
                raise ResetError("reset journal directory is not empty")
            self.journal_dir.rmdir()
            fsync_directory(self.journal_dir.parent)
            self.failpoint("after-journal-dir-remove")
        observed = self._read_completion()
        if observed != completion:
            raise ResetError("reset completion record changed")
        self.completion_path.unlink()
        fsync_directory(self.completion_path.parent)
        self.failpoint("after-completion-remove")

    def _remove_transaction_roots(self, journal: Mapping[str, Any], outcome: str) -> None:
        transaction = journal["transaction_id"]
        roots: set[Path] = set()
        for entry in [*journal["old"], *journal["candidate"]]:
            roots.add(self.layout.path(entry["quarantine"]).parent)
        if not all(f".uap-observer-reset-{transaction}" in str(root) for root in roots):
            raise ResetError("unexpected reset quarantine root")
        for root in sorted(roots, key=lambda path: len(path.parts), reverse=True):
            if root.exists():
                validate_root_control(root, self.layout.expected_uid, 0o700, "directory")
                if any(root.iterdir()):
                    raise ResetError(f"reset quarantine is not empty: {root.name}")
                root.rmdir()
                fsync_directory(root.parent)
        completion = self._completion_record(journal, outcome)
        self._write_completion(completion)
        self.failpoint("after-completion-marker")
        if self.journal_path.exists() or self.journal_path.is_symlink():
            if self._read_journal() != journal:
                raise ResetError("reset journal changed before completion")
            self.journal_path.unlink()
            fsync_directory(self.journal_dir)
        self.failpoint("after-journal-unlink")
        if any(self.journal_dir.iterdir()):
            raise ResetError("reset journal directory is not empty")
        self.journal_dir.rmdir()
        fsync_directory(self.journal_dir.parent)
        self.failpoint("after-journal-dir-remove")
        if self._read_completion() != completion:
            raise ResetError("reset completion record changed")
        self.completion_path.unlink()
        fsync_directory(self.completion_path.parent)
        self.failpoint("after-completion-remove")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subcommands = value.add_subparsers(dest="command", required=True)

    def old(command: str) -> argparse.ArgumentParser:
        child = subcommands.add_parser(command)
        child.add_argument("--machine-id", required=True)
        child.add_argument("--old-install-identity", required=True)
        child.add_argument("--old-closure-digest", required=True)
        return child

    old("apply")
    status = subcommands.add_parser("status")
    status.add_argument("--machine-id", required=True)
    old("rollback")
    final = old("finalize")
    final.add_argument("--new-install-identity", required=True)
    final.add_argument("--new-closure-digest", required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    if os.geteuid() != 0:
        raise ResetError("observer reset must run as root")
    arguments = parser().parse_args(argv)
    controller = ResetController(Layout.production())
    if arguments.command == "status":
        result = controller.status(arguments.machine_id)
    elif arguments.command == "apply":
        result = controller.apply(
            arguments.machine_id, arguments.old_install_identity,
            arguments.old_closure_digest,
        )
    elif arguments.command == "rollback":
        result = controller.rollback(
            arguments.machine_id, arguments.old_install_identity,
            arguments.old_closure_digest,
        )
    else:
        result = controller.finalize(
            arguments.machine_id, arguments.old_install_identity,
            arguments.old_closure_digest, arguments.new_install_identity,
            arguments.new_closure_digest,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ResetError as error:
        print(f"observer reset failed: {error}", file=sys.stderr)
        raise SystemExit(1)
