"""Bounded whole-root acquisition for v3 static scans of cold Git sources.

Blobless Git repositories otherwise fetch one object per size query. Hydrate
validated object IDs in small batches, then read only local objects. This does
not change the source tree, execute source files, or split the analysis root.
"""
from __future__ import annotations

import collections
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.build_bridges import BridgeError, GIT_MODES, LFS_HEADER, portable_path
from scripts.build_discovery_index import DiscoveryError, DiscoveryInputLimitError, normalized_path
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget

FETCH_CHUNK_OBJECTS = 32
TREE_METADATA_BYTES = 16 << 20
STDERR_BYTES = 64 << 10
PACK_BASE_OVERHEAD = 1 << 20
PACK_PER_FILE_OVERHEAD = 256
OID = re.compile(r"[0-9a-f]{40}\Z")

# Set limits in a separate interpreter, not preexec_fn in a threaded process.
# RLIMIT_FSIZE is a per-file limit; cumulative pack bytes are checked separately.
LIMITED_GIT = """import os, resource, sys
limit = int(sys.argv[1])
_, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
if hard != resource.RLIM_INFINITY:
    limit = min(limit, hard)
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execvpe('git', ['git', *sys.argv[2:]], os.environ)
"""


class AcquisitionTransferLimit(DiscoveryInputLimitError):
    """The bounded Git transfer/capture allowance was exhausted."""


def _require(condition, message):
    if not condition:
        raise DiscoveryError(message)


def _environment():
    return {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "LANG": "C", "LC_ALL": "C"}


def _run_git(repository, arguments, budget, *, input_bytes=b"", output_limit=STDERR_BYTES, file_limit=None):
    """Capture bounded output and kill all Git helpers at the shared deadline."""
    arguments = ["--no-lazy-fetch", *arguments]
    command = ([sys.executable, "-c", LIMITED_GIT, str(file_limit), *arguments]
               if file_limit is not None else ["git", *arguments])
    output, errors = bytearray(), bytearray()
    budget.check()
    command_budget = WorkBudget(min(120, budget.remaining()))
    with tempfile.TemporaryFile() as input_file:
        input_file.write(input_bytes)
        input_file.seek(0)
        with subprocess.Popen(command, cwd=repository.root, env=_environment(), stdin=input_file,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as process:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, (output, output_limit))
                    selector.register(process.stderr, selectors.EVENT_READ, (errors, STDERR_BYTES))
                    while selector.get_map():
                        for key, _ in selector.select(timeout=min(1, budget.remaining(), command_budget.remaining())):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            target, limit = key.data
                            if len(target) + len(chunk) > limit:
                                raise AcquisitionTransferLimit("Git acquisition output exceeds its bounded capture")
                            target.extend(chunk)
                    process.wait(timeout=min(budget.remaining(), command_budget.remaining()))
                budget.check()
            except BaseException as error:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                if isinstance(error, subprocess.TimeoutExpired):
                    raise CheckpointYield("Git acquisition reached its preparation deadline") from error
                raise
            if process.returncode:
                detail = bytes(errors).lower()
                if file_limit is not None and (process.returncode == -signal.SIGXFSZ or
                        any(text in detail for text in (b"file too large", b"file size limit", b"signal 25"))):
                    raise AcquisitionTransferLimit("Git transfer reached its bounded pack-file allowance")
                raise BridgeError("Bounded Git acquisition failed: " + bytes(errors[:512]).decode("utf-8", "replace"))
    return bytes(output)


def _tree_records(repository, package_path, max_files, budget):
    prefix = normalized_path(package_path)
    raw = _run_git(repository, ["ls-tree", "-rz", "-r", repository.revision, "--", prefix or "."],
        budget, output_limit=TREE_METADATA_BYTES)
    _require(not raw or raw.endswith(b"\0"), "package tree is truncated")
    records, seen = [], set()
    prefix_with_slash = prefix + "/" if prefix else ""
    for row in raw.split(b"\0"):
        budget.check()
        if not row:
            continue
        try:
            metadata, encoded_path = row.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            full_path = encoded_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise DiscoveryError("package tree contains an invalid Git entry") from error
        _require(kind == "blob" and mode in GIT_MODES and OID.fullmatch(object_id), "unsupported package tree entry")
        try:
            portable_path(full_path, "package tree")
        except BridgeError as error:
            raise DiscoveryError(str(error)) from error
        _require(not prefix or full_path.startswith(prefix_with_slash), "package tree escaped the selected root")
        relative = full_path[len(prefix_with_slash):]
        _require(bool(relative) and full_path.casefold() not in seen, "package tree contains an empty or case-colliding path")
        seen.add(full_path.casefold())
        records.append((relative, GIT_MODES[mode], object_id))
        if len(records) > max_files:
            raise DiscoveryInputLimitError(f"package tree exceeds {max_files} files")
    _require(bool(records), "package root is empty")
    return records


def _object_sizes(repository, object_ids, budget):
    body = _run_git(repository, ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], budget,
        input_bytes=("\n".join(object_ids) + "\n").encode("ascii"), output_limit=len(object_ids) * 128)
    rows = body.splitlines()
    _require(len(rows) == len(object_ids), "Git object metadata is incomplete")
    sizes = {}
    for object_id, row in zip(object_ids, rows):
        fields = row.split()
        if fields == [object_id.encode("ascii"), b"missing"]:
            sizes[object_id] = None
            continue
        _require(len(fields) == 3 and fields[0] == object_id.encode("ascii") and fields[1] == b"blob" and
            fields[2].isdigit() and len(fields[2]) <= 20, "Git object metadata differs from the pinned tree")
        sizes[object_id] = int(fields[2])
    return sizes


def _check_sizes(sizes, multiplicities, max_file_bytes, max_tree_bytes):
    if any(size is not None and size > max_file_bytes for size in sizes.values()):
        raise DiscoveryInputLimitError(f"package file exceeds {max_file_bytes} bytes")
    if sum(size * multiplicities[oid] for oid, size in sizes.items() if size is not None) > max_tree_bytes:
        raise DiscoveryInputLimitError(f"package tree exceeds {max_tree_bytes} bytes")


def _pack_files(repository):
    result = {}
    for path in (repository.root / "objects/pack").glob("*.pack"):
        metadata = path.lstat()
        _require(stat.S_ISREG(metadata.st_mode), "Git pack must be a regular file")
        result[path.name] = metadata.st_size
    return result


def _added_pack_bytes(repository, initial):
    current = _pack_files(repository)
    _require(all(current.get(name) == size for name, size in initial.items()), "initial Git packs changed during acquisition")
    return sum(size for name, size in current.items() if name not in initial)


def _fetch_objects(repository, object_ids, budget, remaining):
    # Origin belongs to PinnedRepository; only its explicit offline mirror may
    # use the file transport. Source content never controls a remote or ref.
    origin = _run_git(repository, ["remote", "get-url", "origin"], budget).decode("utf-8").strip()
    online = origin == f"https://github.com/{repository.repository}.git"
    _require(online or Path(origin).is_absolute() and Path(origin).is_dir(), "unexpected pinned Git remote")
    _run_git(repository, ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
        "-c", "protocol.file.allow=" + ("never" if online else "always"),
        "-c", "fetch.unpackLimit=1", "-c", "fetch.writeCommitGraph=false",
        "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules",
        "--no-auto-maintenance", "origin", "--stdin"], budget,
        input_bytes=("\n".join(object_ids) + "\n").encode("ascii"), file_limit=remaining)


def _decode_blobs(body, object_ids, sizes):
    position, result = 0, {}
    for object_id in object_ids:
        expected = f"{object_id} blob {sizes[object_id]}\n".encode("ascii")
        _require(body[position:position + len(expected)] == expected, "Git blob header differs from checked metadata")
        start = position + len(expected)
        end = start + sizes[object_id]
        _require(end < len(body) and body[end:end + 1] == b"\n", "Git blob body is truncated")
        content = body[start:end]
        identity = hashlib.sha1(f"blob {len(content)}\0".encode("ascii") + content).hexdigest()
        _require(identity == object_id, "Git blob bytes differ from the pinned object ID")
        result[object_id] = content
        position = end + 1
    _require(position == len(body), "Git batch has unexpected trailing bytes")
    return result


def read_blobs(repository, object_ids, *, max_files, max_file_bytes, max_tree_bytes, budget=None):
    """Read a prevalidated tree's blob IDs, accounting for every input occurrence."""
    _require(all(type(value) is int and value > 0 for value in (max_files, max_file_bytes, max_tree_bytes)),
        "invalid acquisition limits")
    _require(bool(object_ids) and all(isinstance(oid, str) and OID.fullmatch(oid) for oid in object_ids),
        "invalid pinned blob identities")
    if len(object_ids) > max_files:
        raise DiscoveryInputLimitError(f"selected tree exceeds {max_files} files")
    budget = budget or getattr(repository, "work_budget", None) or WorkBudget(120)
    multiplicities = collections.Counter(object_ids)
    object_ids = list(multiplicities)
    sizes = _object_sizes(repository, object_ids, budget)
    _check_sizes(sizes, multiplicities, max_file_bytes, max_tree_bytes)
    initial = _pack_files(repository)
    transfer_limit = max_tree_bytes + PACK_BASE_OVERHEAD + max_files * PACK_PER_FILE_OVERHEAD
    missing = [oid for oid in object_ids if sizes[oid] is None]
    for offset in range(0, len(missing), FETCH_CHUNK_OBJECTS):
        chunk = missing[offset:offset + FETCH_CHUNK_OBJECTS]
        # A server may have supplied more objects than requested previously.
        sizes.update(_object_sizes(repository, chunk, budget))
        _check_sizes(sizes, multiplicities, max_file_bytes, max_tree_bytes)
        needed = [oid for oid in chunk if sizes[oid] is None]
        if needed:
            remaining = transfer_limit - _added_pack_bytes(repository, initial)
            if remaining <= 0:
                raise AcquisitionTransferLimit("Git transfer exhausted its cumulative pack-byte allowance")
            _fetch_objects(repository, needed, budget, remaining)
            if _added_pack_bytes(repository, initial) > transfer_limit:
                raise AcquisitionTransferLimit("Git transfer exceeded its cumulative pack-byte allowance")
            sizes.update(_object_sizes(repository, needed, budget))
            _require(all(sizes[oid] is not None for oid in needed), "bounded fetch did not supply every requested blob")
            _check_sizes(sizes, multiplicities, max_file_bytes, max_tree_bytes)
    _require(all(size is not None for size in sizes.values()), "package still contains missing blobs")
    body = _run_git(repository, ["cat-file", "--batch"], budget,
        input_bytes=("\n".join(object_ids) + "\n").encode("ascii"),
        output_limit=sum(sizes.values()) + len(object_ids) * 128)
    blobs = _decode_blobs(body, object_ids, sizes)
    budget.check()
    return blobs


def bounded_package_files(repository, package_path, *, max_files, max_file_bytes, max_tree_bytes):
    """Acquire one complete pinned root within its existing content/deadline limits."""
    _require(type(max_files) is int and max_files > 0, "invalid acquisition file limit")
    budget = getattr(repository, "work_budget", None) or WorkBudget(120)
    records = _tree_records(repository, package_path, max_files, budget)
    blobs = read_blobs(repository, [oid for _, _, oid in records], max_files=max_files,
        max_file_bytes=max_file_bytes, max_tree_bytes=max_tree_bytes, budget=budget)
    _require(not any(body.startswith(LFS_HEADER) for body in blobs.values()), "Git LFS pointer is forbidden")
    return [(path, mode, blobs[oid]) for path, mode, oid in records]
