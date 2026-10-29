"""Bounded v3 Git-object transport; report interpretation stays in the producer."""
from __future__ import annotations

import errno
import hashlib
import http.client
import re
import socket
import sys
import time
import urllib.error
import urllib.request

from scripts.directory_publication import PublicationError, canonical_json, parse_json_bytes, require
from scripts.publish_skillspector_reports import REPOSITORY

SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_API_BYTES = 32 << 20
MAX_TREE_ENTRIES = 128
MAX_TREE_REQUEST_BYTES = 256 << 10
MAX_TREE_FILES = 100_000
MAX_ERROR_BYTES = 8192


def validation_diagnostic(error):
    """Classify optional 422 details without echoing server-supplied content."""
    try:
        body = error.read(MAX_ERROR_BYTES + 1)
    except (OSError, http.client.HTTPException):
        return "diagnostic_body=unreadable"
    if len(body) > MAX_ERROR_BYTES:
        return "diagnostic_body=oversized"
    try:
        value = parse_json_bytes(body, "GitHub validation diagnostic", max_bytes=MAX_ERROR_BYTES)
    except (PublicationError, ValueError, RecursionError):
        return "diagnostic_body=malformed"
    if not isinstance(value, dict):
        return "diagnostic_body=invalid_shape"
    # An API error can echo uploaded scanner content, including credentials, in
    # its message or arbitrary error fields. Only fixed allowlisted labels leave
    # this parser; never include messages, values, URLs, or unknown identifiers.
    category = {"Validation Failed": "validation_failed", "Invalid request": "invalid_request"}
    message = value.get("message")
    labels = ["error_category=" + (category.get(message, "unclassified")
                                  if isinstance(message, str) else "unclassified")]
    errors = value.get("errors")
    if isinstance(errors, list):
        labels.append(f"error_count={len(errors)}")
        for key, allowed in (
            ("code", {"missing", "missing_field", "invalid", "already_exists", "unprocessable", "custom"}),
            ("field", {"tree", "base_tree", "path", "mode", "type", "sha", "content", "encoding"}),
        ):
            present = {row[key] for row in errors if isinstance(row, dict) and
                       isinstance(row.get(key), str) and row[key] in allowed}
            if present:
                labels.append(f"error_{key}s=" + ",".join(sorted(present)))
    return " ".join(labels)


def git_tree_sha(entries):
    """Git sorts a directory name as if it ended with '/'."""
    ordered = sorted(entries, key=lambda entry: entry["path"].encode("utf-8") +
                     (b"/" if entry["type"] == "tree" else b""))
    body = b"".join((b"40000" if entry["type"] == "tree" else b"100644") + b" " +
                    entry["path"].encode("utf-8") + b"\0" + bytes.fromhex(entry["sha"])
                    for entry in ordered)
    return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()


def create_filtered_tree(github, files, *, known_trees=None):
    """Materialize only selected files, using bounded immediate-child writes.

    Every base_tree is a verified prefix created inside this call. An existing
    tree is reused only when its exact identity equals the complete filtered
    subtree; no unfiltered old root is ever used as a base.
    """
    require(isinstance(files, dict) and 0 < len(files) <= MAX_TREE_FILES, "invalid publication tree file count")
    known_trees = known_trees or {}
    root = {}
    for path, sha in sorted(files.items()):
        require(isinstance(path, str) and 0 < len(path.encode("utf-8")) <= 1000 and
                "\\" not in path and "\0" not in path and isinstance(sha, str) and SHA.fullmatch(sha),
                "invalid publication tree entry")
        parts = path.split("/")
        require(len(parts) <= 16 and all(part not in {"", ".", "..", ".git"} for part in parts),
                "invalid publication tree path")
        node = root
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            require(isinstance(child, dict), "publication file and directory collide")
            node = child
        require(parts[-1] not in node, "publication file and directory collide")
        node[parts[-1]] = sha

    def materialize(node, path):
        rows = []
        for name, value in sorted(node.items()):
            is_tree = isinstance(value, dict)
            sha = materialize(value, f"{path}/{name}".lstrip("/")) if is_tree else value
            rows.append({"path": name, "mode": "040000" if is_tree else "100644",
                         "type": "tree" if is_tree else "blob", "sha": sha})
        expected = git_tree_sha(rows)
        if known_trees.get(path) == expected:
            return expected
        prefix, base = [], None
        for offset in range(0, len(rows), MAX_TREE_ENTRIES):
            chunk = rows[offset:offset + MAX_TREE_ENTRIES]
            payload = {"tree": chunk}
            if base is not None:
                payload["base_tree"] = base
            require(len(canonical_json(payload)) <= MAX_TREE_REQUEST_BYTES, "publication tree request exceeds limit")
            prefix.extend(chunk)
            expected_prefix = git_tree_sha(prefix)
            created = github.request("POST", "git/trees", payload)
            require(isinstance(created, dict) and created.get("sha") == expected_prefix,
                    "uploaded publication tree identity differs")
            # A create response can truncate its tree listing even for a bounded
            # write. Read the resulting immediate children explicitly before
            # accepting this object as the next verified prefix.
            verified = github.request("GET", f"git/trees/{expected_prefix}")
            require(isinstance(verified, dict) and verified.get("sha") == expected_prefix,
                    "uploaded publication tree verification identity differs")
            require(verified.get("truncated") is False,
                    "uploaded publication tree verification is incomplete or truncated")
            fields = ("path", "mode", "type", "sha")
            require(isinstance(verified.get("tree"), list) and
                    all(isinstance(entry, dict) and all(isinstance(entry.get(field), str) for field in fields)
                        for entry in verified["tree"]), "uploaded publication tree verification entries are malformed")
            actual = {(entry["path"], entry["mode"], entry["type"], entry["sha"]) for entry in verified["tree"]}
            wanted = {(entry["path"], entry["mode"], entry["type"], entry["sha"]) for entry in prefix}
            require(actual == wanted and len(verified["tree"]) == len(prefix), "uploaded publication tree entries differ")
            base = created["sha"]
        require(base == expected, "final publication tree identity differs")
        return expected

    return {"sha": materialize(root, "")}


class GitHub:
    """Retry reads and content-addressed object writes, never ref/commit writes."""
    def __init__(self, token="", *, opener=None, clock=None, sleeper=None, budget_seconds=600):
        self.token = token
        self._open = opener or urllib.request.urlopen
        self._clock = clock or time.monotonic
        self._sleep = sleeper or time.sleep
        self._deadline = self._clock() + budget_seconds

    @staticmethod
    def _transient(error):
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        return isinstance(reason, (TimeoutError, ConnectionError, http.client.RemoteDisconnected,
                                   http.client.IncompleteRead)) or (
            isinstance(reason, socket.gaierror) and reason.errno == socket.EAI_AGAIN) or (
            isinstance(reason, OSError) and reason.errno in {
                errno.ECONNRESET, errno.ECONNREFUSED, errno.ECONNABORTED, errno.ETIMEDOUT,
                errno.EPIPE, errno.EHOSTUNREACH, errno.ENETUNREACH})

    def request(self, method, path, data=None):
        require(method in {"GET", "POST", "PATCH"} and re.fullmatch(r"[A-Za-z0-9/?.=&_-]{1,200}", path),
                "invalid GitHub publication request")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "uap-skillspector-coverage"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        body = None if data is None else canonical_json(data)
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/{path}",
                                         data=body, headers=headers, method=method)
        safe_retry = method == "GET" or method == "POST" and path in {"git/trees", "git/blobs"}
        for attempt in range(3):
            remaining = self._deadline - self._clock()
            require(remaining > 0, "GitHub publication transport budget exhausted; prior report retained")
            request_id, status, retry, delay = "unknown", "transport", False, 2 ** attempt
            details = ""
            try:
                with self._open(request, timeout=min(30, remaining)) as response:
                    payload = response.read(MAX_API_BYTES + 1)
                require(len(payload) <= MAX_API_BYTES, "GitHub response exceeds limit")
                return parse_json_bytes(payload, "GitHub coverage response", max_bytes=MAX_API_BYTES)
            except urllib.error.HTTPError as error:
                status = str(error.code)
                try:
                    candidate = error.headers.get("X-GitHub-Request-Id", "unknown")
                    if re.fullmatch(r"[A-Za-z0-9:._-]{1,100}", candidate) and not (self.token and self.token in candidate):
                        request_id = candidate
                    if error.code == 404 and method == "GET":
                        return None
                    diagnostic = b""
                    if error.code == 403:
                        try:
                            diagnostic = error.read(8192).lower()
                        except (OSError, http.client.HTTPException):
                            # A truncated optional error body must not mask the
                            # HTTP status or cause us to print response content.
                            pass
                    if error.code == 422:
                        details = " " + validation_diagnostic(error) + f" request_bytes={len(body or b'')}"
                        if path == "git/trees" and isinstance(data, dict) and isinstance(data.get("tree"), list):
                            details += f" tree_entries={len(data['tree'])}"
                    raw_delay = error.headers.get("Retry-After")
                    pacing = error.code == 429 or error.code == 403 and (
                        raw_delay is not None or b"secondary rate limit" in diagnostic)
                    retry = safe_retry and (error.code in {500, 502, 503, 504} or pacing)
                    if pacing:
                        raw_delay = raw_delay or "60"
                        retry = retry and raw_delay.isdigit() and int(raw_delay) <= 60
                        if retry:
                            delay = max(1, int(raw_delay))
                finally:
                    try:
                        error.close()
                    except (OSError, http.client.HTTPException):
                        pass
            except (urllib.error.URLError, TimeoutError, ConnectionError,
                    http.client.RemoteDisconnected, http.client.IncompleteRead) as error:
                retry = safe_retry and self._transient(error)
            diagnostic = (f"GitHub coverage request failed method={method} path={path} "
                          f"status={status} request_id={request_id} attempt={attempt + 1}/3" + details)
            if not retry or attempt == 2 or self._clock() + delay >= self._deadline:
                raise PublicationError(diagnostic) from None
            print(diagnostic + "; bounded retry", file=sys.stderr)
            self._sleep(delay)
        raise AssertionError("unreachable GitHub retry loop")
