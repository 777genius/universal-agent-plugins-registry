#!/usr/bin/env python3
"""Discover bounded immutable static-scan subjects; never execute skill content.

The catalog is a discovery hint. An explicit path is verified against its pinned
Git tree and declared name; otherwise only an unambiguous declared name resolves
a listing to a root. Partial acquisitions retain prior roots
as historical subjects and are explicitly reported, never called fresh scans.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import selectors
import signal
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml

from scripts.build_bridges import BridgeError, PinnedRepository, UniqueKeyLoader, portable_path
from scripts.build_discovery_index import DiscoveryError, GitHubAPI, REPOSITORY_RE, repository_states
from scripts.build_registry import RegistryError, directory_preview
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget, atomic_json
from scripts.directory_publication import (MAX_ENVELOPE_BYTES, MAX_LATEST_BYTES, MAX_SNAPSHOT_BYTES,
    PublicationError, canonical_json, format_timestamp, load_public_keys, parse_json_bytes, parse_timestamp,
    read_json, sha256_digest, validate_latest, validate_snapshot_semantics, verify_envelope)
from scripts.observe_directory_publication import cryptography_ed25519_verify
from scripts.skillspector_acquisition import read_blobs

ROOT = Path(__file__).resolve().parents[1]
MAX_PAGES = 50
MAX_LISTINGS = 10_000
MAX_ROOTS = 10_000
MAX_TREE_BYTES = 16 << 20
MAX_TREE_ENTRIES = 100_000
MAX_DOCUMENT_BYTES = 256 << 10
MAX_DOCUMENTS = 4096
MAX_DOCUMENT_TOTAL_BYTES = 16 << 20
MAX_DIAGNOSTICS = 256
MAX_CANDIDATES = 64
MAX_SOURCE_STATES = MAX_LISTINGS + MAX_ROOTS
RESOLVER_VERSION = 2
PATH_RE = re.compile(r"^(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIRECTORY_ORIGIN = "https://777genius.github.io/universal-agent-plugins-registry/registry/schemas/1/"
DIRECTORY_KEYS = ROOT / "registry/publication/trusted-keys.json"


def now():
    return format_timestamp(datetime.now(timezone.utc))


def require(condition, message):
    if not condition:
        raise DiscoveryError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DiscoveryError("catalog redirects are forbidden")


def fetch_page(page, budget):
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(f"https://www.skills.sh/api/skills/all-time/{page}",
                                    headers={"Accept": "application/json", "User-Agent": "uap-skillspector-discovery/1"})
    for attempt in range(3):
        budget.check()
        try:
            with opener.open(request, timeout=min(20, budget.remaining())) as response:
                body = response.read((2 << 20) + 1)
            require(len(body) <= 2 << 20, "catalog page exceeds size limit")
            return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
            retry = error.headers.get("Retry-After", "")
            delay = min(30, max(1, int(retry))) if retry.isdigit() else 5 * (attempt + 1)
            # Never wait past the stage deadline.
            time.sleep(min(delay, budget.remaining()))
        except OSError:
            if attempt == 2:
                raise
            time.sleep(min(5 * (attempt + 1), budget.remaining()))
    raise DiscoveryError("catalog acquisition exhausted retries")


def fetch_directory(relative, maximum, budget):
    """Read only the fixed production feed; never send GitHub credentials."""
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(DIRECTORY_ORIGIN + relative,
        headers={"Accept": "application/json", "User-Agent": "uap-skillspector-discovery/2"})
    for attempt in range(3):
        budget.check()
        try:
            with opener.open(request, timeout=min(20, budget.remaining())) as response:
                body = response.read(maximum + 1)
            require(len(body) <= maximum, "Directory artifact exceeds its byte limit")
            return body
        except urllib.error.HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
            retry = error.headers.get("Retry-After", "")
            delay = min(30, max(1, int(retry))) if retry.isdigit() else 5 * (attempt + 1)
            time.sleep(min(delay, budget.remaining()))
        except OSError:
            if attempt == 2:
                raise
            time.sleep(min(5 * (attempt + 1), budget.remaining()))
    raise DiscoveryError("Directory acquisition exhausted retries")


def published_plugin_sources(snapshot):
    """Use the release identities displayed by the signed Directory consumer.

    The legacy registry/index.json is a different catalog and can point to
    retired MCP-only distributions. Reuse the Directory's release projection;
    the first release of each distribution is its newest eligible display
    choice (or its newest visible release when none is eligible).
    """
    plugins = []
    for product in directory_preview(snapshot)["products"]:
        seen = set()
        for distribution in product["distributions"]:
            if distribution["id"] in seen:
                continue
            seen.add(distribution["id"])
            source = distribution["source"]
            require(SHA_RE.fullmatch(str(source.get("revision", ""))) is not None,
                    "published Directory source is not immutable")
            plugins.append({"name": distribution["id"], "components": distribution["components"],
                            "source": {key: source[key] for key in ("repository", "revision", "path")}})
    require(len(plugins) <= MAX_ROOTS, "published Directory distribution count exceeds limit")
    return plugins


def load_published_plugins(budget, *, fetch=fetch_directory, trusted_keys=DIRECTORY_KEYS, current=None):
    pointer_body = fetch("latest.json", MAX_LATEST_BYTES, budget)
    pointer = parse_json_bytes(pointer_body, "Directory pointer", max_bytes=MAX_LATEST_BYTES)
    require(canonical_json(pointer) == pointer_body, "Directory pointer is not canonical JSON")
    validate_latest(pointer)
    body = fetch(pointer["snapshot_path"], pointer["fetch_contract"]["snapshot_max_bytes"], budget)
    envelope_body = fetch(pointer["envelope_path"], pointer["fetch_contract"]["envelope_max_bytes"], budget)
    envelope = parse_json_bytes(envelope_body, "Directory envelope", max_bytes=MAX_ENVELOPE_BYTES)
    require(canonical_json(envelope) == envelope_body, "Directory envelope is not canonical JSON")
    verify_envelope(body, envelope, load_public_keys(trusted_keys), signature_verifier=cryptography_ed25519_verify)
    snapshot = parse_json_bytes(body, "Directory snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    validate_snapshot_semantics(snapshot)
    require(snapshot["sequence"] == envelope["sequence"] == pointer["sequence"], "Directory sequence mismatch")
    current = current or datetime.now(timezone.utc)
    require(parse_timestamp(snapshot["generated_at"], "Directory generated_at") <= current <
            parse_timestamp(snapshot["expires_at"], "Directory expires_at"), "Directory snapshot is outside its validity window")
    return published_plugin_sources(snapshot), {"state": "resolved", "reason": None, "sequence": snapshot["sequence"],
        "source_commit": snapshot["source_commit"], "snapshot_digest": sha256_digest(body)}


def browse_catalog(budget, *, fetch=fetch_page, max_pages=MAX_PAGES):
    listings, seen = [], set()
    metadata = {"pages": 0, "provider_total": None, "complete": False, "error": None}
    try:
        for page in range(max_pages):
            budget.check()
            value = fetch(page, budget)
            require(isinstance(value, dict) and type(value.get("page")) is int and value["page"] == page,
                    "catalog page identity is invalid")
            require(type(value.get("total")) is int and value["total"] >= 0 and type(value.get("hasMore")) is bool,
                    "catalog pagination is invalid")
            rows = value.get("skills")
            require(isinstance(rows, list) and len(rows) <= 200 and (rows or not value["hasMore"]),
                    "catalog rows are invalid")
            page_rows = []
            page_seen = set()
            for row in rows:
                require(isinstance(row, dict), "catalog listing is invalid")
                for key in ("source", "skillId", "name"):
                    text = row.get(key)
                    require(isinstance(text, str) and 0 < len(text) <= 512 and
                            not any(ord(c) < 32 or ord(c) == 127 for c in text), "catalog identity is invalid")
                identity = (row["source"].casefold(), row["skillId"])
                require(identity not in page_seen, "catalog page repeats a listing")
                page_seen.add(identity)
                listing = {key: row[key] for key in ("source", "skillId", "name")}
                # A slug is not a filesystem path. Keep only an explicitly
                # supplied path; current skills.sh listings usually omit it.
                if "path" in row:
                    require(isinstance(row["path"], str) and len(row["path"]) <= 1000 and
                            not any(ord(c) < 32 or ord(c) == 127 for c in row["path"]),
                            "catalog path is invalid")
                    listing["path"] = row["path"]
                page_rows.append(listing)
            # Ranking can move while pages are fetched. Retain unique rows but
            # expose overlap instead of asserting a complete provider census.
            for row in page_rows:
                identity = (row["source"].casefold(), row["skillId"])
                if identity not in seen:
                    seen.add(identity)
                    listings.append(row)
            metadata.update(pages=page + 1, provider_total=value["total"])
            if not value["hasMore"]:
                metadata["complete"] = len(listings) == value["total"]
                if not metadata["complete"]:
                    metadata["error"] = "catalog_changed_during_pagination"
                break
        else:
            metadata["error"] = "catalog_page_limit_reached"
    except (DiscoveryError, CheckpointYield, OSError, ValueError, UnicodeError) as error:
        metadata["error"] = "catalog_budget_exhausted" if isinstance(error, CheckpointYield) else "catalog_acquisition_failed"
    return listings[:MAX_LISTINGS], metadata


def declared_name(body):
    require(len(body) <= MAX_DOCUMENT_BYTES, "skill document exceeds limit")
    text = body.decode("utf-8").replace("\r\n", "\n")
    require(text.startswith("---\n"), "skill frontmatter is missing")
    end = re.search(r"^---[ \t]*$", text[4:], re.MULTILINE)
    require(end is not None, "skill frontmatter terminator is missing")
    header = text[4:4 + end.start()]
    require(len(header.encode()) <= 65536, "skill frontmatter exceeds limit")
    # Reject aliases and anchors before constructing potentially recursive YAML.
    require(not any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in yaml.scan(header)),
            "skill frontmatter aliases are unsupported")
    value = yaml.load(header, Loader=UniqueKeyLoader)
    name = value.get("name") if isinstance(value, dict) else None
    require(isinstance(name, str) and 0 < len(name) <= 200 and
            not any(ord(c) < 32 or ord(c) == 127 for c in name), "skill declared name is invalid")
    return name


def bounded_tree(pinned, budget, paths=None):
    """Limit Git output while it is produced, rather than after allocation."""
    environment = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                   "GIT_OPTIONAL_LOCKS": "0", "LANG": "C", "LC_ALL": "C"}
    chunks, size = [], 0
    arguments = ["git", "ls-tree", "-rz", "-r", pinned.revision]
    if paths is not None:
        arguments.extend(["--", *paths])
    with subprocess.Popen(arguments, cwd=pinned.root,
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          start_new_session=True) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    budget.check()
                    for key, _ in selector.select(timeout=min(1, budget.remaining())):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        require(size <= MAX_TREE_BYTES, "repository tree exceeds limit")
                        chunks.append(chunk)
            require(process.wait(timeout=min(5, budget.remaining())) == 0, "repository tree read failed")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    return b"".join(chunks)


def skill_documents(pinned, budget, paths=None, *, plugin_path=None):
    """Read only bounded regular SKILL.md blobs; unrelated modes stay inert."""
    budget.check()
    # A published plugin installs only its immediate skills/* roots. Scope the
    # tree request and document hydration before applying limits: unrelated
    # packages or nested helper documents must not suppress an eligible root.
    # This changes discovery only; scanning still acquires the full skill tree.
    prefix = None
    if plugin_path is not None:
        require(paths is None, "plugin and exact document scopes are mutually exclusive")
        if plugin_path:
            portable_path(plugin_path, "plugin path")
        prefix = (plugin_path + "/" if plugin_path else "") + "skills/"
        raw = bounded_tree(pinned, budget, [prefix.removesuffix("/")])
    else:
        raw = bounded_tree(pinned, budget) if paths is None else bounded_tree(pinned, budget, paths)
    rows = raw.split(b"\0")
    require(len(rows) <= MAX_TREE_ENTRIES + 1, "repository entry count exceeds limit")
    documents, invalid = [], []
    for row in rows:
        budget.check()
        if not row:
            continue
        metadata, encoded = row.split(b"\t", 1)
        path = encoded.decode("utf-8")
        if PurePosixPath(path).name != "SKILL.md":
            continue
        if prefix is not None and (not path.startswith(prefix) or len(path[len(prefix):].split("/")) != 2):
            continue
        if paths is not None and path not in paths:
            continue
        mode, kind, oid = metadata.decode("ascii").split()
        if mode not in {"100644", "100755"} or kind != "blob" or not PATH_RE.fullmatch(path):
            invalid.append(path)
            continue
        try:
            portable_path(path, "skill document")
        except BridgeError:
            invalid.append(path)
            continue
        require(len(documents) < MAX_DOCUMENTS, "repository skill document limit exceeded")
        documents.append((path, oid))
    # Hydrate only the validated SKILL.md subset in bounded batches. A plain
    # cat-file --batch-check still lazy-fetches each cold object separately.
    bodies = {}
    if documents:
        budget.check()
        bodies = read_blobs(pinned, [oid for _, oid in documents], max_files=MAX_DOCUMENTS,
            max_file_bytes=MAX_DOCUMENT_BYTES, max_tree_bytes=MAX_DOCUMENT_TOTAL_BYTES, budget=budget)
    names = collections.defaultdict(list)
    for path, oid in documents:
        budget.check()
        body = bodies[oid]
        try:
            name = declared_name(body)
        except (DiscoveryError, BridgeError, ValueError, UnicodeError, RecursionError, yaml.YAMLError):
            invalid.append(path)
            continue
        names[name].append(str(PurePosixPath(path).parent).removeprefix("./") if "/" in path else "")
    return dict(names), invalid


def listing_path(listing):
    """Return an explicitly provided skill root without guessing from a slug."""
    path = listing["path"]
    require(isinstance(path, str) and len(path) <= 1000 and PATH_RE.fullmatch(path) is not None,
            "catalog path is unsupported")
    if path:
        portable_path(path, "catalog skill path")
    if path == "SKILL.md":
        return ""
    return path.removesuffix("/SKILL.md")


def resolve_listings(repository, revision, listings, pinned, budget):
    sources, diagnostics, explicit = [], [], {}
    eligible = []
    for listing in listings:
        if listing["source"].casefold() != repository.casefold():
            diagnostics.append({"code": "source_identity_mismatch", "repository": repository,
                                "id": f"{listing['source'].casefold()}/{listing['skillId']}"})
        else:
            eligible.append(listing)
    listings = eligible
    if not listings:
        return sources, diagnostics, {}
    for listing in listings:
        if "path" not in listing:
            continue
        identity = f"{listing['source'].casefold()}/{listing['skillId']}"
        try:
            explicit[identity] = listing_path(listing)
        except (DiscoveryError, BridgeError):
            explicit[identity] = None
            diagnostics.append({"code": "invalid_skill_path", "repository": repository, "id": identity})
    # Exact paths avoid inventorying unrelated SKILL.md blobs in large trees.
    # Any listing without a path still requires the whole bounded name index.
    if len(explicit) == len(listings):
        paths = {(path + "/" if path else "") + "SKILL.md" for path in explicit.values() if path is not None}
        names, invalid = skill_documents(pinned, budget, sorted(paths)) if paths else ({}, [])
    else:
        names, invalid = skill_documents(pinned, budget)
    for listing in listings:
        identity = f"{listing['source'].casefold()}/{listing['skillId']}"
        if identity in explicit:
            root = explicit[identity]
            if root is None:
                continue
            document = (root + "/" if root else "") + "SKILL.md"
            if root not in names.get(listing["name"], []):
                code = "declared_name_mismatch" if any(root in roots for roots in names.values()) else \
                    "invalid_skill_document" if document in invalid else "skill_path_not_found"
                diagnostics.append({"code": code, "repository": repository, "id": identity, "path": root})
                continue
            paths = [root]
        else:
            paths = names.get(listing["name"], [])
        if len(paths) != 1:
            issue = {"code": "ambiguous_name" if paths else "skill_not_found", "repository": repository, "id": identity}
            if paths:
                issue.update(candidates=sorted(paths)[:MAX_CANDIDATES], count=len(paths))
            diagnostics.append(issue)
            continue
        sources.append({"id": identity, "kind": "standalone_skill",
                        "repository": repository, "revision": revision, "path": paths[0], "plugin_path": None})
    if invalid:
        diagnostics.append({"code": "invalid_skill_documents", "repository": repository, "count": len(invalid)})
    return sources, diagnostics, names


def valid_source(source):
    basic = isinstance(source, dict) and set(source) == {"id", "kind", "repository", "revision", "path", "plugin_path"} and \
        isinstance(source["id"], str) and 0 < len(source["id"]) <= 200 and \
        isinstance(source["repository"], str) and len(source["repository"]) <= 200 and REPOSITORY_RE.fullmatch(source["repository"]) is not None and \
        isinstance(source["revision"], str) and SHA_RE.fullmatch(source["revision"]) is not None and \
        isinstance(source["path"], str) and len(source["path"]) <= 1000 and PATH_RE.fullmatch(source["path"]) is not None and \
        source["kind"] in {"standalone_skill", "plugin_skill"} and \
        (source["plugin_path"] is None if source["kind"] == "standalone_skill" else isinstance(source["plugin_path"], str))
    if not basic:
        return False
    try:
        if source["path"]:
            portable_path(source["path"], "selected path")
        if source["kind"] == "plugin_skill":
            parent = source["plugin_path"]
            if parent:
                portable_path(parent, "plugin path")
            prefix = (parent + "/" if parent else "") + "skills/"
            return source["path"].startswith(prefix) and bool(source["path"][len(prefix):]) and "/" not in source["path"][len(prefix):]
    except BridgeError:
        return False
    return True


def load_sources(path):
    if path is None or not path.exists():
        return []
    value = read_json(path, max_bytes=16 << 20)
    require(isinstance(value, dict) and value.get("schema_version") == 1 and isinstance(value.get("sources"), list) and
            len(value["sources"]) <= MAX_ROOTS and all(valid_source(s) for s in value["sources"]), "invalid previous selection")
    require(len({s["id"] for s in value["sources"]}) == len(value["sources"]), "selection IDs repeat")
    return value["sources"]


def subject_key(source):
    return (source["kind"], source["repository"].casefold(), source["revision"], source["path"], source["plugin_path"])


def previous_existence_proofs(previous, summary):
    """Validate positive resolutions and removal proof at an exact examined pin."""
    if not isinstance(summary, dict) or not SHA_RE.fullmatch(str(summary.get("source_commit", ""))):
        return set(), set()
    from scripts.skillspector_coverage import validate_discovery_summary
    try:
        validate_discovery_summary(summary, {"schema_version": 1, "sources": list(previous)}, summary["source_commit"])
    except (PublicationError, ValueError, KeyError, TypeError):
        return set(), set()
    subjects = {source["id"]: source for source in previous}
    resolved, removed = set(), set()
    for state in summary.get("source_states", []):
        for identifier in state["selected_ids"]:
            source = subjects[identifier]
            if state["current"]:
                resolved.add(subject_key(source))
            elif state["state"] == "historical" and state["reason"] == "skill_removed" and \
                    state["id"] == identifier and state["selected_ids"] == [identifier] and \
                    state["repository"].casefold() == source["repository"].casefold() and state["path"] == source["path"]:
                # Keep established proof only at the exact previously examined
                # target; this is not evidence about a newly observed revision.
                removed.add((identifier, subject_key(source), state["revision"], state["path"]))
    return resolved, removed


def listing_hints_digest(listings):
    # A resolver upgrade must re-evaluate old missing/ambiguous mappings even
    # when the catalog and revision did not change. This also prevents old
    # cached diagnostics without candidate paths from surviving indefinitely.
    return sha256_digest(canonical_json({"resolver_version": RESOLVER_VERSION,
        "listings": sorted(listings, key=lambda source: (source["skillId"], source["name"]))}))


def discover(listings, catalog, api, budget, *, source_commit, previous=(), reviewed=(), plugins=(),
             workers=8, mirror_root=None, previous_summary=None, max_pages=MAX_PAGES):
    require(SHA_RE.fullmatch(source_commit) is not None, "source commit must be immutable")
    grouped = collections.defaultdict(list)
    listing_names = {}
    diagnostics = []
    for listing in listings:
        if REPOSITORY_RE.fullmatch(listing["source"]) is None:
            diagnostics.append({"code": "unsupported_source", "repository": listing["source"],
                                "id": f"{listing['source'].casefold()}/{listing['skillId']}"})
        elif len(f"{listing['source']}/{listing['skillId']}") > 200:
            diagnostics.append({"code": "listing_identity_limit", "repository": listing["source"],
                                "id": f"{listing['source'].casefold()}/{listing['skillId']}"})
        else:
            grouped[listing["source"].casefold()].append(listing)
            listing_names[f"{listing['source'].casefold()}/{listing['skillId']}"] = listing["name"]
    previous_by_repo = collections.defaultdict(list)
    previous_by_id = {source["id"]: source for source in previous}
    for source in previous:
        previous_by_repo[source["repository"].casefold()].append(source)
    cache = previous_summary.get("resolution_cache", {}) if isinstance(previous_summary, dict) else {}
    if not isinstance(cache, dict):
        cache = {}
    states, resolution_cache, resolved, retained = {}, {}, {}, set()
    prior_resolved, prior_removed = previous_existence_proofs(previous, previous_summary)
    removed_by_id = {}
    # Resolve in bounded batches. A transient batch failure must not erase old
    # immutable subjects, and other batches can still make progress.
    for offset in range(0, len(grouped), 50):
        batch = sorted(grouped)[offset:offset + 50]
        try:
            budget.check()
            states.update(repository_states(api, batch, work_budget=budget))
        except (DiscoveryError, CheckpointYield, OSError, ValueError) as error:
            diagnostics.extend({"code": "repository_resolution_failed", "repository": repo} for repo in batch)
            if isinstance(error, CheckpointYield):
                break

    def confirm_removed(repo, revision, sources, issues, entry):
        # The current resolver proved an exact path absent. Establish that the
        # same root really existed before calling it removed, never from a
        # missing name, a GitHub null response, or an unverified seed alone.
        issues = [dict(issue) for issue in issues]
        removed = {}
        rows = {f"{row['source'].casefold()}/{row['skillId']}": row for row in grouped[repo]}
        for issue in issues:
            identifier = issue.get("id")
            old, row = previous_by_id.get(identifier), rows.get(identifier)
            if issue.get("code") != "skill_path_not_found" or old is None or row is None or "path" not in row:
                continue
            root = listing_path(row)
            if old["kind"] != "standalone_skill" or old["repository"].casefold() != repo or \
                    old["path"] != root or issue.get("path") != root or old["revision"] == revision:
                continue
            verified = subject_key(old) in prior_resolved or (identifier, subject_key(old), revision, root) in prior_removed
            if not verified:
                try:
                    budget.check()
                    pinned = PinnedRepository(old["repository"], old["revision"], mirror_root,
                        github_token=getattr(api, "token", None) if mirror_root is None else None, work_budget=budget)
                    try:
                        names, _ = skill_documents(pinned, budget, [(root + "/" if root else "") + "SKILL.md"])
                        verified = root in names.get(row["name"], [])
                    finally:
                        pinned.close()
                except (DiscoveryError, BridgeError, CheckpointYield, OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                    continue
            if verified:
                issue["code"] = "skill_removed"
                removed[identifier] = old
        return repo, sources, issues, entry, removed

    def resolve(repo):
        budget.check()
        state = states.get(repo)
        if not state or not state.get("available"):
            return repo, None, [{"code": "repository_unavailable", "repository": repo}], None, {}
        canonical, revision = state["repository"], state["revision"]
        hints = listing_hints_digest(grouped[repo])
        prior = cache.get(repo, {})
        if not isinstance(prior, dict):
            prior = {}
        prior_sources = previous_by_id
        ids = prior.get("selected_ids")
        if prior.get("revision") == revision and prior.get("hints_digest") == hints and isinstance(ids, list) and \
                all(isinstance(i, str) and i in prior_sources and prior_sources[i]["revision"] == revision and
                    prior_sources[i]["repository"].casefold() == repo.casefold() and
                    prior_sources[i]["kind"] == "standalone_skill" for i in ids) and \
                isinstance(prior.get("diagnostics"), list) and all(isinstance(d, dict) and isinstance(d.get("code"), str) for d in prior["diagnostics"]):
            return confirm_removed(repo, revision, [prior_sources[i] for i in ids], prior.get("diagnostics", []), prior)
        pinned = PinnedRepository(canonical, revision, mirror_root,
                                  github_token=getattr(api, "token", None) if mirror_root is None else None, work_budget=budget)
        try:
            # Keep the provider locator for the public repository/name join.
            # GitHub's canonical repository is used for acquisition and its
            # verified immutable head is the subject revision either way.
            sources, issues, _ = resolve_listings(repo, revision, grouped[repo], pinned, budget)
        finally:
            pinned.close()
        entry = {"revision": revision, "hints_digest": hints, "selected_ids": [s["id"] for s in sources],
                 "diagnostics": issues[:MAX_DIAGNOSTICS]}
        return confirm_removed(repo, revision, sources, issues, entry)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(resolve, repo): repo for repo in sorted(grouped)}
        for future in as_completed(futures):
            repo = futures[future]
            try:
                _, sources, issues, entry, removed = future.result()
                diagnostics.extend(issues)
                removed_by_id.update(removed)
                if sources is not None:
                    resolved[repo] = sources
                    resolution_cache[repo] = entry
            except (DiscoveryError, BridgeError, CheckpointYield, OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                diagnostics.append({"code": "repository_acquisition_failed", "repository": repo})

    candidates = []
    plugin_states = []
    superseded_plugin_roots = set()
    for repo in sorted(grouped):
        if repo in resolved:
            candidates.extend(resolved[repo])
            removed = [removed_by_id[identifier] for row in grouped[repo]
                       if (identifier := f"{row['source'].casefold()}/{row['skillId']}") in removed_by_id]
            candidates.extend(removed)
            if removed:
                retained.add(repo)
        else:
            # A provider locator may be an old alias while a previous subject
            # stores GitHub's canonical renamed repository. Its stable listing
            # ID still proves which historical subject must survive a failure.
            historical = list(previous_by_repo.get(repo, []))
            historical.extend(previous_by_id[identity] for row in grouped[repo]
                if (identity := f"{row['source'].casefold()}/{row['skillId']}") in previous_by_id)
            candidates.extend(historical)
            if historical:
                retained.add(repo)
    if not catalog["complete"]:
        for repo in sorted(set(previous_by_repo) - set(grouped)):
            candidates.extend(previous_by_repo[repo])
            retained.add(repo)
    directory_unavailable = catalog.get("directory", {}).get("state") == "unavailable"
    if directory_unavailable:
        diagnostics.append({"code": "directory_acquisition_failed", "repository": "777genius/universal-agent-plugins-registry"})
        candidates.extend(source for source in previous if source["kind"] == "plugin_skill")
        old_states = previous_summary.get("plugin_states", []) if isinstance(previous_summary, dict) else []
        for state in old_states:
            plugin_states.append({**state, "state": "unavailable", "reason": "directory_acquisition_failed",
                                  "selected_ids": []})
        known_roots = {(state["repository"].casefold(), state["plugin_path"]) for state in plugin_states}
        for source in [*previous, *reviewed]:
            root = (source["repository"].casefold(), source["plugin_path"])
            if source["kind"] != "plugin_skill" or root in known_roots:
                continue
            known_roots.add(root)
            plugin_states.append({"id": "historical:" + sha256_digest(canonical_json(list(root)))[7:31],
                "repository": source["repository"], "plugin_path": source["plugin_path"], "revision": source["revision"],
                "state": "unavailable", "reason": "directory_acquisition_failed", "skills_total": None, "selected_ids": []})
    # Enumerate pinned Directory plugin roots independently of catalog names.
    for plugin in plugins:
        source = plugin.get("source", {})
        plugin_state = {"id": plugin["name"], "repository": source.get("repository", ""),
                        "plugin_path": source.get("path", ""),
                        "revision": source.get("revision") if SHA_RE.fullmatch(str(source.get("revision", ""))) else None,
                        "state": "unresolved", "reason": None, "skills_total": None, "selected_ids": []}
        plugin_states.append(plugin_state)
        if "skills" not in plugin.get("components", []):
            plugin_state.update(state="not_applicable", reason="plugin_has_no_skills", skills_total=0)
            # The current signed package declares no skills. Do not queue its
            # former skill roots just because a historical bootstrap lists them.
            candidates = [old for old in candidates if not (old["kind"] == "plugin_skill" and
                old["repository"].casefold() == source.get("repository", "").casefold() and
                old["plugin_path"] == source.get("path"))]
            superseded_plugin_roots.add((source.get("repository", "").casefold(), source.get("path")))
            continue
        if not SHA_RE.fullmatch(str(source.get("revision", ""))):
            plugin_state["reason"] = "plugin_revision_unpinned"
            continue
        try:
            budget.check()
            pinned = PinnedRepository(source["repository"], source["revision"], mirror_root,
                                      github_token=getattr(api, "token", None) if mirror_root is None else None, work_budget=budget)
            try:
                names, invalid = skill_documents(pinned, budget, plugin_path=source["path"])
            finally:
                pinned.close()
            prefix = (source["path"] + "/" if source["path"] else "") + "skills/"
            # An explicit published Directory source supersedes historical
            # plugin revisions only after successful enumeration. Otherwise
            # preserve their exact immutable evidence for the next attempt.
            candidates = [old for old in candidates if not (old["kind"] == "plugin_skill" and
                old["repository"].casefold() == source["repository"].casefold() and old["plugin_path"] == source["path"])]
            superseded_plugin_roots.add((source["repository"].casefold(), source["path"]))
            valid_paths = {path for paths in names.values() for path in paths
                           if path.startswith(prefix) and "/" not in path[len(prefix):]}
            invalid_paths = {str(PurePosixPath(path).parent) for path in invalid
                             if path.startswith(prefix) and "/" not in path[len(prefix):].removesuffix("/SKILL.md")}
            plugin_state.update(skills_total=len(valid_paths | invalid_paths),
                                state="resolved" if valid_paths and not invalid_paths else "unresolved",
                                reason="invalid_skill_documents" if invalid_paths else
                                       None if valid_paths else "plugin_skills_not_found")
            for path in sorted({path for paths in names.values() for path in paths}):
                if path.startswith(prefix) and "/" not in path[len(prefix):]:
                    candidates.append({"id": f"plugin:{plugin['name']}/{path[len(prefix):]}", "kind": "plugin_skill",
                                       "repository": source["repository"], "revision": source["revision"],
                                       "path": path, "plugin_path": source["path"]})
        except (DiscoveryError, BridgeError, CheckpointYield, OSError, ValueError, subprocess.SubprocessError):
            plugin_state.update(state="unavailable", reason="plugin_acquisition_failed")
            diagnostics.append({"code": "plugin_acquisition_failed", "repository": source.get("repository", "")})
            candidates.extend(s for s in previous if s["kind"] == "plugin_skill" and
                              s["repository"] == source.get("repository") and s["plugin_path"] == source.get("path"))
    # Current resolved or retained prior subjects take precedence over the
    # initial reviewed bootstrap. A failed acquisition must never regress a
    # previously resolved current subject to its older bootstrap revision.
    for old in reviewed:
        if old["kind"] == "plugin_skill" and (old["repository"].casefold(), old["plugin_path"]) in superseded_plugin_roots:
            continue
        successor = any(new["kind"] == old["kind"] and new["repository"].casefold() == old["repository"].casefold() and
            (new["path"] == old["path"] or (old["kind"] == "standalone_skill" and
             old["id"].rsplit("/", 1)[-1] in {new["id"].rsplit("/", 1)[-1], listing_names.get(new["id"])}))
            for new in candidates)
        if not successor:
            candidates.append(old)
    subjects, ids, selected = set(), set(), []
    for source in candidates:
        subject = subject_key(source)
        if source["id"] not in ids and subject not in subjects and valid_source(source):
            ids.add(source["id"])
            subjects.add(subject)
            selected.append(source)
    # Preserve useful cold-start coverage: reviewed roots (including verified
    # successors) first, then the provider's popularity order. Retained roots
    # outside the acquired catalog keep a deterministic ID fallback.
    reviewed_ids, reviewed_paths, reviewed_names = {}, {}, {}
    for position, source in enumerate(reviewed):
        reviewed_ids.setdefault(source["id"], position)
        reviewed_paths.setdefault((source["kind"], source["repository"].casefold(), source["path"]), position)
        if source["kind"] == "standalone_skill":
            reviewed_names.setdefault((source["repository"].casefold(), source["id"].rsplit("/", 1)[-1]), position)
    catalog_positions = {}
    for position, row in enumerate(listings):
        catalog_positions.setdefault(f"{row['source'].casefold()}/{row['skillId']}", position)

    def priority(source):
        positions = [reviewed_ids.get(source["id"]), reviewed_paths.get((source["kind"], source["repository"].casefold(), source["path"]))]
        if source["kind"] == "standalone_skill":
            positions.extend(reviewed_names.get((source["repository"].casefold(), name)) for name in
                             (source["id"].rsplit("/", 1)[-1], listing_names.get(source["id"])))
        positions = [position for position in positions if position is not None]
        if positions:
            return (0, min(positions), source["id"])
        if source["id"] in catalog_positions:
            return (1, catalog_positions[source["id"]], source["id"])
        return (2, 0, source["id"])

    selected.sort(key=priority)
    truncated = len(selected) > MAX_ROOTS
    selected = selected[:MAX_ROOTS]
    # Dedupe can replace a generated ID with an equivalent already-selected ID.
    # Cache only the actual emitted subjects, so the next run can reuse them.
    emitted_by_subject = {subject_key(s): s["id"] for s in selected}
    for repo, entry in list(resolution_cache.items()):
        if any(emitted_by_subject.get(subject_key(source)) != source["id"] for source in resolved[repo]):
            # A capped result is not a complete reusable name resolution. Do
            # not let omitted roots become permanent cache misses next run.
            # Equivalent catalog aliases also need fresh resolution: selected
            # IDs alone cannot reconstruct all of their per-card mappings.
            del resolution_cache[repo]
            continue
        entry["selected_ids"] = sorted({emitted_by_subject[subject] for s in resolved[repo]
            if (subject := subject_key(s)) in emitted_by_subject})
    counts = dict(sorted(collections.Counter(d["code"] for d in diagnostics).items()))
    # Persist discovery outcomes for every observed card, including cards that
    # could not produce a scan subject. A historical scan is useful evidence,
    # but it must never masquerade as analysis of the currently requested source.
    source_states = []
    issues_by_id = {d["id"]: d for d in diagnostics if "id" in d}
    issues_by_repo = {d["repository"].casefold(): d for d in diagnostics if "id" not in d and "repository" in d}
    selected_by_id = {source["id"]: source for source in selected}
    resolved_by_id = {source["id"]: source for sources in resolved.values() for source in sources}
    for listing in listings:
        repo = listing["source"].casefold()
        identity = f"{repo}/{listing['skillId']}"
        repository_state = states.get(repo, {})
        issue = issues_by_id.get(identity) or issues_by_repo.get(repo, {})
        current_source = resolved_by_id.get(identity)
        selected_ids = []
        if current_source is not None and subject_key(current_source) in emitted_by_subject:
            selected_ids = [emitted_by_subject[subject_key(current_source)]]
            state, reason, current = "resolved", None, True
        else:
            historical = selected_by_id.get(identity)
            if historical:
                selected_ids = [identity]
            current = False
            if REPOSITORY_RE.fullmatch(listing["source"]) is None:
                state, reason = "unsupported", "unsupported_source"
            elif historical:
                state, reason = "historical", issue.get("code", "source_resolution_incomplete")
            elif issue.get("code") == "listing_identity_limit":
                state, reason = "unresolved", "listing_identity_limit"
            elif repo not in resolved:
                state, reason = "unavailable", issue.get("code", "repository_unavailable")
            else:
                state, reason = "unresolved", issue.get("code", "selection_limit_reached" if current_source else "skill_not_found")
        source_states.append({"id": identity, "repository": repo, "state": state, "current": current,
                              "reason": reason, "revision": repository_state.get("revision"),
                              "path": current_source["path"] if current_source else issue.get("path"),
                              "selected_ids": selected_ids, "candidates": issue.get("candidates", [])})
    for state in plugin_states:
        state["selected_ids"] = [source["id"] for source in selected if source["kind"] == "plugin_skill" and
                                 source["repository"].casefold() == state["repository"].casefold() and
                                 source["plugin_path"] == state["plugin_path"]]
        if state["state"] == "resolved" and len(state["selected_ids"]) != state["skills_total"]:
            state.update(state="unresolved", reason="selection_limit_reached")
    observed_ids = {state["id"] for state in source_states}
    plugin_by_root = {(state["repository"].casefold(), state["plugin_path"]): state for state in plugin_states}
    for source in selected:
        if source["id"] in observed_ids:
            continue
        plugin_state = plugin_by_root.get((source["repository"].casefold(), source["plugin_path"])) \
            if source["kind"] == "plugin_skill" else None
        current = bool(plugin_state and plugin_state["state"] == "resolved" and source["revision"] == plugin_state["revision"])
        source_states.append({"id": source["id"], "repository": source["repository"].casefold(),
                              "state": "resolved" if current else "historical", "current": current,
                              "reason": None if current else (plugin_state or {}).get("reason") or "catalog_not_observed",
                              "revision": plugin_state["revision"] if plugin_state else None,
                              "path": source["path"], "selected_ids": [source["id"]], "candidates": []})
    catalog_counts = collections.Counter(state["state"] for state in source_states[:len(listings)])
    catalog_coverage = {"observed": len(listings), **{key: catalog_counts[key]
                        for key in ("resolved", "historical", "unresolved", "unavailable", "unsupported")}}
    aliases = [{"repository": repository, "canonical_repository": state["repository"], "revision": state["revision"]}
               for repository, state in sorted(states.items())
               if state.get("available") and repository.casefold() != state["repository"].casefold()]
    selection = {"schema_version": 1, "sources": selected}
    summary = {"schema_version": 1, "source_commit": source_commit, "generated_at": now(),
               "scope": "bounded_catalog_and_reviewed_sources", "catalog": catalog,
               "bounds": {"pages": max_pages, "listings": MAX_LISTINGS, "roots": MAX_ROOTS},
               "listings_observed": len(listings), "repositories_observed": len(grouped),
               "repositories_resolved": len(resolved), "repositories_retained": len(retained),
               "selected_roots": len(selected), "selection_digest": sha256_digest(canonical_json(selection)),
               "complete": catalog["complete"] and not directory_unavailable and len(resolved) == len(grouped) and not truncated and
                           catalog_coverage["resolved"] == catalog_coverage["observed"] and
                           all(state["state"] in {"resolved", "not_applicable"} for state in plugin_states),
               "selection_truncated": truncated, "diagnostic_counts": counts,
               "diagnostics": diagnostics[:MAX_DIAGNOSTICS], "diagnostics_truncated": len(diagnostics) > MAX_DIAGNOSTICS,
               "resolution_cache": resolution_cache, "source_states": source_states, "plugin_states": plugin_states,
               "repository_aliases": aliases, "catalog_coverage": catalog_coverage}
    return selection, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--previous-selection", type=Path)
    parser.add_argument("--previous-summary", type=Path)
    parser.add_argument("--budget-seconds", type=int, default=1200)
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=8)
    parser.add_argument("--max-pages", type=int, choices=range(1, MAX_PAGES + 1), default=MAX_PAGES)
    args = parser.parse_args()
    budget = WorkBudget(args.budget_seconds)
    try:
        plugins, directory = load_published_plugins(budget)
    except (DiscoveryError, PublicationError, RegistryError, CheckpointYield, OSError, ValueError, KeyError, TypeError):
        plugins, directory = [], {"state": "unavailable", "reason": "directory_acquisition_failed", "sequence": None,
                                  "source_commit": None, "snapshot_digest": None}
    listings, catalog = browse_catalog(budget, max_pages=args.max_pages)
    catalog["directory"] = directory
    previous_summary = read_json(args.previous_summary, max_bytes=16 << 20) if args.previous_summary and args.previous_summary.exists() else None
    selection, summary = discover(listings, catalog, GitHubAPI(os.environ.get("GITHUB_TOKEN", ""), work_budget=budget), budget,
                                  source_commit=args.source_commit, previous=load_sources(args.previous_selection),
                                  reviewed=load_sources(ROOT / "registry/skillspector-selection.json"),
                                  plugins=plugins, workers=args.workers,
                                  previous_summary=previous_summary, max_pages=args.max_pages)
    atomic_json(args.output, selection)
    atomic_json(args.summary, summary)
    print(json.dumps({key: value for key, value in summary.items() if key not in {"diagnostics", "resolution_cache"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
