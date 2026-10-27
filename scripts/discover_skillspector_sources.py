#!/usr/bin/env python3
"""Discover bounded immutable static-scan subjects; never execute skill content.

The catalog is a discovery hint. Only an unambiguous declared name in a pinned
Git tree resolves a listing to a root. Partial acquisitions retain prior roots
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
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget, atomic_json
from scripts.directory_publication import canonical_json, format_timestamp, read_json, sha256_digest

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
PATH_RE = re.compile(r"^(?:[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


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
    raise DiscoveryError("catalog acquisition exhausted retries")


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
                page_rows.append({key: row[key] for key in ("source", "skillId", "name")})
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


def bounded_tree(pinned, budget):
    """Limit Git output while it is produced, rather than after allocation."""
    environment = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                   "GIT_OPTIONAL_LOCKS": "0", "LANG": "C", "LC_ALL": "C"}
    chunks, size = [], 0
    with subprocess.Popen(["git", "ls-tree", "-rz", "-r", pinned.revision], cwd=pinned.root,
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


def skill_documents(pinned, budget):
    """Read only bounded regular SKILL.md blobs; unrelated modes stay inert."""
    budget.check()
    raw = bounded_tree(pinned, budget)
    rows = raw.split(b"\0")
    require(len(rows) <= MAX_TREE_ENTRIES + 1, "repository entry count exceeds limit")
    documents, invalid, total = [], [], 0
    for row in rows:
        budget.check()
        if not row:
            continue
        metadata, encoded = row.split(b"\t", 1)
        path = encoded.decode("utf-8")
        if PurePosixPath(path).name != "SKILL.md":
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
    # In a blobless repository, ls-tree -l can fetch every unrelated blob just
    # to determine sizes. Ask for sizes only after exact candidate filtering.
    if documents:
        budget.check()
        sizes = pinned.git("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                           input_bytes="".join(oid + "\n" for _, oid in documents).encode("ascii"))
        rows = sizes.splitlines()
        require(len(sizes) <= MAX_DOCUMENTS * 128 and len(rows) == len(documents), "invalid skill document sizes")
        for (_, expected_oid), row in zip(documents, rows):
            oid, kind, size = row.decode("ascii").split()
            length = int(size)
            require(oid == expected_oid and kind == "blob" and 0 <= length <= MAX_DOCUMENT_BYTES,
                    "repository skill document limit exceeded")
            total += length
            require(total <= MAX_DOCUMENT_TOTAL_BYTES, "repository skill documents exceed byte limit")
    names = collections.defaultdict(list)
    for path, oid in documents:
        budget.check()
        body = pinned.git("cat-file", "blob", oid)
        try:
            name = declared_name(body)
        except (DiscoveryError, BridgeError, ValueError, UnicodeError, RecursionError, yaml.YAMLError):
            invalid.append(path)
            continue
        names[name].append(str(PurePosixPath(path).parent).removeprefix("./") if "/" in path else "")
    return dict(names), invalid


def resolve_listings(repository, revision, listings, pinned, budget):
    names, invalid = skill_documents(pinned, budget)
    sources, diagnostics = [], []
    for listing in listings:
        paths = names.get(listing["name"], [])
        if len(paths) != 1:
            diagnostics.append({"code": "ambiguous_name" if paths else "skill_not_found", "repository": repository,
                                "id": f"{listing['source'].casefold()}/{listing['skillId']}"})
            continue
        sources.append({"id": f"{listing['source'].casefold()}/{listing['skillId']}", "kind": "standalone_skill",
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


def discover(listings, catalog, api, budget, *, source_commit, previous=(), reviewed=(), plugins=(),
             workers=8, mirror_root=None, previous_summary=None, max_pages=MAX_PAGES):
    require(SHA_RE.fullmatch(source_commit) is not None, "source commit must be immutable")
    grouped = collections.defaultdict(list)
    listing_names = {}
    diagnostics = []
    for listing in listings:
        if REPOSITORY_RE.fullmatch(listing["source"]) is None:
            diagnostics.append({"code": "unsupported_source", "repository": listing["source"]})
        elif len(f"{listing['source']}/{listing['skillId']}") > 200:
            diagnostics.append({"code": "listing_identity_limit", "repository": listing["source"]})
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

    def resolve(repo):
        budget.check()
        state = states.get(repo)
        if not state or not state.get("available"):
            return repo, None, [{"code": "repository_unavailable", "repository": repo}], None
        canonical, revision = state["repository"], state["revision"]
        hints = sha256_digest(canonical_json(sorted(grouped[repo], key=lambda s: (s["skillId"], s["name"]))))
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
            return repo, [prior_sources[i] for i in ids], prior.get("diagnostics", []), prior
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
        return repo, sources, issues, entry

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(resolve, repo): repo for repo in sorted(grouped)}
        for future in as_completed(futures):
            repo = futures[future]
            try:
                _, sources, issues, entry = future.result()
                diagnostics.extend(issues)
                if sources is not None:
                    resolved[repo] = sources
                    resolution_cache[repo] = entry
            except (DiscoveryError, BridgeError, CheckpointYield, OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                diagnostics.append({"code": "repository_acquisition_failed", "repository": repo})

    candidates = []
    superseded_plugin_roots = set()
    for repo in sorted(grouped):
        if repo in resolved:
            candidates.extend(resolved[repo])
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
    # Enumerate pinned Directory plugin roots independently of catalog names.
    for plugin in plugins:
        source = plugin.get("source", {})
        if "skills" not in plugin.get("components", []) or not SHA_RE.fullmatch(str(source.get("revision", ""))):
            continue
        try:
            budget.check()
            pinned = PinnedRepository(source["repository"], source["revision"], mirror_root,
                                      github_token=getattr(api, "token", None) if mirror_root is None else None, work_budget=budget)
            try:
                names, _ = skill_documents(pinned, budget)
            finally:
                pinned.close()
            prefix = (source["path"] + "/" if source["path"] else "") + "skills/"
            # An explicit published Directory source supersedes historical
            # plugin revisions only after successful enumeration. Otherwise
            # preserve their exact immutable evidence for the next attempt.
            candidates = [old for old in candidates if not (old["kind"] == "plugin_skill" and
                old["repository"].casefold() == source["repository"].casefold() and old["plugin_path"] == source["path"])]
            superseded_plugin_roots.add((source["repository"].casefold(), source["path"]))
            for path in sorted({path for paths in names.values() for path in paths}):
                if path.startswith(prefix) and "/" not in path[len(prefix):]:
                    candidates.append({"id": f"plugin:{plugin['name']}/{path[len(prefix):]}", "kind": "plugin_skill",
                                       "repository": source["repository"], "revision": source["revision"],
                                       "path": path, "plugin_path": source["path"]})
        except (DiscoveryError, BridgeError, CheckpointYield, OSError, ValueError, subprocess.SubprocessError):
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
        if any(subject_key(source) not in emitted_by_subject for source in resolved[repo]):
            # A capped result is not a complete reusable name resolution. Do
            # not let omitted roots become permanent cache misses next run.
            del resolution_cache[repo]
            continue
        entry["selected_ids"] = sorted({emitted_by_subject[subject] for s in resolved[repo]
            if (subject := subject_key(s)) in emitted_by_subject})
    counts = dict(sorted(collections.Counter(d["code"] for d in diagnostics).items()))
    selection = {"schema_version": 1, "sources": selected}
    summary = {"schema_version": 1, "source_commit": source_commit, "generated_at": now(),
               "scope": "bounded_catalog_and_reviewed_sources", "catalog": catalog,
               "bounds": {"pages": max_pages, "listings": MAX_LISTINGS, "roots": MAX_ROOTS},
               "listings_observed": len(listings), "repositories_observed": len(grouped),
               "repositories_resolved": len(resolved), "repositories_retained": len(retained),
               "selected_roots": len(selected), "selection_digest": sha256_digest(canonical_json(selection)),
               "complete": catalog["complete"] and len(resolved) == len(grouped) and not truncated and not counts.get("plugin_acquisition_failed"),
               "selection_truncated": truncated, "diagnostic_counts": counts,
               "diagnostics": diagnostics[:MAX_DIAGNOSTICS], "diagnostics_truncated": len(diagnostics) > MAX_DIAGNOSTICS,
               "resolution_cache": resolution_cache}
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
    listings, catalog = browse_catalog(budget, max_pages=args.max_pages)
    previous_summary = read_json(args.previous_summary, max_bytes=16 << 20) if args.previous_summary and args.previous_summary.exists() else None
    selection, summary = discover(listings, catalog, GitHubAPI(os.environ.get("GITHUB_TOKEN", ""), work_budget=budget), budget,
                                  source_commit=args.source_commit, previous=load_sources(args.previous_selection),
                                  reviewed=load_sources(ROOT / "registry/skillspector-selection.json"),
                                  plugins=read_json(ROOT / "registry/index.json")["plugins"], workers=args.workers,
                                  previous_summary=previous_summary, max_pages=args.max_pages)
    atomic_json(args.output, selection)
    atomic_json(args.summary, summary)
    print(json.dumps({key: value for key, value in summary.items() if key not in {"diagnostics", "resolution_cache"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
