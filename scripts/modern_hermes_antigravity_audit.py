#!/usr/bin/env python3
"""Unsigned, source-only compatibility inventory for Hermes and Antigravity.

NEVER creates policy targets, saved-install receipts, signed feed files, or grants.
All inputs are Git commit objects, not platform-dependent checkout bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

from client_contract import (RELEASE_RE, REPOSITORY, SOURCE_PATH,
                             contract_client_ids, parse_json)

ROOT = Path(__file__).resolve().parents[1]
CLIENTS = ("hermes", "antigravity")
SCOPES = ("user", "project")
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?\Z")
# Immutable source-approved CLI: a modified lock plus modified JSON is not
# an independently verified release (review a new release before upgrading).
FROZEN_CLIENT_RELEASE = "agentplugins-v0.1.108"
FROZEN_CLIENT_REVISION = "8c3cfa28e332c533b0cc0845739c0275730a4285"
FROZEN_CLIENT_DIGEST = "sha256:57e78f6c8559c2e0367311dfeebc6f6148f2c1654b0e5d563b3670b163910c89"
PACKAGE_PATH = re.compile(r"(?:\.|[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)\Z")
MANIFEST_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class AuditError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AuditError(reason)


def committed_bytes(head: str, path: str) -> bytes:
    require(SHA.fullmatch(head) is not None, "source HEAD must be an exact SHA")
    require(re.fullmatch(r"[a-zA-Z0-9_./-]+", path) is not None
            and ".." not in Path(path).parts and not path.startswith("/"),
            "invalid committed path")
    return subprocess.run(["git", "show", f"{head}:{path}"], cwd=ROOT,
                          capture_output=True, timeout=30, check=True).stdout


def require_released_contract_pin(lock: dict) -> None:
    """Refuse a self-consistent edited lock pointing at another CLI release."""
    require(isinstance(lock, dict)
            and lock.get("release") == FROZEN_CLIENT_RELEASE
            and lock.get("revision") == FROZEN_CLIENT_REVISION
            and lock.get("digest") == FROZEN_CLIENT_DIGEST,
            "client contract pin differs from reviewed published CLI release")


def committed_inputs(head: str) -> tuple[dict, list[dict]]:
    checkout = subprocess.run(["git", "rev-parse", "--verify", "HEAD"],
                              cwd=ROOT, capture_output=True, text=True,
                              check=True, timeout=15).stdout.strip()
    require(checkout == head, "script checkout does not match exact source HEAD")
    lock = parse_json(committed_bytes(head, "registry/client-capabilities.lock.json"), "contract pin")
    require(isinstance(lock, dict) and set(lock) == {
        "schema_version", "repository", "release", "revision", "path", "digest"},
        "unexpected client contract pin")
    require(type(lock["schema_version"]) is int and lock["schema_version"] == 1
            and lock["repository"] == REPOSITORY and lock["path"] == SOURCE_PATH
            and isinstance(lock["release"], str) and RELEASE_RE.fullmatch(lock["release"])
            and isinstance(lock["revision"], str) and SHA.fullmatch(lock["revision"]),
            "untrusted client contract provenance")
    require_released_contract_pin(lock)
    raw_contract = committed_bytes(head, "registry/client-capabilities.json")
    require(lock["digest"] == "sha256:" + hashlib.sha256(raw_contract).hexdigest(),
            "committed client contract differs from frozen released pin")
    names = contract_client_ids(raw_contract)
    require(len(names) == 17 and all(client in names for client in CLIENTS),
            "expected reviewed 17-client contract is missing")
    contract = parse_json(raw_contract, "client capabilities")
    source = parse_json(committed_bytes(head, "registry/directory.json"), "Directory source")
    require(isinstance(source, dict) and type(source.get("schema_version")) is int
            and source["schema_version"] == 1
            and isinstance(source.get("products"), list)
            and isinstance(source.get("distributions"), list),
            "invalid committed Directory source")
    return source, contract


def source_identity(release: dict, head: str) -> dict:
    package = release["package_source"]
    repo, revision, path = package["repository"], package["revision"], package["path"]
    require(isinstance(repo, str) and REPO.fullmatch(repo) is not None
            and not repo.endswith(".git"),
            "non-canonical package repository")
    require(revision is None or isinstance(revision, str) and SHA.fullmatch(revision),
            "package revision must be an immutable commit")
    require(revision is not None or repo == "777genius/universal-agent-plugins-registry",
            "unbound external package source")
    require(isinstance(path, str) and PACKAGE_PATH.fullmatch(path) is not None
            and (path == "." or all(part not in {".", ".."} for part in path.split("/"))),
            "invalid package path")
    for key in ("tree_digest", "manifest_digest"):
        require(isinstance(release[key], str) and DIGEST.fullmatch(release[key]) is not None,
                "missing exact pinned package digest")
    require(isinstance(release.get("manifest_name"), str)
            and MANIFEST_NAME.fullmatch(release["manifest_name"]) is not None,
            "non-canonical manifest identity")
    return {"repository": repo, "revision": revision or head, "path": path,
            "tree_digest": release["tree_digest"],
            "manifest_digest": release["manifest_digest"],
            "manifest_name": release["manifest_name"]}


def committed_local_dependencies(source: dict, head: str) -> dict[tuple[str, int], list[dict]]:
    """Read exact-version local dependency declarations; these are not grants.

    Remote dependency declarations and complete transitive closures still need
    their own independent source review. No missing TOML implies proof of no deps.
    """
    distributions = {d["id"]: d for d in source["distributions"]}
    products = {p["id"]: p for p in source["products"]}
    result = {}
    for distribution in source["distributions"]:
        if distribution["status"] != "active":
            continue
        releases = {r["sequence"]: r for r in distribution["releases"]}
        for policy in distribution["release_policies"]:
            if policy["status"] != "active":
                continue
            release = releases[policy["release_sequence"]]
            identity = source_identity(release, head)
            if identity["repository"] != "777genius/universal-agent-plugins-registry" or (
                    release["package_source"]["revision"] is not None):
                continue
            # Read the exact same commit as Directory. Missing optional TOML
            # remains an unverified dependency closure, never positive evidence.
            path = identity["path"] + "/uap.toml"
            proc = subprocess.run(["git", "show", f"{head}:{path}"], cwd=ROOT,
                                  capture_output=True, timeout=30, check=False)
            if proc.returncode != 0:
                continue
            try:
                data = tomllib.loads(proc.stdout.decode("utf-8"))
            except (UnicodeError, tomllib.TOMLDecodeError) as error:
                raise AuditError("invalid exact-source dependency TOML") from error
            declared = data.get("dependencies", {})
            require(isinstance(declared, dict), "dependency declaration must be a table")
            rows = []
            for child_id, version in sorted(declared.items()):
                require(isinstance(child_id, str) and child_id in distributions
                        and isinstance(version, str)
                        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
                        "missing exact-version dependency source")
                child = distributions[child_id]
                require(child["status"] == "active", "required dependency is suspended")
                matches = [r for r in child["releases"]
                           if r["package_version"] == version and any(
                               p["status"] == "active" and p["release_sequence"] == r["sequence"]
                               for p in child["release_policies"])]
                require(len(matches) == 1, "dependency has no unique active exact release")
                child_release = matches[0]
                minimum = products[child["product_id"]]["minimum_capabilities"]
                rows.append({"distribution": child_id, "version": version,
                             "required_mcp": minimum["mcp"] == "required",
                             "required_skills": minimum["skills"] == "required",
                             "source": source_identity(child_release, head)})
            result[(distribution["id"], policy["release_sequence"])] = rows
    return result


def audit(source: dict, contract: list[dict], head: str,
          dependency_rows: dict[tuple[str, int], list[dict]] | None = None) -> dict:
    require(SHA.fullmatch(head) is not None, "source HEAD must be a full SHA")
    contract_map = {row["id"]: row for row in contract}
    require(all(c in contract_map for c in CLIENTS), "missing native client capabilities")
    products = {p["id"]: p for p in source["products"]}
    rows = []
    seen = set()
    dependency_rows = dependency_rows or {}
    for distribution in source["distributions"]:
        releases = {r["sequence"]: r for r in distribution["releases"]}
        require(distribution["product_id"] in products, "unknown product")
        mandatory = products[distribution["product_id"]]["minimum_capabilities"]
        require(set(mandatory) == {"skills", "mcp"}
                and set(mandatory.values()) <= {"optional", "required"},
                "unknown minimum capabilities")
        for policy in distribution["release_policies"]:
            if policy["status"] != "active":
                continue
            sequence = policy["release_sequence"]
            require(type(sequence) is int and sequence in releases,
                    "policy has no exact release")
            identity = source_identity(releases[sequence], head)
            children = dependency_rows.get((distribution["id"], sequence), [])
            components = releases[sequence]["components"]
            require(isinstance(components, list) and bool(components)
                    and set(components) <= {"skills", "mcp", "extensions"},
                    "unknown release component")
            for client in CLIENTS:
                require(not any(t["client"] == client for t in policy["targets"]),
                        "historical Directory already contains modern client grant")
                for scope in SCOPES:
                    key = (distribution["id"], sequence, client, scope)
                    require(key not in seen, "duplicate source/scope")
                    seen.add(key)
                    capability = contract_map[client]
                    selection = capability if scope == "user" else capability["project"]
                    unsupported = []
                    for component in ("skills", "mcp"):
                        if mandatory[component] != "required":
                            continue
                        require(component in components,
                                "minimum capabilities disagree with package manifest")
                        if component == "skills":
                            if selection["skill_support"] == "unsupported":
                                unsupported.append("mandatory_skills_unsupported")
                        else:
                            transports = selection["mcp_transports"]
                            # Native availability in the client contract is NOT proof
                            # of the release's transport, authentication or dependencies.
                            if not any(transports[t] == "native" for t in ("stdio", "streamable-http")):
                                unsupported.append("mandatory_mcp_unsupported")
                    if any(child["required_mcp"] for child in children) and not any(
                            selection["mcp_transports"][t] == "native"
                            for t in ("stdio", "streamable-http")):
                        unsupported.append("mandatory_mcp_dependency_unsupported")
                    if any(child["required_skills"] for child in children) and (
                            selection["skill_support"] == "unsupported"):
                        unsupported.append("mandatory_skills_dependency_unsupported")
                    if distribution["status"] != "active":
                        status, blockers = "excluded", ["distribution_suspended"]
                    elif unsupported:
                        status, blockers = "native_incompatible", unsupported
                    else:
                        status, blockers = "review_required", [
                            "exact_transport_and_auth_not_reviewed",
                            "transitive_dependency_closure_not_verified",
                            "three_os_real_saved_lifecycle_missing",
                            "independent_signed_issuer_and_grant_missing",
                        ]
                    rows.append({"client": client, "scope": scope,
                                 "distribution": distribution["id"],
                                 "release_sequence": sequence,
                                 "source": identity,
                                 "declared_local_dependencies": children,
                                 "mandatory": dict(mandatory),
                                 "components": list(components),
                                 "status": status, "blockers": blockers})
    require(bool(rows), "Directory contains no active policies")
    summary = {client: {scope: {state: sum(
        row["client"] == client and row["scope"] == scope and row["status"] == state
        for row in rows) for state in ("review_required", "native_incompatible", "excluded")}
        for scope in SCOPES} for client in CLIENTS}
    return {"schema_version": 1, "kind": "unsigned-source-compatibility-review-only",
            "source_commit": head,
            "client_contract": {"release": FROZEN_CLIENT_RELEASE,
                                "revision": FROZEN_CLIENT_REVISION,
                                "digest": FROZEN_CLIENT_DIGEST},
            "verified_signed_grants": False,
            "saved_lifecycle_evidence": False, "sign_ready": False,
            "note": "Source contract is not a reviewed policy, signed grant, dependency closure or saved E2E.",
            "summary": summary, "rows": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, contract = committed_inputs(args.source_head)
    dependencies = committed_local_dependencies(source, args.source_head)
    result = audit(source, contract, args.source_head, dependencies)
    # Review artifact only: never write into source or publication trees.
    require(not args.output.resolve().is_relative_to(ROOT.resolve()),
            "review report must not enter registry or published feed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True)
        out.write("\n")
    print("UNSIGNED SOURCE REVIEW ONLY; no managed saved lifecycle or signed authority")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
