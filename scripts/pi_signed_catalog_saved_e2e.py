#!/usr/bin/env python3
"""Manual-only full-catalog genuine signed Pi saved lifecycle acceptance.

This is deliberately NOT the unsigned 70/72 planner or direct --no-save test.
A positive run is forbidden until the owner/editor has approved and published a
real Pi-authorized signed Directory snapshot. No test key or origin override.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from pi_catalog_inventory_e2e import ROOT, active_sources, require_exact_checkout
from pi_signed_marketing_kit_e2e import (
    StageFailure, fresh_case, invoke, native_root, require,
)

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
PLATFORMS = {"ubuntu-24.04": "Linux", "macos-15": "macOS", "windows-2025": "Windows"}
SCOPES = ("user", "project")
SHARDS = 6
ACTIVE_RELEASES = 36  # A changed catalog requires a reviewed expectation update.
PUBLIC_CLI = "0.1.114"
REPO = "777genius/universal-agent-plugins-registry"
BAD_FINDINGS = {"native_projection_not_checked", "native_projection_changed",
                "managed_integrity_not_checked", "managed_integrity_check_failed"}


def digest(value: object) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def native_fingerprint(root: Path) -> dict[str, str]:
    """Hash actual native files and reject links/non-files; no private data output."""
    if not root.exists():
        return {}
    require(root.is_dir() and not root.is_symlink(), "unsafe Pi native root")
    result = {}
    for entry in root.rglob("*"):
        require(not entry.is_symlink(), "symlink in native Pi projection")
        if entry.is_dir():
            continue
        require(entry.is_file(), "non-file in native Pi projection")
        require(entry.stat().st_size <= 8 * 1024 * 1024,
                "unbounded native Pi projection file")
        result[entry.relative_to(root).as_posix()] = hashlib.sha256(entry.read_bytes()).hexdigest()
    return result


def signed_info(cli: str, env: dict[str, str], project: Path,
                distribution: str, scope: str) -> dict:
    response = invoke(cli, env, project, "signed-info", "info", distribution,
                      "--target", "pi", "--scope", "user")
    data = response.get("data")
    require(response.get("command") == "info" and isinstance(data, dict)
            and data.get("selected_distribution") == distribution
            and isinstance(data.get("product_id"), str) and bool(data["product_id"])
            and type(data.get("snapshot_sequence")) is int
            and data["snapshot_sequence"] > 0 and digest(data.get("snapshot_digest")),
            "signed info lacks authenticated distribution/snapshot identity")
    release = data.get("selected_release")
    require(isinstance(release, dict) and release.get("id") == distribution
            and release.get("release_status") == "active"
            and type(release.get("release_sequence")) is int
            and release["release_sequence"] > 0
            and SHA.fullmatch(str(release.get("resolved_revision", ""))) is not None
            and isinstance(release.get("repository"), str)
            and bool(release["repository"])
            and isinstance(release.get("package_path", ""), str)
            and all(digest(release.get(k)) for k in ("tree_digest", "manifest_digest"))
            and isinstance(release.get("package_version"), str)
            and bool(release["package_version"]),
            "signed info lacks immutable active release identity")
    targets = release.get("target_compatibility")
    require(isinstance(targets, list) and any(
        isinstance(t, dict) and t.get("client") == "pi"
        and t.get("delivery") == "managed" and t.get("scopes") == ["user"]
        for t in targets), "authentic signed release does not grant managed Pi")
    return {"distribution": distribution, "product_id": data["product_id"],
            "snapshot": (data["snapshot_sequence"], data["snapshot_digest"]),
            "release": release}


def check_root_source(signed: dict, item: dict) -> None:
    release = signed["release"]
    # Registry-local null revisions resolve at publication time, not at
    # this test-only workflow commit. Never equate current HEAD with that
    # immutable published revision; compare signed digests and explicit pins.
    require(release["release_sequence"] == item["release_sequence"]
            and (item["authored_revision"] is None or
                 release["resolved_revision"] == item["authored_revision"])
            and release["tree_digest"] == item["tree_digest"]
            and release["manifest_digest"] == item["manifest_digest"],
            "authenticated Pi root differs from exact reviewed catalog source")


def inspect_saved(cli: str, env: dict[str, str], project: Path,
                  portable: Path, scope: str, source: dict,
                  native_before: dict[str, str], other_before: dict[str, str],
                  expected_snapshot: tuple | None = None) -> tuple[str, dict[str, str], dict[str, str], tuple]:
    """Bind real lock, signed info, saved receipts and Pi discovery together."""
    lockfile = portable / "uap.lock"
    require(lockfile.is_file() and not lockfile.is_symlink(), "saved lock absent")
    lockbytes = lockfile.read_bytes()
    lock = json.loads(lockbytes)
    packages = lock.get("packages")
    require(isinstance(packages, list) and packages, "saved dependency graph absent")
    pinned: dict[str, dict] = {}
    distributions = set()
    for package in packages:
        require(isinstance(package, dict), "malformed saved lock package")
        alias = package.get("alias")
        key = package.get("source_key")
        require(isinstance(alias, str) and bool(alias)
                and alias not in pinned and isinstance(key, str)
                and key.startswith("directory:")
                and package.get("targets") == ["pi"]
                and all(digest(package.get(k)) for k in ("tree_digest", "manifest_digest")),
                "unsigned, duplicate or malformed saved dependency")
        dist = key[len("directory:"):]
        require(dist and dist not in distributions, "duplicate Directory package identity")
        distributions.add(dist)
        pinned[alias] = package
    root_alias = source["manifest_name"]
    require(root_alias in pinned and pinned[root_alias]["source_key"] ==
            "directory:" + source["distribution"],
            "managed saved graph omitted reviewed root")
    expected_info = {}
    feed_ids = set()
    snapshot = None
    for alias, package in pinned.items():
        dist = package["source_key"][len("directory:"):]
        info = signed_info(cli, env, project, dist, scope)
        release = info["release"]
        require(snapshot is None or info["snapshot"] == snapshot,
                "signed dependency graph uses inconsistent snapshots")
        snapshot = info["snapshot"]
        registry = package.get("source", {}).get("registry") if isinstance(package.get("source"), dict) else None
        require(isinstance(registry, dict)
                and registry.get("distribution") == dist
                and registry.get("distribution_id") == dist
                and registry.get("product_id") == info["product_id"]
                and registry.get("repository") == release["repository"]
                and registry.get("path", "") == release.get("package_path", "")
                and registry.get("commit") == release["resolved_revision"]
                and registry.get("release_sequence") == release["release_sequence"]
                and package.get("version") == release["package_version"]
                and all(package[k] == release[k] for k in ("tree_digest", "manifest_digest")),
                "saved package differs from authenticated signed dependency")
        feed_id = registry.get("feed_id", "")
        require(isinstance(feed_id, str), "malformed signed feed identity")
        feed_ids.add(feed_id)
        parents = package.get("required_by", [])
        require(isinstance(parents, list), "malformed saved dependency edges")
        if alias == root_alias:
            require(not parents, "saved root has unexpected parents")
        else:
            require(bool(parents) and all(
                isinstance(edge, dict) and edge.get("alias") in pinned
                and isinstance(edge.get("selector"), dict)
                and edge["selector"].get("kind") == "version"
                and edge["selector"].get("value") == package["version"]
                for edge in parents), "saved dependency has invalid parent/selector")
        expected_info[dist] = (package, release, info)
    require(len(feed_ids) == 1, "dependency graph mixes signed feed identities")
    require(expected_snapshot is None or snapshot == expected_snapshot,
            "snapshot changed during signed saved lifecycle")
    # All dependencies must connect transitively to the signed root.
    reachable = {root_alias}
    for _ in pinned:
        reachable |= {alias for alias, package in pinned.items()
                      if any(e["alias"] in reachable for e in package.get("required_by", []))}
    require(reachable == set(pinned), "orphaned or cyclic signed dependency graph")
    check_root_source(expected_info[source["distribution"]][2], source)
    listing = invoke(cli, env, project, "signed-list", "list", "--target", "pi",
                     "--scope", scope, *(("--project-root", str(project)) if scope == "project" else ()))
    data = listing.get("data")
    require(isinstance(data, dict) and isinstance(data.get("installations"), list)
            and len(data["installations"]) == len(pinned),
            "saved signed inventory differs from dependency graph")
    owners = {}
    for record in data["installations"]:
        require(isinstance(record, dict) and isinstance(record.get("directory"), dict),
                "missing saved Directory receipt")
        signed = record["directory"]
        dist = signed.get("recorded_distribution")
        installation_id = record.get("installation_id")
        bindings = record.get("clients")
        if isinstance(bindings, dict):
            bindings = list(bindings.values())
        require(dist in expected_info and dist not in owners
                and isinstance(installation_id, str) and bool(installation_id)
                and isinstance(bindings, list) and len(bindings) == 1
                and isinstance(bindings[0], dict),
                "native Pi saved receipt omitted/duplicated owner")
        binding = bindings[0]
        package, release, _ = expected_info[dist]
        revision = binding.get("package_revision")
        require(binding.get("client_id") == "pi" and binding.get("scope") == scope
                and binding.get("materialization") == "materialized"
                and binding.get("verification") == "installation_verified"
                and isinstance(revision, dict)
                and revision.get("distribution_id") == dist
                and revision.get("release_sequence") == release["release_sequence"]
                and revision.get("resolved_revision") == release["resolved_revision"]
                and all(revision.get(k) == package[k] for k in ("tree_digest", "manifest_digest"))
                and revision.get("version") == release["package_version"]
                and signed.get("recorded_release_sequence") == release["release_sequence"]
                and signed.get("recorded_revision") == release["resolved_revision"]
                and signed.get("recorded_snapshot_sequence") == snapshot[0]
                and signed.get("feed_id", "") in feed_ids,
                "saved Pi owner is not authenticated immutable signed release")
        owners[dist] = installation_id
    require(len(owners) == len(pinned) and len(set(owners.values())) == len(owners),
            "saved Pi owner set incomplete")
    actual = native_fingerprint(native_root(env, project, scope))
    other = native_fingerprint(native_root(env, project, "project" if scope == "user" else "user"))
    require(actual != native_before and other == other_before,
            "Pi native projection missing or leaked to other scope")
    for alias in pinned:
        result = invoke(cli, env, project, "native-doctor", "doctor", alias,
                        "--target", "pi", "--scope", scope,
                        *(("--project-root", str(project)) if scope == "project" else ()))
        doctor = result.get("data")
        require(result.get("command") == "doctor" and isinstance(doctor, dict)
                and doctor.get("read_only") is True
                and doctor.get("installation_count") == len(pinned)
                and doctor.get("open_operation_count") == 0
                and isinstance(doctor.get("findings"), list)
                and all(isinstance(f, dict) and isinstance(f.get("status"), str)
                        and isinstance(f.get("code"), str)
                        and f["status"] != "degraded" and f["code"] not in BAD_FINDINGS
                        for f in doctor["findings"]),
                "read-only native doctor did not validate signed installation")
    return ("sha256:" + hashlib.sha256(lockbytes).hexdigest(), owners, actual, snapshot)
