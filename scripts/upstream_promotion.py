#!/usr/bin/env python3
"""Select, record, apply, and verify fail-closed upstream promotions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_registry import (
    CLIENT_IDS, RegistryError, directory_preview, directory_search, encoded,
    validate_directory, validate_registry_path,
)
from repository_identity import active_registry_repository
from publication_trust_policy import load_publication_trust_config


ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE = re.compile(
    r"^automation/upstream-promotion-([a-z0-9]+(?:-[a-z0-9]+)*)-([0-9a-f]{12})-([0-9a-f]{12})$"
)
MAX_JSON_BYTES = 262_144


class PromotionError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def read_object(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        body = path.read_bytes()
        require(len(body) <= max_bytes, f"{path}: JSON exceeds {max_bytes} bytes")
        value = json.loads(body)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PromotionError(f"{path}: invalid JSON: {error}") from error
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def schema(path: str) -> dict[str, Any]:
    return read_object(ROOT / "schemas" / path)


def validate_watch(path: Path) -> dict[str, Any]:
    watch = read_object(path)
    jsonschema.Draft202012Validator(schema("upstream-promotion-watch.schema.json")).validate(watch)
    entries = watch["entries"]
    product_ids = [item["product_id"] for item in entries]
    require(product_ids == sorted(set(product_ids)), "promotion watch entries must have unique sorted product IDs")
    for item in entries:
        validate_registry_path(item["package_path"])
        clients = [target["client"] for target in item["targets"]]
        require(
            clients == [client for client in CLIENT_IDS if client in clients] and len(clients) == len(set(clients)),
            f"{item['product_id']}: targets must be unique and in canonical order",
        )
        if item["promotion_mode"] == "automatic":
            require(
                item["distribution_id"].split("/", 1)[0].casefold()
                == item["repository"].split("/", 1)[0].casefold(),
                f"{item['product_id']}: upstream publisher differs from repository owner",
            )
        elif item["promotion_mode"] == "locked_bridge_manual":
            bridge = item["bridge"]
            require(bridge["id"] == item["product_id"], f"{item['product_id']}: bridge id differs from product")
            require(
                item["distribution_id"] == f"777genius/{item['product_id']}-bridge",
                f"{item['product_id']}: locked bridge distribution identity is invalid",
            )
            entrypoint = bridge["entrypoint"]
            require(
                entrypoint.startswith(f"node_modules/{bridge['npm_package']}/")
                and "\\" not in entrypoint and ".." not in Path(entrypoint).parts,
                f"{item['product_id']}: bridge entrypoint must remain inside its npm dependency",
            )
    return watch


def gh_value(gh: Path, endpoint: str) -> object:
    environment = {
        "PATH": os.environ.get("PATH", ""), "GH_TOKEN": os.environ.get("GH_TOKEN", ""),
        "LANG": "C", "LC_ALL": "C",
    }
    require(bool(environment["GH_TOKEN"]), "GH_TOKEN is required for observation")
    try:
        completed = subprocess.run(
            [str(gh), "api", endpoint], env=environment, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PromotionError(f"GitHub query failed: {error}") from error
    require(completed.returncode == 0, f"GitHub query failed for {endpoint}: {completed.stderr.decode('utf-8', 'replace')[:500]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise PromotionError(f"GitHub returned invalid JSON for {endpoint}") from error
    return value


def gh_json(gh: Path, endpoint: str) -> dict[str, Any]:
    value = gh_value(gh, endpoint)
    require(isinstance(value, dict), f"GitHub returned a non-object for {endpoint}")
    return value


def normalized_pr(entry: dict[str, Any], raw: dict[str, Any], repository: dict[str, Any]) -> dict[str, Any]:
    number = entry["upstream_pr_number"]
    merged = raw.get("merged_at")
    merge_sha = raw.get("merge_commit_sha")
    head = raw.get("head") if isinstance(raw.get("head"), dict) else {}
    base = raw.get("base") if isinstance(raw.get("base"), dict) else {}
    default = repository.get("default_branch")
    metadata = {
        "schema_version": 1,
        "repository_id": entry["repository"],
        "upstream_pr_number": number,
        "url": f"https://github.com/{entry['repository']}/pull/{number}",
        "state": "MERGED" if merged else str(raw.get("state", "")).upper(),
        "is_draft": bool(raw.get("draft")),
        "head_ref_oid": head.get("sha"),
        "merge_commit_oid": merge_sha,
        "base_ref_name": base.get("ref"),
        "default_branch": default,
        "merged_at": merged,
    }
    if merged:
        require(raw.get("html_url") == metadata["url"], "upstream PR URL differs from the watch entry")
        require(raw.get("number") == number, "upstream PR number differs from the watch entry")
        require(metadata["is_draft"] is False, "merged upstream PR is unexpectedly draft")
        for field in ("head_ref_oid", "merge_commit_oid"):
            require(isinstance(metadata[field], str) and SHA_RE.fullmatch(metadata[field]), f"upstream {field} is invalid")
        require(isinstance(default, str) and default and isinstance(metadata["base_ref_name"], str), "upstream branch metadata is invalid")
    return metadata


def select(args: argparse.Namespace) -> dict[str, Any]:
    watch = validate_watch(args.watch)
    directory = read_object(args.directory)
    products = {item["id"]: item for item in directory.get("products", [])}
    distributions = {item["id"]: item for item in directory.get("distributions", [])}
    diagnostics = []
    repository = active_registry_repository()
    open_pulls = gh_value(args.gh, f"repos/{repository}/pulls?state=open&per_page=100")
    require(isinstance(open_pulls, list) and len(open_pulls) <= 100, "GitHub returned an invalid open-PR set")
    reserved = []
    for item in open_pulls:
        require(isinstance(item, dict), "GitHub returned an invalid open PR")
        head = item.get("head") if isinstance(item.get("head"), dict) else {}
        repository = head.get("repo") if isinstance(head.get("repo"), dict) else {}
        if repository.get("full_name") == active_registry_repository() and BRANCH_RE.fullmatch(str(head.get("ref", ""))):
            reserved.append(item.get("number"))
    if reserved:
        return {
            "schema_version": 1, "decision": "none",
            "diagnostics": [{"outcome": "promotion_pr_open", "pull_requests": sorted(reserved)}],
        }
    for entry in watch["entries"]:
        product = products.get(entry["product_id"])
        require(product is not None, f"{entry['product_id']}: watched product is absent from the Directory")
        current = distributions.get(entry["distribution_id"])
        if current is not None and any(
            release["sequence"] == entry["release_sequence"] for release in current["releases"]
        ):
            diagnostics.append({"product_id": entry["product_id"], "outcome": "already_promoted"})
            continue
        raw = gh_json(args.gh, f"repos/{entry['repository']}/pulls/{entry['upstream_pr_number']}")
        repository = gh_json(args.gh, f"repos/{entry['repository']}")
        metadata = normalized_pr(entry, raw, repository)
        if metadata["state"] != "MERGED":
            diagnostics.append({"product_id": entry["product_id"], "outcome": "awaiting_merge"})
            continue
        if metadata["head_ref_oid"] != entry["reviewed_head_sha"]:
            diagnostics.append({
                "product_id": entry["product_id"], "outcome": "reviewed_head_changed",
                "expected": entry["reviewed_head_sha"], "actual": metadata["head_ref_oid"],
            })
            continue
        if entry["promotion_mode"] == "observe_only":
            diagnostics.append({
                "product_id": entry["product_id"], "outcome": "awaiting_policy",
                "reason": entry["block_reason"],
            })
            continue
        return {
            "schema_version": 1,
            "decision": "promote_bridge" if entry["promotion_mode"] == "locked_bridge_manual" else "promote",
            "entry": entry,
            "pr_metadata": metadata, "diagnostics": diagnostics,
        }
    return {"schema_version": 1, "decision": "none", "diagnostics": diagnostics}


def materialization_evidence_payloads(
    selection: dict[str, Any], raw: dict[str, Any], os_name: str, architecture: str,
) -> list[dict[str, Any]]:
    """Project one aggregate observer result into signer-readable client records."""
    require(selection.get("decision") == "promote", "selection is not a promotion")
    entry, metadata = selection["entry"], selection["pr_metadata"]
    require(raw.get("schema_version") == 1 and raw.get("outcome") == "passed", "materialization did not pass")
    identity = raw.get("package")
    require(isinstance(identity, dict), "materialization package identity is absent")
    require(
        raw.get("product_id") == entry["product_id"]
        and raw.get("repository") == entry["repository"]
        and raw.get("revision") == metadata["merge_commit_oid"]
        and raw.get("path") == entry["package_path"],
        "materialization source differs from the selected official package",
    )
    clients = [target["client"] for target in entry["targets"]]
    require(raw.get("clients") == clients, "materialization clients differ from policy")
    require(
        raw.get("installer_version") == entry["minimum_installer_version"],
        "materialization installer differs from policy",
    )
    observed_at = raw.get("observed_at")
    require(isinstance(observed_at, str), "materialization observed_at is absent")
    evidence_schema = schema("directory-evidence-artifact.schema.json")
    evidence: list[dict[str, Any]] = []
    for client in clients:
        payload = {
            "schema_version": 1,
            "id": f"promotion/{entry['product_id']}/{metadata['merge_commit_oid'][:12]}/{client}",
            "product_id": entry["product_id"], "distribution_id": entry["distribution_id"],
            "release_sequence": entry["release_sequence"],
            "package_tree_digest": identity["tree_digest"], "manifest_digest": identity["manifest_digest"],
            "source_repository": entry["repository"], "source_revision": metadata["merge_commit_oid"],
            "source_path": entry["package_path"], "level": "materialization", "outcome": "passed",
            "client": client, "client_version": "isolated-configuration-fixture",
            "installer_version": entry["minimum_installer_version"],
            "adapter_version": f"agentplugins-{entry['minimum_installer_version']}",
            "os": os_name, "architecture": architecture,
            "dependency_identity": f"agentplugins@{entry['minimum_installer_version']}",
            "observed_at": observed_at,
        }
        jsonschema.Draft202012Validator(evidence_schema).validate(payload)
        evidence.append(payload)
    return evidence


def write_evidence_artifacts(args: argparse.Namespace) -> dict[str, Any]:
    selection = read_object(args.selection)
    raw = read_object(args.materialization)
    payloads = materialization_evidence_payloads(
        selection, raw, args.os, args.architecture,
    )
    args.output_directory.mkdir(parents=True, exist_ok=True)
    expected_names = {f"{item['client']}.json" for item in payloads}
    existing_names = {path.name for path in args.output_directory.iterdir()}
    require(
        existing_names.issubset(expected_names),
        "evidence output directory contains unexpected entries",
    )
    for payload in payloads:
        path = args.output_directory / f"{payload['client']}.json"
        require(not path.is_symlink(), f"{path}: evidence artifact cannot be a symlink")
        path.write_bytes(pretty(payload))
    return {
        "schema_version": 1, "outcome": "written",
        "evidence_count": len(payloads),
    }


def review_record(args: argparse.Namespace) -> dict[str, Any]:
    selection = read_object(args.selection)
    raw = read_object(args.materialization)
    payloads = materialization_evidence_payloads(
        selection, raw, args.os, args.architecture,
    )
    entry, metadata = selection["entry"], selection["pr_metadata"]
    identity = raw["package"]
    require(SHA_RE.fullmatch(args.artifact_revision) is not None, "artifact revision must be a full SHA")
    artifact_directory = validate_registry_path(args.artifact_directory)
    artifact_root = args.repository / artifact_directory
    expected_names = {f"{item['client']}.json" for item in payloads}
    require(
        artifact_root.is_dir()
        and {path.name for path in artifact_root.iterdir()} == expected_names,
        "materialization evidence artifacts differ from selected clients",
    )
    evidence = []
    for payload in payloads:
        artifact_path = f"{artifact_directory}/{payload['client']}.json"
        artifact_file = args.repository / artifact_path
        body = artifact_file.read_bytes()
        require(body == pretty(payload), f"{artifact_path}: evidence artifact is not canonical")
        require(read_object(artifact_file) == payload, f"{artifact_path}: evidence artifact differs from materialization")
        evidence.append({
            **payload,
            "artifact": {
                "repository": active_registry_repository(),
                "revision": args.artifact_revision,
                "path": artifact_path,
                "digest": sha256(body),
            },
            "trust": {"kind": "reviewed_external"},
        })
    record = {
        "schema_version": 3, "repository": entry["repository"], "path": entry["package_path"],
        "reviewed_revision": entry["reviewed_head_sha"],
        "reviewed_tree_digest": identity["tree_digest"],
        "reviewed_manifest_digest": identity["manifest_digest"],
        "product_id": entry["product_id"], "manifest_name": entry["product_id"],
        "distribution_id": entry["distribution_id"], "release_sequence": entry["release_sequence"],
        "policy": {
            "status": "active", "minimum_installer_version": entry["minimum_installer_version"],
            "targets": entry["targets"],
        },
        "evidence": evidence,
    }
    require(len(canonical(record)) <= MAX_JSON_BYTES, "review record exceeds size bound")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(pretty(record))
    return {"schema_version": 1, "outcome": "recorded", "evidence_count": len(evidence), "record_digest": sha256(canonical(record))}


def apply_candidate(args: argparse.Namespace) -> dict[str, Any]:
    candidate = read_object(args.candidate)
    jsonschema.Draft202012Validator(schema("promotion-candidate.schema.json")).validate(candidate)
    review = read_object(args.review_record)
    directory = read_object(args.directory)
    publication_config = load_publication_trust_config(args.publication_config)
    require(candidate["decision"] == "reviewable_promotion_candidate", "candidate is not reviewable")
    product_id = candidate["product"]["id"]
    distribution_id = candidate["distribution"]["id"]
    require(review["product_id"] == product_id and review["distribution_id"] == distribution_id, "candidate and review identities differ")
    require(
        review["manifest_name"] == candidate["product"]["manifest_name"]
        and review["release_sequence"] == candidate["release"]["sequence"]
        and review["policy"] == candidate["policy"],
        "candidate release policy differs from the exact review record",
    )
    require(
        review["repository"] == candidate["source"]["repository"]
        and review["path"] == candidate["source"]["path"]
        and review["reviewed_revision"] == candidate["source"]["reviewed_pr_head_sha"]
        and review["reviewed_tree_digest"] == candidate["release"]["tree_digest"]
        and review["reviewed_manifest_digest"] == candidate["release"]["manifest_digest"],
        "candidate package identity differs from the exact review record",
    )
    expected_evidence = [{
        "id": item["id"], "record_digest": sha256(canonical(item)), "level": item["level"],
        "client": item.get("client"), "installer_version": item.get("installer_version"),
        "artifact": item["artifact"],
    } for item in review["evidence"]]
    require(candidate["evidence"] == expected_evidence, "candidate evidence projection differs from the review record")
    products = [item for item in directory["products"] if item["id"] == product_id]
    require(len(products) == 1, "candidate product is not unique")
    product = products[0]
    existing = [item for item in directory["distributions"] if item["id"] == distribution_id]
    require(len(existing) <= 1, "candidate distribution is not unique")
    release = {
        "sequence": candidate["release"]["sequence"],
        "package_version": candidate["release"]["package_version"],
        "manifest_name": candidate["product"]["manifest_name"],
        "agent_plugins_schema": candidate["release"]["agent_plugins_schema"],
        "package_source": {
            "repository": candidate["source"]["repository"],
            "revision": candidate["source"]["official_candidate_sha"],
            "path": candidate["source"]["path"],
        },
        "tree_digest_algorithm": candidate["release"]["tree_digest_algorithm"],
        "tree_digest": candidate["release"]["tree_digest"],
        "manifest_digest": candidate["release"]["manifest_digest"],
        "components": candidate["release"]["components"],
        "published_at": candidate["source"]["merged_at"],
    }
    policy = {**candidate["policy"], "release_sequence": release["sequence"], "current_evidence": [item["id"] for item in review["evidence"]]}
    if existing:
        distribution = existing[0]
        require(distribution["product_id"] == product_id and distribution["kind"] == "upstream", "distribution identity collision")
        require(all(item["sequence"] != release["sequence"] for item in distribution["releases"]), "release already exists")
        distribution["releases"].append(release)
        distribution["release_policies"].append(policy)
        distribution["status"] = "active"
    else:
        directory["distributions"].append({
            "schema_version": 1, "id": distribution_id, "product_id": product_id,
            "kind": "upstream", "status": "active", "packager": distribution_id.split("/", 1)[0],
            "releases": [release], "release_policies": [policy],
        })
    existing_evidence = {item["id"] for item in directory["evidence"]}
    require(not existing_evidence.intersection(policy["current_evidence"]), "promotion evidence identity collision")
    directory["evidence"].extend(review["evidence"])
    product["default_distribution"] = distribution_id
    product["distributions"] = sorted(set([*product["distributions"], distribution_id]))
    directory["distributions"].sort(key=lambda item: item["id"])
    directory["evidence"].sort(key=lambda item: item["id"])
    validate_directory(directory, verify_packages=False)
    artifact_revisions = {item["artifact"]["revision"] for item in review["evidence"]}
    require(len(artifact_revisions) == 1, "promotion evidence must share one immutable commit")
    trusted = publication_config["trusted_external_evidence"]
    for item in review["evidence"]:
        require(item.get("trust") == {"kind": "reviewed_external"}, "promotion evidence trust must be reviewed_external")
        artifact = item["artifact"]
        require(
            artifact["repository"] == active_registry_repository(),
            "promotion evidence artifact repository differs from the registry",
        )
        require(artifact not in trusted, "promotion evidence artifact is already trusted")
        trusted.append(artifact)
    trusted.sort(key=lambda item: (
        item["repository"], item["revision"], item["path"], item["digest"],
    ))
    publication_config["local_evidence_main_anchor"] = next(iter(artifact_revisions))
    with tempfile.TemporaryDirectory(prefix="validate-promotion-config-") as temporary:
        candidate_config = Path(temporary) / "config.json"
        candidate_config.write_bytes(pretty(publication_config))
        load_publication_trust_config(candidate_config)
    args.directory.write_bytes(pretty(directory))
    args.publication_config.write_bytes(pretty(publication_config))
    return {
        "schema_version": 1, "outcome": "applied", "product_id": product_id,
        "distribution_id": distribution_id, "release_sequence": release["sequence"],
    }


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=repository, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "LANG": "C", "LC_ALL": "C"},
    )
    require(completed.returncode == 0, f"git {' '.join(arguments[:2])} failed: {completed.stderr[:500]}")
    return completed.stdout.strip()


def verify_pr(args: argparse.Namespace) -> dict[str, Any]:
    require(SHA_RE.fullmatch(args.base_sha) is not None and SHA_RE.fullmatch(args.head_sha) is not None, "base/head SHA is invalid")
    branch_match = BRANCH_RE.fullmatch(args.branch)
    require(branch_match is not None, "promotion branch name is invalid")
    product_id, short_sha, base_short_sha = branch_match.groups()
    require(args.base_sha.startswith(base_short_sha), "promotion branch does not bind the exact trusted base")
    require(git(args.repository, "rev-parse", "HEAD^{commit}") == args.head_sha, "checked-out head differs from PR head")
    commits = git(args.repository, "rev-list", "--reverse", f"{args.base_sha}..{args.head_sha}").splitlines()
    changed_paths = git(args.repository, "diff", "--name-only", args.base_sha, args.head_sha).splitlines()
    bridge_audits = [
        item for item in changed_paths
        if re.fullmatch(
            rf"registry/upstream-promotion-audit/{re.escape(product_id)}/[0-9a-f]{{40}}/manual-review\.json",
            item,
        )
    ]
    if bridge_audits:
        require(len(bridge_audits) == 1, "locked bridge promotion contains multiple review records")
        from upstream_bridge_promotion import verify_pr as verify_bridge_pr
        return verify_bridge_pr(
            repository=args.repository, base_sha=args.base_sha, head_sha=args.head_sha,
            branch=args.branch, product_id=product_id, short_sha=short_sha,
            commits=commits, audit_path=bridge_audits[0],
        )
    require(len(commits) == 2, "automated promotion PR must contain exactly two commits")
    evidence_commit, promotion_commit = commits
    require(promotion_commit == args.head_sha, "promotion commit is not the PR head")
    require(git(args.repository, "rev-parse", f"{evidence_commit}^") == args.base_sha, "evidence commit is not based on the PR base")
    require(git(args.repository, "rev-parse", f"{promotion_commit}^") == evidence_commit, "promotion commit is not based on evidence")
    evidence_paths = git(args.repository, "diff", "--name-only", args.base_sha, evidence_commit).splitlines()
    raw_candidates = [path for path in evidence_paths if path.endswith("/materialization.json")]
    require(len(raw_candidates) == 1, "evidence commit must contain one aggregate materialization record")
    raw_path = raw_candidates[0]
    require(raw_path.startswith(f"evidence/upstream-promotions/{product_id}/"), "evidence commit changed an unexpected materialization path")
    require(raw_path.endswith("/materialization.json") and f"/{short_sha}" in raw_path, "evidence path does not match the branch identity")
    raw = read_object(args.repository / raw_path)
    require(raw.get("product_id") == product_id and str(raw.get("revision", "")).startswith(short_sha), "raw evidence identity differs from branch")
    clients = raw.get("clients")
    require(
        isinstance(clients, list) and clients
        and clients == [client for client in CLIENT_IDS if client in clients]
        and len(clients) == len(set(clients)),
        "raw evidence clients are invalid",
    )
    evidence_root = raw_path.removesuffix("/materialization.json")
    leaf_paths = [f"{evidence_root}/clients/{client}.json" for client in clients]
    require(
        sorted(evidence_paths) == sorted([raw_path, *leaf_paths]),
        "evidence commit changed unexpected paths",
    )
    audit_root = f"registry/upstream-promotion-audit/{product_id}/{raw['revision']}"
    expected_paths = sorted([
        raw_path, *leaf_paths, "registry/directory.json", "registry/review-preview.json",
        "registry/publication/config.json",
        f"{audit_root}/promotion-candidate.json", f"{audit_root}/review-record.json",
    ])
    actual_paths = sorted(git(args.repository, "diff", "--name-only", args.base_sha, args.head_sha).splitlines())
    require(actual_paths == expected_paths, f"promotion PR changed unexpected paths: {actual_paths!r} != {expected_paths!r}")
    review_path = args.repository / audit_root / "review-record.json"
    candidate_path = args.repository / audit_root / "promotion-candidate.json"
    review, candidate = read_object(review_path), read_object(candidate_path)
    trusted_selection = {
        "decision": "promote",
        "entry": {
            "product_id": candidate["product"]["id"],
            "repository": candidate["source"]["repository"],
            "package_path": candidate["source"]["path"],
            "distribution_id": candidate["distribution"]["id"],
            "release_sequence": candidate["release"]["sequence"],
            "minimum_installer_version": candidate["policy"]["minimum_installer_version"],
            "targets": candidate["policy"]["targets"],
        },
        "pr_metadata": {
            "merge_commit_oid": candidate["source"]["official_candidate_sha"],
        },
    }
    expected_payloads = materialization_evidence_payloads(
        trusted_selection, raw, "linux", "amd64",
    )
    require(
        [item.get("client") for item in review["evidence"]] == clients,
        "review evidence clients differ from raw evidence",
    )
    for item, artifact_path, expected_payload in zip(
        review["evidence"], leaf_paths, expected_payloads, strict=True,
    ):
        artifact = item["artifact"]
        require(
            artifact["repository"] == active_registry_repository()
            and artifact["revision"] == evidence_commit
            and artifact["path"] == artifact_path,
            "review evidence does not bind its client artifact",
        )
        body = (args.repository / artifact_path).read_bytes()
        require(artifact["digest"] == sha256(body), "review evidence digest differs from its client artifact")
        payload = read_object(args.repository / artifact_path)
        jsonschema.Draft202012Validator(schema("directory-evidence-artifact.schema.json")).validate(payload)
        require(body == pretty(payload), f"{artifact_path}: evidence artifact is not canonical")
        require(payload == expected_payload, "client evidence artifact differs from aggregate materialization")
        require(
            {key: value for key, value in item.items() if key not in {"artifact", "trust"}} == payload,
            "review evidence differs from its client artifact",
        )
        require(item.get("trust") == {"kind": "reviewed_external"}, "review evidence trust is invalid")
    require(candidate["source"]["official_candidate_sha"] == raw["revision"], "candidate source differs from raw evidence")
    require(candidate["product"]["id"] == product_id, "candidate product differs from branch")
    require(
        raw["package"]["tree_digest"] == candidate["release"]["tree_digest"]
        and raw["package"]["manifest_digest"] == candidate["release"]["manifest_digest"]
        and raw["package"]["package_version"] == candidate["release"]["package_version"],
        "raw materialization package identity differs from the promotion candidate",
    )
    with tempfile.TemporaryDirectory(prefix="verify-upstream-promotion-") as temporary:
        reconstructed = Path(temporary) / "directory.json"
        reconstructed_config = Path(temporary) / "config.json"
        base_directory = subprocess.run(
            ["git", "show", f"{args.base_sha}:registry/directory.json"], cwd=args.repository,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "LANG": "C", "LC_ALL": "C"},
        ).stdout
        reconstructed.write_bytes(base_directory)
        base_config = subprocess.run(
            ["git", "show", f"{args.base_sha}:registry/publication/config.json"], cwd=args.repository,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            env={"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "LANG": "C", "LC_ALL": "C"},
        ).stdout
        reconstructed_config.write_bytes(base_config)
        apply_args = argparse.Namespace(
            candidate=candidate_path, review_record=review_path,
            directory=reconstructed, publication_config=reconstructed_config,
        )
        apply_candidate(apply_args)
        expected_directory = read_object(reconstructed)
        require(reconstructed.read_bytes() == (args.repository / "registry/directory.json").read_bytes(), "Directory change is not the deterministic promotion result")
        require(
            reconstructed_config.read_bytes()
            == (args.repository / "registry/publication/config.json").read_bytes(),
            "publication trust change is not the deterministic promotion result",
        )
        reconstructed_trust = load_publication_trust_config(reconstructed_config)
        require(
            reconstructed_trust.get("local_evidence_main_anchor") == evidence_commit,
            "publication trust anchor does not preserve the evidence commit",
        )
        require(
            git(args.repository, "merge-base", "--is-ancestor", evidence_commit, args.head_sha) == "",
            "evidence commit is not durable from the promotion head",
        )
        require(
            encoded(directory_preview(expected_directory)) == (args.repository / "registry/review-preview.json").read_bytes(),
            "review preview is not the deterministic promotion projection",
        )
        require(
            encoded(directory_search(expected_directory)) == (args.repository / "registry/review-search.json").read_bytes(),
            "review search is not the deterministic promotion projection",
        )
    return {
        "schema_version": 1, "outcome": "verified", "product_id": product_id,
        "head_sha": args.head_sha, "auto_merge": True, "promotion_kind": "upstream",
        "observer_run_id": raw["run"]["id"],
        "observer_run_attempt": raw["run"]["attempt"], "observer_source_sha": raw["run"]["source_sha"],
        "materialization_path": raw_path, "materialization_digest": sha256((args.repository / raw_path).read_bytes()),
        "upstream_repository": candidate["source"]["repository"],
        "upstream_pr_number": candidate["source"]["upstream_pr_number"],
        "upstream_reviewed_head": candidate["source"]["reviewed_pr_head_sha"],
        "upstream_merge_sha": candidate["source"]["official_candidate_sha"],
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    observe = commands.add_parser("select")
    observe.add_argument("--watch", type=Path, required=True)
    observe.add_argument("--directory", type=Path, required=True)
    observe.add_argument("--gh", type=Path, required=True)
    artifacts = commands.add_parser("evidence-artifacts")
    artifacts.add_argument("--selection", type=Path, required=True)
    artifacts.add_argument("--materialization", type=Path, required=True)
    artifacts.add_argument("--os", default="linux")
    artifacts.add_argument("--architecture", default="amd64")
    artifacts.add_argument("--output-directory", type=Path, required=True)
    record = commands.add_parser("review-record")
    record.add_argument("--selection", type=Path, required=True)
    record.add_argument("--materialization", type=Path, required=True)
    record.add_argument("--artifact-revision", required=True)
    record.add_argument("--artifact-directory", required=True)
    record.add_argument("--repository", type=Path, default=ROOT)
    record.add_argument("--os", default="linux")
    record.add_argument("--architecture", default="amd64")
    record.add_argument("--output", type=Path, required=True)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("--candidate", type=Path, required=True)
    apply_parser.add_argument("--review-record", type=Path, required=True)
    apply_parser.add_argument("--directory", type=Path, required=True)
    apply_parser.add_argument("--publication-config", type=Path, required=True)
    verify = commands.add_parser("verify-pr")
    verify.add_argument("--repository", type=Path, required=True)
    verify.add_argument("--base-sha", required=True)
    verify.add_argument("--head-sha", required=True)
    verify.add_argument("--branch", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "select":
            result = select(args)
        elif args.command == "evidence-artifacts":
            result = write_evidence_artifacts(args)
        elif args.command == "review-record":
            result = review_record(args)
        elif args.command == "apply":
            result = apply_candidate(args)
        else:
            result = verify_pr(args)
    except (PromotionError, RegistryError, jsonschema.ValidationError, OSError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema_version": 1, "outcome": "rejected", "reason": str(error)}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
