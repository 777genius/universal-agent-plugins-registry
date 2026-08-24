#!/usr/bin/env python3
"""Validate, derive, and persist permanent stable-launch evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from directory_publication import (  # noqa: E402
    PublicationError,
    canonical_json,
    parse_json_bytes,
    read_bytes_bounded,
    require,
    validate_with_schema,
)


ROOT = Path(__file__).resolve().parents[1]
LAUNCH_SCHEMA = ROOT / "tests" / "e2e" / "schemas" / "launch-evidence.schema.json"
EVIDENCE_SCHEMA = ROOT / "schemas" / "directory-evidence-artifact.schema.json"
GIT = "/usr/bin/git"
GH = "/usr/bin/gh"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
WORKFLOW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*/\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$")
SOURCE_REF_RE = re.compile(r"^refs/heads/[A-Za-z0-9._/-]+$")
HEROES = {"agent-code-navigator", "context7", "cloudflare-docs", "chrome-devtools", "notion"}
HERO_CLIENTS = {"codex", "cursor", "kiro"}
MAX_FILES = 64
MAX_FILE_BYTES = 4 << 20
MAX_BUNDLE_BYTES = 16 << 20
LEDGER_ROOT = PurePosixPath("registry/evidence/sha256")
BOT_NAME = "uap-directory-publisher[bot]"
BOT_EMAIL = "uap-directory-publisher[bot]@users.noreply.github.com"


class EvidenceError(PublicationError):
    """The launch evidence cannot be promoted into permanent Directory data."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def safe_relative(path: str) -> PurePosixPath:
    candidate = PurePosixPath(path)
    if (
        not path or path.startswith("/") or "\\" in path
        or candidate.as_posix() != path or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        fail(f"unsafe evidence path: {path!r}")
    return candidate


def _git(repo: Path, args: Sequence[str], *, input_bytes: bytes | None = None,
         env: Mapping[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [GIT, "-C", str(repo), *args], input=input_bytes, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, check=check,
    )


def require_sha(value: str, label: str) -> None:
    if SHA_RE.fullmatch(value) is None:
        fail(f"{label} must be a full lowercase commit SHA")


def read_json(path: Path, label: str) -> dict[str, Any]:
    value = parse_json_bytes(read_bytes_bounded(path, MAX_FILE_BYTES), label, max_bytes=MAX_FILE_BYTES)
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def applicability(row: dict[str, Any]) -> dict[str, Any]:
    tuple_value = row["tuple"]
    fields = (
        "product_id", "tree_digest", "manifest_digest", "distribution_id",
        "release_sequence", "source_repository", "source_revision", "source_path",
        "dependency_identity", "installer_version", "adapter_version", "client_version",
        "os", "architecture",
    )
    return {"level": row["level"], "client": row["client"], **{field: tuple_value[field] for field in fields}}


def selected_rows(launch: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in launch["matrix"]:
        hero_runtime = (
            row.get("scenario") == "hero_5x3_runtime"
            and row.get("plugin") in HEROES and row.get("client") in HERO_CLIENTS
            and row.get("level") == "runtime"
        )
        chatgpt_runtime = (
            row.get("scenario") == "chatgpt_registered_binding"
            and row.get("plugin") == "cloudflare-docs" and row.get("client") == "chatgpt"
            and row.get("level") == "runtime"
        )
        if not (hero_runtime or chatgpt_runtime):
            continue
        if row.get("outcome") != "passed":
            fail(f"authoritative launch row did not pass: {row.get('id')}")
        details = row.get("details")
        if (
            not isinstance(details, dict)
            or details.get("evidence_basis") != "protected_external_observer"
            or (row.get("client") == "chatgpt" and details.get("public_mcp_proof") is not True)
            or (row.get("client") != "chatgpt" and details.get("native_discovery_proof") is not True)
        ):
            fail(f"launch row is not authoritative protected observer evidence: {row.get('id')}")
        rows.append(row)
    if len(rows) != 16:
        fail(f"expected 16 authoritative hero runtime/OAuth rows, found {len(rows)}")
    expected_runtime = {(plugin, client) for plugin in HEROES for client in HERO_CLIENTS}
    actual_runtime = {(row["plugin"], row["client"]) for row in rows if row["client"] in HERO_CLIENTS}
    if actual_runtime != expected_runtime:
        fail("hero runtime applicability matrix is incomplete or duplicated")
    if sum(row["client"] == "chatgpt" and row["level"] == "runtime" for row in rows) != 1:
        fail("exactly one Cloudflare ChatGPT public-MCP runtime record is required")
    keys = [canonical_json(applicability(row)) for row in rows]
    if len(keys) != len(set(keys)):
        fail("duplicate current-evidence applicability tuple")
    return sorted(rows, key=lambda row: canonical_json(applicability(row)))


def evidence_record(row: dict[str, Any]) -> dict[str, Any]:
    tuple_value = row["tuple"]
    evidence_identity = {
        "applicability": applicability(row),
        "observed_at": tuple_value["observed_at"],
    }
    applicability_digest = hashlib.sha256(canonical_json(evidence_identity)).hexdigest()
    record = {
        "schema_version": 1,
        "id": f"launch/{row['plugin']}/{row['client']}/{row['level']}/{applicability_digest[:24]}",
        "product_id": tuple_value["product_id"],
        "distribution_id": tuple_value["distribution_id"],
        "release_sequence": tuple_value["release_sequence"],
        "package_tree_digest": tuple_value["tree_digest"],
        "manifest_digest": tuple_value["manifest_digest"],
        "source_repository": tuple_value["source_repository"],
        "source_revision": tuple_value["source_revision"],
        "source_path": tuple_value["source_path"],
        "level": row["level"],
        "outcome": row["outcome"],
        "client": row["client"],
        "client_version": tuple_value["client_version"],
        "installer_version": tuple_value["installer_version"],
        "adapter_version": tuple_value["adapter_version"],
        "os": tuple_value["os"],
        "architecture": tuple_value["architecture"],
        "dependency_identity": tuple_value["dependency_identity"],
        "observed_at": tuple_value["observed_at"],
    }
    validate_with_schema(record, EVIDENCE_SCHEMA)
    return record


def checksum_bytes(files: Mapping[str, bytes]) -> bytes:
    lines = [f"{hashlib.sha256(files[path]).hexdigest()}  {path}\n" for path in sorted(files)]
    return "".join(lines).encode("ascii")


def build_bundle(artifact_dir: Path, *, repository: str, workflow: str,
                 source_ref: str, source_digest: str, expected_run_id: str,
                 expected_publication_id: str, expected_sequence: int,
                 expected_snapshot_digest: str, expected_source_commit: str) -> tuple[str, dict[str, bytes]]:
    if REPOSITORY_RE.fullmatch(repository) is None or WORKFLOW_RE.fullmatch(workflow) is None:
        fail("repository or workflow identity is invalid")
    if not workflow.startswith(repository + "/.github/workflows/"):
        fail("workflow and repository identities differ")
    if SOURCE_REF_RE.fullmatch(source_ref) is None:
        fail("protected workflow source ref is invalid")
    require_sha(source_digest, "workflow source digest")
    require_sha(expected_source_commit, "publication source commit")
    if not expected_run_id.isdigit() or not expected_publication_id.isdigit():
        fail("run and publication IDs must be decimal strings")
    if type(expected_sequence) is not int or expected_sequence < 1:
        fail("publication sequence must be a positive integer")
    if DIGEST_RE.fullmatch(expected_snapshot_digest) is None:
        fail("publication snapshot digest is invalid")

    launch_path = artifact_dir / "launch-evidence.json"
    bundle_path = artifact_dir / "signed-observer-bundle.json"
    launch = read_json(launch_path, "launch evidence")
    observer_bytes = read_bytes_bounded(bundle_path, MAX_FILE_BYTES)
    observer = parse_json_bytes(observer_bytes, "signed observer bundle", max_bytes=MAX_FILE_BYTES)
    validate_with_schema(launch, LAUNCH_SCHEMA)
    if launch["run"].get("mode") != "enforced" or launch["run"].get("runtime_claims") is not True:
        fail("only enforced runtime launch evidence is publishable")
    if launch["summary"].get("required_gates_complete") is not True or launch["summary"].get("hero_runtime_results") != 15:
        fail("launch evidence does not prove the complete stable gate")
    if launch["run"].get("github_sha") != source_digest:
        fail("launch evidence workflow source digest mismatch")
    if launch["run"].get("github_run_id") != expected_run_id:
        fail("launch evidence workflow run ID mismatch")
    directory = launch["directory"]
    expected_directory = {
        "sequence": expected_sequence,
        "snapshot_digest": expected_snapshot_digest,
    }
    if any(directory.get(key) != value for key, value in expected_directory.items()):
        fail("launch evidence Directory identity mismatch")
    # The launch harness challenge binds the exact staged source commit.  Each
    # selected row independently carries the immutable release source revision.
    if not isinstance(observer, dict) or sha256(observer_bytes) != launch["run"]["observer_bundle_digest"]:
        fail("signed observer bundle digest mismatch")

    launch_bytes = canonical_json(launch)
    digest = sha256(launch_bytes)
    records = [evidence_record(row) for row in selected_rows(launch)]
    files: dict[str, bytes] = {
        "launch-evidence.json": launch_bytes,
        "signed-observer-bundle.json": observer_bytes,
    }
    index_records: list[dict[str, Any]] = []
    for record in records:
        suffix = record["id"].split("/")[-1]
        filename = f"directory-evidence/records/{record['product_id']}-{record['client']}-{record['level']}-{suffix}.json"
        body = canonical_json(record)
        files[filename] = body
        index_records.append({"id": record["id"], "path": filename, "digest": sha256(body)})
    index = {
        "schema_version": 1,
        "launch_evidence_digest": digest,
        "repository": repository,
        "workflow": workflow,
        "source_ref": source_ref,
        "source_digest": source_digest,
        "workflow_run_id": expected_run_id,
        "publication_id": expected_publication_id,
        "publication_sequence": expected_sequence,
        "publication_snapshot_digest": expected_snapshot_digest,
        "publication_source_commit": expected_source_commit,
        "records": sorted(index_records, key=lambda item: item["id"]),
    }
    files["directory-evidence/index.json"] = canonical_json(index)
    files["SHA256SUMS"] = checksum_bytes(files)
    validate_bounded_files(files)
    return digest, files


def validate_bounded_files(files: Mapping[str, bytes]) -> None:
    if not 1 <= len(files) <= MAX_FILES:
        fail(f"evidence bundle must contain between 1 and {MAX_FILES} files")
    total = 0
    folded: set[str] = set()
    for path, body in files.items():
        safe_relative(path)
        normalized = path.casefold()
        if normalized in folded:
            fail(f"case-colliding evidence path: {path}")
        folded.add(normalized)
        if len(body) > MAX_FILE_BYTES:
            fail(f"evidence file exceeds {MAX_FILE_BYTES} bytes: {path}")
        total += len(body)
    if total > MAX_BUNDLE_BYTES:
        fail(f"evidence bundle exceeds {MAX_BUNDLE_BYTES} bytes")


def write_bundle(directory: Path, files: Mapping[str, bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    expected = set(files)
    for existing in directory.rglob("*"):
        if existing.is_symlink() or (existing.is_file() and existing.relative_to(directory).as_posix() not in expected):
            fail(f"unexpected evidence bundle entry: {existing.relative_to(directory)}")
    for relative, body in files.items():
        destination = directory / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)


def verify_exact_bundle(directory: Path, expected: Mapping[str, bytes]) -> None:
    actual: dict[str, bytes] = {}
    for path in directory.rglob("*"):
        if path.is_symlink() or not path.is_file():
            if path.is_dir():
                continue
            fail(f"evidence bundle contains a non-regular entry: {path}")
        relative = path.relative_to(directory).as_posix()
        safe_relative(relative)
        actual[relative] = read_bytes_bounded(path, MAX_FILE_BYTES)
    validate_bounded_files(actual)
    if set(actual) != set(expected):
        fail(f"evidence bundle paths differ: expected {sorted(expected)}, observed {sorted(actual)}")
    for path, body in expected.items():
        if actual[path] != body:
            fail(f"evidence bundle file is not canonical or checksum-bound: {path}")


def verify_attestation(directory: Path, *, repository: str, workflow: str,
                       source_ref: str, source_digest: str) -> None:
    if not Path(GH).is_file():
        fail(f"required attestation verifier is missing: {GH}")
    command = [
        GH, "attestation", "verify", str(directory / "launch-evidence.json"),
        "--repo", repository, "--signer-workflow", workflow,
        "--source-ref", source_ref, "--source-digest", source_digest,
        "--deny-self-hosted-runners",
    ]
    completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed.returncode != 0:
        fail("launch evidence workflow attestation verification failed")


def load_index(files: Mapping[str, bytes]) -> dict[str, Any]:
    value = parse_json_bytes(files["directory-evidence/index.json"], "evidence index", max_bytes=MAX_FILE_BYTES)
    if not isinstance(value, dict):
        fail("evidence index must be an object")
    return value


def pointer_for(record: dict[str, Any], *, repository: str, ledger_commit: str,
                root: str, index: dict[str, Any], index_digest: str) -> dict[str, Any]:
    index_record = next((item for item in index["records"] if item["id"] == record["id"]), None)
    if index_record is None:
        fail(f"evidence index omitted {record['id']}")
    artifact = {
        "repository": repository,
        "revision": ledger_commit,
        "path": f"{root}/{index_record['path']}",
        "digest": index_record["digest"],
    }
    return {
        **copy.deepcopy(record),
        "artifact": artifact,
        "trust": {
            "kind": "github_actions",
            "workflow": index["workflow"],
            "source_ref": index["source_ref"],
            "source_digest": index["source_digest"],
            "attested_artifact": {
                "repository": repository,
                "revision": ledger_commit,
                "path": f"{root}/launch-evidence.json",
                "digest": index["launch_evidence_digest"],
            },
            "evidence_index": {
                "repository": repository,
                "revision": ledger_commit,
                "path": f"{root}/directory-evidence/index.json",
                "digest": index_digest,
            },
        },
    }


def directory_applicability(record: Mapping[str, Any]) -> bytes:
    return canonical_json({
        "level": record["level"], "client": record.get("client"),
        **{name: record.get(name) for name in (
            "product_id", "package_tree_digest", "manifest_digest", "distribution_id",
            "release_sequence", "source_repository", "source_revision", "source_path",
            "dependency_identity", "installer_version", "adapter_version", "client_version",
            "os", "architecture",
        )},
    })


def update_directory(source: dict[str, Any], pointers: list[dict[str, Any]]) -> dict[str, Any]:
    result = copy.deepcopy(source)
    existing = {item["id"]: item for item in result["evidence"]}
    for pointer in pointers:
        if pointer["id"] in existing and existing[pointer["id"]] != pointer:
            fail(f"immutable evidence identity already exists with different bytes: {pointer['id']}")
        existing[pointer["id"]] = pointer
    result["evidence"] = [existing[key] for key in sorted(existing)]
    policies = {
        (distribution["id"], policy["release_sequence"]): policy
        for distribution in result["distributions"] for policy in distribution["release_policies"]
    }
    applicability_by_id = {
        evidence_id: directory_applicability(record)
        for evidence_id, record in existing.items()
        if record.get("level") != "schema"
    }
    by_applicability: dict[bytes, str] = {}
    for pointer in pointers:
        key = directory_applicability(pointer)
        if key in by_applicability:
            fail(f"duplicate applicability record: {pointer['id']}")
        by_applicability[key] = pointer["id"]
        identity = (pointer["distribution_id"], pointer["release_sequence"])
        policy = policies.get(identity)
        if policy is None:
            fail(f"evidence references missing release policy: {identity[0]}@{identity[1]}")
        current = {
            evidence_id for evidence_id in policy["current_evidence"]
            if applicability_by_id.get(evidence_id) != key
        }
        current.add(pointer["id"])
        policy["current_evidence"] = sorted(current)
    return result


def deterministic_timestamp(digest: str) -> int:
    if DIGEST_RE.fullmatch(digest) is None:
        fail("launch evidence digest is invalid")
    return 946684800 + int(digest.removeprefix("sha256:")[:16], 16) % (100 * 366 * 24 * 60 * 60)


def commit_with_files(repo: Path, parent: str, files: Mapping[str, bytes], message: str,
                      digest: str) -> str:
    require_sha(parent, "commit parent")
    with tempfile.NamedTemporaryFile(prefix="uap-evidence-index-", delete=True) as index:
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = index.name
        _git(repo, ["read-tree", parent], env=env)
        for path, body in sorted(files.items()):
            safe_relative(path)
            blob = _git(repo, ["hash-object", "-w", "--stdin"], input_bytes=body).stdout.decode().strip()
            _git(repo, ["update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"], env=env)
        tree = _git(repo, ["write-tree"], env=env).stdout.decode().strip()
    timestamp = deterministic_timestamp(digest)
    identity = dict(os.environ)
    identity.update({
        "GIT_AUTHOR_NAME": BOT_NAME, "GIT_AUTHOR_EMAIL": BOT_EMAIL,
        "GIT_COMMITTER_NAME": BOT_NAME, "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        "GIT_AUTHOR_DATE": f"@{timestamp} +0000", "GIT_COMMITTER_DATE": f"@{timestamp} +0000",
    })
    return _git(repo, ["commit-tree", tree, "-p", parent], input_bytes=message.encode("utf-8"), env=identity).stdout.decode().strip()


def materialize_commits(source_repo: Path, ledger_repo: Path, artifact_dir: Path, files: Mapping[str, bytes],
                        *, repository: str, main_parent: str, ledger_parent: str, digest: str) -> dict[str, str]:
    require_sha(main_parent, "main parent")
    require_sha(ledger_parent, "ledger parent")
    if _git(source_repo, ["rev-parse", "HEAD"]).stdout.decode().strip() != main_parent:
        fail("source checkout is not the exact main parent")
    if _git(ledger_repo, ["rev-parse", "HEAD"]).stdout.decode().strip() != ledger_parent:
        fail("ledger checkout is not the exact ledger parent")
    root = (LEDGER_ROOT / digest.removeprefix("sha256:")).as_posix()
    if _git(ledger_repo, ["cat-file", "-e", f"{ledger_parent}:{root}"], check=False).returncode == 0:
        fail("immutable evidence root already exists")
    ledger_files = {f"{root}/{path}": body for path, body in files.items()}
    ledger_message = (
        "chore(evidence): persist stable launch evidence\n\n"
        "Launch-Evidence-Persistence: 1\n"
        f"Launch-Evidence-Digest: {digest}\n"
        f"Workflow-Source-Commit: {load_index(files)['source_digest']}\n"
    )
    ledger_commit = commit_with_files(ledger_repo, ledger_parent, ledger_files, ledger_message, digest)
    changed = _git(ledger_repo, ["diff-tree", "--no-commit-id", "--name-status", "-r", ledger_parent, ledger_commit]).stdout.decode().splitlines()
    if not changed or any(not line.startswith(f"A\t{root}/") for line in changed):
        fail("evidence ledger commit is not a bounded append-only root")

    index = load_index(files)
    pointers: list[dict[str, Any]] = []
    for item in index["records"]:
        body = files[item["path"]]
        record = parse_json_bytes(body, item["path"], max_bytes=MAX_FILE_BYTES)
        if not isinstance(record, dict):
            fail(f"invalid Directory evidence leaf: {item['path']}")
        pointers.append(pointer_for(
            record, repository=repository, ledger_commit=ledger_commit, root=root,
            index=index, index_digest=sha256(files["directory-evidence/index.json"]),
        ))
    directory_path = source_repo / "registry" / "directory.json"
    directory = read_json(directory_path, "Directory source")
    updated = update_directory(directory, pointers)
    main_message = (
        "chore(evidence): select stable launch evidence\n\n"
        "Launch-Evidence-Selection: 1\n"
        f"Launch-Evidence-Digest: {digest}\n"
        f"Evidence-Ledger-Commit: {ledger_commit}\n"
    )
    main_commit = commit_with_files(
        source_repo, main_parent, {"registry/directory.json": canonical_json(updated)},
        main_message, digest,
    )
    changed_main = _git(source_repo, ["diff-tree", "--no-commit-id", "--name-only", "-r", main_parent, main_commit]).stdout.decode().splitlines()
    if changed_main != ["registry/directory.json"]:
        fail("mechanical main commit changed paths outside registry/directory.json")
    return {
        "schema_version": "1", "launch_evidence_digest": digest,
        "main_parent": main_parent, "main_commit": main_commit,
        "ledger_parent": ledger_parent, "ledger_commit": ledger_commit,
        "approval_target": ledger_parent,
    }


def write_outputs(path: Path | None, values: Mapping[str, str]) -> None:
    body = canonical_json(dict(values))
    if path is None:
        sys.stdout.buffer.write(body)
    else:
        path.write_bytes(body)


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-publication-id", required=True)
    parser.add_argument("--expected-publication-sequence", type=int, required=True)
    parser.add_argument("--expected-publication-snapshot-digest", required=True)
    parser.add_argument("--expected-publication-source-commit", required=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-bundle")
    common_arguments(prepare)
    prepare.add_argument("--output", type=Path)
    verify = commands.add_parser("verify-bundle")
    common_arguments(verify)
    verify.add_argument("--verify-attestation", action="store_true")
    verify.add_argument("--output", type=Path)
    commit = commands.add_parser("commit")
    common_arguments(commit)
    commit.add_argument("--source-repo", type=Path, required=True)
    commit.add_argument("--ledger-repo", type=Path, required=True)
    commit.add_argument("--main-parent", required=True)
    commit.add_argument("--ledger-parent", required=True)
    commit.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest, files = build_bundle(
            args.artifact_dir, repository=args.repository, workflow=args.workflow,
            source_ref=args.source_ref, source_digest=args.source_digest,
            expected_run_id=args.expected_run_id,
            expected_publication_id=args.expected_publication_id,
            expected_sequence=args.expected_publication_sequence,
            expected_snapshot_digest=args.expected_publication_snapshot_digest,
            expected_source_commit=args.expected_publication_source_commit,
        )
        if args.command == "prepare-bundle":
            write_bundle(args.artifact_dir, files)
            values = {"launch_evidence_digest": digest}
        else:
            verify_exact_bundle(args.artifact_dir, files)
            if getattr(args, "verify_attestation", False):
                verify_attestation(
                    args.artifact_dir, repository=args.repository, workflow=args.workflow,
                    source_ref=args.source_ref, source_digest=args.source_digest,
                )
            values = {"launch_evidence_digest": digest}
            if args.command == "commit":
                values = materialize_commits(
                    args.source_repo, args.ledger_repo, args.artifact_dir, files,
                    repository=args.repository, main_parent=args.main_parent,
                    ledger_parent=args.ledger_parent, digest=digest,
                )
        write_outputs(args.output, values)
    except (EvidenceError, PublicationError, OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError) as error:
        print(f"launch-evidence-materializer: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
