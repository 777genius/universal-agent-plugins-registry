#!/usr/bin/env python3
"""Resolve a bridge predecessor from the authenticated public CLI search view."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ResolutionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ResolutionError(message)


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def resolve(
    directory: dict[str, Any], search: dict[str, Any], production_snapshot_body: bytes, *, distribution_id: str,
    next_sequence: int, fallback_revision: str,
) -> dict[str, Any]:
    require(SHA_RE.fullmatch(fallback_revision) is not None, "fallback revision is invalid")
    distributions = [item for item in directory.get("distributions", []) if item.get("id") == distribution_id]
    require(len(distributions) == 1, "bridge distribution is absent or ambiguous")
    distribution = distributions[0]
    releases = sorted(distribution.get("releases", []), key=lambda item: item.get("sequence", -1))
    predecessors = [item for item in releases if item.get("sequence") == next_sequence - 1]
    require(len(predecessors) == 1, "bridge predecessor is absent or ambiguous")
    predecessor = predecessors[0]
    source = predecessor.get("package_source", {})
    require(source.get("revision") is None, "bridge predecessor is already bound in review source")

    data = search.get("data", {})
    require(search.get("result") == "success" and isinstance(data, dict), "CLI search did not succeed")
    sequence = data.get("snapshot_sequence")
    digest = data.get("snapshot_digest")
    require(isinstance(sequence, int) and sequence > 0, "CLI search omitted the signed Directory sequence")
    require(isinstance(digest, str) and digest.startswith("sha256:"), "CLI search omitted the signed Directory digest")
    production_snapshot = json.loads(production_snapshot_body)
    require(isinstance(production_snapshot, dict), "production Directory snapshot is not an object")
    production_digest = "sha256:" + hashlib.sha256(production_snapshot_body).hexdigest()
    require(production_snapshot.get("sequence") == sequence, "CLI search did not use the current production Directory sequence")
    require(production_digest == digest, "CLI search did not use the current production Directory digest")
    published_distributions = [
        item for item in production_snapshot.get("distributions", [])
        if item.get("id") == distribution_id
    ]
    require(len(published_distributions) <= 1, "production Directory contains an ambiguous bridge distribution")
    if not published_distributions:
        return {
            "revision": fallback_revision, "source": "unpublished_predecessor",
            "snapshot_sequence": sequence, "snapshot_digest": digest,
        }

    published_releases = published_distributions[0].get("releases", [])
    published_predecessors = [item for item in published_releases if item.get("sequence") == next_sequence - 1]
    require(len(published_predecessors) <= 1, "production Directory contains an ambiguous bridge predecessor")
    if not published_predecessors:
        require(
            all(isinstance(item.get("sequence"), int) and item["sequence"] < next_sequence - 1 for item in published_releases),
            "production Directory skipped the exact bridge predecessor",
        )
        return {
            "revision": fallback_revision, "source": "unpublished_predecessor",
            "snapshot_sequence": sequence, "snapshot_digest": digest,
        }

    published = published_predecessors[0]
    published_source = published.get("package_source", {})
    revision = published_source.get("revision")
    require(published.get("package_version") == predecessor.get("package_version"), "published predecessor version changed")
    require(SHA_RE.fullmatch(str(revision)) is not None, "signed predecessor revision is invalid")
    require(published_source.get("repository") == source.get("repository"), "signed predecessor repository changed")
    require(published_source.get("path") == source.get("path"), "signed predecessor path changed")
    return {
        "revision": revision, "source": "signed_directory",
        "snapshot_sequence": sequence, "snapshot_digest": digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--search", type=Path, required=True)
    parser.add_argument("--production-snapshot", type=Path, required=True)
    parser.add_argument("--distribution-id", required=True)
    parser.add_argument("--next-sequence", type=int, required=True)
    parser.add_argument("--fallback-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = resolve(
        read_object(args.directory), read_object(args.search), args.production_snapshot.read_bytes(),
        distribution_id=args.distribution_id, next_sequence=args.next_sequence,
        fallback_revision=args.fallback_revision,
    )
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, ResolutionError) as error:
        raise SystemExit(f"resolve-bridge-predecessor: {error}") from error
