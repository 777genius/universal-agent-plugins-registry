#!/usr/bin/env python3
"""Export inert historical browse data, never a signed Discovery candidate."""
from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

from scripts.build_discovery_index import SEARCH_SCHEMA, validate_document
from scripts.directory_publication import canonical_json, parse_timestamp, sha256_digest
from scripts.discovery_checkpoint import MAX_BYTES, atomic_json


def read_checkpoint(path: Path, kind: str, expected_digest: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    if path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError("invalid checkpoint file")
    body = path.read_bytes()
    value = json.loads(body, object_pairs_hook=unique)
    if canonical_json(value) != body:
        raise ValueError("noncanonical checkpoint")
    if value["checkpoint_schema_version"] != 1 or value["kind"] != kind:
        raise ValueError("wrong checkpoint kind/version")
    actual = sha256_digest(canonical_json(value["payload"]))
    if actual != expected_digest or actual != value["payload_digest"]:
        raise ValueError("checkpoint payload does not match reviewed evidence")
    return value


def export(acquisition: dict, validation: dict) -> dict:
    source = "0fb86410740472691636630984c5d1dccaf89f85"
    observed = "2026-10-03T03:02:03Z"
    if (acquisition["binding"]["source_commit"] != source
            or acquisition["binding"]["mode"] != "discover"
            or acquisition["generated_at"] != observed
            or validation["generated_at"] != observed
            or validation["binding"] != "sha256:5df2987364289d53a628ee63579213b0176532c5c126616c95788f5b7e37924e"
            or acquisition["payload"]["complete"] is not True):
        raise ValueError("source observation/binding differs from reviewed scan")
    selected = []
    identities = set()
    completed = 0
    for result in validation["payload"]["results"].values():
        if result["complete"] is not True:
            continue
        completed += 1
        for identity, record in result["records"]:
            if record["availability"] != "available":
                continue
            expected = record["repository"].casefold() + "\0" + record["package_path"].casefold()
            if identity != expected or identity in identities or record["last_seen"] != observed:
                raise ValueError("invalid/duplicate saved record identity or observation")
            identities.add(identity)
            selected.append(record)
    selected.sort(key=lambda record: (record["repository"], record["package_path"].casefold(), record["slug"]))
    validate_document({"search_schema_version": 1, "sequence": 1,
                       "generated_at": observed, "records": selected}, SEARCH_SCHEMA, "saved browse records")
    fields = ("name", "description", "repository", "package_path", "revision", "version",
              "components", "manifest_digest", "tree_digest", "first_seen", "last_seen")
    return {"schema_version": 1, "source_run": 37091816539, "source_commit": source,
            "acquisition_artifact": 11265591271, "validation_artifact": 11271029047,
            "observed_at": observed,
            "checkpoint_fresh_until": (parse_timestamp(observed, "observation") + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
            "scan_complete": False, "complete_cached_repositories": completed,
            "acquisition_candidate_paths": 6688,
            "acquisition_payload_digest": acquisition["payload_digest"],
            "validation_payload_digest": validation["payload_digest"],
            "records": [{field: record[field] for field in fields} for record in selected]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquisition", required=True, type=Path)
    parser.add_argument("--validation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    acquisition = read_checkpoint(args.acquisition, "acquisition", "sha256:4c39706b92c950334f75592f6d365e7d9caf3875ed4f28ef59db39137cf61ccf")
    validation = read_checkpoint(args.validation, "validation", "sha256:e6bb8d73e42cabaf3398542e0b24d9fc5459ae50a9d65d22a5d5767f8e137085")
    result = export(acquisition, validation)
    atomic_json(args.output, result)
    print(f"Exported {len(result['records'])} historical browse-only records; signed feed unchanged")


if __name__ == "__main__":
    main()
