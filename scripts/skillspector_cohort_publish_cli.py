#!/usr/bin/env python3
"""Main-only SkillSpector v1 signed cohort publication entrypoint.

The no-LLM scanner is executed in a separate read-only reusable workflow.
This step receives the protected independent key only after all nine scan
results exist, then rechecks every old-v3 shard and current signed feed.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts import discover_skillspector_sources as discovery
from scripts import publish_skillspector_cohort as publisher
from scripts import publish_skillspector_coverage_v3 as old_publisher
from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_cohort_release_protocol as protocol
from scripts import skillspector_live_cohort_preflight as live
from scripts import skillspector_reports as scanner
from scripts import skillspector_coverage_v3 as coverage
from scripts.directory_publication import (
    ed25519_private_key, format_timestamp, load_public_keys,
    canonical_json, require,
)
from scripts.discovery_checkpoint import WorkBudget
from scripts.publish_skillspector_reports import GitHub

REPOSITORY = "777genius/universal-agent-plugins-registry"
TRUSTED_KEYS = scanner.ROOT / "registry/skillspector-cohort/trusted-keys.json"


def authenticated_fresh_sources(previous: dict, plan: dict) -> dict:
    """Re-fetch current Ed25519-signed Community and Directory snapshots."""
    budget = WorkBudget(300)
    community, community_info = discovery.load_published_community_plugins(budget)
    directory, directory_info = discovery.load_published_plugins(budget)
    return live.verify_live_pins(
        previous, plan, community, community_info, directory, directory_info)


def publish_one(candidate_path: Path, token: str, signing_seed: str,
                signing_key_id: str, source_commit: str) -> str:
    """Requalify source, sign with protected key and CAS-publish exact bytes."""
    require(isinstance(token, str) and bool(token), "publisher GitHub token is absent")
    require(admission.SHA.fullmatch(source_commit) is not None,
            "caller source SHA is invalid")
    require(isinstance(signing_key_id, str) and bool(signing_key_id),
            "reviewed cohort signing key ID is missing")
    trusted_keys = load_public_keys(TRUSTED_KEYS)
    require(bool(trusted_keys) and signing_key_id in trusted_keys,
            "independent cohort trusted public key has not been reviewed/registered")
    private_seed = ed25519_private_key(signing_seed)
    github = GitHub(token)
    with tempfile.TemporaryDirectory(prefix="skillspector-signed-cohort-v1-") as temporary:
        previous_dir = Path(temporary) / "published-v3"
        report_commit = old_publisher.previous(github, previous_dir)
        require(report_commit is not None,
                "no trusted previous SkillSpector v3 report branch")
        previous = protocol.candidate_signature.load_verified_previous(
            previous_dir, report_commit)
        plan = admission.build_plan(previous, previous["selection"], report_commit)
        proof = scanner.read_report_json(candidate_path,
                                        max_bytes=protocol.candidate.MAX_PROOF_BYTES)
        protocol.candidate_signature.validate_candidate_proof(
            proof, previous_dir, report_commit)

        # Main-only signer runs the independent live source verifier; a
        # plan copied from the old report does NOT constitute live evidence.
        def fresh_source_loader() -> dict:
            return authenticated_fresh_sources(previous, plan)

        source_pins = fresh_source_loader()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        release = protocol.build_release(
            proof, source_pins, previous_dir, source_commit,
            format_timestamp(now), format_timestamp(now + timedelta(hours=24)),
            now=now)
        envelope = protocol.sign_release(
            release, trusted_keys, signing_key_id, private_seed, previous_dir,
            fresh_source_loader, now=now)
        body, sealed = scanner.report_json(release), canonical_json(envelope)
        expected_head = publisher.checked_head(github, publisher.BRANCH)
        published = publisher.publish(
            github, body, sealed, trusted_keys, previous_dir,
            fresh_source_loader, expected_head, now=now)
        print("Signed cohort v1 published and read back at immutable Git SHA: " + published)
        return published


def main() -> int:
    """Require an exact main workflow before opening protected signing context."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "cohort production publication requires an explicit main workflow")
    candidate_path = args.candidate
    require(candidate_path.is_file() and not candidate_path.is_symlink(),
            "candidate artifact must be a regular file")
    publish_one(
        candidate_path, os.environ.get("GITHUB_TOKEN", ""),
        os.environ.get("SKILLSPECTOR_COHORT_ED25519_PRIVATE_KEY", ""),
        os.environ.get("SKILLSPECTOR_COHORT_SIGNING_KEY_ID", ""),
        os.environ.get("GITHUB_SHA", ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
