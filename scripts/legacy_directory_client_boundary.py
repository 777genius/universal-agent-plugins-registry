#!/usr/bin/env python3
"""Bound signed Directory client IDs to the pinned released client contract.

Target and evidence still require their independent policy, source, and
signature validations. A known client ID alone is not a package grant.
"""
from __future__ import annotations

if __package__:
    from .directory_publication import CLIENTS, require
else:
    from directory_publication import CLIENTS, require

# CLIENTS is loaded from the digest-verified contract pinned to a released CLI.
# Keep the existing name for callers; this is a wire boundary, not a grant.
LEGACY_DIRECTORY_CLIENT_IDS = CLIENTS


def require_legacy_directory_clients(distributions: list[dict], evidence: list[dict]) -> None:
    """Reject unqualified targets AND evidence during preparation and signing."""
    for distribution in distributions:
        for policy in distribution["release_policies"]:
            require(
                all(target["client"] in LEGACY_DIRECTORY_CLIENT_IDS for target in policy["targets"]),
                "Directory publisher cannot sign an unknown client target",
            )
    require(
        all("client" not in record or record["client"] in LEGACY_DIRECTORY_CLIENT_IDS for record in evidence),
        "Directory publisher cannot sign unknown-client evidence",
    )

