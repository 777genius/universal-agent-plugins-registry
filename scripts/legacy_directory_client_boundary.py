#!/usr/bin/env python3
"""Keep Pi out of the historical signed Directory v1 publisher.

The modern-client v1 feed needs its own protected publisher, signing key,
ledger, cache and origin. This check deliberately applies to *all* policies,
including revoked and suspended ones, because older readers parse the entire
signed snapshot before evaluating individual release eligibility.
"""
from __future__ import annotations

from directory_publication import require


def require_pi_free_legacy_distributions(distributions: list[dict]) -> None:
    """Refuse a Pi target before preparing OR signing a historical v1 release."""
    for distribution in distributions:
        for policy in distribution["release_policies"]:
            require(
                all(target["client"] != "pi" for target in policy["targets"]),
                "historical Directory v1 publisher cannot sign a Pi client target; "
                "use a separately approved modern-client signed v1 lineage",
            )
