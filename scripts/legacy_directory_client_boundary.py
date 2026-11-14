#!/usr/bin/env python3
"""Freeze the historical signed Directory v1 reader's accepted client IDs.

The modern-client v1 feed needs its own protected publisher, signing key,
ledger, cache and origin. This check deliberately applies to *all* policies,
including revoked and suspended ones, because older readers parse the entire
signed snapshot, including evidence, before evaluating release eligibility.
"""
from __future__ import annotations

from directory_publication import require

# This is a historical wire boundary, not the list of currently supported UAP
# adapters. Never derive it from a newer released client-capability contract.
LEGACY_DIRECTORY_CLIENT_IDS = frozenset({
    "codex", "chatgpt", "cursor", "copilot", "vscode", "kiro", "claude",
    "gemini", "opencode", "cline", "windsurf", "grok", "kimi", "qoder",
})


def require_legacy_directory_clients(distributions: list[dict], evidence: list[dict]) -> None:
    """Reject new targets AND evidence before preparing or signing legacy v1."""
    for distribution in distributions:
        for policy in distribution["release_policies"]:
            require(
                all(target["client"] in LEGACY_DIRECTORY_CLIENT_IDS for target in policy["targets"]),
                "historical Directory v1 publisher cannot sign a new client target; "
                "use a separately approved modern-client signed v1 lineage",
            )
    require(
        all("client" not in record or record["client"] in LEGACY_DIRECTORY_CLIENT_IDS for record in evidence),
        "historical Directory v1 publisher cannot sign new-client evidence; "
        "use a separately approved modern-client signed v1 lineage",
    )
