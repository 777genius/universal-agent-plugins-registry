#!/usr/bin/env python3
"""Bound signed Directory v1 client IDs to explicitly qualified readers.

Pi is admitted to the existing publisher under the owner decision to retire
old readers that reject it. Target and evidence still require their independent
policy, source, and signature validations.
"""
from __future__ import annotations

if __package__:
    from .directory_publication import require
else:
    from directory_publication import require

# This is the reviewed wire boundary, not an automatic grant to every adapter.
# Adding an ID allows parsing; it does not confer any package eligibility.
LEGACY_DIRECTORY_CLIENT_IDS = frozenset({
    "codex", "chatgpt", "cursor", "copilot", "vscode", "kiro", "claude",
    "gemini", "opencode", "cline", "windsurf", "grok", "kimi", "qoder", "pi",
})


def require_legacy_directory_clients(distributions: list[dict], evidence: list[dict]) -> None:
    """Reject unqualified targets AND evidence during preparation and signing."""
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
