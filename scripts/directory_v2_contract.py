"""Scoped-grant identity rules for the optional Directory v2 wire contract.

The signed v1 format and its validator remain unchanged. This module performs
only semantic checks JSON Schema cannot express; no publication path uses v2
until signed bootstrap/readers are qualified.
"""
from __future__ import annotations


def require_unique_scoped_grants(policy: dict) -> None:
    targets = policy.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("scoped policy requires nonempty targets")
    seen: set[tuple[str, str]] = set()
    for index, grant in enumerate(targets):
        if not isinstance(grant, dict):
            raise ValueError(f"scoped target {index} must be an object")
        client, scope = grant.get("client"), grant.get("scope")
        if not isinstance(client, str) or not isinstance(scope, str):
            raise ValueError(f"scoped target {index} lacks client/scope identity")
        key = (client, scope)
        if key in seen:
            raise ValueError(f"duplicate scoped target {client}/{scope}")
        seen.add(key)
