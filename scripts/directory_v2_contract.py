"""Scoped-grant identity rules for the optional Directory v2 wire contract.

The signed v1 format and its validator remain unchanged. This module performs
only semantic checks JSON Schema cannot express; no publication path uses v2
until signed bootstrap/readers are qualified.
"""
from __future__ import annotations

import copy
import re


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

def legacy_user_v2_distribution(distribution: dict, installer_version: str) -> dict:
    """Project a reviewed v1 source into v2 *user-only* bootstrap grants.

    The caller must still apply the signed publication pipeline and verify the
    original v1 source; this function does not authorize or publish new scopes.
    """
    def version(value: str) -> tuple[int, int, int]:
        if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value):
            raise ValueError("invalid installer version in v1 bootstrap")
        return tuple(int(part) for part in value.split("."))

    floor = version(installer_version)
    if not isinstance(distribution, dict) or distribution.get("schema_version") != 1:
        raise ValueError("v2 bootstrap requires a reviewed v1 distribution")
    projected = copy.deepcopy(distribution)
    projected["schema_version"] = 2
    for policy in projected["release_policies"]:
        previous_floor = version(policy["minimum_installer_version"])
        effective_floor = max(floor, previous_floor)
        grants = []
        for target in policy["targets"]:
            if target.get("scopes") != ["user"]:
                raise ValueError("v1 bootstrap cannot promote non-user scopes")
            grant = {key: value for key, value in target.items() if key != "scopes"}
            grant["scope"] = "user"
            grant["minimum_installer_version"] = ".".join(map(str, effective_floor))
            grant["current_evidence"] = list(policy["current_evidence"])
            grants.append(grant)
        policy["targets"] = grants
        require_unique_scoped_grants(policy)
    return projected
