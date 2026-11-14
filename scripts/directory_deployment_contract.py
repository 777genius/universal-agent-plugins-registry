"""Public modern deployment authority from one fixed reviewed-source path.

There is deliberately no provisioned production contract in this change. Tests
use disposable source trees; callers cannot select another contract with an
environment variable, candidate field or command-line option.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from .directory_feed_contract import MODERN_FEED, reviewed_source_path
    from .directory_publication import PublicationError, load_feed_trusted_keys, read_json, require
else:
    from directory_feed_contract import MODERN_FEED, reviewed_source_path
    from directory_publication import PublicationError, load_feed_trusted_keys, read_json, require

ROOT = Path(__file__).resolve().parents[1]


def _https_authority(origin: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(origin)
        port = 443 if parsed.port is None else parsed.port
    except ValueError as error:
        raise PublicationError("deployment origin has an invalid HTTPS authority") from error
    require(parsed.scheme == "https" and bool(parsed.hostname) and 1 <= port <= 65535
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment
            and not any(character.isspace() or character == "\\" for character in origin),
            "deployment origin has an invalid HTTPS authority")
    return parsed.hostname.rstrip(".").lower(), port


def load_modern_deployment_contract() -> dict:
    """Fail closed before transport if public authority is not provisioned."""
    path = reviewed_source_path(ROOT, MODERN_FEED.deployment_contract_path)
    value = read_json(path)
    fields = {"contract_version", "marker_ref", "sequence_tag_prefix",
              "bootstrap_ledger_commit", "origin", "publisher_app_id"}
    require(isinstance(value, dict) and set(value) == fields,
            "modern deployment contract has invalid fields")
    require(value["contract_version"] == 1 and not isinstance(value["contract_version"], bool),
            "modern deployment contract version is unsupported")
    require(value["marker_ref"] == MODERN_FEED.production_ref
            and value["sequence_tag_prefix"] == MODERN_FEED.sequence_ref_prefix,
            "modern deployment contract uses the wrong ref namespace")
    require(isinstance(value["bootstrap_ledger_commit"], str)
            and re.fullmatch(r"[0-9a-f]{40}", value["bootstrap_ledger_commit"]) is not None,
            "modern deployment contract must pin its exact ledger seed")
    require(isinstance(value["publisher_app_id"], int)
            and not isinstance(value["publisher_app_id"], bool) and value["publisher_app_id"] > 0,
            "modern deployment contract must identify its approved publisher App")
    origin = value["origin"]
    require(isinstance(origin, str) and origin == origin.strip(),
            "modern deployment origin is invalid")
    authority = _https_authority(origin)
    require(urlsplit(origin).path.endswith("/" + MODERN_FEED.feed_path + "/"),
            "modern deployment origin must identify the fixed HTTPS feed path")
    legacy = read_json(reviewed_source_path(ROOT, "tests/e2e/production-launch.json"))
    require(authority != _https_authority(legacy["production_origin"]),
            "modern deployment requires an independent HTTPS authority from legacy")
    # Besides requiring the reviewed public key file, this retains the existing
    # check that modern key IDs and bytes are independent of legacy trust.
    load_feed_trusted_keys(reviewed_source_path(ROOT, MODERN_FEED.trusted_keys_path), MODERN_FEED)
    return value
