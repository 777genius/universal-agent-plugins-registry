#!/usr/bin/env python3
"""Strict validators for the two protected launch-evidence lanes.

This module is deliberately an artifact contract, not a production CLI mode.
Policy evidence can gate a release, but can never be projected into Directory
runtime evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_SCENARIO_IDS = (
    "retained_data_readd_before_changed_default",
    "revoked_operations_boundary",
    "signed_sequence_not_semver",
    "directory_offline",
    "directory_expired",
    "directory_tampered",
    "directory_sequence_rollback",
    "upstream_owned_short_name",
    "community_bridge_short_name",
    "distribution_sticky_update",
    "external_activation_failure",
)
POLICY_SCENARIO_SET = frozenset(POLICY_SCENARIO_IDS)
RUNTIME_RESULT_COUNT = 15
POLICY_RESULT_COUNT = len(POLICY_SCENARIO_IDS)
PLUGIN_KIT_REPOSITORY = "777genius/plugin-kit-ai"
PLUGIN_KIT_TAG = "agentplugins-v0.1.18"
PLUGIN_KIT_COMMIT = "74a3790ee15d92afda8e8e3dd8f903c04811cfc7"
UAP_COMMIT = "b37eda9a710b4e41bde3cc27ada56dd3b17edc40"
FIXTURE_KEY_ID = "launch-conformance-only"
RELEASED_LINUX_AMD64_DIGEST = "sha256:9a294d2d117d6be2042aa28f911999edccf051ccbc3f1c7f0f46920cfd6b5779"
RELEASE_MANIFEST_DIGEST = "sha256:0e8f7316ddef542067bdd7276273fffa3bc00532afed8fd42be12f612aedea57"
RELEASE_CHECKSUMS_DIGEST = "sha256:d581ac34d9880afe998f8f871df285b5474623778d2eae98ebc8780a932a9fa8"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class TwoLaneEvidenceError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes())


def classified_runtime_lists(config: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Return immutable runtime-only lists and reject classification drift."""
    classified = tuple(
        config[family]
        for family in ("fault_scenarios", "adapter_repair_faults", "advanced_scenarios")
    )
    flat = tuple(item for family in classified for item in family)
    if len(flat) != len(set(flat)) or len(flat) != 21:
        raise TwoLaneEvidenceError("fault/adapter/advanced contract must contain exactly 21 unique IDs")
    present = tuple(item for item in flat if item in POLICY_SCENARIO_SET)
    acceptance = tuple(config["acceptance_postconditions"])
    if tuple(item for item in acceptance if item in POLICY_SCENARIO_SET) != POLICY_SCENARIO_IDS[:3]:
        raise TwoLaneEvidenceError("acceptance policy classification drift")
    if set(present) != POLICY_SCENARIO_SET - set(POLICY_SCENARIO_IDS[:3]):
        raise TwoLaneEvidenceError("fault/advanced policy classification drift")
    return {
        "fault_adapter_advanced": tuple(item for item in flat if item not in POLICY_SCENARIO_SET),
        "acceptance": tuple(item for item in acceptance if item not in POLICY_SCENARIO_SET),
    }


def reject_policy_scenario_before_effect(scenario_id: str) -> None:
    """Released-lane preflight. Call before creating a subprocess or path."""
    if scenario_id in POLICY_SCENARIO_SET:
        raise TwoLaneEvidenceError(
            f"{scenario_id} is source-policy conformance and is forbidden in released-binary execution"
        )


def validate_released_binary_evidence(value: dict[str, Any]) -> str:
    if value.get("evidence_class") != "released_binary":
        raise TwoLaneEvidenceError("runtime evidence_class must be released_binary")
    run = value.get("run", {})
    summary = value.get("summary", {})
    if run.get("mode") != "enforced" or run.get("runtime_claims") is not True:
        raise TwoLaneEvidenceError("released evidence must make an enforced runtime claim")
    if summary.get("released_binary_gate_complete") is not True:
        raise TwoLaneEvidenceError("released binary gate is incomplete")
    cli = run.get("cli", {})
    release = value.get("release", {})
    directory = value.get("directory", {})
    if not (
        cli.get("version") == "0.1.18"
        and cli.get("binary_digest") == RELEASED_LINUX_AMD64_DIGEST
        and release.get("repository") == PLUGIN_KIT_REPOSITORY
        and release.get("tag") == PLUGIN_KIT_TAG
        and release.get("tag_commit") == PLUGIN_KIT_COMMIT
        and release.get("immutable") is True
        and release.get("manifest_digest") == RELEASE_MANIFEST_DIGEST
        and release.get("checksums_digest") == RELEASE_CHECKSUMS_DIGEST
        and re.fullmatch(r"[0-9a-f]{40}", str(run.get("github_sha", "")))
        and re.fullmatch(r"https://raw\.githubusercontent\.com/777genius/universal-agent-plugins/[0-9a-f]{40}/registry/schemas/1/", str(directory.get("origin", "")))
        and type(directory.get("sequence")) is int and directory["sequence"] > 0
        and DIGEST.fullmatch(str(directory.get("snapshot_digest", "")))
        and DIGEST.fullmatch(str(directory.get("trust_root_digest", "")))
    ):
        raise TwoLaneEvidenceError("released binary/release/UAP/Directory identity mismatch")
    rows = value.get("matrix")
    if not isinstance(rows, list) or any(row.get("scenario") in POLICY_SCENARIO_SET for row in rows):
        raise TwoLaneEvidenceError("released evidence contains a source-policy row")
    if summary.get("hero_runtime_results") != RUNTIME_RESULT_COUNT:
        raise TwoLaneEvidenceError("released evidence requires exactly 15 runtime results")
    return sha256(canonical_json(value))


def validate_source_policy_evidence(
    value: dict[str, Any], *, scenario_digest: str, harness_digest: str,
    overlay_digest: str, uap_sha: str = UAP_COMMIT,
) -> str:
    identities = value.get("identities", {})
    expected = {
        "plugin_kit_repository": PLUGIN_KIT_REPOSITORY,
        "plugin_kit_tag": PLUGIN_KIT_TAG,
        "plugin_kit_commit": PLUGIN_KIT_COMMIT,
        "uap_sha": uap_sha,
        "scenario_digest": scenario_digest,
        "harness_digest": harness_digest,
        "overlay_digest": overlay_digest,
    }
    if value.get("evidence_class") != "source_policy_conformance":
        raise TwoLaneEvidenceError("policy evidence_class mismatch")
    if value.get("runtime_claims") is not False or value.get("released_binary_executed") is not False:
        raise TwoLaneEvidenceError("policy evidence cannot claim released runtime execution")
    if value.get("fixture_key_id") != FIXTURE_KEY_ID:
        raise TwoLaneEvidenceError("policy fixture key mismatch")
    if any(identities.get(key) != expected_value for key, expected_value in expected.items()):
        raise TwoLaneEvidenceError("source-policy identity mismatch")
    if (
        identities.get("release_manifest_digest") != RELEASE_MANIFEST_DIGEST
        or identities.get("release_checksums_digest") != RELEASE_CHECKSUMS_DIGEST
    ):
        raise TwoLaneEvidenceError("release manifest/checksum identity mismatch")
    rows = value.get("results")
    if not isinstance(rows, list):
        raise TwoLaneEvidenceError("policy results must be an array")
    actual = Counter(row.get("id") for row in rows)
    if set(actual) != POLICY_SCENARIO_SET or any(actual[item] != 1 for item in POLICY_SCENARIO_IDS):
        raise TwoLaneEvidenceError("policy evidence must contain the exact 11 IDs once each")
    if any(
        row.get("outcome") != "passed"
        or not isinstance(row.get("test"), dict)
        or row["test"].get("passed") is not True
        or not isinstance(row.get("proof"), dict)
        or row["proof"].get("runtime_evidence_eligible") is not False
        or sha256(canonical_json(row["proof"])) != row.get("proof_digest")
        or not DIGEST.fullmatch(str(row.get("proof_digest", "")))
        for row in rows
    ):
        raise TwoLaneEvidenceError("policy evidence contains a failed or incomplete proof")
    revoked = next(row for row in rows if row["id"] == "revoked_operations_boundary")["proof"].get("unit_oracle", {})
    revoked_stderr = (
        "Resolving and validating one Agent Plugin package for every selected target...\n"
        "agentplugins: no eligible directory release for \"context7\": "
        "upstash/context7: release 1 is revoked\n"
    )
    if not (
        revoked.get("argv") == ["add", "context7", "--target", "codex", "--format", "json"]
        and revoked.get("exit_code") == 1
        and revoked.get("zero_mutation") is True
        and revoked.get("runtime_evidence_eligible") is False
        and revoked.get("stdout_digest") == sha256(b"")
        and revoked.get("stderr_digest") == sha256(revoked_stderr.encode())
    ):
        raise TwoLaneEvidenceError("revoked policy unit oracle is incomplete")
    if value.get("production_source_unchanged") is not True:
        raise TwoLaneEvidenceError("production source tree was not proven unchanged")
    if value.get("policy_conformance_gate_complete") is not True:
        raise TwoLaneEvidenceError("policy conformance gate is incomplete")
    return sha256(canonical_json(value))


def build_readiness_envelope(runtime: dict[str, Any], policy: dict[str, Any], *,
                             scenario_digest: str, harness_digest: str,
                             overlay_digest: str, uap_sha: str = UAP_COMMIT) -> dict[str, Any]:
    runtime_digest = validate_released_binary_evidence(runtime)
    policy_digest = validate_source_policy_evidence(
        policy, scenario_digest=scenario_digest, harness_digest=harness_digest,
        overlay_digest=overlay_digest, uap_sha=uap_sha,
    )
    return {
        "schema_version": 1,
        "evidence_class": "two_lane_readiness",
        "runtime_evidence_digest": runtime_digest,
        "source_policy_evidence_digest": policy_digest,
        "runtime_results": RUNTIME_RESULT_COUNT,
        "policy_results": POLICY_RESULT_COUNT,
        "readiness_gate_complete": True,
    }


def validate_completed_readiness(envelope: dict[str, Any], runtime: dict[str, Any],
                                 policy: dict[str, Any], **identity: str) -> None:
    expected = build_readiness_envelope(runtime, policy, **identity)
    if envelope != expected:
        raise TwoLaneEvidenceError("completed readiness replay differs from either canonical evidence digest")
