"""Validation against the reviewed repository evidence schemas."""

from __future__ import annotations

import json
import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, RefResolver

from .canonical import ARTIFACT_NAMES

SCHEMA_ROOT = Path(__file__).parents[1] / "tests" / "e2e" / "schemas"
BASE_URI = "https://uap.invalid/schemas/"


@lru_cache(maxsize=1)
def _validators() -> tuple[Draft202012Validator, Draft202012Validator]:
    if not SCHEMA_ROOT.is_dir():
        raise ValueError("reviewed observer schemas are unavailable")
    schemas: dict[str, dict[str, Any]] = {}
    for path in SCHEMA_ROOT.glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        value = {**value, "$id": BASE_URI + path.name}
        schemas[path.name] = value
    try:
        runtime = schemas["runtime-attestations.schema.json"]
        consent = schemas["consent.schema.json"]
    except KeyError:
        raise ValueError("reviewed observer schemas are incomplete") from None
    store = {BASE_URI + name: schema for name, schema in schemas.items()}
    runtime_resolver = RefResolver(BASE_URI + "runtime-attestations.schema.json", runtime, store=store)
    consent_resolver = RefResolver(BASE_URI + "consent.schema.json", consent, store=store)
    checker = FormatChecker()
    return (
        Draft202012Validator(runtime, resolver=runtime_resolver, format_checker=checker),
        Draft202012Validator(consent, resolver=consent_resolver, format_checker=checker),
    )


def validate_artifact_schemas(
    artifacts: dict[str, Any], *, challenge: str, scenario_contract_digest: str | None = None,
    expected_bindings: dict[str, str] | None = None,
) -> None:
    if set(artifacts) != ARTIFACT_NAMES:
        raise ValueError("observer artifact set is not canonical")
    runtime, consent_validator = _validators()
    for name in (
        "runtime-attestations.json", "notion-oauth-attestations.json",
        "chatgpt-cloudflare-attestation.json",
    ):
        errors = sorted(runtime.iter_errors(artifacts[name]), key=lambda item: list(item.absolute_path))
        if errors:
            raise ValueError(f"{name} does not match the reviewed schema")
        for record in artifacts[name].get("attestations", []):
            if record.get("challenge") != challenge:
                raise ValueError(f"{name} is not challenge-bound")
    errors = sorted(consent_validator.iter_errors(artifacts["consent.json"]), key=lambda item: list(item.absolute_path))
    if errors:
        raise ValueError("consent.json does not match the reviewed schema")
    if artifacts["consent.json"].get("challenge") != challenge:
        raise ValueError("consent.json is not challenge-bound")
    if scenario_contract_digest is not None and artifacts["consent.json"].get("scenario_contract_digest") != scenario_contract_digest:
        raise ValueError("consent.json is not scenario-contract-bound")
    _validate_exact_phase_six_set(artifacts, challenge=challenge, expected_bindings=expected_bindings)


def _validate_exact_phase_six_set(
    artifacts: dict[str, Any], *, challenge: str,
    expected_bindings: dict[str, str] | None,
) -> None:
    clients = {"codex", "cursor", "kiro"}
    runtime_plugins = {"agent-code-navigator", "context7", "cloudflare-docs", "chrome-devtools"}
    expected_pairs = {
        "runtime-attestations.json": {(plugin, client) for plugin in runtime_plugins for client in clients},
        "notion-oauth-attestations.json": {("notion", client) for client in clients},
        "chatgpt-cloudflare-attestation.json": {("cloudflare-docs", "chatgpt")},
    }
    consent = artifacts["consent.json"]
    exported_consent = (json.dumps(consent, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    consent_digest = "sha256:" + hashlib.sha256(exported_consent).hexdigest()
    binding_fields = (
        "release_manifest_digest", "release_checksums_digest", "directory_digest",
        "scenario_contract_digest",
    )
    common_bindings: dict[str, str] | None = None
    release_identities: dict[str, dict[str, Any]] = {}
    for name, pairs in expected_pairs.items():
        records = artifacts[name]["attestations"]
        actual = [(record.get("plugin"), record.get("client")) for record in records]
        if len(actual) != len(set(actual)) or set(actual) != pairs:
            raise ValueError(f"{name} does not contain the exact unique Phase 6 pair set")
        for record in records:
            plugin, client = record["plugin"], record["client"]
            expected_level = "oauth" if name != "runtime-attestations.json" else "runtime"
            expected_scenario = "chatgpt_registered_binding" if client == "chatgpt" else "hero_5x3_runtime"
            if record.get("level") != expected_level or record.get("scenario_id") != expected_scenario:
                raise ValueError(f"{name} contains a misplaced attestation")
            if (
                record.get("challenge") != challenge
                or record.get("run_id") != consent.get("run_id")
                or record.get("run_attempt") != consent.get("run_attempt")
                or record.get("identity_id") != consent.get("pseudonymous_identity_id")
                or record.get("pseudonymous_identity_id") != consent.get("pseudonymous_identity_id")
                or record.get("pseudonymous_workspace_id") != consent.get("pseudonymous_workspace_id")
                or record.get("consent_artifact_digest") != consent_digest
            ):
                raise ValueError(f"{name} contains foreign run, consent, or pseudonym bindings")
            bindings = {field: record.get(field) for field in binding_fields}
            if bindings["scenario_contract_digest"] != consent.get("scenario_contract_digest"):
                raise ValueError(f"{name} is not scenario-contract-bound")
            if common_bindings is None:
                common_bindings = bindings  # type: ignore[assignment]
            elif bindings != common_bindings:
                raise ValueError("attestation artifacts mix directory or release identities")
            github = record.get("github_attestation")
            if not isinstance(github, dict) or (
                str(github.get("run_id")) != consent.get("run_id")
                or str(github.get("run_attempt")) != consent.get("run_attempt")
                or github.get("sha") != consent.get("catalog_sha")
                or github.get("challenge") != challenge
                or github.get("workflow") != "launch-evidence-e2e.yml"
                or github.get("job") != "protected-observer-inputs"
            ):
                raise ValueError(f"{name} contains a foreign GitHub run binding")
            tuple_value = record.get("tuple")
            if not isinstance(tuple_value, dict) or tuple_value.get("product_id") != plugin:
                raise ValueError(f"{name} contains a foreign release tuple")
            static_tuple = {key: value for key, value in tuple_value.items() if key not in {"client_version", "observed_at"}}
            previous = release_identities.setdefault(plugin, static_tuple)
            if static_tuple != previous:
                raise ValueError("attestation artifacts mix release tuple identities")
    if expected_bindings is not None:
        selected = {field: expected_bindings.get(field) for field in binding_fields}
        if common_bindings != selected:
            raise ValueError("attestation artifacts differ from the authorized request bindings")
