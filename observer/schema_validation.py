"""Validation against the reviewed repository evidence schemas."""

from __future__ import annotations

import json
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
