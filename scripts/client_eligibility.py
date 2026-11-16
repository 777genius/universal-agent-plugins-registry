"""Capability-derived Directory client targets without author opt-in.

A derived target is computed from immutable release metadata, the
digest-pinned released client capability contract, verified package facts and
positive evidence bound to the exact release. Explicit denials, non-active
distributions and policies, unpinned sources, failed evidence and unresolved
dependencies always win. Derivation never signs, publishes or relaxes any
signature, source, ledger, sequence, rollback, revocation or expiry check.

This module is deliberately dependency-free so that unsigned review tooling
and the registry validator share one implementation.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Callable, Iterable, Mapping

# Clients whose Directory targets are derived instead of authored, with the
# first public installer release qualified to materialize them.
PI_MINIMUM_INSTALLER_VERSION = "0.1.102"
DERIVED_CLIENT_MINIMUM_INSTALLER = {"pi": PI_MINIMUM_INSTALLER_VERSION}
# The owner's Pi scope is portable Skills and MCP. Other component kinds stay
# authored until their client mapping is reviewed separately.
DERIVABLE_COMPONENTS = frozenset({"skills", "mcp"})
# Positive evidence must cover every supported desktop OS family.
REQUIRED_EVIDENCE_OS = ("linux", "macos", "windows")
TRUSTED_EVIDENCE_KINDS = frozenset({"github_actions", "reviewed_external"})
# Matches the resolver: these trusted failures block a release for a client.
BLOCKING_FAILURE_LEVELS = frozenset({"materialization", "discovery", "runtime"})
KNOWN_AUTHENTICATION = frozenset({"required", "not_required"})
MARKETING_KIT = "777genius/marketing-kit"
# Reviewed exclusions. A denial beats capability and evidence, and covers every
# release of the distribution until an editor removes it in review.
EXPLICIT_DENIALS: Mapping[tuple[str, str], str] = {
    ("pi", MARKETING_KIT): (
        "released CLI 0.1.102 refuses its saved dependency closure through "
        "777genius/hubspot-crm in user and project scope (70/72 in #451); "
        "excluded, not repaired"
    ),
}
DERIVED = "derived"
EXPLICIT = "explicit"
EXCLUDED = "excluded"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Same form as the distribution schema's minimum_installer_version.
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

FactsProvider = Callable[[dict, dict, dict], "Mapping[str, Any] | None"]


class EligibilityError(ValueError):
    """Derivation inputs violate the eligibility contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EligibilityError(message)


def installer_version(value: object) -> tuple[int, int, int]:
    require(isinstance(value, str) and VERSION_RE.fullmatch(value) is not None,
            f"invalid installer version {value!r}")
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def derived_client_minimum(client: str) -> str:
    require(client in DERIVED_CLIENT_MINIMUM_INSTALLER,
            f"{client!r} is not a capability-derived Directory client")
    return DERIVED_CLIENT_MINIMUM_INSTALLER[client]


def explicit_denial(client: str, distribution_id: str) -> str | None:
    return EXPLICIT_DENIALS.get((client, distribution_id))


def binds_positive_materialization(
    observation: Mapping[str, Any], distribution: Mapping[str, Any],
    release: Mapping[str, Any], minimum_installer_version: str,
) -> bool:
    """Whether one observation is passed materialization of these exact bytes."""
    internal_identity = {
        "manifest_digest": release["manifest_digest"],
        "source_repository": release["package_source"]["repository"],
        "source_revision": release["package_source"]["revision"],
        "source_path": release["package_source"]["path"],
    }
    present = internal_identity.keys() & observation.keys()
    if present:
        # Source-registry evidence is the stronger internal form. Never
        # accept a partial tuple or silently downgrade it to wire evidence.
        bound = present == internal_identity.keys() and all(
            observation.get(field) == value for field, value in internal_identity.items()
        )
    else:
        # Signed public snapshots intentionally omit the internal source tuple.
        # Their wire evidence remains release-bound by the signed distribution,
        # sequence and package tree digest, matching the released CLI contract.
        trust = observation.get("trust")
        artifact = observation.get("artifact")
        bound = isinstance(trust, dict) and (
            trust == {"kind": "reviewed_external"}
            or (
                trust.keys() == {"kind", "workflow", "source_ref", "source_digest"}
                and trust.get("kind") == "github_actions"
                and isinstance(artifact, dict)
                and trust.get("source_digest") == artifact.get("revision")
            )
        )
    return (
        bound
        and observation.get("distribution_id") == distribution["id"]
        and observation.get("release_sequence") == release["sequence"]
        and observation.get("package_tree_digest") == release["tree_digest"]
        and observation.get("installer_version") == minimum_installer_version
        and observation.get("level") == "materialization"
        and observation.get("outcome") == "passed"
    )


def blocking_client_failures(
    client: str, distribution: Mapping[str, Any], release: Mapping[str, Any],
    observations: Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """Failed observations for these bytes; binding is intentionally broad."""
    return [
        observation for observation in observations
        if observation.get("client") == client
        and observation.get("distribution_id") == distribution["id"]
        and observation.get("release_sequence") == release["sequence"]
        and observation.get("package_tree_digest") == release["tree_digest"]
        and observation.get("level") in BLOCKING_FAILURE_LEVELS
        and observation.get("outcome") == "failed"
    ]


def positive_client_evidence(
    client: str, distribution: Mapping[str, Any], release: Mapping[str, Any],
    minimum_installer_version: str, observations: Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    return [
        observation for observation in observations
        if observation.get("client") == client
        and isinstance(observation.get("trust"), dict)
        and observation["trust"].get("kind") in TRUSTED_EVIDENCE_KINDS
        and binds_positive_materialization(
            observation, distribution, release, minimum_installer_version,
        )
    ]


def client_target_gate(
    client: str, distribution: Mapping[str, Any], release: Mapping[str, Any],
    policy: Mapping[str, Any], current: Iterable[Mapping[str, Any]],
    known: Iterable[Mapping[str, Any]],
) -> str | None:
    """Return why a derived-client target is inadmissible, or None.

    Positive evidence must be among the policy's ``current`` observations;
    a failure anywhere in ``known`` evidence still blocks. The registry
    validator applies this to every active derived-client target, including
    hand-written ones, so author opt-in cannot bypass evidence.
    """
    minimum = derived_client_minimum(client)
    denial = explicit_denial(client, distribution["id"])
    if denial is not None:
        return f"explicit {client} denial: {denial}"
    if installer_version(policy["minimum_installer_version"]) < installer_version(minimum):
        return (f"policy minimum installer {policy['minimum_installer_version']} is below "
                f"the qualified {client} installer {minimum}")
    failures = blocking_client_failures(client, distribution, release, [*current, *known])
    if failures:
        levels = ",".join(sorted({str(item.get("level")) for item in failures}))
        return f"trusted failed {client} evidence ({levels}) blocks this release"
    positives = positive_client_evidence(
        client, distribution, release, policy["minimum_installer_version"], current,
    )
    covered = {observation.get("os") for observation in positives}
    missing = [name for name in REQUIRED_EVIDENCE_OS if name not in covered]
    if missing:
        return (f"lacks trusted passed {client} materialization evidence at installer "
                f"{policy['minimum_installer_version']} for os: {','.join(missing)}")
    return None


def _native_capability(client: str, capability: Mapping[str, Any]) -> None:
    require(isinstance(capability, Mapping) and capability.get("id") == client,
            f"{client}: released capability row is missing")
    require(capability.get("excluded_reason") == "",
            f"{client}: released capability contract excludes this client")
    require(capability.get("package_mode") == "native",
            f"{client}: derived managed delivery requires a native package mode")
    require(isinstance(capability.get("mcp_transports"), Mapping),
            f"{client}: released capability has no MCP transport map")


def capability_incompatibility(
    client: str, capability: Mapping[str, Any], components: Iterable[str],
    facts: Mapping[str, Any],
) -> str | None:
    """Compare package facts with the client's released user-scope capability."""
    components = set(components)
    if "skills" in components and capability.get("skill_support") != "native":
        return f"skills are {capability.get('skill_support')!r} for {client}, not native"
    transports = facts["mcp_transports"]
    if "mcp" in components:
        if not transports:
            return "MCP component declares no transport"
        for transport in transports:
            support = capability["mcp_transports"].get(transport, "unsupported")
            if support != "native":
                return f"MCP transport {transport} is {support!r} for {client}"
    elif transports:
        return "package declares MCP servers outside its release components"
    if facts["dependencies"] and capability.get("saved_dependency") is not True:
        return f"{client} cannot install saved package dependencies"
    return None


def _validated_facts(facts: object, label: str) -> Mapping[str, Any]:
    require(isinstance(facts, Mapping) and set(facts) == {"mcp_transports", "dependencies"},
            f"{label}: package facts must contain exactly mcp_transports and dependencies")
    transports = facts["mcp_transports"]
    dependencies = facts["dependencies"]
    require(isinstance(transports, list) and all(isinstance(item, str) for item in transports),
            f"{label}: MCP transports must be strings")
    require(isinstance(dependencies, Mapping) and all(
        isinstance(key, str) and isinstance(value, str) for key, value in dependencies.items()
    ), f"{label}: dependencies must map distribution IDs to exact versions")
    return facts


def derive_client_targets(
    source: Mapping[str, Any], client: str, capability: Mapping[str, Any],
    facts_for: FactsProvider, *, client_order: Iterable[str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return a derived candidate copy and one decision per release.

    The input is never mutated. Callers must validate the result with the
    ordinary Directory validator before staging or publication.
    """
    minimum = derived_client_minimum(client)
    _native_capability(client, capability)
    if client_order is None:
        from client_contract import load_client_ids
        client_order = load_client_ids()
    order = tuple(client_order)
    require(client in order, f"{client}: not in the released client order")
    products = {item["id"]: item for item in source["products"]}
    distributions = {item["id"]: item for item in source["distributions"]}
    observations = [item for item in source["evidence"] if item.get("client") == client]
    results: dict[tuple[str, int], dict[str, Any]] = {}
    pending: set[tuple[str, int]] = set()

    def excluded(reason: str) -> dict[str, Any]:
        return {"outcome": EXCLUDED, "reason": reason}

    def evaluate(distribution: Mapping[str, Any], release: Mapping[str, Any]) -> dict[str, Any]:
        key = (distribution["id"], release["sequence"])
        if key in results:
            return results[key]
        if key in pending:
            return excluded("dependency cycle")
        pending.add(key)
        try:
            outcome = evaluate_release(distribution, release)
        finally:
            pending.discard(key)
        results[key] = outcome
        return outcome

    def evaluate_release(distribution: Mapping[str, Any], release: Mapping[str, Any]) -> dict[str, Any]:
        label = f"{distribution['id']}@{release['sequence']}"
        policies = [item for item in distribution["release_policies"]
                    if item["release_sequence"] == release["sequence"]]
        require(len(policies) == 1, f"{label}: release must have exactly one policy")
        policy = policies[0]
        if distribution["status"] != "active":
            return excluded(f"distribution is {distribution['status']}")
        if policy["status"] != "active":
            return excluded(f"release policy is {policy['status']}")
        denial = explicit_denial(client, distribution["id"])
        if any(target["client"] == client for target in policy["targets"]):
            require(denial is None, f"{label}: explicit {client} target conflicts with its denial")
            return {"outcome": EXPLICIT, "reason": f"authored {client} target is kept and validated"}
        if denial is not None:
            return excluded(f"explicit {client} denial: {denial}")
        product = products[distribution["product_id"]]
        required = {name for name, state in product["minimum_capabilities"].items() if state == "required"}
        if not required.issubset(release["components"]):
            return excluded("release misses product-required components")
        extra = sorted(set(release["components"]) - DERIVABLE_COMPONENTS)
        if extra:
            return excluded(f"component kinds {','.join(extra)} are not derived for {client}")
        revision = release["package_source"]["revision"]
        if not isinstance(revision, str) or SHA_RE.fullmatch(revision) is None:
            return excluded("unresolved source revision cannot bind exact-release evidence")
        authentication = {target["authentication"] for target in policy["targets"]}
        if len(authentication) != 1 or not authentication <= KNOWN_AUTHENTICATION:
            return excluded("existing targets do not share one known authentication requirement")
        derived_minimum = max(policy["minimum_installer_version"], minimum, key=installer_version)
        if derived_minimum != policy["minimum_installer_version"] and policy["current_evidence"]:
            return excluded(
                f"raising the policy minimum installer to {derived_minimum} would orphan "
                "existing exact-version evidence; requalify every target first",
            )
        positives = positive_client_evidence(client, distribution, release, derived_minimum, observations)
        prospective = {
            **policy, "minimum_installer_version": derived_minimum,
            "current_evidence": sorted({*policy["current_evidence"], *(item["id"] for item in positives)}),
        }
        reason = client_target_gate(client, distribution, release, prospective, positives, observations)
        if reason is not None:
            return excluded(reason)
        facts = facts_for(dict(distribution), dict(release), dict(policy))
        if facts is None:
            return excluded("verified package facts are unavailable")
        facts = _validated_facts(facts, label)
        reason = capability_incompatibility(client, capability, release["components"], facts)
        if reason is not None:
            return excluded(reason)
        for dependency_id, version in sorted(facts["dependencies"].items()):
            dependency = distributions.get(dependency_id)
            if dependency is None:
                return excluded(f"dependency {dependency_id} is not in the Directory")
            matches = [item for item in dependency["releases"] if item["package_version"] == version]
            if len(matches) != 1:
                return excluded(f"dependency {dependency_id}@{version} does not resolve to one release")
            resolved = evaluate(dependency, matches[0])
            if resolved["outcome"] not in {DERIVED, EXPLICIT}:
                return excluded(
                    f"dependency {dependency_id}@{version} is not {client}-eligible: {resolved['reason']}",
                )
        return {
            "outcome": DERIVED, "reason": "capability-compatible with positive exact-release evidence",
            "target": {
                "client": client, "scopes": ["user"], "delivery": "managed",
                "authentication": authentication.pop(),
            },
            "policy": prospective,
        }

    for distribution in sorted(source["distributions"], key=lambda item: item["id"]):
        for release in sorted(distribution["releases"], key=lambda item: item["sequence"]):
            evaluate(distribution, release)

    candidate = copy.deepcopy(dict(source))
    for distribution in candidate["distributions"]:
        for policy in distribution["release_policies"]:
            decision = results[(distribution["id"], policy["release_sequence"])]
            if decision["outcome"] != DERIVED:
                continue
            targets = [*policy["targets"], dict(decision["target"])]
            require(all(target["client"] in order for target in targets),
                    f"{distribution['id']}: unknown client target")
            policy["targets"] = sorted(targets, key=lambda target: order.index(target["client"]))
            policy["current_evidence"] = list(decision["policy"]["current_evidence"])
            policy["minimum_installer_version"] = decision["policy"]["minimum_installer_version"]
    decisions = [
        {"client": client, "distribution_id": key[0], "release_sequence": key[1],
         "outcome": value["outcome"], "reason": value["reason"]}
        for key, value in sorted(results.items())
    ]
    return candidate, decisions
