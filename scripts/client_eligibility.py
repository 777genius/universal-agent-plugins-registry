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
# excluded until their client mapping is reviewed separately.
DERIVABLE_COMPONENTS = frozenset({"skills", "mcp"})
# Positive evidence must cover every supported desktop OS family.
REQUIRED_EVIDENCE_OS = ("linux", "macos", "windows")
TRUSTED_EVIDENCE_KINDS = frozenset({"github_actions", "reviewed_external"})
# The resolver's blocking levels. Unlike the resolver, any failed observation
# for these bytes blocks, whatever its installer, trust or policy pointer.
BLOCKING_FAILURE_LEVELS = frozenset({"materialization", "discovery", "runtime"})
KNOWN_AUTHENTICATION = frozenset({"required", "not_required"})
# Fields that make two observations the same applicability tuple; the
# validator admits only one current pointer per tuple.
APPLICABILITY_FIELDS = (
    "level", "client", "dependency_identity", "client_version",
    "installer_version", "adapter_version", "os", "architecture",
)
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
FACT_FIELDS = frozenset({"mcp_transports", "dependencies", "unsupported_requirements"})

FactsProvider = Callable[[dict, dict, dict], "Mapping[str, Any] | None"]
TrustCheck = Callable[[Mapping[str, Any]], bool]


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


def expected_target(client: str, authentication: str) -> dict[str, Any]:
    return {"client": client, "scopes": ["user"], "delivery": "managed",
            "authentication": authentication}


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
    trust_check: TrustCheck | None = None,
) -> list[Mapping[str, Any]]:
    """Trusted passed materialization of the exact bytes at the policy floor.

    ``trust_check`` lets publication-aware callers also require the signer's
    workflow/artifact allowlist instead of only a declared trust kind.
    """
    return [
        observation for observation in observations
        if observation.get("client") == client
        and isinstance(observation.get("trust"), dict)
        and observation["trust"].get("kind") in TRUSTED_EVIDENCE_KINDS
        and binds_positive_materialization(
            observation, distribution, release, minimum_installer_version,
        )
        and (trust_check is None or trust_check(observation))
    ]


def one_per_applicability(observations: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Keep the newest observation per tuple, so a rerun cannot void a release."""
    selected: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    for observation in observations:
        key = tuple(observation.get(field) for field in APPLICABILITY_FIELDS)
        rank = (str(observation.get("observed_at", "")), str(observation.get("id", "")))
        current = selected.get(key)
        if current is None or rank > (str(current.get("observed_at", "")), str(current.get("id", ""))):
            selected[key] = observation
    return list(selected.values())


def client_target_gate(
    client: str, distribution: Mapping[str, Any], release: Mapping[str, Any],
    policy: Mapping[str, Any], current: Iterable[Mapping[str, Any]],
    known: Iterable[Mapping[str, Any]], trust_check: TrustCheck | None = None,
) -> str | None:
    """Return why the denial/installer/evidence gate rejects a target, or None.

    Positive evidence must be among the policy's ``current`` observations;
    a failure anywhere in ``known`` evidence still blocks.
    """
    current = list(current)
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
        return f"failed {client} evidence ({levels}) for these bytes blocks this release"
    positives = positive_client_evidence(
        client, distribution, release, policy["minimum_installer_version"], current, trust_check,
    )
    covered = {observation.get("os") for observation in positives}
    missing = [name for name in REQUIRED_EVIDENCE_OS if name not in covered]
    if missing:
        return (f"lacks trusted passed {client} materialization evidence at installer "
                f"{policy['minimum_installer_version']} for os: {','.join(missing)}")
    return None


def release_shape(
    client: str, product: Mapping[str, Any], release: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    """Byte-free checks; returns (reason, authentication for the client target)."""
    required = {name for name, state in product["minimum_capabilities"].items() if state == "required"}
    if not required.issubset(release["components"]):
        return "release misses product-required components", None
    extra = sorted(set(release["components"]) - DERIVABLE_COMPONENTS)
    if extra:
        return f"component kinds {','.join(extra)} are not derived for {client}", None
    revision = release["package_source"]["revision"]
    if not isinstance(revision, str) or SHA_RE.fullmatch(revision) is None:
        return "unresolved source revision cannot bind exact-release evidence", None
    # Pending owner confirmation: authentication is treated as a package
    # property shared by every target; unknown or mixed values never qualify.
    authentication = {
        target["authentication"] for target in policy["targets"] if target["client"] != client
    }
    if len(authentication) != 1 or not authentication <= KNOWN_AUTHENTICATION:
        return "existing targets do not share one known authentication requirement", None
    return None, next(iter(authentication))


def admitted_target_reason(
    client: str, product: Mapping[str, Any], distribution: Mapping[str, Any],
    release: Mapping[str, Any], policy: Mapping[str, Any],
    current: Iterable[Mapping[str, Any]], known: Iterable[Mapping[str, Any]],
    trust_check: TrustCheck | None = None,
) -> str | None:
    """Validator gate for a present client target, authored or derived.

    Package-byte checks (transports and dependencies) need acquisition and
    run during derivation; everything else is enforced here as well.
    """
    denial = explicit_denial(client, distribution["id"])
    if denial is not None:
        return f"explicit {client} denial: {denial}"
    reason, authentication = release_shape(client, product, release, policy)
    if reason is not None:
        return reason
    expected = expected_target(client, authentication)
    if [target for target in policy["targets"] if target["client"] == client] != [expected]:
        return f"target must be exactly {expected}"
    return client_target_gate(client, distribution, release, policy, current, known, trust_check)


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
    if facts["unsupported_requirements"]:
        return ("uap.toml requirement forms are not derivable: "
                + ",".join(facts["unsupported_requirements"]))
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
    require(isinstance(facts, Mapping) and set(facts) == FACT_FIELDS,
            f"{label}: package facts must contain exactly {sorted(FACT_FIELDS)}")
    transports = facts["mcp_transports"]
    dependencies = facts["dependencies"]
    unsupported = facts["unsupported_requirements"]
    require(isinstance(transports, list) and all(isinstance(item, str) for item in transports),
            f"{label}: MCP transports must be strings")
    require(isinstance(dependencies, Mapping) and all(
        isinstance(key, str) and isinstance(value, str) for key, value in dependencies.items()
    ), f"{label}: dependencies must map distribution IDs to exact versions")
    require(isinstance(unsupported, list) and all(isinstance(item, str) for item in unsupported),
            f"{label}: unsupported requirements must be strings")
    return facts


def derive_client_targets(
    source: Mapping[str, Any], client: str, capability: Mapping[str, Any],
    facts_for: FactsProvider, *, client_order: Iterable[str] | None = None,
    trust_check: TrustCheck | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return a derived candidate copy and one decision per release.

    The input is never mutated. An authored client target must pass the same
    checks and equal its derived form; otherwise derivation fails closed.
    Callers must validate the result with the ordinary Directory validator.
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
    evidence_by_id = {item["id"]: item for item in source["evidence"]}
    observations = [item for item in source["evidence"] if item.get("client") == client]
    results: dict[tuple[str, int], dict[str, Any]] = {}
    pending: set[tuple[str, int]] = set()

    def excluded(reason: str) -> dict[str, Any]:
        return {"outcome": EXCLUDED, "reason": reason}

    def policy_for(distribution: Mapping[str, Any], release: Mapping[str, Any]) -> Mapping[str, Any]:
        policies = [item for item in distribution["release_policies"]
                    if item["release_sequence"] == release["sequence"]]
        require(len(policies) == 1,
                f"{distribution['id']}@{release['sequence']}: release must have exactly one policy")
        return policies[0]

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
        policy = policy_for(distribution, release)
        if distribution["status"] != "active":
            return excluded(f"distribution is {distribution['status']}")
        if policy["status"] != "active":
            return excluded(f"release policy is {policy['status']}")
        authored = any(target["client"] == client for target in policy["targets"])
        outcome = qualify(distribution, release, policy, authored)
        if not authored:
            return outcome
        # An authored target is never trusted alone and never a dependency
        # shortcut: it must survive every derivation check unchanged.
        require(outcome["outcome"] == DERIVED,
                f"{label}: authored {client} target is inadmissible: {outcome['reason']}")
        return {"outcome": EXPLICIT, "reason": f"authored {client} target equals its derived form"}

    def qualify(distribution: Mapping[str, Any], release: Mapping[str, Any],
                policy: Mapping[str, Any], authored: bool) -> dict[str, Any]:
        label = f"{distribution['id']}@{release['sequence']}"
        product = products[distribution["product_id"]]
        if authored:
            current = [evidence_by_id[item] for item in policy["current_evidence"] if item in evidence_by_id]
            reason = admitted_target_reason(
                client, product, distribution, release, policy, current, observations, trust_check,
            )
            if reason is not None:
                return excluded(reason)
            prospective = policy
            target = next(item for item in policy["targets"] if item["client"] == client)
        else:
            denial = explicit_denial(client, distribution["id"])
            if denial is not None:
                return excluded(f"explicit {client} denial: {denial}")
            reason, authentication = release_shape(client, product, release, policy)
            if reason is not None:
                return excluded(reason)
            floor = max(policy["minimum_installer_version"], minimum, key=installer_version)
            if floor != policy["minimum_installer_version"] and policy["current_evidence"]:
                return excluded(
                    f"raising the policy minimum installer to {floor} would orphan "
                    "existing exact-version evidence; requalify every target first",
                )
            positives = one_per_applicability(positive_client_evidence(
                client, distribution, release, floor, observations, trust_check,
            ))
            prospective = {
                **policy, "minimum_installer_version": floor,
                "current_evidence": sorted({*policy["current_evidence"], *(item["id"] for item in positives)}),
            }
            reason = client_target_gate(
                client, distribution, release, prospective, positives, observations, trust_check,
            )
            if reason is not None:
                return excluded(reason)
            target = expected_target(client, authentication)
        facts = facts_for(dict(distribution), dict(release), dict(prospective))
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
            if dependency["status"] != "active":
                return excluded(f"dependency {dependency_id} is {dependency['status']}")
            # Like the installer, consider only installable releases of that version.
            matches = [
                item for item in dependency["releases"]
                if item["package_version"] == version
                and policy_for(dependency, item)["status"] == "active"
            ]
            if len(matches) != 1:
                return excluded(f"dependency {dependency_id}@{version} does not resolve to one active release")
            resolved = evaluate(dependency, matches[0])
            if resolved["outcome"] not in {DERIVED, EXPLICIT}:
                return excluded(
                    f"dependency {dependency_id}@{version} is not {client}-eligible: {resolved['reason']}",
                )
        return {
            "outcome": DERIVED, "reason": "capability-compatible with positive exact-release evidence",
            "target": target, "policy": prospective,
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
