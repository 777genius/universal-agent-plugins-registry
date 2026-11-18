"""Read-only v2 proof of semantic finding parity for bounded SkillSpector cohorts.

This does not rewrite or reinterpret the already-signed v1 comparison bits.
Generated per-run finding IDs are correlation handles, not security evidence;
all other data, including fingerprints, snippets, positions, rules and severity,
are compared byte-for-byte after canonical JSON encoding.

A successful result proves ONLY finding parity for these two records; it is not
source-acquisition proof, coverage completeness, or publication authorization.
"""
from __future__ import annotations

from collections import Counter
import copy
import json
import re

_EPHEMERAL_ID = re.compile(r"finding-[0-9a-f]{32}\Z")


class EvidenceRejected(ValueError):
    """Finding-equivalence proof is absent or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceRejected(message)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def _fully_represented(record: dict) -> Counter[str]:
    require(isinstance(record, dict) and isinstance(record.get("findings"), list),
            "missing finding groups")
    coverage = record.get("coverage")
    require(isinstance(coverage, dict)
            and coverage.get("grouping_complete") is True
            and record.get("findings_truncated") is False
            and coverage.get("reference_evidence_truncated") is False,
            "finding grouping or evidence truncated")
    for key in ("finding_group_count", "finding_count", "raw_finding_count"):
        require(type(record.get(key)) is int and record[key] >= 0,
                "missing or malformed finding count")
    require(record["finding_group_count"] == len(record["findings"])
            and record["raw_finding_count"] >= record["finding_count"]
            >= record["finding_group_count"], "finding counters inconsistent")

    seen_ids: set[str] = set()
    groups: Counter[str] = Counter()
    total_occurrences = 0
    for group in record["findings"]:
        require(isinstance(group, dict) and isinstance(group.get("finding_ids"), list)
                and isinstance(group.get("occurrences"), list),
                "missing group correlation ledger")
        ids = group["finding_ids"]
        occurrences = group["occurrences"]
        require(ids and len(ids) == len(occurrences),
                "inconsistent group occurrence count")
        require(all(isinstance(i, str) and _EPHEMERAL_ID.fullmatch(i) for i in ids)
                and len(set(ids)) == len(ids)
                and not (set(ids) & seen_ids),
                "non-generated, duplicated, or reused finding IDs")
        require(all(isinstance(o, dict) and isinstance(o.get("finding_id"), str)
                    for o in occurrences), "missing occurrence correlation ID")
        require(Counter(ids) == Counter(o["finding_id"] for o in occurrences),
                "group-to-occurrence ID membership differs")
        seen_ids.update(ids)
        stripped = copy.deepcopy(group)
        del stripped["finding_ids"]
        for occurrence in stripped["occurrences"]:
            del occurrence["finding_id"]
        groups[_canonical(stripped)] += 1
        total_occurrences += len(occurrences)
    require(total_occurrences == record["finding_count"],
            "content finding count differs from occurrence ledger")
    # Raw findings may additionally include coverage-only findings (e.g. AE1).
    # We do NOT infer their parity from this function.
    return groups


def compare_findings_v2(old: dict, candidate: dict) -> dict:
    """Strict evidence comparison; cannot certify or publish a source."""
    require(isinstance(old, dict) and isinstance(candidate, dict)
            and old.get("id") == candidate.get("id")
            and isinstance(old.get("id"), str) and bool(old["id"]),
            "different source record identity")
    for key in ("finding_group_count", "finding_count", "raw_finding_count"):
        require(old.get(key) == candidate.get(key), f"{key} changed")
    before = _fully_represented(old)
    after = _fully_represented(candidate)
    require(before == after, "independent security evidence changed")
    return {
        "schema_version": 2,
        "kind": "skillspector-finding-parity-read-only",
        "id": old["id"],
        "finding_group_count": old["finding_group_count"],
        "finding_count": old["finding_count"],
        "raw_finding_count": old["raw_finding_count"],
        "semantic_findings_unchanged": True,
        "coverage_only_raw_findings_verified": False,
        "source_identity_verified": False,
        "scanner_coverage_verified": False,
        "publication_authorized": False,
        "production_partial_reduction": 0,
        "certified_complete": False,
    }
