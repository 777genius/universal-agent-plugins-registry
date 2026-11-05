#!/usr/bin/env python3
"""Read-only actual-CLI comparison for strict named YAML version metadata."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from patch_skillspector_directory_refs_2133_canary import apply as patch_directory
from skillspector_upgrade_compare import FIXTURES, input_fingerprint, scan, version

SKILLS = (
    "braids", "braids-audit", "braids-claims", "braids-depth",
    "braids-help", "braids-review", "braids-risk",
)
BASE = "018daa3afa2fa3ad084dda251fb562c5045cb423"
CANDIDATE = "42366154e3c9520082ebc5f0bba9250641916aac"
SOURCE = "79c913e9d27854d88c7ee58aa9906bd2b45001b4"
CONTROLS = {
    "clean": FIXTURES["complete_control"],
    "true_missing": FIXTURES["true_missing_executable"],
    "directory": FIXTURES["directory_uninspected"],
    "traversal": FIXTURES["traversal_reference"],
    "json_version": FIXTURES["json_version_literal"],
    "typed_field": FIXTURES["typed_data_field"],
    "named_version": (
        "---\nname: metadata\ndescription: Version metadata proof.\nmetadata:\n"
        '  methodology-version: "3.1.0"\n---\nExplain the result.\n'
    ),
    "other_key": (
        "---\nname: other-key\ndescription: Missing literal proof.\nmetadata:\n"
        '  some-other-key: "3.1.0"\n---\nExplain the result.\n'
    ),
    "version_link": (
        "---\nname: version-link\ndescription: Missing filename proof.\nmetadata:\n"
        '  methodology-version: "3.1.0"\n---\nRead [version file](3.1.0).\n'
    ),
}


# Exact pinned SkillSpector v2.13.3 constant: risk above this threshold
# independently causes CLI exit 1 even when inspection coverage is Complete.
RISK_THRESHOLD = 50


def require_status(
    row: dict, status: str, *, missing: bool, allow_risk_exit: bool = False
) -> None:
    expected_exit = 0 if status == "complete" else 1
    exit_ok = row["exit_code"] == expected_exit
    if allow_risk_exit and status == "complete" and row["exit_code"] == 1:
        # Never discard or relabel content findings. Only allow an actual
        # high-risk score to explain an otherwise fully inspected CLI result.
        exit_ok = row["risk_score"] > RISK_THRESHOLD and row["finding_count"] > 0
    if not (
        row["status"] == status
        and row["is_complete"] == (status == "complete")
        and exit_ok
        and bool(row["missing_reference_count"]) == missing
    ):
        raise AssertionError(("Unexpected completeness result", status, missing, row))



def source_revision(checkout: Path) -> str:
    """Verify that a pinned checkout has no modified, untracked OR ignored inputs."""
    safe_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        env=safe_env, text=True, timeout=30,
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(checkout), "status", "--porcelain",
         "--untracked-files=all", "--ignored=matching"],
        env=safe_env, text=True, timeout=30,
    ).strip()
    if dirty:
        raise AssertionError(("Pinned Braids checkout has untracked or modified inputs", dirty))
    return revision


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", required=True, type=Path)
    parser.add_argument("--new", required=True, type=Path)
    parser.add_argument("--real-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    results: dict[str, dict] = {"old": {}, "new": {}}
    evidence = {
        "format": "uap.skillspector.named-version-comparison.v1",
        "base_sha": BASE,
        "candidate_sha": CANDIDATE,
        "pinned_source_sha": SOURCE,
        "scanner_versions": {},
        "inputs": {},
        "cli_flags": ["--no-llm", "--format", "json", "--fail-on-incomplete"],
        "directory_inventory_patch": "uap-directory-inventory-v1",
        "production_changed": False,
        "results": results,
    }
    # Preserve a non-success evidence envelope even if version, SHA, patch,
    # source or fixture checks abort before any CLI measurement is available.
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    scanners = {"old": args.old.resolve(), "new": args.new.resolve()}
    roots = {name: binary.parents[2] for name, binary in scanners.items()}
    versions = {k: version(binary) for k, binary in scanners.items()}
    if not all(v.endswith("v2.13.3") for v in versions.values()):
        raise AssertionError(("Scanner release differs", versions))
    evidence["scanner_versions"] = versions

    # Match production's conservative directory-inventory semantics on BOTH
    # candidates; verify full commit + pre-patch module blobs before writing.
    patch_directory(roots["old"])
    patch_directory(roots["new"], expected_release=CANDIDATE, expected_blobs={
        "src/skillspector/references.py": "425a29f4f969a90eaabf9e817f60826eb2084ccb",
        "src/skillspector/nodes/build_context.py": "174887b736d1d5940cd1cf04b235210290702960",
    })
    adapter = Path(__file__).with_name("patch_skillspector_directory_refs_2133_canary.py")
    for root in roots.values():
        subprocess.run([str(root / ".venv/bin/python"), str(adapter), str(root), "--check-only"],
                       timeout=60, check=True)

    source_checkout = args.real_root.resolve().parent
    source_commit = source_revision(source_checkout)
    if source_commit != SOURCE:
        raise AssertionError(("Unexpected immutable Braids source SHA", source_commit))
    with tempfile.TemporaryDirectory(prefix="uap-named-version-") as temp:
        inputs = Path(temp)
        roots = {}
        for name, body in CONTROLS.items():
            root = inputs / name
            root.mkdir()
            (root / "SKILL.md").write_text(body, encoding="utf-8")
            if name == "directory":
                (root / "docs").mkdir()
                (root / "docs" / "guide.md").write_text("Inert directory evidence.\n", encoding="utf-8")
            roots[name] = root
        outside = inputs / "outside-runner.sh"
        outside.write_text("Inert out-of-bundle fixture.\n", encoding="utf-8")
        for skill in SKILLS:
            root = args.real_root.resolve() / skill
            if root.is_symlink() or not root.is_dir() or not (root / "SKILL.md").is_file():
                raise AssertionError(("Missing pinned Skill", skill))
            roots["real/" + skill] = root
        fingerprints = {name: input_fingerprint(root) for name, root in roots.items()}
        evidence["inputs"] = fingerprints
        outside_bytes = outside.read_bytes()
        try:
            for name, binary in scanners.items():
                for label, root in roots.items():
                    results[name][label] = scan(binary, root)
                    if input_fingerprint(root) != fingerprints[label]:
                        raise AssertionError(("Scanner mutated pinned input", name, label))
                if outside.read_bytes() != outside_bytes:
                    raise AssertionError(("Scanner mutated outside fixture", name))
        finally:
            args.out.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(evidence, sort_keys=True, indent=2))
    for label in ("clean", "json_version"):
        for scanner in scanners:
            require_status(results[scanner][label], "complete", missing=False)
    for label in ("true_missing", "typed_field", "other_key", "version_link"):
        for scanner in scanners:
            require_status(results[scanner][label], "partial", missing=True)
    for scanner in scanners:
        directory = results[scanner]["directory"]
        if (directory["status"] != "partial" or directory["is_complete"]
                or directory["exit_code"] != 1
                or directory["missing_reference_count"] != 0
                or not directory["reason_counts"].get("referenced_uninspected")):
            raise AssertionError(("Directory incorrectly marked Complete", scanner, directory))
        traversal = results[scanner]["traversal"]
        if not (
            traversal["status"] == "partial"
            and not traversal["is_complete"]
            and traversal["exit_code"] == 1
            and traversal["rejected_partial_count"] >= 1
            and traversal["reason_counts"].get("referenced_uninspected")
        ):
            raise AssertionError(("False Complete on traversal", scanner, traversal))
    for label in ("named_version", *("real/" + name for name in SKILLS)):
        old, new = results["old"][label], results["new"][label]
        require_status(old, "partial", missing=True)
        require_status(
            new, "complete", missing=False, allow_risk_exit=label.startswith("real/")
        )
        if label.startswith("real/") and (
            old["risk_score"] != new["risk_score"]
            or old["finding_count"] != new["finding_count"]
            or old["finding_rules"] != new["finding_rules"]
        ):
            raise AssertionError(("Risk findings changed while correcting coverage", label, old, new))
        if not old["reason_counts"].get("reference_missing"):
            raise AssertionError(("Baseline missing reference not reproduced", label, old))


if __name__ == "__main__":
    main()
