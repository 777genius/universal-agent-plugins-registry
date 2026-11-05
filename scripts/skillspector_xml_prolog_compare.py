#!/usr/bin/env python3
"""Pinned actual-CLI comparison of strict XML prolog evidence on real Skills."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from patch_skillspector_directory_refs_2133_canary import apply as patch_directory
from skillspector_named_version_compare import require_status, uncommitted_inputs
from skillspector_upgrade_compare import FIXTURES, input_fingerprint, scan, version

BASE = "018daa3afa2fa3ad084dda251fb562c5045cb423"
CANDIDATE = "604a1cff1249ec4023012be4bdb77eac20621893"
SOURCES = {
    "digital-marketing-pro": "cc45ca06eaf48abde3bb60fb79d31c41229c58db",
    "digitalmarketingpro-techshu": "e97a5bdd91601024a9cfa870807a8d3c81dc3caf",
}
CONTROLS = {
    "clean": FIXTURES["complete_control"],
    "missing_script": FIXTURES["true_missing_executable"],
    "uninspected_directory": FIXTURES["directory_uninspected"],
    "traversal": FIXTURES["traversal_reference"],
    "json_version": FIXTURES["json_version_literal"],
    "xml_prolog": (
        "---\nname: xml-prolog\ndescription: Document a sitemap.\n---\n"
        '```xml\n<?xml version="1.0" encoding="UTF-8"?>\n```\n'
    ),
    "named_version": (
        "---\nname: yaml-xml-combined\ndescription: Keep YAML metadata semantics.\nmetadata:\n"
        '  methodology-version: "3.1.0"\n---\nRead the complete report.\n'
    ),
    "xml_malformed": (
        "---\nname: xml-mismatch\ndescription: Preserve non-declaration evidence.\n---\n"
        "<?xml version='1.0' encoding='UTF-8'?>\n"
    ),
    "numbered_link": (
        "---\nname: numbered-link\ndescription: Missing version-shaped file.\n---\n"
        "Read [the versioned file](1.0).\n"
    ),
}


def git_revision(root: Path) -> str:
    """Attest pinned checkout HEAD and its exact tracked/untracked file state."""
    safe = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        env=safe, timeout=30, text=True,
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all", "--ignored=matching"],
        env=safe, timeout=30, text=True,
    ).strip()
    if dirty:
        raise AssertionError(("Pinned XML source checkout has local changes", root.name, dirty))
    return revision


def checked_skill_root(path: Path) -> Path:
    """Reject symlinks in the supplied Skill path before canonicalizing it."""
    original = path.absolute()
    if any(part.is_symlink() for part in (original, *original.parents)):
        raise AssertionError(("Symlinked Skill path", str(path)))
    root = original.resolve(strict=True)
    if not root.is_dir() or not (root / "SKILL.md").is_file():
        raise AssertionError(("Missing pinned Skill root", str(path)))
    return root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--digital", type=Path, required=True)
    parser.add_argument("--techshu", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    results: dict[str, dict] = {"old": {}, "new": {}}
    evidence = {
        "format": "uap.skillspector.xml-prolog-comparison.v1",
        "old_sha": BASE, "new_sha": CANDIDATE,
        "source_shas": SOURCES, "input_sha256": {},
        "versions": {},
        "cli_flags": ["--no-llm", "--format", "json", "--fail-on-incomplete"],
        "directory_inventory_patch": "uap-directory-inventory-v1",
        "production_changed": False, "results": results,
    }
    # Even checkout/version mismatch produces a deterministic failure artifact.
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    scanners = {"old": args.old.resolve(), "new": args.new.resolve()}
    old_root, new_root = (binary.parents[2] for binary in scanners.values())
    # Before running the editable CLI or patching source, verify both the
    # immutable revision and the entire importable src/ tree. uv's .venv is
    # intentionally out of scope; ignored code inside src/ is NOT.
    safe_git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    for label, root, expected in (("old", old_root, BASE), ("new", new_root, CANDIDATE)):
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            env=safe_git_env, text=True, timeout=30,
        ).strip()
        dirty = uncommitted_inputs(root, "src")
        if revision != expected or dirty:
            raise AssertionError(("Pinned XML scanner source changed", label, revision, dirty))
    versions = {name: version(binary) for name, binary in scanners.items()}
    if not all(item.endswith("v2.13.3") for item in versions.values()):
        raise AssertionError(("Scanner versions differ", versions))
    evidence["versions"] = versions
    patch_directory(old_root)
    patch_directory(new_root, expected_release=CANDIDATE, expected_blobs={
        "src/skillspector/references.py": "a80b1a5f77b1a74403d8c44a04af082fe5f19b8c",
        "src/skillspector/nodes/build_context.py": "174887b736d1d5940cd1cf04b235210290702960",
    })
    adapter = Path(__file__).with_name("patch_skillspector_directory_refs_2133_canary.py")
    for root in (old_root, new_root):
        subprocess.run(
            [str(root / ".venv/bin/python"), str(adapter), str(root), "--check-only"],
            check=True, timeout=60,
        )

    roots = {
        "digital-marketing-pro": checked_skill_root(args.digital),
        "digitalmarketingpro-techshu": checked_skill_root(args.techshu),
    }
    for name, root in roots.items():
        if git_revision(root.parents[1]) != SOURCES[name]:
            raise AssertionError(("Real source checkout changed", name))

    with tempfile.TemporaryDirectory(prefix="uap-xml-prolog-proof-") as tmp:
        work = Path(tmp)
        for name, body in CONTROLS.items():
            root = work / name
            root.mkdir()
            (root / "SKILL.md").write_text(body, encoding="utf-8")
            if name == "uninspected_directory":
                (root / "docs").mkdir()
                (root / "docs" / "guide.md").write_text("Inert documentation.\n", encoding="utf-8")
            roots[name] = root
        outside = work / "outside-runner.sh"
        marker = work / "outside-runner.marker"
        outside.write_text(f': > "{marker}"\n', encoding="utf-8")
        hashes = {name: input_fingerprint(root) for name, root in roots.items()}
        evidence["input_sha256"] = hashes
        outside_bytes = outside.read_bytes()
        try:
            for name, binary in scanners.items():
                for label, root in roots.items():
                    results[name][label] = scan(binary, root)
                    if input_fingerprint(root) != hashes[label]:
                        raise AssertionError(("Scanner mutated input", name, label))
                if outside.read_bytes() != outside_bytes:
                    raise AssertionError(("Scanner mutated external target", name))
                if marker.exists():
                    raise AssertionError(("Scanner executed external target", name))
                for label, root in roots.items():
                    if input_fingerprint(root) != hashes[label]:
                        raise AssertionError(("Scanner mutated another input", name, label))
        finally:
            args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(evidence, indent=2, sort_keys=True))
    for label in ("clean", "json_version"):
        for scanner in scanners:
            require_status(results[scanner][label], "complete", missing=False)
    for label in ("missing_script", "xml_malformed", "numbered_link"):
        for scanner in scanners:
            require_status(results[scanner][label], "partial", missing=True)
    for scanner in scanners:
        for key in ("traversal", "uninspected_directory"):
            row = results[scanner][key]
            if (row["status"] != "partial" or row["is_complete"]
                    or row["exit_code"] != 1
                    or not row["reason_counts"].get("referenced_uninspected")
                    or (key == "traversal" and row["rejected_partial_count"] < 1)):
                raise AssertionError(("Unsafe dependency incorrectly Complete", scanner, key, row))
    for label in ("xml_prolog", "named_version", *SOURCES):
        require_status(results["old"][label], "partial", missing=True)
        require_status(results["new"][label], "complete", missing=False)


if __name__ == "__main__":
    main()
