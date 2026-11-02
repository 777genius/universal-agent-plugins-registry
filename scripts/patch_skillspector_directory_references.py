#!/usr/bin/env python3
"""Scoped v2.13.1 maintenance patch: preserve directory evidence from bounded inventory.

This modifies *only* the immutable scanner checkout on the ephemeral CI runner.
The upstream revision and locked dependencies stay unchanged. The v3 scan profile
carries a distinct patch identity so historical reports cannot impersonate new
evidence. Remove this patch when a compatible upstream release is qualified.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

UPSTREAM_SHA = "f3b25697d76256998ca9d42c198d256258d4c035"
PATCH_ID = "uap-directory-inventory-v1"
ORIGINAL_BLOBS = {
    "src/skillspector/references.py": "ceb6efaae6dd8739823ee4313476e9dc310f5f3c",
    "src/skillspector/nodes/build_context.py": "81659a08df151319260fa910b8af05982c9785b8",
}

# A directory itself is absent from the bounded *file* inventory. The presence
# of an acquired descendant is positive proof of an existing directory, without
# re-probing the filesystem or silently expanding analyzer work.
RESOLVER_BEFORE = '''            else:
                status = "missing"
                disposition = ArtifactDisposition.PARTIAL
        # Real inventory matches'''
RESOLVER_AFTER = '''            else:
                # Only explicit directory links with an acquired descendant.
                # These files belong to the scanner's already bounded inventory;
                # no directory read, symlink following, or additional scan occurs.
                if urlsplit(raw.strip()).path.endswith("/") and any(
                    path.startswith(target + "/") for path in known
                ):
                    resolved_target = target
                    status = "uninspected"
                else:
                    status = "missing"
                disposition = ArtifactDisposition.PARTIAL
        # Real inventory matches'''

LEDGER_BEFORE = '''            if reference["status"] in {"missing", "ambiguous"}
        )

    referenced_paths = frozenset('''
LEDGER_AFTER = '''            if reference["status"] in {"missing", "ambiguous"}
        )
        reference_events.extend(
            ledger_event(
                outcome=LedgerOutcome.PARTIAL,
                record_type=LedgerRecordType.SYSTEM,
                phase="reference_resolution",
                path=primary_path,
                start_line=int(reference["line"]),
                end_line=int(reference["line"]),
                reason=LedgerReason.REFERENCED_UNINSPECTED,
            )
            for reference in references
            if reference["status"] == "uninspected"
        )

    referenced_paths = frozenset('''

PATCHES = {
    "src/skillspector/references.py": (RESOLVER_BEFORE, RESOLVER_AFTER),
    "src/skillspector/nodes/build_context.py": (LEDGER_BEFORE, LEDGER_AFTER),
}


def apply_patch(scanner: Path) -> None:
    checkout_sha = subprocess.check_output(
        ["git", "-C", str(scanner), "rev-parse", "HEAD"], text=True
    ).strip()
    if checkout_sha != UPSTREAM_SHA:
        raise RuntimeError(f"Unsupported upstream scanner revision: {checkout_sha}")

    # Check every original blob and anchor before mutating either module.
    modified = {}
    for relative, (before, after) in PATCHES.items():
        path = scanner / relative
        actual_blob = subprocess.check_output(
            ["git", "-C", str(scanner), "hash-object", str(path)], text=True
        ).strip()
        if actual_blob != ORIGINAL_BLOBS[relative]:
            raise RuntimeError(f"Scanner source bytes differ for {relative}: {actual_blob}")
        body = path.read_text(encoding="utf-8")
        if body.count(before) != 1:
            raise RuntimeError(f"Expected exactly one compatibility anchor in {relative}")
        modified[path] = body.replace(before, after, 1)
    for path, body in modified.items():
        path.write_text(body, encoding="utf-8")
    print(f"Applied {PATCH_ID} to immutable SkillSpector {UPSTREAM_SHA}")


def verify_resolver(scanner: Path) -> None:
    # This imports the patched local scanner, not the project working tree.
    sys.path.insert(0, str(scanner / "src"))
    from skillspector.references import resolve_bundle_references_with_metadata

    with tempfile.TemporaryDirectory(prefix="skillspector-dir-reference-") as tmp:
        root = Path(tmp)
        (root / "SKILL.md").write_text("# Local directory links\n", encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs" / "guide.md").write_text("real", encoding="utf-8")
        (root / "docset").mkdir()
        (root / "docset" / "guide.md").write_text("sibling", encoding="utf-8")
        # This symlink and its target must never be traversed to prove existence.
        try:
            (root / "linked").symlink_to(root / "docs", target_is_directory=True)
        except OSError:
            pass

        known = ["SKILL.md", "docs/guide.md", "docset/guide.md"]
        cases = (
            ("[folder](./docs/)", "uninspected", "docs", known),
            ("[folder](docs/)", "uninspected", "docs", known),
            ("[missing](./absent/)", "missing", None, known),
            ("[sibling](./doc/)", "missing", None, known),
            ("[out-of-inventory](./docs/)", "missing", None, ["SKILL.md"]),
            ("[symlink](./linked/)", "missing", None, known),
            ("[escape](../docs/)", "rejected", None, known),
            ("[encoded escape](%2e%2e/docs/)", "rejected", None, known),
            ("[file](docs/guide.md)", "resolved", "docs/guide.md", known),
            ("[runtime](./future.sh)", "missing", None, known),
        )
        for source, status, target, inventory in cases:
            outcome = resolve_bundle_references_with_metadata(
                root, source_path="SKILL.md", source_text=source, known_paths=inventory
            )
            assert outcome.complete, (source, outcome.limitations)
            assert len(outcome.records) == 1, (source, outcome.records)
            record = outcome.records[0]
            assert record["status"] == status, (source, record)
            assert record["target_path"] == target, (source, record)
            if status == "uninspected":
                assert str(record["disposition"]) == "partial", record
    print("Directory reference inventory, missing, symlink and traversal checks passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    apply_patch(args.scanner)
    if args.verify:
        verify_resolver(args.scanner)


if __name__ == "__main__":
    main()
