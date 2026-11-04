#!/usr/bin/env python3
"""Canary-only compatibility proof for the existing directory-reference patch.

Check the immutable v2.13.3 fork with the independently reviewed JSON VERSION
and out-of-bundle reference fixes. Apply the same conservative directory
inventory patch to both scanner releases, preserving identical inventory rules.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from patch_skillspector_directory_references import PATCHES as PRODUCTION_PATCHES, verify_resolver

# The fork inserts out-of-bundle rejected/partial ledger evidence immediately
# after the missing/ambiguous block. Apply the unchanged production directory
# rule at that exact point without overwriting the additional fork evidence.
FORK_LEDGER_BEFORE = '''            if reference["status"] in {"missing", "ambiguous"}
        )
        # The resolver retains rejected for parent-traversal links'''
FORK_LEDGER_AFTER = '''            if reference["status"] in {"missing", "ambiguous"}
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
        # The resolver retains rejected for parent-traversal links'''
PATCHES = PRODUCTION_PATCHES | {
    "src/skillspector/nodes/build_context.py": (
        FORK_LEDGER_BEFORE,
        FORK_LEDGER_AFTER,
    ),
}

EXPECTED_RELEASE = "13963c56dfce8f708079018100ac24f32b85b9a7"
EXPECTED_BLOBS = {
    "src/skillspector/references.py": "25a08b982d66da1dea0ae57484950a92f4540e16",
    "src/skillspector/nodes/build_context.py": "174887b736d1d5940cd1cf04b235210290702960",
}


def apply(scanner: Path) -> None:
    safe_env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}

    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(scanner), *args], env=safe_env, text=True, timeout=30,
        ).strip()

    if git("rev-parse", "HEAD") != EXPECTED_RELEASE:
        raise RuntimeError("Canary scanner must be exact immutable vetted fork commit")
    replacements: dict[Path, str] = {}
    for path, (before, after) in PATCHES.items():
        target = scanner / path
        if (target.is_symlink() or target.parent.is_symlink()
                or not target.resolve().is_relative_to(scanner) or not target.is_file()):
            raise RuntimeError(f"Missing or symlinked scanner module: {path}")
        if git("rev-parse", f"HEAD:{path}") != EXPECTED_BLOBS[path]:
            raise RuntimeError(f"Unexpected immutable source blob: {path}")
        if git("hash-object", path) != EXPECTED_BLOBS[path]:
            raise RuntimeError(f"Unexpected working tree content: {path}")
        body = target.read_text(encoding="utf-8")
        if body.count(before) != 1:
            raise RuntimeError(f"Missing or duplicate compatibility anchor: {path}")
        replacements[target] = body.replace(before, after, 1)
    for target, body in replacements.items():
        target.write_text(body, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    scanner = args.scanner.resolve()
    if args.check_only:
        verify_resolver(scanner)
        return
    apply(scanner)
    subprocess.run(
        [str(scanner / ".venv/bin/python"), str(Path(__file__).resolve()),
         str(scanner), "--check-only"],
        check=True, timeout=60,
    )
    print("Pinned fork directory inventory patch matches conservative acceptance")


if __name__ == "__main__":
    main()
