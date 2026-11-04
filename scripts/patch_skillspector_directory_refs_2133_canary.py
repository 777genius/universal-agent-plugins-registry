#!/usr/bin/env python3
"""Canary-only compatibility proof for the existing directory-reference patch.

The v2.13.3 references.py blob is identical to production v2.13.1; its
build_context.py differs only by two newly supported JavaScript extensions.
Apply the *same* conservative inventory patch to both scanners to compare
static-analysis behavior without introducing a new missing-directory variable.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from patch_skillspector_directory_references import PATCHES, verify_resolver

EXPECTED_RELEASE = "38a1dfe93325d2f8bfcd4f8d0241eed706334915"
EXPECTED_BLOBS = {
    "src/skillspector/references.py": "ceb6efaae6dd8739823ee4313476e9dc310f5f3c",
    "src/skillspector/nodes/build_context.py": "a4faaba2739dc0ded1712495835d6bf56e79deb5",
}


def apply(scanner: Path) -> None:
    safe_env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}

    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(scanner), *args], env=safe_env, text=True, timeout=30,
        ).strip()

    if git("rev-parse", "HEAD") != EXPECTED_RELEASE:
        raise RuntimeError("Canary scanner must be exact immutable v2.13.3")
    replacements: dict[Path, str] = {}
    for path, (before, after) in PATCHES.items():
        target = scanner / path
        if target.is_symlink() or target.parent.is_symlink() or not target.is_file():
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
    print("v2.13.3 directory inventory patch matches the existing conservative acceptance")


if __name__ == "__main__":
    main()
