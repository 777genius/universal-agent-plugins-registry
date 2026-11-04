#!/usr/bin/env python3
"""Canary-only lexical containment guard for explicit Markdown dependencies.

This does NOT change production scanner/profile identity. Apply after the
existing pinned directory-inventory patch, to a disposable scanner checkout.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from patch_skillspector_directory_references import ORIGINAL_BLOBS, PATCHES, UPSTREAM_SHA

REFERENCE_BEFORE = '''        status = "rejected"
        disposition = ArtifactDisposition.OUT_OF_SCOPE
        resolved_target: str | None = None'''
REFERENCE_AFTER = '''        status = "rejected"
        disposition = ArtifactDisposition.OUT_OF_SCOPE
        # Rejected remote/absolute/fragment links stay out of scope. An explicit
        # Markdown dependency with a lexical parent escape is uninspectable,
        # however: do not silently interpret that as Complete.
        if target is None and reference_kind is ReferenceKind.MARKDOWN_LINK:
            split = urlsplit(raw.strip())
            relative = unquote(split.path).replace("\\\\", "/")
            if (
                not split.scheme and not split.netloc
                and not raw.strip().startswith(("/", "\\\\", "#"))
                and relative and not relative.startswith("/")
                and not (len(relative) >= 2 and relative[1] == ":")
            ):
                joined = posixpath.normpath(
                    posixpath.join(PurePosixPath(source_path).parent.as_posix(), relative)
                )
                if joined == ".." or joined.startswith("../"):
                    disposition = ArtifactDisposition.PARTIAL
        resolved_target: str | None = None'''
LEDGER_BEFORE = '''    referenced_paths = frozenset('''
LEDGER_AFTER = '''    reference_events.extend(
        ledger_event(
            outcome=LedgerOutcome.PARTIAL,
            record_type=LedgerRecordType.SYSTEM,
            phase="reference_resolution",
            path=primary_path,
            start_line=int(reference["line"]),
            end_line=int(reference["line"]),
            reason=LedgerReason.REFERENCE_UNRESOLVED,
        )
        for reference in references
        if (
            reference["status"] == "rejected"
            and reference["disposition"] is ArtifactDisposition.PARTIAL
        )
    )

    referenced_paths = frozenset('''

GUARDS = {
    "src/skillspector/references.py": (REFERENCE_BEFORE, REFERENCE_AFTER),
    "src/skillspector/nodes/build_context.py": (LEDGER_BEFORE, LEDGER_AFTER),
}


def apply(scanner: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(scanner), *args], text=True, timeout=30
        ).strip()

    if git("rev-parse", "HEAD") != UPSTREAM_SHA:
        raise RuntimeError("Unsupported immutable SkillSpector revision")
    updated = {}
    for relative, (before, after) in GUARDS.items():
        target = scanner / relative
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f"Missing/linked scanner module: {relative}")
        if git("rev-parse", f"HEAD:{relative}") != ORIGINAL_BLOBS[relative]:
            raise RuntimeError(f"Pinned scanner blob changed: {relative}")
        original = subprocess.check_output(
            ["git", "-C", str(scanner), "show", f"HEAD:{relative}"],
            text=True, timeout=30,
        )
        directory_before, directory_after = PATCHES[relative]
        if original.count(directory_before) != 1:
            raise RuntimeError(f"Directory maintenance anchor changed: {relative}")
        expected = original.replace(directory_before, directory_after, 1)
        current = target.read_text(encoding="utf-8")
        if current != expected or current.count(before) != 1:
            raise RuntimeError(f"Unexpected maintenance-patched input: {relative}")
        updated[target] = current.replace(before, after, 1)
    for target, source in updated.items():
        target.write_text(source, encoding="utf-8")


def verify(scanner: Path) -> None:
    sys.path.insert(0, str(scanner / "src"))
    from skillspector.artifacts import ArtifactDisposition
    from skillspector.references import resolve_bundle_references_with_metadata

    checks = (
        ("[outside](../outside-runner.sh)", "rejected", ArtifactDisposition.PARTIAL),
        ("[encoded](%2e%2e/outside-runner.sh)", "rejected", ArtifactDisposition.PARTIAL),
        ("[nested](docs/../../outside.sh)", "rejected", ArtifactDisposition.PARTIAL),
        ("[missing](./missing.sh)", "missing", ArtifactDisposition.PARTIAL),
        ("[web](https://example.invalid/x)", "rejected", ArtifactDisposition.OUT_OF_SCOPE),
        ("[fragment](#overview)", "rejected", ArtifactDisposition.OUT_OF_SCOPE),
        ("[absolute](/etc/passwd)", "rejected", ArtifactDisposition.OUT_OF_SCOPE),
    )
    for markdown, status, disposition in checks:
        result = resolve_bundle_references_with_metadata(
            Path("/not-accessed"), source_path="SKILL.md",
            source_text=markdown, known_paths=["SKILL.md"],
        )
        if not result.complete or len(result.records) != 1:
            raise AssertionError((markdown, result))
        record = result.records[0]
        if record["status"] != status or record["disposition"] is not disposition:
            raise AssertionError((markdown, record))
    print("Lexical escape guard verifies local traversal without treating web links as missing")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    scanner = args.scanner.resolve()
    if not args.check_only:
        apply(scanner)
    if args.check_only:
        verify(scanner)
    elif args.verify:
        subprocess.run(
            [str(scanner / ".venv/bin/python"), str(Path(__file__).resolve()),
             str(scanner), "--check-only"],
            check=True, timeout=60,
        )


if __name__ == "__main__":
    main()
