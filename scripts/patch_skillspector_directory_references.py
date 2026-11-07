#!/usr/bin/env python3
"""Scoped v2.13.1 maintenance patch: preserve bounded directory and URL-host evidence.

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
PATCH_ID = "uap-directory-inventory-url-host-v2"
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

# Independently reviewed classifier from merged SkillSpector PR #4 c9efce7dcf423f83a305b15631890658d01c2c2f.
# The 2.13.1 parser has the identical reference-candidate hook; this is an
# exact, fail-closed compatibility backport, not a general 2.13.3 upgrade.
URL_HOST_HELPER = r'''# A literal domain listed as a URL host is not a local file dependency. Keep
# this exception bounded to unescaped single-backtick prose; actual inventory
# matches and explicit file/command uses still take precedence.
_DOCUMENTED_URL_HOST = re.compile(r"\b(?:URL[ \t]+hosts?|hostnames?|domains?)\b", re.IGNORECASE)
_DOCUMENTED_URL_HOST_FILE_USE = re.compile(
    r"\b(?:files?|filenames?|paths?|scripts?|commands?|read|run|execut\w*|open|load|"
    r"include|import|download\w*|upload\w*|cop(?:y|ied|ying)|mov(?:e|es|ed|ing)|"
    r"delet\w*|install\w*)\b",
    re.IGNORECASE,
)


def _is_documented_url_hostname(text: str, start: int, end: int) -> bool:
    if end - start > 128 or _DOTTED_IDENTIFIER.fullmatch(text, start, end) is None:
        return False
    if (
        start < 1
        or end >= len(text)
        or text[start - 1] != "`"
        or text[end] != "`"
        or (start > 1 and text[start - 2] in "`\\")
        or (end + 1 < len(text) and text[end + 1] == "`")
    ):
        return False
    # Only demonstrated DNS suffixes qualify for this bounded prose exception.
    # An unknown suffix can be a local artifact (e.g. data.csv or bundle.zip);
    # retain its missing-reference evidence instead of guessing a hostname.
    tld = text[start:end].rsplit(".", 1)[-1]
    if tld.lower() not in {"com", "org", "net"}:
        return False
    # Never cross a line boundary or interpret an instruction to use a file
    # as documentation of a hostname.
    # A host qualifier in a previous sentence cannot excuse a missing local
    # file on the same line. Explicit file use after the token also wins.
    before = _DATA_FIELD_CLAUSE_END.split(text[max(0, start - 96) : start - 1])[-1]
    after = _DATA_FIELD_CLAUSE_END.split(text[end + 1 : end + 97], maxsplit=1)[0]
    return (
        bool(_DOCUMENTED_URL_HOST.search(before))
        and not _DOCUMENTED_URL_HOST_FILE_USE.search(before)
        and not _DOCUMENTED_URL_HOST_FILE_USE.search(after)
    )'''
URL_HOST_EXP_BEFORE = r'''                            and _is_documented_data_field(
                                text, line_offset + match.start, line_offset + match.end
                            ),'''
URL_HOST_EXP_AFTER = r'''                            and (
                                _is_documented_data_field(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                                or _is_documented_url_hostname(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                            ),'''
URL_HOST_INSERT_BEFORE = "\n\n@dataclass(frozen=True)\nclass ReferenceResolutionResult"


def add_url_host_prose_patch(body: str) -> str:
    # Both anchors must exist exactly once in the authenticated upstream blob.
    if body.count(URL_HOST_INSERT_BEFORE) != 1 or body.count(URL_HOST_EXP_BEFORE) != 1:
        raise RuntimeError("Unsupported URL-host parser anchors")
    body = body.replace(URL_HOST_INSERT_BEFORE, "\n\n" + URL_HOST_HELPER + URL_HOST_INSERT_BEFORE, 1)
    return body.replace(URL_HOST_EXP_BEFORE, URL_HOST_EXP_AFTER, 1)


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
            ["git", "-C", str(scanner), "hash-object", relative], text=True
        ).strip()
        if actual_blob != ORIGINAL_BLOBS[relative]:
            raise RuntimeError(f"Scanner source bytes differ for {relative}: {actual_blob}")
        body = path.read_text(encoding="utf-8")
        if body.count(before) != 1:
            raise RuntimeError(f"Expected exactly one compatibility anchor in {relative}")
        updated = body.replace(before, after, 1)
        if relative == "src/skillspector/references.py":
            updated = add_url_host_prose_patch(updated)
        modified[path] = updated
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
    # Tests execute the patched installed scanner; local artifacts and genuine
    # missing dependencies keep their original evidence and partial disposition.
    with tempfile.TemporaryDirectory(prefix="skillspector-host-reference-") as tmp:
        root = Path(tmp)
        (root / "SKILL.md").write_text("# Host reference fixtures\n", encoding="utf-8")
        (root / "agoda.com").write_text("real local artifact", encoding="utf-8")
        known = ["SKILL.md"]
        examples = (
            ("Attribute the source only from the URL host (`agoda.com`, `trip.com`, `traveloka.com`).", (), known),
            ("The hostname `api.example.org` is public. The local `config.ini` is required.", ("missing",), known),
            ("The URL host `bundle.zip` is listed.", ("missing",), known),
            ("Run [setup](scripts/required.sh) before continuing.", ("missing",), known),
            ("Attribute the source only from the URL host (`agoda.com`).", ("resolved",), known + ["agoda.com"]),
        )
        for source, expected, inventory in examples:
            outcome = resolve_bundle_references_with_metadata(
                root, source_path="SKILL.md", source_text=source, known_paths=inventory
            )
            assert outcome.complete, (source, outcome.limitations)
            statuses = tuple(record["status"] for record in outcome.records)
            assert statuses == expected, (source, statuses, expected)
            if expected == ("missing",):
                assert outcome.records[0]["target_path"] is None, source
                assert str(outcome.records[0]["disposition"]) == "partial", source
    print("Exact merged URL-host classifier and fail-closed references passed")
    print("Directory reference inventory, missing, symlink and traversal checks passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--check-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.check_only:
        verify_resolver(args.scanner)
        return
    apply_patch(args.scanner)
    if args.verify:
        # The scanner package is installed into its locked venv, not the
        # setup-python interpreter. Import from that interpreter so package
        # metadata and runtime dependencies resolve exactly as in production.
        interpreter = args.scanner / ".venv" / "bin" / "python"
        subprocess.run(
            [str(interpreter), str(Path(__file__).resolve()), str(args.scanner), "--check-only"],
            check=True,
        )


if __name__ == "__main__":
    main()
