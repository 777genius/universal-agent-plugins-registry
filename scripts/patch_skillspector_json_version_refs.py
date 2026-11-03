#!/usr/bin/env python3
"""Non-production canary for issue #411: exact JSON VERSION reference classification.

NOT wired into the production scanner or scan profile. Only exercised against
the immutable pinned scanner after its existing directory maintenance patch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

UPSTREAM_SHA = "f3b25697d76256998ca9d42c198d256258d4c035"
REFERENCES_BLOB = "ceb6efaae6dd8739823ee4313476e9dc310f5f3c"
PATCH_ID = "uap-json-version-canary-v1"
REAL_SKILL_BLOB = "121e813665d7fe7512e4a59ad0c341b92d8d124c"

# Only a whole JSON field line with a three-component numeric VERSION value.
# No generic semver, IP, property or path suppression is permitted.
PATCHES = (
    (
        "_QUOTED_OR_CODE_PATH = re.compile(\n",
        "_JSON_VERSION_FIELD = re.compile(\n"
        "    r'^[ \\t]*\"VERSION\"[ \\t]*:[ \\t]*\"(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)\"[ \\t]*,?[ \\t]*$'\n"
        ")\n"
        "_QUOTED_OR_CODE_PATH = re.compile(\n",
    ),
    (
        "        version_match = _FRONTMATTER_VERSION.match(stripped_line) if quoted_scalars else None\n",
        "        version_match = _FRONTMATTER_VERSION.match(stripped_line) if quoted_scalars else None\n"
        "        json_version_match = _JSON_VERSION_FIELD.fullmatch(stripped_line)\n",
    ),
    (
        "            if not inside_destination and not redundant_image_label and not is_version_metadata:\n",
        "            is_json_version_metadata = (\n"
        "                reference_kind is ReferenceKind.QUOTED_OR_CODE\n"
        "                and json_version_match is not None\n"
        "                and (match.start, match.end) == json_version_match.span(\"version\")\n"
        "            )\n"
        "            if (\n"
        "                not inside_destination\n"
        "                and not redundant_image_label\n"
        "                and not is_version_metadata\n"
        "                and not is_json_version_metadata\n"
        "            ):\n",
    ),
)


def apply_patch(scanner: Path) -> None:
    # Verify the *working bytes* the canary is about to edit, not only the
    # committed Git blob. Otherwise a mutated checkout could pass the gate.
    from patch_skillspector_directory_references import RESOLVER_BEFORE, RESOLVER_AFTER

    safe_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(scanner), *args], env=safe_env)

    if git("rev-parse", "HEAD").decode().strip() != UPSTREAM_SHA:
        raise RuntimeError("Unexpected SkillSpector checkout: fail closed")
    if git("rev-parse", "HEAD:src/skillspector/references.py").decode().strip() != REFERENCES_BLOB:
        raise RuntimeError("Unexpected immutable upstream source: fail closed")

    path = scanner / "src/skillspector/references.py"
    if any(item.is_symlink() for item in (path.parent.parent, path.parent, path)) or not path.is_file():
        raise RuntimeError("Scanner references path is not a regular in-tree file")
    pinned_source = git("show", "HEAD:src/skillspector/references.py").decode("utf-8")
    if pinned_source.count(RESOLVER_BEFORE) != 1:
        raise RuntimeError("Pinned upstream directory-patch anchor differs")
    expected = pinned_source.replace(RESOLVER_BEFORE, RESOLVER_AFTER, 1)
    if path.read_bytes() != expected.encode("utf-8"):
        raise RuntimeError("Working scanner differs from the exact vetted directory patch")

    content = expected
    for before, after in PATCHES:
        if content.count(before) != 1:
            raise RuntimeError(f"Candidate patch anchor absent or duplicated: {before!r}")
        content = content.replace(before, after, 1)
    path.write_text(content, encoding="utf-8")
    print(f"Applied experimental {PATCH_ID}; production policy unchanged")


def verify(scanner: Path, *, baseline: bool, real_skill: Path | None = None) -> None:
    sys.path.insert(0, str(scanner / "src"))
    from skillspector.references import resolve_bundle_references_with_metadata

    with tempfile.TemporaryDirectory(prefix="skillspector-version-ref-") as temporary:
        root = Path(temporary)
        (root / "SKILL.md").write_text("# fixture\n", encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs/guide.md").write_text("# present\n", encoding="utf-8")
        (root / "symlink").symlink_to(root / "docs", target_is_directory=True)
        known = ["SKILL.md", "docs/guide.md"]
        cases = (
            ('"VERSION": "1.0.0",\n', ("missing",) if baseline else ()),
            ('```json\n{\n"VERSION": "1.0.0",\n}\n```\n', ("missing",) if baseline else ()),
            ('"VERSION": "1.0.0", "file": "missing.md"\n', ("missing", "missing")),
            ('"version": "1.0.0",\n', ("missing",)),
            ('"VERSION": "1.x",\n', ("missing",)),
            ('"VERSION": "0.0.0.0",\n', ("missing",)),
            ('`data.coverage`\n', ("missing",)),
            ('[version artifact](1.0.0)\n', ("missing",)),
            ('[missing file](./missing.md)\n', ("missing",)),
            ('`runtime/generated.json`\n', ("missing",)),
            ('[real file](docs/guide.md)\n', ("resolved",)),
            ('[present directory](./docs/)\n', ("uninspected",)),
            ('[symlink path](./symlink/guide.md)\n', ("missing",)),
            ('[unsafe traversal](../outside.md)\n', ("rejected",)),
        )
        for source, statuses in cases:
            result = resolve_bundle_references_with_metadata(
                root, source_path="SKILL.md", source_text=source, known_paths=known
            )
            if not result.complete:
                raise AssertionError((source, result.limitations))
            actual = tuple(reference["status"] for reference in result.records)
            if actual != statuses:
                raise AssertionError((source, actual, statuses, result.records))
        print(f"Verified {'unpatched baseline' if baseline else PATCH_ID} adversarial resolver cases")

    if real_skill is not None:
        source = real_skill / "SKILL.md"
        if source.is_symlink() or not source.is_file():
            raise AssertionError("Pinned real Skill is not a regular file")
        body = source.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()
        if blob != REAL_SKILL_BLOB:
            raise AssertionError(("Real source SHA differs", blob))
        lines = body.decode("utf-8").splitlines()
        if len(lines) < 153 or lines[152].strip() != '"VERSION": "1.0.0",':
            raise AssertionError("Real immutable VERSION line 153 differs")
        inventory = [
            item.relative_to(real_skill).as_posix()
            for item in real_skill.rglob("*")
            if item.is_file() and not item.is_symlink()
        ]
        if len(inventory) > 2048:
            raise AssertionError("Real source inventory unexpectedly large")
        result = resolve_bundle_references_with_metadata(
            real_skill, source_path="SKILL.md",
            source_text=body.decode("utf-8"), known_paths=inventory,
        )
        if not result.complete:
            raise AssertionError(("Real source extraction incomplete", result.limitations))
        version_refs = [
            item for item in result.records
            if item["line"] == 153 and '"VERSION": "1.0.0"' in item["evidence"]
        ]
        if baseline and not (len(version_refs) == 1 and
                             version_refs[0]["status"] == "missing" and
                             str(version_refs[0]["reference_kind"]) == "quoted_or_code"):
            raise AssertionError(("Real baseline did not reproduce false reference", version_refs))
        if not baseline and version_refs:
            raise AssertionError(("Corrected real source retains false reference", version_refs))
        print(f"Verified immutable asc-workflow VERSION case, baseline={baseline}")

    if not baseline:
        with tempfile.TemporaryDirectory(prefix="skillspector-version-cli-") as home:
            source_dir = Path(home) / "source"
            source_dir.mkdir()
            skill = source_dir / "SKILL.md"
            skill.write_text(
                "---\nname: json-version-proof\ndescription: Inspect metadata without hiding missing files.\n---\n"
                "```json\n{\n\"VERSION\": \"1.0.0\",\n}\n```\n"
                "Read [missing file](./missing.md).\n", encoding="utf-8",
            )
            before = skill.read_bytes()
            process = subprocess.run(
                [str(scanner / ".venv/bin/skillspector"), "scan", str(source_dir),
                 "--no-llm", "--format", "json", "--fail-on-incomplete"],
                cwd=home, env={"PATH": os.defpath, "HOME": home, "LANG": "C.UTF-8",
                               "PYTHONNOUSERSITE": "1", "LANGCHAIN_TRACING_V2": "false",
                               "LANGSMITH_TRACING": "false", "SKILLSPECTOR_OSV_TIMEOUT": "3",
                               "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "55"},
                capture_output=True, timeout=110, check=False,
            )
            if process.returncode != 1 or not process.stdout:
                raise AssertionError((process.returncode, process.stderr.decode(errors="replace")[-900:]))
            report = json.loads(process.stdout)
            refs = report["analysis_completeness"]["references"]
            if any("1.0.0" in item["evidence"] for item in refs):
                raise AssertionError(("Version scalar falsely retained", refs))
            if not any(item["status"] == "missing" and "missing.md" in item["evidence"] for item in refs):
                raise AssertionError(("True missing reference not retained", refs))
            if report["analysis_completeness"]["is_complete"] or skill.read_bytes() != before:
                raise AssertionError("CLI incorrectly marked complete or mutated source")
            print("Verified pinned scanner CLI remains Partial for real missing reference")

        # Independent positive end-to-end proof: with only VERSION metadata and
        # no missing files, the actual patched CLI must complete inspection.
        # A resolver-only green check is not evidence of a fully checked Skill.
        with tempfile.TemporaryDirectory(prefix="skillspector-version-complete-") as home:
            root = Path(home) / "source"
            root.mkdir()
            source = root / "SKILL.md"
            source.write_text(
                "---\nname: version-only\ndescription: Verify standalone metadata.\n---\n"
                '"VERSION": "1.0.0",\n',
                encoding="utf-8",
            )
            before = source.read_bytes()
            result = subprocess.run(
                [str(scanner / ".venv/bin/skillspector"), "scan", str(root),
                 "--no-llm", "--format", "json", "--fail-on-incomplete"],
                cwd=home,
                env={"PATH": os.defpath, "HOME": home, "LANG": "C.UTF-8",
                     "PYTHONNOUSERSITE": "1", "LANGCHAIN_TRACING_V2": "false",
                     "LANGSMITH_TRACING": "false", "SKILLSPECTOR_OSV_TIMEOUT": "3",
                     "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "55"},
                capture_output=True, timeout=110, check=False,
            )
            if result.returncode != 0 or not result.stdout:
                raise AssertionError(("VERSION-only Skill not fully inspected",
                                      result.returncode, result.stderr.decode(errors="replace")[-900:]))
            report = json.loads(result.stdout)
            coverage = report["analysis_completeness"]
            if not coverage["is_complete"] or coverage["status"] != "complete":
                raise AssertionError(("VERSION-only scan remained incomplete", coverage))
            if any("1.0.0" in ref["evidence"] for ref in coverage["references"]):
                raise AssertionError(("False VERSION reference survived CLI scan", coverage["references"]))
            if source.read_bytes() != before:
                raise AssertionError("Scanner changed the input Skill")
            print("Verified pinned scanner CLI fully inspects VERSION-only Skill")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    parser.add_argument("--real-skill", type=Path)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--check-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.baseline or args.check_only:
        verify(args.scanner.resolve(), baseline=args.baseline,
               real_skill=args.real_skill.resolve() if args.real_skill else None)
        return
    apply_patch(args.scanner.resolve())
    if args.verify:
        command = [
            str(args.scanner.resolve() / ".venv/bin/python"),
            str(Path(__file__).resolve()), str(args.scanner.resolve()), "--check-only",
        ]
        if args.real_skill is not None:
            command.extend(["--real-skill", str(args.real_skill.resolve())])
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
