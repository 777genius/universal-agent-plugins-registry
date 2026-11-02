#!/usr/bin/env python3
"""CLI-level pinned SkillSpector regression for directory reference evidence."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    scanner = Path(sys.argv[1]).resolve()
    assert scanner.is_file() and not scanner.is_symlink()
    with tempfile.TemporaryDirectory(prefix="uap-directory-cli-") as home:
        root = Path(home) / "source"
        root.mkdir()
        (root / "docs").mkdir()
        (root / "docs" / "guide.md").write_text("# A real scanned child\n", encoding="utf-8")
        skill = root / "SKILL.md"
        skill.write_text(
            "---\nname: directory-proof\ndescription: Inspect local references carefully.\n---\n"
            "Read [the linked folder](./docs/).\n"
            "Read [the missing folder](./absent/).\n",
            encoding="utf-8",
        )
        before = skill.read_bytes()
        env = {
            "PATH": os.defpath, "HOME": home, "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1", "LANGCHAIN_TRACING_V2": "false",
            "LANGSMITH_TRACING": "false", "SKILLSPECTOR_OSV_TIMEOUT": "3",
            "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "55",
        }
        completed = subprocess.run(
            [str(scanner), "scan", str(root), "--no-llm", "--format", "json",
             "--fail-on-incomplete"],
            cwd=home, env=env, capture_output=True, timeout=110, check=False,
        )
        assert completed.returncode == 1, (
            f"Expected --fail-on-incomplete exit 1; got {completed.returncode}: "
            f"{completed.stderr.decode(errors='replace')[-800:]}"
        )
        if not completed.stdout:
            raise AssertionError(
                f"No scanner JSON. exit={completed.returncode}, "
                f"stderr={completed.stderr.decode(errors='replace')[-1000:]}"
            )
        report = json.loads(completed.stdout)
        coverage = report["analysis_completeness"]
        refs = [x for x in coverage["references"] if x["reference_kind"] == "markdown_link"]
        found = {x["evidence"]: x for x in refs}
        directory = next((x for x in refs if "./docs/" in x["evidence"]), None)
        missing = next((x for x in refs if "./absent/" in x["evidence"]), None)
        assert directory is not None and directory["status"] == "uninspected", found
        assert directory["target_path"] == "docs", directory
        assert str(directory["disposition"]) == "partial", directory
        assert missing is not None and missing["status"] == "missing", found
        assert missing["target_path"] is None, missing
        assert coverage["is_complete"] is False, coverage
        assert coverage["status"] == "partial", coverage
        reason_codes = {x["reason_code"] for x in coverage["ledger_exceptions"]}
        assert "referenced_uninspected" in reason_codes, reason_codes
        assert "reference_missing" in reason_codes, reason_codes
        assert skill.read_bytes() == before, "scanner modified source contents"
        assert report["metadata"]["skillspector_version"] == "2.13.1"
        print("Verified pinned scanner CLI evidence and incomplete scan: directory vs missing")

    if len(sys.argv) >= 4:
        # Re-run the unchanged pinned public daisyUI source and the immutable
        # Cloudflare community bridge, rather than relying on synthetic paths.
        daisy, cloudflare = (Path(value).resolve() for value in sys.argv[2:4])
        for label, source in (("daisyui", daisy), ("cloudflare", cloudflare)):
            with tempfile.TemporaryDirectory(prefix="uap-real-reference-") as temp_home:
                process = subprocess.run(
                    [str(scanner), "scan", str(source), "--no-llm", "--format", "json",
                     "--fail-on-incomplete"],
                    cwd=temp_home,
                    env={**env, "HOME": temp_home, "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "80"},
                    capture_output=True, timeout=150, check=False,
                )
                assert process.stdout, (
                    label, process.returncode, process.stderr.decode(errors="replace")[-600:]
                )
                report = json.loads(process.stdout)
                refs = report["analysis_completeness"]["references"]
                if label == "daisyui":
                    relevant = [r for r in refs if r["reference_kind"] == "markdown_link"
                                and "./components/" in r["evidence"]]
                    assert any(r["status"] == "uninspected" and
                               r["target_path"] == "components" and
                               str(r["disposition"]) == "partial" for r in relevant), relevant
                    assert report["analysis_completeness"]["is_complete"] is False
                else:
                    missing_runtime = [r for r in refs
                        if "node_modules/wrangler/config-schema.json" in r["evidence"]]
                    assert any(r["status"] == "missing" and r["target_path"] is None
                               for r in missing_runtime), missing_runtime
                print(f"Verified real {label} source with pinned scanner")


if __name__ == "__main__":
    main()
