#!/usr/bin/env python3
"""Actual pinned CLI E2E: parent escapes are Partial, benign web links unchanged."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def scan(scanner: Path, root: Path) -> tuple[int, dict]:
    with tempfile.TemporaryDirectory(prefix="uap-traversal-cli-home-") as home:
        environment = {
            "PATH": os.defpath, "HOME": home, "LANG": "C.UTF-8",
            "PYTHONNOUSERSITE": "1", "LANGCHAIN_TRACING_V2": "false",
            "LANGSMITH_TRACING": "false", "SKILLSPECTOR_OSV_TIMEOUT": "3",
            "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "55",
        }
        result = subprocess.run(
            [str(scanner), "scan", str(root), "--no-llm", "--format", "json",
             "--fail-on-incomplete"],
            cwd=home, env=environment, capture_output=True, timeout=120, check=False,
        )
    if result.returncode not in (0, 1) or not result.stdout:
        raise AssertionError(
            (root.name, result.returncode, result.stderr.decode(errors="replace")[-500:])
        )
    payload = json.loads(result.stdout)
    if payload.get("execution_successful") is not True:
        raise AssertionError((root.name, "Scanner did not complete", payload.get("status")))
    return result.returncode, payload


def main() -> None:
    scanner = Path(sys.argv[1]).resolve()
    if not scanner.is_file() or scanner.is_symlink():
        raise AssertionError("Pinned scanner executable must be a regular file")
    checks = (
        ("plain", "[outside](../outside-runner.sh)"),
        ("encoded", "[outside](%2e%2e/outside-runner.sh)"),
        ("nested", "[outside](docs/../../outside-runner.sh)"),
    )
    with tempfile.TemporaryDirectory(prefix="uap-traversal-e2e-") as temp:
        inputs = Path(temp)
        external = inputs / "outside-runner.sh"
        external.write_text("# Outside the selected skill, do not execute\n", encoding="utf-8")
        source_digest = hashlib.sha256(external.read_bytes()).hexdigest()
        for name, reference in checks:
            root = inputs / name
            root.mkdir()
            text = (
                "---\nname: escaping-dependency\ndescription: Uninspectable local dependency.\n---\n"
                "Run the referenced file to generate results: " + reference + "\n"
            )
            manifest = root / "SKILL.md"
            manifest.write_text(text, encoding="utf-8")
            before = manifest.read_bytes()
            code, report = scan(scanner, root)
            coverage = report["analysis_completeness"]
            records = [r for r in coverage["references"]
                       if r["reference_kind"] == "markdown_link"]
            assert len(records) == 1, (name, records)
            assert records[0]["status"] == "rejected", (name, records)
            assert records[0]["disposition"] == "partial", (name, records)
            reasons = {e["reason_code"] for e in coverage["ledger_exceptions"]}
            assert "reference_unresolved" in reasons, (name, reasons)
            assert code == 1 and not coverage["is_complete"] and coverage["status"] == "partial", (
                name, code, coverage["status"]
            )
            assert manifest.read_bytes() == before
            assert hashlib.sha256(external.read_bytes()).hexdigest() == source_digest
            print(name, "actual-CLI Partial, reference_unresolved, immutable inputs")
        remote = inputs / "remote"
        remote.mkdir()
        (remote / "SKILL.md").write_text(
            "---\nname: external-docs\ndescription: Informational web docs only.\n---\n"
            "See [public documentation](https://example.invalid/docs).\n", encoding="utf-8"
        )
        _, report = scan(scanner, remote)
        coverage = report["analysis_completeness"]
        assert not any(
            event["reason_code"] == "reference_unresolved"
            for event in coverage["ledger_exceptions"]
        ), coverage["ledger_exceptions"]
        remote_refs = [r for r in coverage["references"]
                       if r["reference_kind"] == "markdown_link"]
        assert len(remote_refs) == 1 and remote_refs[0]["status"] == "rejected", remote_refs
        assert remote_refs[0]["disposition"] == "out_of_scope", remote_refs
        print("Remote informational link remains out_of_scope (not fabricated missing)")


if __name__ == "__main__":
    main()
