#!/usr/bin/env python3
"""Stage exact successful npm audit artifacts for an ephemeral MCP preview.

No signed Directory source, published release policy, or caller checkout is
committed. The staged tree is qualified only within a disposable CI runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "io.github.777genius.agentplugins/runtime"
AUDIT = ROOT / "registry/upstream-promotion-audit/runtime-dependencies/2026-10-29/remediation-candidates.json"
SOURCES = {
    "firebase": ("firebase-tools", "15.35.0"),
    "hubspot-developer": ("@hubspot/cli", "8.18.0"),
}

# HubSpot CLI 8.18.0 upstream registration, qualified only in the ephemeral
# preview; historical signed releases and old expected contracts stay intact.
HUBSPOT_818_ADDED_TOOLS = ("search-knowledge-base", "submit-feedback")


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise RuntimeError(detail)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: dict) -> None:
    # Signed candidate digests must not depend on Windows text-mode CRLF translation.
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_registry as registry

    record = json.loads(AUDIT.read_text(encoding="utf-8"))
    outcomes = []
    for name, (dependency, version) in SOURCES.items():
        evidence = args.artifacts / f"runtime-candidate-{name}"
        root = ROOT / "plugins" / name
        runtime_dir = root / RUNTIME
        require(evidence.is_dir() and runtime_dir.is_dir(), f"missing candidate {name}")
        candidate = next((c for c in record["candidates"] if c["product_id"] == name), None)
        require(candidate is not None, f"candidate not reviewed: {name}")

        descriptor = json.loads((evidence / "candidate-result.json").read_text())
        require(descriptor["passed"] is True and descriptor["audit_exit"] == 0
                and descriptor["audit_totals"]["total"] == 0, f"candidate audit unclean: {name}")
        require((descriptor["root_name"], descriptor["root_version"]) ==
                (dependency, version), f"candidate identity mismatch: {name}")
        manifest_body = (evidence / "package.json").read_bytes()
        manifest = json.loads(manifest_body)
        require(manifest["dependencies"] == {dependency: version}
                and manifest.get("overrides") == descriptor["overrides"]
                and "scripts" not in manifest, f"package manifest mismatch: {name}")
        lock_body = (evidence / "package-lock.json").read_bytes()
        lock = json.loads(lock_body)
        require(digest(lock_body) == descriptor["lock_digest"]
                and lock["lockfileVersion"] == 3
                and lock["packages"][""].get("dependencies") == manifest["dependencies"]
                and lock["packages"][f"node_modules/{dependency}"]["version"] == version
                and lock["packages"][f"node_modules/{dependency}"]["integrity"] ==
                descriptor["integrity"], f"candidate lock/integrity mismatch: {name}")

        (runtime_dir / "package.json").write_bytes(manifest_body)
        (runtime_dir / "package-lock.json").write_bytes(lock_body)
        runtime = json.loads((runtime_dir / "runtime.json").read_text())
        require(runtime["package"] == dependency, f"runtime package mismatch: {name}")
        runtime["version"] = version
        runtime["package_lock_sha256"] = descriptor["lock_digest"]
        write_json(runtime_dir / "runtime.json", runtime)
        candidate["runtime"] = runtime
        candidate["npm_root_integrity"] = descriptor["integrity"]

        if name == "hubspot-developer":
            mcp_path = root / "mcp.json"
            mcp = json.loads(mcp_path.read_text(encoding="utf-8"))
            require(mcp["mcpServers"][name]["env"]["HUBSPOT_CLI_VERSION"] == "8.15.0",
                    "HubSpot reviewed MCP environment changed")
            mcp["mcpServers"][name]["env"]["HUBSPOT_CLI_VERSION"] = version
            write_json(mcp_path, mcp)
            manifest_path = root / "plugin.json"
            plugin = json.loads(manifest_path.read_text(encoding="utf-8"))
            require("8.15.0" in plugin["description"], "HubSpot description drift")
            plugin["description"] = plugin["description"].replace("8.15.0", version)
            write_json(manifest_path, plugin)
            # The owner has accepted the vendor's added tool inventory for
            # qualification, with its external-feedback side effect documented
            # in the plugin README. Do not waive tool/schema/permission checks.
            expected = candidate["expected_mcp"]["toolNames"]
            require(isinstance(expected, list) and
                    all(tool not in expected for tool in HUBSPOT_818_ADDED_TOOLS),
                    "HubSpot upstream MCP expectations already modified")
            expected.extend(HUBSPOT_818_ADDED_TOOLS)
        candidate["candidate_manifest_digest"] = digest((root / "plugin.json").read_bytes())
        candidate["candidate_tree_digest"] = registry.directory_tree_digest(root)
        require(candidate["candidate_tree_digest"].startswith("sha256:"), "tree digest absent")
        outcomes.append({"product": name, "version": version,
                         "lock_sha256": descriptor["lock_digest"],
                         "manifest_sha256": candidate["candidate_manifest_digest"],
                         "tree_sha256": candidate["candidate_tree_digest"],
                         "npm_audit_vulnerabilities": 0})
    write_json(AUDIT, record)
    args.report.write_text(json.dumps({"stage": "ephemeral-preview-only",
                                      "unsigned": True, "outcomes": outcomes},
                                     indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outcomes))


if __name__ == "__main__":
    main()
