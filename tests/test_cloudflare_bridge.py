"""Cloudflare's complete portable skill package, not just its API endpoint."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_bridges import validate_components
from build_registry import load_directory_source, resolve_directory


SKILLS = sorted([
    "agents-sdk", "cloudflare-email-service", "cloudflare-one-migrations",
    "cloudflare-one", "cloudflare", "durable-objects", "sandbox-migrate-to-next",
    "sandbox-next", "sandbox-stable", "turnstile-spin", "web-perf",
    "workers-best-practices", "wrangler",
])


class CloudflareBridgeTests(unittest.TestCase):
    def test_complete_skills_and_original_mcp_are_packaged(self) -> None:
        recipe = yaml.safe_load((ROOT / "bridges/cloudflare/bridge.yaml").read_text())
        package = ROOT / "plugins/cloudflare"
        inventory = validate_components(package, recipe)
        self.assertEqual(inventory["skills"], SKILLS)
        self.assertEqual(inventory["mcp_servers"], ["cloudflare"])
        self.assertEqual(inventory["executables"], [
            "skills/turnstile-spin/scripts/auth-probe.sh",
            "skills/turnstile-spin/scripts/persist-skill.sh",
            "skills/turnstile-spin/scripts/validate.sh",
            "skills/turnstile-spin/scripts/widget-create.sh",
        ])
        config = json.loads((package / "mcp.json").read_text())
        self.assertEqual(config["mcpServers"], {
            "cloudflare": {"type": "streamable-http", "url": "https://mcp.cloudflare.com/mcp"},
        })
        self.assertTrue((package / "LICENSE").is_file())
        self.assertTrue((package / "NOTICE").is_file())
        self.assertEqual({item["path"] for item in recipe["overlay_replacements"]}, {
            "skills/cloudflare/SKILL.md", "skills/turnstile-spin/SKILL.md",
        })

    def test_relocated_reference_lists_preserve_all_existing_targets(self) -> None:
        references = {
            "cloudflare": [f"{name}/README.md" for name in (
                "workers", "pages", "d1", "durable-objects", "workers-ai",
            )],
            "turnstile-spin": [f"{name}.md" for name in (
                "vanilla-html", "nextjs-app", "nextjs-pages", "astro", "sveltekit", "hugo",
            )],
        }
        for skill, names in references.items():
            root = ROOT / "plugins/cloudflare/skills" / skill
            text = (root / "SKILL.md").read_text()
            metadata = yaml.safe_load(text.split("---", 2)[1])
            self.assertNotIn("references", metadata)
            self.assertIn("Modified by 777genius for this community bridge", text)
            for name in names:
                with self.subTest(skill=skill, reference=name):
                    self.assertIn(f"](references/{name})", text)
                    self.assertTrue((root / "references" / name).is_file())

    def test_openai_projection_preserves_license_and_attribution(self) -> None:
        portable = ROOT / "plugins/cloudflare"
        projected = ROOT / "compat/openai/plugins/cloudflare"
        for name in ("LICENSE", "NOTICE"):
            with self.subTest(name=name):
                self.assertEqual((projected / name).read_bytes(), (portable / name).read_bytes())

    def test_short_names_select_bridges_without_reassigning_old_distributions(self) -> None:
        source = load_directory_source()
        original = copy.deepcopy(source)
        for product in ("cloudflare", "cloudflare-bindings", "cloudflare-observability"):
            with self.subTest(product=product):
                selected = resolve_directory(source, product, ["codex", "cursor", "kiro"])
                self.assertEqual(selected["distribution_id"], f"777genius/{product}-bridge")
                legacy = resolve_directory(source, f"777genius/{product}", ["codex", "cursor", "kiro"])
                self.assertEqual(legacy["distribution_id"], f"777genius/{product}")
                self.assertEqual(legacy["release_sequence"], 1)
        self.assertEqual(source, original)
        distributions = {item["id"]: item for item in source["distributions"]}
        full = distributions["777genius/cloudflare-bridge"]
        self.assertEqual(full["kind"], "community_bridge")
        self.assertEqual(full["releases"][0]["components"], ["mcp", "skills"])
        self.assertEqual(distributions["777genius/cloudflare"]["releases"][0]["components"], ["mcp"])
        for policy in full["release_policies"]:
            self.assertEqual(policy["current_evidence"], [])  # No OAuth/runtime claim from packaging tests.
            self.assertTrue(all(item["authentication"] == "required" for item in policy["targets"]))
            self.assertNotIn("chatgpt", [item["client"] for item in policy["targets"]])


if __name__ == "__main__":
    unittest.main()
