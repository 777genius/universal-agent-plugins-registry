"""Fail-closed CI admission for optional native package/Pi/SkillSpector E2E.

The full validate workflow remains unfiltered; this only defers independent,
expensive checks while a PR is Draft. Ready, main and explicit dispatch retain
their original evidence paths.
"""
from copy import deepcopy
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
READY = ("opened", "synchronize", "reopened", "ready_for_review")
GATE = {
    "simple": "github.event_name != 'pull_request' || github.event.pull_request.draft != true",
    "fork": ("github.event_name != 'pull_request' || "
             "(github.event.pull_request.head.repo.full_name == github.repository && "
             "github.event.pull_request.draft != true)"),
    "same-repo": ("github.event.pull_request.head.repo.full_name == github.repository && "
                  "github.event.pull_request.draft != true"),
    "pi": ("github.event_name == 'workflow_dispatch' || "
           "(github.event.pull_request.head.repo.full_name == github.repository && "
           "github.event.pull_request.draft != true)"),
    "pi-always": ("always() && (github.event_name == 'workflow_dispatch' || "
                  "(github.event.pull_request.head.repo.full_name == github.repository && "
                  "github.event.pull_request.draft != true))"),
}
# name -> (exact job roster and gates, manual, push-to-main)
CASES = {
    "cloudflare-package-e2e.yml": ({"lifecycle": "simple"}, True, False),
    "playwright-package-e2e.yml": ({
        "lifecycle": "simple", "live-readonly": "simple", "browser-boundary": "simple"}, True, False),
    "firecrawl-package-e2e.yml": ({"lifecycle": "simple", "live-readonly": "simple"}, True, False),
    "tinyfish-package-e2e.yml": ({"lifecycle": "simple"}, True, False),
    "pi-catalog-materialization-e2e.yml": ({
        "native-materialization": "pi", "exact-coverage": "pi-always"}, True, False),
    "pi-modern-candidate-3os.yml": ({"candidate-writer": "fork"}, False, True),
    "runtime-remediation-qualification.yml": ({"qualify": "simple"}, True, False),
    "skillspector-2134-qualification.yml": ({"qualify": "simple"}, True, False),
    "skillspector-2134-sql-api-e2e.yml": ({"qualify": "simple"}, True, False),
    "skillspector-2134-json-version-e2e.yml": ({"qualify": "simple"}, True, False),
    "skillspector-470-real-shadow-e2e.yml": ({
        "goframe-immutable-shadow": "same-repo"}, False, False),
    "skillspector-470-requalification-e2e.yml": ({"audit": "fork"}, True, False),
    "skillspector-470-exhausted-unicode-e2e.yml": ({
        "pinned-three-root-acquisition": "same-repo"}, False, False),
    "skillspector-unicode-e2e.yml": ({
        "pinned-five-root-acquisition": "same-repo"}, False, False),
    "skillspector-live-cohort-preflight.yml": ({
        "current-signed-nine-source-pins": "simple"}, True, True),
    "skillspector-cohort9-security-parity.yml": ({
        "immutable-evidence-parity": "simple"}, True, False),
}


def check_policy(filename, source):
    expected_jobs, manual, main_push = CASES[filename]
    # Do not silently accept YAML duplicate event keys (PyYAML keeps last).
    if len(re.findall(r"^    types:", source, flags=re.M)) != 1:
        raise ValueError("duplicate or missing PR event list")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    if not isinstance(workflow, dict):
        raise ValueError("invalid workflow")
    events = workflow.get("on", {})
    if not isinstance(events, dict):
        raise ValueError("missing triggers")
    pr = events.get("pull_request", {})
    if tuple(pr.get("types", [])) != READY or not pr.get("paths"):
        raise ValueError("ready source and path filters required")
    if ("workflow_dispatch" in events) != manual:
        raise ValueError("manual dispatch changed")
    if ("push" in events) != main_push:
        raise ValueError("main push changed")
    if main_push and events["push"].get("branches") != ["main"]:
        raise ValueError("production main branch changed")
    if "workflow_call" in events or "schedule" in events or "pull_request_target" in events:
        raise ValueError("unexpected privileged or scheduled trigger")
    jobs = workflow.get("jobs", {})
    if set(jobs) != set(expected_jobs):
        raise ValueError("native test graph changed")
    for job, mode in expected_jobs.items():
        entry = jobs[job]
        if entry.get("if") != GATE[mode]:
            raise ValueError("missing strict Draft gate on " + job)
        if "continue-on-error" in entry:
            raise ValueError("E2E failure override")
        if int(entry.get("timeout-minutes", "0")) <= 0:
            raise ValueError("native timeout removed")
    if filename == "pi-catalog-materialization-e2e.yml":
        native = jobs["native-materialization"]
        if native["strategy"]["matrix"]["os"] != ["ubuntu-24.04", "macos-15", "windows-2025"]:
            raise ValueError("missing Pi operating system")
        if native["strategy"]["matrix"]["shard"] != ["0", "1", "2"]:
            raise ValueError("missing Pi shard")
        if jobs["exact-coverage"].get("needs") != ["native-materialization"]:
            raise ValueError("Pi 72-source evidence aggregation changed")
        if "needs.native-materialization.result" not in str(jobs["exact-coverage"]["steps"]):
            raise ValueError("Pi E2E aggregate can accept a missing native result")
    return workflow


class DeferredNativeCIContract(unittest.TestCase):
    def test_all_optional_workflows_defer_draft_and_keep_real_e2e(self):
        for name in CASES:
            with self.subTest(name=name):
                check_policy(name, (WORKFLOWS / name).read_text())

    def test_mutations_fail_closed(self):
        name = "pi-catalog-materialization-e2e.yml"
        original = (WORKFLOWS / name).read_text()
        for changed in (
            original.replace(", ready_for_review", "", 1),
            original.replace("    types: [", "    types: [opened]\n    types: [", 1),
            original.replace(GATE["pi"], "true", 1),
            original.replace(GATE["pi-always"], "always()", 1),
            original.replace("shard: [0, 1, 2]", "shard: [0, 1]", 1),
            original.replace("needs: [native-materialization]", "needs: []", 1),
            original.replace("  workflow_dispatch:", "  removed_dispatch:", 1),
        ):
            with self.subTest(change=changed[:70]), self.assertRaises(ValueError):
                check_policy(name, changed)
        name = "pi-modern-candidate-3os.yml"
        original = (WORKFLOWS / name).read_text()
        for changed in (
            original.replace(GATE["fork"], GATE["simple"], 1),
            original.replace("branches: [main]", "branches: [staging]", 1),
        ):
            with self.assertRaises(ValueError):
                check_policy(name, changed)

    def test_protected_validate_and_signed_publisher_unchanged(self):
        validation = yaml.load((WORKFLOWS / "validate.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertIn("pull_request", validation["on"])
        self.assertEqual(validation["on"]["push"]["branches"], ["main"])
        self.assertEqual(
            set(validation["jobs"]),
            {"npm-facade", "bridge-reproduction", "portable-catalog", "agentplugins-chatgpt-catalog-v2"},
        )
        for job in validation["jobs"].values():
            self.assertNotIn("if", job)
        publisher = yaml.load((WORKFLOWS / "directory-publication.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertIn("push", publisher["on"])
        self.assertIn("schedule", publisher["on"])
        self.assertIn("workflow_dispatch", publisher["on"])


if __name__ == "__main__":
    unittest.main()
