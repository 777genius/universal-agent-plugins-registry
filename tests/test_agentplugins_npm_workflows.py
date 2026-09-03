import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/agentplugins-npm-publish.yml"


class AgentpluginsNpmWorkflowContractTests(unittest.TestCase):
    def test_registry_publisher_is_explicitly_retired(self):
        workflow = yaml.safe_load(PUBLISH.read_text())
        self.assertEqual(workflow[True]["workflow_dispatch"]["inputs"]["verify_only"]["default"], True)
        self.assertEqual(set(workflow["jobs"]), {"retired"})
        body = PUBLISH.read_text()
        self.assertIn("npm publication is retired in the registry repository", body)
        self.assertNotIn("npm publish", body)
        self.assertNotIn("id-token: write", body)


if __name__ == "__main__":
    unittest.main()
