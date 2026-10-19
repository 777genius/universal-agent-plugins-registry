import copy
import unittest

from scripts.export_saved_discovery_scan import export


class SavedDiscoveryExportTests(unittest.TestCase):
    def inputs(self):
        observed = "2026-10-03T03:02:03Z"
        acquisition = {
            "binding": {"source_commit": "0fb86410740472691636630984c5d1dccaf89f85", "mode": "discover"},
            "generated_at": observed, "payload": {"complete": True}, "payload_digest": "sha256:" + "a" * 64,
        }
        validation = {
            "generated_at": observed,
            "binding": "sha256:5df2987364289d53a628ee63579213b0176532c5c126616c95788f5b7e37924e",
            "payload_digest": "sha256:" + "b" * 64,
            "payload": {"results": {"owner/partial": {"complete": False, "records": [["bad", {"availability": "available"}]]}}},
        }
        return acquisition, validation

    def test_partial_repository_is_excluded_before_record_export(self):
        acquisition, validation = self.inputs()
        result = export(acquisition, validation)
        self.assertEqual(result["records"], [])
        self.assertFalse(result["scan_complete"])
        self.assertEqual(result["observed_at"], validation["generated_at"])
        self.assertEqual(result["complete_cached_repositories"], 0)

    def test_source_and_original_observation_cannot_be_rebound(self):
        acquisition, validation = self.inputs()
        for target, field in ((acquisition, "generated_at"), (validation, "generated_at"), (validation, "binding")):
            altered = copy.deepcopy(target)
            altered[field] = "2026-10-04T03:02:03Z"
            with self.assertRaises(ValueError):
                export(altered if target is acquisition else acquisition,
                       altered if target is validation else validation)


if __name__ == "__main__":
    unittest.main()
