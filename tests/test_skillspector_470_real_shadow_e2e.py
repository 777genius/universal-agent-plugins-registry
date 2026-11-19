"""Fail-closed admission tests for the single real #470 read-only scanner canary."""
import copy
import hashlib
import unittest

from scripts.skillspector_470_real_shadow_e2e import git_blob, validate_no_llm_scan


def real_report():
    return {
        "metadata": {"skillspector_version": "2.13.1", "llm_requested": False,
                     "inference_usage": []},
        "execution_successful": True,
        "analysis_completeness": {
            "status": "partial", "is_complete": False, "execution_successful": True,
            "findings_before_filtering": 1, "findings_after_filtering": 1,
        },
        "issues": [{"id": "security-evidence"}],
        "suppressed": [], "suppressed_count": 0,
    }


class RealShadowAdmissionTests(unittest.TestCase):
    def test_git_blob_identity_includes_length_and_content(self):
        body = b"canonical source\n"
        self.assertEqual(
            git_blob(body),
            hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest(),
        )
        self.assertNotEqual(git_blob(body), git_blob(body + b"\n"))

    def test_accept_real_incomplete_scan_without_certification(self):
        self.assertEqual(validate_no_llm_scan(real_report(), 1), "partial")
        complete = real_report()
        complete["analysis_completeness"].update(status="complete", is_complete=True)
        self.assertEqual(validate_no_llm_scan(complete, 0), "complete")

    def test_reject_nonzero_failure_and_boolean_exit(self):
        for code in (-1, 2, 124, True, False, None):
            with self.subTest(code=code), self.assertRaises(ValueError):
                validate_no_llm_scan(real_report(), code)

    def test_reject_spoofed_analyzer_or_llm(self):
        for field, value in (
            ("skillspector_version", "2.13.4"),
            ("llm_requested", True),
            ("inference_usage", [{"provider": "remote"}]),
            ("inference_usage", None),
        ):
            changed = copy.deepcopy(real_report())
            changed["metadata"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_no_llm_scan(changed, 1)

    def test_reject_missing_execution_or_inconsistent_coverage(self):
        for field, value in (
            ("status", "complete"),
            ("status", "complete_with_caveats"),
            ("status", "error"),
            ("is_complete", True),
            ("is_complete", None),
            ("execution_successful", False),
        ):
            changed = copy.deepcopy(real_report())
            changed["analysis_completeness"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_no_llm_scan(changed, 1)
        changed = real_report()
        changed["execution_successful"] = False
        with self.assertRaises(ValueError):
            validate_no_llm_scan(changed, 1)

    def test_reject_missing_findings_list_or_metadata(self):
        for field, value in (("issues", None), ("issues", {}),
                             ("metadata", None), ("analysis_completeness", [])):
            changed = real_report()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_no_llm_scan(changed, 1)


if __name__ == "__main__":
    unittest.main()
