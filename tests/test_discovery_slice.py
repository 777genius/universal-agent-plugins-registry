"""The shell transport must never confuse a yielded slice with a candidate."""
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run_discovery_slice.sh"
STUB = r'''import os,sys
from pathlib import Path
args=sys.argv[1:]
Path('../invoked').write_text('\n'.join(args))
status=int(os.environ['SLICE_STATUS'])
if status in (0,3):
    Path(args[args.index('--output')+1]).write_text('candidate-bytes')
    Path(args[args.index('--diagnostics-output')+1]).write_text('[]')
sys.exit(status)
'''


class DiscoverySliceTests(unittest.TestCase):
    def run_slice(self, root, status, phase="validate", **extra):
        source = root / "source"
        (source / "scripts").mkdir(parents=True, exist_ok=True)
        (source / "scripts/build_discovery_index.py").write_text(STUB)
        env_file = root / "environment"
        env_file.write_text("")
        environment = {**os.environ, "MODE": "discover", "PHASE_BUDGET_MINUTES": "300", "DISCOVERY_PHASE_FINISHED": "false",
                       "GITHUB_ENV": str(env_file), "SLICE_STATUS": str(status), **extra}
        result = subprocess.run(["bash", str(SCRIPT), phase], cwd=source, env=environment,
                                capture_output=True, text=True)
        return result, env_file.read_text()

    def test_yield_does_not_mark_finished_or_create_candidate(self):
        # Red if exit4 could make the workflow publish a partial result.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, environment = self.run_slice(root, 4)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(environment, "")
            self.assertFalse((root / "candidate.json").exists())
            arguments = (root / "invoked").read_text().splitlines()
            self.assertEqual(arguments[arguments.index("--work-budget-seconds") + 1], "1800")
            self.assertEqual(arguments[arguments.index("--repository-workers") + 1], "8")

    def test_finished_candidate_preserves_complete_vs_incomplete_boundary(self):
        for status, complete in ((0, "true"), (3, "false")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                result, environment = self.run_slice(Path(temporary), status)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("DISCOVERY_PHASE_FINISHED=true\n", environment)
                self.assertIn(f"DISCOVERY_CANDIDATE_COMPLETE={complete}\n", environment)
                digest = hashlib.sha256(b"candidate-bytes").hexdigest()
                self.assertIn(f"DISCOVERY_CANDIDATE_DIGEST=sha256:{digest}\n", environment)

    def test_error_and_timeout_remain_fatal_and_acquisition_rejects_status3(self):
        for status, phase in ((1, "validate"), (124, "validate"), (3, "acquire")):
            with self.subTest(status=status, phase=phase), tempfile.TemporaryDirectory() as temporary:
                result, environment = self.run_slice(Path(temporary), status, phase)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(environment, "")

    def test_wall_budget_includes_previous_slices_and_refuses_more_work(self):
        # Red if each new slice resets the overall phase's bounded budget.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".discovery-validate-started").write_text("1\n")
            result, environment = self.run_slice(root, 0)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("wall budget exhausted", result.stdout)
            self.assertFalse((root / "invoked").exists())
            self.assertEqual(environment, "")

    def test_yield_refuses_stale_candidate_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "candidate.json").write_text("untrusted stale output")
            result, environment = self.run_slice(root, 4)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(environment, "")
