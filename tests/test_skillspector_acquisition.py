from __future__ import annotations

import hashlib
import math
import random
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts import discover_skillspector_sources as discovery
from scripts import skillspector_acquisition as acquisition
from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_reports as scanner
from scripts.build_bridges import PinnedRepository
from scripts.build_discovery_index import DiscoveryError, DiscoveryInputLimitError, materialize_package
from scripts.build_registry import directory_tree_digest
from scripts.discovery_checkpoint import CheckpointYield, WorkBudget
from tests.test_skillspector_reports import fixture_repository, git, item


class ColdAcquisitionTests(unittest.TestCase):
    def fixture(self, root, additions=None, *, symlink=False):
        mirrors, selected = fixture_repository(root, symlink=symlink)
        source = root / "source"
        for path, body in (additions or {}).items():
            target = source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        if additions:
            git(source, "add", ".")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "additional inert blobs")
            selected["sources"][0]["revision"] = git(source, "rev-parse", "HEAD")
            git(mirrors / "owner/repo.git", "fetch", str(source), selected["sources"][0]["revision"])
        mirror = mirrors / "owner/repo.git"
        # Without this the local server ignores --filter and masks cold-path bugs.
        git(mirror, "config", "uploadpack.allowFilter", "true")
        git(mirror, "config", "uploadpack.allowAnySHA1InWant", "true")
        pinned = PinnedRepository("owner/repo", selected["sources"][0]["revision"], mirrors, work_budget=WorkBudget(20))
        self.addCleanup(pinned.close)
        return pinned, selected["sources"][0]

    def read(self, pinned, **limits):
        return acquisition.bounded_package_files(pinned, "skills/demo", **{
            "max_files": 512, "max_file_bytes": 4 << 20, "max_tree_bytes": 4 << 20, **limits})

    def test_real_cold_promisor_batches_fetches_and_preserves_binary_modes_and_whole_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = bytes(range(256)) * 3 + b"\x00\n\r\n"
            additions = {f"skills/demo/data/f{n:03}.bin": bytes([n]) * (100 + n) for n in range(40)}
            additions.update({"skills/demo/binary.dat": binary, "skills/demo/duplicate.dat": binary})
            pinned, _ = self.fixture(root, additions)
            records = acquisition._tree_records(pinned, "skills/demo", 512, pinned.work_budget)
            object_ids = list(dict.fromkeys(oid for _, _, oid in records))
            self.assertTrue(all(value is None for value in acquisition._object_sizes(pinned, object_ids, pinned.work_budget).values()))
            trace = root / "git.trace"
            environment = acquisition._environment() | {"GIT_TRACE": str(trace)}
            with mock.patch.object(acquisition, "_environment", return_value=environment):
                files = self.read(pinned)
                again = self.read(pinned)
            fetches = [line for line in trace.read_text().splitlines() if "built-in: git " in line and " fetch " in line]
            self.assertEqual(len(fetches), math.ceil(len(object_ids) / acquisition.FETCH_CHUNK_OBJECTS))
            self.assertTrue(all("--stdin" in line and "--no-write-fetch-head" in line and "--no-recurse-submodules" in line
                                and "--no-auto-maintenance" in line for line in fetches))
            self.assertEqual(files, again)
            self.assertEqual(next(body for path, _, body in files if path == "binary.dat"), binary)
            self.assertEqual(next(mode for path, mode, _ in files if path == "evil.py"), 0o755)
            output = root / "materialized"
            output.mkdir()
            materialize_package(files, output, pinned.work_budget)
            self.assertEqual(directory_tree_digest(output), directory_tree_digest(root / "source/skills/demo"))

    def test_pinned_nfc_unicode_tree_is_fully_acquired_and_staged_without_dropping_files(self):
        """Three real Error cohorts use ordinary Unicode names, not broken Git transport."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            additions = {
                "skills/demo/references/WEB服务开发/HTTPClient-代理Proxy设置.md": b"proxy reference\n",
                "skills/demo/references/马斯克决策模式与行为分析.md": b"analysis reference\n",
            }
            pinned, _ = self.fixture(root, additions)
            files = self.read(pinned)
            self.assertEqual(len([path for path, _, _ in files if not path.isascii()]), 2)
            output = root / "scanned"
            output.mkdir()
            acquisition.materialize_scanned_files(files, output, pinned.work_budget)
            self.assertEqual(directory_tree_digest(output), directory_tree_digest(root / "source/skills/demo"))
            self.assertEqual((output / "references/WEB服务开发/HTTPClient-代理Proxy设置.md").read_bytes(),
                             b"proxy reference\n")
            # Directory installation remains intentionally ASCII-only.
            legacy = root / "legacy-package"
            legacy.mkdir()
            with self.assertRaisesRegex(DiscoveryError, "ASCII"):
                materialize_package(files, legacy, pinned.work_budget)

    def test_unsafe_unicode_or_nonportable_git_tree_paths_fail_before_hydration(self):
        paths = (
            "skills/demo/references/a\u0301.md",  # NFD ambiguity
            "skills/demo/references/bad?.md",
            "skills/demo/references/bad%20.md",
            "skills/demo/references/../escape.md",
            "skills/demo/references/.GIT/config",
            "skills/demo/references/CON.md",
            "skills/demo/references/trailing .",
            "skills/demo/references/back\\slash.md",
            "skills/demo/" + ("a" * 256) + ".md",
        )
        for path in paths:
            row = f"100644 blob {'a' * 40}\t{path}\0".encode("utf-8")
            with self.subTest(path=path), \
                 mock.patch.object(acquisition, "_run_git", return_value=row), \
                 mock.patch.object(acquisition, "_object_sizes") as sizes, \
                 mock.patch.object(acquisition, "_fetch_objects") as fetch, \
                 self.assertRaises(DiscoveryError):
                self.read(mock.Mock(work_budget=WorkBudget(5)))
            sizes.assert_not_called()
            fetch.assert_not_called()

    def test_unicode_casefold_collision_and_symlink_cannot_be_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            pinned, _ = self.fixture(Path(temporary), {
                "skills/demo/Ω.md": b"one", "skills/demo/ω.md": b"two",
            })
            with mock.patch.object(acquisition, "_object_sizes") as sizes, \
                 mock.patch.object(acquisition, "_fetch_objects") as fetch, \
                 self.assertRaisesRegex(DiscoveryError, "case-colliding"):
                self.read(pinned)
            sizes.assert_not_called()
            fetch.assert_not_called()

    def test_count_symlink_case_collision_and_invalid_oid_refuse_before_any_hydration(self):
        cases = ({"symlink": True}, {"additions": {"skills/demo/FILE": b"1", "skills/demo/file": b"2"}}, {})
        for options in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                pinned, _ = self.fixture(Path(temporary), **options)
                with mock.patch.object(acquisition, "_object_sizes") as sizes, \
                     mock.patch.object(acquisition, "_fetch_objects") as fetch, self.assertRaises(DiscoveryError):
                    self.read(pinned, max_files=1 if not options else 512)
                sizes.assert_not_called()
                fetch.assert_not_called()
        with mock.patch.object(acquisition, "_run_git", return_value=b"100644 blob invalid\tskills/demo/SKILL.md\0"), \
             mock.patch.object(acquisition, "_fetch_objects") as fetch, self.assertRaises(DiscoveryError):
            self.read(mock.Mock(work_budget=WorkBudget(5)))
        fetch.assert_not_called()

    def test_per_file_and_duplicate_path_total_limits_are_checked_before_materialization(self):
        for case in ("file", "duplicate"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                duplicate = b"same object\n" * 100
                pinned, _ = self.fixture(root, {"skills/demo/a": duplicate, "skills/demo/b": duplicate})
                originals = [path.read_bytes() for path in (root / "source/skills/demo").rglob("*") if path.is_file()]
                unique_total = sum(map(len, set(originals)))
                with self.assertRaises(DiscoveryInputLimitError):
                    self.read(pinned, max_file_bytes=10 if case == "file" else 4 << 20,
                        max_tree_bytes=unique_total if case == "duplicate" else 4 << 20)

    def test_fetch_pack_file_cap_is_enforced_by_child_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pinned, _ = self.fixture(root, {"skills/demo/large.bin": random.Random(7).randbytes(2 << 20)})
            with self.assertRaises(acquisition.AcquisitionTransferLimit):
                self.read(pinned, max_files=8, max_file_bytes=64, max_tree_bytes=64)

    def test_child_wrapper_respects_an_existing_lower_hard_file_limit(self):
        child = "import resource\nresource.setrlimit(resource.RLIMIT_FSIZE, (256, 256))\n" + \
            "exec(" + repr(acquisition.LIMITED_GIT) + ")"
        result = subprocess.run([sys.executable, "-c", child, "1024", "--version"],
            env=acquisition._environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(result.stdout.startswith(b"git version "))

    def test_running_git_obeys_the_shared_deadline_and_capture_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            pinned, _ = self.fixture(Path(temporary))
            started = time.monotonic()
            with self.assertRaises(CheckpointYield):
                acquisition._run_git(pinned, ["-c", "alias.wait=!sleep 10", "wait"], WorkBudget(0.05))
            self.assertLess(time.monotonic() - started, 2)
            with self.assertRaises(acquisition.AcquisitionTransferLimit):
                acquisition._run_git(pinned, ["cat-file", "--batch-all-objects", "--batch"],
                    pinned.work_budget, output_limit=1)

    def test_cumulative_pack_cap_includes_multiple_packs_but_excludes_initial_tree_pack(self):
        with tempfile.TemporaryDirectory() as temporary:
            pinned, _ = self.fixture(Path(temporary))
            initial = acquisition._pack_files(pinned)
            self.assertTrue(initial)
            self.assertEqual(acquisition._added_pack_bytes(pinned, initial), 0)
            # Simulate a server supplying two extra packs, each below the
            # process's per-file cap but together exceeding the transfer cap.
            def oversized_transfer(repository, object_ids, budget, remaining):
                for index in range(2):
                    (repository.root / f"objects/pack/extra-{index}.pack").write_bytes(b"x" * (remaining // 2 + 1))
            with mock.patch.object(acquisition, "_fetch_objects", side_effect=oversized_transfer), \
                 self.assertRaises(acquisition.AcquisitionTransferLimit):
                self.read(pinned)

    def test_incomplete_explicit_fetch_never_falls_back_to_lazy_network_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pinned, _ = self.fixture(root)
            trace = root / "git.trace"
            environment = acquisition._environment() | {"GIT_TRACE": str(trace)}
            with mock.patch.object(acquisition, "_environment", return_value=environment), \
                 mock.patch.object(acquisition, "_fetch_objects"), self.assertRaisesRegex(DiscoveryError, "did not supply"):
                self.read(pinned)
            self.assertFalse(any("built-in: git " in line and " fetch " in line for line in trace.read_text().splitlines()))

    def test_binary_batch_rejects_truncated_tampered_misidentified_or_trailing_bytes(self):
        content = b"binary\x00\n\xff\r\n"
        oid = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
        header = f"{oid} blob {len(content)}\n".encode()
        body = header + content + b"\n"
        self.assertEqual(acquisition._decode_blobs(body, [oid], {oid: len(content)}), {oid: content})
        for malformed in (body[:-1], body + b"extra", body.replace(content, b"X" * len(content)),
                          body.replace(oid.encode(), b"a" * 40, 1)):
            with self.subTest(body=malformed), self.assertRaises(DiscoveryError):
                acquisition._decode_blobs(malformed, [oid], {oid: len(content)})

    def test_existing_shared_deadline_and_profile_digests_are_preserved(self):
        budget = WorkBudget(120, monotonic=lambda: 0)
        budget.monotonic = lambda: 121
        with mock.patch.object(acquisition.subprocess, "Popen") as launch, self.assertRaises(CheckpointYield):
            acquisition._run_git(mock.Mock(), ["status"], budget)
        launch.assert_not_called()
        self.assertEqual(coverage.PREPARATION_SECONDS, 120)
        self.assertEqual(scanner.PROFILES, {key: {"id": key, "digest": scanner.sha256_digest(scanner.canonical_json(document))}
            for key, document in scanner.PROFILE_DOCUMENTS.items()})

    def test_transfer_limit_is_explicit_and_retries_extended_only_once(self):
        subject = item()
        with mock.patch.object(coverage, "bounded_package_files", side_effect=acquisition.AcquisitionTransferLimit("cap")):
            standard = coverage.scan_selected(Path("/never-run"), subject, mock.Mock(), WorkBudget(2100))
            extended = coverage.scan_selected(Path("/never-run"), subject, mock.Mock(), WorkBudget(2100),
                profile_id=scanner.EXTENDED_PROFILE["id"])
        self.assertIsNone(standard["source"]["content_digest"])
        self.assertIsNone(standard["execution"]["analysis_seconds"])
        self.assertEqual(standard["coverage"]["reasons"][0]["code"], "acquisition_transfer_limit")
        self.assertTrue(standard["coverage"]["reasons"][0]["retryable"])
        first = coverage.make_attempt(subject, standard)
        self.assertEqual(first["next_profile"], scanner.EXTENDED_PROFILE["id"])
        final = coverage.make_attempt(subject, extended, first)
        self.assertEqual(final["disposition"], "exhausted")
        self.assertIsNone(final["next_attempt_at"])

    def test_discovery_batches_only_validated_skill_documents_and_keeps_exact_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            additions = {f"catalog/s{n:03}/SKILL.md": f"---\nname: Skill {n}\n---\n".encode() for n in range(40)}
            additions["unrelated/huge.bin"] = b"x" * (discovery.MAX_DOCUMENT_BYTES + 1)
            pinned, _ = self.fixture(root, additions)
            trace = root / "git.trace"
            environment = acquisition._environment() | {"GIT_TRACE": str(trace)}
            with mock.patch.object(acquisition, "_environment", return_value=environment):
                names, invalid = discovery.skill_documents(pinned, pinned.work_budget)
            self.assertEqual(len(names), 41)
            self.assertEqual(names["Skill 39"], ["catalog/s039"])
            self.assertEqual(invalid, [])
            fetches = [line for line in trace.read_text().splitlines() if "built-in: git " in line and " fetch " in line]
            self.assertEqual(len(fetches), 2)
            # Exact-path discovery must not hydrate every other SKILL.md.
            fresh = PinnedRepository("owner/repo", pinned.revision, root / "mirrors", work_budget=WorkBudget(10))
            self.addCleanup(fresh.close)
            with mock.patch.object(acquisition, "_fetch_objects", wraps=acquisition._fetch_objects) as fetch:
                names, invalid = discovery.skill_documents(fresh, fresh.work_budget, ["catalog/s039/SKILL.md"])
            self.assertEqual(names, {"Skill 39": ["catalog/s039"]})
            self.assertEqual(invalid, [])
            self.assertEqual(sum(len(call.args[1]) for call in fetch.call_args_list), 1)

    def test_invalid_metadata_document_does_not_hide_other_roots_but_lfs_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pointer = acquisition.LFS_HEADER + b"oid sha256:" + b"a" * 64 + b"\nsize 1\n"
            pinned, _ = self.fixture(root, {"catalog/lfs/SKILL.md": pointer, "skills/demo/payload.bin": pointer})
            names, invalid = discovery.skill_documents(pinned, pinned.work_budget)
            self.assertEqual(names, {"demo": ["skills/demo"]})
            self.assertEqual(invalid, ["catalog/lfs/SKILL.md"])
            with self.assertRaisesRegex(DiscoveryError, "LFS pointer"):
                self.read(pinned)


class OnlineBlobFetchRetryTests(unittest.TestCase):
    """Transport-only retries; immutable object and resource checks remain separate."""

    def run_fetch(self, failures, *, origin=None, remaining=20, mutate_pack=False, mutate_loose=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packs = root / "objects" / "pack"
            packs.mkdir(parents=True)
            source = mock.Mock(root=root, repository="owner/repo")
            remote = origin or "https://github.com/owner/repo.git"
            budget = mock.Mock()
            budget.remaining.return_value = remaining
            calls = []

            def fake_git(_source, arguments, _budget, **options):
                if arguments == ["remote", "get-url", "origin"]:
                    return (remote + "\n").encode("utf-8")
                self.assertIn("fetch", arguments)
                calls.append((arguments, options))
                number = len(calls)
                if number <= len(failures):
                    if mutate_pack and number == 1:
                        (packs / "unexpected.pack").write_bytes(b"changed")
                    if mutate_loose and number == 1:
                        loose = packs.parent / "aa"
                        loose.mkdir()
                        (loose / ("b" * 38)).write_bytes(b"changed")
                    raise failures[number - 1]
                return b""

            result = None
            with mock.patch.object(acquisition, "_run_git", side_effect=fake_git), \
                    mock.patch.object(acquisition.time, "sleep") as sleep:
                try:
                    acquisition._fetch_objects(source, ["a" * 40], budget, 4 << 20)
                except Exception as error:
                    result = error
            return result, calls, [call.args[0] for call in sleep.call_args_list]

    def test_online_429_then_success_retries_exact_oids_with_same_cap(self):
        error, calls, sleeps = self.run_fetch([
            acquisition.BridgeError("The requested URL returned error: 429")
        ])
        self.assertIsNone(error)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [0.25])
        for arguments, options in calls:
            self.assertEqual(options["input_bytes"], ("a" * 40 + "\n").encode())
            self.assertEqual(options["file_limit"], 4 << 20)
            self.assertIn("protocol.allow=never", arguments)
            self.assertIn("protocol.https.allow=always", arguments)

    def test_repeated_transient_failure_is_bounded_and_not_reported_as_success(self):
        error, calls, sleeps = self.run_fetch([
            acquisition.BridgeError("The requested URL returned error: 503")
        ] * 3)
        self.assertIsInstance(error, acquisition.BridgeError)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [0.25, 0.5])

    def test_permanent_statuses_and_unsupported_remote_do_not_retry(self):
        for message in (
            "The requested URL returned error: 403",
            "The requested URL returned error: 404",
            "fatal: couldn't find remote ref",
            "not our ref",
        ):
            with self.subTest(message=message):
                error, calls, sleeps = self.run_fetch([acquisition.BridgeError(message)])
                self.assertIsInstance(error, acquisition.BridgeError)
                self.assertEqual(len(calls), 1)
                self.assertEqual(sleeps, [])
        with tempfile.TemporaryDirectory() as offline:
            error, calls, sleeps = self.run_fetch(
                [acquisition.BridgeError("The requested URL returned error: 503")],
                origin=offline,
            )
            self.assertIsInstance(error, acquisition.BridgeError)
            self.assertEqual(len(calls), 1)
            self.assertEqual(sleeps, [])

    def test_budget_or_pack_changes_prevent_unbounded_transport_retry(self):
        # The retry cutoff is inclusive: at delay + one reserved second,
        # the original transport failure must remain the only outcome.
        for scenario in ({"remaining": 1.1}, {"remaining": 1.25},
                         {"mutate_pack": True}, {"mutate_loose": True}):
            with self.subTest(scenario=scenario):
                error, calls, sleeps = self.run_fetch(
                    [acquisition.BridgeError("The requested URL returned error: 502")],
                    **scenario,
                )
                self.assertIsInstance(error, acquisition.BridgeError)
                self.assertEqual(len(calls), 1)
                self.assertEqual(sleeps, [])
        error, calls, sleeps = self.run_fetch(
            [acquisition.BridgeError("The requested URL returned error: 502")],
            remaining=1.251,
        )
        self.assertIsNone(error)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [0.25])

    def test_real_budget_expiring_during_retry_never_launches_another_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "objects" / "pack").mkdir(parents=True)
            source = mock.Mock(root=root, repository="owner/repo")
            clock = [0.0]
            budget = WorkBudget(2, monotonic=lambda: clock[0])
            fetches = []

            def fake_git(_source, arguments, _budget, **_options):
                if arguments == ["remote", "get-url", "origin"]:
                    return b"https://github.com/owner/repo.git\n"
                fetches.append(arguments)
                raise acquisition.BridgeError("The requested URL returned error: 503")

            def expire(_seconds):
                clock[0] = 2.0

            with mock.patch.object(acquisition, "_run_git", side_effect=fake_git), \
                    mock.patch.object(acquisition.time, "sleep", side_effect=expire), \
                    self.assertRaises(CheckpointYield):
                acquisition._fetch_objects(source, ["a" * 40], budget, 4 << 20)
            self.assertEqual(len(fetches), 1)

    def test_size_and_transfer_limits_are_never_treated_as_transport_retry(self):
        for exception in (
            acquisition.AcquisitionTransferLimit("Git pack exceeded cap"),
            DiscoveryInputLimitError("Source exceeds file cap"),
        ):
            with self.subTest(exception=type(exception).__name__):
                error, calls, sleeps = self.run_fetch([exception])
                self.assertIs(error, exception)
                self.assertEqual(len(calls), 1)
                self.assertEqual(sleeps, [])


if __name__ == "__main__":
    unittest.main()
