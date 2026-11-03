"""Git's own tree encoder is the oracle; no network or report scanning occurs."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr
from unittest import mock
from pathlib import Path

from scripts import skillspector_publication_transport as transport
from scripts.directory_publication import PublicationError, canonical_json
from tests.test_skillspector_coverage import FakeGitHub as LegacyFakeGitHub


FIXTURE = Path(__file__).parent / "fixtures/skillspector-publication-tree-2026-10-28.json"


class GitTreeStore:
    def __init__(self, root):
        self.root, self.entries = Path(root), {}
        subprocess.run(["git", "init", "--bare", "--quiet", str(self.root)], check=True)

    def write(self, entries):
        body = b"".join(f"{row['mode']} {row['type']} {row['sha']}\t{row['path']}".encode() + b"\0"
                        for row in entries)
        sha = subprocess.check_output(["git", "-C", str(self.root), "mktree", "--missing", "-z"], input=body).decode().strip()
        self.entries[sha] = copy.deepcopy(entries)
        return sha

    def build(self, files):
        node = {}
        for path, sha in files.items():
            parent = node
            parts = path.split("/")
            for part in parts[:-1]:
                parent = parent.setdefault(part, {})
            parent[parts[-1]] = sha
        def tree(children):
            return self.write([{"path": name, "mode": "040000" if isinstance(value, dict) else "100644",
                "type": "tree" if isinstance(value, dict) else "blob",
                "sha": tree(value) if isinstance(value, dict) else value} for name, value in children.items()])
        return tree(node)

    def flatten(self, sha):
        output = subprocess.check_output(["git", "-C", str(self.root), "ls-tree", "-r", "-z", sha])
        files = {}
        for row in output.split(b"\0"):
            if row:
                header, path = row.split(b"\t")
                mode, kind, oid = header.split()
                if mode != b"100644" or kind != b"blob":
                    raise AssertionError("unexpected final tree entry")
                files[path.decode()] = oid.decode()
        return files


class FakeGitHub(LegacyFakeGitHub):
    """The publication API contract backed by independent native Git objects."""
    def __init__(self, root, *, create_response_limit=None, **kwargs):
        super().__init__(**kwargs)
        self.store = GitTreeStore(root)
        self.created = set()
        self.assembly_calls = []
        self.create_response_limit = create_response_limit

    def request(self, method, path, data=None):
        if method == "GET" and path.startswith("git/trees/") and path.removeprefix("git/trees/") in self.created:
            self.calls.append((method, path, copy.deepcopy(data)))
            sha = path.removeprefix("git/trees/")
            return {"sha": sha, "truncated": False, "tree": copy.deepcopy(self.store.entries[sha])}
        if (method, path) != ("POST", "git/trees"):
            return super().request(method, path, data)
        self.calls.append((method, path, copy.deepcopy(data)))
        inline = any("content" in row for row in data["tree"])
        assert len(data["tree"]) <= transport.MAX_TREE_ENTRIES
        if not inline:
            assert len(canonical_json(data)) <= transport.MAX_TREE_REQUEST_BYTES
            assert all("/" not in row["path"] for row in data["tree"])
            self.assembly_calls.append(copy.deepcopy(data))
        entries = {}
        if "base_tree" in data:
            assert data["base_tree"] in self.created, "base must be a newly created prefix"
            entries.update({row["path"]: row for row in self.store.entries[data["base_tree"]]})
        for row in data["tree"]:
            row = dict(row)
            if "content" in row:
                body = row.pop("content").encode()
                row["sha"] = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
            entries[row["path"]] = row
        rows = list(entries.values())
        sha = self.store.write(rows)
        self.created.add(sha)
        limit = self.create_response_limit
        return {"sha": sha, "truncated": limit is not None and len(rows) > limit,
                "tree": rows if limit is None else rows[:limit]}


class TreeTests(unittest.TestCase):
    def test_truncated_create_response_is_verified_with_complete_nonrecursive_read(self):
        files = {f"file{number:04d}": "a" * 40 for number in range(1087)}
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git", create_response_limit=1000)
            expected = github.store.build(files)
            result = transport.create_filtered_tree(github, files)
            self.assertEqual(result["sha"], expected)
            self.assertEqual(github.store.flatten(result["sha"]), files)
            self.assertEqual([method for method, _, _ in github.calls], ["POST", "GET"] * 9)
            self.assertTrue(all("?" not in path for method, path, _ in github.calls if method == "GET"))

    def test_create_listing_is_not_used_instead_of_independent_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git")
            original = github.request
            def request(method, path, data=None):
                value = original(method, path, data)
                return {"sha": value["sha"]} if method == "POST" else value
            github.request = request
            result = transport.create_filtered_tree(github, {"file": "a" * 40})
            self.assertEqual(github.store.flatten(result["sha"]), {"file": "a" * 40})
            self.assertEqual([method for method, _, _ in github.calls], ["POST", "GET"])

    def test_newly_uploaded_tree_can_be_temporarily_invisible_on_get(self):
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git")
            original = github.request
            lookups = []
            def request(method, path, data=None):
                if method == "GET" and path.startswith("git/trees/"):
                    lookups.append(path)
                    if len(lookups) <= 2:
                        return None  # GitHub returns HTTP 404 during object propagation.
                return original(method, path, data)
            github.request = request
            with mock.patch.object(transport.time, "sleep") as pause:
                result = transport.create_filtered_tree(github, {"file": "a" * 40})
            self.assertEqual(github.store.flatten(result["sha"]), {"file": "a" * 40})
            self.assertEqual(len(lookups), 3)
            self.assertEqual([call.args for call in pause.call_args_list], [(1,), (2,)])

    def test_stale_verification_sha_retries_until_exact_object_arrives(self):
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git")
            original = github.request
            lookups = []
            def request(method, path, data=None):
                if method == "GET" and path.startswith("git/trees/"):
                    lookups.append(path)
                    if len(lookups) <= 2:
                        value = original(method, path, data)
                        return {**value, "sha": "f" * 40}
                return original(method, path, data)
            github.request = request
            with mock.patch.object(transport.time, "sleep") as pause:
                result = transport.create_filtered_tree(github, {"file": "a" * 40})
            self.assertEqual(github.store.flatten(result["sha"]), {"file": "a" * 40})
            self.assertEqual(len(lookups), 3)
            self.assertEqual([call.args for call in pause.call_args_list], [(1,), (2,)])

    def test_permanently_unreadable_tree_never_publishes_unverified_data(self):
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git")
            original = github.request
            lookups = []
            def request(method, path, data=None):
                if method == "GET" and path.startswith("git/trees/"):
                    lookups.append(path)
                    return None
                return original(method, path, data)
            github.request = request
            with mock.patch.object(transport.time, "sleep") as pause:
                with self.assertRaisesRegex(PublicationError, "not visible after bounded verification retries"):
                    transport.create_filtered_tree(github, {"file": "a" * 40})
            self.assertEqual(len(lookups), 5)
            self.assertEqual([call.args for call in pause.call_args_list], [(1,), (2,), (4,), (8,)])
            self.assertFalse(any(path in {"git/commits", "git/refs"} or path.startswith("git/refs/")
                                 for _, path, _ in github.calls))

    def test_exact_real_1297_file_artifact_preserves_all_673_legacy_files(self):
        fixture = json.loads(FIXTURE.read_text())
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git")
            legacy = {path: sha for path, sha in fixture["files"].items() if "/v3/" not in path}
            github.store.build(legacy)
            result = transport.create_filtered_tree(github, fixture["files"], known_trees=fixture["known_trees"])
            self.assertEqual(result["sha"], fixture["expected_root"])
            self.assertEqual(github.store.flatten(result["sha"]), fixture["files"])
            self.assertEqual(len(legacy), 673)
            self.assertEqual(len(fixture["files"]), 1297)
            self.assertIn(fixture["expected_v3"], github.created)
            self.assertIn(fixture["expected_shards"], github.created)
            self.assertFalse(set(fixture["known_trees"].values()) & github.created)
            self.assertEqual(len(github.assembly_calls), 9)
            self.assertEqual(sum("base_tree" in call for call in github.assembly_calls), 4)
            self.assertEqual(max(len(call["tree"]) for call in github.assembly_calls), 128)

    def test_known_tree_only_reused_for_exact_filtered_identity(self):
        files = {"folder/file": "a" * 40}
        with tempfile.TemporaryDirectory() as directory:
            github = FakeGitHub(Path(directory) / "git")
            old = github.store.build({**files, "folder/unrelated": "b" * 40})
            result = transport.create_filtered_tree(github, files, known_trees={"": old})
            self.assertNotEqual(result["sha"], old)
            self.assertEqual(github.store.flatten(result["sha"]), files)
            self.assertTrue(all("base_tree" not in call for call in github.assembly_calls))

    def test_invalid_paths_and_file_directory_conflicts_fail_before_write(self):
        for files in ({"/absolute": "a" * 40}, {"x/../y": "a" * 40}, {"a": "a" * 40, "a/b": "b" * 40},
                      {"x//y": "a" * 40}, {"x\\y": "a" * 40}, {".git/config": "a" * 40}, {"x": "wrong"}):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as directory:
                github = FakeGitHub(Path(directory) / "git")
                with self.assertRaises(PublicationError):
                    transport.create_filtered_tree(github, files)
                self.assertEqual(github.calls, [])

    def test_bad_hash_mode_missing_entry_and_truncation_fail_closed(self):
        corruptions = (lambda value: value.update(sha="f" * 40),
                       lambda value: value.update(truncated=True),
                       lambda value: value["tree"][0].update(mode="100755"),
                       lambda value: value["tree"].clear(),
                       lambda value: value["tree"].append(copy.deepcopy(value["tree"][0])))
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as directory:
                github = FakeGitHub(Path(directory) / "git")
                original = github.request
                def request(method, path, data=None):
                    value = original(method, path, data)
                    if method == "GET":
                        corrupt(value)
                    return value
                github.request = request
                with mock.patch.object(transport.time, "sleep") as pause:
                    with self.assertRaises(PublicationError):
                        transport.create_filtered_tree(github, {"x": "a" * 40})
                if corrupt == corruptions[0]:
                    self.assertEqual([method for method, _, _ in github.calls], ["POST"] + ["GET"] * 5)
                    self.assertEqual([call.args for call in pause.call_args_list], [(1,), (2,), (4,), (8,)])
                else:
                    self.assertEqual([method for method, _, _ in github.calls], ["POST", "GET"])

    def test_forged_or_malformed_create_identity_stops_before_verification(self):
        changes = [lambda _value: [], lambda _value: "unexpected", lambda _value: None,
                   lambda value: {key: item for key, item in value.items() if key != "sha"},
                   lambda value: {**value, "sha": "f" * 40},
                   lambda value: {**value, "sha": ["invalid"]}]
        for index, change in enumerate(changes):
            with self.subTest(shape=index), tempfile.TemporaryDirectory() as directory:
                github = FakeGitHub(Path(directory) / "git")
                original = github.request
                github.request = lambda *args, **kwargs: change(original(*args, **kwargs))
                with self.assertRaisesRegex(PublicationError, "uploaded publication tree identity differs"):
                    transport.create_filtered_tree(github, {"nested/file": "a" * 40})
                self.assertEqual(len(github.calls), 1)
                self.assertEqual(github.calls[0][:2], ("POST", "git/trees"))

    def test_malformed_verification_shapes_fail_before_any_further_api_write(self):
        def missing_tree(value):
            del value["tree"]
            return value
        # A 404/missing tree is covered by the bounded visibility retry tests;
        # malformed *present* verification responses must fail immediately.
        changes = [lambda _value: [], lambda _value: "unexpected",
                   missing_tree, lambda value: {**value, "tree": {}},
                   lambda value: {**value, "tree": [None]},
                   lambda value: {**value, "tree": [{}]},
                   lambda value: {key: item for key, item in value.items() if key != "truncated"},
                   lambda value: {**value, "truncated": 0}]
        for field in ("path", "mode", "type", "sha"):
            changes.append(lambda value, field=field: {**value,
                "tree": [{key: item for key, item in value["tree"][0].items() if key != field}]})
            changes.append(lambda value, field=field: {**value,
                "tree": [{**value["tree"][0], field: ["invalid"]}]})
        for index, change in enumerate(changes):
            with self.subTest(shape=index), tempfile.TemporaryDirectory() as directory:
                github = FakeGitHub(Path(directory) / "git")
                original = github.request
                def request(method, path, data=None):
                    value = original(method, path, data)
                    return change(value) if method == "GET" else value
                github.request = request
                with self.assertRaisesRegex(PublicationError, "uploaded publication tree verification"):
                    transport.create_filtered_tree(github, {"nested/file": "a" * 40})
                self.assertEqual(len(github.calls), 2)
                self.assertEqual(github.calls[0][:2], ("POST", "git/trees"))
                self.assertEqual(github.calls[1][0], "GET")


class Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *_args): self.close()


class Clock:
    def __init__(self): self.now, self.sleeps = 0, []
    def __call__(self): return self.now
    def sleep(self, seconds): self.sleeps.append(seconds); self.now += seconds


def http_error(status, headers=None, body=b"response body must never be printed"):
    return urllib.error.HTTPError("https://api.github.com", status, "failure", headers or {}, io.BytesIO(body))


class TransportTests(unittest.TestCase):
    def client(self, events, **kwargs):
        self.clock, self.requests = Clock(), []
        def opener(request, timeout):
            self.requests.append((request, timeout))
            value = events.pop(0)
            if isinstance(value, Exception): raise value
            return Response(json.dumps(value).encode())
        return transport.GitHub("secret-token", opener=opener, clock=self.clock,
                                sleeper=self.clock.sleep, **kwargs)

    def test_tree_502_retries_with_sanitized_diagnostics_and_same_payload(self):
        client = self.client([http_error(502, {"X-GitHub-Request-Id": "ABCD:1234"}), {"sha": "a" * 40}])
        output = io.StringIO()
        with redirect_stderr(output):
            result = client.request("POST", "git/trees", {"tree": []})
        self.assertEqual(result["sha"], "a" * 40)
        self.assertEqual(self.clock.sleeps, [1])
        self.assertEqual(self.requests[0][0].data, self.requests[1][0].data)
        self.assertEqual(output.getvalue(), "GitHub coverage transient failure; bounded retry\n")
        self.assertNotIn("secret-token", output.getvalue())
        self.assertNotIn("response body", output.getvalue())

    def test_untrusted_request_id_and_exception_text_are_never_logged_in_plaintext(self):
        echoed = 'server-echo-secret-token'
        client = self.client([http_error(502, {'X-GitHub-Request-Id': echoed}, echoed.encode()), {'ok': True}])
        output = io.StringIO()
        with redirect_stderr(output):
            self.assertEqual(client.request('GET', 'git/ref/heads/main'), {'ok': True})
        self.assertNotIn('secret-token', output.getvalue())
        self.assertNotIn(echoed, output.getvalue())
        self.assertEqual(output.getvalue(), 'GitHub coverage transient failure; bounded retry\n')

    def test_api_parse_read_and_budget_failures_are_typed_without_response_or_request_text(self):
        secret = 'server-echo-secret-token'
        bodies = [('{"' + secret + '":1,"' + secret + '":2}').encode(),
                  ('{"' + secret + '\\u0301":1}').encode(), b'{"' + secret.encode(), b'\xff']
        for body in bodies:
            with self.subTest(body=body):
                clock = Clock()
                client = transport.GitHub('secret-token', opener=lambda *_args, **_kwargs: Response(body),
                                          clock=clock, sleeper=clock.sleep)
                with redirect_stderr(io.StringIO()) as output, self.assertRaises(transport.GitHubTransportError) as raised:
                    client.request('GET', 'actions/runs?probe=secret-token')
                self.assertEqual(str(raised.exception), 'GitHub coverage response invalid; prior report retained')
                self.assertNotIn(secret, str(raised.exception) + output.getvalue())
                self.assertNotIn('secret-token', str(raised.exception) + output.getvalue())
        with mock.patch.object(transport, 'MAX_API_BYTES', 8):
            client = transport.GitHub('secret-token', opener=lambda *_args, **_kwargs: Response(secret.encode()))
            with self.assertRaisesRegex(transport.GitHubTransportError, 'response invalid'):
                client.request('GET', 'git/ref/heads/main')
        client = self.client([OSError(secret)])
        with self.assertRaises(transport.GitHubTransportError) as raised:
            client.request('GET', 'git/ref/heads/main')
        self.assertNotIn(secret, str(raised.exception))
        client = self.client([], budget_seconds=1)
        self.clock.now = 2
        with self.assertRaisesRegex(transport.GitHubTransportError, 'budget exhausted'):
            client.request('GET', 'git/ref/heads/main')

    def test_terminal_http_errors_never_echo_paths_queries_or_headers(self):
        client = self.client([http_error(503, {'X-GitHub-Request-Id': 'secret-token'}, b'secret-token') for _ in range(3)])
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(transport.GitHubTransportError) as raised:
            client.request('GET', 'actions/runs?probe=secret-token')
        self.assertEqual(str(raised.exception), 'GitHub coverage request failed operation=read target=actions status=503 attempt=3/3')
        self.assertNotIn('secret-token', output.getvalue() + str(raised.exception))
        self.assertNotIn('actions/runs', str(raised.exception))

    def test_optional_validation_parser_uses_only_canonical_allowlist_labels(self):
        error = http_error(422, body=json.dumps({'message': 'Validation Failed', 'errors': [
            {'code': 'invalid', 'field': 'content', 'value': 'secret-token'},
            {'code': 'secret-token', 'field': 'secret-token'}]}).encode())
        try:
            result = transport.validation_diagnostic(error)
        finally:
            error.close()
        self.assertEqual(result, 'error_category=validation_failed error_count=2 error_codes=invalid error_fields=content')

    def test_encoded_recovery_cursor_query_is_accepted_but_malformed_escapes_are_rejected(self):
        path = 'actions/workflows/9/runs?branch=main&status=completed&per_page=100&page=6&created=%3C%3D2026-11-03T00%3A00%3A00Z'
        client = self.client([{'workflow_runs': []}])
        self.assertEqual(client.request('GET', path), {'workflow_runs': []})
        self.assertTrue(self.requests[0][0].full_url.endswith(path))
        for malformed in ('actions/runs?created=%', 'actions/runs?created=%0G', 'actions/runs?created=%3',
                          'actions/%2Fruns?created=1', 'actions/../runs?created=1'):
            with self.subTest(path=malformed), self.assertRaises(PublicationError):
                client.request('GET', malformed)

    def test_production_transport_accepts_only_sha_to_sha_ancestry_comparisons(self):
        sha_path = 'compare/' + 'a' * 40 + '...' + 'b' * 40
        for path in (sha_path, sha_path + '?per_page=1', 'contents/.github/workflows/skillspector-reports.yml',
                     'contents/schemas/skillspector-manifest-v3.schema.json'):
            with self.subTest(path=path):
                client = self.client([{'ok': True}])
                self.assertEqual(client.request('GET', path), {'ok': True})
        for path in ('compare/../main', 'compare/abc...main', 'compare/' + 'a' * 40 + '...main',
                     'git/ref/heads/../secrets', 'git/ref/heads/./main'):
            with self.subTest(path=path), self.assertRaises(PublicationError):
                self.client([]).request('GET', path)

    def test_only_three_safe_retries_and_strict_global_budget(self):
        client = self.client([http_error(503) for _ in range(3)])
        with redirect_stderr(io.StringIO()), self.assertRaisesRegex(PublicationError, "attempt=3/3"):
            client.request("GET", "git/ref/heads/main")
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.clock.sleeps, [1, 2])
        client = self.client([http_error(502)], budget_seconds=1)
        with self.assertRaises(PublicationError): client.request("POST", "git/trees", {"tree": []})
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(self.requests[0][1], 1)

    def test_commit_ref_writes_and_permanent_errors_are_never_retried(self):
        for method, path, failure in (("POST", "git/commits", http_error(502)),
            ("PATCH", "git/refs/heads/skillspector-reports", TimeoutError()),
            ("POST", "git/refs", http_error(503)), ("POST", "git/trees", http_error(422)),
            ("GET", "git/ref/heads/main", http_error(403)),
            ("GET", "git/ref/heads/main", urllib.error.URLError("certificate verification failed"))):
            with self.subTest(method=method, path=path):
                client = self.client([failure])
                with self.assertRaises(PublicationError): client.request(method, path, {})
                self.assertEqual(len(self.requests), 1)
                self.assertEqual(self.clock.sleeps, [])

    def test_transient_read_failure_retries_and_missing_read_returns_none(self):
        client = self.client([urllib.error.URLError(TimeoutError()), {"ok": True}])
        with redirect_stderr(io.StringIO()):
            self.assertEqual(client.request("GET", "git/ref/heads/main"), {"ok": True})
        self.assertEqual(len(self.requests), 2)
        client = self.client([http_error(404)])
        self.assertIsNone(client.request("GET", "git/ref/heads/missing"))

    def test_incomplete_forbidden_body_preserves_http_diagnostic(self):
        error = http_error(403, {"X-GitHub-Request-Id": "SAFE:123"})
        def broken_read(*_args): raise TimeoutError()
        error.read = broken_read
        client = self.client([error])
        with self.assertRaisesRegex(PublicationError, "status=403"):
            client.request("GET", "git/ref/heads/main")
        self.assertEqual(len(self.requests), 1)

    def test_forbidden_pacing_hints_keep_supported_retry_behavior(self):
        for headers, body, delay in (({"Retry-After": "7"}, b"private response", 7),
                                     ({}, b"You have exceeded a secondary rate limit.", 60)):
            with self.subTest(headers=headers):
                error = http_error(403, headers, body)
                stream = error.fp
                client = self.client([error, {"sha": "a" * 40}])
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(client.request("POST", "git/trees", {"tree": []})["sha"], "a" * 40)
                self.assertEqual(self.clock.sleeps, [delay])
                self.assertTrue(stream.closed)

    def test_validation_errors_emit_only_fixed_operation_status_and_local_attempt(self):
        secret = "private-scanner-content-secret-token"
        response = {"message": "Validation Failed", "documentation_url": "https://example.test/" + secret,
            "errors": [{"resource": secret, "field": "content", "code": "invalid", "message": secret,
                        "value": secret}, {"field": "sha", "code": "missing_field"},
                       {"field": secret, "code": secret}, secret, None]}
        error = http_error(422, {"X-GitHub-Request-Id": "SAFE:422", "Retry-After": "1"},
                           json.dumps(response).encode())
        stream = error.fp
        client = self.client([error])
        output = io.StringIO()
        payload = {"tree": [{"path": "blob00000", "mode": "100644", "type": "blob", "content": secret}]}
        with redirect_stderr(output), self.assertRaises(PublicationError) as raised:
            client.request("POST", "git/trees", payload)
        diagnostic = str(raised.exception)
        self.assertIn("status=422 attempt=1/3", diagnostic)
        self.assertNotIn("error_category=", diagnostic)
        self.assertNotIn("error_codes=", diagnostic)
        self.assertNotIn("request_bytes=", diagnostic)
        self.assertNotIn(secret, diagnostic + output.getvalue())
        self.assertNotIn("https://", diagnostic)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.clock.sleeps, [])
        self.assertTrue(stream.closed)

    def test_unknown_validation_messages_and_fields_are_not_echoed(self):
        for message, category in (("Invalid request", "invalid_request"),
            ("Validation Failed private-scanner-content", "unclassified"),
            ({"private-scanner-content": "secret-token"}, "unclassified")):
            with self.subTest(category=category):
                response = {"message": message, "errors": [
                    {"field": ["content", "private-scanner-content"], "code": {"invalid": "secret-token"}},
                    {"field": "content\nprivate-scanner-content", "code": "invalid-secret-token"}]}
                error = http_error(422, body=json.dumps(response).encode())
                client = self.client([error])
                with self.assertRaises(PublicationError) as raised:
                    client.request("POST", "git/trees", {"tree": []})
                diagnostic = str(raised.exception)
                self.assertNotIn("error_category=", diagnostic)
                self.assertNotIn("error_count=", diagnostic)
                self.assertNotIn("error_codes=", diagnostic)
                self.assertNotIn("error_fields=", diagnostic)
                self.assertNotIn("private-scanner-content", diagnostic)
                self.assertNotIn("secret-token", diagnostic)
                self.assertEqual(len(self.requests), 1)
                self.assertEqual(self.clock.sleeps, [])

    def test_validation_bodies_are_not_read_or_reflected_in_errors(self):
        for body, expected in ((b"<html>private-scanner-content</html>", "malformed"),
            (b"\xff", "malformed"), (b'{"message":', "malformed"),
            (b'{"message":"Validation Failed","message":"secret-token"}', "malformed"),
            (b'[]', "invalid_shape"),
            (b"private-scanner-content" + b"x" * transport.MAX_ERROR_BYTES, "oversized")):
            with self.subTest(expected=expected, bytes=len(body)):
                error = http_error(422, {"X-GitHub-Request-Id": "SAFE:422"}, body)
                stream, read, sizes = error.fp, error.read, []
                def bounded_read(size):
                    sizes.append(size)
                    return read(size)
                error.read = bounded_read
                client = self.client([error])
                with self.assertRaises(PublicationError) as raised:
                    client.request("POST", "git/trees", {"tree": []})
                diagnostic = str(raised.exception)
                self.assertIn("status=422", diagnostic)
                self.assertNotIn("diagnostic_body=", diagnostic)
                self.assertNotIn("private-scanner-content", diagnostic)
                self.assertNotIn("secret-token", diagnostic)
                self.assertEqual(sizes, [])
                self.assertTrue(stream.closed)
                self.assertEqual(len(self.requests), 1)
                self.assertEqual(self.clock.sleeps, [])

    def test_unreadable_validation_body_preserves_status_and_closes_error(self):
        for failure in (TimeoutError("secret-token"), ConnectionResetError("private-scanner-content"),
                        transport.http.client.IncompleteRead(b"secret-token", 10)):
            with self.subTest(failure=type(failure).__name__):
                error = http_error(422, {"X-GitHub-Request-Id": "SAFE:422"})
                stream = error.fp
                def broken_read(*_args): raise failure
                error.read = broken_read
                client = self.client([error])
                with self.assertRaises(PublicationError) as raised:
                    client.request("POST", "git/trees", {"tree": []})
                diagnostic = str(raised.exception)
                self.assertIn("status=422", diagnostic)
                self.assertNotIn("diagnostic_body=", diagnostic)
                self.assertNotIn("secret-token", diagnostic)
                self.assertNotIn("private-scanner-content", diagnostic)
                self.assertTrue(stream.closed)
                self.assertEqual(len(self.requests), 1)
                self.assertEqual(self.clock.sleeps, [])

    def test_validation_close_failure_preserves_only_fixed_status_without_retry(self):
        error = http_error(422, {"X-GitHub-Request-Id": "SAFE:422"},
            b'{"message":"Validation Failed"}')
        stream, close = error.fp, error.close
        def broken_close():
            close()
            raise OSError("private-scanner-content-secret-token")
        error.close = broken_close
        client = self.client([error])
        try:
            with self.assertRaises(PublicationError) as raised:
                client.request("POST", "git/trees", {"tree": []})
        finally:
            error.close = close
        diagnostic = str(raised.exception)
        self.assertIn("status=422 attempt=1/3", diagnostic)
        self.assertNotIn("error_category=", diagnostic)
        self.assertNotIn("private-scanner-content", diagnostic)
        self.assertNotIn("secret-token", diagnostic)
        self.assertTrue(stream.closed)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.clock.sleeps, [])

    def test_v3_inline_upload_422_stops_before_commit_or_report_ref_update(self):
        from scripts import publish_skillspector_coverage_v3 as publisher
        from tests.test_skillspector_coverage_v3 import COMMIT, bundle, item, record
        source = item()
        error = http_error(422, {"X-GitHub-Request-Id": "SAFE:422"}, json.dumps({
            "message": "Validation Failed", "errors": [{"field": "content", "code": "invalid",
                "value": "private-scanner-content-secret-token"}]}).encode())
        # Model an existing report ref: the normal publisher may read it, but
        # must never create a commit or move that ref after a rejected upload.
        client = self.client([{"object": {"sha": COMMIT}}, {"object": {"sha": "a" * 40}},
                              {"truncated": False, "tree": []}, error])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "reports"
            bundle(root, {"schema_version": 1, "sources": [source]}, [record(source)])
            publisher.coverage.write_bounded(root / "publication-base.json",
                {"schema_version": 1, "report_commit": "a" * 40}, 4096)
            with self.assertRaisesRegex(PublicationError, "status=422.*attempt=1/3"):
                publisher.publish(client, root, COMMIT, fetch=lambda *args, **kwargs: None)
        self.assertEqual([request.get_method() for request, _ in self.requests], ["GET", "GET", "GET", "POST"])
        self.assertTrue(self.requests[-1][0].full_url.endswith("/git/trees"))
        self.assertTrue(any("content" in row for row in json.loads(self.requests[-1][0].data)["tree"]))
        self.assertEqual(self.clock.sleeps, [])


if __name__ == "__main__":
    unittest.main()
