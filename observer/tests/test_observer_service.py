from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

import observer.fixed_runner as fixed_runner
import observer.fixed_adapters as fixed_adapters
from observer.auth import AuthenticationError, GitHubCorroborator, JwksCache, OidcVerifier, ReplayStore
from observer.canonical import canonical_json, request_digest, signed_payload, validate_redacted
from observer.config import Config, IdentityPolicy
from observer.fixed_runner import Adapter, ReviewedRunner, serve as serve_runner
from observer.http_server import BoundedThreadingHTTPServer, MAX_REQUEST_BYTES, ObserverHandler
from observer.runner import SocketRunner
from observer.schema_validation import validate_artifact_schemas
from observer.secure_files import read_owned_regular
from observer.service import CHALLENGE_DOMAIN, ObserverService, WorkBusyError
from observer.signer import SocketSigner
from observer.signer import CacheExpiredError


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.now = 1_800_000_000
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.observer_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = self.observer_key.public_key().public_bytes_raw()
        numbers = self.rsa_key.public_key().public_numbers()
        self.kid = "fixture-rsa-key"
        self.policy = IdentityPolicy(
            repository="777genius/universal-agent-plugins",
            repository_id="123456",
            repository_owner_id="777",
            ref="refs/heads/main",
            ref_type="branch",
            environment="stable-launch-e2e",
            workflow_ref="777genius/universal-agent-plugins/.github/workflows/directory-publication.yml@refs/heads/main",
            job_workflow_ref="777genius/universal-agent-plugins/.github/workflows/launch-evidence-e2e.yml@refs/heads/main",
            workflow="Signed Directory publication",
            event_names=("push", "workflow_dispatch"),
            job_name_suffix="protected-observer-inputs",
        )
        runner_source = root / "runner"
        runner_source.write_text("#!/bin/sh\nexit 1\n")
        runner_source.chmod(0o755)
        self.config = Config(
            bind_host="127.0.0.1", bind_port=8765, state_root=root / "state",
            jwks_url="https://token.actions.githubusercontent.com/.well-known/jwks",
            github_api_url="https://api.github.com", audience="stable-launch-observer",
            issuer="https://token.actions.githubusercontent.com", key_id="fixture-ed25519",
            public_key_base64=base64.b64encode(public_bytes).decode(),
            cli_release_repository="777genius/plugin-kit-ai", cli_release_tag="agentplugins-v0.1.13",
            signer_socket=root / "sign.sock", runner_socket=root / "runner.sock",
            runner_source_path=runner_source,
            runner_source_digest="sha256:" + hashlib.sha256(runner_source.read_bytes()).hexdigest(),
            runner_user="root", runner_timeout_seconds=5,
            policies=(self.policy,), enforce_root_ownership=False,
        )
        self.jwks = {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
            "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }]}

    def request(self) -> dict[str, Any]:
        sha = "a" * 40
        release = "sha256:" + "b" * 64
        directory = "sha256:" + "c" * 64
        scenario = "sha256:" + "1" * 64
        challenge = {
            "nonce": "d" * 64, "github_sha": sha, "run_id": "1001", "run_attempt": "2",
            "release_manifest_digest": release, "directory_digest": directory,
            "scenario_contract_digest": scenario, "root_id": "e" * 64,
        }
        challenge["value"] = hashlib.sha256(CHALLENGE_DOMAIN + canonical_json(challenge)).hexdigest()
        return {
            "schema_version": 1, "purpose": "stable-launch-e2e",
            "catalog_repository": self.policy.repository,
            "cli_release_repository": "777genius/plugin-kit-ai", "cli_release_tag": "agentplugins-v0.1.13",
            "release_manifest_digest": release, "release_checksums_digest": "sha256:" + "f" * 64,
            "directory_digest": directory, "scenario_contract_digest": scenario,
            "github": {"sha": sha, "run_id": "1001", "run_attempt": "2"},
            "challenge": challenge,
        }

    def claims(self, *, jti: str = "fixture-jti-0001", **changes: Any) -> dict[str, Any]:
        claims = {
            "iss": self.config.issuer, "aud": self.config.audience,
            "sub": "repo:777genius@777/universal-agent-plugins@123456:environment:stable-launch-e2e",
            "iat": self.now - 10, "nbf": self.now - 10, "exp": self.now + 300, "jti": jti,
            "repository": self.policy.repository, "repository_id": self.policy.repository_id,
            "repository_owner_id": self.policy.repository_owner_id, "ref": self.policy.ref,
            "sha": "a" * 40, "run_id": "1001", "run_attempt": "2",
            "environment": self.policy.environment, "workflow_ref": self.policy.workflow_ref,
            "job_workflow_ref": self.policy.job_workflow_ref,
            "workflow_sha": "a" * 40, "job_workflow_sha": "a" * 40,
            "workflow": self.policy.workflow, "event_name": "workflow_dispatch", "ref_type": "branch",
        }
        claims.update(changes)
        return claims

    def token(self, **changes: Any) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        claims = self.claims(**changes)
        message = b64url(canonical_json(header)) + "." + b64url(canonical_json(claims))
        signature = self.rsa_key.sign(message.encode(), padding.PKCS1v15(), SHA256())
        return message + "." + b64url(signature)

    def fetch(self, url: str) -> Any:
        if url == self.config.jwks_url:
            return self.jwks
        if url.endswith("/jobs?filter=latest&per_page=100"):
            return {"jobs": [{
                "name": "required-stable-launch-evidence / protected-observer-inputs",
                "run_id": 1001, "run_attempt": 2, "head_sha": "a" * 40,
                "status": "in_progress", "workflow_name": self.policy.workflow,
            }]}
        if url.endswith("/actions/runs/1001/attempts/2"):
            return {
                "id": 1001, "run_attempt": 2, "head_sha": "a" * 40,
                "path": ".github/workflows/directory-publication.yml", "event": "workflow_dispatch",
                "repository": {"full_name": self.policy.repository, "id": 123456, "owner": {"id": 777}},
            }
        raise AssertionError(url)


def artifacts(challenge: str = "a" * 64) -> dict[str, Any]:
    return {
        "runtime-attestations.json": {"schema_version": 1, "attestations": []},
        "notion-oauth-attestations.json": {"schema_version": 1, "attestations": []},
        "chatgpt-cloudflare-attestation.json": {"schema_version": 1, "attestations": []},
        "consent.json": {
            "schema_version": 1, "purpose": "stable-launch-e2e", "consent": True,
            "mode": "enforced", "challenge": challenge, "run_id": "1001", "run_attempt": "2",
            "catalog_sha": "a" * 40, "scenario_contract_digest": "sha256:" + "1" * 64,
            "pseudonymous_identity_id": "fixture-identity", "pseudonymous_workspace_id": "e" * 64,
            "dedicated_identity": True, "disposable_project_status": "disposed",
            "operation_mode": "read-only", "auth_origin": "fresh-dedicated-identity",
            "cleanup_outcome": "cleaned", "no_real_project_proof": {
                "real_project_accessed": False, "absolute_paths_exported": False,
                "credential_material_exported": False, "auth_copied": False,
                "enforcement": "systemd-mount-namespace-v1",
            },
        },
    }


class FakeRunner:
    def __init__(self, value: Any = None, delay: float = 0):
        self.value, self.delay, self.calls = value, delay, 0
        self.lock = threading.Lock()

    def run(self, run_dir: Path, context: dict[str, Any], *, deadline: float | None = None) -> dict[str, Any]:
        del deadline
        with self.lock:
            self.calls += 1
        time.sleep(self.delay)
        if isinstance(self.value, Exception):
            raise self.value
        from observer.canonical import validate_artifacts
        value = self.value if self.value is not None else artifacts(context["request"]["challenge"]["value"])
        return validate_artifacts(value)


class FakeSigner:
    def __init__(self, key: ed25519.Ed25519PrivateKey | None = None):
        self.key = key or ed25519.Ed25519PrivateKey.generate()

    def sign(self, unsigned: dict[str, Any], *, deadline: float | None = None) -> str:
        del deadline
        return base64.b64encode(self.key.sign(signed_payload(unsigned))).decode()

    def verify_cached(self, encoded: bytes, *, challenge: str, now: float) -> dict[str, Any]:
        bundle = json.loads(encoded)
        if canonical_json(bundle) != encoded or bundle["challenge"] != challenge:
            raise ValueError("invalid fixture cache")
        unsigned = {key: value for key, value in bundle.items() if key != "signature"}
        self.key.public_key().verify(base64.b64decode(bundle["signature"]), signed_payload(unsigned))
        signed_at = datetime.fromisoformat(bundle["signed_at"].replace("Z", "+00:00")).timestamp()
        if now - signed_at > 1800:
            raise CacheExpiredError("stale")
        return bundle


class ObserverTests(unittest.TestCase):
    def test_protected_reads_reject_parent_symlinks_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected"
            protected.mkdir(mode=0o700)
            target = protected / "record"
            target.write_bytes(b"value")
            target.chmod(0o600)
            alias = root / "alias"
            alias.symlink_to(protected, target_is_directory=True)
            with self.assertRaises(OSError):
                read_owned_regular(alias / "record", 32, owner_uid=os.geteuid())
            linked = protected / "linked"
            os.link(target, linked)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_owned_regular(target, 32, owner_uid=os.geteuid())

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def service(self, runner: FakeRunner | None = None, fetch=None) -> tuple[ObserverService, FakeRunner, FakeSigner]:
        fixture, runner, signer = self.fixture, runner or FakeRunner(), FakeSigner(self.fixture.observer_key)
        selected_fetch = fetch or fixture.fetch
        verifier = OidcVerifier(fixture.config, fetch=selected_fetch, now=lambda: fixture.now)
        service = ObserverService(
            fixture.config, verifier=verifier, corroborator=GitHubCorroborator(fixture.config, selected_fetch),
            replay=ReplayStore(fixture.config.state_root / "replay", lambda: fixture.now),
            runner=runner, signer=signer, now=lambda: fixture.now,
        )
        return service, runner, signer

    def test_success_is_signed_and_cached_for_fresh_oidc_jti(self) -> None:
        service, runner, signer = self.service()
        first = service.observe(self.fixture.request(), self.fixture.token(jti="fixture-jti-0001"))
        second = service.observe(self.fixture.request(), self.fixture.token(jti="fixture-jti-0002"))
        self.assertEqual(first, second)
        self.assertEqual(runner.calls, 1)
        bundle = json.loads(first)
        signature = base64.b64decode(bundle.pop("signature"))
        signer.key.public_key().verify(signature, signed_payload(bundle))
        self.assertEqual(bundle["challenge"], self.fixture.request()["challenge"]["value"])

    def test_oidc_replay_is_rejected(self) -> None:
        service, _, _ = self.service()
        token = self.fixture.token(jti="fixture-jti-replay")
        service.observe(self.fixture.request(), token)
        with self.assertRaisesRegex(AuthenticationError, "already used"):
            service.observe(self.fixture.request(), token)

    def test_expired_cache_is_atomically_replaced(self) -> None:
        service, runner, _ = self.service()
        first = service.observe(self.fixture.request(), self.fixture.token(jti="fixture-cache-old"))
        self.fixture.now += 1801
        second = service.observe(self.fixture.request(), self.fixture.token(jti="fixture-cache-new"))
        self.assertNotEqual(first, second)
        self.assertEqual(runner.calls, 2)
        runs = self.fixture.config.state_root / "runs"
        self.assertEqual(len([path for path in runs.iterdir() if not path.name.startswith(".")]), 1)

    def test_expired_oidc_is_rejected(self) -> None:
        service, _, _ = self.service()
        with self.assertRaisesRegex(AuthenticationError, "expired"):
            service.observe(self.fixture.request(), self.fixture.token(iat=self.fixture.now - 700, nbf=self.fixture.now - 700, exp=self.fixture.now - 100))

    def test_wrong_exact_claim_is_rejected(self) -> None:
        service, _, _ = self.service()
        with self.assertRaisesRegex(AuthenticationError, "not allowlisted"):
            service.observe(self.fixture.request(), self.fixture.token(ref="refs/heads/feature"))

    def test_wrong_run_claim_is_rejected_before_execution(self) -> None:
        service, runner, _ = self.service()
        with self.assertRaisesRegex(AuthenticationError, "identities differ"):
            service.observe(self.fixture.request(), self.fixture.token(run_attempt="3"))
        self.assertEqual(runner.calls, 0)

    def test_public_job_mismatch_fails_closed(self) -> None:
        fixture = self.fixture
        def wrong_fetch(url: str) -> Any:
            value = fixture.fetch(url)
            if url.endswith("/jobs?filter=latest&per_page=100"):
                value["jobs"][0]["head_sha"] = "0" * 40
            return value
        service, runner, _ = self.service(fetch=wrong_fetch)
        with self.assertRaisesRegex(AuthenticationError, "job does not corroborate"):
            service.observe(fixture.request(), fixture.token())
        self.assertEqual(runner.calls, 0)

    def test_completed_job_cannot_authorize_a_new_observation(self) -> None:
        fixture = self.fixture
        def completed_fetch(url: str) -> Any:
            value = fixture.fetch(url)
            if url.endswith("/jobs?filter=latest&per_page=100"):
                value["jobs"][0].update({"status": "completed", "conclusion": "success"})
            return value
        service, runner, _ = self.service(fetch=completed_fetch)
        with self.assertRaisesRegex(AuthenticationError, "not active"):
            service.observe(fixture.request(), fixture.token())
        self.assertEqual(runner.calls, 0)

    def test_concurrent_identical_requests_are_single_flight(self) -> None:
        service, runner, _ = self.service(FakeRunner(delay=0.05))
        responses: list[bytes] = []
        failures: list[Exception] = []
        def call(index: int) -> None:
            try:
                responses.append(service.observe(self.fixture.request(), self.fixture.token(jti=f"fixture-concurrent-{index}")))
            except Exception as error:
                failures.append(error)
        threads = [threading.Thread(target=call, args=(index,)) for index in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertFalse(failures)
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0], responses[1])
        self.assertEqual(runner.calls, 1)

    def test_redaction_violation_fails_and_does_not_publish_run(self) -> None:
        unsafe = artifacts()
        unsafe["runtime-attestations.json"]["debug_path"] = "/home/runner/private.json"
        service, _, _ = self.service(FakeRunner(unsafe))
        with self.assertRaisesRegex(ValueError, "absolute path"):
            service.observe(self.fixture.request(), self.fixture.token())
        runs = self.fixture.config.state_root / "runs"
        self.assertFalse(runs.exists() and any(path.name[0] != "." for path in runs.iterdir()))

    def test_nested_credential_value_is_rejected(self) -> None:
        unsafe = artifacts()
        unsafe["runtime-attestations.json"]["access_token"] = ["bare-secret"]
        service, _, _ = self.service(FakeRunner(unsafe))
        with self.assertRaisesRegex(ValueError, "credential-like"):
            service.observe(self.fixture.request(), self.fixture.token())

    def test_path_uri_and_quoted_path_variants_are_rejected(self) -> None:
        unsafe = (
            "path:/home/alice/private.json", "file:///home/alice/private.json",
            "workspace:/Users/alice/private-project",
            "'/home/alice/private.json'", r"path:C:\Users\alice\private.json",
            r"\\?\C:\Users\alice\private.json",
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "absolute path"):
                validate_redacted({"message": value})
        with self.assertRaisesRegex(ValueError, "URL credential"):
            validate_redacted({"endpoint": "https://example.test/callback?access_token=secret"})
        with self.assertRaisesRegex(ValueError, "URL credential"):
            validate_redacted({"endpoint": "https://example.test/callback#access_token=secret"})
        validate_redacted({"endpoint": "https://api.example.test/v1"})

    def test_common_tokens_any_url_payload_and_encoded_paths_are_rejected(self) -> None:
        unsafe = (
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.abcdefghijklmnopqrstuvwxyz",
            "AKIAABCDEFGHIJKLMNOP",
            "https://example.test/path?harmless=value", "https://example.test/path#payload",
            "file:%252Fhome%252Fuser%252Fsecret", "path:%2FC%3A%5CUsers%5Csecret",
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_redacted({"nested": [{"value": value}]})

    def test_adversarial_credential_names_values_and_argv_are_rejected(self) -> None:
        samples = (
            {"api_key": "live-value"},
            {"access_token": "live-value"},
            {"client_secret": "live-value"},
            {"endpoint": "https://example.test/?X-Amz-Signature=live-value"},
            {"endpoint": "https://example.test/?next=access_token%3Dlive-value"},
            {"argv": ["client", "--api_key=live-value"]},
            {"argv": ["client", "workspace:/Users/alice/private-project"]},
        )
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                validate_redacted(sample)

    def test_distinct_concurrent_request_fails_fast(self) -> None:
        service, runner, _ = self.service(FakeRunner(delay=0.15))
        first_request = self.fixture.request()
        second_request = self.fixture.request()
        second_request["challenge"]["nonce"] = "9" * 64
        challenge = second_request["challenge"]
        challenge["value"] = hashlib.sha256(CHALLENGE_DOMAIN + canonical_json({
            key: challenge[key] for key in (
                "github_sha", "run_id", "run_attempt", "release_manifest_digest",
                "directory_digest", "scenario_contract_digest", "root_id", "nonce",
            )
        })).hexdigest()
        failures: list[Exception] = []
        thread = threading.Thread(target=lambda: service.observe(first_request, self.fixture.token(jti="fixture-distinct-leader")))
        thread.start()
        deadline = time.monotonic() + 5
        while runner.calls == 0 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(runner.calls, 1, "leader did not enter the protected runner")
        try:
            with self.assertRaises(WorkBusyError):
                service.observe(second_request, self.fixture.token(jti="fixture-distinct-follower"))
        finally:
            thread.join()
        self.assertEqual(runner.calls, 1)

    def test_cache_symlink_and_fifo_are_rejected_without_following(self) -> None:
        service, _, _ = self.service()
        request = self.fixture.request()
        service.observe(request, self.fixture.token(jti="fixture-cache-safe"))
        response = service._target(request, request_digest(request)) / "response.json"
        saved = response.read_bytes()
        response.unlink()
        outside = Path(self.temp.name) / "outside.json"
        outside.write_bytes(saved)
        response.symlink_to(outside)
        with self.assertRaises(OSError):
            service.observe(request, self.fixture.token(jti="fixture-cache-symlink"))
        response.unlink()
        os.mkfifo(response, 0o600)
        started = time.monotonic()
        with self.assertRaises(ValueError):
            service.observe(request, self.fixture.token(jti="fixture-cache-fifo"))
        self.assertLess(time.monotonic() - started, 1)

    def test_cache_signature_tampering_is_rejected_without_rerunning(self) -> None:
        service, runner, _ = self.service()
        request = self.fixture.request()
        service.observe(request, self.fixture.token(jti="fixture-cache-signed"))
        response = service._target(request, request_digest(request)) / "response.json"
        bundle = json.loads(response.read_bytes())
        bundle["signature"] = base64.b64encode(b"x" * 64).decode()
        response.write_bytes(canonical_json(bundle))
        with self.assertRaises(InvalidSignature):
            service.observe(request, self.fixture.token(jti="fixture-cache-tampered"))
        self.assertEqual(runner.calls, 1)

    def test_cache_retention_is_bounded_and_rejects_untrusted_shapes(self) -> None:
        service, _, _ = self.service()
        runs = self.fixture.config.state_root / "runs"
        runs.mkdir(parents=True)
        for index in range(64):
            entry = runs / f"run-{index:03d}"
            entry.mkdir(mode=0o700)
            (entry / "response.json").write_bytes(b"{}")
            os.utime(entry / "response.json", (index + 1, index + 1))
        service._retain_cache(runs)
        self.assertEqual(len(list(runs.iterdir())), 63)
        (runs / "bad").symlink_to(next(runs.iterdir()), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "untrusted"):
            service._retain_cache(runs)

    def test_schema_invalid_artifact_is_never_signed(self) -> None:
        invalid = artifacts()
        del invalid["consent.json"]["run_id"]
        service, _, _ = self.service(FakeRunner(invalid))
        with self.assertRaisesRegex(ValueError, "reviewed schema"):
            service.observe(self.fixture.request(), self.fixture.token())

    def test_github_trust_endpoints_are_pinned(self) -> None:
        with self.assertRaisesRegex(ValueError, "GitHub API endpoint"):
            replace(self.fixture.config, github_api_url="https://mirror.invalid").validate()

    def test_runner_wall_time_is_fixed(self) -> None:
        with self.assertRaisesRegex(ValueError, "wall-time"):
            replace(self.fixture.config, runner_timeout_seconds=841).validate()

    def test_runner_failure_is_sanitized_and_atomic(self) -> None:
        service, _, _ = self.service(FakeRunner(RuntimeError("secret runner output")))
        with self.assertRaisesRegex(RuntimeError, "secret runner output"):
            service.observe(self.fixture.request(), self.fixture.token())
        runs = self.fixture.config.state_root / "runs"
        self.assertEqual(list(runs.iterdir()), [])


class HttpBoundaryTests(unittest.TestCase):
    def test_body_over_128k_is_rejected_without_calling_service(self) -> None:
        class NeverCalled:
            def observe(self, request: Any, token: str) -> bytes:
                raise AssertionError("service must not be called")
        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), ObserverHandler)
        server.service = NeverCalled()  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.putrequest("POST", "/v1/stable-launch/observe")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
            connection.putheader("Authorization", "Bearer ignored")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response.read()), {"error": "request rejected"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_endpoint_rate_limit_rejects_the_thirty_first_request(self) -> None:
        class NeverCalled:
            def observe(self, request: Any, token: str, *, deadline: float) -> bytes:
                raise AssertionError("unauthenticated requests must not call the service")
        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), ObserverHandler)
        server.service = NeverCalled()  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            statuses = []
            for _ in range(31):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
                connection.request("POST", "/v1/stable-launch/observe", body=b"{}", headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                statuses.append(response.status)
                response.read()
                connection.close()
            self.assertEqual(statuses[:30], [401] * 30)
            self.assertEqual(statuses[30], 429)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class ExternalSignerTests(unittest.TestCase):
    def test_socket_helper_signs_only_canonical_bundle(self) -> None:
        helper_path = Path(__file__).parents[2] / "deploy" / "uap-observer-signer.py"
        spec = importlib.util.spec_from_file_location("uap_observer_signer", helper_path)
        self.assertIsNotNone(spec and spec.loader)
        helper = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(helper)  # type: ignore[union-attr]
        with tempfile.TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "sign.sock"
            server = helper.socketserver.UnixStreamServer(str(socket_path), helper.Handler)
            private_key = ed25519.Ed25519PrivateKey.generate()
            server.private_key = private_key
            server.key_id = "fixture-ed25519"
            server.allowed_uid = os.geteuid()
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                unsigned = {
                    "schema_version": 1, "challenge": "a" * 64,
                    "signed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "key_id": "fixture-ed25519", "artifacts": artifacts(),
                }
                public = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
                signer = SocketSigner(socket_path, public, "fixture-ed25519")
                signature = base64.b64decode(signer.sign(unsigned))
                private_key.public_key().verify(signature, signed_payload(unsigned))
                with self.assertRaisesRegex(ValueError, "invalid response"):
                    signer.sign({**unsigned, "key_id": "untrusted-key"})
                server.allowed_uid = os.geteuid() + 1
                with self.assertRaisesRegex(ValueError, "invalid response"):
                    signer.sign(unsigned)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_service_failure_is_redacted(self) -> None:
        class Failing:
            def observe(self, request: Any, token: str) -> bytes:
                raise ValueError("provider secret should never escape")
        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), ObserverHandler)
        server.service = Failing()  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            body = b"{}"
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.request(
                "POST", "/v1/stable-launch/observe", body=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer fixture"},
            )
            response = connection.getresponse()
            encoded = response.read()
            self.assertEqual(response.status, 503)
            self.assertNotIn(b"secret", encoded)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class JwksHardeningTests(unittest.TestCase):
    def test_random_unknown_kids_share_one_refresh_per_cooldown(self) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private.public_key().public_numbers()
        def jwk(kid: str) -> dict[str, str]:
            return {
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            }
        clock = [0.0]
        calls = []
        active = [{"keys": [jwk("known")]}]
        def fetch(url: str) -> Any:
            calls.append(url)
            return active[0]
        cache = JwksCache("https://jwks.test", fetch, lambda: clock[0])
        cache.key("known")
        failures = []
        threads = []
        for index in range(12):
            thread = threading.Thread(target=lambda kid=f"unknown-{index}": _capture_error(lambda: cache.key(kid), failures))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(failures), 12)
        active[0] = {"keys": [jwk("known"), jwk("rotated")]}
        clock[0] = 61
        self.assertIsNotNone(cache.key("rotated"))
        self.assertEqual(len(calls), 3)

    def test_withdrawn_key_is_rejected_on_the_next_successful_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            clock = [0.0]
            replacement = {"keys": [{**fixture.jwks["keys"][0], "kid": "replacement"}]}
            values = [fixture.jwks, replacement]
            cache = JwksCache("https://jwks.test", lambda _: values.pop(0), lambda: clock[0])
            cache.key(fixture.kid)
            clock[0] = cache.REFRESH_SECONDS + 1
            with self.assertRaises(AuthenticationError):
                cache.key(fixture.kid)

    def test_jwks_outage_fails_closed_after_hard_stale_age(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            clock, available = [0.0], [True]
            def fetch(_: str) -> Any:
                if available[0]:
                    return fixture.jwks
                raise OSError("outage")
            cache = JwksCache("https://jwks.test", fetch, lambda: clock[0])
            cache.key(fixture.kid)
            available[0] = False
            clock[0] = cache.MAX_STALE_SECONDS + 1
            with self.assertRaisesRegex(AuthenticationError, "discovery failed"):
                cache.key(fixture.kid)


def _capture_error(call, failures: list[Exception]) -> None:  # type: ignore[no-untyped-def]
    try:
        call()
    except Exception as error:
        failures.append(error)


class FixedRunnerFixtureTests(unittest.TestCase):
    def test_cgroup_v2_path_stays_beneath_mount_and_kills_descendants_after_leader_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cgroup_root = root / "cgroup"
            parent = cgroup_root / "delegated" / "runner"
            parent.mkdir(parents=True)
            (cgroup_root / "cgroup.controllers").write_text("pids\n")
            identity = root / "self.cgroup"
            identity.write_text("0::/delegated/runner\n")
            target = fixed_runner.delegated_job_cgroup(cgroup_root, identity)
            self.assertEqual(target.parent, parent)
            calls: list[str] = []
            states = iter(("populated 1\n", "populated 0\n"))
            def remove() -> None:
                calls.append("rmdir")
                target.rmdir()
            fixed_runner.destroy_job_cgroup(
                target, kill=lambda: calls.append("cgroup.kill"),
                events=lambda: next(states), remove=remove,
            )
            self.assertEqual(calls, ["cgroup.kill", "rmdir"])

    def test_root_challenge_record_is_atomically_tombstoned_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pending, consumed = root / "pending", root / "consumed"
            pending.mkdir(mode=0o700)
            consumed.mkdir(mode=0o700)
            challenge = "a" * 64
            record = pending / f"{challenge}.json"
            record.write_text("{}")
            record.chmod(0o640)
            fixed_runner.tombstone_record(root, challenge)
            self.assertFalse(record.exists())
            self.assertTrue((consumed / record.name).is_file())
            with self.assertRaisesRegex(ValueError, "already consumed|No such file"):
                fixed_runner.tombstone_record(root, challenge)

    def test_client_artifacts_are_split_across_isolated_identities(self) -> None:
        self.assertEqual(fixed_runner.ARTIFACT_IDENTITIES["runtime-attestations.json"], ("codex", "cursor", "kiro"))
        self.assertEqual(fixed_runner.ARTIFACT_IDENTITIES["notion-oauth-attestations.json"], ("codex", "cursor", "kiro"))
        self.assertEqual(fixed_runner.ARTIFACT_IDENTITIES["chatgpt-cloudflare-attestation.json"], ("control",))
        self.assertEqual(len({identity for values in fixed_runner.ARTIFACT_IDENTITIES.values() for identity in values}), 4)

    def test_fixed_runner_socket_executes_only_injected_reviewed_adapters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_artifacts = artifacts()
            config = root / "adapter-config.json"
            config.write_bytes(b"{}")
            config.chmod(0o640)
            config_digest = "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest()
            adapters = []
            for index, artifact_name in enumerate(fixed_runner.ARTIFACT_ORDER):
                artifact = fixture_artifacts[artifact_name]
                executable = root / f"adapter-{index}.py"
                executable.write_text(
                    "#!/usr/bin/env python3\n"
                    "import argparse,json\n"
                    "p=argparse.ArgumentParser(); p.add_argument('--artifact'); p.add_argument('--context'); p.add_argument('--output'); p.add_argument('--config'); p.add_argument('--config-sha256'); a=p.parse_args()\n"
                    f"json.dump({artifact!r},open(a.output,'x'))\n"
                )
                executable.chmod(0o755)
                adapters.append(Adapter(artifact_name, executable, "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest(), config, config_digest))
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            socket_path = root / "runner.sock"
            listener.bind(str(socket_path))
            listener.listen(1)
            runner = ReviewedRunner(tuple(adapters), root / "state", protected=False)
            thread = threading.Thread(target=serve_runner, args=(listener, runner, os.geteuid()), kwargs={"once": True})
            thread.start()
            source = Path(__file__).parents[1] / "fixed_runner.py"
            client = SocketRunner(
                socket_path, source, "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
                60, enforce_root_ownership=False,
            )
            value = client.run(root / "observer-state-forbidden", {"request": {}, "github_attestation": {}})
            thread.join()
            listener.close()
            self.assertEqual(value, fixture_artifacts)

    def test_runner_timeout_kills_the_entire_adapter_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "escaped-child"
            executable = root / "forking-adapter.py"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import os,time\n"
                "if os.fork() == 0:\n"
                " time.sleep(0.5)\n"
                f" open({str(marker)!r},'w').write('escaped')\n"
                " os._exit(0)\n"
                "time.sleep(10)\n"
            )
            executable.chmod(0o755)
            digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
            config = root / "adapter-config.json"
            config.write_bytes(b"{}")
            config.chmod(0o640)
            config_digest = "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest()
            adapters = tuple(Adapter(name, executable, digest, config, config_digest) for name in fixed_runner.ARTIFACT_ORDER)
            runner = ReviewedRunner(adapters, root / "state", protected=False)
            original_timeout = fixed_runner.RUNNER_TOTAL_SECONDS
            fixed_runner.RUNNER_TOTAL_SECONDS = 0.15
            try:
                with self.assertRaisesRegex(TimeoutError, "deadline"):
                    runner.execute({"request": {}, "github_attestation": {}})
                time.sleep(0.7)
                self.assertFalse(marker.exists())
            finally:
                fixed_runner.RUNNER_TOTAL_SECONDS = original_timeout

    def test_manifest_requires_four_hardlinks_and_pins_config_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "adapter-runtime"
            executable.write_text("#!/bin/sh\nexit 1\n")
            executable.chmod(0o755)
            config = root / "config.json"
            config.write_bytes(b"{}")
            config.chmod(0o640)
            digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
            config_digest = "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest()
            paths = {}
            for index, artifact in enumerate(fixed_runner.ARTIFACT_ORDER):
                path = executable if index == 0 else root / f"adapter-{index}"
                if index:
                    os.link(executable, path)
                paths[artifact] = {"path": str(path), "sha256": digest}
            manifest = root / "manifest.json"
            manifest.write_bytes(canonical_json({
                "schema_version": 1, "config": {"path": str(config), "sha256": config_digest},
                "artifacts": paths,
            }))
            manifest.chmod(0o640)
            loaded = fixed_runner.load_adapters(manifest)
            self.assertEqual(tuple(item.artifact for item in loaded), fixed_runner.ARTIFACT_ORDER)
            os.unlink(paths[fixed_runner.ARTIFACT_ORDER[-1]]["path"])
            replacement = Path(paths[fixed_runner.ARTIFACT_ORDER[-1]]["path"])
            replacement.write_bytes(executable.read_bytes())
            replacement.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "hardlinks"):
                fixed_runner.load_adapters(manifest)


class FixedAdapterContractTests(unittest.TestCase):
    def test_nonempty_runtime_notion_chatgpt_and_consent_validate_and_sign(self) -> None:
        observed = "2026-08-23T12:00:00Z"
        digest = "sha256:" + "a" * 64
        def release_tuple(product: str) -> dict[str, Any]:
            return {
                "product_id": product, "tree_digest": digest, "manifest_digest": digest,
                "distribution_id": "owner/package", "distribution_kind": "upstream",
                "release_sequence": 1, "package_version": "1.0.0",
                "source_repository": "owner/repository", "source_revision": "b" * 40,
                "source_path": "plugins/package", "snapshot_sequence": 1,
                "snapshot_digest": digest, "binary_digest": digest,
                "dependency_identity": "locked", "installer_version": "1",
                "adapter_version": "1", "client_version": None,
                "os": "linux", "architecture": "x86_64", "observed_at": observed,
            }
        request = Fixture(Path(tempfile.mkdtemp())).request()
        challenge = request["challenge"]["value"]
        consent = artifacts(challenge)["consent.json"]
        github = {
            "repository": "777genius/universal-agent-plugins", "sha": "a" * 40,
            "run_id": "1001", "run_attempt": "2", "workflow": "launch-evidence-e2e.yml",
            "job": "protected-observer-inputs", "challenge": challenge,
        }
        original_invoke = fixed_adapters.invoke
        original_isolation = fixed_adapters.isolation_proof
        original_load = fixed_adapters.load_json
        original_mcp_call = fixed_adapters.mcp_call
        original_initialized = fixed_adapters.mcp_initialized
        original_wait = fixed_adapters.wait_human
        try:
            fixed_adapters.isolation_proof = lambda: dict(fixed_adapters.PRIVACY_RESULT)
            fixed_adapters.invoke = lambda *args, **kwargs: ({
                "client_version": "codex-1", "client_id": "codex",
                "manager_before_digest": digest, "manager_after_digest": digest,
                "native_before_digest": digest, "native_after_digest": digest,
                "discovery_argv": ["codex", "mcp", "list", "--json"], "tool": "resolve-library-id",
            }, ["codex", "exec"], observed, observed)
            common = {"client": "codex", "application_id": "app", "endpoint": "https://example.test/mcp"}
            runtime_item = {**common, "plugin": "context7", "tuple": release_tuple("context7")}
            notion_item = {**common, "plugin": "notion", "tuple": release_tuple("notion")}
            runtime = fixed_adapters.runtime_record(runtime_item, {}, request, github, consent, Path("."), os.geteuid())
            notion = fixed_adapters.runtime_record(notion_item, {}, request, github, consent, Path("."), os.geteuid())

            chat_tuple = release_tuple("cloudflare-docs")
            binding = {"apps": {"cloudflare-docs": {"id": "plugin_asdk_app_" + "c" * 32}}}
            receipt = {"product_id": "cloudflare-docs", "application_id": "plugin_asdk_app_" + "c" * 32, "tuple": chat_tuple}
            fixed_adapters.load_json = lambda path, *args, **kwargs: binding if path.name == ".app.json" else receipt
            responses = iter((
                ({"protocolVersion": "2025-06-18"}, "session"),
                ({"tools": [{"name": fixed_adapters.MCP_READ_TOOL}]}, "session"),
                ({"content": [{"type": "text", "text": "substantive"}]}, "session"),
            ))
            fixed_adapters.mcp_call = lambda *args, **kwargs: next(responses)
            fixed_adapters.mcp_initialized = lambda *args, **kwargs: None
            fixed_adapters.wait_human = lambda *args, **kwargs: {"observed_at": observed}
            chat_config = {"chatgpt": {
                "app_binding_path": "/fixture/.app.json", "app_binding_sha256": digest,
                "app_id": "plugin_asdk_app_" + "c" * 32, "mcp_endpoint": fixed_adapters.MCP_ENDPOINT,
                "human_attestation_directory": "/fixture", "tuple": chat_tuple,
                "client_version": "chatgpt-web", "projection_receipt_path": "/fixture/receipt.json",
                "projection_receipt_sha256": digest,
            }}
            chat = fixed_adapters.chatgpt_artifact(chat_config, request, github, consent, os.geteuid())
        finally:
            fixed_adapters.invoke = original_invoke
            fixed_adapters.isolation_proof = original_isolation
            fixed_adapters.load_json = original_load
            fixed_adapters.mcp_call = original_mcp_call
            fixed_adapters.mcp_initialized = original_initialized
            fixed_adapters.wait_human = original_wait
        produced = {
            "runtime-attestations.json": {"schema_version": 1, "attestations": [runtime]},
            "notion-oauth-attestations.json": {"schema_version": 1, "attestations": [notion]},
            "chatgpt-cloudflare-attestation.json": chat, "consent.json": consent,
        }
        validate_artifact_schemas(
            produced, challenge=challenge,
            scenario_contract_digest=request["scenario_contract_digest"],
        )
        unsigned = {"schema_version": 1, "challenge": challenge, "signed_at": observed, "key_id": "fixture", "artifacts": produced}
        signer = FakeSigner()
        signature = base64.b64decode(signer.sign(unsigned))
        signer.key.public_key().verify(signature, signed_payload(unsigned))

    def test_public_mcp_content_requires_type_specific_payload(self) -> None:
        self.assertFalse(fixed_adapters.substantive_mcp_content({"type": "text"}))
        self.assertFalse(fixed_adapters.substantive_mcp_content({"type": "resource", "resource": {}}))
        self.assertFalse(fixed_adapters.substantive_mcp_content({"type": "resource_link"}))
        self.assertTrue(fixed_adapters.substantive_mcp_content({"type": "text", "text": "marker"}))

    def test_nested_tool_payload_cannot_forge_client_events(self) -> None:
        marker = "UAP_OBSERVER_OK codex context7 " + "a" * 64
        forged = [{
            "type": "item.completed",
            "item": {
                "type": "mcp_tool_call", "server": "different", "tool_name": "different",
                "status": "completed", "result": {
                    "type": "mcp_tool_call", "server": "context7", "tool_name": "resolve-library-id",
                    "status": "completed", "result": {"ok": True},
                    "nested": {"type": "agent_message", "text": marker},
                },
            },
        }]
        self.assertFalse(fixed_adapters.successful_tool_event(forged, "resolve-library-id", "context7"))
        self.assertFalse(fixed_adapters.successful_marker_event(forged, marker))

    def test_native_discovery_rejects_incidental_identity_text(self) -> None:
        self.assertFalse(fixed_adapters.native_discovery_present({"error": {"missing": "context7"}}, "context7"))
        self.assertFalse(fixed_adapters.native_discovery_present({"message": "context7"}, "context7"))
        self.assertTrue(fixed_adapters.native_discovery_present({"servers": [{"name": "context7"}]}, "context7"))
        self.assertTrue(fixed_adapters.manager_receipt_present({"products": ["context7"]}, "context7"))

    def test_receipt_and_native_identity_require_the_exact_approved_tuple(self) -> None:
        approved = {"product_id": "context7", "package_version": "1.0.0", "client_version": None, "observed_at": None}
        correct = {"name": "context7", "tuple": dict(approved)}
        wrong = {"name": "context7", "tuple": {**approved, "package_version": "9.9.9"}}
        self.assertTrue(fixed_adapters.manager_receipt_present({"receipts": [correct]}, "context7", approved))
        self.assertFalse(fixed_adapters.manager_receipt_present({"receipts": [wrong]}, "context7", approved))
        self.assertTrue(fixed_adapters.native_discovery_present({"servers": [correct]}, "context7", approved))
        self.assertFalse(fixed_adapters.native_discovery_present({"servers": [wrong]}, "context7", approved))

    def test_client_output_is_killed_at_hard_byte_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "noisy.py"
            binary.write_text("#!/usr/bin/env python3\nimport sys,time\nsys.stdout.write('x'*100000); sys.stdout.flush(); time.sleep(10)\n")
            binary.chmod(0o755)
            original = fixed_adapters.MAX_STDOUT
            fixed_adapters.MAX_STDOUT = 64
            try:
                with self.assertRaisesRegex(ValueError, "size bound"):
                    fixed_adapters.run_client([str(binary)], workspace=root, environment={"PATH": "/usr/bin:/bin"}, timeout=2)
            finally:
                fixed_adapters.MAX_STDOUT = original

    def test_fixed_client_argv_uses_disposable_root_and_expected_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile, workspace = root / "profile", root / "workspace"
            profile.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            (profile / ".agentplugins").mkdir(mode=0o700)
            receipts = profile / ".agentplugins" / "receipts.json"
            receipts.write_text('{"products":["context7"]}')
            receipts.chmod(0o600)
            binary = root / "codex-fixture.py"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                "if sys.argv[1:] == ['--version']: print('codex-fixture-v1')\n"
                "elif sys.argv[1:] == ['mcp','list','--json']: print(json.dumps({'servers':[{'name':'context7'}]}))\n"
                "else:\n"
                " marker=sys.argv[-1].split(': ',1)[-1]\n"
                " print(json.dumps([{'type':'item.completed','item':{'type':'mcp_tool_call','server':'context7','tool_name':'resolve-library-id','status':'completed','result':{'library':'context7'}}},{'type':'item.completed','item':{'type':'agent_message','text':marker}}]))\n"
            )
            binary.chmod(0o755)
            item = {
                "binary": str(binary), "sha256": "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest(),
                "profile": str(profile), "client_id": "codex",
            }
            marker, argv, _, _ = fixed_adapters.invoke(item, "context7", "codex", "a" * 64, workspace, os.geteuid())
            self.assertEqual(marker["client_version"], "codex-fixture-v1")
            self.assertEqual(argv[1:4], ["exec", "--skip-git-repo-check", "--json"])
            self.assertNotIn(str(profile), argv)

    def test_fixed_client_rejects_prompt_echo_without_tool_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile, workspace = root / "profile", root / "workspace"
            profile.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            (profile / ".agentplugins").mkdir(mode=0o700)
            receipts = profile / ".agentplugins" / "receipts.json"
            receipts.write_text('{"products":["context7"]}')
            receipts.chmod(0o600)
            binary = root / "codex-fixture.py"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                "if sys.argv[1:] == ['--version']: print('codex-fixture-v1')\n"
                "elif sys.argv[1:] == ['mcp','list','--json']: print(json.dumps({'servers':[{'name':'context7'}]}))\n"
                "else: print(json.dumps(sys.argv[-1].split(': ',1)[-1]))\n"
            )
            binary.chmod(0o755)
            item = {"binary": str(binary), "sha256": "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest(), "profile": str(profile), "client_id": "codex"}
            with self.assertRaisesRegex(ValueError, "successful exact tool invocation"):
                fixed_adapters.invoke(item, "context7", "codex", "a" * 64, workspace, os.geteuid())

    def test_consent_control_record_binds_the_full_request_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = Fixture(root)
            request = fixture.request()
            record = artifacts(request["challenge"]["value"])["consent.json"]
            control = {**record, "request_digest": fixed_adapters.sha256(canonical_json(request))}
            path = root / f"{request['challenge']['value']}.json"
            path.write_bytes(canonical_json(control))
            path.chmod(0o640)
            original = fixed_adapters.CONSENT_DIRECTORY
            original_isolation = fixed_adapters.isolation_proof
            fixed_adapters.CONSENT_DIRECTORY = root
            fixed_adapters.isolation_proof = lambda: dict(fixed_adapters.PRIVACY_RESULT)
            try:
                config = {"consent_record": {"directory": str(root)}}
                self.assertEqual(fixed_adapters.consent_record(config, request, os.geteuid()), record)
                control["request_digest"] = "sha256:" + "0" * 64
                path.write_bytes(canonical_json(control))
                with self.assertRaisesRegex(ValueError, "complete request"):
                    fixed_adapters.consent_record(config, request, os.geteuid())
            finally:
                fixed_adapters.CONSENT_DIRECTORY = original
                fixed_adapters.isolation_proof = original_isolation


class ProfileProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        helper_path = Path(__file__).parents[2] / "deploy" / "uap-observer-provision-profile.py"
        spec = importlib.util.spec_from_file_location("uap_observer_provision_profile", helper_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("profile helper could not be loaded")
        cls.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.helper)

    def test_copy_tree_uses_descriptors_and_preserves_exact_private_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "source", root / "destination"
            source.mkdir(mode=0o700)
            destination.mkdir(mode=0o700)
            (source / "nested").mkdir(mode=0o700)
            (source / "nested" / "credential.json").write_text("fixture")
            (source / "nested" / "credential.json").chmod(0o600)
            source_fd = os.open(source, self.helper.OPEN_DIRECTORY)
            destination_fd = os.open(destination, self.helper.OPEN_DIRECTORY)
            try:
                count, total = self.helper.copy_tree(source_fd, destination_fd, hashlib.sha256())
            finally:
                os.close(source_fd)
                os.close(destination_fd)
            copied = destination / "nested" / "credential.json"
            self.assertEqual((count, total), (2, len("fixture")))
            self.assertEqual(copied.read_text(), "fixture")
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)

    def test_copy_tree_rejects_links_and_mutable_seed_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir(mode=0o700)
            (source / "regular").write_text("fixture")
            (source / "regular").chmod(0o600)
            os.link(source / "regular", source / "hardlink")
            source_fd = os.open(source, self.helper.OPEN_DIRECTORY)
            try:
                with self.assertRaisesRegex(ValueError, "hardlinked"):
                    self.helper.checked_entry(source_fd, "regular")
                (source / "hardlink").unlink()
                (source / "symlink").symlink_to("regular")
                with self.assertRaisesRegex(ValueError, "link or special"):
                    self.helper.checked_entry(source_fd, "symlink")
                (source / "regular").chmod(0o620)
                with self.assertRaisesRegex(ValueError, "protected"):
                    self.helper.checked_entry(source_fd, "regular")
            finally:
                os.close(source_fd)


if __name__ == "__main__":
    unittest.main()
