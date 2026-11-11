"""Offline fixtures only: no package commands, accounts or network."""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import catalog_publication_readiness as gate
import directory_publication as publication
import run_mcp_e2e as mcp

# Synthetic fixed release authority for offline contract tests only.
PROJECT_RELEASE_FIXTURE = {"cli": {"version": "0.1.103", "tag": "agentplugins-v0.1.103",
    "commit": "a" * 40, "binary_digest": "sha256:" + "b" * 64},
    "checksums_digest": "sha256:" + "c" * 64, "manifest_digest": "sha256:" + "d" * 64}


SIGNED45_FEED = ROOT / "tests/fixtures/catalog-signed45"
SIGNED46_FEED = ROOT / "tests/fixtures/catalog-signed46"


class ProofTime(datetime):
    """Fixed offline verification time within both original signed lifetimes."""
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 11, 1, 0, tzinfo=timezone.utc)


def paired_arguments(root):
    snapshot = json.loads((SIGNED46_FEED / "snapshots/00000000000000000046.json").read_text())
    args = arguments(snapshot)
    args.repository = "777genius/universal-agent-plugins-registry"
    args.source_sha = snapshot["source_commit"]
    args.signed_ledger_sha = "a154e1524d41975afb5b02bcac2474a3930f7ebd"
    # Synthetic materialization/workflow invocation for offline contract tests.
    args.sequence = 46
    args.snapshot_digest = gate.digest((SIGNED46_FEED / "snapshots/00000000000000000046.json").read_bytes())
    args.directory_origin = f"https://raw.githubusercontent.com/{args.repository}/{args.materialized_ledger_sha}/registry/schemas/1/"
    args.feed, args.baseline_feed = SIGNED46_FEED, SIGNED45_FEED
    args.trusted_keys = ROOT / "registry/publication/trusted-keys.json"
    for field in ("binary", "managed_binary", "project_binary", "sandbox", "output", "claude", "copilot", "codex", "opencode", "npx"):
        setattr(args, field, root / field)
    args.inspector = None
    return args



def load_historical_source(args, ctx):
    """Point-in-time audit only; no historical flag on current publisher args."""
    historical = copy.deepcopy(args)
    historical.refusal_feed = SIGNED45_FEED
    return gate.load_refusal_source(historical, ctx)


def synthetic_catalog(value):
    """Copy policy/source facts into synthetic offline unit context only."""
    value = copy.deepcopy(value)
    for distribution in value["distributions"]:
        for release in distribution["releases"]:
            if release["package_source"]["revision"] is None:
                release["package_source"]["revision"] = "a" * 40
    value.update(sequence=20, publication_id="test-publication", source_commit="a" * 40,
                 snapshot_schema_version=1, generated_at="2026-08-30T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    return value


def catalog():
    # Keep final signed45 source authority independent of unsigned future policy.
    return synthetic_catalog(json.loads((SIGNED45_FEED / "snapshots/00000000000000000045.json").read_text()))


def unsigned_source_catalog():
    return synthetic_catalog(json.loads((ROOT / "registry/directory.json").read_text()))


def arguments(snapshot):
    values = dict(repository="777genius/universal-agent-plugins", source_sha="a" * 40,
                  workflow_sha="b" * 40, signed_ledger_sha="c" * 40,
                  materialized_ledger_sha="d" * 40, publication_id=snapshot["publication_id"],
                  sequence=20, snapshot_digest="sha256:" + "e" * 64, run_id="123", run_attempt=1,
                  directory_origin="https://raw.githubusercontent.com/777genius/universal-agent-plugins/" + "d" * 40 + "/registry/schemas/1/")
    return argparse.Namespace(**values)


class CatalogContractTests(unittest.TestCase):
    def setUp(self):
        release = patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE)
        release.start()
        self.addCleanup(release.stop)
        self.snapshot = catalog()
        self.args = arguments(self.snapshot)
        self.identity = {"sequence": 20, "snapshot_digest": self.args.snapshot_digest}
        self.baseline = copy.deepcopy(self.snapshot)
        self.baseline["sequence"] = 13
        self.baseline_identity = {"sequence": 13, "snapshot_digest": "sha256:" + "f" * 64}

    def expected(self):
        return gate.expected_artifact(self.snapshot, self.baseline, self.baseline_identity,
                                      gate.context(self.args, self.snapshot, self.identity))

    def test_frozen_signed45_feed_authenticates_untouched_bytes_and_provenance(self):
        # This loads original signed bytes, not catalog()'s synthetic unit
        # context. Only historical expiry is relaxed by baseline=True.
        snapshot, identity = gate.load_feed(SIGNED45_FEED, ROOT / "registry/publication/trusted-keys.json", baseline=True)
        provenance = json.loads((SIGNED45_FEED / "provenance.json").read_text())
        self.assertEqual(identity, {"sequence": 45, "snapshot_digest": "sha256:2aba9b0d97556ac0756dff5f974aa7377914e0d8d1d9b735b46c5bc804b81f50"})
        self.assertEqual(snapshot["publication_id"], provenance["publication_id"])
        self.assertEqual(snapshot["source_commit"], provenance["source_commit"])
        self.assertEqual(provenance["publication_id"], "42888897655")
        self.assertEqual(provenance["source_commit"], "8c032ba2169637c1c42f0b8080da7ba3713a48ac")
        self.assertEqual(provenance["materialized_ledger_sha"], "3509baaac8e4f7ee3d565440f8c0d0bd1f928fba")
        self.assertEqual(provenance["snapshot_digest"], identity["snapshot_digest"])
        root = next(item for item in snapshot["distributions"] if item["id"] == gate.managed.ROOT)
        clients = tuple(target["client"] for target in root["release_policies"][0]["targets"])
        self.assertEqual(clients, gate.managed.CLIENTS)
        self.assertNotIn("vscode", clients)

    def test_fixed_matrix_fallback_and_honest_claims(self):
        artifact = self.expected()
        self.assertEqual(len(artifact["rows"]), 380)
        self.assertEqual(len(artifact["static_metadata"]), 2)
        self.assertEqual(len(artifact["mcp_probes"]), 4)
        chrome = [row for row in artifact["rows"] if row["selector"] == "chrome-devtools"]
        self.assertEqual({row["client"] for row in chrome}, set(gate.CATALOG_CLIENTS))
        self.assertTrue(
            {(alias, client) for alias in gate.ALIASES for client in gate.CATALOG_CLIENTS}
            <= {(row["selector"], row["client"]) for row in artifact["rows"]},
        )
        self.assertEqual({row["distribution_id"] for row in chrome}, {"777genius/chrome-devtools-bridge"})
        bridge = next(item for item in self.snapshot["distributions"] if item["id"] == "777genius/chrome-devtools-bridge")
        active_sequence = next(item["release_sequence"] for item in bridge["release_policies"] if item["status"] == "active")
        self.assertEqual({row["release_sequence"] for row in chrome}, {active_sequence})
        self.assertTrue(all(row["fallback_reason"] for row in chrome))
        context7_fallback = [row for row in artifact["rows"] if row["selector"] == "777genius/context7"]
        self.assertEqual({row["client"] for row in context7_fallback}, set(gate.CATALOG_CLIENTS))
        self.assertEqual({row["distribution_id"] for row in context7_fallback}, {"777genius/context7"})
        self.assertNotIn(
            next(product for product in self.snapshot["products"] if product["id"] == "context7")["default_distribution"],
            {probe["distribution_id"] for probe in artifact["mcp_probes"]},
        )
        self.assertTrue(all(
            gate.credential_free_probe(gate.selected(self.snapshot, probe["distribution_id"], gate.CATALOG_CLIENTS))
            for probe in artifact["mcp_probes"]
        ))
        github = [row for row in artifact["rows"] if row["selector"] == "github/github"]
        self.assertEqual({row["client"] for row in github}, set(gate.CORE))
        self.assertEqual({row["distribution_id"] for row in github}, {"github/github"})
        self.assertTrue(all(row["fallback_reason"] is None for row in github))
        self.assertIs(artifact["runtime_claims"], False)
        self.assertTrue(all(row["oauth"] == "not_tested" for row in artifact["mcp_probes"]))
        gate.validate_artifact(artifact, self.expected())

    def test_rejects_mutated_identity_partial_rows_runtime_claims_and_extra_fields(self):
        for mutation in (
            lambda value: value["rows"].pop(),
            lambda value: value["rows"].append(value["rows"][0]),
            lambda value: value.update(runtime_claims=True),
            lambda value: value.update(runtime_claims=0),
            lambda value: value["cli"].update(version="0.1.27"),
            lambda value: value["context"].update(run_attempt=2),
            lambda value: value["mcp_probes"].pop(),
            lambda value: value["rows"][0]["proof"].update(acquisition_count=True),
            lambda value: value["static_metadata"][0].update(native_activation="passed"),
            lambda value: value.update(stdout="private"),
        ):
            with self.subTest(mutation=mutation):
                expected = self.expected()
                changed = copy.deepcopy(expected)
                mutation(changed)
                with self.assertRaises(ValueError):
                    gate.validate_artifact(changed, expected)

    def test_context_rejects_wrong_source_run_origin_and_snapshot(self):
        for field, value in (("source_sha", "b" * 40), ("run_id", "1/attempts/2"),
                             ("directory_origin", "https://example.com/feed/"), ("sequence", True),
                             ("snapshot_digest", "sha256:" + "1" * 64), ("publication_id", "old")):
            args = copy.deepcopy(self.args)
            setattr(args, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.context(args, self.snapshot, self.identity)

    def test_identity_accepts_omitted_empty_version_but_not_a_wrong_version(self):
        selection = gate.selected(self.snapshot, "github", gate.CORE)
        self.assertEqual(selection["package_version"], "")
        source = selection["package_source"]
        data = {
            "plugin": selection["product_id"],
            "source": gate.public_source(source),
            "revision": source["revision"],
            "tree_digest": selection["tree_digest"],
            "manifest_digest": selection["manifest_digest"],
            "directory": {
                "product_id": selection["product_id"],
                "distribution_id": selection["distribution_id"],
                "distribution_kind": selection["distribution_kind"],
                "desired_release_sequence": selection["release_sequence"],
                "snapshot_schema": 1,
                "snapshot_sequence": self.identity["sequence"],
                "snapshot_digest": self.identity["snapshot_digest"],
            },
        }

        gate.check_identity(data, selection, self.identity)
        data["version"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "wrong version"):
            gate.check_identity(data, selection, self.identity)

    def test_identity_still_requires_a_nonempty_version(self):
        selection = gate.selected(self.snapshot, "context7", gate.CORE)
        self.assertTrue(selection["package_version"])
        source = selection["package_source"]
        data = {
            "plugin": selection["product_id"],
            "source": gate.public_source(source),
            "revision": source["revision"],
            "tree_digest": selection["tree_digest"],
            "manifest_digest": selection["manifest_digest"],
            "directory": {
                "product_id": selection["product_id"],
                "distribution_id": selection["distribution_id"],
                "distribution_kind": selection["distribution_kind"],
                "desired_release_sequence": selection["release_sequence"],
                "snapshot_schema": 1,
                "snapshot_sequence": self.identity["sequence"],
                "snapshot_digest": self.identity["snapshot_digest"],
            },
        }

        with self.assertRaisesRegex(ValueError, "wrong version"):
            gate.check_identity(data, selection, self.identity)

    def test_identity_source_matches_the_pinned_cli_public_repository_path(self):
        # The released CLI renders add's source as repository/subpath
        # (publicRepositoryPath at the pinned commit). The harness once demanded
        # a repository//subpath string the released CLI never emits, so every
        # real add failed validate_add with "CLI selected wrong source".
        selection = gate.selected(self.snapshot, "context7", gate.CORE)
        source = selection["package_source"]
        repository, subpath = source["repository"].strip("/"), source["path"].strip("/")
        rendered = repository if not subpath else repository + "/" + subpath
        self.assertEqual(gate.public_source(source), rendered)
        self.assertNotIn("//", rendered)
        data = {
            "plugin": selection["product_id"],
            "version": selection["package_version"],
            "source": rendered,
            "revision": source["revision"],
            "tree_digest": selection["tree_digest"],
            "manifest_digest": selection["manifest_digest"],
            "directory": {
                "product_id": selection["product_id"],
                "distribution_id": selection["distribution_id"],
                "distribution_kind": selection["distribution_kind"],
                "desired_release_sequence": selection["release_sequence"],
                "snapshot_schema": 1,
                "snapshot_sequence": self.identity["sequence"],
                "snapshot_digest": self.identity["snapshot_digest"],
            },
        }
        gate.check_identity(data, selection, self.identity)
        for wrong in (repository + "//" + subpath, rendered + "/extra",
                      repository.upper() + "/" + subpath, "local"):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, "wrong source"):
                gate.check_identity({**data, "source": wrong}, selection, self.identity)
        self.assertEqual(gate.public_source({"repository": "/example/repo/", "path": "/"}), "example/repo")
        self.assertEqual(gate.public_source({"repository": "r/", "path": "/plugins/context7/"}), "r/plugins/context7")
        for missing in ({"repository": "//", "path": "pkg"}, {"repository": "  ", "path": "pkg"}):
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "repository missing"):
                gate.public_source(missing)

    def test_new_uncovered_target_policy_fails_closed(self):
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == "777genius/cloudflare")
        policy = next(item for item in distribution["release_policies"] if item["status"] == "active")
        policy["targets"][0]["delivery"] = "surprise"
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            self.expected()

    def test_uncovered_alternate_reactivation_or_new_release_cannot_reuse_old_target(self):
        for change in ("reactivation", "new_release", "lower_floor"):
            with self.subTest(change=change):
                self.snapshot, self.baseline = catalog(), catalog()
                old = next(item for item in self.baseline["distributions"] if item["id"] == "777genius/cloudflare")
                new = next(item for item in self.snapshot["distributions"] if item["id"] == "777genius/cloudflare")
                if change == "reactivation":
                    old["status"] = "suspended"
                elif change == "new_release":
                    for policy in new["release_policies"]:
                        policy["release_sequence"] += 100
                else:
                    for policy in old["release_policies"]:
                        policy["minimum_installer_version"] = "0.1.27"
                with self.assertRaisesRegex(ValueError, "uncovered"):
                    self.expected()

    def test_unselected_release_cannot_borrow_selected_distribution_coverage(self):
        selection = gate.selected(self.snapshot, "chrome-devtools", gate.CHROME)
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == selection["distribution_id"])
        extra = copy.deepcopy(selection["policy"])
        extra["release_sequence"] = 0
        distribution["release_policies"].append(extra)
        with self.assertRaisesRegex(ValueError, "uncovered"):
            self.expected()

    def test_new_client_claims_only_land_where_the_fixed_matrix_resolves_them(self):
        # Regression: the thirteen-client widening once reached shadowed active
        # policies (whose own target set resolves to a newer release), claiming
        # installs the readiness matrix can never exercise.  Against a
        # pre-widening baseline those claims were unprovable and staged
        # publication failed closed with "uncovered target policy change".
        stripped = copy.deepcopy(self.snapshot)
        for distribution in stripped["distributions"]:
            for policy in distribution["release_policies"]:
                policy["targets"] = [target for target in policy["targets"]
                                     if target["client"] not in ("grok", "kimi", "qoder")]
        self.baseline = stripped
        self.expected()

        firebase = next(item for item in self.snapshot["distributions"] if item["id"] == "777genius/firebase")
        current = max((policy for policy in firebase["release_policies"] if policy["status"] == "active"),
                      key=lambda policy: policy["release_sequence"])
        # Construct a shadowed active policy explicitly: production may correctly
        # supersede every older release when promoting a security update.
        shadowed = next(policy for policy in firebase["release_policies"]
                        if policy["status"] == "superseded"
                        and policy["release_sequence"] < current["release_sequence"])
        shadowed["status"] = "active"
        shadowed["targets"] = [target for target in shadowed["targets"]
                               if target["client"] not in ("grok", "kimi", "qoder")]
        baseline_firebase = next(item for item in self.baseline["distributions"]
                                 if item["id"] == firebase["id"])
        baseline_shadowed = next(policy for policy in baseline_firebase["release_policies"]
                                 if policy["release_sequence"] == shadowed["release_sequence"])
        baseline_shadowed["status"] = "active"
        self.expected()
        shadowed["targets"] = copy.deepcopy(current["targets"])
        with self.assertRaisesRegex(ValueError, "uncovered target policy change: 777genius/firebase:(grok|kimi|qoder)"):
            self.expected()

    def test_authentication_tightening_is_not_account_runtime_expansion(self):
        for snapshot, authentication in ((self.baseline, "not_required"), (self.snapshot, "required")):
            distribution = next(item for item in snapshot["distributions"] if item["id"] == "777genius/cloudflare")
            for policy in distribution["release_policies"]:
                for target in policy["targets"]:
                    target["authentication"] = authentication
        self.expected()
        self.snapshot, self.baseline = self.baseline, self.snapshot
        with self.assertRaisesRegex(ValueError, "uncovered target"):
            self.expected()

    def test_new_cli_floor_and_missing_alias_fail(self):
        selected = gate.selected(self.snapshot, "chrome-devtools", gate.CHROME)
        distribution = next(item for item in self.snapshot["distributions"] if item["id"] == selected["distribution_id"])
        major, minor, patch = (int(part) for part in gate.CLI["version"].split("."))
        for policy in distribution["release_policies"]:
            policy["minimum_installer_version"] = "%d.%d.%d" % (major, minor, patch + 1)
        with self.assertRaisesRegex(ValueError, "newer CLI"):
            gate.plan(self.snapshot)
        self.snapshot = catalog()
        self.snapshot["products"] = [p for p in self.snapshot["products"] if p["id"] != "github"]
        with self.assertRaises(Exception):
            gate.plan(self.snapshot)

    def test_qualified_fallback_does_not_replace_short_alias_or_duplicate_selection(self):
        product = next(item for item in self.snapshot["products"] if item["id"] == "context7")
        default_id = product["default_distribution"]
        for snapshot in (self.snapshot, self.baseline):
            default = next(item for item in snapshot["distributions"] if item["id"] == default_id)
            policy = next(item for item in default["release_policies"] if item["status"] == "active")
            policy["targets"] = [target for target in policy["targets"] if target["client"] in gate.CORE]

        selections = gate.plan(self.snapshot)
        context7 = [(selection, clients) for selection, clients in selections
                    if selection["product_id"] == "context7"]
        self.assertEqual(len(context7), 2)
        self.assertEqual(
            {(selection["distribution_id"], selection.get("_case_id"), clients) for selection, clients in context7},
            {("777genius/context7", None, gate.CATALOG_CLIENTS),
             (default_id, "default-context7", gate.CORE)},
        )
        for selection, _ in context7:
            gate.lifecycle_step(argparse.Namespace(), selection.get("_case_id", selection["selector"]), "complete")

    def test_read_json_rejects_duplicates_and_noncanonical_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "artifact.json"
            for body in (b'{"x":1,"x":2}\n', b'{ "x": 1 }\n'):
                path.write_bytes(body)
                with self.assertRaises((ValueError, publication.PublicationError)):
                    gate.read_json(path, canonical=True)

    def test_actual_signed_feed_and_tamper(self):
        fixture = ROOT / "tests/fixtures/directory-publication"
        with tempfile.TemporaryDirectory() as root:
            feed = Path(root)
            (feed / "snapshots").mkdir()
            latest = json.loads((fixture / "latest.json").read_text())
            for destination, source in (("latest.json", "latest.json"),
                                        (latest["snapshot_path"], "snapshot.json"),
                                        (latest["envelope_path"], "envelope-current.json")):
                (feed / destination).write_bytes((fixture / source).read_bytes())
            snapshot, identity = gate.load_feed(feed, fixture / "trusted-keys.json", baseline=True)
            self.assertEqual(identity["sequence"], 15)
            (feed / latest["snapshot_path"]).write_bytes(publication.canonical_json({**snapshot, "sequence": 16}))
            with self.assertRaises(publication.PublicationError):
                gate.load_feed(feed, fixture / "trusted-keys.json", baseline=True)

    def test_environment_does_not_inherit_credentials_or_directory_injection(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"GH_TOKEN": "secret", "OPENAI_API_KEY": "secret", "AGENTPLUGINS_DIRECTORY_SNAPSHOT": "/bad"}):
            _, env = gate.isolated_environment(Path(root), self.args.directory_origin, ())
            self.assertFalse({"GH_TOKEN", "OPENAI_API_KEY", "AGENTPLUGINS_DIRECTORY_SNAPSHOT"} & env.keys())
            self.assertEqual(env["AGENTPLUGINS_DIRECTORY_ORIGIN"], self.args.directory_origin)

    def test_add_invokes_the_released_cli_with_no_save(self):
        # 0.1.88's add distinguishes manifest saving; the readiness add step must
        # install without saving portable dependency intent.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tools = root / "tools"
            tools.mkdir()
            for name in ("agentplugins", "claude", "copilot", "npx"):
                (tools / name).write_bytes(b"fixture only; never executed")
            args = argparse.Namespace(binary=tools / "agentplugins", claude=tools / "claude",
                                      copilot=tools / "copilot", npx=tools / "npx",
                                      inspector=None, opencode=None)
            invocations = []
            def stop_at_add(binary, argv, env, cwd, *, root, readonly):
                invocations.append(argv)
                raise ValueError("fixture stops at the add step")
            selection = gate.selected(self.snapshot, "context7", gate.CORE)
            with patch.object(gate, "command", side_effect=stop_at_add):
                with self.assertRaisesRegex(ValueError, "fixture stops"):
                    gate.run_lifecycle(args, root / "case", selection, gate.CORE, vars(self.args))
            self.assertEqual(invocations, [["add", "context7", "--target", "codex,cursor,kiro", "--no-save"]])

    def test_isolated_environment_seeds_grok_kimi_qoder_roots_and_path_stubs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            roots, env = gate.isolated_environment(root, self.args.directory_origin, ())
            for name in (".grok", ".kimi-code", ".qoder"):
                self.assertTrue((roots["home"] / name).is_dir(), f"missing {name} config root")
            tool_bin = root / "bin"
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(tool_bin))
            for name in ("grok", "kimi", "qoder"):
                stub = tool_bin / name
                self.assertTrue(stub.is_file(), f"missing {name} stub")
                self.assertTrue(os.access(stub, os.X_OK), f"{name} stub is not executable")

    def test_grok_kimi_qoder_stubs_answer_the_cli_projection_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            roots, env = gate.isolated_environment(root, self.args.directory_origin, ())
            self.assertTrue(all((root / "bin" / name).is_file() for name in ("grok", "kimi", "qoder")))
            def stub(name, *argv):
                return subprocess.run([str(root / "bin" / name), *argv], env=env,
                                      capture_output=True, text=True, check=False)
            self.assertEqual(stub("kimi", "--version").stdout.strip(), "1.0.0")
            package = root / "projected"
            for manifest in (".grok-plugin", ".qoder-plugin"):
                (package / manifest).mkdir(parents=True)
                (package / manifest / "plugin.json").write_text(
                    json.dumps({"name": "chrome-devtools", "version": "1.7.0"}, indent=2))
            self.assertEqual(json.loads(stub("grok", "plugin", "list", "--json").stdout), [])
            self.assertEqual(stub("grok", "plugin", "install", "--trust", str(package)).returncode, 0)
            self.assertEqual(json.loads(stub("grok", "plugin", "list", "--json").stdout),
                             [{"name": "chrome-devtools", "status": "installed", "source": str(package),
                               "version": "1.7.0"}])
            self.assertEqual(stub("grok", "plugin", "uninstall", "--confirm", "chrome-devtools").returncode, 0)
            self.assertEqual(json.loads(stub("grok", "plugin", "list", "--json").stdout), [])
            self.assertEqual(json.loads(stub("qoder", "plugins", "list", "--json").stdout), [])
            self.assertEqual(stub("qoder", "plugins", "install", str(package), "--scope", "user").returncode, 0)
            self.assertEqual(json.loads(stub("qoder", "plugins", "list", "--json").stdout),
                             [{"id": "chrome-devtools@local", "version": "1.7.0"}])
            self.assertEqual(stub("qoder", "plugins", "uninstall", "chrome-devtools").returncode, 0)
            self.assertEqual(json.loads(stub("qoder", "plugins", "list", "--json").stdout), [])

    def test_stub_state_drops_exact_names_and_rejects_corrupting_source_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            roots, env = gate.isolated_environment(root, self.args.directory_origin, ())
            def stub(name, *argv):
                return subprocess.run([str(root / "bin" / name), *argv], env=env,
                                      capture_output=True, text=True, check=False)
            def package(dirname, manifest_name, manifest):
                pkg = root / dirname
                (pkg / manifest).mkdir(parents=True)
                (pkg / manifest / "plugin.json").write_text(
                    json.dumps({"name": manifest_name, "version": "1.7.0"}, indent=2))
                return pkg
            # A numeric-looking name must not collide with a different name in
            # the state registry: "7" must never drop the "007" entry.
            numeric = package("numeric", "007", ".grok-plugin")
            self.assertEqual(stub("grok", "plugin", "install", "--trust", str(numeric)).returncode, 0)
            self.assertEqual(stub("grok", "plugin", "uninstall", "--confirm", "7").returncode, 0)
            self.assertEqual([item["name"] for item in json.loads(stub("grok", "plugin", "list", "--json").stdout)],
                             ["007"])
            qnumeric = package("qnumeric", "007", ".qoder-plugin")
            self.assertEqual(stub("qoder", "plugins", "install", str(qnumeric), "--scope", "user").returncode, 0)
            self.assertEqual(stub("qoder", "plugins", "uninstall", "7").returncode, 0)
            self.assertEqual(json.loads(stub("qoder", "plugins", "list", "--json").stdout),
                             [{"id": "007@local", "version": "1.7.0"}])
            # A source path with a pipe must be rejected: writing it into the
            # pipe-delimited registry would corrupt the list --json emission.
            weird = package("pa|ckage", "chrome-devtools", ".grok-plugin")
            self.assertNotEqual(stub("grok", "plugin", "install", "--trust", str(weird)).returncode, 0)
            qweird = package("qpa|ckage", "chrome-devtools", ".qoder-plugin")
            self.assertNotEqual(stub("qoder", "plugins", "install", str(qweird), "--scope", "user").returncode, 0)
            self.assertEqual(json.loads(stub("grok", "plugin", "list", "--json").stdout),
                             [{"name": "007", "status": "installed", "source": str(numeric), "version": "1.7.0"}])
            self.assertEqual(json.loads(stub("qoder", "plugins", "list", "--json").stdout),
                             [{"id": "007@local", "version": "1.7.0"}])
            # Ordinary extract paths with plus signs stay installable.
            plussed = package("pkg-1.7.0+build", "cloudflare-docs", ".grok-plugin")
            self.assertEqual(stub("grok", "plugin", "install", "--trust", str(plussed)).returncode, 0)
            self.assertEqual(json.loads(stub("grok", "plugin", "list", "--json").stdout),
                             [{"name": "007", "status": "installed", "source": str(numeric), "version": "1.7.0"},
                              {"name": "cloudflare-docs", "status": "installed", "source": str(plussed),
                               "version": "1.7.0"}])

    def test_stub_seeding_refuses_to_shadow_a_linked_tool_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            tool_bin = Path(temporary) / "bin"
            tool_bin.mkdir()
            fixture = tool_bin / "real-tool"
            fixture.write_bytes(b"fixture bytes")
            (tool_bin / "grok").symlink_to(fixture)
            with self.assertRaisesRegex(ValueError, "refusing to shadow"):
                gate.seed_client_stubs(tool_bin)
            self.assertEqual(fixture.read_bytes(), b"fixture bytes")
            self.assertTrue((tool_bin / "grok").is_symlink())

    def test_only_verified_active_activation_counts_for_stub_backed_clients(self):
        def target(name, activation):
            return {"target": name, "output": {"result": {"activation": activation}}}
        active = {"activation": "active", "verification": "installation_verified"}
        gate.require_verified_activation([target("grok", active), target("kimi", active), target("qoder", active)])
        for broken in ({"activation": "manual_activation_required", "verification": "installation_verified"},
                       {"activation": "active", "verification": "not_run"},
                       {"activation": "prepared", "verification": "package_validated"},
                       None,
                       "active"):
            with self.assertRaisesRegex(ValueError, "not verified"):
                gate.require_verified_activation([target("kimi", broken)])
        with self.assertRaises(KeyError):
            gate.require_verified_activation([{"target": "grok", "output": {"result": {}}}])
        # Clients outside the stub-backed set keep their documented outcomes.
        gate.require_verified_activation([target("vscode", {"activation": "manual_activation_required",
                                                            "verification": "not_run"})])

    def test_produce_parser_and_lifecycle_expose_the_native_opencode_fixture(self):
        # OpenCode preflight verifies native executable bytes and rejects
        # shell/npm shims, so the producer must receive a Go fixture and the
        # lifecycle must expose it on the case PATH as `opencode`.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tools = root / "tools"
            tools.mkdir()
            for name in ("agentplugins", "claude", "copilot", "npx", "opencode"):
                (tools / name).write_bytes(b"fixture only; never executed")
            argv = ["produce", "--feed", str(root / "feed"), "--trusted-keys", str(root / "keys"),
                    "--baseline-feed", str(root / "base")]
            for name, value in vars(self.args).items():
                argv += ["--" + name.replace("_", "-"), str(value)]
            argv += ["--binary", str(tools / "agentplugins"), "--claude", str(tools / "claude"),
                     "--copilot", str(tools / "copilot"), "--sandbox", str(root / "sandbox"),
                     "--output", str(root / "out.json"), "--opencode", str(tools / "opencode")]
            self.assertEqual(gate.parser().parse_args(argv).opencode, tools / "opencode")
            args = argparse.Namespace(binary=tools / "agentplugins", claude=tools / "claude",
                                      copilot=tools / "copilot", npx=tools / "npx",
                                      inspector=None, opencode=tools / "opencode")
            def stop_at_add(binary, argv, env, cwd, *, root, readonly):
                raise ValueError("fixture stops at the add step")
            selection = gate.selected(self.snapshot, "context7", gate.CORE)
            with patch.object(gate, "command", side_effect=stop_at_add):
                with self.assertRaisesRegex(ValueError, "fixture stops"):
                    gate.run_lifecycle(args, root / "case", selection, gate.CORE, vars(self.args))
            exposed = root / "case" / "bin" / "opencode"
            self.assertTrue(exposed.exists(), "opencode fixture missing from the lifecycle PATH")
            self.assertEqual(exposed.resolve(), (tools / "opencode").resolve())
            self.assertIn((tools / "opencode").resolve().parent, gate.tool_paths(args))

    @unittest.skipUnless(shutil.which("go"), "Go toolchain required to build the native fixture")
    def test_opencode_fixture_is_native_and_answers_only_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / "opencode"
            env = dict(os.environ, CGO_ENABLED="0", GO111MODULE="off", GOENV="off",
                       GOTOOLCHAIN="local", GOFLAGS="", GOPATH=str(root / "go-path"),
                       GOCACHE=str(root / "go-cache"), GOMODCACHE=str(root / "go-mod-cache"))
            build = subprocess.run(["go", "build", "-trimpath", "-o", str(binary),
                                    str(ROOT / "tests/fixtures/opencode-fixture.go")],
                                   env=env, capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertFalse(binary.read_bytes().startswith(b"#!"), "fixture is a script shim")
            self.assertIn(binary.read_bytes()[:4], (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                                                    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                                                    b"\xca\xfe\xba\xbe", b"MZ"),
                          "fixture is not native executable bytes")
            version = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout.strip(), "1.18.34")
            self.assertNotEqual(subprocess.run([str(binary), "--help"], capture_output=True).returncode, 0)
            home, sandbox = root / "home", root / "sandbox"
            home.mkdir(); sandbox.mkdir()
            tree = lambda: sorted(str(p.relative_to(root)) for base in (home, sandbox) for p in base.rglob("*"))
            before = tree()
            run = subprocess.run([str(binary), "--version"], cwd=sandbox,
                                 env={"PATH": "/usr/bin:/bin", "HOME": str(home)}, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(tree(), before, "fixture wrote to HOME or cwd at runtime")

    def test_acquired_root_mcp_override_does_not_use_repository_plugin(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            package, sandbox = root / "acquired", root / "sandbox"
            package.mkdir(); sandbox.mkdir()
            (package / "mcp.json").write_text(json.dumps({"mcpServers": {"context7": {"command": "node", "args": ["${PLUGIN_ROOT}/exact.mjs"]}}}))
            config, env = mcp.materialize_inspector_config("context7", sandbox, plugin_root=package)
            server = json.loads(config.read_text())["mcpServers"]["context7"]
            self.assertEqual(server["args"], [str(package.resolve() / "exact.mjs")])
            self.assertEqual(env["PLUGIN_ROOT"], str(package.resolve()))

    def test_exact_target_status_rejects_success_failure_contradiction(self):
        good = {"succeeded": 3, "failed": 0, "targets": [{"target": client, "status": "external_completed"} for client in gate.CORE]}
        gate.exact_targets(good, gate.CORE)
        for field, value in (("succeeded", True), ("failed", 1), ("targets", good["targets"][:2])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.exact_targets({**good, field: value}, gate.CORE)
        good["targets"][0]["status"] = "failed"
        with self.assertRaises(ValueError):
            gate.exact_targets(good, gate.CORE)

    def test_native_version_accepts_exact_branded_release_formats(self):
        # Copilot punctuation/notice format is documented by the exact released
        # c78c79 clientdetect/detector_test.go:397-435 fixtures (then 1.0.80).
        for output in ("GitHub Copilot CLI 1.0.82.\n", "GitHub Copilot CLI v1.0.82.\n",
                       "GitHub Copilot CLI 1.0.82\n", "GitHub Copilot CLI 1.0.82.\nA newer version is available."):
            with self.subTest(output=output):
                gate.validate_native_version("copilot", output)
        gate.validate_native_version("claude", "2.1.251 (Claude Code)\n")

    def test_native_version_rejects_malformed_or_wrong_version_even_in_notice(self):
        for output in ("", "GitHub Copilot CLI 1.0.82..", "GitHub Copilot CLI .1.0.82.",
                       "GitHub Copilot CLI 1..82.", "GitHub Copilot CLI 1.0.x.",
                       "GitHub Copilot CLI 1.0.82beta.", "GitHub Copilot CLI 1.0.82-beta.1.",
                       "GitHub Copilot CLI 1.0.82+build.1.", "GitHub Copilot CLI 11.0.82.",
                       "GitHub Copilot CLI 1.0.820.", "warning: GitHub Copilot CLI 1.0.82.",
                       "GitHub Copilot CLI 1.0.81.\nA newer version 1.0.82 is available.",
                       "GitHub Copilot CLI 1.0.81.\nGitHub Copilot CLI 1.0.82."):
            with self.subTest(output=output), self.assertRaises(ValueError):
                gate.validate_native_version("copilot", output)
        for output in ("2.1.250 (Claude Code)\nUpdate to 2.1.251", "12.1.251 (Claude Code)",
                       "2.1.251-beta (Claude Code)", "other-program 2.1.251", "2.1.251 (Claude Code) extra"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                gate.validate_native_version("claude", output)

    def test_native_version_diagnostics_distinguish_client_exit_and_format(self):
        for client, failure in (("claude", "exit"), ("claude", "format"), ("copilot", "exit"), ("copilot", "format")):
            with self.subTest(client=client, failure=failure), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary).resolve()
                tools = parent / "tools"
                tools.mkdir()
                for name in ("agentplugins", "claude", "copilot", "npx", "opencode"):
                    (tools / name).write_bytes(b"fixture only; not executed")
                args = argparse.Namespace(binary=tools / "agentplugins", claude=tools / "claude",
                                          copilot=tools / "copilot", npx=tools / "npx", inspector=None,
                                          opencode=tools / "opencode")
                def child(argv, **_):
                    name = Path(argv[0]).name
                    self.assertEqual(argv[1:], ["--version"])
                    output = "2.1.251 (Claude Code)\n" if name == "claude" else "GitHub Copilot CLI 1.0.82.\n"
                    code = 0
                    if name == client:
                        code = 9 if failure == "exit" else 0
                        output = "wrong format" if failure == "format" else output
                    return subprocess.CompletedProcess(argv, code, output, "not persisted")
                with patch.object(gate, "child", side_effect=child), self.assertRaises(ValueError):
                    gate.run_lifecycle(args, parent / "case", gate.selected(self.snapshot, "chrome-devtools", gate.CHROME),
                                       gate.CHROME, vars(self.args))
                self.assertEqual(args.failure_phase, f"lifecycle:chrome-devtools:native_version_{client}_{failure}")

    def test_static_package_binds_signed_app_key_to_acquired_http_interface(self):
        selection = gate.selected(self.snapshot, gate.STATIC[0], ("chatgpt",))
        with tempfile.TemporaryDirectory() as root:
            package = Path(root)
            (package / "plugin.json").write_text('{"name":"cloudflare-docs"}')
            mcp_path = package / "mcp.json"
            valid = {"mcpServers": {"cloudflare-docs": {"type": "streamable-http", "url": "https://docs.mcp.cloudflare.com/mcp"}}}
            mcp_path.write_text(json.dumps(valid))
            gate.check_static_package(package, selection)
            valid["mcpServers"]["cloudflare-docs"]["url"] = "https://other.example/mcp"
            mcp_path.write_text(json.dumps(valid))
            with self.assertRaisesRegex(ValueError, "acquired Cloudflare"):
                gate.check_static_package(package, selection)

    def test_shared_copilot_removes_natively_before_remaining_targets_and_purge(self):
        events = []
        def run(*argv):
            events.append(argv)
            clients = tuple(argv[argv.index("--target") + 1].split(","))
            return {"succeeded": len(clients), "failed": 0,
                    "targets": [{"target": client, "status": "external_completed"} for client in clients],
                    "plugin_data_preserved": False, "data_retained": False}
        gate.remove_targets(run, "chrome-devtools", gate.CHROME, lambda: events.append("native_absent"))
        self.assertEqual(events[0], ("remove", "chrome-devtools", "--target", "copilot,vscode"))
        self.assertEqual(events[1], "native_absent")
        self.assertEqual(events[2], ("remove", "chrome-devtools", "--target",
                                    "codex,cursor,kiro,claude,gemini,opencode,cline,windsurf,grok,kimi,qoder",
                                    "--external-uninstalled", "--purge-data"))

    def test_shared_native_failure_does_not_proceed_to_purge(self):
        run = unittest.mock.Mock(return_value={"succeeded": 0, "failed": 2, "targets": []})
        with self.assertRaises(ValueError):
            gate.remove_targets(run, "chrome-devtools", gate.CHROME, unittest.mock.Mock())
        self.assertEqual(run.call_count, 1)

    def test_cli_and_native_inspection_use_required_isolated_child(self):
        completed = subprocess.CompletedProcess([], 0, '{"command":"list","result":"success","data":{}}', "")
        with tempfile.TemporaryDirectory() as temporary, patch.object(gate, "child", return_value=completed) as child:
            root = Path(temporary)
            gate.command(root / "agentplugins", ["list"], {}, root, root=root, readonly=(root / "tools",))
            self.assertEqual(child.call_args.kwargs["root"], root)
            self.assertEqual(child.call_args.kwargs["readonly"], (root / "tools",))
            child.return_value = subprocess.CompletedProcess([], 0, '[]', "")
            gate.native_listing(Path("claude"), {}, root, "chrome-devtools", False, root=root, readonly=())
            self.assertEqual(child.call_args.args[0], ["claude", "plugin", "list", "--json"])

    def test_copilot_exact_official_empty_registry_after_removal(self):
        official = "No plugins installed.\n\nUse 'copilot plugin install <source>' to install a plugin."
        for output in (official, official + "\n", official.replace("\n", "\r\n"),
                       (official + "\n").replace("\n", "\r\n")):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                completed = subprocess.CompletedProcess([], 0, output, "")
                with patch.object(gate, "child", return_value=completed) as child:
                    gate.native_listing(Path("copilot"), {}, root, "chrome-devtools", False, root=root, readonly=())
                    self.assertEqual(child.call_args.args[0], ["copilot", "plugin", "list"])
                    self.assertEqual(child.call_args.kwargs["root"], root)
                    with self.assertRaisesRegex(ValueError, "unexpectedly empty"):
                        gate.native_listing(Path("copilot"), {}, root, "chrome-devtools", True, root=root, readonly=(),
                                            expected_marketplace="agentplugins-123456789abc", expected_version="1.0.0",
                                            expected_path=root / "managed")

    def test_copilot_empty_registry_rejects_truncation_prefix_suffix_and_failed_process(self):
        # Mirrors c78c79 native_identity_test.go's absent_short/prefix/suffix
        # negatives; no broad prefix/suffix tolerance is introduced.
        official = "No plugins installed.\n\nUse 'copilot plugin install <source>' to install a plugin."
        for output in ("No plugins installed.\n", "\n" + official + "\n", official + "\n\n",
                       official + " extra", "prefix\n" + official, official.replace("\n\n", "\n"),
                       official + "\r", "", "No plugins installed"):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(gate, "child", return_value=subprocess.CompletedProcess([], 0, output, "")):
                    with self.assertRaises(ValueError):
                        gate.native_listing(Path("copilot"), {}, root, "chrome-devtools", False, root=root, readonly=())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(gate, "child", return_value=subprocess.CompletedProcess([], 1, official, "not persisted")):
                with self.assertRaisesRegex(ValueError, "listing failed"):
                    gate.native_listing(Path("copilot"), {}, root, "chrome-devtools", False, root=root, readonly=())

    def check_native_diagnostic(self, client, output, expected_stage, *, installed=True, returncode=0,
                                expected_marketplace="agentplugins-123456789abc", expected_version="1.0.0",
                                expected_path=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = argparse.Namespace()
            completed = subprocess.CompletedProcess([], returncode, output, "private stderr must not escape")
            callback = lambda phase: gate.lifecycle_step(args, "chrome-devtools", phase)
            expected_path = expected_path or root / "managed"
            with patch.object(gate, "child", return_value=completed) as child:
                with self.assertRaises(ValueError):
                    gate.native_listing(Path(client), {}, root, "chrome-devtools", installed,
                                        root=root, readonly=(), expected_marketplace=expected_marketplace,
                                        expected_version=expected_version, expected_path=expected_path, diagnostic=callback)
                self.assertEqual(child.call_count, 1)
            state = "installed" if installed else "removed"
            self.assertEqual(args.failure_phase, f"lifecycle:chrome-devtools:native_list_{client}_{state}_{expected_stage}")
            self.assertNotIn("private", args.failure_phase)

    def test_claude_native_json_shape_fails_cleanly_with_bounded_diagnostics(self):
        self.check_native_diagnostic("claude", '{"private raw value":', "json_decode")
        for value in ({}, None, True, [None], [42], ["private raw value"], [{}],
                      [{"id": None}], [{"id": 9}], [{"id": []}], [{"id": ""}]):
            with self.subTest(value=value):
                self.check_native_diagnostic("claude", json.dumps(value), "json_shape")

    def test_claude_native_diagnostics_distinguish_exit_matching_scope_and_enabled(self):
        good = {"id": "chrome-devtools@skills-dir", "scope": "user", "enabled": True}
        self.check_native_diagnostic("claude", json.dumps([good]), "exit", returncode=7)
        self.check_native_diagnostic("claude", "[]", "matching")
        self.check_native_diagnostic("claude", json.dumps([good, good]), "matching")
        self.check_native_diagnostic("claude", json.dumps([good]), "matching", installed=False)
        for scope in (None, "project", True, {}):
            self.check_native_diagnostic("claude", json.dumps([{**good, "scope": scope}]), "scope")
        for enabled in (None, False, 1, "true", {}):
            self.check_native_diagnostic("claude", json.dumps([{**good, "enabled": enabled}]), "enabled")

    def test_copilot_native_diagnostics_distinguish_exit_section_format_count(self):
        good = "Installed plugins:\n  • chrome-devtools@agentplugins-123456789abc (v1.0.0)\n"
        self.check_native_diagnostic("copilot", good, "exit", returncode=1)
        self.check_native_diagnostic("copilot", "private unexpected response", "section")
        self.check_native_diagnostic("copilot", "Installed plugins:\n  invalid entry\n", "format")
        self.check_native_diagnostic("copilot", "Installed plugins:\n", "count")
        self.check_native_diagnostic("copilot", good + "Installed plugins:\n", "section")
        self.check_native_diagnostic("copilot", good, "count", installed=False)

    def test_copilot_exact_live_plugin_contract_binds_identity_version_status_and_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "state/managed/copilot/chrome-devtools-fixture"
            marketplace = gate.managed_marketplace("chrome-devtools-fixture")
            body = ("Live Plugins (loaded from a local marketplace directory, never copied):\n"
                    f"  • chrome-devtools@{marketplace} (v1.7.0-uap.1) (enabled)\n"
                    f"      from {managed}")
            for output in (body, body + "\n", body.replace("\n", "\r\n"), (body + "\n").replace("\n", "\r\n")):
                seen = []
                with self.subTest(output=output), patch.object(
                    gate, "child", return_value=subprocess.CompletedProcess([], 0, output, "")
                ):
                    gate.native_listing(Path("copilot"), {}, root, "chrome-devtools", True,
                                        root=root, readonly=(), expected_marketplace=marketplace,
                                        expected_version="1.7.0-uap.1", expected_path=managed,
                                        diagnostic=seen.append)
                self.assertEqual(seen[-1], "native_list_copilot_installed_count")

    def test_copilot_multi_live_listing_qualifies_only_the_requested_package(self):
        # The native Copilot marketplace can list all four mandatory managed
        # packages at once. Validate each entry and never mistake another
        # package for this selection or accept a duplicate identity.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = [
                ("notion", "1.0.0"), ("marketing-kit", "0.1.0"),
                ("hubspot-crm", "1.0.0"), ("playwright-bridge", "0.0.80"),
            ]
            entries = [
                (f"  • {name}@agentplugins-{index:012x} (v{version}) (enabled)",
                 f"      from {root / 'state' / name}")
                for index, (name, version) in enumerate(records)
            ]
            header = "Live Plugins (loaded from a local marketplace directory, never copied):"
            def document(values):
                return header + "\n" + "\n".join(line for pair in values for line in pair)
            for index, (name, version) in enumerate(records):
                with self.subTest(client_package=name), patch.object(
                    gate, "child", return_value=subprocess.CompletedProcess([], 0, document(entries), "")
                ):
                    gate.native_listing(Path("copilot"), {}, root, name, True,
                                        root=root, readonly=(),
                                        expected_marketplace=f"agentplugins-{index:012x}",
                                        expected_version=version, expected_path=root / "state" / name)
            without_kit = entries[:1] + entries[2:]
            with patch.object(gate, "child",
                              return_value=subprocess.CompletedProcess([], 0, document(without_kit), "")):
                gate.native_listing(Path("copilot"), {}, root, "marketing-kit", False,
                                    root=root, readonly=())
                with self.assertRaisesRegex(ValueError, "identity"):
                    gate.native_listing(Path("copilot"), {}, root, "marketing-kit", True,
                                        root=root, readonly=(),
                                        expected_marketplace="agentplugins-000000000001",
                                        expected_version="0.1.0",
                                        expected_path=root / "state/marketing-kit")
            for name, altered in (
                ("duplicate", entries + [entries[1]]),
                ("trailing", entries + [("extra", "unpaired")]),
                ("wrong_version", [*entries[:1],
                                   (entries[1][0].replace("v0.1.0", "v9.9.9"), entries[1][1]),
                                   *entries[2:]]),
                ("disabled", [*entries[:1],
                              (entries[1][0].replace("(enabled)", "(disabled)"), entries[1][1]),
                              *entries[2:]]),
                ("wrong_path", [*entries[:1],
                                (entries[1][0], "      from relative/path"),
                                *entries[2:]]),
            ):
                with self.subTest(bad=name), patch.object(
                    gate, "child", return_value=subprocess.CompletedProcess([], 0, document(altered), "")
                ):
                    with self.assertRaises(ValueError):
                        gate.native_listing(Path("copilot"), {}, root, "marketing-kit", True,
                                            root=root, readonly=(),
                                            expected_marketplace="agentplugins-000000000001",
                                            expected_version="0.1.0",
                                            expected_path=root / "state/marketing-kit")

    def test_copilot_live_plugin_rejects_malformed_or_unbound_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "state/managed/copilot/chrome-devtools-fixture"
            marketplace = gate.managed_marketplace("chrome-devtools-fixture")
            header = "Live Plugins (loaded from a local marketplace directory, never copied):"
            valid_entry = f"  • chrome-devtools@{marketplace} (v1.7.0-uap.1) (enabled)"
            valid_path = f"      from {managed}"
            cases = {
                "section": "Live plugins:\n" + valid_entry + "\n" + valid_path,
                "format": header + "\n" + valid_entry,
                "format_extra": header + "\n" + valid_entry + "\n" + valid_path + "\nextra",
                "identity": header + "\n" + valid_entry.replace("chrome-devtools@", "other@") + "\n" + valid_path,
                "marketplace": header + "\n" + valid_entry.replace(marketplace, "agentplugins-deadbeefcafe") + "\n" + valid_path,
                "version": header + "\n" + valid_entry.replace("1.7.0-uap.1", "1.7.0-uap.2") + "\n" + valid_path,
                "status": header + "\n" + valid_entry.replace("enabled", "disabled") + "\n" + valid_path,
                "at_literal": header + "\n" + valid_entry + "\n      at " + str(managed),
                "path": header + "\n" + valid_entry + "\n      from " + str(root / "other"),
                "relative_path": header + "\n" + valid_entry + "\n      from relative/path",
                "duplicate": header + "\n" + valid_entry + "\n" + valid_path + "\n" + valid_entry + "\n" + valid_path,
            }
            for name, output in cases.items():
                expected_stage = ("identity" if name == "marketplace" else "format" if name in ("format_extra", "duplicate", "at_literal")
                                  else "path" if name == "relative_path" else name)
                with self.subTest(name=name):
                    self.check_native_diagnostic("copilot", output, expected_stage,
                                                 expected_marketplace=marketplace, expected_version="1.7.0-uap.1")

    def test_claude_installed_path_is_absolute_exact_binding_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "state/managed/claude/chrome-devtools-fixture"
            base = {"id": "chrome-devtools@skills-dir", "scope": "user", "enabled": True}
            for install_path in (None, 7, [], {}, "relative/path", str(root / "other")):
                with self.subTest(install_path=install_path):
                    output = json.dumps([{**base, "installPath": install_path}])
                    expected_stage = "path"
                    self.check_native_diagnostic("claude", output, expected_stage)

    def test_marketplace_identity_matches_released_sha256_prefix_contract(self):
        physical = "chrome-devtools-123456789abc"
        self.assertEqual(gate.managed_marketplace(physical),
                         "agentplugins-" + hashlib.sha256(physical.encode()).hexdigest()[:12])
        for invalid in (None, 7, "", "  "):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                gate.managed_marketplace(invalid)

    def test_shared_copilot_binding_can_be_owned_by_vscode(self):
        shared = {"client_id": "vscode", "affected_surfaces": ["copilot", "vscode"],
                  "target_locator": "/isolated/shared"}
        claude = {"client_id": "claude", "affected_surfaces": ["claude"],
                  "target_locator": "/isolated/claude"}
        self.assertIs(gate.native_binding([shared, claude], "copilot"), shared)
        self.assertIs(gate.native_binding([shared, claude], "claude"), claude)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            gate.native_binding([shared, {**shared, "client_id": "copilot"}], "copilot")
        with self.assertRaisesRegex(ValueError, "missing"):
            gate.native_binding([claude], "copilot")

    def test_installed_marketplace_requires_exact_lowercase_twelve_hex(self):
        output = "Installed plugins:\n  • chrome-devtools@agentplugins-123456789abc (v1.0.0)\n"
        for marketplace in ("agentplugins-fixture", "agentplugins-123", "agentplugins-123456789abcd",
                            "agentplugins-123456789abG", "prefix-agentplugins-123456789abc"):
            with self.subTest(marketplace=marketplace), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(gate, "child", return_value=subprocess.CompletedProcess([], 0, output, "")):
                    with self.assertRaisesRegex(ValueError, "identity is incomplete"):
                        gate.native_listing(Path("copilot"), {}, root, "chrome-devtools", True,
                                            root=root, readonly=(), expected_marketplace=marketplace,
                                            expected_version="1.0.0", expected_path=root / "managed")

    def test_successful_native_diagnostics_only_emit_fixed_client_stage_enums(self):
        cases = (("claude", json.dumps([{"id": "chrome-devtools@skills-dir", "scope": "user", "enabled": True,
                                          "installPath": None}]), "path"),
                 ("copilot", "Installed plugins:\n  • chrome-devtools@agentplugins-123456789abc (v1.0.0)\n", "version"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for client, output, last in cases:
                seen = []
                managed = root / "managed"
                if client == "claude":
                    output = json.dumps([{"id": "chrome-devtools@skills-dir", "scope": "user",
                                          "enabled": True, "installPath": str(managed)}])
                with patch.object(gate, "child", return_value=subprocess.CompletedProcess([], 0, output, "")):
                    gate.native_listing(Path(client), {}, root, "chrome-devtools", True,
                                        root=root, readonly=(), expected_marketplace="agentplugins-123456789abc",
                                        expected_version="1.0.0", expected_path=managed, diagnostic=seen.append)
                self.assertTrue(set(seen).issubset(gate.LIFECYCLE_STEPS))
                self.assertEqual(seen[0], f"native_list_{client}_installed_probe")
                self.assertEqual(seen[-1], f"native_list_{client}_installed_{last}")

    def run_first_package_fixture(self, parent: Path, mutation: str | None = None):
        """Only the process boundary is fake; state, files and lifecycle checks are real.

        Released c78c79 service.go stores plan.ActivePath as TargetLocator;
        planner.go joins the physical artifact ID and stager.go materializes a
        managed_package_directory, including for skills-only packages.
        """
        tools = parent / "tools"
        tools.mkdir()
        for name in ("agentplugins", "claude", "copilot", "npx", "opencode"):
            (tools / name).write_bytes(b"fixture only; never executed")
        args = argparse.Namespace(binary=tools / "agentplugins", claude=tools / "claude",
                                  copilot=tools / "copilot", npx=tools / "npx", inspector=None,
                                  opencode=tools / "opencode")
        root = parent / "case"
        selection = gate.selected(self.snapshot, "context7", gate.CORE)
        package_revision = {key: selection[key] for key in ("tree_digest", "manifest_digest")}
        owned = {client: root / "state" / "managed" / client / "context7-fixture" for client in gate.CORE}
        clients = {client: {"client_id": client, "target_locator": str(path),
                            "affected_surfaces": [client], "package_revision": package_revision}
                   for client, path in owned.items()}
        state = {"installations": [{"installation_id": "fixture-installation", "origin_mode": "directory",
                                   "source": {"repository": selection["package_source"]["repository"],
                                              "resolved_revision": selection["package_source"]["revision"],
                                              "tree_digest": selection["tree_digest"]}, "clients": clients}]}
        state_path = root / "state" / "state-v2.json"
        calls = []

        def targets():
            physical_id = None if mutation == "missing_physical_id" else "context7-fixture"
            return {"succeeded": 3, "failed": 0, "targets": [
                {"target": client, "status": "external_completed", "output": {"result": {
                    "installation_id": "fixture-installation", "no_change": True, "mutated": False,
                        "plan": {"physical_artifact_id": physical_id}}}}
                for client in gate.CORE]}

        def child(argv, **kwargs):
            self.assertEqual(kwargs["root"], root)
            phase = argv[1]
            calls.append(phase)
            if phase == "add":
                for client, path in owned.items():
                    path.parent.mkdir(parents=True)
                    if mutation == "file_locator" and client == "kiro":
                        path.write_bytes(b"not a managed package directory")
                    else:
                        path.mkdir()
                        (path / "SKILL.md").write_bytes(b"# Fixture skill\n")
                        (path / "SKILL.md").chmod(0o640)
                        (path / "linked-skill").symlink_to("SKILL.md")
                state_path.write_bytes(publication.canonical_json(state))
                acquisition = {**package_revision, "acquisition_id": "fixture-acquisition",
                               "closure_digest": "sha256:" + "1" * 64, "acquisition_count": 1,
                               "fetched": True, "validated": True}
                data = {**targets(), **package_revision, "plugin": selection["product_id"],
                        "version": selection["package_version"],
                        "source": gate.public_source(selection["package_source"]),
                        "revision": selection["package_source"]["revision"], "acquisition": acquisition,
                        "target_outcomes": {client: {**acquisition, "outcome": "passed"} for client in gate.CORE},
                        "directory": {"product_id": selection["product_id"], "distribution_id": selection["distribution_id"],
                                      "distribution_kind": selection["distribution_kind"],
                                      "desired_release_sequence": selection["release_sequence"],
                                      "snapshot_schema": 1, "snapshot_sequence": self.args.sequence,
                                      "snapshot_digest": self.args.snapshot_digest}}
            elif phase == "info":
                data = {"installation_id": "fixture-installation", "clients": list(clients.values())}
            elif phase == "update":
                path = owned["codex"] / "SKILL.md"
                if mutation == "file_bytes":
                    path.write_bytes(b"changed skill")
                elif mutation == "file_mode":
                    path.chmod(0o600)
                elif mutation == "topology":
                    (owned["codex"] / "unexpected-file").write_bytes(b"new artifact")
                elif mutation == "symlink_target":
                    link = owned["codex"] / "linked-skill"
                    link.unlink()
                    link.symlink_to("different-target")
                data = {**targets(), "status": "completed"}
            elif phase == "remove":
                for path in owned.values():
                    shutil.rmtree(path)
                state_path.write_bytes(publication.canonical_json({"installations": []}))
                data = {**targets(), "plugin_data_preserved": False, "data_retained": False}
            elif phase == "list":
                data = {"installations": []}
            elif phase == "doctor":
                data = {"read_only": True, "installation_count": 0, "open_operation_count": 0,
                        "findings": [{"status": "healthy", "code": "no_degradation_detected",
                                      "message": "no tracked degradation was detected"}]}
                if mutation == "doctor_findings":
                    data["findings"] = []
                elif mutation == "doctor_mutation":
                    (root / "home" / "unexpected-write").write_bytes(b"doctor must be read-only")
                elif mutation == "doctor_open_operation":
                    data["open_operation_count"] = 1
            else:
                self.fail(f"unexpected fixture phase: {phase}")
            reported = "list" if phase == "doctor" and mutation == "wrong_command" else phase
            body = json.dumps({"command": reported, "result": "success", "data": data})
            return subprocess.CompletedProcess(argv, 0, body, "")

        try:
            with patch.object(gate, "child", side_effect=child):
                gate.run_lifecycle(args, root, selection, gate.CORE, vars(self.args))
        except (ValueError, gate.EvidenceError) as error:
            return args, calls, error
        return args, calls, None

    def test_first_package_full_lifecycle_accepts_exact_doctor_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args, calls, error = self.run_first_package_fixture(root)
            self.assertIsNone(error)
            self.assertEqual(calls, ["add", "info", "update", "remove", "list", "doctor"])
            self.assertEqual(args.failure_phase, "lifecycle:context7:complete")
            self.assertEqual(gate.read_json(root / "case/state/state-v2.json")["installations"], [])
            self.assertFalse(any(path.is_file() or path.is_symlink() for path in (root / "case/state/managed").rglob("*")))

    def test_first_package_real_files_modes_and_symlink_targets_are_not_ignored(self):
        for mutation in ("file_bytes", "file_mode", "topology", "symlink_target"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, calls, error = self.run_first_package_fixture(Path(temporary).resolve(), mutation)
                self.assertIsInstance(error, ValueError)
                self.assertEqual(calls, ["add", "info", "update"])
                self.assertEqual(args.failure_phase, "lifecycle:context7:snapshot_after_update")

    def test_file_locator_is_rejected_not_silently_dropped_from_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, calls, error = self.run_first_package_fixture(Path(temporary).resolve(), "file_locator")
            self.assertIsInstance(error, gate.EvidenceError)
            self.assertEqual(calls, ["add", "info"])
            self.assertEqual(args.failure_phase, "lifecycle:context7:snapshot_before_update")

    def test_missing_physical_artifact_id_fails_before_identity_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, calls, error = self.run_first_package_fixture(Path(temporary).resolve(), "missing_physical_id")
            self.assertIsInstance(error, ValueError)
            self.assertIn("valid physical artifact", str(error))
            self.assertEqual(calls, ["add"])
            self.assertEqual(args.failure_phase, "lifecycle:context7:validate_add")

    def test_doctor_wrong_command_findings_mutation_and_open_operation_fail_precisely(self):
        for mutation, phase in (("wrong_command", "doctor"), ("doctor_findings", "validate_doctor"),
                                ("doctor_mutation", "snapshot_after_doctor"), ("doctor_open_operation", "validate_cleanup")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, calls, error = self.run_first_package_fixture(Path(temporary).resolve(), mutation)
                self.assertIsNotNone(error)
                self.assertEqual(calls[-1], "doctor")
                self.assertEqual(args.failure_phase, "lifecycle:context7:" + phase)

    def test_diagnostic_steps_reject_unbounded_input(self):
        for selector, step in (("/private/path", "add"), ("context7", "raw log secret")):
            with self.assertRaisesRegex(ValueError, "unknown lifecycle"):
                gate.lifecycle_step(argparse.Namespace(), selector, step)

    def test_inspector_runner_receives_fresh_bounded_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            package, parent = root / "package", root / "sessions"
            package.mkdir(); parent.mkdir()
            (package / "mcp.json").write_text('{"mcpServers":{"context7":{"command":"node","args":[]}}}')
            observed = []
            def runner(argv, **kwargs):
                sandbox = Path(kwargs["cwd"])
                self.assertTrue(sandbox.is_relative_to(parent))
                self.assertNotEqual(sandbox, parent)
                self.assertEqual(kwargs["env"]["PLUGIN_ROOT"], str(package))
                self.assertTrue((sandbox / "mcp.json").is_file())
                observed.append(sandbox)
                return subprocess.CompletedProcess(argv, 0, '{"result":{"tools":[{"name":"resolve-library-id"}]}}', "")
            result = mcp.inspector_check("context7", plugin_root=package, sandbox_parent=parent,
                                         process_runner=runner, inspector=Path("/exact/mcp-inspector"))
            self.assertEqual(result["status"], "passed")
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists())

    def test_producer_composes_all_phases_and_only_emits_after_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = argparse.Namespace(binary=root / "binary", sandbox=root / "isolated", output=root / "evidence.json",
                                      claude=Path("claude"), copilot=Path("copilot"), npx=Path("npx"), inspector=None,
                                      opencode=Path("opencode"))
            args.binary.write_bytes(b"fixture binary")
            with patch.object(gate, "canonical_inputs", side_effect=lambda _: (self.snapshot, self.expected())), \
                    patch.dict(gate.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}), \
                    patch.object(gate.managed, "run") as managed_run, \
                    patch.object(gate.project, "run_user_refusal") as user_refusal, \
                    patch.object(gate, "run_lifecycle") as lifecycle, \
                    patch.object(gate, "acquired_package", return_value=root) as acquire, \
                    patch.object(gate, "check_static_package") as static, \
                    patch.object(gate, "inspector_check", return_value={"status": "passed"}) as probe:
                expected = self.expected()
                gate.produce(args, self.snapshot, expected)
                self.assertEqual(managed_run.call_count, 3)
                self.assertEqual(managed_run.call_args_list[0].args[2]["targets"], list(gate.managed.LEGACY_CLIENTS))
                self.assertEqual(managed_run.call_args_list[1].args[2]["placement_scope"], "user")
                self.assertEqual(managed_run.call_args_list[1].args[2]["targets"], list(gate.managed.CLIENTS))
                self.assertEqual(managed_run.call_args_list[2].args[2]["placement_scope"], "project")
                self.assertEqual(managed_run.call_args_list[1].args[2]["cli"], managed_run.call_args_list[2].args[2]["cli"])
                user_refusal.assert_called_once()
                self.assertEqual(lifecycle.call_count, 30)
                default_call = next(call for call in lifecycle.call_args_list
                                    if call.args[2]["selector"] == "github/github")
                self.assertEqual(default_call.args[1].name, "default-github")
                self.assertEqual(default_call.args[3], gate.CORE)
                self.assertEqual(acquire.call_count, 4)
                self.assertEqual(static.call_count, 2)
                self.assertEqual(probe.call_count, 4)
                self.assertFalse(args.sandbox.exists())
                gate.validate_artifact(gate.read_json(args.output, canonical=True), expected)

    @contextmanager
    def _producer_path_calls(self, args):
        args.binary.write_bytes(b"fixture binary")
        with patch.object(gate, "canonical_inputs", side_effect=lambda _: (self.snapshot, self.expected())), \
                patch.dict(gate.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}), \
                patch.object(gate.managed, "run") as managed_run, \
                patch.object(gate.project, "run_user_refusal") as refusal, \
                patch.object(gate, "run_lifecycle") as lifecycle, \
                patch.object(gate, "acquired_package", return_value=args.binary.parent), \
                patch.object(gate, "check_static_package"), \
                patch.object(gate, "inspector_check", return_value={"status": "passed"}):
            yield managed_run, refusal, lifecycle

    def test_producer_canonical_output_preserves_parent_alias_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            physical, alias = root / "physical", root / "alias"
            physical.mkdir()
            alias.symlink_to(physical, target_is_directory=True)
            sandbox = alias / "case"
            args = argparse.Namespace(binary=root / "binary", sandbox=sandbox,
                                      output=sandbox / ".." / "report.json", npx=Path("npx"), inspector=None)
            with self._producer_path_calls(args) as (managed_run, _, _):
                expected = copy.deepcopy(self.expected())
                gate.produce(args, self.snapshot, expected)
                self.assertEqual(managed_run.call_count, 3)
                for call in managed_run.call_args_list:
                    self.assertTrue(call.args[1].is_relative_to(physical / "case"))
            self.assertFalse((physical / "case").exists())
            gate.validate_artifact(gate.read_json(physical / "report.json", canonical=True), expected)

    def test_producer_canonical_output_rejects_stale_artifact_before_execution(self):
        for through_case in (False, True):
            with self.subTest(through_case=through_case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                stale = root / "report.json"
                stale.write_bytes(b"existing success must survive")
                sandbox = root / "case"
                output = sandbox / ".." / stale.name if through_case else stale
                args = argparse.Namespace(binary=root / "binary", sandbox=sandbox, output=output)
                with self._producer_path_calls(args) as calls:
                    with self.assertRaisesRegex(ValueError, "stale success artifact"):
                        gate.produce(args, self.snapshot, self.expected())
                    for call in calls:
                        call.assert_not_called()
                self.assertFalse(sandbox.exists())
                self.assertEqual(stale.read_bytes(), b"existing success must survive")

    def test_producer_final_symlinks_and_inside_outputs_refuse_before_execution(self):
        for invalid in ("sandbox_dangling", "sandbox_existing", "output_dangling", "output_existing",
                        "output_hidden_dangling", "output_hidden_existing", "output_dotdot",
                        "inside", "aliased_inside"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                sandbox, output = root / "case", root / "report.json"
                target = root / "target"
                if invalid.startswith("sandbox_"):
                    if invalid == "sandbox_existing":
                        target.mkdir()
                    sandbox.symlink_to(target, target_is_directory=True)
                elif invalid == "output_dotdot":
                    output = root / "not-created" / "child" / ".."
                elif invalid.startswith("output_"):
                    if invalid.endswith("_existing"):
                        target.write_bytes(b"existing output target")
                    output.symlink_to(target)
                    if invalid.startswith("output_hidden_"):
                        output = sandbox / ".." / output.name
                elif invalid == "inside":
                    output = sandbox / "report.json"
                else:
                    alias = root / "case-alias"
                    alias.symlink_to(sandbox, target_is_directory=True)
                    output = alias / "report.json"
                args = argparse.Namespace(binary=root / "binary", sandbox=sandbox, output=output,
                                          npx=Path("npx"), inspector=None)
                message = "sandbox must be a new directory" if invalid.startswith("sandbox_") else "output"
                with self._producer_path_calls(args) as calls:
                    with self.assertRaisesRegex(ValueError, message):
                        gate.produce(args, self.snapshot, self.expected())
                    for call in calls:
                        call.assert_not_called()
                if invalid.startswith("sandbox_"):
                    self.assertTrue(sandbox.is_symlink())
                else:
                    self.assertFalse(sandbox.exists())
                if invalid in ("output_existing", "output_hidden_existing"):
                    self.assertEqual(target.read_bytes(), b"existing output target")
                if invalid == "output_dotdot":
                    self.assertFalse((root / "not-created").exists())

    def test_main_canonical_failure_output_does_not_recreate_disposable_root(self):
        for failing in ("managed", "hidden_dangling", "hidden_existing"):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                sandbox, report, target = root / "case", root / "report.json", root / "target"
                if failing.startswith("hidden_"):
                    if failing == "hidden_existing":
                        target.write_bytes(b"existing output target")
                    report.symlink_to(target)
                args = argparse.Namespace(mode="produce", binary=root / "binary", sandbox=sandbox,
                                          output=sandbox / ".." / report.name, claude=Path("claude"),
                                          copilot=Path("copilot"), opencode=Path("opencode"),
                                          project_binary=root / "project-binary")
                with self._producer_path_calls(args) as calls, patch.object(gate, "parser") as parser:
                    parser.return_value.parse_args.return_value = args
                    if failing == "managed":
                        calls[0].side_effect = ValueError("fixture lifecycle failure")
                    self.assertEqual(gate.main([]), 1)
                    if failing == "managed":
                        calls[0].assert_called_once()
                    else:
                        for call in calls:
                            call.assert_not_called()
                self.assertFalse(sandbox.exists())
                if failing.startswith("hidden_"):
                    self.assertTrue(report.is_symlink())
                else:
                    self.assertFalse(report.exists())
                if failing == "hidden_existing":
                    self.assertEqual(target.read_bytes(), b"existing output target")
                else:
                    self.assertFalse(target.exists())
                failure = gate.read_json(root / "catalog-readiness-failure.json", canonical=True)
                self.assertEqual(failure["phase"], "managed:prepare" if failing == "managed" else "validate_inputs")
                self.assertEqual(failure["outcome"], "failed")

    def test_direct_producer_rejects_omitted_or_substituted_dependency_blocks_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = argparse.Namespace(binary=root / "binary", sandbox=root / "isolated", output=root / "evidence.json")
            args.binary.write_bytes(b"fixture binary")
            expected = self.expected()
            mutations = [lambda value, name=name: value.pop(name) for name in
                         ("project_dependencies", "release_user_dependencies", "vscode_user_refusal")]
            mutations.extend((
                lambda value: value["release_user_dependencies"]["proof"].update(locked_restore="not_tested"),
                lambda value: value["release_user_dependencies"]["cli"].update(binary_digest="sha256:" + "0" * 64),
                lambda value: value["vscode_user_refusal"].update(target="copilot"),
            ))
            with patch.object(gate, "canonical_inputs", side_effect=lambda _: (self.snapshot, self.expected())), \
                    patch.dict(gate.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}), \
                    patch.object(gate.managed, "run") as managed_run, patch.object(gate.project, "run_user_refusal") as refusal:
                for mutation in mutations:
                    value = copy.deepcopy(expected)
                    mutation(value)
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        gate.produce(args, self.snapshot, value)
                    self.assertFalse(args.sandbox.exists())
                    self.assertFalse(args.output.exists())
                managed_run.assert_not_called()
                refusal.assert_not_called()

    def test_failed_cli_mcp_static_or_cleanup_never_emits_success(self):
        for failing in ("managed", "release_user", "project", "project_refusal", "run_lifecycle", "inspector_check", "check_static_package", "cleanup"):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = argparse.Namespace(binary=root / "binary", sandbox=root / "isolated", output=root / "evidence.json",
                                          claude=Path("claude"), copilot=Path("copilot"), npx=Path("npx"), inspector=None,
                                          opencode=Path("opencode"))
                args.binary.write_bytes(b"fixture binary")
                with patch.object(gate, "canonical_inputs", side_effect=lambda _: (self.snapshot, self.expected())), \
                    patch.dict(gate.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}), \
                        patch.object(gate.managed, "run") as managed_run, \
                        patch.object(gate.project, "run_user_refusal") as user_refusal, \
                        patch.object(gate, "run_lifecycle") as lifecycle, \
                        patch.object(gate, "acquired_package", return_value=root), \
                        patch.object(gate, "check_static_package") as static, \
                        patch.object(gate, "inspector_check", return_value={"status": "passed"}) as probe:
                    expected = self.expected()
                    if failing == "cleanup":
                        with patch.object(gate.shutil, "rmtree", side_effect=OSError("fixture cleanup failure")):
                            with self.assertRaises(OSError):
                                gate.produce(args, self.snapshot, expected)
                    else:
                        if failing in ("project", "release_user"):
                            def fail_project(_args, _root, case, _ctx):
                                if (failing == "project" and case.get("placement_scope") == "project") or (
                                        failing == "release_user" and case.get("placement_scope") == "user" and tuple(case["targets"]) == gate.managed.CLIENTS):
                                    raise ValueError("fixture Project failure")
                            managed_run.side_effect = fail_project
                        else:
                            {"managed": managed_run, "project_refusal": user_refusal, "run_lifecycle": lifecycle,
                             "inspector_check": probe, "check_static_package": static}[failing].side_effect = ValueError("fixture phase failure")
                        with self.assertRaises(ValueError):
                            gate.produce(args, self.snapshot, expected)
                        self.assertFalse(args.sandbox.exists())
                    self.assertFalse(args.output.exists())

    def test_wrong_binary_does_not_create_sandbox_or_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            binary.write_bytes(b"not the release")
            args = argparse.Namespace(binary=binary, sandbox=root / "isolated", output=root / "evidence.json")
            with patch.object(gate, "canonical_inputs", return_value=(self.snapshot, self.expected())), \
                    self.assertRaisesRegex(ValueError, "wrong released binary"):
                gate.produce(args, self.snapshot, self.expected())
            self.assertFalse(args.sandbox.exists())
            self.assertFalse(args.output.exists())


class CurrentPolicyTests(unittest.TestCase):
    def setUp(self):
        for manager in (patch.dict(os.environ, {"UAP_ACTIVE_REPOSITORY": "777genius/universal-agent-plugins-registry"}),
                        patch.object(gate, "datetime", ProofTime),
                        patch.object(gate.project, "RELEASE", PROJECT_RELEASE_FIXTURE)):
            manager.start()
            self.addCleanup(manager.stop)

    def inputs(self, root, six=False):
        args = paired_arguments(root)
        if six:
            snapshot = json.loads((SIGNED45_FEED / "snapshots/00000000000000000045.json").read_text())
            pins = gate.project.refusal_source_identity()
            for key, value in pins.items():
                setattr(args, key, value)
            args.feed = SIGNED45_FEED
            args.source_sha, args.publication_id = snapshot["source_commit"], snapshot["publication_id"]
            args.directory_origin = f"https://raw.githubusercontent.com/{args.repository}/{args.materialized_ledger_sha}/registry/schemas/1/"
        return args

    def baseline_loader(self, args):
        original = gate.load_feed
        def load(root, keys, *, baseline=False):
            snapshot, identity = original(root, keys, baseline=baseline)
            if baseline and args.feed == SIGNED45_FEED:
                # Offline baseline policy facts only. Candidate45 itself is
                # still authenticated through the ordinary unmodified loader.
                return {**snapshot, "sequence": 44}, {"sequence": 44, "snapshot_digest": "sha256:" + "f" * 64}
            return snapshot, identity
        return patch.object(gate, "load_feed", side_effect=load)

    def test_authentic_current_policies_select_exactly_one_truthful_boundary(self):
        for six in (False, True):
            with self.subTest(six=six), tempfile.TemporaryDirectory() as temporary:
                args = self.inputs(Path(temporary), six)
                with self.baseline_loader(args):
                    snapshot, artifact = gate.canonical_inputs(args)
                boundary = artifact["vscode_user_policy_boundary"]
                self.assertEqual(boundary["source"], "current_authenticated_feed")
                self.assertEqual(boundary["kind"], "missing_signed_target" if six else "prepared_target_saved_management")
                self.assertEqual("vscode_user_refusal" in artifact, six)
                self.assertEqual("vscode_user_saved_management" in artifact, not six)
                for key in ("project_dependencies", "release_user_dependencies"):
                    self.assertEqual(artifact[key]["cli"], PROJECT_RELEASE_FIXTURE["cli"])
                    self.assertEqual(artifact[key]["targets"], list(gate.managed.CLIENTS))
                    self.assertEqual(gate.managed.immutable_closure(artifact[key]), gate.project.REVIEWED_SOURCE_CLOSURE)
                if not six:
                    saved = artifact["vscode_user_saved_management"]
                    self.assertEqual(saved["context"], artifact["context"])
                    self.assertFalse(saved["signed_target_refusal"])
                    self.assertEqual(saved["prepared_native_absence"], "not_claimed")
                    self.assertEqual(saved["standalone_editor_lifecycle"], "not_tested")
                    prior, prior_ctx = load_historical_source(args, artifact["context"])
                    gate.project.validate_refusal_pair(artifact["project_dependencies"], (prior, prior_ctx), gate.selected)
                    self.assertNotEqual(prior_ctx["sequence"], artifact["context"]["sequence"])
                else:
                    self.assertNotIn("context", artifact["vscode_user_refusal"])

    def test_unknown_current_policy_shape_never_selects_an_oracle(self):
        snapshot = json.loads((SIGNED46_FEED / "snapshots/00000000000000000046.json").read_text())
        for change in ("extra_target", "missing_copilot", "managed_vscode", "project_scope", "weaker_authentication"):
            value = copy.deepcopy(snapshot)
            targets = next(item for item in value["distributions"] if item["id"] == gate.managed.ROOT)["release_policies"][0]["targets"]
            if change == "extra_target":
                targets.append({"client": "kiro", "scopes": ["user"], "delivery": "managed", "authentication": "required"})
            elif change == "missing_copilot":
                targets[:] = [item for item in targets if item["client"] != "copilot"]
            elif change == "managed_vscode":
                next(item for item in targets if item["client"] == "vscode")["delivery"] = "managed"
            elif change == "project_scope":
                targets[0]["scopes"] = ["project"]
            else:
                targets[0]["authentication"] = "not_required"
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.dependency_cases(value, {})

    def test_source_anchor_equals_authentic_historical_facts_and_rejects_every_tuple_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.inputs(Path(temporary))
            _, artifact = gate.canonical_inputs(args)
            prior, _ = load_historical_source(args, artifact["context"])
            historical = gate.project.expected(prior, gate.selected)
            self.assertEqual(gate.project.REVIEWED_SOURCE_CLOSURE, gate.managed.immutable_closure(historical))
            for index in range(4):
                for key in ("product_id", "distribution_id", "release_sequence", "package_version", "tree_digest", "manifest_digest"):
                    changed = copy.deepcopy(artifact["project_dependencies"])
                    changed["closure"][index][key] = 99 if key == "release_sequence" else "changed"
                    with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                        gate.project.validate_source_anchor(changed)
                for key in ("repository", "path", "revision"):
                    changed = copy.deepcopy(artifact["project_dependencies"])
                    changed["closure"][index]["package_source"][key] = "changed"
                    with self.subTest(index=index, source=key), self.assertRaisesRegex(ValueError, "source anchor"):
                        gate.project.validate_source_anchor(changed)
            original = gate.selected
            def substituted(snapshot, alias, clients, **kwargs):
                value = original(snapshot, alias, clients, **kwargs)
                if alias == gate.managed.ROOT:
                    value["package_source"] = {**value["package_source"], "revision": "f" * 40}
                return value
            with patch.object(gate, "selected", side_effect=substituted), self.assertRaisesRegex(ValueError, "source anchor"):
                gate.canonical_inputs(args)

    def test_current46_remains_valid_after_historical45_expiry_without_runtime_history(self):
        class AfterHistoricalExpiry(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 12, 10, 20, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary, patch.object(gate, "datetime", AfterHistoricalExpiry):
            args = self.inputs(Path(temporary))
            with patch.object(gate, "load_refusal_source", side_effect=AssertionError("historical runtime dependency")), \
                    patch.object(gate.project, "validate_refusal_pair", side_effect=AssertionError("historical authorization dependency")):
                _, artifact = gate.canonical_inputs(args)
            self.assertEqual(artifact["context"]["sequence"], 46)
            self.assertNotIn("vscode_user_refusal", artifact)
            with self.assertRaisesRegex(ValueError, "expired candidate"):
                gate.load_feed(SIGNED45_FEED, args.trusted_keys)

    def test_current_expiry_and_historical_expiry_both_still_fail_normally(self):
        class AfterCurrentExpiry(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 12, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            args = self.inputs(Path(temporary))
            _, artifact = gate.canonical_inputs(args)
            with patch.object(gate.project, "RELEASE", None), self.assertRaisesRegex(ValueError, "identity is unset"):
                gate.canonical_inputs(args)
            with patch.object(gate, "datetime", AfterCurrentExpiry):
                with self.assertRaisesRegex(ValueError, "expired candidate"):
                    gate.canonical_inputs(args)
                with self.assertRaisesRegex(ValueError, "expired candidate"):
                    load_historical_source(args, artifact["context"])
                historical_args = copy.deepcopy(args)
                historical_args.refusal_feed = SIGNED45_FEED
                # No binary exists. Even an explicit historical helper call
                # must reject expiry before mkdir/child, not trust its context.
                prior = json.loads((SIGNED45_FEED / "snapshots/00000000000000000045.json").read_text())
                prior_case = gate.project.expected(prior, gate.selected)
                pins = gate.project.refusal_source_identity()
                historical_ctx = {**artifact["context"], **pins, "source_sha": prior["source_commit"],
                                  "publication_id": prior["publication_id"],
                                  "directory_origin": f"https://raw.githubusercontent.com/{args.repository}/{pins['materialized_ledger_sha']}/registry/schemas/1/"}
                refusal = gate.project.expected_user_refusal(prior_case, context=historical_ctx)
                with patch.object(gate, "child") as child, self.assertRaisesRegex(ValueError, "expired candidate"):
                    gate.project.run_user_refusal(historical_args, Path(temporary) / "not-created", refusal, historical_ctx)
                child.assert_not_called()
                self.assertFalse((Path(temporary) / "not-created").exists())
            args.refusal_feed = SIGNED45_FEED
            with self.assertRaisesRegex(ValueError, "not a recurring publication input"):
                gate.canonical_inputs(args)

    def test_direct_producer_rejects_missing_mixed_wrong_oracle_context_and_source_before_execution(self):
        for six in (False, True):
            with self.subTest(six=six), tempfile.TemporaryDirectory() as temporary:
                args = self.inputs(Path(temporary), six)
                with self.baseline_loader(args):
                    snapshot, expected = gate.canonical_inputs(args)
                    selected = "vscode_user_refusal" if six else "vscode_user_saved_management"
                    wrong = "vscode_user_saved_management" if six else "vscode_user_refusal"
                    mutations = [lambda value, name=name: value.pop(name) for name in
                                 ("managed_dependencies", "release_user_dependencies", "project_dependencies", "vscode_user_policy_boundary", selected)]
                    for field, value in (("run_id", "456"), ("run_attempt", 2), ("workflow_sha", "9" * 40), ("source_sha", "8" * 40)):
                        mutations.append(lambda item, field=field, value=value: item["context"].update({field: value}))
                    mutations.extend((
                        lambda item: item.update({wrong: copy.deepcopy(item[selected])}),
                        lambda item: item["vscode_user_policy_boundary"].update(kind="unknown"),
                        lambda item: item["vscode_user_policy_boundary"].update(kind="prepared_target_saved_management" if six else "missing_signed_target"),
                        lambda item: item[selected].update(cli=copy.deepcopy(gate.managed.CLI)),
                        lambda item: item["project_dependencies"]["closure"][0]["package_source"].update(revision="6" * 40),
                        lambda item: item["rows"].pop(),
                    ))
                    if not six:
                        historical_ctx = load_historical_source(args, expected["context"])[1]
                        mutations.append(lambda item: item[selected].update(context=historical_ctx))
                    with patch.object(gate, "child") as child, patch.object(gate.managed, "run") as managed_run, \
                            patch.object(gate.project, "run_user_refusal") as refusal, \
                            patch.object(gate.project, "run_user_saved_management") as saved, patch.object(gate, "run_lifecycle") as lifecycle:
                        for mutate in mutations:
                            value = copy.deepcopy(expected)
                            mutate(value)
                            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                                gate.produce(args, snapshot, value)
                            self.assertFalse(args.sandbox.exists())
                            self.assertFalse(args.output.exists())
                        changed = copy.deepcopy(snapshot)
                        changed["publication_id"] = "foreign-publication"
                        with self.assertRaisesRegex(ValueError, "snapshot differs"):
                            gate.produce(args, changed, expected)
                        for function in (child, managed_run, refusal, saved, lifecycle):
                            function.assert_not_called()

    def test_producer_dispatches_only_current_oracle_and_verifier_reconstructs_both_branches(self):
        for six in (False, True):
            with self.subTest(six=six), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = self.inputs(root, six)
                args.binary.write_bytes(b"offline orchestration binary")
                with self.baseline_loader(args), patch.dict(gate.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}):
                    snapshot, expected = gate.canonical_inputs(args)
                    with patch.object(gate.managed, "run") as managed_run, \
                            patch.object(gate.project, "run_user_refusal") as refusal, \
                            patch.object(gate.project, "run_user_saved_management") as saved, \
                            patch.object(gate, "run_lifecycle"), patch.object(gate, "acquired_package", return_value=root), \
                            patch.object(gate, "check_static_package"), patch.object(gate, "inspector_check", return_value={"status": "passed"}):
                        gate.produce(args, snapshot, expected)
                        self.assertEqual(managed_run.call_count, 3)
                        if six:
                            refusal.assert_called_once()
                            saved.assert_not_called()
                            self.assertEqual(refusal.call_args.args[3], expected["context"])
                        else:
                            saved.assert_called_once()
                            refusal.assert_not_called()
                            self.assertEqual(saved.call_args.args[3], expected["context"])
                            self.assertEqual(saved.call_args.args[4], expected["project_dependencies"])
                        self.assertFalse(args.sandbox.exists())
                    argv = ["verify", "--artifact", str(args.output)]
                    for field in (*gate.CONTEXT_FIELDS, "feed", "baseline_feed", "trusted_keys"):
                        argv += ["--" + field.replace("_", "-"), str(getattr(args, field))]
                    self.assertEqual(gate.main(argv), 0)
                    tampered = copy.deepcopy(expected)
                    tampered["vscode_user_policy_boundary"]["kind"] = "unknown"
                    args.output.write_bytes(publication.canonical_json(tampered))
                    self.assertEqual(gate.main(argv), 1)

    def test_failed_mandatory_boundary_never_emits_success(self):
        for six in (False, True):
            with self.subTest(six=six), tempfile.TemporaryDirectory() as temporary:
                args = self.inputs(Path(temporary), six)
                args.binary.write_bytes(b"offline orchestration binary")
                with self.baseline_loader(args), patch.dict(gate.CLI, {"binary_digest": gate.digest(args.binary.read_bytes())}):
                    snapshot, expected = gate.canonical_inputs(args)
                    selected = "run_user_refusal" if six else "run_user_saved_management"
                    with patch.object(gate.managed, "run"), patch.object(gate.project, selected, side_effect=ValueError("boundary failure")) as boundary, \
                            self.assertRaisesRegex(ValueError, "boundary failure"):
                        gate.produce(args, snapshot, expected)
                    boundary.assert_called_once()
                    self.assertFalse(args.sandbox.exists())
                    self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
