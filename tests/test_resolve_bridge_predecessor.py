import hashlib
import json
import unittest

from scripts import resolve_bridge_predecessor as resolver


DIST = "777genius/demo-bridge"
FALLBACK = "a" * 40
SIGNED = "b" * 40
def directory() -> dict:
    return {
        "distributions": [{
            "id": DIST,
            "releases": [
                {
                    "sequence": 1, "package_version": "1.0.0",
                    "package_source": {
                        "repository": "777genius/universal-agent-plugins",
                        "revision": "d" * 40, "path": "plugins/demo",
                    },
                },
                {
                    "sequence": 2, "package_version": "2.0.0",
                    "package_source": {
                        "repository": "777genius/universal-agent-plugins",
                        "revision": None, "path": "plugins/demo",
                    },
                },
            ],
        }],
    }


def production_body(releases: list[dict] | None = None, *, sequence: int = 33) -> bytes:
    if releases is None:
        releases = [{
            "sequence": 2, "package_version": "2.0.0",
            "package_source": {
                "repository": "777genius/universal-agent-plugins",
                "revision": SIGNED, "path": "plugins/demo",
            },
        }]
    value = {"sequence": sequence, "distributions": [{"id": DIST, "releases": releases}]}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def search(body: bytes) -> dict:
    snapshot = json.loads(body)
    return {
        "result": "success",
        "data": {
            "snapshot_sequence": snapshot["sequence"],
            "snapshot_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "results": [],
        },
    }


class ResolveBridgePredecessorTests(unittest.TestCase):
    def resolve(self, source: dict, body: bytes) -> dict:
        return resolver.resolve(
            source, search(body), body, distribution_id=DIST,
            next_sequence=3, fallback_revision=FALLBACK,
        )

    def test_reuses_exact_signed_predecessor(self) -> None:
        body = production_body()
        actual = self.resolve(directory(), body)
        self.assertEqual(actual, {
            "revision": SIGNED, "source": "signed_directory",
            "snapshot_sequence": 33,
            "snapshot_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        })

    def test_uses_base_only_when_predecessor_is_not_yet_public(self) -> None:
        older = production_body([{
            "sequence": 1, "package_version": "1.0.0",
            "package_source": {
                "repository": "777genius/universal-agent-plugins",
                "revision": "d" * 40, "path": "plugins/demo",
            },
        }])
        actual = self.resolve(directory(), older)
        self.assertEqual(actual["revision"], FALLBACK)
        self.assertEqual(actual["source"], "unpublished_predecessor")

        absent = (json.dumps({"sequence": 33, "distributions": []}, separators=(",", ":")) + "\n").encode()
        self.assertEqual(self.resolve(directory(), absent)["revision"], FALLBACK)

    def test_uses_exact_sequence_when_versions_repeat(self) -> None:
        releases = [
            {
                "sequence": 1, "package_version": "2.0.0",
                "package_source": {
                    "repository": "777genius/universal-agent-plugins",
                    "revision": "d" * 40, "path": "plugins/demo",
                },
            },
            {
                "sequence": 2, "package_version": "2.0.0",
                "package_source": {
                    "repository": "777genius/universal-agent-plugins",
                    "revision": SIGNED, "path": "plugins/demo",
                },
            },
        ]
        self.assertEqual(self.resolve(directory(), production_body(releases))["revision"], SIGNED)

    def test_rejects_ambiguous_or_changed_signed_identity(self) -> None:
        ambiguous_value = json.loads(production_body())
        ambiguous_value["distributions"].append(ambiguous_value["distributions"][0])
        ambiguous = (json.dumps(ambiguous_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self.assertRaisesRegex(resolver.ResolutionError, "ambiguous"):
            self.resolve(directory(), ambiguous)

        changed_release = json.loads(production_body())["distributions"][0]["releases"][0]
        changed_release["package_source"]["repository"] = "attacker/repository"
        with self.assertRaisesRegex(resolver.ResolutionError, "repository changed"):
            self.resolve(directory(), production_body([changed_release]))

        skipped = production_body([{
            "sequence": 3, "package_version": "3.0.0",
            "package_source": {
                "repository": "777genius/universal-agent-plugins",
                "revision": "e" * 40, "path": "plugins/demo",
            },
        }])
        with self.assertRaisesRegex(resolver.ResolutionError, "skipped"):
            self.resolve(directory(), skipped)

    def test_requires_unresolved_exact_predecessor_and_authenticated_search(self) -> None:
        bound = directory()
        bound["distributions"][0]["releases"][1]["package_source"]["revision"] = SIGNED
        with self.assertRaisesRegex(resolver.ResolutionError, "already bound"):
            self.resolve(bound, production_body())

        body = production_body()
        failed = search(body)
        failed["result"] = "error"
        with self.assertRaisesRegex(resolver.ResolutionError, "did not succeed"):
            resolver.resolve(
                directory(), failed, body, distribution_id=DIST,
                next_sequence=3, fallback_revision=FALLBACK,
            )

    def test_rejects_stale_cli_fallback_before_inferring_unpublished(self) -> None:
        stale_body = production_body(sequence=34)
        stale = search(production_body())
        with self.assertRaisesRegex(resolver.ResolutionError, "current production Directory sequence"):
            resolver.resolve(
                directory(), stale, stale_body, distribution_id=DIST,
                next_sequence=3, fallback_revision=FALLBACK,
            )

        body = production_body()
        changed = search(body)
        changed["data"]["snapshot_digest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(resolver.ResolutionError, "current production Directory digest"):
            resolver.resolve(
                directory(), changed, body, distribution_id=DIST,
                next_sequence=3, fallback_revision=FALLBACK,
            )


if __name__ == "__main__":
    unittest.main()
