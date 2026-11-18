#!/usr/bin/env python3
"""Read only, immutable GitHub artifacts for SkillSpector #482 cohort parity.

Never executes third-party source content, signs reports, or publishes a scan.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from scripts import skillspector_cohort9_semantic_parity_v2 as proof

REPO = "777genius/universal-agent-plugins-registry"
PINS = (
    (14387894677, proof.BASELINE_SHA, 75 << 20),
    (14394423232, proof.CANDIDATE_SHA, 4 << 20),
)


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def original_artifact(artifact_id: int, digest: str, maximum: int, token: str) -> bytes:
    require(token != "", "missing Actions read token")
    uri = f"https://api.github.com/repos/{REPO}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(uri, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "skillspector-482-readonly-parity",
    })
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=40):
            raise ValueError("GitHub artifact API returned no signed redirect")
    except urllib.error.HTTPError as error:
        if error.code not in (302, 303, 307, 308):
            raise
        location = error.headers.get("Location", "")
    parsed = urllib.parse.urlparse(location)
    require(
        parsed.scheme == "https" and bool(parsed.hostname)
        and parsed.username is None and parsed.password is None
        and parsed.hostname not in ("localhost", "127.0.0.1", "::1"),
        "unsafe signed artifact location",
    )
    # Deliberately no GitHub Authorization header for the temporary object store.
    with urllib.request.urlopen(urllib.request.Request(location, headers={
        "User-Agent": "skillspector-482-readonly-parity",
    }), timeout=90) as response:
        data = response.read(maximum + 1)
    require(0 < len(data) <= maximum, "missing or oversized original artifact")
    require(hashlib.sha256(data).hexdigest() == digest, "original immutable artifact SHA mismatch")
    return data


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    with tempfile.TemporaryDirectory(prefix="skillspector-482-cohort9-") as directory:
        files = []
        for artifact_id, expected, limit in PINS:
            content = original_artifact(artifact_id, expected, limit, token)
            destination = Path(directory) / f"{artifact_id}.zip"
            destination.write_bytes(content)
            files.append(destination)
        result = proof.audit(files[0], files[1])
        candidate, original = proof.read_bundles(files[0], files[1])
        old = next(row for row in original.values() if row["id"].endswith("/braids"))
        new = next(row for row in candidate["records"] if row["id"].endswith("/braids"))
        negatives = proof.negative_tests(old, new)
        require(len(negatives) == 12, "negative security cases incomplete")
        require(result["source_count"] == 9
                and result["security_groups_preserved"] == 9
                and result["false_missing_reference_rows_removed_in_candidate"] == 11
                and result["production_partial_reduction"] == 0
                and result["publication_authorized"] is False,
                "candidate or publication trust boundary changed")
        print("PASS pinned original artifacts, signed-v1 unchanged, nine-source semantic parity, "
              "twelve fail-closed negatives; production improvement ZERO")


if __name__ == "__main__":
    main()
