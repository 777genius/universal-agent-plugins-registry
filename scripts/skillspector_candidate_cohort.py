#!/usr/bin/env python3
"""Read-only nine-source SkillSpector 2.13.3 cohort scan with separate policy.

No v3 manifest mutation, retry rewrite, signed-directory change, or publication.
The original 2.13.1 reports remain the only current public reports.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

import yaml

from scripts import skillspector_bounded_cohort as admission
from scripts import skillspector_reports as scanner
from scripts import skillspector_coverage_v3 as coverage
from scripts.build_bridges import PinnedRepository
from scripts.build_discovery_index import materialize_package
from scripts.skillspector_acquisition import bounded_package_files
from scripts.build_registry import directory_tree_digest
from scripts.directory_publication import canonical_json, sha256_digest

NEW_SCANNER = admission.NEW_SCANNER
# Do not reuse either current-v3 profile identity or the v2.13.1 exception set.
# This independent 2.13.3 signed cohort uses the ORIGINAL bounded v3 profile;
# changing the global 2.13.1 producer's parser policy must not rotate this
# already-published cohort digest or break the UAP Ed25519 source join.
PROFILE_DOCUMENT = scanner.LEGACY_PROFILE_DOCUMENTS["static-standard-v3"] | {
    "id": "static-cohort-2.13.3-v1",
    "scanner": NEW_SCANNER,
    "exception_set_digest": None,
    "cohort": "nine-immutable-source-pins",
}
PROFILE = {
    "id": PROFILE_DOCUMENT["id"],
    "digest": sha256_digest(canonical_json(PROFILE_DOCUMENT)),
}
MAX_PROOF_BYTES = 16 << 20


def require(condition: bool, message: str) -> None:
    if not condition:
        raise admission.CohortRejected(message)


def finding_signature(record: dict) -> list[tuple]:
    return sorted(
        (row["rule"], row["severity"], row["path"], row.get("line", 0),
         tuple(sorted(scanner.report_json(position) for position in row.get("occurrences", []))))
        for row in record["findings"]
    )


def verify_candidate(item: dict, old: dict, new: dict) -> dict:
    """Require complete inspection without erasing or inventing security findings."""
    require(new["id"] == old["id"] == item["id"] and
            new["kind"] == old["kind"] == item["kind"] and
            new["plugin_path"] == old["plugin_path"] == item["plugin_path"],
            "candidate selection identity differs")
    require(new["source"] == old["source"] and new["source"]["content_digest"] is not None,
            "candidate source bytes or pinned identity differ")
    require(new["scanner"] == NEW_SCANNER and new["profile"] == PROFILE,
            "candidate scanner/profile identity differs")
    require(new["status"] == "complete" and new["coverage"]["status"] == "complete"
            and new["execution"]["state"] == "completed"
            and type(new["execution"]["exit_code"]) is int
            and new["execution"]["exit_code"] in (0, 1),
            "candidate did not complete bounded static analysis")
    cv = new["coverage"]
    require(all(type(cv.get(key)) is int and cv[key] >= 0 for key in (
                "fully_inspected_files", "partially_inspected_files",
                "entirely_uninspected_files", "references_total", "ledger_exceptions_total"))
            and isinstance(cv.get("references"), list)
            and isinstance(cv.get("ledger_exceptions"), list),
            "candidate coverage counters or arrays are invalid")
    require(cv["fully_inspected_files"] > 0 and cv["partially_inspected_files"] == 0
            and cv["entirely_uninspected_files"] == 0
            and cv.get("grouping_complete") is True
            and not cv.get("reference_evidence_truncated")
            and not cv.get("reasons")
            and cv.get("references_total", 0) == len(cv.get("references", []))
            and not new["findings_truncated"] and not new["errors"],
            "candidate has uninspected, incomplete or truncated evidence")
    for ref in cv.get("references", []):
        require(ref["status"] in {"resolved", "missing", "ambiguous", "rejected", "uninspected"}
                and ref["disposition"] in {"analyzed", "partial", "failed", "out_of_scope"}
                and ref["status"] not in {"missing", "ambiguous", "uninspected"}
                and not (ref["status"] == "rejected" and ref["disposition"] == "partial")
                and not (ref["status"] == "resolved" and ref["disposition"] != "analyzed"),
                "candidate retains an uninspected reference")
    require(cv.get("ledger_exceptions_total", 0) == 0 and not cv.get("ledger_exceptions"),
            "candidate has unresolved ledger exceptions")
    require(all(type(new.get(key)) is int and new[key] >= 0 for key in (
                "raw_finding_count", "finding_count", "finding_group_count"))
            and isinstance(new.get("findings"), list)
            and new["raw_finding_count"] >= new["finding_count"] >= new["finding_group_count"]
            and new["finding_group_count"] == len(new["findings"]),
            "candidate finding groups are omitted or malformed")
    return {
        "id": item["id"],
        "source_digest": new["source"]["content_digest"],
        "old_findings": old["finding_count"],
        "candidate_findings": new["finding_count"],
        "findings_changed": (
            old["finding_count"] != new["finding_count"] or
            finding_signature(old) != finding_signature(new)
        ),
        "candidate_exit_code": new["execution"]["exit_code"],
    }


def scan_one(executable: Path, item: dict, pinned: PinnedRepository) -> dict:
    """Materialize inert Git blobs; execute only pinned scanner, never Skill code."""
    record = scanner.empty_record_v3(item)
    record["scanner"] = copy.deepcopy(NEW_SCANNER)
    record["profile"] = copy.deepcopy(PROFILE)
    record["execution"]["started_at"] = scanner.now()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="uap-2133-cohort-") as directory:
        home, root = Path(directory), Path(directory) / "content"
        root.mkdir()
        policy = scanner.STANDARD_PROFILE_DOCUMENT
        files = bounded_package_files(
            pinned, item["path"], max_files=policy["max_files"],
            max_file_bytes=policy["max_tree_bytes"], max_tree_bytes=policy["max_tree_bytes"],
        )
        require(any(name == "SKILL.md" for name, _, _ in files),
                "pinned candidate source lacks SKILL.md")
        materialize_package(files, root)
        record["source"]["content_digest"] = directory_tree_digest(root)
        document = (root / "SKILL.md").read_text(encoding="utf-8")
        if document.startswith("---\n") and "\n---" in document[4:]:
            header = document[4:].split("\n---", 1)[0]
            require(len(header.encode("utf-8")) <= 65536, "source frontmatter exceeds bound")
            metadata = yaml.safe_load(header)
            if isinstance(metadata, dict) and isinstance(metadata.get("name"), str):
                record["skill_name"] = scanner.clean(metadata["name"], 200) or None
        record["execution"]["acquisition_seconds"] = round(time.monotonic() - started, 6)
        record["scanned_at"] = scanner.now()
        analysis_start = time.monotonic()
        code, body = scanner.run_scanner_v3(
            executable, ["scan", str(root), *policy["arguments"]],
            home, policy["timeout_seconds"], profile_id="static-standard-v3",
        )
        record["execution"]["analysis_seconds"] = round(time.monotonic() - analysis_start, 6)
        require(directory_tree_digest(root) == record["source"]["content_digest"],
                "candidate scanner changed source files")
        return scanner.normalize_report_v3(record, body, code, root, scanner_identity=NEW_SCANNER)



def verify_pinned_scanner(executable: Path) -> Path:
    """Require the exact vetted fork + two byte-for-byte directory patches."""
    binary = executable.absolute()
    require(binary.is_file() and not binary.is_symlink()
            and binary.parent.name == "bin"
            and binary.parent.parent.name == ".venv",
            "candidate executable must be an installed pinned scanner entrypoint")
    checkout = binary.parents[2]
    clean_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}

    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(checkout), *args], env=clean_env,
            text=True, timeout=30,
        )

    require(git("rev-parse", "HEAD").strip() == NEW_SCANNER["revision"],
            "scanner checkout must match the exact reviewed fork revision")
    # Existing vetted patch module uses sibling absolute imports in direct CLI
    # mode; keep its source modules local rather than importing random paths.
    scripts = str(Path(__file__).resolve().parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from patch_skillspector_directory_refs_2133_canary import PATCHES
    pinned_blobs = {
        "src/skillspector/references.py": "a80b1a5f77b1a74403d8c44a04af082fe5f19b8c",
        "src/skillspector/nodes/build_context.py": "174887b736d1d5940cd1cf04b235210290702960",
    }
    require(set(PATCHES) == set(pinned_blobs), "candidate source patch allowlist differs")
    for path, expected in pinned_blobs.items():
        require(git("rev-parse", "HEAD:" + path).strip() == expected,
                "unrecognized original scanner module blob")
        before, after = PATCHES[path]
        original = git("show", "HEAD:" + path)
        require(original.count(before) == 1, "candidate directory patch anchor differs")
        require((checkout / path).read_text(encoding="utf-8") ==
                original.replace(before, after, 1),
                "candidate scanner module differs from vetted compatibility patch")
    status = git("status", "--porcelain", "--untracked-files=all",
                 "--ignored=matching", "--", "src").splitlines()
    require(len(status) == len(pinned_blobs) and
            all(row.startswith(" M ") for row in status) and
            {row[3:] for row in status} == set(pinned_blobs),
            "candidate scanner has unknown modified or ignored importable source")
    return binary


def run_candidate(plan: dict, previous: dict, executable: Path, *,
                  github_token: str | None = None, progress_dir: Path | None = None) -> dict:
    require(plan.get("kind") == "skillspector-bounded-cohort-preflight"
            and plan.get("candidate_status") == "not_scanned"
            and plan.get("publication_authorized") is False
            and plan.get("live_selection_verified") is False
            and plan.get("candidate_scanner") == NEW_SCANNER,
            "unsafe candidate plan state")
    expected = admission.build_plan(
        previous, previous["selection"], plan["base_report_commit"],
    )
    require(plan == expected, "candidate plan does not match fully verified old bundle")
    binary = verify_pinned_scanner(executable)
    version = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True,
        timeout=25, check=True,
    )
    require((version.stdout + version.stderr).strip().endswith("v2.13.3"),
            "candidate CLI version differs")
    records, comparisons = [], []
    progress_bytes = 0
    with ExitStack() as stack:
        pins: dict[tuple[str, str], PinnedRepository] = {}
        for ordinal, item in enumerate(plan["selection"]["sources"], 1):
            new = None
            try:
                key = (item["repository"], item["revision"])
                if key not in pins:
                    pinned = PinnedRepository(*key, mirror_root=None, github_token=github_token)
                    pins[key] = pinned
                    stack.callback(pinned.close)
                old = previous["records"][item["id"]]
                admission.checked_old_partial(old, item, admission.COHORT[
                    item["repository"], item["revision"], item["path"],
                ])
                new = scan_one(binary, item, pins[key])
                comparison = verify_candidate(item, old, new)
                if progress_dir is not None:
                    require(not scanner.has_public_credentials(new),
                            "candidate contains credential-shaped public evidence")
                    progress_bytes += len(scanner.report_json(new))
                    require(progress_bytes <= MAX_PROOF_BYTES, "candidate evidence budget exceeded")
                    admission.write_plan_exclusively(
                        progress_dir / f"accepted-{ordinal:02d}.json",
                        {"record": new, "comparison": comparison, "publication_authorized": False},
                    )
            except Exception as error:
                if progress_dir is not None:
                    # Rejected raw evidence is not safe to publish. Keep only a
                    # bounded, source-pinned failure witness, never raw scanner text.
                    observed = new.get("status") if isinstance(new, dict) else None
                    admission.write_plan_exclusively(
                        progress_dir / f"rejected-{ordinal:02d}.json",
                        {"id": item["id"], "error_class": type(error).__name__,
                         "observed_status": observed if observed in {"complete", "partial", "error"} else None,
                         "completed_records": len(records), "publication_authorized": False},
                    )
                raise
            comparisons.append(comparison)
            records.append(new)
    require(len(records) == 9 and len({r["id"] for r in records}) == 9,
            "incomplete isolated candidate scan")
    proof = {
        "schema_version": 1,
        "kind": "skillspector-2.13.3-nine-source-candidate",
        "base_report_commit": plan["base_report_commit"],
        "base_manifest_digest": plan["base_manifest_digest"],
        "scanner": copy.deepcopy(NEW_SCANNER),
        "profile": copy.deepcopy(PROFILE),
        "profile_policy_digest": sha256_digest(canonical_json(PROFILE_DOCUMENT)),
        "candidate_status": "measured_complete_unpublished",
        "live_selection_verified": False,
        "publication_authorized": False,
        "comparisons": comparisons,
        "records": records,
    }
    require(not scanner.has_public_credentials(proof),
            "candidate artifact retains credential-shaped public data")
    require(len(scanner.report_json(proof)) <= MAX_PROOF_BYTES,
            "complete normalized candidate evidence exceeds proof budget")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-dir", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    previous = coverage.read_bundle(args.previous_dir)
    require(previous is not None, "authenticated old v3 bundle missing")
    coverage.validate_manifest(previous["manifest"], current_policy=True)
    plan = json.loads(args.plan.read_bytes())
    proof = run_candidate(plan, previous, args.scanner, github_token=os.environ.get("GITHUB_TOKEN"),
                          progress_dir=args.output.parent)
    admission.write_plan_exclusively(args.output, proof)
    print("Nine exact pinned sources rescanned by 2.13.3. Unpublished candidate only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
