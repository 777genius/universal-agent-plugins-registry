#!/usr/bin/env python3
"""Read-only, exact-original production regression for issue #482.

Two original GitHub Actions ZIPs are SHA-pinned. Neither third-party source
code nor an untrusted skill is executed; evidence is only parsed and checked.
A successful candidate is NOT a Complete status or authorization to publish.
"""
import copy
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

from scripts import skillspector_coverage_v3 as coverage
from scripts import skillspector_recovery as recovery

SOURCE_COMMIT = "19c33027f43733abee88322ffd9767c40fddb40d"
SOURCE_REVISION = "467f92cebc17f25735ba1e80bc86f38ccd1cf098"
CONTENT_DIGEST = "sha256:add76fb6660a06c4a0982949c0c4d332fa5d7eca251afabd8cddc1abef7ee5d2"
SUBJECT = "everyinc/compound-engineering-plugin/ce-brainstorm"
OLD_REPORT = "sha256:02ecd86606059736f012dc91c82257d406b987f47986f2409734716687430d57"
NEW_REPORT = "sha256:ff1607024d71fa4ce6d8014b30d5247f862342a4041d334e1997d9dbd81258e4"
OLD_ZIP = "30996971b3da05f02cf866851e4db306fa963534581d04d03c9b1f60a8ba2769"
NEW_ZIP = "de2e8e9bc77ca5370b4176df17c46a6bd3f0a4dd1fe28d172d1b8b6dc3a41336"
ORIGIN = {"run_id": 44733681502, "run_attempt": 1}
PREVIOUS_ENTRY = re.compile(
    r"previous/(?:index|selection|attempts|coverage|recovery|publication-base)\.json|"
    r"previous/shards/[0-9a-f]{64}\.json"
)


def insist(condition, description):
    if not condition:
        raise AssertionError(description)


def validated_zip(path, digest, max_files):
    with path.open("rb") as handle:
        insist(hashlib.file_digest(handle, "sha256").hexdigest() == digest,
               "immutable original ZIP SHA-256 mismatch")
    archive = zipfile.ZipFile(path)
    insist(len(archive.infolist()) <= max_files and archive.testzip() is None,
           "original ZIP member count/CRC invalid")
    names = archive.namelist()
    insist(len(set(names)) == len(names), "duplicate ZIP members")
    return archive


def assert_refusal(fn, fragment):
    try:
        fn()
    except coverage.PublicationError as exc:
        insist(fragment in str(exc), "unexpected fail-closed reason")
    else:
        raise AssertionError("unauthorized novel security evidence was accepted")


def run(previous_zip, current_zip, output):
    with tempfile.TemporaryDirectory(prefix="skillspector-current-original-") as directory:
        root = Path(directory)
        prior = validated_zip(previous_zip, OLD_ZIP, 2100)
        try:
            entries = [info for info in prior.infolist()
                       if info.filename.startswith("previous/")]
            insist(len(entries) >= 2050, "original manifest/shards incomplete")
            insist(sum(info.file_size for info in entries) < (600 << 20),
                   "previous bundle too large")
            previous_dir = root / "previous"
            for info in entries:
                insist(PREVIOUS_ENTRY.fullmatch(info.filename) is not None and
                       not info.is_dir() and info.file_size <= (64 << 20),
                       "unexpected original bundle path or oversized file")
                destination = root / info.filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(prior.read(info))
            previous = coverage.read_bundle(previous_dir)
            insist(previous["manifest"]["source_commit"] == SOURCE_COMMIT,
                   "wrong previous main SHA")
        finally:
            prior.close()
        worker_zip = validated_zip(current_zip, NEW_ZIP, 4)
        try:
            insist(set(worker_zip.namelist()) ==
                   {"coverage.json", "selection.json", "worker.json", "provenance.json"},
                   "unexpected worker ZIP contents")
            provenance = json.loads(worker_zip.read("provenance.json"))
            documents = {name: worker_zip.read(name) for name in
                         ("coverage.json", "selection.json", "worker.json")}
            for name, body in documents.items():
                insist(provenance["files"][name] == {
                    "bytes": len(body),
                    "digest": "sha256:" + hashlib.sha256(body).hexdigest()},
                    "worker provenance bytes/digest mismatch")
            insist((provenance["run_id"], provenance["run_attempt"],
                    provenance["head_branch"], provenance["head_sha"]) ==
                   (44733681502, 1, "main", SOURCE_COMMIT),
                   "unexpected producing main origin")
            batch = recovery.validate_provenance(provenance, documents)
            insist(batch["execution_origin"] == ORIGIN and not batch["unsupported_policy"],
                   "original worker origin/policy not authenticated")
        finally:
            worker_zip.close()
        selection = previous["selection"]
        item = next(entry for entry in selection["sources"] if entry["id"] == SUBJECT)
        old = previous["records"][SUBJECT]
        before_attempt = previous["attempts"][SUBJECT]
        matching = [value for worker in batch["workers"] for value in worker["attempts"]
                    if value["attempt"]["id"] == SUBJECT]
        insist(len(matching) == 1, "expected exactly one immutable source execution")
        outcome = matching[0]
        new = outcome["record"]
        insist(item["revision"] == SOURCE_REVISION and
               old["source"] == new["source"] and
               old["source"]["content_digest"] == CONTENT_DIGEST,
               "source revision/content changed")
        insist(old["report_digest"] == OLD_REPORT and new["report_digest"] == NEW_REPORT and
               old["scanner"] == new["scanner"],
               "wrong scanner identity or original report digests")
        insist(old["status"] == new["status"] == "partial" and
               len(old["findings"]) == 32 and len(new["findings"]) == 37,
               "actual original report statuses/findings differ")
        old_groups = coverage.finding_evidence_identities(old)
        new_groups = coverage.finding_evidence_identities(new)
        insist(not (old_groups - new_groups) and
               sum((new_groups - old_groups).values()) == 5 and
               coverage.degraded_rescan(old, new),
               "full security-group topology no longer matches 32+5 regression")
        insist(before_attempt["attempt_count"] == 1 and
               outcome["attempt"]["attempt_count"] == 2,
               "original attempt lineage changed")

        def probe(authenticated=False, origin=None):
            records, attempts = {SUBJECT: copy.deepcopy(old)}, {SUBJECT: copy.deepcopy(before_attempt)}
            try:
                coverage.apply_outcome(records, attempts, item, outcome,
                    authenticated_current_worker=authenticated, verified_current_origin=origin)
            finally:
                if origin is None:
                    insist(records[SUBJECT] == old and attempts[SUBJECT] == before_attempt,
                           "unauthorized attempt mutated original report/retry lineage")

        assert_refusal(lambda: probe(), "degraded partial rescan introduces new findings")
        assert_refusal(lambda: probe(authenticated=True),
                       "degraded partial introduces unrepresented new findings")
        records, attempts = {SUBJECT: copy.deepcopy(old)}, {SUBJECT: copy.deepcopy(before_attempt)}
        insist(coverage.apply_outcome(records, attempts, item, outcome,
            authenticated_current_worker=True, verified_current_origin=ORIGIN),
            "authenticated current Partial not accepted")
        retained = records[SUBJECT]
        insist(retained["status"] == "partial" and retained["findings"] == old["findings"] and
               retained["report_digest"] == OLD_REPORT and retained["findings_truncated"],
               "older original security evidence/Partial not retained")
        insist(retained["recovery_witnesses"] == [{"origin": ORIGIN, "record": new}],
               "new original not retained exactly as signed-source witness")
        insist(not (new_groups - coverage.represented_finding_evidence_identities(retained)),
               "new independent security evidence lost")
        insist(attempts[SUBJECT]["attempt_count"] == 2 and
               attempts[SUBJECT]["reason"] in {"recovery_conflict", "recovery_conflict_attempt_limit"},
               "retry lineage or incomplete reason was laundered")
        insist(coverage.witness_fits_shard_budget(
            retained, item["repository"]), "signed witness cannot fit shard budget")

        # Repack all current selected records from an actual, immutable previous
        # bundle, modifying only this authenticated source. Missing partitions
        # are disclosed; this is read-only qualification, never a production publish.
        matching_worker = next(w for w in batch["workers"] if
                               any(x["attempt"]["id"] == SUBJECT for x in w["attempts"]))
        worker = copy.deepcopy(matching_worker)
        worker["attempts"] = [outcome]
        rebuilt_dir = root / "rebuilt"
        coverage.merge_reports(selection, previous, [worker], source_commit=SOURCE_COMMIT,
            output_dir=rebuilt_dir, expected_partition_count=8,
            allow_partial_workers=True, authenticated_current_workers=True,
            verified_current_origin=ORIGIN)
        rebuilt = coverage.read_bundle(rebuilt_dir)
        published = rebuilt["records"][SUBJECT]
        insist(published["status"] == "partial" and
               published["findings"] == old["findings"] and
               published["report_digest"] == OLD_REPORT and
               published["recovery_witnesses"] == [{"origin": ORIGIN, "record": new}] and
               not (new_groups - coverage.represented_finding_evidence_identities(published)),
               "read-back of hashed shard lost original source security evidence")
        insist(rebuilt["manifest"]["execution_summary"]["missing_partitions"] ==
               [0, 1, 2, 3, 5, 6, 7], "read-only qualification hidden missing partitions")
        receipt = {"schema_version": 1, "result": "passed_read_only",
                   "source_commit": SOURCE_COMMIT, "source_revision": SOURCE_REVISION,
                   "content_digest": CONTENT_DIGEST, "old_report_digest": OLD_REPORT,
                   "new_report_digest": NEW_REPORT, "original_run_id": ORIGIN["run_id"],
                   "original_attempt": ORIGIN["run_attempt"],
                   "old_finding_groups": 32, "additional_finding_groups": 5,
                   "lost_original_groups": 0, "signed_witnesses": 1,
                   "persisted_status": "partial", "missing_partitions_disclosed": True,
                   "published_improvements": 0}
        output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: script.py ORIGINAL_PLAN_ZIP ORIGINAL_WORKER_ZIP RECEIPT_JSON")
    run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
