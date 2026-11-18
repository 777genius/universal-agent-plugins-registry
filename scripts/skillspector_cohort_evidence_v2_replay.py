"""Read-only replay of nine immutable original/candidate GitHub Actions artifacts.

Recheck original ZIP SHA-256 and member CRC; never rewrite signed v1 bits,
scanner output, production records, or source provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from scripts.skillspector_cohort_evidence_v2 import (
    EvidenceRejected, compare_findings_v2, require,
)

OLD_SHA = 'fd0792b4aadecd958493ec22749d05298b44dd9f3c0a2fc559ce532f82f80a72'
NEW_SHA = 'cb43297a81ca592a588dbd5798e145d9a6c8b23caaf626c048ef0f91c6e70d99'
REPORT_COMMIT = '991b25b3f543ded46c17a6b403532dcdc06407c9'
OLD_SCANNER = {'id': 'skillspector', 'revision': 'f3b25697d76256998ca9d42c198d256258d4c035', 'version': '2.13.1'}
NEW_SCANNER = {'id': 'skillspector', 'revision': '604a1cff1249ec4023012be4bdb77eac20621893', 'version': '2.13.3'}
EXPECTED_IDS = {
    'plugin:community:3b7213be12f01b1365846d8ba375d59f/sitemap-manager',
    'plugin:community:4d73239dc1cf321957d109bdf29c27dd/sitemap-manager',
    *('plugin:community:b0fa2f8fff3c4570b38ffe3e0c1401a7/' + slug for slug in (
        'braids', 'braids-audit', 'braids-claims', 'braids-depth', 'braids-help',
        'braids-review', 'braids-risk',
    )),
}


def verify_archive(path: Path, expected: str) -> zipfile.ZipFile:
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    require(sha == expected, 'original GitHub Actions artifact digest mismatch')
    archive = zipfile.ZipFile(path)
    require(archive.testzip() is None, 'original GitHub Actions ZIP CRC mismatch')
    return archive


def replay(old_path: Path, candidate_path: Path) -> dict:
    with verify_archive(old_path, OLD_SHA) as old_zip, verify_archive(candidate_path, NEW_SHA) as new_zip:
        proof = json.loads(new_zip.read('candidate.json'))
        require(proof.get('base_report_commit') == REPORT_COMMIT
                and proof.get('scanner') == NEW_SCANNER
                and proof.get('candidate_status') == 'measured_complete_unpublished'
                and proof.get('publication_authorized') is False
                and proof.get('live_selection_verified') is False,
                'candidate artifact is not the original unapproved cohort')
        records = proof.get('records')
        require(isinstance(records, list) and len(records) == 9
                and {r['id'] for r in records} == EXPECTED_IDS,
                'candidate nine-source scope or identity differs')
        previous = {}
        for name in old_zip.namelist():
            if name.startswith('shards/') and name.endswith('.json'):
                shard = json.loads(old_zip.read(name))
                for old in shard['records']:
                    source_id = old['id']
                    if source_id in EXPECTED_IDS:
                        require(source_id not in previous, 'duplicate published source record')
                        previous[source_id] = old
        require(set(previous) == EXPECTED_IDS,
                'published immutable source is missing')
        receipts = []
        for new in records:
            old = previous[new['id']]
            require(old.get('scanner') == OLD_SCANNER and new.get('scanner') == NEW_SCANNER
                    and old.get('source') == new.get('source')
                    and old.get('kind') == new.get('kind')
                    and old.get('plugin_path') == new.get('plugin_path')
                    and old.get('status') == 'partial'
                    and new.get('status') == 'complete',
                    'candidate scanner/source/status changed')
            receipt = compare_findings_v2(old, new)
            # Coverage and the original v1 comparison field are NOT silently
            # reinterpreted. In particular the old signed v1 is immutable.
            receipts.append(receipt)
        require(sum(r['finding_group_count'] for r in receipts) == 9,
                'the original nine security groups are not preserved')
        return {
            'schema_version': 2,
            'kind': 'skillspector-original-actions-cohort-finding-parity-replay',
            'original_report_commit': REPORT_COMMIT,
            'old_actions_artifact_sha256': OLD_SHA,
            'candidate_actions_artifact_sha256': NEW_SHA,
            'proofs': receipts,
            'source_count': len(receipts),
            'security_groups_preserved': 9,
            'source_completeness_certified': False,
            'signed_v1_bits_modified': False,
            'publication_authorized': False,
            'production_partial_reduction': 0,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--published-zip', type=Path, required=True)
    parser.add_argument('--candidate-zip', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = replay(args.published_zip, args.candidate_zip)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(f'PASS {result["source_count"]} immutable source records, '
          f'{result["security_groups_preserved"]} preserved groups; '
          'production Partial/Error reduction 0, no certification')


if __name__ == '__main__':
    main()
