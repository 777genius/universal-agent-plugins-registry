#!/usr/bin/env python3
"""Read-only, fail-closed comparison of published v3 and isolated signed-cohort candidate.

Does not certify or publish a skill. It only checks whether the *reported*
security findings and scoped inspection evidence are preserved at exact sources.
"""
import argparse
from collections import Counter
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path

BASELINE_SHA = 'fd0792b4aadecd958493ec22749d05298b44dd9f3c0a2fc559ce532f82f80a72'
CANDIDATE_SHA = 'cb43297a81ca592a588dbd5798e145d9a6c8b23caaf626c048ef0f91c6e70d99'
REPORT_SHA = '991b25b3f543ded46c17a6b403532dcdc06407c9'
SCANNER_BASELINE = {'id':'skillspector','revision':'f3b25697d76256998ca9d42c198d256258d4c035','version':'2.13.1'}
SCANNER_CANDIDATE = {'id':'skillspector','revision':'604a1cff1249ec4023012be4bdb77eac20621893','version':'2.13.3'}

class AuditRejected(ValueError):
    pass

def check(p, reason):
    if not p: raise AuditRejected(reason)

def normalized_findings(record):
    groups=[]
    for finding in record['findings']:
        x=copy.deepcopy(finding)
        ids=x.pop('finding_ids', None)
        check(isinstance(ids,list), 'missing ephemeral finding-id list')
        for occ in x['occurrences']:
            check(isinstance(occ.pop('finding_id',None),str), 'missing occurrence id')
        groups.append(json.dumps(x,sort_keys=True,separators=(',',':')))
    return Counter(groups)

def false_ref_ok(ref):
    if not (ref.get('status')=='missing' and ref.get('disposition')=='partial'
            and ref.get('reference_kind')=='quoted_or_code'
            and ref.get('source_path')=='SKILL.md' and ref.get('target_path') is None):
        return False
    s=ref.get('evidence')
    return isinstance(s,str) and (bool(re.fullmatch(r'<\?xml version="1\.0" encoding="UTF-8"\?>',s))
                                    or s=='methodology-version: "3.1.0"')

def validate_pair(old,new):
    check(old['id']==new['id'],'source id changed')
    check(old['kind']==new['kind'] and old['plugin_path']==new['plugin_path'],'identity changed')
    check(old['source']==new['source'] and re.fullmatch(r'sha256:[a-f0-9]{64}',old['source']['content_digest']),'immutable source drift')
    check(old['scanner']==SCANNER_BASELINE and new['scanner']==SCANNER_CANDIDATE,'scanner identity changed')
    check(old['status']=='partial' and new['status']=='complete', 'wrong status transition')
    check(old['freshness']=='current' and new['execution']['state']=='completed', 'freshness/execution unproven')
    check(new['coverage']['status']=='complete' and new['execution']['exit_code'] in (0,1), 'candidate scan incomplete')
    for key in ('finding_count','raw_finding_count','finding_group_count','findings_truncated'):
        check(old[key]==new[key],f'{key} changed')
    check(normalized_findings(old)==normalized_findings(new),'security evidence changed')
    co,cn=old['coverage'],new['coverage']
    for key in ('analyzers','fully_inspected_files','partially_inspected_files','entirely_uninspected_files','grouping_complete','reference_evidence_truncated','original_findings'):
        check(co.get(key)==cn.get(key),f'{key} coverage changed')
    check(cn['grouping_complete'] and not cn['reference_evidence_truncated'] and not new['findings_truncated'],'candidate grouping/truncation')
    check(cn['partially_inspected_files']==cn['entirely_uninspected_files']==0,'candidate uninspected files')
    check(cn['references_total']==len(cn['references']) and cn['ledger_exceptions_total']==len(cn['ledger_exceptions'])==0, 'candidate reference exception')
    check(co['references_total']==len(co['references']) and co['ledger_exceptions_total']==len(co['ledger_exceptions']), 'old reference ledger malformed')
    refs_old=Counter(json.dumps(r,sort_keys=True) for r in co['references'])
    refs_new=Counter(json.dumps(r,sort_keys=True) for r in cn['references'])
    check(not (refs_new-refs_old),'candidate added or changed reference')
    removed=[json.loads(s) for s in (refs_old-refs_new).elements()]
    check(len(removed)==(2 if 'sitemap-manager' in old['id'] else 1) and all(map(false_ref_ok,removed)), 'removed a real/unapproved reference')
    check(co['ledger_exceptions_total']==len(removed) and len(co['reasons'])==1 and co['reasons'][0].get('code')=='reference_missing','baseline had other coverage failures')
    check(not cn['reasons'] and not cn['ledger_exceptions'] and not new['errors'],'candidate hid or retained coverage errors')
    check(all(ref['status']=='resolved' and ref['disposition']=='analyzed' for ref in cn['references']),'candidate retained uninspected references')
    return {'id':old['id'],'source':old['source'],'old_status':old['status'],'candidate_status':new['status'],
            'security_groups':old['finding_group_count'],'content_occurrences':old['finding_count'],
            'raw_findings':old['raw_finding_count'],'references_before':co['references_total'],
            'references_after':cn['references_total'],'false_references_removed':removed,
            'semantic_findings_unchanged':True,'analyzer_inspection_unchanged':True,
            'production_partial_reduction':0,'publication_authorized':False}

def read_bundles(old_zip, candidate_zip):
    check(hashlib.sha256(Path(old_zip).read_bytes()).hexdigest()==BASELINE_SHA,'published artifact SHA mismatch')
    check(hashlib.sha256(Path(candidate_zip).read_bytes()).hexdigest()==CANDIDATE_SHA,'candidate artifact SHA mismatch')
    with zipfile.ZipFile(old_zip) as z, zipfile.ZipFile(candidate_zip) as w:
        check(z.testzip() is None and w.testzip() is None,'ZIP CRC mismatch')
        proof=json.loads(w.read('candidate.json'))
        check(proof['base_report_commit']==REPORT_SHA and proof['publication_authorized'] is False
              and proof['live_selection_verified'] is False and proof['candidate_status']=='measured_complete_unpublished'
              and proof['scanner']==SCANNER_CANDIDATE,'candidate proof identity/authorization differs')
        ids={r['id'] for r in proof['records']}
        check(len(ids)==len(proof['records'])==9,'candidate cohort is not nine distinct records')
        previous={}
        for name in z.namelist():
            if name.startswith('shards/'):
                for record in json.loads(z.read(name))['records']:
                    if record['id'] in ids:
                        check(record['id'] not in previous,'duplicate immutable original')
                        previous[record['id']]=record
        check(set(previous)==ids,'missing published baseline source')
        return proof,previous

def audit(old_zip,candidate_zip):
    proof,previous=read_bundles(old_zip,candidate_zip)
    rows=[validate_pair(previous[r['id']],r) for r in proof['records']]
    check([p['id'] for p in proof['comparisons']]==[r['id'] for r in rows],'comparison row/record mismatch')
    old_v1_changed = {c['id'] for c in proof['comparisons'] if c['findings_changed'] is True}
    required_old_v1_changed = {r['id'] for r in rows if r['id'].rsplit('/', 1)[-1] in {'braids', 'braids-depth', 'braids-help', 'braids-risk'}}
    check(old_v1_changed == required_old_v1_changed and len(old_v1_changed) == 4, 'signed v1 comparison-bit provenance changed')
    for c,r in zip(proof['comparisons'],rows):
        check(c['source_digest']==r['source']['content_digest'] and c['candidate_findings']==r['content_occurrences']
              and c['old_findings']==r['content_occurrences'] and c['candidate_exit_code'] in (0,1),'candidate source or finding summary differs')
    check(sum(x['security_groups'] for x in rows)==9,'expected security group count mismatch')
    check(sum(len(x['false_references_removed']) for x in rows)==11,'expected false reference count mismatch')
    return {'kind':'independent-source-pinned-nine-cohort-security-parity-v1',
            'published_report_commit':REPORT_SHA,'published_zip_sha256':BASELINE_SHA,
            'candidate_zip_sha256':CANDIDATE_SHA,'source_count':9,
            'security_groups_preserved':9,'false_missing_reference_rows_removed_in_candidate':11,
            'production_partial_reduction':0,'publication_authorized':False,
            'signed_v1_comparison_bits_unchanged': True,
            'semantic_parity_proof_v2_only': True,
            'not_certified_reasons':['read-only candidate, distinct scanner/profile policy',
                'signed cohort release does not authorize production status changes',
                'no current-source production publish and API/browser acceptance'],
            'sources':rows}

def negative_tests(old,new):
    # Mutation testing: the independent guard must fail closed, not just check counts.
    cases=[]
    def attack(name,fn):
        a,b=copy.deepcopy(old),copy.deepcopy(new);fn(a,b)
        try: validate_pair(a,b)
        except AuditRejected: cases.append(name)
        else: raise AssertionError(f'negative test missed {name}')
    attack('lost_security_group',lambda a,b:b['findings'].pop())
    attack('changed_finding_severity',lambda a,b:b['findings'][0].__setitem__('severity','LOW'))
    attack('changed_security_rule',lambda a,b:b['findings'][0].__setitem__('rule','FORGED'))
    attack('changed_security_evidence',lambda a,b:b['findings'][0].__setitem__('evidence','FORGED'))
    attack('lost_security_occurrence',lambda a,b:b['findings'][0]['occurrences'].pop())
    attack('hidden_analyzer_partial',lambda a,b:b['coverage']['analyzers'][0].__setitem__('status','partial'))
    attack('concealed_missing_executable',lambda a,b:b['coverage']['references'].append({'status':'uninspected','disposition':'partial'}))
    attack('missing_source_digest',lambda a,b:b['source'].__setitem__('content_digest','sha256:'+('f'*64)))
    attack('changed_scanner_revision',lambda a,b:b['scanner'].__setitem__('revision','0'*40))
    attack('changed_reference_evidence',lambda a,b:b['coverage']['references'][0].__setitem__('evidence','FORGED'))
    attack('fake_complete_on_old',lambda a,b:a.__setitem__('status','complete'))
    attack('dropped_original_coverage_evidence',lambda a,b:b['coverage'].__setitem__('original_findings',[] if a['coverage']['original_findings'] else ['forged']))
    return cases

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--old',default='/mnt/data/published-14387894677.zip')
    parser.add_argument('--candidate',default='/mnt/data/cohort-14394423232.zip')
    parser.add_argument('--output',default='/mnt/data/skillspector_cohort9_security_parity_20261118.json')
    args=parser.parse_args()
    result=audit(args.old,args.candidate)
    candidate,previous=read_bundles(args.old,args.candidate)
    result['negative_tests_passed']=negative_tests(next(x for x in previous.values() if x['id'].endswith('/braids')),next(x for x in candidate['records'] if x['id'].endswith('/braids')))
    Path(args.output).write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    print(f"PASS {result['source_count']} exact immutable sources; {result['security_groups_preserved']} security groups, {result['false_missing_reference_rows_removed_in_candidate']} false reference rows, {len(result['negative_tests_passed'])} negative tests; published improvements 0")