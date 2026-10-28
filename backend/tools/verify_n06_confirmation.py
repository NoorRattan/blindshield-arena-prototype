"""Compose exact-source N06 local acceptance with one frozen real confirmation.

Reuse only immutable executed components whose complete original source hashes
still match. Retain failed discovery and interrupted attempts. A durable FAIL
checkpoint precedes commands; only a completed collector may publish PASS.
"""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

from arena.contracts.crypto import sha256
from measure_n06_confirmation import analyze_confirmation
from verify_n04 import sources

ROOT=Path(__file__).resolve().parents[1]


def write_json_atomic(path,value):
    """Flush a complete replacement before exposing a checkpoint or final receipt."""
    temporary=path.with_name(path.name+'.pending')
    with temporary.open('w',encoding='ascii',newline='\n') as stream:
        stream.write(json.dumps(value,indent=2)+'\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def matching_test_counts(counts):
    return len(counts)==2 and counts[0]==counts[1] and counts[0]>=287


def verify_reused_mock(original,previous):
    """Check immutable bytes, then apply the all-phase gate without rewriting V2."""
    raw=(original/'mock-timing/observations.jsonl').read_bytes()
    plan_raw=(original/'mock-timing/protocol.json').read_bytes()
    if sha256(raw)!=previous['observations_sha256'] or sha256(plan_raw)!=previous['protocol_sha256']:
        raise ValueError('IMMUTABLE_MOCK_OBSERVATIONS_AND_PROTOCOL_REQUIRED')
    rows=[json.loads(line) for line in raw.splitlines()]
    checked=analyze_confirmation(rows,json.loads(plan_raw))
    if checked['result']!='WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE':
        raise ValueError('REUSED_MOCK_ALL_PHASE_GATES_REQUIRED')
    return dict(observations_sha256=sha256(raw),protocol_sha256=sha256(plan_raw),
        observations=len(rows),early_publications_all_phases=checked['arms']['SHAPED']['early_publications_all_phases'],
        all_phase_early_release_gate_passed=checked['all_phase_early_release_gate_passed'])


def collect(args):
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/'artifacts'):
        raise ValueError('NEW_PRIVATE_RECEIPT_REQUIRED')
    work=ROOT/'artifacts/n06-confirmation-checks'/uuid4().hex
    work.mkdir(parents=True)
    results=[];before={};discovery={};active=None
    def checkpoint(state,error=None):
        value=dict(discovery)
        value.update(observed_at_utc=datetime.now(timezone.utc).isoformat(),result='FAIL',n06_local_profile_complete=False,
            collector_state=state,active_command=active,command_results=list(results),source_sha256=before,
            source_unchanged_during_checks=False,validation_error_type=type(error).__name__ if error else None,
            collector_error=str(error) if error else None,confirmation_work=work.relative_to(ROOT.parent).as_posix())
        write_json_atomic(work/'progress.json',value)
        write_json_atomic(args.output,value)
    try:
        checkpoint('IN_PROGRESS')
        before=sources()
        discovery=json.loads(args.discovery.read_bytes())
        additions=set(before)-set(discovery['source_sha256'])
        allowed={'backend/tools/measure_n06_confirmation.py','backend/tools/verify_n06_confirmation.py',
            'backend/tests/integration/test_n06_confirmation.py'}
        if (discovery['result'] not in ('PASS','FAIL') or discovery['validation_error_type'] is not None or not discovery['source_unchanged_during_checks']
            or not matching_test_counts(discovery['pytest_counts']) or any(c['exit_code']!=0 for c in discovery['command_results'])
            or discovery['timing']['mock']['result']!='WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE'
            or discovery['timing']['real-canary']['result'] not in ('WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE','INCONCLUSIVE_OR_OUTSIDE_ENVELOPE')
            or not discovery['timing_matches_real_workload_policy'] or additions not in (set(),allowed)
            or any(before.get(path)!=value for path,value in discovery['source_sha256'].items())):
            raise ValueError('EXACT_UNCHANGED_DISCOVERY_COMPONENTS_REQUIRED')
        original=(ROOT.parent/discovery['command_results'][0]['raw_output']).parent
        for item in discovery['command_results']:
            if sha256((ROOT.parent/item['raw_output']).read_bytes())!=item['raw_sha256']:
                raise ValueError('IMMUTABLE_DISCOVERY_OUTPUT_REQUIRED')
        mock_check=verify_reused_mock(original,discovery['timing']['mock'])
        write_json_atomic(work/'source-before.json',before)
        def execute(name,command,timeout=1800):
            nonlocal active
            active=name;checkpoint('IN_PROGRESS')
            try:
                ran=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=timeout)
                code,raw=ran.returncode,ran.stdout+ran.stderr
            except subprocess.TimeoutExpired as exc:
                code,raw=124,(exc.stdout or b'')+(exc.stderr or b'')+b'\nCOMMAND_TIMEOUT\n'
            log=work/(name+'.log')
            with log.open('wb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            lines=raw.decode(errors='replace').strip().splitlines();summary=lines[-1] if lines else ''
            item=dict(name=name,command=command,exit_code=code,raw_output=log.relative_to(ROOT.parent).as_posix(),raw_sha256=sha256(raw),summary=summary)
            results.append(item);active=None;checkpoint('IN_PROGRESS')
            print(json.dumps({k:item[k] for k in ('name','exit_code','summary')}),flush=True)
        execute('real-canary-timing-v3',[sys.executable,'tools/measure_n06_confirmation.py','--output',str(work/'real-timing'),
            '--lock',str(original/'admission/admission.json'),'--model',str(args.model.resolve()),
            '--policy',str(original/'candidate/policy.json'),'--policy-public-key',str(original/'candidate/policy-public.hex'),
            '--policy-key-id','n06-local-policy','--discovery-analysis',str(original/'real-timing/analysis.json')],timeout=5400)
        for name,command in (
            ('pytest-primary',[sys.executable,'-m','pytest','-q','-W','error']),
            ('pytest-offline',[str(args.offline_python.resolve()),'-m','pytest','-q','-W','error']),
            ('schemas',[sys.executable,'-m','arena.cli.main','schemas','--output','contracts/arena.v2.schema.json','--check']),
            ('vectors',[sys.executable,'-m','arena.cli.main','check-vectors','--path','fixtures/arena-v2/vectors.json']),
            ('control-smoke',[sys.executable,'examples/broker_control_smoke.py']),
            ('contract-smoke',[sys.executable,'examples/monu_contract_smoke.py']),
            ('dependencies',[sys.executable,'-m','pip','check'])):execute(name,command)
        execute('real-single-lane-regression',[sys.executable,'-m','arena.integration.cli','--lock',str(original/'admission/cell-admission.json'),
            '--model',str(args.model.resolve()),'--corpus',str(args.corpus.resolve()),'--corpus-receipt',str(args.corpus_receipt.resolve()),
            '--corpus-keys',str(args.corpus_keys.resolve()),'--output',str(work/'single-lane'),'--traffic','real','--mode','INPUT'])
        names={r['name'] for r in results}
        reused=[r for r in discovery['command_results'] if r['name'] not in names and r['name']!='real-canary-timing-v2']
        analysis_path=work/'real-timing/analysis.json'
        timing=json.loads(analysis_path.read_bytes()) if analysis_path.exists() else None
        authority=[]
        for path in sorted((work/'real-timing').glob('*/authority.json')):
            value=json.loads(path.read_bytes());log=path.parent/'verifier.log'
            authority.append(dict(path=path.relative_to(ROOT.parent).as_posix(),sha256=sha256(path.read_bytes()),
                verifier_output=log.relative_to(ROOT.parent).as_posix(),verifier_sha256=sha256(log.read_bytes()),**value))
        functional=[a for a in discovery['campaign_authority']['real-canary'] if '/functional/' in a['path']]
        counts=[int(m.group(1)) for r in results if r['name'].startswith('pytest') for m in [re.search(r'(\d+) passed',r['summary'])] if m]
        after=sources()
        plan=json.loads((work/'real-timing/protocol.json').read_bytes()) if (work/'real-timing/protocol.json').exists() else {}
        policy=discovery['validation']['feedback_policy']
        policy_matches=all(plan.get(a)==policy[b] for a,b in (('deadline_ms','execution_deadline_ms'),('floor_ms','release_floor_ms'),('body_bytes','body_bytes')))
        # Recompute from complete immutable observations, not only the child summary.
        real_gate=False
        if timing:
            raw=(work/'real-timing/observations.jsonl').read_bytes()
            if sha256(raw)!=timing['observations_sha256'] or sha256((work/'real-timing/protocol.json').read_bytes())!=timing['protocol_sha256']:
                raise ValueError('IMMUTABLE_CONFIRMATION_OBSERVATIONS_REQUIRED')
            checked=analyze_confirmation([json.loads(line) for line in raw.splitlines()],plan)
            real_gate=checked['result']=='WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE' and checked['all_phase_early_release_gate_passed']
        ok=bool(timing and timing['result']=='WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE' and timing['source_unchanged_during_checks']
            and real_gate and len(authority)==20 and len(functional)==1 and policy_matches and matching_test_counts(counts) and before==after
            and all(a['sealed_profile_verified'] and a['blue_projection_constant'] for a in authority)
            and all(r['exit_code']==0 for r in results))
        receipt=dict(discovery)
        receipt.update(observed_at_utc=datetime.now(timezone.utc).isoformat(),result='PASS' if ok else 'FAIL',n06_local_profile_complete=ok,
            collector_state='COMPLETED',active_command=None,collector_error=None,
            source_sha256=before,source_unchanged_during_checks=before==after,pytest_counts=counts,
            command_results=reused+results,timing={'mock':discovery['timing']['mock'],'real-canary':timing},
            campaign_authority={'mock':discovery['campaign_authority']['mock'],'real-canary':authority+functional},
            timing_matches_real_workload_policy=policy_matches,
            discovery_receipt=dict(path=args.discovery.resolve().relative_to(ROOT.parent).as_posix(),sha256=sha256(args.discovery.read_bytes()),result=discovery['result']),
            component_reuse={'scope':'IMMUTABLE_EXECUTED_COMPONENTS_WITH_ALL_ORIGINAL_SOURCE_BYTES_UNCHANGED',
                'source_sha256':discovery['source_sha256'],'added_tools':sorted(additions),'reused_commands':[r['name'] for r in reused],
                'mock_all_phase_early_release_check':mock_check,
                'original_work':original.relative_to(ROOT.parent).as_posix(),'confirmation_work':work.relative_to(ROOT.parent).as_posix()},
            superseded_real_timing=discovery['timing']['real-canary'],optional_stopping_used=False)
        write_json_atomic(work/'progress.json',receipt)
        write_json_atomic(args.output,receipt)
        print(json.dumps({'result':receipt['result'],'n06_local_profile_complete':ok,'pytest_counts':counts,'real_timing':timing['result'] if timing else None}),flush=True)
        return 0 if ok else 1
    except Exception as exc:
        checkpoint('FAILED',exc)
        print(json.dumps({'result':'FAIL','collector_state':'FAILED','error_type':type(exc).__name__}),flush=True)
        return 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('discovery','model','offline-python','corpus','corpus-receipt','corpus-keys','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    return collect(parser.parse_args())


if __name__=='__main__':raise SystemExit(main())
