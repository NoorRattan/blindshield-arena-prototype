"""One fixed-size N06 real-backend confirmation; never optional stopping.

Keeps the failed v2 discovery result. Same gates, floor, bytes, token caps and
real-data exclusion; higher-resolution observer and lane/period counterbalance.
"""
import argparse
import asyncio
from datetime import datetime,timezone
import json
from pathlib import Path
import random
import sys
import time

import measure_n06_release as release
from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.execution.policy import SignedPolicy,validate_policy
from arena.measurement.evaluation import analyze
from verify_n04 import sources

ROOT=Path(__file__).resolve().parents[1]


def balanced_labels(rng):
    """ABBA or BAAB in every lane: classes share lane and mean period."""
    columns=[[0,1,1,0] if rng.getrandbits(1) else [1,0,0,1] for _ in range(3)]
    return [columns[lane][wave] for wave in range(4) for lane in range(3)]


def analyze_confirmation(rows, plan):
    """Retain baseline analysis and enforce no early shaped reply in either phase."""
    result=analyze(rows,plan)
    for arm,values in result['arms'].items():
        values['early_publications_all_phases']=sum(
            bool(row['early_publication']) for row in rows
            if row['arm']==arm and row['phase'] in ('selection','validation'))
    result['all_phase_early_release_gate_passed']=not result['arms']['SHAPED']['early_publications_all_phases']
    if not result['all_phase_early_release_gate_passed']:
        result['result']='INCONCLUSIVE_OR_OUTSIDE_ENVELOPE'
    return result


async def main_async(args):
    output=args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'artifacts'):
        raise ValueError('NEW_PRIVATE_DIRECTORY_REQUIRED')
    old=json.loads(args.discovery_analysis.read_bytes())
    if (old['result'] not in ('INCONCLUSIVE_OR_OUTSIDE_ENVELOPE','WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE') or not old['real_model']
        or not old['negative_control_detectable']):
        raise ValueError('ACTUAL_DISCOVERY_RESULT_REQUIRED')
    signed=load_wire(SignedPolicy,args.policy.read_bytes())
    policy=validate_policy(signed,bytes.fromhex(args.policy_public_key.read_text(encoding='ascii').strip()),args.policy_key_id)
    if policy.run_label!='REAL_PUBLIC' or policy.body_bytes!=16384:
        raise ValueError('FROZEN_REAL_WORKLOAD_POLICY_REQUIRED')
    output.mkdir(parents=True)
    plan=release.protocol('real-canary',policy)
    plan.update(schema_version='arena-n06-release-protocol.v3',seed=261023,
        scope='REAL_QWEN_SYNTHETIC_CANARY_FIXED_CONFIRMATION',validation_campaigns_per_arm=8,
        precision_scope='96 held-out per arm across eight campaigns; exploratory, not population certification',
        ordering='ABBA/BAAB independently seeded per lane; each lane two ALLOW and two BLOCK; matched arms',
        latency_clock={k:getattr(time.get_clock_info('perf_counter'),k) for k in ('implementation','resolution','monotonic','adjustable')},
        policy_clock={k:getattr(time.get_clock_info('monotonic'),k) for k in ('implementation','resolution','monotonic','adjustable')},
        clock_rule='elapsed ns uses perf_counter_ns; release/early checks stay on monotonic_ns; never subtract different clocks',
        discovery_analysis_sha256=sha256(args.discovery_analysis.read_bytes()),
        replication_rule='one predeclared fixed-size new study; no optional stopping, failed discovery retained, gates unchanged',
        early_release_rule='zero early SHAPED replies across selection AND validation; held-out count retained separately',
        separate_functional_cases=[],source_sha256=sources())
    (output/'protocol.json').write_text(json.dumps(plan,indent=2)+'\n',encoding='ascii',newline='\n')
    (output/'recipe.json').write_bytes(release.RECIPE_RAW)
    (output/'reference-feedback-policy.json').write_bytes(args.policy.read_bytes())
    runtime=release.prepare_runtime(output,args.lock,args.model)
    original_observer=release.observe_turn
    async def high_resolution_observer(send,**kwargs):
        return await original_observer(send,clock=time.perf_counter_ns,**kwargs)
    # Developer measurement callback only. Gateway/runtime/policy clocks unchanged.
    release.observe_turn=high_resolution_observer
    rows=[];rng=random.Random(plan['seed'])
    try:
        await asyncio.to_thread(runtime.start)
        with (output/'observations.jsonl').open('x',encoding='ascii',newline='\n') as log:
            for phase in ('selection','validation'):
                for number in range(plan[phase+'_campaigns_per_arm']):
                    labels=balanced_labels(rng)
                    arms=['SHAPED','UNSHAPED_SYNTHETIC_CONTROL']
                    if number%2:arms.reverse()
                    for arm in arms:
                        values=await release.campaign(output/f'{phase}-{number}-{arm}',arm,phase,number,labels,plan,runtime)
                        for row in values:log.write(json.dumps(row)+'\n')
                        log.flush();rows.extend(values)
                        print(json.dumps({'phase':phase,'campaign':number,'arm':arm,'observations':len(values)}),flush=True)
        result=dict(analyze_confirmation(rows,plan),observed_at_utc=datetime.now(timezone.utc).isoformat(),
            protocol_sha256=sha256((output/'protocol.json').read_bytes()),observations_sha256=sha256((output/'observations.jsonl').read_bytes()),
            source_unchanged_during_checks=plan['source_sha256']==sources(),
            failed_discovery_retained=old['result']=='INCONCLUSIVE_OR_OUTSIDE_ENVELOPE',optional_stopping_used=False)
        (output/'analysis.json').write_text(json.dumps(result,indent=2)+'\n',encoding='ascii',newline='\n')
        print(json.dumps(result),flush=True)
        return 0 if result['source_unchanged_during_checks'] else 1
    finally:
        release.observe_turn=original_observer
        await asyncio.to_thread(runtime.stop)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','lock','model','policy','policy-public-key','discovery-analysis'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--policy-key-id',required=True)
    raise SystemExit(asyncio.run(main_async(parser.parse_args())))
