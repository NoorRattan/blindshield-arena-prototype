"""All-phase timing acceptance and crash-safe confirmation checkpoints."""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import measure_n06_confirmation as measurement
import verify_n06_confirmation as collector
from arena.contracts.crypto import sha256
from arena.measurement.evaluation import analyze
from test_n06_release_measurement import vector


@pytest.mark.parametrize('phase',['selection','validation'])
def test_early_shaped_response_fails_confirmation_in_either_phase(phase):
    rows,plan=vector()
    assert measurement.analyze_confirmation(rows,plan)['result']=='WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE'
    next(row for row in rows if row['arm']=='SHAPED' and row['phase']==phase)['early_publication']=True
    # This is the preserved historical baseline behavior the new gate closes.
    if phase=='selection':
        assert analyze(rows,plan)['result']=='WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE'
    checked=measurement.analyze_confirmation(rows,plan)
    assert checked['result']=='INCONCLUSIVE_OR_OUTSIDE_ENVELOPE'
    assert not checked['all_phase_early_release_gate_passed']
    assert checked['arms']['SHAPED']['early_publications_all_phases']==1


def test_mock_reuse_requires_hash_bound_bytes_and_no_early_selection(tmp_path):
    rows,plan=vector()
    folder=tmp_path/'mock-timing';folder.mkdir()
    raw=b''.join((json.dumps(row)+'\n').encode() for row in rows)
    plan_raw=json.dumps(plan).encode()
    (folder/'observations.jsonl').write_bytes(raw)
    (folder/'protocol.json').write_bytes(plan_raw)
    previous=dict(observations_sha256=sha256(raw),protocol_sha256=sha256(plan_raw))
    original=copy.deepcopy(previous)
    assert collector.verify_reused_mock(tmp_path,previous)['all_phase_early_release_gate_passed']
    next(row for row in rows if row['arm']=='SHAPED' and row['phase']=='selection')['early_publication']=True
    changed=b''.join((json.dumps(row)+'\n').encode() for row in rows)
    (folder/'observations.jsonl').write_bytes(changed)
    with pytest.raises(ValueError,match='IMMUTABLE_MOCK'):
        collector.verify_reused_mock(tmp_path,previous)
    # Even an otherwise authentic prior observation set cannot waive the new gate.
    with pytest.raises(ValueError,match='ALL_PHASE_GATES'):
        collector.verify_reused_mock(tmp_path,dict(previous,observations_sha256=sha256(changed)))
    assert previous==original


@pytest.mark.parametrize('failure',[OSError,KeyboardInterrupt])
def test_collector_checkpoints_completed_commands_before_exception_or_interruption(tmp_path,monkeypatch,failure):
    root=tmp_path/'backend';root.mkdir()
    original=root/'artifacts/original';original.mkdir(parents=True)
    log=original/'start.log';log.write_bytes(b'prior executed command\n')
    discovery=dict(result='FAIL',validation_error_type=None,source_unchanged_during_checks=True,
        pytest_counts=[287,287],source_sha256={},timing_matches_real_workload_policy=True,
        timing={'mock':{'result':'WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE'},
            'real-canary':{'result':'INCONCLUSIVE_OR_OUTSIDE_ENVELOPE'}},
        command_results=[dict(name='origin',exit_code=0,raw_output=log.relative_to(tmp_path).as_posix(),raw_sha256=sha256(log.read_bytes()))])
    discovery_path=original/'receipt.json';discovery_path.write_text(json.dumps(discovery))
    output=root/'artifacts/confirmation.json'
    args=SimpleNamespace(discovery=discovery_path,output=output,model=tmp_path/'model',offline_python=tmp_path/'python',
        corpus=tmp_path/'corpus',corpus_receipt=tmp_path/'corpus-receipt',corpus_keys=tmp_path/'keys')
    added={name:'fixture' for name in ('backend/tools/measure_n06_confirmation.py',
        'backend/tools/verify_n06_confirmation.py','backend/tests/integration/test_n06_confirmation.py')}
    monkeypatch.setattr(collector,'ROOT',root)
    monkeypatch.setattr(collector,'sources',lambda:added)
    monkeypatch.setattr(collector,'verify_reused_mock',lambda *args:{'all_phase_early_release_gate_passed':True})
    calls=[]
    def run(command,**kwargs):
        checkpoint=json.loads(output.read_bytes())
        assert checkpoint['result']=='FAIL' and not checkpoint['n06_local_profile_complete']
        assert checkpoint['collector_state']=='IN_PROGRESS'
        calls.append(command)
        if len(calls)==1:
            assert checkpoint['active_command']=='real-canary-timing-v3' and not checkpoint['command_results']
            return SimpleNamespace(returncode=0,stdout=b'first command finished\n',stderr=b'')
        assert checkpoint['active_command']=='pytest-primary'
        assert [item['name'] for item in checkpoint['command_results']]==['real-canary-timing-v3']
        raise failure('simulated interruption after one completed command')
    monkeypatch.setattr(collector.subprocess,'run',run)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):collector.collect(args)
    else:
        assert collector.collect(args)==1
    receipt=json.loads(output.read_bytes())
    assert receipt['result']=='FAIL' and not receipt['n06_local_profile_complete']
    assert receipt['collector_state']==('IN_PROGRESS' if failure is KeyboardInterrupt else 'FAILED')
    if failure is OSError:assert receipt['validation_error_type']=='OSError'
    recorded=receipt['command_results'][0]
    assert sha256((tmp_path/recorded['raw_output']).read_bytes())==recorded['raw_sha256']
    assert json.loads((tmp_path/receipt['confirmation_work']/'progress.json').read_bytes())==receipt
