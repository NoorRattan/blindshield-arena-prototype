"""Real private journal, actual mTLS denials, and operation-failure hooks."""
import asyncio
from contextlib import closing
import json
import os
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from arena.broker.alerts import CODES, OperatorAlerts, RETENTION, journal_path
from arena.broker.store import Store
from arena.prototype.service import PrototypeService
from test_control import arena, live


def wait_codes(journal, expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        snapshot = journal.snapshot()
        if expected <= {row['code'] for row in snapshot['alerts']}:
            return snapshot
        time.sleep(.01)
    raise AssertionError('Operator alerts were not retained')


def test_alert_retention_overflow_restart_and_private_cli(tmp_path):
    path = journal_path(tmp_path / 'broker.sqlite3')
    journal = OperatorAlerts(path)
    journal.initialize()
    for _ in range(RETENTION + 7):
        journal.record('DENIED_PATH')
    value = OperatorAlerts(path).snapshot()
    assert value['retention'] == len(value['alerts']) == RETENTION
    assert value['dropped'] == 7
    assert value['alerts'][0]['sequence'] == 8
    assert all(set(row) == {'sequence', 'observed_at_unix_ns', 'code'} for row in value['alerts'])
    assert all(row['code'] in CODES for row in value['alerts'])
    with pytest.raises(ValueError, match='FIXED_OPERATOR_ALERT_CODE_REQUIRED'):
        journal.record('SYNTHETIC_SECRET_NOT_AN_ALERT')
    result = subprocess.run([sys.executable, '-m', 'arena.broker', 'alerts', '--directory', str(tmp_path)], capture_output=True)
    assert result.returncode == 0
    assert json.loads(result.stdout)['dropped'] == 7
    if os.name != 'nt':
        assert path.stat().st_mode & 0o077 == 0


def test_actual_tls_denial_stale_version_outage_and_privacy(live, monkeypatch):
    (broker, directory, _), _, _, request = live
    secret = 'SYNTHETIC_PRIVATE_CANARY_NOT_DIAGNOSTICS'
    assert request('GET', '/v1/' + secret, subject='red')[0] == 404
    body = broker.config.profiles[0].request.model_dump()
    _, first = request('POST', '/v1/experiments', body, key='first')
    assert request('POST', f"/v1/experiments/{first['experiment_id']}/seal", {'epoch': first['epoch'] + 1}, key='stale')[0] == 409
    assert request('POST', '/v1/experiments', dict(body, model_version_id='not-approved'), key='version')[0] == 503
    def unavailable(*args):
        raise OSError(secret)
    monkeypatch.setattr(broker, 'status', unavailable)
    status, response = request('GET', f"/v1/experiments/{first['experiment_id']}/status")
    assert status == 503 and response['code'] == 'AUDIT_UNAVAILABLE'
    snapshot = wait_codes(broker.store.operator_alerts, {'DENIED_PATH', 'STALE_STATE', 'VERSION_MISMATCH', 'AUDIT_UNAVAILABLE'})
    assert secret not in json.dumps(snapshot) and secret not in json.dumps(response)
    assert set(response) == {'code', 'request_id'}
    assert request('GET', '/v1/alerts', subject='red')[0] == 404
    # Neither the SQLite journal nor a diagnostics route is part of an HTTP response.
    assert 'alerts' not in response and 'dropped' not in response


def test_unavailable_private_sink_does_not_replace_or_leak_denial(live, monkeypatch):
    (broker, _, _), _, _, request = live
    def failed_sink(code):
        raise sqlite3.OperationalError('SYNTHETIC_SECRET_STORAGE_ERROR')
    monkeypatch.setattr(broker.store.operator_alerts, 'record', failed_sink)
    status, response = request('GET', '/forbidden', subject='red')
    assert status == 404 and response['code'] == 'NOT_FOUND'
    deadline = time.monotonic() + 3
    while broker.store.operator_alerts.unretained_in_process == 0 and time.monotonic() < deadline:
        time.sleep(.01)
    assert broker.store.operator_alerts.snapshot()['unretained_in_process'] >= 1
    assert 'STORAGE_ERROR' not in json.dumps(response)


def test_failed_recorder_operation_retains_fixed_alert_and_original_failed_state(tmp_path):
    async def scenario():
        store = Store(tmp_path / 'broker.sqlite3', os.urandom(32))
        store.initialize()
        op = str(uuid4())
        with store.transaction() as conn:
            conn.execute('CREATE TABLE prototype_operations(id TEXT PRIMARY KEY,state TEXT,result_json TEXT)')
            conn.execute('INSERT INTO prototype_operations VALUES(?,?,NULL)', (op, 'RUNNING'))
        async def unavailable(principal):
            raise OSError('SYNTHETIC_PRIVATE_RECORDER_DETAIL')
        service = SimpleNamespace(store=store, operation_lock=asyncio.Lock(), recovery_only=False,
                                  controller=SimpleNamespace(close=unavailable))
        await PrototypeService._perform(service, op, 'close', object())
        with closing(store.connect()) as conn:
            row = conn.execute('SELECT state,result_json FROM prototype_operations').fetchone()
        assert row['state'] == 'FAILED'
        assert json.loads(row['result_json']) == {'code': 'AUDIT_UNAVAILABLE', 'exception_type': 'OSError'}
        snapshot = store.operator_alerts.snapshot()
        assert [row['code'] for row in snapshot['alerts']] == ['AUDIT_UNAVAILABLE']
        assert 'RECORDER_DETAIL' not in json.dumps(snapshot)
    asyncio.run(scenario())
