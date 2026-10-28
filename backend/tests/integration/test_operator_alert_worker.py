"""Failed worker audit produces private diagnostics without another dispatch."""
import asyncio
import json

from arena.ports import DependencyUnavailable
from test_n06_execution import environment, submit, job_row


def test_worker_recorder_failure_is_alerted_without_retry_or_private_error_echo(tmp_path, monkeypatch):
    async def scenario():
        env = await environment(tmp_path)
        async def unavailable(*args, **kwargs):
            raise DependencyUnavailable('SYNTHETIC_PRIVATE_RECORDER_DETAIL')
        monkeypatch.setattr(env.controller, '_event', unavailable)
        turn = submit(env)
        await env.worker.run_once()
        row = job_row(env, turn)
        assert row['state'] == 'FAILED'
        assert not await env.worker.run_once()
        assert len(env.runtime.model.calls) == 0
        assert env.worker.failure_audit_acknowledged == [False]
        snapshot = env.store.operator_alerts.snapshot()
        assert [row['code'] for row in snapshot['alerts']] == ['AUDIT_UNAVAILABLE']
        assert 'RECORDER_DETAIL' not in json.dumps(snapshot)
    asyncio.run(scenario())
