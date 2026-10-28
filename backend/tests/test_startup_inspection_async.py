"""Synthetic startup scheduling regressions, not model/isolation measurements."""

import asyncio
import importlib.util
from pathlib import Path
import sqlite3
import threading

import pytest

from arena.ports import DependencyUnavailable


_spec = importlib.util.spec_from_file_location(
    "_startup_inspection_n04_helpers",
    Path(__file__).parent / "integration" / "test_n04.py",
)
_n04 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_n04)


def test_blocking_startup_inspection_leaves_event_loop_responsive(tmp_path, monkeypatch):
    entered = threading.Event()
    loop_progress = threading.Event()
    inspection_threads = []
    original = _n04.SyntheticRuntime.inspect

    async def exercise():
        loop_thread = threading.get_ident()

        def inspect(runtime):
            inspection_threads.append(threading.get_ident())
            entered.set()
            # A real Docker inspection blocks on subprocesses. Only the event
            # loop can acknowledge this handshake; running inline must fail.
            assert loop_progress.wait(3), "STARTUP_INSPECTION_BLOCKED_EVENT_LOOP"
            return original(runtime)

        monkeypatch.setattr(_n04.SyntheticRuntime, "inspect", inspect)

        async def heartbeat():
            deadline = asyncio.get_running_loop().time() + 3
            while not entered.is_set():
                assert asyncio.get_running_loop().time() < deadline
                await asyncio.sleep(.005)
            # Exercise another loop task while inspection is still pending.
            await asyncio.sleep(.01)
            loop_progress.set()

        env, _ = await asyncio.gather(_n04.environment(tmp_path), heartbeat())
        assert inspection_threads and all(t != loop_thread for t in inspection_threads)
        assert env.start.phase == "RUNNING"
        assert env.runtime.model.calls == []
        with env.store.connect() as conn:
            assert conn.execute("SELECT phase,integrity FROM experiments").fetchone()[:] == (
                "RUNNING", "PENDING"
            )
            assert conn.execute("SELECT state FROM n04_runs").fetchone()[0] == "RUNNING"

    asyncio.run(exercise())


@pytest.mark.parametrize("error_type", [DependencyUnavailable, RuntimeError])
def test_inspection_failure_still_propagates_and_invalidates(tmp_path, monkeypatch, error_type):
    failure = error_type("SYNTHETIC_INSPECTION_REJECTION")
    inspected = []

    def inspect(runtime):
        inspected.append(runtime)
        raise failure

    monkeypatch.setattr(_n04.SyntheticRuntime, "inspect", inspect)
    with pytest.raises(error_type) as raised:
        asyncio.run(_n04.environment(tmp_path))
    assert raised.value is failure
    assert len(inspected) == 1 and inspected[0].model.calls == []
    with sqlite3.connect(tmp_path / "broker.sqlite3") as conn:
        assert conn.execute("SELECT phase,integrity FROM experiments").fetchone() == (
            "INVALID", "INVALID"
        )
        assert conn.execute("SELECT state FROM n04_runs").fetchone()[0] == "INVALID"
        assert conn.execute("SELECT count(*) FROM turns").fetchone()[0] == 0
