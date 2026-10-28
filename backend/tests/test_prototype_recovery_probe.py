from __future__ import annotations

import sys
import json
import queue
import subprocess
import os
import asyncio
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from prototype_recovery_probe import (  # noqa: E402
    _corpus_inputs_available,
    _pause_for_parent,
    _process_exited,
    _child_python,
    _after_durable_authorization,
    _write_boundary_rejection,
    _wait_for_boundary_line,
)


def test_step5_probe_accepts_prepared_corpus_directory_and_regular_metadata(tmp_path):
    corpus = tmp_path / "prepared-corpus"
    corpus.mkdir()
    receipt = tmp_path / "receipt.json"
    key_file = tmp_path / "keys.json"
    receipt.write_text("{}", encoding="utf-8")
    key_file.write_text("{}", encoding="utf-8")

    assert _corpus_inputs_available(corpus, receipt, key_file)


def test_step5_probe_rejects_file_where_prepared_corpus_directory_is_required(tmp_path):
    corpus_file = tmp_path / "not-a-corpus-directory"
    corpus_file.write_text("{}", encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    key_file = tmp_path / "keys.json"
    receipt.write_text("{}", encoding="utf-8")
    key_file.write_text("{}", encoding="utf-8")

    assert not _corpus_inputs_available(corpus_file, receipt, key_file)


def test_step5_probe_stops_waiting_when_crash_boundary_is_rejected(tmp_path):
    boundary = tmp_path / "boundary.json"
    failure = tmp_path / "boundary-failure.json"
    failure.write_text(json.dumps({
        "event": "BOUNDARY_REJECTED",
        "error_code": "CRASH_CUT_NOT_EXACTLY_ONE_EXECUTED_ORPHAN",
        "runtime_model_trace_count_before": 3,
        "runtime_model_trace_count_after": 5,
    }), encoding="utf-8")

    try:
        _wait_for_boundary_line(queue.Queue(), boundary, 5)
    except RuntimeError as exc:
        assert str(exc) == "CRASH_BOUNDARY_REJECTED_CRASH_CUT_NOT_EXACTLY_ONE_EXECUTED_ORPHAN"
    else:
        raise AssertionError("boundary rejection must not wait for the full timeout")


def test_step5_boundary_failure_reports_only_sanitized_missing_attribute(tmp_path):
    boundary = tmp_path / "boundary.json"
    failure = tmp_path / "boundary-failure.json"
    error = AttributeError("private response data was not available")
    error.name = "response_text"
    _write_boundary_rejection(
        boundary,
        error,
        0,
        1,
    )

    record = json.loads(failure.read_text(encoding="utf-8"))
    assert record["error_attribute"] == "response_text"
    assert "private response data" not in failure.read_text(encoding="utf-8")


def test_crash_boundary_marker_binds_case_and_excludes_private_metadata(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("prototype_recovery_probe.threading.Event.wait", lambda self: None)
    boundary = tmp_path / "boundary.json"
    _pause_for_parent({
        "boundary": "AFTER_FEEDBACK_AUTHORIZED_BEFORE_RECEIPT",
        "child_pid": 123, "turn_id": "turn-1", "profile_sha256": "a" * 64,
        "source_commit": "b" * 40, "idempotency_key": "private-key",
    }, boundary, case="orphan")
    marker = json.loads(capsys.readouterr().out)
    saved = json.loads(boundary.read_text())
    assert marker["case"] == saved["case"] == "orphan"
    assert marker["boundary"] == saved["boundary"]
    assert "idempotency_key" not in marker
    assert saved["idempotency_key"] == "private-key"


def test_process_liveness_check_does_not_signal_live_child():
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        assert not _process_exited(child.pid)
        assert child.poll() is None
        child.terminate()
        child.wait(timeout=5)
        assert _process_exited(child.pid)
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


def test_child_launch_preserves_venv_and_has_exact_controllable_pid():
    env = os.environ.copy()
    command = [_child_python(env), "-c", (
        "import json,os,sys,pydantic; "
        "print(json.dumps(dict(pid=os.getpid(),prefix=sys.prefix,version=pydantic.__version__)))"
    )]
    child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 0, stderr
    observed = json.loads(stdout)
    assert observed["pid"] == child.pid
    assert Path(observed["prefix"]).resolve() == Path(sys.prefix).resolve()
    import pydantic
    assert observed["version"] == pydantic.__version__


def test_original_receipt_crash_hook_runs_only_after_async_authorization_returns():
    order = []
    signed = object()
    async def authorize(value):
        assert value == "turn"
        await asyncio.sleep(0)
        order.append("durable")
        return signed
    def pause(value):
        assert value is signed
        order.append("boundary")
    result = asyncio.run(_after_durable_authorization(authorize, pause)("turn"))
    assert result is signed
    assert order == ["durable", "boundary"]


def test_original_receipt_crash_hook_does_not_claim_failed_authorization():
    observed = []
    async def authorize():
        raise RuntimeError("AUTHORIZATION_REFUSED")
    try:
        asyncio.run(_after_durable_authorization(authorize, observed.append)())
    except RuntimeError as exc:
        assert str(exc) == "AUTHORIZATION_REFUSED"
    else:
        raise AssertionError("authorization failure must propagate")
    assert not observed
