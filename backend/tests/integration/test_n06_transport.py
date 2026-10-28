"""Actual loopback mTLS + durable/evidence services, synthetic model adapters.

These are bounded transport/failure tests, not Docker isolation or timing bounds.
"""

import asyncio
from contextlib import closing
from dataclasses import replace
import json
import multiprocessing
import os
import ssl
import time
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.broker.server import Server, tls_context
from arena.broker.store import BrokerError
from arena.contracts.api import EpochRequest, TurnSubmission
from arena.execution.lab import LocalMTLSPilot
from arena.execution.transport import LabProfile, ParticipantGateway, SignedLabProfile, lab_message
from arena.contracts.crypto import sha256
from arena.ports import DependencyUnavailable
from test_n06_execution import environment, job_row


def signed(env, **changes):
    profile = LabProfile(**env.ctx.model_dump(), execution_lock_sha256=env.broker.config.profiles[0].execution_lock_sha256,
        feedback_policy_sha256=sha256(env.signed.policy.model_dump_json().encode()), admission_window_ms=100).model_copy(update=changes)
    key = Ed25519PrivateKey.generate()
    return SignedLabProfile(profile=profile, signer_key_id="lab", signature=key.sign(lab_message(profile, "lab")).hex()), key.public_key().public_bytes_raw()


def gateway(env, **changes):
    profile, public = signed(env, **changes)
    return ParticipantGateway(env.p["operator"], env.worker, profile, public, "lab")


def request(env, index=0, **changes):
    return TurnSubmission(epoch=env.ctx.epoch, turn_index=index, text=env.source.text).model_copy(update=changes)


@pytest.mark.parametrize("change", ["key", "context", "lock", "policy", "window", "owner", "phase"])
def test_local_boot_requires_independent_signature_exact_binding_and_actual_start(tmp_path, change):
    async def scenario():
        env = await environment(tmp_path)
        changes = {"context": {"experiment_id": str(uuid4())}, "lock": {"execution_lock_sha256": "0"*64},
            "policy": {"feedback_policy_sha256": "0"*64}, "window": {"admission_window_ms": 6000}}.get(change, {})
        profile, public = signed(env, **changes)
        if change == "key": public = os.urandom(32)
        if change == "phase":
            with env.store.transaction() as conn:
                conn.execute("UPDATE n04_runs SET start_json=NULL")
        with pytest.raises((ValueError, DependencyUnavailable, BrokerError)):
            ParticipantGateway(env.p["red"] if change == "owner" else env.p["operator"], env.worker, profile, public, "lab")
    asyncio.run(scenario())


def test_fixed_round_blocks_private_failure_admission_oracle_and_keeps_replay(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        gate = gateway(env)
        status, ack = gate.submit(env.p["red"], env.session, request(env), "one")
        assert status == 202 and len(ack) == 4096
        turn = json.loads(ack)["turn_id"]
        with closing(env.store.connect()) as conn:
            before = dict(conn.execute("SELECT * FROM n06_lab_runs").fetchone())
            assert before["closes_ns"] == 100_000_000 and before["unblocks_ns"] == 6_000_000_000
        env.clock.ns = 100_000_000
        busy = gate.submit(env.p["red"], env.session, request(env, 1), "fresh")
        job = env.queue.claim(env.ctx, env.worker.worker_id)
        env.queue.fail_claim(job, env.worker.worker_id, fallback="NOT_EVALUATED")
        # Deliberately unguarded synthetic negative control: the old private
        # operator projection reveals the phase. It is never served by this API.
        assert env.broker.status(env.p["operator"], env.ctx.experiment_id)[1]["phase"] == "INVALID"
        assert gate.submit(env.p["red"], env.session, request(env, 1), "fresh") == busy
        assert busy[0] == 429 and json.loads(busy[1])["status"] == "RETRY_LATER"
        assert gate.submit(env.p["red"], env.session, request(env), "one") == (status, ack)
        with pytest.raises(BrokerError, match="IDEMPOTENCY_CONFLICT"):
            gate.submit(env.p["red"], env.session, request(env, text="changed"), "one")
        assert env.queue.project(env.p["red"], env.ctx, env.session, turn).status == 202
        for role, expected in (("red", "CONTROLLED"), ("blue-human", "EMBARGOED")):
            for path in ("status", "feedback"):
                result = gate.dispatch(env.p[role], "GET", f"/v1/experiments/{env.ctx.experiment_id}/{path}", {}, b"")
                assert result[0] == 200 and json.loads(result[1])["status"] == expected and len(result[1]) == 4096
        env.clock.ns = 6_000_000_000
        assert env.queue.project(env.p["red"], env.ctx, env.session, turn).status == 503
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
    asyncio.run(scenario())


def test_round_commit_is_atomic_with_reservation_and_worker_waits_for_window(tmp_path, monkeypatch):
    async def scenario():
        env = await environment(tmp_path)
        gate = gateway(env)
        old = env.queue.submit
        def failed(*args, **kwargs):
            def hook(*unused): raise RuntimeError("synthetic-transaction-failure")
            return old(*args, **(kwargs | {"on_enqueued": hook}))
        monkeypatch.setattr(env.queue, "submit", failed)
        with pytest.raises(RuntimeError): gate.submit(env.p["red"], env.session, request(env), "one")
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT count(*) FROM n06_jobs").fetchone()[0] == 0
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 0
            assert conn.execute("SELECT opens_ns FROM n06_lab_runs").fetchone()[0] is None
        monkeypatch.setattr(env.queue, "submit", old)
        gate.submit(env.p["red"], env.session, request(env), "one")
        pump = asyncio.create_task(gate.pump())
        await asyncio.sleep(.05)
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT state FROM n06_jobs").fetchone()[0] == "QUEUED"
        assert not env.runtime.model.calls
        env.clock.ns = 100_000_000
        for _ in range(100):
            await asyncio.sleep(.01)
            with closing(env.store.connect()) as conn:
                if conn.execute("SELECT state FROM n06_jobs").fetchone()[0] == "AUTHORIZED": break
        assert len(env.runtime.model.calls) == 1
        assert await gate.quiesce()
        await pump
        with pytest.raises(DependencyUnavailable, match="FRESH_AUTHORITATIVE"):
            gateway(env)
    asyncio.run(scenario())


def _register_and_exit(root):
    async def scenario():
        env = await environment(root)
        gate = gateway(env)
        gate.submit(env.p["red"], env.session, request(env), "crash")
    from pathlib import Path
    asyncio.run(scenario())
    os._exit(23)


def test_process_exit_keeps_sticky_owner_and_never_requeues(tmp_path):
    process = multiprocessing.get_context("spawn").Process(target=_register_and_exit, args=(tmp_path,))
    process.start(); process.join(15)
    if process.is_alive():
        process.terminate(); process.join(5)
    assert process.exitcode == 23
    import sqlite3
    with sqlite3.connect(tmp_path / "broker.sqlite3") as conn:
        assert conn.execute("SELECT state FROM n06_lab_runs").fetchone()[0] == "ACTIVE"
        assert conn.execute("SELECT state FROM n06_jobs").fetchone()[0] == "QUEUED"
        assert conn.execute("SELECT count(*) FROM n04_turns").fetchone()[0] == 0
        assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 1


def test_cancellation_resistant_task_blocks_quiescence_until_it_really_settles(tmp_path):
    async def scenario():
        env = await environment(tmp_path, execution_deadline_ms=250, release_floor_ms=500)
        env.queue.clock_ns = time.monotonic_ns
        gate = gateway(env)
        entered, release = asyncio.Event(), asyncio.Event()
        async def resistant(*unused):
            entered.set()
            while not release.is_set():
                try: await release.wait()
                except asyncio.CancelledError: pass
            return env.source
        env.worker.resolve_payload = resistant
        gate.submit(env.p["red"], env.session, request(env), "resistant")
        pump = asyncio.create_task(gate.pump())
        await asyncio.wait_for(entered.wait(), 2)
        await asyncio.sleep(.3)
        assert not await gate.quiesce()
        assert env.worker.tasks and not env.runtime.model.calls
        release.set()
        for _ in range(50):
            if not env.worker.tasks: break
            await asyncio.sleep(.01)
        assert await gate.quiesce()
        await pump
        assert not env.runtime.model.calls
    asyncio.run(scenario())


@pytest.mark.parametrize("verdict", ["ALLOW", "BLOCK", "SANITIZE"])
def test_actual_mtls_async_response_and_reconnect_no_extra_charge(verdict, tmp_path):
    async def scenario():
        env = await environment(tmp_path, verdict=verdict, execution_deadline_ms=5000, release_floor_ms=5100)
        env.queue.clock_ns = time.monotonic_ns
        lab = LocalMTLSPilot(env.worker, env.p["operator"], env.p, tmp_path / "tls", admission_window_ms=100)
        try:
            measured = await lab.turn(env.p["red"], env.session, request(env), "tls-turn", index=0, lane=0)
            assert measured.result.result.pipeline_disposition == {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED_BY_DEFENSE", "SANITIZE": "SANITIZED"}[verdict]
            assert lab.network_samples[0]["admission_rtt_ns"] < 5_000_000_000
            assert lab.network_samples[0]["ack_bytes"] == lab.network_samples[0]["feedback_bytes"] == 4096
            assert len(env.runtime.model.calls) == (0 if verdict == "BLOCK" else 1)
            with closing(env.store.connect()) as conn:
                assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
            with pytest.raises(ValueError, match="LOCAL_PARTICIPANT"):
                Server(("0.0.0.0", 0), env.broker, lab.server.context, participant_gateway=lab.gateway)
        finally:
            await lab.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("case", ["blue", "operator", "wrong-session", "query", "spoof", "duplicate-json", "unknown-field", "revoked"])
def test_actual_mtls_denials_are_fixed_and_side_effect_free(tmp_path, case):
    async def scenario():
        env = await environment(tmp_path)
        env.queue.clock_ns = time.monotonic_ns
        lab = LocalMTLSPilot(env.worker, env.p["operator"], env.p, tmp_path / "tls", admission_window_ms=100)
        path = f"/v1/experiments/{env.ctx.experiment_id}/sessions/{env.session}/turns"
        role, value, headers = "red", request(env).model_dump(exclude_none=True), {}
        if case in {"blue", "operator"}: role = "blue-human" if case == "blue" else "operator"
        if case == "wrong-session": path = path.replace(env.session, str(uuid4()))
        if case == "query": path += "?phase=1"
        if case == "spoof": headers["X-Role"] = "operator"
        if case == "unknown-field": value["role"] = "operator"
        if case == "revoked":
            with env.store.transaction() as conn: conn.execute("UPDATE principals SET enabled=0 WHERE role='red'")
        try:
            if case == "duplicate-json":
                import http.client
                client = http.client.HTTPSConnection("127.0.0.1", lab.server.server_address[1], context=lab.contexts["red"], timeout=6)
                try:
                    client.request("POST", path, b'{"epoch":1,"epoch":1}', {"Content-Type":"application/json", "Idempotency-Key":"bad"})
                    response = client.getresponse(); status, body = response.status, response.read()
                finally: client.close()
            else:
                status, body, _ = await asyncio.to_thread(lab.request, role, "POST", path, value, "bad", headers)
            assert status in {400, 401, 403, 404} and len(body) == 4096
            assert json.loads(body)["schema_version"] == "arena.execution.v1"
            assert env.source.text.encode() not in body
            with closing(env.store.connect()) as conn:
                assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 0
        finally: await lab.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("when", ["queued", "authorized", "unknown"])
def test_cancellation_records_intent_retains_execution_and_does_not_publish_early(tmp_path, when):
    async def scenario():
        env = await environment(tmp_path)
        gate = gateway(env)
        _, ack = gate.submit(env.p["red"], env.session, request(env), "one")
        turn = {"turn_id": json.loads(ack)["turn_id"]}
        if when == "authorized":
            assert await env.worker.run_once()
        elif when == "unknown":
            env.queue.claim(env.ctx, env.worker.worker_id)
        result = gate.cancel(env.p["red"], env.session, EpochRequest(epoch=env.ctx.epoch), "cancel")
        assert result == gate.cancel(env.p["red"], env.session, EpochRequest(epoch=env.ctx.epoch), "cancel")
        assert json.loads(result[1])["status"] == "CANCEL_REQUESTED"
        job = job_row(env, turn)
        assert job["known_execution"] == {"queued": "NOT_EVALUATED", "authorized": "EXECUTED", "unknown": "UNKNOWN"}[when]
        assert env.queue.project(env.p["red"], env.ctx, env.session, turn["turn_id"]).status == 202
        await gate.flush_actions()
        events = tuple(env.recorder.get_events(env.ctx))
        assert events[-1].event_type == "INTEGRITY_VIOLATION"
        await gate.flush_actions()
        assert tuple(env.recorder.get_events(env.ctx)) == events
        env.clock.ns = 6_000_000_000
        final = env.queue.project(env.p["red"], env.ctx, env.session, turn["turn_id"])
        assert final.status == 503 and len(final.body) == 4096
        assert not await env.worker.run_once()
        assert await gate.quiesce()
        await env.controller.close(env.p["operator"])
        with closing(env.store.connect()) as conn:
            assert tuple(conn.execute("SELECT phase,integrity FROM experiments").fetchone()) == ("CLOSED", "INVALID")
    asyncio.run(scenario())


def test_timeout_does_not_retry_and_recorder_failure_blocks_clean_close(tmp_path, monkeypatch):
    async def scenario():
        env = await environment(tmp_path, execution_deadline_ms=250, release_floor_ms=500)
        env.queue.clock_ns = time.monotonic_ns
        async def slow(*args): await asyncio.Event().wait()
        env.worker.resolve_payload = slow
        lab = LocalMTLSPilot(env.worker, env.p["operator"], env.p, tmp_path / "tls", admission_window_ms=100)
        path = f"/v1/experiments/{env.ctx.experiment_id}/sessions/{env.session}/turns"
        status, ack, _ = await asyncio.to_thread(lab.request, "red", "POST", path, request(env).model_dump(exclude_none=True), "slow")
        turn = json.loads(ack)["turn_id"]
        await asyncio.sleep(.35)
        status, body, _ = await asyncio.to_thread(lab.request, "red", "GET", path + "/" + turn)
        assert status == 202 and json.loads(body)["status"] == "PENDING"
        busy = await asyncio.to_thread(lab.request, "red", "POST", path, request(env, 1).model_dump(exclude_none=True), "new")
        assert busy[0] == 429
        await asyncio.sleep(.2)
        status, body, _ = await asyncio.to_thread(lab.request, "red", "GET", path + "/" + turn)
        assert status == 503 and json.loads(body)["status"] == "UNAVAILABLE" and len(body) == 4096
        assert not env.runtime.model.calls and not await env.worker.run_once()
        assert env.worker.failure_audit_acknowledged == [True]
        await lab.close()
        # A missing cancellation ACK cannot become successful close authority.
        second = await environment(tmp_path / "second")
        gate = gateway(second)
        gate.cancel(second.p["red"], second.session, EpochRequest(epoch=second.ctx.epoch), "cancel")
        async def unavailable(*args, **kwargs): raise DependencyUnavailable("synthetic-recorder-outage")
        monkeypatch.setattr(second.controller, "_event", unavailable)
        with pytest.raises(DependencyUnavailable): await gate.quiesce()
    asyncio.run(scenario())


def test_model_completion_after_cancel_preserves_executed_without_late_public_success(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        gate = gateway(env)
        entered, release = asyncio.Event(), asyncio.Event()
        infer = env.runtime.model.infer
        async def delayed(value):
            entered.set()
            await release.wait()
            return await infer(value)
        env.runtime.model.infer = delayed
        _, ack = gate.submit(env.p["red"], env.session, request(env), "late")
        env.clock.ns = 100_000_000
        pump = asyncio.create_task(gate.pump())
        await asyncio.wait_for(entered.wait(), 2)
        gate.cancel(env.p["red"], env.session, EpochRequest(epoch=env.ctx.epoch), "cancel")
        release.set()
        assert await gate.quiesce()
        await pump
        turn_id = json.loads(ack)["turn_id"]
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT known_execution FROM n04_turns WHERE turn_id=?", (turn_id,)).fetchone()[0] == "EXECUTED"
            job = conn.execute("SELECT state,known_execution,body_ref FROM n06_jobs WHERE turn_id=?", (turn_id,)).fetchone()
            assert tuple(job) == ("FAILED", "EXECUTED", None)
        env.clock.ns = 6_000_000_000
        assert env.queue.project(env.p["red"], env.ctx, env.session, turn_id).status == 503
        assert len(env.runtime.model.calls) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("intent_already_durable", [False, True])
def test_late_cancel_handler_cannot_write_after_quiescence_or_recorder_close(tmp_path, intent_already_durable):
    async def scenario():
        env = await environment(tmp_path)
        gate = gateway(env)
        if intent_already_durable:
            gate.cancel(env.p["red"], env.session, EpochRequest(epoch=env.ctx.epoch), "prior")
        assert await gate.quiesce()
        await env.controller.close(env.p["operator"])
        before = tuple(env.recorder.get_events(env.ctx))
        # Models an already parsed authenticated handler reaching dispatch late;
        # shutdown must deny fresh writes, not rely on daemon-thread termination.
        status, body = gate.dispatch(env.p["red"], "POST",
            f"/v1/experiments/{env.ctx.experiment_id}/sessions/{env.session}/cancel",
            {"idempotency-key": "late"}, json.dumps({"epoch": env.ctx.epoch}).encode())
        assert status == (202 if intent_already_durable else 503)
        assert json.loads(body)["status"] == ("CANCEL_REQUESTED" if intent_already_durable else "UNAVAILABLE")
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT count(*) FROM n06_lab_actions").fetchone()[0] == int(intent_already_durable)
            assert conn.execute("SELECT count(*) FROM n06_lab_actions WHERE acknowledged=0").fetchone()[0] == 0
        await gate.flush_actions()
        assert tuple(env.recorder.get_events(env.ctx)) == before
    asyncio.run(scenario())
