"""Integrated terminal-ACK crash evidence using synthetic model components.

The subprocess runs the real queue, worker, controller, recorder and witness
implementations. The target adapter is synthetic; this is not inference or
deployment evidence.
"""

import asyncio
from contextlib import closing
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.broker.config import BrokerConfig
from arena.broker.core import Broker
from arena.broker.store import BrokerError, Store
from arena.contracts.common import Context, Principal
from arena.contracts.evidence import StartResponse, SignedCheckpoint
from arena.execution.queue import ExecutionQueue
from arena.execution.worker import AsyncTurnWorker
from arena.integration.artifacts import ArtifactVault
from arena.integration.controller import N04Controller
from arena.ports import DependencyUnavailable
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority
from test_n04 import SyntheticRuntime, verify_export
from test_n06_execution import environment, project, submit


def _child_spec(env):
    recorder_private_key = env.recorder.private_key
    witness_private_key = env.controller.witness.private_key
    recorder_public_key = Ed25519PrivateKey.from_private_bytes(
        recorder_private_key
    ).public_key().public_bytes_raw()
    witness_public_key = Ed25519PrivateKey.from_private_bytes(
        witness_private_key
    ).public_key().public_bytes_raw()
    return {
        "root": str(env.root),
        "store_path": str(env.store.path),
        "master_key": env.store.master_key,
        "broker_config": env.broker.config.model_dump_json(),
        "policy_key": env.queue.policy_key,
        "clock_id": env.queue.clock_id,
        "context": env.ctx.model_dump(),
        "operator": env.p["operator"].model_dump(),
        "session_id": env.session,
        "source": env.source.model_dump_json(),
        "recorder_private_key": recorder_private_key,
        "recorder_public_key": recorder_public_key,
        "witness_private_key": witness_private_key,
        "witness_public_key": witness_public_key,
        "vault_key": env.controller.vault.key,
    }


def _child_complete_and_close(spec, pipe, lose_close_ack):
    """Run one full integrated turn, then optionally pause after witness commit."""
    try:
        asyncio.run(_child_async(spec, pipe, lose_close_ack))
    except BaseException as error:
        try:
            pipe.send({"stage": "child-error", "error_type": type(error).__name__})
        except Exception:
            pass
        raise
    finally:
        pipe.close()


async def _child_async(spec, pipe, lose_close_ack):
    from arena.contracts.api import ResolvedPayload

    root = Path(spec["root"])
    store = Store(Path(spec["store_path"]), spec["master_key"])
    broker = Broker(store, BrokerConfig.model_validate_json(spec["broker_config"]))
    ctx = Context.model_validate(spec["context"])
    queue = ExecutionQueue(
        broker,
        spec["policy_key"],
        "policy",
        clock_ns=lambda: 0,
        clock_id=spec["clock_id"],
    )
    recorder = DurableRecorder(root / "recorder.sqlite3", spec["recorder_private_key"], "recorder")
    witness = SQLiteWitnessAuthority(
        root / "witness.sqlite3",
        spec["witness_private_key"],
        "witness",
        initialize_if_missing=False,
        recorder_public_key=spec["recorder_public_key"],
        recorder_key_id="recorder",
    )
    vault = ArtifactVault(root / "vault", ctx, spec["vault_key"])
    runtime = SyntheticRuntime(("ALLOW",))
    controller = N04Controller(
        broker,
        recorder,
        witness,
        vault,
        runtime,
        SimpleNamespace(receipt_sha256=runtime.lock["corpus_receipt_sha256"]),
        recorder_public_key=spec["recorder_public_key"],
        witness_public_key=spec["witness_public_key"],
    )
    source = ResolvedPayload.model_validate_json(spec["source"])

    async def resolve_payload(request, job):
        if request.text != source.text:
            raise AssertionError("RESOLVED_SOURCE_MISMATCH")
        return source

    worker = AsyncTurnWorker(queue, controller, resolve_payload)
    if not await worker.run_once():
        raise AssertionError("HEALTHY_CONTROL_DID_NOT_CLAIM_JOB")

    if lose_close_ack:
        original = witness.close_checkpoint

        async def commit_then_withhold(checkpoint):
            signed = await original(checkpoint)
            pipe.send({"stage": "WITNESS_CLOSE_COMMITTED_BEFORE_CONTROLLER_ACK"})
            pipe.recv()
            return signed

        witness.close_checkpoint = commit_then_withhold

    await controller.close(Principal.model_validate(spec["operator"]))


def _spawn_close_child(env, *, lose_close_ack):
    spawn = multiprocessing.get_context("spawn")
    parent_pipe, child_pipe = spawn.Pipe(duplex=True)
    process = spawn.Process(
        target=_child_complete_and_close,
        args=(_child_spec(env), child_pipe, lose_close_ack),
    )
    process.start()
    child_pipe.close()
    return process, parent_pipe


def _wait_for_stage(process, pipe, expected):
    assert pipe.poll(30), "SUBPROCESS_DID_NOT_REACH_EXPECTED_FAULT_WINDOW"
    message = pipe.recv()
    assert message == {"stage": expected}
    assert process.is_alive()


def _run_snapshot(env, turn):
    witness = env.controller.witness
    with closing(env.store.connect()) as conn:
        job = dict(conn.execute("SELECT * FROM n06_jobs WHERE turn_id=?", (turn["turn_id"],)).fetchone())
        broker_turn = dict(conn.execute("SELECT * FROM turns WHERE id=?", (turn["turn_id"],)).fetchone())
        n04_turn = dict(conn.execute("SELECT * FROM n04_turns WHERE turn_id=?", (turn["turn_id"],)).fetchone())
        run = dict(conn.execute("SELECT * FROM n04_runs WHERE experiment_id=?", (env.ctx.experiment_id,)).fetchone())
        experiment = dict(conn.execute("SELECT phase,integrity FROM experiments WHERE id=?", (env.ctx.experiment_id,)).fetchone())
        admitted = conn.execute("SELECT admitted FROM budgets WHERE experiment_id=?", (env.ctx.experiment_id,)).fetchone()[0]
    with env.recorder._get_connection() as conn:
        checkpoint_count = conn.execute("SELECT count(*) FROM checkpoints").fetchone()[0]
        turn_authorization_count = conn.execute("SELECT count(*) FROM turn_authorizations").fetchone()[0]
    with witness._get_connection() as conn:
        witness_close_count = conn.execute("SELECT count(*) FROM close_receipts").fetchone()[0]
        witness_close = conn.execute("SELECT receipt_json,signature FROM close_receipts").fetchone()
    return {
        "job": job,
        "broker_turn": broker_turn,
        "n04_turn": n04_turn,
        "run": run,
        "experiment": experiment,
        "admitted": admitted,
        "checkpoint_count": checkpoint_count,
        "turn_authorization_count": turn_authorization_count,
        "witness_close_count": witness_close_count,
        "witness_close": witness_close,
        "event_count": len(env.recorder.get_events(env.ctx)),
    }


def _verifier_environment(env, snapshot):
    start = StartResponse.model_validate_json(snapshot["run"]["start_json"])
    rec_pub = Ed25519PrivateKey.from_private_bytes(env.recorder.private_key).public_key().public_bytes_raw()
    wit_pub = Ed25519PrivateKey.from_private_bytes(env.controller.witness.private_key).public_key().public_bytes_raw()
    return SimpleNamespace(
        controller=env.controller,
        principals=env.p,
        rec_pub=rec_pub,
        wit_pub=wit_pub,
        ctx=env.ctx,
        start=start,
    )


def _assert_healthy_completed(env, turn):
    snapshot = _run_snapshot(env, turn)
    assert snapshot["job"]["state"] == "AUTHORIZED"
    assert snapshot["job"]["known_execution"] == "EXECUTED"
    assert snapshot["job"]["body_ref"]
    assert snapshot["broker_turn"]["state"] == "COMPLETED"
    result = json.loads(snapshot["broker_turn"]["result_json"])
    assert result["model_execution"] == "EXECUTED"
    assert result["integrity"] == "VALID_WITHIN_PROFILE"
    assert snapshot["n04_turn"]["state"] == "DONE"
    assert snapshot["n04_turn"]["known_execution"] == "EXECUTED"
    assert snapshot["n04_turn"]["receipt_json"]
    assert snapshot["admitted"] == 1
    assert snapshot["turn_authorization_count"] == 1
    event_types = [event.event_type for event in env.recorder.get_events(env.ctx)]
    assert event_types.count("TURN_COMMITTED") == 1
    assert event_types.count("DEFENSE_RESULT") == 1
    assert event_types.count("DISPATCH_INTENT") == 1
    assert event_types.count("MODEL_RESULT") == 1
    assert event_types.count("SCORE_RESULT") == 1
    assert event_types.count("FEEDBACK_AUTHORIZED") == 1
    assert event_types.count("CLOSE_REQUESTED") == 1
    assert event_types.count("CLOSED") == 1
    return snapshot


def test_subprocess_terminal_ack_loss_retries_exact_close_without_reexecution(tmp_path):
    async def scenario():
        healthy = await environment(tmp_path / "healthy")
        healthy_turn = submit(healthy, key="healthy-turn")
        healthy_process, healthy_pipe = _spawn_close_child(healthy, lose_close_ack=False)
        healthy_process.join(30)
        assert not healthy_process.is_alive() and healthy_process.exitcode == 0
        healthy_pipe.close()
        healthy_snapshot = _assert_healthy_completed(healthy, healthy_turn)
        assert healthy_snapshot["run"]["state"] == "CLOSED"
        assert healthy_snapshot["run"]["witness_json"]
        assert healthy_snapshot["experiment"] == {"phase": "CLOSED", "integrity": "VALID_WITHIN_PROFILE"}
        healthy.clock.ns = 6_000_000_000
        healthy_feedback = project(healthy, healthy_turn)
        assert healthy_feedback.status == 200 and len(healthy_feedback.body) == 4096
        assert json.loads(healthy_feedback.body)["public_status"] == "COMPLETED"
        healthy_verification = verify_export(
            _verifier_environment(healthy, healthy_snapshot), tmp_path / "healthy-verifier", "INPUT"
        )
        assert healthy_verification.status == "PASS_PUBLIC_EVIDENCE"

        interrupted = await environment(tmp_path / "lost-ack")
        interrupted_turn = submit(interrupted, key="lost-ack-turn")
        process, pipe = _spawn_close_child(interrupted, lose_close_ack=True)
        _wait_for_stage(process, pipe, "WITNESS_CLOSE_COMMITTED_BEFORE_CONTROLLER_ACK")
        process.terminate()
        process.join(20)
        assert not process.is_alive() and process.exitcode not in (None, 0)
        pipe.close()

        pending = _assert_healthy_completed(interrupted, interrupted_turn)
        assert pending["run"]["state"] == "CLOSING"
        assert pending["run"]["close_json"] and pending["run"]["witness_json"] is None
        assert pending["experiment"] == {"phase": "SCORED", "integrity": "PENDING"}
        assert pending["checkpoint_count"] == pending["witness_close_count"] == 1
        assert pending["witness_close"] is not None
        with pytest.raises(DependencyUnavailable, match="RELEASE_REQUIRES_AUTHORITATIVE_CLOSE"):
            interrupted.controller.release(interrupted.p["operator"])
        with pytest.raises(BrokerError, match="WRONG_PHASE"):
            interrupted.controller.export(interrupted.p["auditor"], tmp_path / "premature.zip")

        pending_checkpoint = SignedCheckpoint.model_validate_json(pending["run"]["close_json"])
        retried_checkpoint = await interrupted.controller.close(interrupted.p["operator"])
        assert retried_checkpoint == pending_checkpoint
        completed = _run_snapshot(interrupted, interrupted_turn)
        assert completed["run"]["state"] == "CLOSED"
        assert completed["run"]["witness_json"]
        assert completed["experiment"] == {"phase": "CLOSED", "integrity": "VALID_WITHIN_PROFILE"}
        assert completed["checkpoint_count"] == completed["witness_close_count"] == 1
        assert completed["turn_authorization_count"] == 1
        assert completed["event_count"] == pending["event_count"]
        assert completed["witness_close"] == pending["witness_close"]
        assert completed["admitted"] == 1
        interrupted.clock.ns = 6_000_000_000
        final_feedback = project(interrupted, interrupted_turn)
        assert final_feedback.status == 200 and len(final_feedback.body) == 4096
        assert json.loads(final_feedback.body)["public_status"] == "COMPLETED"
        interrupted.controller.release(interrupted.p["operator"])
        verification = verify_export(
            _verifier_environment(interrupted, completed), tmp_path / "lost-ack-verifier", "INPUT"
        )
        assert verification.status == "PASS_PUBLIC_EVIDENCE"

        print("N07B_OBSERVED " + json.dumps({
            "healthy_control": {
                "job": healthy_snapshot["job"]["state"],
                "execution": result_execution(healthy_snapshot),
                "feedback_status": "COMPLETED",
                "offline_verifier": healthy_verification.status,
            },
            "lost_ack": {
                "after_process_death": "CLOSING",
                "integrity_before_ack": pending["experiment"]["integrity"],
                "witness_receipt_committed": True,
                "release_refused_before_controller_ack": True,
                "export_refused_before_controller_ack": True,
                "retry_state": completed["run"]["state"],
                "close_receipts": completed["witness_close_count"],
                "turn_authorizations": completed["turn_authorization_count"],
                "event_count_unchanged": completed["event_count"] == pending["event_count"],
                "budget_admissions": completed["admitted"],
                "offline_verifier": verification.status,
            },
            "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
            "full_n07_acceptance": False,
        }, sort_keys=True))

    asyncio.run(scenario())


def result_execution(snapshot):
    return json.loads(snapshot["broker_turn"]["result_json"])["model_execution"]
