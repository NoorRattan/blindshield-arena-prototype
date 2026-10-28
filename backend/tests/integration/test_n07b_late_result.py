"""Worker death after synthetic target completion but before durable result evidence.

The target response exists inside the isolated test child, but the controller
has not accepted it. A killed worker must therefore leave execution UNKNOWN and
must not make the queued turn eligible for replay.
"""

import asyncio
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from arena.broker.store import BrokerError
from arena.contracts.common import Context
from arena.execution.queue import ExecutionQueue
from arena.execution.worker import AsyncTurnWorker
from arena.integration.artifacts import ArtifactVault
from arena.integration.controller import N04Controller
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority

from test_n04 import SyntheticRuntime, verify_export
from test_n06_execution import environment, submit
from test_n07b_integrated_faults import (
    _child_spec,
    _run_snapshot,
    _verifier_environment,
    _wait_for_stage,
)


def _child_pause_after_target_response(spec, pipe):
    try:
        asyncio.run(_child_async(spec, pipe))
    except BaseException as error:
        try:
            pipe.send({"stage": "child-error", "error_type": type(error).__name__})
        except Exception:
            pass
        raise
    finally:
        pipe.close()


async def _child_async(spec, pipe):
    root = Path(spec["root"])
    from arena.broker.config import BrokerConfig
    from arena.broker.core import Broker
    from arena.broker.store import Store

    store = Store(root / "broker.sqlite3", spec["master_key"])
    broker = Broker(store, BrokerConfig.model_validate_json(spec["broker_config"]))
    ctx = Context.model_validate(spec["context"])
    queue = ExecutionQueue(
        broker,
        spec["policy_key"],
        "policy",
        clock_ns=lambda: 0,
        clock_id=spec["clock_id"],
    )
    recorder = DurableRecorder(
        root / "recorder.sqlite3", spec["recorder_private_key"], "recorder"
    )
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
    original_infer = runtime.model.infer

    async def withhold_completed_response(target):
        response = await original_infer(target)
        pipe.send({"stage": "TARGET_RESPONSE_BEFORE_CONTROLLER_ACCEPTANCE"})
        pipe.recv()
        return response

    runtime.model.infer = withhold_completed_response
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
    from arena.contracts.api import ResolvedPayload

    source = ResolvedPayload.model_validate_json(spec["source"])

    async def resolve_payload(request, job):
        if request.text != source.text:
            raise AssertionError("RESOLVED_SOURCE_MISMATCH")
        return source

    worker = AsyncTurnWorker(queue, controller, resolve_payload)
    await worker.run_once()


def test_process_death_after_target_response_preserves_unknown_and_never_retries(tmp_path):
    async def scenario():
        env = await environment(tmp_path / "late-result")
        turn = submit(env, key="target-response-lost")
        spawn = multiprocessing.get_context("spawn")
        parent_pipe, child_pipe = spawn.Pipe(duplex=True)
        process = spawn.Process(
            target=_child_pause_after_target_response,
            args=(_child_spec(env), child_pipe),
        )
        process.start()
        child_pipe.close()
        _wait_for_stage(
            process, parent_pipe, "TARGET_RESPONSE_BEFORE_CONTROLLER_ACCEPTANCE"
        )
        process.terminate()
        process.join(20)
        assert not process.is_alive() and process.exitcode not in (None, 0)
        parent_pipe.close()

        before_recovery = _run_snapshot(env, turn)
        assert before_recovery["job"]["state"] == "CLAIMED"
        assert before_recovery["job"]["body_ref"] is None
        assert before_recovery["job"]["published"] == 0
        # Queue execution truth is still NOT_EVALUATED until explicit failure
        # reconciliation copies the durable controller UNKNOWN value.
        assert before_recovery["job"]["known_execution"] == "NOT_EVALUATED"
        assert before_recovery["broker_turn"]["state"] == "DISPATCHED"
        assert before_recovery["broker_turn"]["result_json"] is None
        assert before_recovery["n04_turn"]["state"] == "DISPATCHED"
        assert before_recovery["n04_turn"]["known_execution"] == "UNKNOWN"
        assert before_recovery["n04_turn"]["receipt_json"] is None
        assert before_recovery["admitted"] == 1
        assert before_recovery["turn_authorization_count"] == 0
        events = env.recorder.get_events(env.ctx)
        event_types = [event.event_type for event in events]
        assert event_types.count("DISPATCH_INTENT") == 1
        assert event_types.count("MODEL_RESULT") == 0
        assert event_types.count("FEEDBACK_AUTHORIZED") == 0

        recovered_queue = ExecutionQueue(
            env.broker,
            env.policy_key,
            "policy",
            clock_ns=env.clock,
            clock_id=env.queue.clock_id,
        )
        assert recovered_queue.claim(env.ctx, str(uuid4())) is None
        recovered_queue.abandon(env.p["operator"], env.ctx, turn["turn_id"])
        turn_context = {
            **env.ctx.model_dump(),
            "session_id": env.session,
            "turn_id": turn["turn_id"],
            "turn_index": before_recovery["broker_turn"]["turn_index"],
        }
        await env.controller._event(
            "INTEGRITY_VIOLATION", "FAILED", turn=turn_context
        )

        abandoned = _run_snapshot(env, turn)
        assert abandoned["job"]["state"] == "FAILED"
        assert abandoned["job"]["known_execution"] == "UNKNOWN"
        assert abandoned["job"]["body_ref"] is None
        assert abandoned["broker_turn"]["state"] == "UNKNOWN"
        failed_result = json.loads(abandoned["broker_turn"]["result_json"])
        assert failed_result["model_execution"] == "UNKNOWN"
        assert failed_result["integrity"] == "INVALID"
        assert abandoned["n04_turn"]["known_execution"] == "UNKNOWN"
        assert abandoned["experiment"] == {"phase": "INVALID", "integrity": "INVALID"}
        assert abandoned["n04_turn"]["state"] == "DISPATCHED"
        assert abandoned["admitted"] == 1
        assert abandoned["turn_authorization_count"] == 0
        assert recovered_queue.claim(env.ctx, str(uuid4())) is None
        with pytest.raises(BrokerError, match="WRONG_PHASE"):
            recovered_queue._save_authorized(
                before_recovery["job"],
                before_recovery["job"]["worker_id"],
                b"x" * 4096,
            )
        still_failed = _run_snapshot(env, turn)
        assert still_failed["job"]["state"] == "FAILED"
        assert still_failed["job"]["known_execution"] == "UNKNOWN"
        assert still_failed["job"]["body_ref"] is None
        assert still_failed["experiment"] == {
            "phase": "INVALID",
            "integrity": "INVALID",
        }

        env.clock.ns = 6_000_000_000
        unavailable = recovered_queue.project(
            env.p["red"], env.ctx, env.session, turn["turn_id"]
        )
        assert unavailable.status == 503 and len(unavailable.body) == 4096
        assert json.loads(unavailable.body)["status"] == "UNAVAILABLE"
        await env.controller.close(env.p["operator"])
        closed = _run_snapshot(env, turn)
        assert closed["run"]["state"] == "CLOSED"
        assert closed["experiment"] == {"phase": "CLOSED", "integrity": "INVALID"}
        assert closed["job"]["known_execution"] == "UNKNOWN"
        assert closed["job"]["body_ref"] is None
        assert closed["n04_turn"]["state"] == "DISPATCHED"
        assert closed["n04_turn"]["known_execution"] == "UNKNOWN"
        assert closed["admitted"] == 1
        assert closed["turn_authorization_count"] == 0
        assert closed["checkpoint_count"] == closed["witness_close_count"] == 1

        verifier_dir = tmp_path / "late-result-verifier"
        verifier_dir.mkdir()
        verification = verify_export(
            _verifier_environment(env, closed), verifier_dir, "INPUT"
        )
        assert verification.status == "AUTHENTIC_INVALID"
        print(
            "N07B_LATE_RESULT_OBSERVED "
            + json.dumps(
                {
                    "fault_boundary": "TARGET_RESPONSE_BEFORE_CONTROLLER_ACCEPTANCE",
                    "child_exit": "TERMINATED",
                    "before_recovery_job": before_recovery["job"]["state"],
                    "controller_execution": before_recovery["n04_turn"]["known_execution"],
                    "controller_turn_state_after_abandon": abandoned["n04_turn"]["state"],
                    "dispatch_events": event_types.count("DISPATCH_INTENT"),
                    "model_result_events": event_types.count("MODEL_RESULT"),
                    "feedback_authorization_events": event_types.count("FEEDBACK_AUTHORIZED"),
                    "budget_admissions": closed["admitted"],
                    "execution_after_abandon": closed["job"]["known_execution"],
                    "stale_publication_rejected": True,
                    "aggregate_integrity": closed["experiment"]["integrity"],
                    "offline_verifier": verification.status,
                    "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
                    "full_n07_acceptance": False,
                },
                sort_keys=True,
            )
        )

    asyncio.run(scenario())
