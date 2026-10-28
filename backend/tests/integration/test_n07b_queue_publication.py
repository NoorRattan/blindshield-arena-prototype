"""Integrated worker death after controller success but before queue publication.

The child uses the real broker, queue, worker, controller, recorder and witness
around the synthetic target used by the N07B component fixtures. This is not
real inference or deployment evidence.
"""

import asyncio
from contextlib import closing
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from arena.broker.store import BrokerError
from arena.contracts.api import ResolvedPayload
from arena.execution.queue import ExecutionQueue
from arena.execution.worker import AsyncTurnWorker
from arena.integration.artifacts import ArtifactVault
from arena.integration.controller import N04Controller
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority

from test_n04 import verify_export
from test_n06_execution import environment, submit
from test_n07b_integrated_faults import (
    _child_spec,
    _run_snapshot,
    _verifier_environment,
    _wait_for_stage,
)


def _child_pause_before_queue_publication(spec, pipe):
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
    from arena.contracts.common import Context, Principal

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
    from test_n04 import SyntheticRuntime

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
    original_save = queue._save_authorized

    def withhold_queue_publication(job, worker_id, body):
        pipe.send({"stage": "CONTROLLER_DONE_BEFORE_QUEUE_PUBLICATION"})
        pipe.recv()
        return original_save(job, worker_id, body)

    queue._save_authorized = withhold_queue_publication
    if not await worker.run_once():
        raise AssertionError("HEALTHY_CONTROL_DID_NOT_CLAIM_JOB")
    await controller.close(Principal.model_validate(spec["operator"]))


def test_process_death_after_controller_success_never_publishes_or_retries(tmp_path):
    async def scenario():
        env = await environment(tmp_path / "queue-publication")
        turn = submit(env, key="queue-publication-lost")
        spawn = multiprocessing.get_context("spawn")
        parent_pipe, child_pipe = spawn.Pipe(duplex=True)
        process = spawn.Process(
            target=_child_pause_before_queue_publication,
            args=(_child_spec(env), child_pipe),
        )
        process.start()
        child_pipe.close()
        _wait_for_stage(process, parent_pipe, "CONTROLLER_DONE_BEFORE_QUEUE_PUBLICATION")
        process.terminate()
        process.join(20)
        assert not process.is_alive() and process.exitcode not in (None, 0)
        parent_pipe.close()

        before_recovery = _run_snapshot(env, turn)
        assert before_recovery["job"]["state"] == "CLAIMED"
        assert before_recovery["job"]["body_ref"] is None
        assert before_recovery["job"]["published"] == 0
        assert before_recovery["broker_turn"]["state"] == "COMPLETED"
        controller_result = json.loads(before_recovery["broker_turn"]["result_json"])
        assert controller_result["model_execution"] == "EXECUTED"
        assert controller_result["integrity"] == "VALID_WITHIN_PROFILE"
        assert before_recovery["n04_turn"]["state"] == "DONE"
        assert before_recovery["n04_turn"]["known_execution"] == "EXECUTED"
        assert before_recovery["n04_turn"]["receipt_json"]
        assert before_recovery["admitted"] == 1
        assert before_recovery["turn_authorization_count"] == 1
        event_types = [event.event_type for event in env.recorder.get_events(env.ctx)]
        assert event_types.count("DISPATCH_INTENT") == 1
        assert event_types.count("MODEL_RESULT") == 1
        assert event_types.count("FEEDBACK_AUTHORIZED") == 1

        recovered_queue = ExecutionQueue(
            env.broker,
            env.policy_key,
            "policy",
            clock_ns=env.clock,
            clock_id=env.queue.clock_id,
        )
        recovered_queue.abandon(env.p["operator"], env.ctx, turn["turn_id"])
        turn_context = {
            **env.ctx.model_dump(),
            "session_id": env.session,
            "turn_id": turn["turn_id"],
            "turn_index": before_recovery["broker_turn"]["turn_index"],
        }
        await env.controller._event("INTEGRITY_VIOLATION", "FAILED", turn=turn_context)

        abandoned = _run_snapshot(env, turn)
        assert abandoned["job"]["state"] == "FAILED"
        assert abandoned["job"]["known_execution"] == "EXECUTED"
        assert abandoned["job"]["body_ref"] is None
        assert abandoned["broker_turn"]["state"] == "FAILED"
        failed_result = json.loads(abandoned["broker_turn"]["result_json"])
        assert failed_result["model_execution"] == "EXECUTED"
        assert failed_result["integrity"] == "INVALID"
        assert abandoned["n04_turn"]["known_execution"] == "EXECUTED"
        assert abandoned["n04_turn"]["receipt_json"]
        assert abandoned["experiment"] == {"phase": "INVALID", "integrity": "INVALID"}
        assert abandoned["admitted"] == 1
        assert abandoned["turn_authorization_count"] == 1
        assert recovered_queue.claim(env.ctx, str(uuid4())) is None
        with pytest.raises(BrokerError, match="WRONG_PHASE"):
            recovered_queue._save_authorized(
                before_recovery["job"],
                before_recovery["job"]["worker_id"],
                b"x" * 4096,
            )
        still_failed = _run_snapshot(env, turn)
        assert still_failed["job"]["state"] == "FAILED"
        assert still_failed["job"]["body_ref"] is None
        assert still_failed["experiment"] == {"phase": "INVALID", "integrity": "INVALID"}

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
        assert closed["job"]["known_execution"] == "EXECUTED"
        assert closed["job"]["body_ref"] is None
        assert closed["admitted"] == 1
        assert closed["turn_authorization_count"] == 1
        assert closed["checkpoint_count"] == closed["witness_close_count"] == 1

        verifier_dir = tmp_path / "queue-publication-verifier"
        verifier_dir.mkdir()
        verification = verify_export(
            _verifier_environment(env, closed), verifier_dir, "INPUT"
        )
        assert verification.status == "AUTHENTIC_INVALID"
        print(
            "N07B_QUEUE_PUBLICATION_OBSERVED "
            + json.dumps(
                {
                    "fault_boundary": "CONTROLLER_DONE_BEFORE_QUEUE_PUBLICATION",
                    "child_exit": "TERMINATED",
                    "before_recovery_job": before_recovery["job"]["state"],
                    "published_body_after_fault": before_recovery["job"]["body_ref"] is not None,
                    "executed_preserved": closed["job"]["known_execution"] == "EXECUTED",
                    "budget_admissions": closed["admitted"],
                    "dispatch_events": event_types.count("DISPATCH_INTENT"),
                    "model_result_events": event_types.count("MODEL_RESULT"),
                    "stale_publication_rejected": True,
                    "feedback_status": json.loads(unavailable.body)["status"],
                    "aggregate_integrity": closed["experiment"]["integrity"],
                    "offline_verifier": verification.status,
                    "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
                    "full_n07_acceptance": False,
                },
                sort_keys=True,
            )
        )

    asyncio.run(scenario())
