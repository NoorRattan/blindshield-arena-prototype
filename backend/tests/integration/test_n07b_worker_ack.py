"""Worker death after queue publication commits but before the worker returns.

This is the complementary queue boundary to the pre-publication death case:
the authorized response is durable even though the child process is lost.
"""

import asyncio
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

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


def _child_pause_after_queue_commit(spec, pipe):
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
    from arena.contracts.api import ResolvedPayload
    from arena.contracts.common import Context

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

    original_save = queue._save_authorized

    def commit_then_withhold_worker_return(job, worker_id, body):
        saved = original_save(job, worker_id, body)
        if not saved:
            raise AssertionError("AUTHORIZED_FEEDBACK_NOT_COMMITTED")
        pipe.send({"stage": "QUEUE_PUBLICATION_COMMITTED_BEFORE_WORKER_RETURN"})
        pipe.recv()
        return saved

    queue._save_authorized = commit_then_withhold_worker_return
    worker = AsyncTurnWorker(queue, controller, resolve_payload)
    await worker.run_once()


def test_process_death_after_queue_commit_preserves_stable_projection_without_reexecution(tmp_path):
    async def scenario():
        env = await environment(tmp_path / "worker-ack")
        turn = submit(env, key="queue-committed-worker-lost")
        spawn = multiprocessing.get_context("spawn")
        parent_pipe, child_pipe = spawn.Pipe(duplex=True)
        process = spawn.Process(
            target=_child_pause_after_queue_commit,
            args=(_child_spec(env), child_pipe),
        )
        process.start()
        child_pipe.close()
        _wait_for_stage(
            process, parent_pipe, "QUEUE_PUBLICATION_COMMITTED_BEFORE_WORKER_RETURN"
        )
        process.terminate()
        process.join(20)
        assert not process.is_alive() and process.exitcode not in (None, 0)
        parent_pipe.close()

        committed = _run_snapshot(env, turn)
        assert committed["job"]["state"] == "AUTHORIZED"
        assert committed["job"]["body_ref"]
        assert committed["job"]["published"] == 0
        assert committed["job"]["known_execution"] == "EXECUTED"
        assert committed["broker_turn"]["state"] == "COMPLETED"
        controller_result = json.loads(committed["broker_turn"]["result_json"])
        assert controller_result["model_execution"] == "EXECUTED"
        assert controller_result["integrity"] == "VALID_WITHIN_PROFILE"
        assert committed["n04_turn"]["state"] == "DONE"
        assert committed["n04_turn"]["known_execution"] == "EXECUTED"
        assert committed["n04_turn"]["receipt_json"]
        assert committed["admitted"] == 1
        assert committed["turn_authorization_count"] == 1
        events = env.recorder.get_events(env.ctx)
        event_types = [event.event_type for event in events]
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
        assert recovered_queue.claim(env.ctx, str(uuid4())) is None
        pending = recovered_queue.project(
            env.p["red"], env.ctx, env.session, turn["turn_id"]
        )
        assert pending.status == 202 and len(pending.body) == 4096
        assert json.loads(pending.body)["status"] == "PENDING"
        pending_snapshot = _run_snapshot(env, turn)
        assert pending_snapshot["job"]["published"] == 0

        env.clock.ns = 6_000_000_000
        first = recovered_queue.project(
            env.p["red"], env.ctx, env.session, turn["turn_id"]
        )
        second = recovered_queue.project(
            env.p["red"], env.ctx, env.session, turn["turn_id"]
        )
        assert first.status == second.status == 200
        assert len(first.body) == len(second.body) == 4096
        assert first.body == second.body
        assert json.loads(first.body)["public_status"] == "COMPLETED"
        after_projection = _run_snapshot(env, turn)
        assert after_projection["job"]["state"] == "AUTHORIZED"
        assert after_projection["job"]["published"] == 1
        assert after_projection["job"]["body_ref"] == committed["job"]["body_ref"]
        assert after_projection["admitted"] == 1
        assert after_projection["turn_authorization_count"] == 1
        assert after_projection["event_count"] == committed["event_count"]
        assert recovered_queue.claim(env.ctx, str(uuid4())) is None

        await env.controller.close(env.p["operator"])
        closed = _run_snapshot(env, turn)
        assert closed["run"]["state"] == "CLOSED"
        assert closed["experiment"] == {
            "phase": "CLOSED",
            "integrity": "VALID_WITHIN_PROFILE",
        }
        assert closed["job"]["known_execution"] == "EXECUTED"
        assert closed["admitted"] == 1
        assert closed["turn_authorization_count"] == 1
        assert closed["checkpoint_count"] == closed["witness_close_count"] == 1
        verifier_dir = tmp_path / "worker-ack-verifier"
        verifier_dir.mkdir()
        verification = verify_export(
            _verifier_environment(env, closed), verifier_dir, "INPUT"
        )
        assert verification.status == "PASS_PUBLIC_EVIDENCE"
        print(
            "N07B_WORKER_ACK_OBSERVED "
            + json.dumps(
                {
                    "fault_boundary": "QUEUE_PUBLICATION_COMMITTED_BEFORE_WORKER_RETURN",
                    "child_exit": "TERMINATED",
                    "durable_job_after_fault": committed["job"]["state"],
                    "body_committed_before_fault": bool(committed["job"]["body_ref"]),
                    "pre_release_status": json.loads(pending.body)["status"],
                    "published_before_release": pending_snapshot["job"]["published"],
                    "repeated_projection_stable": first.body == second.body,
                    "budget_admissions": closed["admitted"],
                    "dispatch_events": event_types.count("DISPATCH_INTENT"),
                    "model_result_events": event_types.count("MODEL_RESULT"),
                    "feedback_authorization_events": event_types.count("FEEDBACK_AUTHORIZED"),
                    "controller_execution": closed["n04_turn"]["known_execution"],
                    "aggregate_integrity": closed["experiment"]["integrity"],
                    "offline_verifier": verification.status,
                    "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
                    "full_n07_acceptance": False,
                },
                sort_keys=True,
            )
        )

    asyncio.run(scenario())
