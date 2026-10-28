"""Process death after recorder feedback authorization, before bound receipt.

This synthetic-component fixture checks the orphan-event interval between a
durable recorder append and durable bound-turn authorization/broker completion.
It is not real model inference or deployment evidence.
"""

import asyncio
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from arena.ports import DependencyUnavailable

from arena.broker.store import BrokerError
from arena.contracts.api import AttemptResult, ResolvedPayload
from arena.execution.queue import ExecutionQueue
from arena.execution.worker import AsyncTurnWorker
from arena.integration.artifacts import ArtifactVault
from arena.integration.controller import N04Controller
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority
from arena.verifier.invalid_bundle import verify_invalid_evidence_bundle

from test_n04 import SyntheticRuntime, verify_export
from test_n06_execution import environment, submit
from test_n07b_integrated_faults import (
    _child_spec,
    _run_snapshot,
    _verifier_environment,
    _wait_for_stage,
)


def _child_feedback_event(spec, pipe, pause_after_feedback):
    try:
        asyncio.run(_child_async(spec, pipe, pause_after_feedback))
    except BaseException as error:
        try:
            pipe.send({"stage": "child-error", "error_type": type(error).__name__})
        except Exception:
            pass
        raise
    finally:
        pipe.close()


async def _child_async(spec, pipe, pause_after_feedback):
    root = Path(spec["root"])
    from arena.broker.config import BrokerConfig
    from arena.broker.core import Broker
    from arena.broker.store import Store
    from arena.contracts.common import Context, Principal

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
    original_event = controller._event

    async def observe_committed_event(*args, **kwargs):
        event = await original_event(*args, **kwargs)
        kind = args[0] if args else kwargs.get("kind")
        if pause_after_feedback and kind == "FEEDBACK_AUTHORIZED":
            pipe.send({"stage": "FEEDBACK_AUTHORIZED_COMMITTED_BEFORE_BOUND_TURN"})
            pipe.recv()
        return event

    controller._event = observe_committed_event
    source = ResolvedPayload.model_validate_json(spec["source"])

    async def resolve_payload(request, job):
        if request.text != source.text:
            raise AssertionError("RESOLVED_SOURCE_MISMATCH")
        return source

    worker = AsyncTurnWorker(queue, controller, resolve_payload)
    if not await worker.run_once():
        raise AssertionError("HEALTHY_CONTROL_DID_NOT_CLAIM_JOB")
    if not pause_after_feedback:
        await controller.close(Principal.model_validate(spec["operator"]))


def _spawn(env, *, pause_after_feedback):
    spawn = multiprocessing.get_context("spawn")
    parent_pipe, child_pipe = spawn.Pipe(duplex=True)
    process = spawn.Process(
        target=_child_feedback_event,
        args=(_child_spec(env), child_pipe, pause_after_feedback),
    )
    process.start()
    child_pipe.close()
    return process, parent_pipe


def test_process_death_after_feedback_event_keeps_orphan_invalid_and_never_retries(
    tmp_path,
):
    async def scenario():
        healthy = await environment(tmp_path / "healthy")
        healthy_turn = submit(healthy, key="healthy-feedback-event-control")
        healthy_process, healthy_pipe = _spawn(
            healthy, pause_after_feedback=False
        )
        healthy_process.join(30)
        assert not healthy_process.is_alive() and healthy_process.exitcode == 0
        healthy_pipe.close()
        healthy_snapshot = _run_snapshot(healthy, healthy_turn)
        assert healthy_snapshot["job"]["state"] == "AUTHORIZED"
        assert healthy_snapshot["job"]["body_ref"]
        assert healthy_snapshot["broker_turn"]["state"] == "COMPLETED"
        assert healthy_snapshot["n04_turn"]["state"] == "DONE"
        assert healthy_snapshot["turn_authorization_count"] == 1
        healthy_events = [event.event_type for event in healthy.recorder.get_events(healthy.ctx)]
        assert healthy_events.count("FEEDBACK_AUTHORIZED") == 1
        healthy_verify_dir = tmp_path / "healthy-verifier"
        healthy_verify_dir.mkdir()
        healthy_verification = verify_export(
            _verifier_environment(healthy, healthy_snapshot),
            healthy_verify_dir,
            "INPUT",
        )
        assert healthy_verification.status == "PASS_PUBLIC_EVIDENCE"

        interrupted = await environment(tmp_path / "orphan-feedback-event")
        interrupted_turn = submit(interrupted, key="orphan-feedback-event")
        process, pipe = _spawn(interrupted, pause_after_feedback=True)
        _wait_for_stage(
            process, pipe, "FEEDBACK_AUTHORIZED_COMMITTED_BEFORE_BOUND_TURN"
        )
        process.terminate()
        process.join(20)
        assert not process.is_alive() and process.exitcode not in (None, 0)
        pipe.close()

        before_recovery = _run_snapshot(interrupted, interrupted_turn)
        assert before_recovery["job"]["state"] == "CLAIMED"
        assert before_recovery["job"]["body_ref"] is None
        assert before_recovery["job"]["published"] == 0
        assert before_recovery["broker_turn"]["state"] == "DISPATCHED"
        assert before_recovery["broker_turn"]["result_json"] is None
        assert before_recovery["n04_turn"]["state"] == "DISPATCHED"
        assert before_recovery["n04_turn"]["known_execution"] == "EXECUTED"
        assert before_recovery["n04_turn"]["receipt_json"] is None
        assert before_recovery["admitted"] == 1
        assert before_recovery["turn_authorization_count"] == 0
        events = interrupted.recorder.get_events(interrupted.ctx)
        event_types = [event.event_type for event in events]
        assert event_types.count("DISPATCH_INTENT") == 1
        assert event_types.count("MODEL_RESULT") == 1
        assert event_types.count("SCORE_RESULT") == 1
        assert event_types.count("FEEDBACK_AUTHORIZED") == 1

        recovered_queue = ExecutionQueue(
            interrupted.broker,
            interrupted.policy_key,
            "policy",
            clock_ns=interrupted.clock,
            clock_id=interrupted.queue.clock_id,
        )
        assert recovered_queue.claim(interrupted.ctx, str(uuid4())) is None
        recovered_queue.abandon(
            interrupted.p["operator"], interrupted.ctx, interrupted_turn["turn_id"]
        )
        turn_context = {
            **interrupted.ctx.model_dump(),
            "session_id": interrupted.session,
            "turn_id": interrupted_turn["turn_id"],
            "turn_index": before_recovery["broker_turn"]["turn_index"],
        }
        await interrupted.controller._event(
            "INTEGRITY_VIOLATION", "FAILED", turn=turn_context
        )

        abandoned = _run_snapshot(interrupted, interrupted_turn)
        assert abandoned["job"]["state"] == "FAILED"
        assert abandoned["job"]["known_execution"] == "EXECUTED"
        assert abandoned["job"]["body_ref"] is None
        assert abandoned["broker_turn"]["state"] == "FAILED"
        failed_result = json.loads(abandoned["broker_turn"]["result_json"])
        assert failed_result["model_execution"] == "EXECUTED"
        assert failed_result["integrity"] == "INVALID"
        assert abandoned["n04_turn"]["known_execution"] == "EXECUTED"
        assert abandoned["n04_turn"]["receipt_json"] is None
        assert abandoned["experiment"] == {
            "phase": "INVALID",
            "integrity": "INVALID",
        }
        assert abandoned["admitted"] == 1
        assert abandoned["turn_authorization_count"] == 0
        assert recovered_queue.claim(interrupted.ctx, str(uuid4())) is None
        with pytest.raises(BrokerError, match="WRONG_PHASE"):
            recovered_queue._save_authorized(
                before_recovery["job"],
                before_recovery["job"]["worker_id"],
                b"x" * 4096,
            )

        interrupted.clock.ns = 6_000_000_000
        unavailable = recovered_queue.project(
            interrupted.p["red"],
            interrupted.ctx,
            interrupted.session,
            interrupted_turn["turn_id"],
        )
        assert unavailable.status == 503 and len(unavailable.body) == 4096
        assert json.loads(unavailable.body)["status"] == "UNAVAILABLE"
        await interrupted.controller.close(interrupted.p["operator"])
        closed = _run_snapshot(interrupted, interrupted_turn)
        assert closed["run"]["state"] == "CLOSED"
        assert closed["experiment"] == {"phase": "CLOSED", "integrity": "INVALID"}
        assert closed["job"]["known_execution"] == "EXECUTED"
        assert closed["job"]["body_ref"] is None
        assert closed["n04_turn"]["receipt_json"] is None
        assert closed["admitted"] == 1
        assert closed["turn_authorization_count"] == 0
        assert closed["checkpoint_count"] == closed["witness_close_count"] == 1

        verifier_dir = tmp_path / "orphan-feedback-event-verifier"
        verifier_dir.mkdir()
        with pytest.raises(DependencyUnavailable, match="ORDINARY_EXPORT_REQUIRES_VALID_INTEGRITY"):
            interrupted.controller.export(interrupted.p["auditor"], verifier_dir / "evidence.zip")
        assert not (verifier_dir / "evidence.zip").exists()
        anchor_key = Ed25519PrivateKey.generate()
        recovery_key = Ed25519PrivateKey.generate()
        export_key = Ed25519PrivateKey.generate()
        authority = {
            "key_id": "test-invalid-export",
            "public_key_bytes": export_key.public_key().public_bytes_raw(),
        }
        invalid_bundle = verifier_dir / "invalid-evidence.zip"
        interrupted.controller.export_invalid_evidence(
            interrupted.p["auditor"], invalid_bundle, authority, export_key
        )
        offline_invalid = verify_invalid_evidence_bundle(
            invalid_bundle,
            recorder_key=interrupted.controller.recorder_public_key,
            witness_key=interrupted.controller.witness_public_key,
            anchor_key=anchor_key.public_key().public_bytes_raw(),
            recovery_key=recovery_key.public_key().public_bytes_raw(),
            export_key=authority["public_key_bytes"],
            expected_context=interrupted.ctx,
            expected_manifest_digest=interrupted.controller._row(interrupted.p["auditor"])["public_commitment"],
            recorder_key_id=interrupted.controller.recorder.signer_key_id,
            witness_key_id=interrupted.controller.witness.witness_key_id,
            anchor_key_id="test-anchor", recovery_key_id="test-recovery",
            export_key_id=authority["key_id"],
        )
        assert offline_invalid["status"] == "AUTHENTIC_INVALID_INCOMPLETE"
        assert any(gap["gap_code"] == "TURN_RECEIPT_MISSING" for gap in offline_invalid["gaps"])
        print(
            "N07B_FEEDBACK_EVENT_OBSERVED "
            + json.dumps(
                {
                    "fault_boundary": "FEEDBACK_AUTHORIZED_COMMITTED_BEFORE_BOUND_TURN",
                    "child_exit": "TERMINATED",
                    "orphan_feedback_events": event_types.count("FEEDBACK_AUTHORIZED"),
                    "bound_turn_authorizations": closed["turn_authorization_count"],
                    "execution_preserved": closed["job"]["known_execution"] == "EXECUTED",
                    "budget_admissions": closed["admitted"],
                    "body_published": closed["job"]["body_ref"] is not None,
                    "aggregate_integrity": closed["experiment"]["integrity"],
                    "healthy_control_verifier": healthy_verification.status,
                    "ordinary_export": "REFUSED_INVALID_INTEGRITY",
                    "invalid_offline_verifier": offline_invalid["status"],
                    "orphan_receipt_gap": "TURN_RECEIPT_MISSING",
                    "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
                    "full_n07_acceptance": False,
                },
                sort_keys=True,
            )
        )

    asyncio.run(scenario())


def test_invalid_export_handles_committed_turn_without_feedback_event(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        turn = submit(env, key="orphan-commit-without-feedback")
        await env.controller._event(
            "TURN_COMMITTED", turn={
                **env.ctx.model_dump(),
                "session_id": env.session,
                "turn_id": turn["turn_id"],
                "turn_index": turn["turn_index"],
            },
        )
        failure = AttemptResult(
            defense_mode="INPUT",
            pipeline_disposition="INFRASTRUCTURE_FAILED",
            model_execution="NOT_EVALUATED",
            scoring="NOT_EVALUATED",
            integrity="INVALID",
        ).model_dump_json()
        with env.store.transaction() as conn:
            conn.execute(
                "UPDATE n06_jobs SET state='FAILED',known_execution='NOT_EVALUATED',body_ref=NULL,published=0 "
                "WHERE turn_id=?",
                (turn["turn_id"],),
            )
            conn.execute(
                "UPDATE turns SET state='FAILED',result_json=? WHERE id=?",
                (failure, turn["turn_id"]),
            )
            conn.execute(
                "UPDATE n04_turns SET state='FAILED',known_execution='NOT_EVALUATED',result_json=?,"
                "feedback_ref=NULL,receipt_json=NULL WHERE turn_id=?",
                (failure, turn["turn_id"]),
            )
        env.controller._invalidate()
        await env.controller.close(env.p["operator"])

        export_key = Ed25519PrivateKey.generate()
        authority = {
            "key_id": "test-invalid-export",
            "public_key_bytes": export_key.public_key().public_bytes_raw(),
        }
        archive = tmp_path / "orphan-commit-invalid-evidence.zip"
        env.controller.export_invalid_evidence(env.p["auditor"], archive, authority, export_key)
        assert archive.is_file()
        verification = verify_invalid_evidence_bundle(
            archive,
            recorder_key=env.controller.recorder_public_key,
            witness_key=env.controller.witness_public_key,
            export_key=authority["public_key_bytes"],
            expected_context=env.ctx,
            expected_manifest_digest=env.controller._row(env.p["auditor"])["public_commitment"],
            recorder_key_id=env.controller.recorder.signer_key_id,
            witness_key_id=env.controller.witness.witness_key_id,
            export_key_id=authority["key_id"],
        )
        assert verification["status"] == "AUTHENTIC_INVALID_INCOMPLETE"
        assert any(gap["gap_code"] == "TURN_RECEIPT_MISSING" for gap in verification["gaps"])

    asyncio.run(scenario())
