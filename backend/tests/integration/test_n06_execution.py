"""N06 component evidence: synthetic adapters, real SQLite/recorder/witness authority.

No Docker, real model calibration, public HTTP execution or timing-AUC claim.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import json
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.broker.config import BrokerConfig, Profile
from arena.broker.core import Broker
from arena.broker.store import BrokerError, Store
from arena.contracts.api import CreateExperiment, EpochRequest, TurnSubmission
from arena.contracts.common import Context, Principal
from arena.contracts.crypto import sha256
from arena.contracts.evidence import TurnFeedback
from arena.execution.policy import FeedbackPolicy, SignedPolicy, disclosure_id, padded_json, policy_message, validate_policy
from arena.execution.queue import ExecutionQueue
from arena.execution.worker import AsyncTurnWorker
from arena.integration.artifacts import ArtifactVault
from arena.integration.controller import N04Controller
from arena.ports import DependencyUnavailable
from arena.ports import TargetNotDispatched
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority
from test_n04 import CountingModel, SyntheticRuntime, payload


class Clock:
    ns = 0
    def __call__(self):
        return self.ns


def signed_policy(**changes):
    key = Ed25519PrivateKey.generate()
    policy = FeedbackPolicy(policy_id="component-only", run_label="SYNTHETIC_MOCK",
                            **({"execution_deadline_ms": 5000, "release_floor_ms": 6000, "body_bytes": 4096} | changes))
    signed = SignedPolicy(policy=policy, signer_key_id="policy", signature=key.sign(policy_message(policy, "policy")).hex())
    return signed, key.public_key().public_bytes_raw()


async def environment(root, *, verdict="ALLOW", lanes=1, domain_queue_limit=4, sealed_transport=False, runtime_setup=None, admission_window_ms=100, runtime_factory=None, anchor=None, recovery_authority=None, recovery_private_key=None, **policy_changes):
    root.mkdir(exist_ok=True)
    clock = Clock()
    signed, policy_key = signed_policy(**policy_changes)
    store = Store(root / "broker.sqlite3", os.urandom(32))
    store.initialize()
    domain = str(uuid4())
    principals = {role: Principal(subject_id=role, role=role, domain_id=domain, expires_at="2027-01-01T00:00:00Z")
                  for role in ("operator", "red", "blue-human", "auditor")}
    for i, principal in enumerate(principals.values()):
        store.provision(str(i), principal)
    runtime = runtime_factory() if runtime_factory is not None else SyntheticRuntime((verdict,))
    if lanes == 3 and runtime_factory is None:
        # Explicit synthetic pool, not Docker evidence.
        from arena.integration.lanes import ThreeLaneModel
        runtime.lane_count = 3
        cells = [SimpleNamespace(container="synthetic-" + str(i), model=CountingModel()) for i in range(3)]
        runtime.model = ThreeLaneModel(cells, lambda i: SimpleNamespace(container="synthetic-new-" + str(i), model=CountingModel()))
    if runtime_setup is not None:
        runtime_setup(runtime)
    request = CreateExperiment(profile_id="n06-component", model_version_id="synthetic" if runtime_factory is None else "qwen-real-synthetic-canaries", defense_version_id="synthetic" if runtime_factory is None else "literal-defense.v1",
        rubric_version_id="observation", disclosure_profile_id=disclosure_id(signed), interaction_mode="INTERACTIVE",
        defense_mode="INPUT", dataset_catalog_id="synthetic", strategy_version_id="synthetic", budget_profile_id="24")
    profile = Profile(domain_id=domain, request=request, red_subject_id="red", blue_subject_id="blue-human",
        auditor_subject_ids=("auditor",), query_budget=24, session_limit=lanes, domain_queue_limit=domain_queue_limit,
        execution_lock_sha256=sha256(runtime.lock_bytes))
    broker = Broker(store, BrokerConfig(profiles=(profile,)))
    _, created = broker.create(principals["operator"], request, "create")
    ctx = Context(**{name: created[name] for name in ("domain_id", "experiment_id", "epoch")})
    admission = None
    if sealed_transport:
        from arena.contracts.transport_profile import LabProfile, SignedLabProfile, SealedTransportPlan, TransportAdmission, TransportTrust, lab_message
        lab_key = Ed25519PrivateKey.generate()
        lab = LabProfile(**ctx.model_dump(), execution_lock_sha256=profile.execution_lock_sha256,
                         feedback_policy_sha256=sha256(signed.policy.model_dump_json().encode()), admission_window_ms=admission_window_ms)
        lab_signed = SignedLabProfile(profile=lab, signer_key_id="lab", signature=lab_key.sign(lab_message(lab, "lab")).hex())
        admission = TransportAdmission(SealedTransportPlan(feedback=signed, transport=lab_signed),
                                       TransportTrust(policy_key, "policy", lab_key.public_key().public_bytes_raw(), "lab"))
    broker.seal(principals["operator"], ctx.experiment_id, EpochRequest(epoch=ctx.epoch), "seal", transport_admission=admission)
    queue = ExecutionQueue(broker, policy_key, "policy", clock_ns=clock)
    queue.bind_policy(principals["operator"], ctx, signed)
    rec_key, wit_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    recorder = DurableRecorder(root / "recorder.sqlite3", rec_key.private_bytes_raw(), "recorder", anchor=anchor)
    rec_pub, wit_pub = rec_key.public_key().public_bytes_raw(), wit_key.public_key().public_bytes_raw()
    witness = SQLiteWitnessAuthority(root / "witness.sqlite3", wit_key.private_bytes_raw(), "witness", initialize_if_missing=True,
                                     recorder_public_key=rec_pub, recorder_key_id="recorder")
    vault = ArtifactVault(root / "vault", ctx, os.urandom(32))
    controller = N04Controller(broker, recorder, witness, vault, runtime, SimpleNamespace(receipt_sha256=runtime.lock["corpus_receipt_sha256"]),
                               recorder_public_key=rec_pub, witness_public_key=wit_pub, transport_admission=admission,
                               recovery_authority=recovery_authority, recovery_private_key=recovery_private_key)
    await controller.start(principals["operator"])
    _, session = broker.session(principals["operator"], ctx.experiment_id, EpochRequest(epoch=ctx.epoch), "session")
    text = "sanitize_control NOOR_N06_CANARY_雪" if verdict == "SANITIZE" else "NOOR_N06_CANARY_雪"
    source = payload(text)
    async def resolve(request, job):
        assert request.text == source.text
        return source
    worker = AsyncTurnWorker(queue, controller, resolve)
    return SimpleNamespace(root=root, broker=broker, store=store, queue=queue, worker=worker, controller=controller,
                           admission=admission, clock=clock, ctx=ctx, runtime=runtime, recorder=recorder, policy_key=policy_key, signed=signed,
                           session=session["session_id"], p=principals, source=source)


def submit(env, key="turn", index=0):
    return env.queue.submit(env.p["red"], env.ctx.experiment_id, env.session,
        TurnSubmission(epoch=env.ctx.epoch, turn_index=index, text=env.source.text), key)[1]


def project(env, turn):
    return env.queue.project(env.p["red"], env.ctx, env.session, turn["turn_id"])


def job_row(env, turn):
    with closing(env.store.connect()) as conn:
        return dict(conn.execute("SELECT * FROM n06_jobs WHERE turn_id=?", (turn["turn_id"],)).fetchone())


def test_signed_policy_is_context_free_metadata_but_signature_and_limits_are_strict():
    signed, key = signed_policy()
    assert validate_policy(signed, key, "policy") == signed.policy
    with pytest.raises(DependencyUnavailable):
        validate_policy(signed, os.urandom(32), "policy")
    with pytest.raises(DependencyUnavailable):
        validate_policy(signed.model_copy(update={"policy": signed.policy.model_copy(update={"body_bytes": 8192})}), key, "policy")
    with pytest.raises(ValueError):
        signed_policy(execution_deadline_ms=7000)
    with pytest.raises(ValueError):
        signed_policy(body_bytes=True)
    text = "雪\n<script>untrusted</script>"
    raw = padded_json({"public_reply": text}, 2048)
    assert len(raw) == 2048 and json.loads(raw)["public_reply"] == text
    with pytest.raises(DependencyUnavailable, match="BUCKET_EXCEEDED"):
        padded_json({"public_reply": "雪"*1000}, 2048)


def test_admission_hook_failure_rolls_back_payload_budget_turn_and_idempotency(tmp_path, monkeypatch):
    async def scenario():
        env = await environment(tmp_path)
        def counts():
            with closing(env.store.connect()) as conn:
                return [conn.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in ("turns", "payloads", "n06_jobs", "idempotency")] + [conn.execute("SELECT admitted FROM budgets").fetchone()[0]]
        before = counts()
        original = env.queue._policy
        def unavailable(*args):
            raise BrokerError("POLICY_NOT_READY", 503)
        monkeypatch.setattr(env.queue, "_policy", unavailable)
        with pytest.raises(BrokerError, match="POLICY_NOT_READY"):
            submit(env)
        assert counts() == before
        monkeypatch.setattr(env.queue, "_policy", original)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: submit(env), range(2)))
        assert results[0] == results[1] and counts()[0] == counts()[2] == counts()[-1] == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("verdict", ["ALLOW", "BLOCK", "SANITIZE"])
def test_real_evidence_authority_fixed_release_bytes_and_identical_reconnect(verdict, tmp_path):
    async def scenario():
        env = await environment(tmp_path, verdict=verdict)
        turn = submit(env)
        assert project(env, turn).status == 202
        assert await env.worker.run_once()
        assert job_row(env, turn)["state"] == "AUTHORIZED"
        assert project(env, turn).status == 202
        with pytest.raises(BrokerError, match="RESOURCE_BUDGET_EXCEEDED"):
            submit(env, "next", 1)
        env.clock.ns = 6_000_000_000
        final = project(env, turn)
        feedback = TurnFeedback.model_validate_json(final.body)
        assert final.status == 200 and len(final.body) == env.signed.policy.body_bytes
        assert feedback.turn_id == turn["turn_id"] and project(env, turn) == final
        assert submit(env) == turn and not await env.worker.run_once()
        assert len(env.runtime.model.calls) == (0 if verdict == "BLOCK" else 1)
        reopened = ExecutionQueue(env.broker, env.policy_key, "policy", clock_id=str(uuid4()))
        assert reopened.project(env.p["red"], env.ctx, env.session, turn["turn_id"]) == final
        for path in env.root.glob("broker.sqlite3*"):
            raw = path.read_bytes()
            assert env.source.text.encode() not in raw and b"model output" not in raw
        assert env.broker.status(env.p["blue-human"], env.ctx.experiment_id, True)[1] == {"status": "EMBARGOED"}
    asyncio.run(scenario())


def test_swapped_text_with_genuine_signed_receipt_is_rejected_and_execution_is_retained(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        original = env.controller.turn
        async def tampered(*args):
            result = await original(*args)
            return replace(result, public_reply="substituted text")
        env.controller.turn = tampered
        turn = submit(env)
        await env.worker.run_once()
        assert job_row(env, turn)["state"] == "FAILED" and job_row(env, turn)["known_execution"] == "EXECUTED"
        assert env.worker.failure_audit_acknowledged == [True]
        assert project(env, turn).status == 202
        env.clock.ns = 6_000_000_000
        final = project(env, turn)
        assert final.status == 503 and json.loads(final.body)["status"] == "UNAVAILABLE"
        assert b"substituted" not in final.body and len(final.body) == 4096
        assert not await env.worker.run_once() and len(env.runtime.model.calls) == 1
    asyncio.run(scenario())


def test_lost_target_ack_is_unknown_invalid_and_never_retried(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        env.runtime.model.failure = DependencyUnavailable("lost target ACK")
        turn = submit(env)
        await env.worker.run_once()
        assert job_row(env, turn)["known_execution"] == "UNKNOWN"
        assert not await env.worker.run_once() and len(env.runtime.model.calls) == 1
        assert env.broker.status(env.p["blue-human"], env.ctx.experiment_id, True)[1] == {"status": "EMBARGOED"}
    asyncio.run(scenario())


def test_unclaimed_expiry_and_revoked_identity_do_not_execute(tmp_path):
    async def scenario():
        env = await environment(tmp_path / "expired")
        turn = submit(env)
        env.clock.ns = 6_000_000_000
        assert not await env.worker.run_once()
        assert job_row(env, turn)["known_execution"] == "NOT_EVALUATED" and not env.runtime.model.calls
        revoked = await environment(tmp_path / "revoked")
        turn = submit(revoked)
        revoked.store.revoke("red")
        await revoked.worker.run_once()
        assert job_row(revoked, turn)["state"] == "FAILED" and not revoked.runtime.model.calls
    asyncio.run(scenario())


def test_clock_restart_and_wrong_scope_cannot_publish_inflight_work(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        turn = submit(env)
        restarted = ExecutionQueue(env.broker, env.policy_key, "policy", clock_id=str(uuid4()))
        with pytest.raises(BrokerError, match="POLICY_NOT_READY"):
            restarted.project(env.p["red"], env.ctx, env.session, turn["turn_id"])
        with pytest.raises(BrokerError, match="POLICY_NOT_READY"):
            restarted.claim(env.ctx, str(uuid4()))
        for actor in ("operator", "auditor", "blue-human"):
            with pytest.raises(BrokerError, match="FORBIDDEN"):
                env.queue.project(env.p[actor], env.ctx, env.session, turn["turn_id"])
        with pytest.raises(BrokerError, match="NOT_FOUND"):
            env.queue.project(env.p["red"], env.ctx.model_copy(update={"domain_id": str(uuid4())}), env.session, turn["turn_id"])
    asyncio.run(scenario())


def _claim_and_die(db, master, config, public, ctx, clock_id):
    broker = Broker(Store(Path(db), master), BrokerConfig.model_validate_json(config))
    queue = ExecutionQueue(broker, public, "policy", clock_ns=lambda: 0, clock_id=clock_id)
    job = queue.claim(Context.model_validate(ctx), str(uuid4()))
    os._exit(29 if job else 30)


def test_actual_process_death_after_claim_never_requeues_or_refunds(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        turn = submit(env)
        # Share the parent's explicit clock epoch with this controlled same-boot fixture.
        process = multiprocessing.get_context("spawn").Process(target=_claim_and_die, args=(str(env.store.path), env.store.master_key,
            env.broker.config.model_dump_json(), env.policy_key, env.ctx.model_dump(), env.queue.clock_id))
        process.start()
        process.join(20)
        assert not process.is_alive() and process.exitcode == 29
        assert job_row(env, turn)["state"] == "CLAIMED"
        assert env.queue.claim(env.ctx, str(uuid4())) is None
        env.queue.abandon(env.p["operator"], env.ctx, turn["turn_id"])
        assert job_row(env, turn)["state"] == "FAILED" and job_row(env, turn)["known_execution"] == "UNKNOWN"
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
    asyncio.run(scenario())


def test_abandoned_claim_cannot_use_original_reservation_to_dispatch_late(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        turn = submit(env)
        env.queue.claim(env.ctx, str(uuid4()))
        env.queue.abandon(env.p["operator"], env.ctx, turn["turn_id"])
        with pytest.raises(TargetNotDispatched, match="ADMISSION_NO_LONGER_VALID"):
            await env.controller.turn(env.p["red"], env.session,
                TurnSubmission(epoch=env.ctx.epoch, turn_index=0, text=env.source.text), "turn", env.source)
        assert not env.runtime.model.calls
    asyncio.run(scenario())


def test_expiry_during_defense_cannot_reach_target_after_invalidation(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        entered, resume = asyncio.Event(), asyncio.Event()
        original = env.runtime.evaluate
        async def paused(request):
            entered.set()
            await resume.wait()
            return await original(request)
        env.runtime.evaluate = paused
        turn = submit(env)
        running = asyncio.create_task(env.worker.run_once())
        await asyncio.wait_for(entered.wait(), 2)
        env.clock.ns = 6_000_000_000
        assert project(env, turn).status == 503
        resume.set()
        await running
        assert not env.runtime.model.calls and job_row(env, turn)["known_execution"] == "NOT_EVALUATED"
    asyncio.run(scenario())


def test_cancellation_resistant_resolution_is_retained_and_cannot_dispatch_late(tmp_path):
    async def scenario():
        env = await environment(tmp_path, execution_deadline_ms=10, release_floor_ms=20)
        release = asyncio.Event()
        async def ignoring_one_cancel(request, job):
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()
            return env.source
        env.worker.resolve_payload = ignoring_one_cancel
        turn = submit(env)
        await env.worker.run_once()
        assert job_row(env, turn)["state"] == "FAILED" and job_row(env, turn)["known_execution"] == "NOT_EVALUATED"
        assert env.worker.tasks and not env.runtime.model.calls
        remaining = set(env.worker.tasks)
        release.set()
        done, pending = await asyncio.wait(remaining, timeout=2)
        assert done and not pending and not env.runtime.model.calls
        assert not await env.worker.run_once()
    asyncio.run(scenario())


def test_oversized_authorized_reply_is_not_truncated_or_mislabeled_not_evaluated(tmp_path):
    async def scenario():
        env = await environment(tmp_path, body_bytes=2048)
        original = env.runtime.model.infer
        async def large(request):
            response = await original(request)
            return response.model_copy(update={"text": "雪" * 1000})
        env.runtime.model.infer = large
        turn = submit(env)
        await env.worker.run_once()
        row = job_row(env, turn)
        assert row["state"] == "FAILED" and row["known_execution"] == "EXECUTED" and row["body_ref"] is None
        env.clock.ns = 6_000_000_000
        response = project(env, turn)
        assert response.status == 503 and len(response.body) == 2048
        assert "雪" not in response.body.decode()
    asyncio.run(scenario())


def test_domain_quota_counts_completed_feedback_until_scheduled_publication(tmp_path):
    async def scenario():
        env = await environment(tmp_path, lanes=3, domain_queue_limit=1)
        turn = submit(env)
        await env.worker.run_once()
        _, second = env.broker.session(env.p["operator"], env.ctx.experiment_id, EpochRequest(epoch=env.ctx.epoch), "second")
        with pytest.raises(BrokerError, match="RESOURCE_BUDGET_EXCEEDED"):
            env.queue.submit(env.p["red"], env.ctx.experiment_id, second["session_id"],
                TurnSubmission(epoch=env.ctx.epoch, turn_index=0, text=env.source.text), "second-turn")
        assert job_row(env, turn)["state"] == "AUTHORIZED"
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
    asyncio.run(scenario())


def test_controller_explicit_predispatch_rejection_is_not_falsely_unknown(tmp_path):
    async def scenario():
        env = await environment(tmp_path)
        async def rejected(*args):
            raise TargetNotDispatched("AUTHORITATIVE_NO_DISPATCH")
        env.controller.turn = rejected
        turn = submit(env)
        await env.worker.run_once()
        assert job_row(env, turn)["known_execution"] == "NOT_EVALUATED"
        assert not env.runtime.model.calls and not await env.worker.run_once()
    asyncio.run(scenario())
